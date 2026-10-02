import axios from 'axios';
import * as crypto from 'crypto';
import * as fs from 'fs';
import FormData from 'form-data';

// Re-export credential persistence helpers for backward compat with callers
// that imported them from './vt-api'. The implementations live in
// vt-credentials.ts (see its header for why the split exists).
export {
    setStateDir,
    getAgentCredentialsPath,
    loadAgentCredentials,
    saveAgentCredentials,
} from './vt-credentials';
export type { AgentCredentials } from './vt-credentials';
import type { AgentCredentials } from './vt-credentials';

const VT_API_URL = 'https://www.virustotal.com/api/v3';
const VTAI_API_URL = 'https://ai.virustotal.com/api/v3';
const HTTP_TIMEOUT_MS = 30_000; // 30s timeout for all API calls
const DEFAULT_RETRY_MS = 60_000;
const MAX_DATE_MS = 8_640_000_000_000_000;

type QuotaOperation = 'query' | 'upload';

export class VTRateLimitError extends Error {
    readonly status = 429;

    constructor(readonly retryAt: number) {
        super(`VirusTotal rate limit reached. Retry at ${new Date(retryAt).toISOString()}.`);
        this.name = 'VTRateLimitError';
    }
}

function retryDeadline(error: any, now: number): number {
    const headers = error.response?.headers;
    const header = headers?.['retry-after'] ?? headers?.['Retry-After'];
    const fromSeconds = (value: unknown): number | undefined => {
        const seconds = typeof value === 'string' && /^\d+$/.test(value.trim())
            ? Number(value.trim()) : value;
        if (typeof seconds !== 'number' || !Number.isSafeInteger(seconds) || seconds < 0) return;
        const deadline = now + seconds * 1000;
        if (Number.isSafeInteger(deadline) && deadline <= MAX_DATE_MS) return deadline;
    };
    const seconds = fromSeconds(header);
    if (seconds !== undefined) return seconds;
    // HTTP dates begin with a weekday; do not reinterpret malformed numbers as dates.
    if (typeof header === 'string' && /^[A-Za-z]{3,9}[, ]/.test(header)) {
        const date = Date.parse(header);
        if (Number.isFinite(date)) return Math.max(now, date);
    }
    return fromSeconds(error.response?.data?.detail?.retry_after_seconds) ?? now + DEFAULT_RETRY_MS;
}

// --- Types ---

export interface VTAnalysisStats {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
}

export interface VTCrowdsourcedAiResult {
    source: string;
    analysis: string;
    verdict?: string;
    id?: string;
}

export interface VTReport {
    hash: string;
    stats: VTAnalysisStats;
    name?: string;
    crowdsourcedAiResults?: VTCrowdsourcedAiResult[];
    vtLink: string;
}

export interface VTUploadResult {
    analysisId: string;
    message: string;
}

function reportStats(hash: unknown, stats: any): VTAnalysisStats {
    const fields = ['malicious', 'suspicious', 'harmless', 'undetected'] as const;
    if (typeof hash !== 'string' || !/^[a-fA-F0-9]{64}$/.test(hash)
        || !stats || typeof stats !== 'object' || Array.isArray(stats)
        || fields.some(field => !Number.isSafeInteger(stats[field]) || stats[field] < 0)) {
        throw new Error('Invalid VirusTotal report response.');
    }
    return { malicious: stats.malicious, suspicious: stats.suspicious,
        harmless: stats.harmless, undetected: stats.undetected };
}

function aiResults(value: any): VTCrowdsourcedAiResult[] | undefined {
    if (value == null) return;
    if (!Array.isArray(value) || value.some(row => !row || typeof row !== 'object' || Array.isArray(row)
        || ['source', 'analysis', 'verdict', 'id'].some(field => row[field] != null && typeof row[field] !== 'string'))) {
        throw new Error('Invalid VirusTotal report response.');
    }
    return value.map(row => ({ source: row.source ?? '', analysis: row.analysis ?? '',
        verdict: row.verdict ?? undefined, id: row.id ?? undefined }));
}

/**
 * Options for agent registration with VTAI.
 * All fields optional — sensible defaults applied.
 */
export interface RegisterAgentOpts {
    agentFamily?: string;     // default: 'vt-sentinel'
    agentVersion?: string;    // default: '0.2.0'
    displayName?: string;     // default: 'VT Sentinel'
    humanAlias?: string;
    defineYourSelf?: string;
    contactEmail?: string;
}

/**
 * Register a new agent with VirusTotal AI API.
 * No authentication required — zero-friction onboarding.
 */
export async function registerAgent(opts?: RegisterAgentOpts): Promise<AgentCredentials> {
    const body: Record<string, string> = {
        agent_family: opts?.agentFamily || 'vt-sentinel',
        agent_version: opts?.agentVersion || '0.2.0',
        display_name: opts?.displayName || 'VT Sentinel',
    };
    if (opts?.humanAlias) body.human_alias = opts.humanAlias;
    if (opts?.defineYourSelf) body.define_your_self = opts.defineYourSelf;
    if (opts?.contactEmail) body.contact_email = opts.contactEmail;

    const resp = await axios.post(`${VTAI_API_URL}/agents/register`, body, { timeout: HTTP_TIMEOUT_MS });
    return {
        agentId: resp.data.agent_id,
        agentToken: resp.data.agent_token,
        publicHandle: resp.data.public_handle,
        registeredAt: new Date().toISOString(),
    };
}

// --- Helpers ---

export function calculateSHA256(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
        const hash = crypto.createHash('sha256');
        const stream = fs.createReadStream(filePath);
        stream.on('data', (data: string | Buffer) => hash.update(data));
        stream.on('end', () => resolve(hash.digest('hex')));
        stream.on('error', reject);
    });
}

// --- VT API Client (dual-mode: standard VT or VTAI) ---

export class VTApiClient {
    private apiKey: string;
    private baseUrl: string;
    private vtai: boolean;
    private retryAt: Record<QuotaOperation, number> = { query: 0, upload: 0 };

    constructor(apiKey: string, useVtai: boolean = false) {
        this.apiKey = apiKey;
        this.vtai = useVtai;
        this.baseUrl = useVtai ? VTAI_API_URL : VT_API_URL;
    }

    private headers() {
        return { 'x-apikey': this.apiKey };
    }

    /** Fail immediately before entering a caller's request queue or making I/O. */
    assertAvailable(operation: QuotaOperation): void {
        const deadline = this.retryAt[this.vtai ? operation : 'query'];
        if (Date.now() < deadline) throw new VTRateLimitError(deadline);
    }

    private requestFailed(error: unknown, operation: QuotaOperation): never {
        if (axios.isAxiosError(error) && error.response?.status === 429) {
            const bucket = this.vtai ? operation : 'query';
            this.retryAt[bucket] = Math.max(this.retryAt[bucket], retryDeadline(error, Date.now()));
            // The original Axios error can include credentials, request bytes and server text.
            throw new VTRateLimitError(this.retryAt[bucket]);
        }
        throw error;
    }

    /**
     * Lookup a file hash in VirusTotal.
     * Returns full report including AI results if available, or null if not found.
     * Handles both standard VT and VTAI response formats.
     */
    async checkHash(hash: string): Promise<VTReport | null> {
        if (!/^[a-fA-F0-9]{32,128}$/.test(hash)) {
            throw new Error(`Invalid hash: expected 32-128 hex characters, got "${hash.substring(0, 20)}${hash.length > 20 ? '...' : ''}"`);
        }
        this.assertAvailable('query');

        try {
            const resp = await axios.get(`${this.baseUrl}/files/${hash}`, {
                headers: this.headers(),
                timeout: HTTP_TIMEOUT_MS,
            });

            const report = this.vtai
                ? this.parseVtaiReport(resp.data)
                : this.parseStandardReport(resp.data);
            if (hash.length === 64 && report.hash.toLowerCase() !== hash.toLowerCase()) {
                throw new Error('Invalid VirusTotal report response.');
            }
            return report;
        } catch (err: any) {
            if (axios.isAxiosError(err) && err.response?.status === 404) {
                return null;
            }
            return this.requestFailed(err, 'query');
        }
    }

    /**
     * Parse standard VT API response (data.attributes.*)
     */
    private parseStandardReport(data: any): VTReport {
        const attrs = data?.data?.attributes;
        const stats = reportStats(data?.data?.id, attrs?.last_analysis_stats);

        const report: VTReport = {
            hash: data.data.id,
            stats,
            name: attrs.meaningful_name,
            vtLink: `https://www.virustotal.com/gui/file/${data.data.id}`,
        };

        report.crowdsourcedAiResults = aiResults(attrs.crowdsourced_ai_results);

        return report;
    }

    /**
     * Parse VTAI simplified response (data.* without attributes wrapper)
     */
    private parseVtaiReport(data: any): VTReport {
        const fileData = data?.data;
        const stats = reportStats(fileData?.id, fileData?.last_analysis_stats);

        const report: VTReport = {
            hash: fileData.id,
            stats,
            name: fileData.type_description,
            vtLink: `https://www.virustotal.com/gui/file/${fileData.id}`,
        };

        report.crowdsourcedAiResults = aiResults(fileData.ai_insights);

        return report;
    }

    /**
     * Upload a file to VirusTotal for analysis.
     * Standard VT: supports large files (>32MB) via upload_url endpoint.
     * VTAI: max 32MB, no large file support.
     */
    async uploadFile(filePath: string): Promise<VTUploadResult> {
        this.assertAvailable('upload');
        const stat = fs.statSync(filePath);
        const sizeMb = stat.size / (1024 * 1024);

        if (this.vtai && sizeMb > 32) {
            throw new Error(`File too large for VTAI (${sizeMb.toFixed(1)}MB > 32MB). Configure your own VT API key for large file uploads.`);
        }

        let uploadUrl = `${this.baseUrl}/files/`;
        let stream: fs.ReadStream | undefined;
        try {
            if (sizeMb > 32) {
                const urlResp = await axios.get(`${this.baseUrl}/files/upload_url`, {
                    headers: this.headers(),
                    timeout: HTTP_TIMEOUT_MS,
                });
                uploadUrl = urlResp.data.data;
            }

            this.assertAvailable('upload');
            const form = new FormData();
            stream = fs.createReadStream(filePath);
            form.append('file', stream);
            if (this.vtai) {
                form.append('agent_comments', 'Auto-scanned by VT Sentinel for OpenClaw');
            }

            const resp = await axios.post(uploadUrl, form, {
                headers: {
                    ...form.getHeaders(),
                    ...this.headers(),
                },
                maxContentLength: Infinity,
                maxBodyLength: Infinity,
                timeout: HTTP_TIMEOUT_MS * 4, // 120s for uploads (large files)
            });

            return {
                analysisId: resp.data.data.id,
                message: `File uploaded. Analysis ID: ${resp.data.data.id}`,
            };
        } catch (error) {
            return this.requestFailed(error, 'upload');
        } finally {
            stream?.destroy();
        }
    }

}
