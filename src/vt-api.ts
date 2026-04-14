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

    constructor(apiKey: string, useVtai: boolean = false) {
        this.apiKey = apiKey;
        this.vtai = useVtai;
        this.baseUrl = useVtai ? VTAI_API_URL : VT_API_URL;
    }

    private headers() {
        return { 'x-apikey': this.apiKey };
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

        try {
            const resp = await axios.get(`${this.baseUrl}/files/${hash}`, {
                headers: this.headers(),
                timeout: HTTP_TIMEOUT_MS,
            });

            return this.vtai
                ? this.parseVtaiReport(resp.data)
                : this.parseStandardReport(resp.data);
        } catch (err: any) {
            if (axios.isAxiosError(err) && err.response?.status === 404) {
                return null;
            }
            throw err;
        }
    }

    /**
     * Parse standard VT API response (data.attributes.*)
     */
    private parseStandardReport(data: any): VTReport | null {
        const attrs = data?.data?.attributes;
        if (!attrs) return null;

        const report: VTReport = {
            hash: data.data.id,
            stats: attrs.last_analysis_stats,
            name: attrs.meaningful_name,
            vtLink: `https://www.virustotal.com/gui/file/${data.data.id}`,
        };

        if (attrs.crowdsourced_ai_results && attrs.crowdsourced_ai_results.length > 0) {
            report.crowdsourcedAiResults = attrs.crowdsourced_ai_results.map(
                (r: any) => ({
                    source: r.source,
                    analysis: r.analysis,
                    verdict: r.verdict,
                    id: r.id,
                })
            );
        }

        return report;
    }

    /**
     * Parse VTAI simplified response (data.* without attributes wrapper)
     */
    private parseVtaiReport(data: any): VTReport | null {
        const fileData = data?.data;
        if (!fileData) return null;

        const report: VTReport = {
            hash: fileData.id,
            stats: fileData.last_analysis_stats || { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
            name: fileData.type_description,
            vtLink: `https://www.virustotal.com/gui/file/${fileData.id}`,
        };

        if (fileData.ai_insights && fileData.ai_insights.length > 0) {
            report.crowdsourcedAiResults = fileData.ai_insights.map(
                (r: any) => ({
                    source: r.source,
                    analysis: r.analysis,
                    verdict: r.verdict,
                })
            );
        }

        return report;
    }

    /**
     * Upload a file to VirusTotal for analysis.
     * Standard VT: supports large files (>32MB) via upload_url endpoint.
     * VTAI: max 32MB, no large file support.
     */
    async uploadFile(filePath: string): Promise<VTUploadResult> {
        const stat = fs.statSync(filePath);
        const sizeMb = stat.size / (1024 * 1024);

        if (this.vtai && sizeMb > 32) {
            throw new Error(`File too large for VTAI (${sizeMb.toFixed(1)}MB > 32MB). Configure your own VT API key for large file uploads.`);
        }

        let uploadUrl = `${this.baseUrl}/files/`;

        if (sizeMb > 32) {
            const urlResp = await axios.get(`${this.baseUrl}/files/upload_url`, {
                headers: this.headers(),
                timeout: HTTP_TIMEOUT_MS,
            });
            uploadUrl = urlResp.data.data;
        }

        const form = new FormData();
        form.append('file', fs.createReadStream(filePath));
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
    }

}
