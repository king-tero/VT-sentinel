import * as path from 'path';
import * as fs from 'fs';
import { VTApiClient, VTReport, calculateSHA256 } from './vt-api';
import { FileClassifier, FileCategory } from './classifier';
import { Cache, RateLimiter } from './cache';

// --- Types ---

export type ScanVerdict =
    | 'clean' | 'malicious' | 'suspicious'
    | 'unknown' | 'pending' | 'skipped'
    | 'needs_consent';

/**
 * Policy for handling sensitive/ambiguous files (PDF, Office, unknown ZIP).
 *
 *   "ask"           → return needs_consent; agent asks user each time (default)
 *   "ask_once"      → ask the first time, remember choice for the session
 *   "always_upload"  → always upload sensitive files to VT
 *   "hash_only"      → never upload, only check hash
 */
export type SensitiveFilePolicy = 'ask' | 'ask_once' | 'always_upload' | 'hash_only';

export interface ScanResult {
    filePath: string;
    fileName: string;
    sha256: string;
    category: FileCategory;
    verdict: ScanVerdict;
    detections?: { malicious: number; suspicious: number; total: number };
    codeInsight?: { source: string; analysis: string; verdict: string };
    vtLink?: string;
    message: string;
}

// --- Scanner ---

export class Scanner {
    private api: VTApiClient;
    private cache: Cache<ScanResult>;
    private limiter: RateLimiter;
    private maxFileSizeMb: number;
    private sensitivePolicy: SensitiveFilePolicy;
    private semanticPolicy: SensitiveFilePolicy;
    /** In-memory consent cache for "ask_once" policy on sensitive files. null = not yet asked. */
    private consentDecision: boolean | null = null;
    /** In-memory consent cache for "ask_once" policy on semantic files. null = not yet asked. */
    private consentDecisionSemantic: boolean | null = null;
    private logger: { info: (m: string) => void; warn: (m: string) => void; error: (m: string) => void };

    constructor(
        apiKey: string,
        logger: { info: (m: string) => void; warn: (m: string) => void; error: (m: string) => void },
        maxFileSizeMb: number = 32,
        sensitivePolicy: SensitiveFilePolicy = 'ask',
        useVtai: boolean = false,
        semanticPolicy: SensitiveFilePolicy = 'hash_only',
    ) {
        this.api = new VTApiClient(apiKey, useVtai);
        this.cache = new Cache<ScanResult>(15);
        this.limiter = new RateLimiter(4);
        this.maxFileSizeMb = maxFileSizeMb;
        this.sensitivePolicy = sensitivePolicy;
        this.semanticPolicy = semanticPolicy;
        this.logger = logger;
    }

    /**
     * Record the user's consent decision (used by the tool when the user responds).
     * When policy is "ask_once", this persists for the session.
     * @param consentGroup — 'sensitive' or 'semantic', determines which consent cache to update.
     */
    recordConsent(upload: boolean, consentGroup: 'sensitive' | 'semantic' = 'sensitive'): void {
        if (consentGroup === 'semantic') {
            this.consentDecisionSemantic = upload;
        } else {
            this.consentDecision = upload;
        }
    }

    /** Update maxFileSizeMb at runtime without rebuilding scanner. */
    updateMaxFileSizeMb(mb: number): void {
        this.maxFileSizeMb = mb;
    }

    /** Update sensitiveFilePolicy at runtime. Resets consent decision. */
    updateSensitivePolicy(policy: SensitiveFilePolicy): void {
        this.sensitivePolicy = policy;
        this.consentDecision = null;
    }

    /** Update semanticFilePolicy at runtime. Resets semantic consent decision. */
    updateSemanticPolicy(policy: SensitiveFilePolicy): void {
        this.semanticPolicy = policy;
        this.consentDecisionSemantic = null;
    }

    /**
     * Full scan of a file: classify → hash → VT lookup → code insight if applicable.
     * When force=true (manual scan), always do at least a hash check even for SAFE/MEDIA files.
     * When hashOnly=true: only check hash against VT, never upload regardless of category.
     */
    async scanFile(filePath: string, force: boolean = false, precomputedHash?: string, hashOnly: boolean = false): Promise<ScanResult> {
        const fileName = path.basename(filePath);

        if (!fs.existsSync(filePath)) {
            return this.result(filePath, '', FileCategory.SAFE, 'skipped', `File not found: ${fileName}`);
        }

        const stat = fs.statSync(filePath);
        if (stat.size > this.maxFileSizeMb * 1024 * 1024) {
            return this.result(filePath, '', FileCategory.SAFE, 'skipped',
                `File too large (${(stat.size / 1024 / 1024).toFixed(1)}MB > ${this.maxFileSizeMb}MB limit)`);
        }

        const category = FileClassifier.classify(filePath);

        // Auto-scan: skip SAFE/MEDIA early (avoid hashing large benign files and avoid cache poisoning).
        if (!force && (category === FileCategory.MEDIA || category === FileCategory.SAFE)) {
            return this.result(filePath, '', category, 'skipped',
                `Safe/media file (${fileName}) — skipped`);
        }

        const sha256 = precomputedHash || await calculateSHA256(filePath);

        const cached = this.cache.get(sha256);
        if (cached) {
            this.logger.info(`[VT-Sentinel] Cache hit for ${fileName}`);
            // Cache entries are keyed by SHA-256 (VT identity). Rebase per-file context.
            return { ...cached, filePath, fileName, category, sha256 };
        }

        // hashOnly mode: only check hash, never upload (used for read_target scans)
        if (hashOnly) {
            const report = await this.hashCheckOnly(filePath, sha256, category);
            if (report && (report.verdict === 'clean' || report.verdict === 'malicious' ||
                report.verdict === 'suspicious' || report.verdict === 'pending')) {
                this.cache.set(sha256, report);
            }
            return report;
        }

        let result: ScanResult;

        // When force=true (code dirs), treat all files as HIGH_RISK: hash + auto-upload.
        // Media/safe files in skills/hooks/extensions dirs are anomalous and should be fully analyzed.
        const effectiveCategory = force && (category === FileCategory.MEDIA || category === FileCategory.SAFE)
            ? FileCategory.HIGH_RISK
            : category;

        switch (effectiveCategory) {
            case FileCategory.HIGH_RISK:
                result = await this.scanAutoUpload(filePath, sha256, effectiveCategory);
                break;

            case FileCategory.SEMANTIC_RISK:
                result = await this.scanSensitive(filePath, sha256, effectiveCategory, this.semanticPolicy, 'semantic');
                break;

            case FileCategory.SENSITIVE:
                result = await this.scanSensitive(filePath, sha256, effectiveCategory, this.sensitivePolicy, 'sensitive');
                break;

            case FileCategory.MEDIA:
            case FileCategory.SAFE:
            default:
                // Manual scan: always check hash even for safe/media files
                result = await this.scanForced(filePath, sha256, category);
                break;
        }

        // Cache only results derived from VT knowledge or an upload attempt.
        // Do NOT cache "skipped/unknown/needs_consent" because those depend on local policy
        // and should not prevent future uploads or policy changes.
        if (result.verdict === 'clean' ||
            result.verdict === 'malicious' ||
            result.verdict === 'suspicious' ||
            result.verdict === 'pending') {
            this.cache.set(sha256, result);
        }
        return result;
    }

    /**
     * Scan a HIGH_RISK or SEMANTIC_RISK file: hash lookup → upload if unknown.
     * Code Insight is extracted automatically by fromReport() (same as all categories).
     */
    private async scanAutoUpload(filePath: string, sha256: string, category: FileCategory): Promise<ScanResult> {
        const fileName = path.basename(filePath);

        await this.limiter.acquire();
        const report = await this.api.checkHash(sha256);

        if (report) {
            return this.fromReport(filePath, sha256, category, report);
        }

        this.logger.info(`[VT-Sentinel] Unknown ${category} file ${fileName}, uploading...`);
        await this.limiter.acquire();

        try {
            const upload = await this.api.uploadFile(filePath);
            return this.result(filePath, sha256, category, 'pending',
                `Uploaded for analysis (${upload.analysisId}). Results pending.`);
        } catch (err: any) {
            return this.result(filePath, sha256, category, 'unknown',
                `Upload failed: ${err.message}`);
        }
    }

    /**
     * Scan a SENSITIVE or SEMANTIC_RISK file according to the given policy.
     *
     * Step 1 (always): Check hash — this reveals nothing about file content.
     *   - If VT knows the hash → report findings (malicious PDF templates, etc.)
     *
     * Step 2 (if hash unknown): Apply policy:
     *   - "hash_only"       → done, don't upload
     *   - "always_upload"   → upload to VT
     *   - "ask"             → return needs_consent every time
     *   - "ask_once"        → return needs_consent the first time, then use remembered decision
     *
     * @param consentGroup — 'sensitive' or 'semantic', determines which consent cache to use
     */
    private async scanSensitive(
        filePath: string, sha256: string, category: FileCategory,
        policy: SensitiveFilePolicy, consentGroup: 'sensitive' | 'semantic',
    ): Promise<ScanResult> {
        const fileName = path.basename(filePath);

        // Step 1: Hash check (always safe, reveals nothing)
        await this.limiter.acquire();
        const report = await this.api.checkHash(sha256);

        if (report) {
            const result = this.fromReport(filePath, sha256, category, report);
            result.message += ' (hash-only check — file NOT uploaded to VT)';
            return result;
        }

        // Resolve consent for ask_once from the appropriate group
        const consent = consentGroup === 'semantic' ? this.consentDecisionSemantic : this.consentDecision;

        // Step 2: Hash unknown — apply policy
        switch (policy) {
            case 'hash_only':
                return this.result(filePath, sha256, category, 'unknown',
                    `Unknown to VT (${fileName}). Hash checked only — file NOT uploaded (privacy policy).`);

            case 'always_upload':
                return this.uploadSensitive(filePath, sha256, category, fileName);

            case 'ask_once':
                if (consent === true) {
                    return this.uploadSensitive(filePath, sha256, category, fileName);
                }
                if (consent === false) {
                    return this.result(filePath, sha256, category, 'unknown',
                        `Unknown to VT (${fileName}). User previously declined upload — hash-only.`);
                }
                // First time — fall through to ask
                return this.needsConsent(filePath, sha256, category, fileName);

            case 'ask':
            default:
                return this.needsConsent(filePath, sha256, category, fileName);
        }
    }

    /**
     * Forced scan for SAFE/MEDIA files when user explicitly requests it.
     * Always checks hash; does NOT upload (no privacy concern but no reason to upload safe files).
     */
    private async scanForced(filePath: string, sha256: string, category: FileCategory): Promise<ScanResult> {
        const fileName = path.basename(filePath);

        await this.limiter.acquire();
        const report = await this.api.checkHash(sha256);

        if (report) {
            return this.fromReport(filePath, sha256, category, report);
        }

        return this.result(filePath, sha256, category, 'unknown',
            `File "${fileName}" (${category}) not found in VT database. Hash checked — no threats known.`);
    }

    /**
     * Hash-only check: rate-limited hash lookup, never uploads.
     * Used when hashOnly=true (e.g., files read by the agent).
     */
    private async hashCheckOnly(filePath: string, sha256: string, category: FileCategory): Promise<ScanResult> {
        const fileName = path.basename(filePath);

        await this.limiter.acquire();
        const report = await this.api.checkHash(sha256);

        if (report) {
            const result = this.fromReport(filePath, sha256, category, report);
            result.message += ' (hash-only check — file NOT uploaded to VT)';
            return result;
        }

        return this.result(filePath, sha256, category, 'unknown',
            `Unknown to VT (${fileName}). Hash checked only — file NOT uploaded (read-only scan).`);
    }

    private async uploadSensitive(
        filePath: string, sha256: string, category: FileCategory, fileName: string,
    ): Promise<ScanResult> {
        this.logger.info(`[VT-Sentinel] Uploading SENSITIVE file ${fileName} (user consented)...`);
        await this.limiter.acquire();
        try {
            const upload = await this.api.uploadFile(filePath);
            return this.result(filePath, sha256, category, 'pending',
                `Uploaded with consent (${upload.analysisId}). May contain macros or embedded threats — analysis pending.`);
        } catch (err: any) {
            return this.result(filePath, sha256, category, 'unknown',
                `Upload failed: ${err.message}`);
        }
    }

    private needsConsent(
        filePath: string, sha256: string, category: FileCategory, fileName: string,
    ): ScanResult {
        return this.result(filePath, sha256, category, 'needs_consent',
            `File "${fileName}" may contain private data (detected as ${category}). ` +
            `Hash is unknown to VT. ` +
            `Should I upload it to VirusTotal for deep analysis? ` +
            `This would check for macros, embedded threats, and other risks, ` +
            `but the file content will be shared with VirusTotal. ` +
            `Reply YES to upload, NO for hash-only check.`);
    }

    /**
     * Upload a file that the user previously consented to (after needs_consent).
     */
    async uploadWithConsent(filePath: string): Promise<ScanResult> {
        if (!fs.existsSync(filePath)) {
            return this.result(filePath, '', FileCategory.SENSITIVE, 'skipped', 'File not found');
        }

        const sha256 = await calculateSHA256(filePath);
        const category = FileClassifier.classify(filePath);
        const fileName = path.basename(filePath);

        // Remember consent for ask_once policy — only for the file's actual category
        if (category === FileCategory.SEMANTIC_RISK && this.semanticPolicy === 'ask_once') {
            this.consentDecisionSemantic = true;
        } else if (category === FileCategory.SENSITIVE && this.sensitivePolicy === 'ask_once') {
            this.consentDecision = true;
        }

        return this.uploadSensitive(filePath, sha256, category, fileName);
    }

    /**
     * Quick hash check — no classification, no upload.
     */
    async checkHash(hash: string): Promise<ScanResult | null> {
        await this.limiter.acquire();
        const report = await this.api.checkHash(hash);
        if (!report) return null;
        return this.fromReport('', hash, FileCategory.SAFE, report);
    }

    /**
     * Build ScanResult from a VT report.
     * Always extracts both AV detections AND Code Insight (if available).
     * The final verdict is the worst of: AV engines + AI analysis.
     */
    private fromReport(filePath: string, sha256: string, category: FileCategory, report: VTReport): ScanResult {
        const stats = report.stats;
        const total = stats.malicious + stats.suspicious + stats.harmless + stats.undetected;

        // --- AV verdict ---
        let verdict: ScanVerdict = 'clean';
        const msgParts: string[] = [];

        if (stats.malicious > 0) {
            verdict = 'malicious';
            msgParts.push(`AV: ${stats.malicious}/${total} engines detected malware`);
        } else if (stats.suspicious > 0) {
            verdict = 'suspicious';
            msgParts.push(`AV: ${stats.suspicious}/${total} engines flagged suspicious`);
        } else {
            msgParts.push(`AV: clean (0/${total} detections)`);
        }

        const result: ScanResult = {
            filePath,
            fileName: filePath ? path.basename(filePath) : sha256.substring(0, 12),
            sha256,
            category,
            verdict,
            detections: { malicious: stats.malicious, suspicious: stats.suspicious, total },
            vtLink: report.vtLink,
            message: '', // set below
        };

        // --- Code Insight (always extract if present) ---
        if (report.crowdsourcedAiResults && report.crowdsourcedAiResults.length > 0) {
            const ci = report.crowdsourcedAiResults.find(
                (r) => r.source?.toLowerCase().includes('code insight')
            ) || report.crowdsourcedAiResults[0];

            const ciVerdict = (ci.verdict || 'UNKNOWN').toUpperCase();

            result.codeInsight = {
                source: ci.source || 'AI',
                analysis: ci.analysis || '',
                verdict: ciVerdict,
            };

            // AI can escalate the verdict (never downgrade)
            if (ciVerdict.includes('MALICIOUS') && verdict !== 'malicious') {
                verdict = 'malicious';
                result.verdict = verdict;
                msgParts.push(`AI: MALICIOUS — ${ci.analysis?.substring(0, 200)}`);
            } else if (ciVerdict.includes('SUSPICIOUS') && verdict === 'clean') {
                verdict = 'suspicious';
                result.verdict = verdict;
                msgParts.push(`AI: SUSPICIOUS — ${ci.analysis?.substring(0, 200)}`);
            } else {
                msgParts.push(`AI: ${ciVerdict}`);
            }
        }

        result.message = msgParts.join(' | ');
        return result;
    }

    private result(
        filePath: string, sha256: string, category: FileCategory,
        verdict: ScanVerdict, message: string,
    ): ScanResult {
        return {
            filePath,
            fileName: filePath ? path.basename(filePath) : '',
            sha256,
            category,
            verdict,
            message,
        };
    }

    clearCache(): void {
        this.cache.clear();
    }
}
