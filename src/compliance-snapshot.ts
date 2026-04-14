/**
 * Compliance snapshot — the single source of truth that describes, in
 * structured form, what VT Sentinel reads, writes, sends, and where it keeps
 * its state.
 *
 * Consumed by three call sites:
 *   1. `registerSecurityAuditCollector` — maps the snapshot to
 *      `SecurityAuditFinding[]` so `openclaw security audit --deep` can
 *      display it.
 *   2. `vt_sentinel_status` — renders a "Compliance / Data Flow" block from
 *      the same data, so end users see the same picture the audit does.
 *   3. Tests — assert the snapshot shape against mock configurations.
 *
 * This module is a pure function with no module-level side effects. Optional
 * file-mode info can be collected by the caller via `collectLogModes()` and
 * passed in; when absent, the snapshot simply omits permission checks.
 */

import * as fs from 'fs';
import * as path from 'path';
import { ConfigManager } from './config-manager';
import type { FullConfig, BlockMode, NotifyLevel, PresetName, AgentMetadataMode } from './config-manager';
import type { SensitiveFilePolicy } from './scanner';

// --- Public types ---

export type CredentialMode = 'user_key' | 'vtai' | 'none';

export interface LogFileMode {
    path: string;
    exists: boolean;
    mode?: string;          // octal string, e.g. "0600" — undefined if exists=false
    ownerPrivate: boolean;  // true if mode is 0600/0700 or better (no group/other read)
}

export interface LogModesInfo {
    auditDir: LogFileMode;
    uploadsLog: LogFileMode;
    detectionsLog: LogFileMode;
    credentialsFile: LogFileMode;
    stateFile: LogFileMode;
}

export interface ComplianceSnapshotInput {
    config: FullConfig;
    stateDir: string;
    credentialMode: CredentialMode;
    watchDirs: string[];
    agentPublicHandle?: string;
    /** Optional: pre-collected log permission info (see `collectLogModes`). */
    logModes?: LogModesInfo;
    /**
     * Where the snapshot is being built from. `runtime` means the gateway is
     * running and `watchDirs` reflects the live watcher state (including
     * auto-derived dirs like `/tmp`, `~/Downloads`, OpenClaw state subdirs).
     * `static` means the snapshot is being built by a fresh CLI process
     * (e.g. `openclaw security audit --deep`) that cannot see auto-derived
     * dirs — only the user-configured `config.watchDirs` entries.
     * Defaults to `static`.
     */
    source?: 'runtime' | 'static';
}

export interface ComplianceSnapshot {
    // Structured description (consumed by status rendering + tests)
    credentialMode: CredentialMode;
    endpoints: {
        virustotal: boolean;        // true in user_key mode
        virustotalAi: boolean;      // true in vtai mode
        /** npm registry only consulted from the explicit vt_sentinel_update tool */
        npm: 'on-demand-only';
        /** ClawHub only consulted from the explicit vt_sentinel_update tool */
        clawhub: 'on-demand-only';
    };
    policies: {
        autoScan: boolean;
        sensitiveFilePolicy: SensitiveFilePolicy;
        semanticFilePolicy: SensitiveFilePolicy;
        blockMode: BlockMode;
        notifyLevel: NotifyLevel;
        preset: PresetName;
        maxFileSizeMb: number;
        showCleanScanLogs: boolean;
    };
    watchDirs: string[];
    excludeDirs: string[];
    excludeGlobs: string[];
    paths: {
        stateDir: string;
        credentialsFile: string;      // <stateDir>/vt-sentinel-agent.json
        stateFile: string;            // <stateDir>/vt-sentinel-state.json
        auditDir: string;             // <stateDir>/vt-sentinel-audit/
        uploadsLog: string;           // <auditDir>/uploads.log
        detectionsLog: string;        // <auditDir>/detections.log
    };
    identity: {
        /** display name declared to VTAI (either user-set or auto-generated) */
        displayNameSet: boolean;
        humanAliasSet: boolean;
        bioSet: boolean;
        contactEmailSet: boolean;
        metadataMode: AgentMetadataMode;
        publicHandle?: string;        // public, safe to display
    };
    logModes?: LogModesInfo;

    // Findings ready to be emitted by the audit collector or rendered in status.
    // `baseline` are always-emitted info-level entries describing what the plugin
    // does. `risks` are warn-level entries triggered by specific config.
    baseline: AuditFinding[];
    risks: AuditFinding[];
}

export interface AuditFinding {
    checkId: string;
    severity: 'info' | 'warn' | 'critical';
    title: string;
    detail: string;
    remediation?: string;
}

// --- Core paths helper (pure) ---

export function computePaths(stateDir: string): ComplianceSnapshot['paths'] {
    const auditDir = path.join(stateDir, 'vt-sentinel-audit');
    return {
        stateDir,
        credentialsFile: path.join(stateDir, 'vt-sentinel-agent.json'),
        stateFile: path.join(stateDir, 'vt-sentinel-state.json'),
        auditDir,
        uploadsLog: path.join(auditDir, 'uploads.log'),
        detectionsLog: path.join(auditDir, 'detections.log'),
    };
}

// --- Log-mode collector (optional, I/O) ---

/**
 * Stat the log files + state files + audit dir to record their permissions.
 * Safe to call even if none of them exist yet (returns `exists: false`).
 */
export function collectLogModes(stateDir: string): LogModesInfo {
    const p = computePaths(stateDir);
    return {
        auditDir: statMode(p.auditDir, true),
        uploadsLog: statMode(p.uploadsLog, false),
        detectionsLog: statMode(p.detectionsLog, false),
        credentialsFile: statMode(p.credentialsFile, false),
        stateFile: statMode(p.stateFile, false),
    };
}

function statMode(fsPath: string, isDir: boolean): LogFileMode {
    try {
        const st = fs.statSync(fsPath);
        const modeBits = st.mode & 0o777;
        const mode = modeBits.toString(8).padStart(isDir ? 3 : 3, '0');
        // Owner-private means: no group-read AND no other-read
        // For dirs we also want no group-exec/other-exec.
        const ownerPrivate = (modeBits & 0o077) === 0;
        return { path: fsPath, exists: true, mode, ownerPrivate };
    } catch {
        // Missing file / dir is fine — the plugin creates it lazily on first
        // write with {mode: 0o600}/{mode: 0o700} from v0.12.0 onwards, so a
        // non-existent log is implicitly "private once it exists".
        return { path: fsPath, exists: false, ownerPrivate: true };
    }
}

// --- Risk detection (pure helpers) ---

/** A watch dir is "risky" if it's close to the filesystem root or a whole user profile. */
function isBroadWatchDir(dir: string): boolean {
    if (!dir) return false;
    // Root '/' must be handled before trimming the trailing separator.
    if (dir === '/' || /^[A-Za-z]:[\\/]?$/.test(dir)) return true;
    const norm = dir.replace(/[\\/]+$/, ''); // trim trailing separator
    // Unix near-root
    if (['/home', '/Users'].includes(norm)) return true;
    // Exact $HOME (common mistake — scans user profile including dotfiles).
    // $HOME cannot be resolved here without I/O; instead treat paths that end
    // with just the user directory segment as broad.
    // Heuristic: directory depth 2 or less (e.g. /Users/foo, /home/foo, /root).
    const parts = norm.split(/[\\/]/).filter(Boolean);
    if (parts.length <= 2 && /^(Users|home|root)$/.test(parts[0] ?? '')) return true;
    // Windows user dir at depth 2 (e.g. C:\Users\foo)
    if (parts.length === 3 && /^[A-Za-z]:$/.test(parts[0] ?? '') && parts[1]?.toLowerCase() === 'users') return true;
    return false;
}

// --- Main builder ---

/**
 * Build the compliance snapshot. Pure function — no I/O.
 * Callers that want log-permission info should call `collectLogModes(stateDir)`
 * first and pass the result as `input.logModes`.
 */
export function buildComplianceSnapshot(input: ComplianceSnapshotInput): ComplianceSnapshot {
    const { config, stateDir, credentialMode, watchDirs, agentPublicHandle, logModes } = input;
    const source: 'runtime' | 'static' = input.source ?? 'static';
    const paths = computePaths(stateDir);

    const identity: ComplianceSnapshot['identity'] = {
        displayNameSet: !!config.agentDisplayName,
        humanAliasSet: !!config.agentHumanAlias,
        bioSet: !!config.agentBio,
        contactEmailSet: !!config.agentContactEmail,
        metadataMode: config.agentMetadataMode ?? 'minimal',
        publicHandle: agentPublicHandle,
    };

    const baseline: AuditFinding[] = [];
    const risks: AuditFinding[] = [];

    // --- Baseline info findings (what the plugin does) ---

    baseline.push({
        checkId: 'vt-sentinel.credential-mode',
        severity: 'info',
        title: `Credential mode: ${credentialMode}`,
        detail:
            credentialMode === 'user_key'
                ? 'Using a user-provided VirusTotal API key from plugin config. All scans go to www.virustotal.com.'
                : credentialMode === 'vtai'
                    ? 'Using an auto-registered VTAI agent token (zero-config). All scans go to ai.virustotal.com.'
                    : 'No credentials active. Scanner disabled until a config apiKey is set or VTAI auto-registration completes.',
    });

    baseline.push({
        checkId: 'vt-sentinel.endpoints',
        severity: 'info',
        title: 'Network endpoints contacted',
        detail:
            (credentialMode === 'user_key' ? 'www.virustotal.com (scan requests)\n' : '') +
            (credentialMode === 'vtai' ? 'ai.virustotal.com (scan requests)\n' : '') +
            'registry.npmjs.org + clawhub.ai — only when the user explicitly invokes vt_sentinel_update.',
    });

    // Auto-scan finding. Detail text branches on (a) whether autoScan is on
    // and (b) whether we're building the snapshot at runtime (live watcher
    // list available) or statically (CLI audit process — only config.watchDirs
    // is visible; auto-derived dirs like /tmp/Downloads/Desktop/OpenClaw state
    // subdirs are computed by the gateway at runtime and cannot be recovered
    // here).
    const autoScanDetail = (() => {
        if (!config.autoScan) {
            return `Active protection hooks remain registered (block mode: ${config.blockMode}) but no background watcher is running.`;
        }
        const suffix = ` block mode: ${config.blockMode}. notify level: ${config.notifyLevel}.`;
        if (source === 'runtime') {
            return `Watching ${watchDirs.length} director${watchDirs.length === 1 ? 'y' : 'ies'}.${suffix}`;
        }
        // Static/CLI snapshot.
        if (watchDirs.length > 0) {
            return `User-configured watch dirs (${watchDirs.length}): ${watchDirs.join(', ')}. ` +
                   `Additional dirs auto-derived at gateway runtime (OS temp, ~/Downloads, ~/Desktop, OpenClaw state subdirs, workspace). ` +
                   `Run vt_sentinel_status inside the gateway for the live list.${suffix}`;
        }
        return `No user-configured watch dirs. At runtime the gateway auto-derives monitors from OS temp, ~/Downloads, ~/Desktop, and the OpenClaw state subdirs (skills, extensions, hooks, workspace). ` +
               `Run vt_sentinel_status inside the gateway for the live list.${suffix}`;
    })();

    baseline.push({
        checkId: 'vt-sentinel.auto-scan',
        severity: 'info',
        title: `Auto-scan: ${config.autoScan ? 'enabled' : 'disabled'}`,
        detail: autoScanDetail,
    });

    baseline.push({
        checkId: 'vt-sentinel.upload-policies',
        severity: 'info',
        title: 'Upload policies',
        detail:
            `sensitive (PDF/Office/unknown archives): ${config.sensitiveFilePolicy}\n` +
            `semantic (SKILL.md, HOOK.md, AGENTS.md, etc.): ${config.semanticFilePolicy}\n` +
            `preset: ${config.configPreset}, maxFileSizeMb: ${config.maxFileSizeMb}`,
    });

    baseline.push({
        checkId: 'vt-sentinel.state-paths',
        severity: 'info',
        title: 'State and log file paths',
        detail:
            `credentials: ${paths.credentialsFile} (0o600)\n` +
            `runtime state: ${paths.stateFile}\n` +
            `audit logs: ${paths.auditDir} (uploads.log, detections.log, target 0o600)`,
    });

    baseline.push({
        checkId: 'vt-sentinel.identity-metadata',
        severity: 'info',
        title: `VTAI identity metadata: ${identity.metadataMode}`,
        detail:
            `displayName set: ${identity.displayNameSet}\n` +
            `humanAlias set: ${identity.humanAliasSet}\n` +
            `bio set: ${identity.bioSet}\n` +
            `contactEmail set: ${identity.contactEmailSet}` +
            (identity.publicHandle ? `\npublic handle: ${identity.publicHandle}` : ''),
    });

    // --- Risk flags (warnings) ---

    if (credentialMode === 'none') {
        risks.push({
            checkId: 'vt-sentinel.no-credentials',
            severity: 'warn',
            title: 'No active VirusTotal credentials',
            detail: 'The plugin is loaded but cannot run scans until credentials are configured or VTAI auto-registration succeeds.',
            remediation: 'Either invoke any scan tool to trigger VTAI auto-registration, or set plugins.entries.openclaw-plugin-vt-sentinel.config.apiKey via `openclaw config set`.',
        });
    }

    if (config.sensitiveFilePolicy === 'always_upload') {
        risks.push({
            checkId: 'vt-sentinel.always-upload-sensitive',
            severity: 'warn',
            title: 'Sensitive files auto-uploaded without consent',
            detail: 'sensitiveFilePolicy=always_upload means PDFs, Office docs, and unknown archives are sent to VirusTotal with no per-file prompt.',
            remediation: 'Switch to `ask`, `ask_once`, or `hash_only` via vt_sentinel_configure.',
        });
    }

    if (config.semanticFilePolicy === 'always_upload') {
        risks.push({
            checkId: 'vt-sentinel.always-upload-semantic',
            severity: 'warn',
            title: 'Instruction files auto-uploaded without consent',
            detail: 'semanticFilePolicy=always_upload means SKILL.md, HOOK.md, AGENTS.md, etc. are sent to VirusTotal with no per-file prompt. These often contain private operational data.',
            remediation: 'Switch to `hash_only` (recommended default) or `ask` via vt_sentinel_configure.',
        });
    }

    const broadDirs = watchDirs.filter(isBroadWatchDir);
    if (broadDirs.length > 0) {
        risks.push({
            checkId: 'vt-sentinel.broad-watch-dirs',
            severity: 'warn',
            title: 'Very broad directory under watch',
            detail: `Watching: ${broadDirs.join(', ')}. A root-level or whole-profile watcher can generate noisy scan traffic and increases the blast radius of upload policies.`,
            remediation: 'Narrow watchDirs to specific project / download folders via vt_sentinel_configure.',
        });
    }

    if (config.agentContactEmail) {
        risks.push({
            checkId: 'vt-sentinel.contact-email-shared',
            severity: 'warn',
            title: 'Contact email shared with VTAI',
            detail: 'agentContactEmail is set, so the address is sent to VTAI on agent registration. This is your choice but worth surfacing explicitly.',
            remediation: 'Remove agentContactEmail from config if you prefer no PII in the VTAI registration.',
        });
    }

    if (!config.autoScan && config.blockMode === 'quarantine') {
        risks.push({
            checkId: 'vt-sentinel.passive-with-quarantine',
            severity: 'warn',
            title: 'Quarantine mode active without auto-scan',
            detail: 'blockMode=quarantine will isolate files matched by the blocklist, but autoScan=false means new files are not proactively scanned. Threats not yet in the blocklist will not be caught.',
            remediation: 'Either enable autoScan or switch blockMode to `log_only`/`block_only` to align the posture.',
        });
    }

    if (logModes) {
        const nonPrivate: string[] = [];
        if (logModes.credentialsFile.exists && !logModes.credentialsFile.ownerPrivate) nonPrivate.push(`credentials (${logModes.credentialsFile.mode})`);
        if (logModes.stateFile.exists && !logModes.stateFile.ownerPrivate) nonPrivate.push(`state (${logModes.stateFile.mode})`);
        if (logModes.uploadsLog.exists && !logModes.uploadsLog.ownerPrivate) nonPrivate.push(`uploads.log (${logModes.uploadsLog.mode})`);
        if (logModes.detectionsLog.exists && !logModes.detectionsLog.ownerPrivate) nonPrivate.push(`detections.log (${logModes.detectionsLog.mode})`);
        if (logModes.auditDir.exists && !logModes.auditDir.ownerPrivate) nonPrivate.push(`audit dir (${logModes.auditDir.mode})`);
        if (nonPrivate.length > 0) {
            risks.push({
                checkId: 'vt-sentinel.logs-not-private',
                severity: 'warn',
                title: 'State or log files are not owner-private',
                detail: `The following files permit group/other read: ${nonPrivate.join(', ')}. Credentials and detection history should be 0o600 (files) / 0o700 (dirs).`,
                remediation: 'On POSIX, run `chmod 600` on the files and `chmod 700` on the audit dir. New files created by this plugin (v0.12.0+) are already 0o600 on creation.',
            });
        }
    }

    return {
        credentialMode,
        endpoints: {
            virustotal: credentialMode === 'user_key',
            virustotalAi: credentialMode === 'vtai',
            npm: 'on-demand-only',
            clawhub: 'on-demand-only',
        },
        policies: {
            autoScan: config.autoScan,
            sensitiveFilePolicy: config.sensitiveFilePolicy,
            semanticFilePolicy: config.semanticFilePolicy,
            blockMode: config.blockMode,
            notifyLevel: config.notifyLevel,
            preset: config.configPreset,
            maxFileSizeMb: config.maxFileSizeMb,
            showCleanScanLogs: config.showCleanScanLogs,
        },
        watchDirs: [...watchDirs],
        excludeDirs: [...(config.excludeDirs ?? [])],
        excludeGlobs: [...(config.excludeGlobs ?? [])],
        paths,
        identity,
        logModes,
        baseline,
        risks,
    };
}

// --- Static (module-level) security audit collector ---
//
// The OpenClaw `security audit --deep` CLI runs in a fresh process that
// does NOT share state with the gateway. It therefore reads
// `securityAuditCollectors` from the plugin's module-level definition, NOT
// from runtime `api.registerSecurityAuditCollector(...)` calls.
//
// This function is the canonical collector used by the CLI. It derives the
// same snapshot as the gateway-side collector, but exclusively from the
// audit context (ctx.config, ctx.stateDir, ctx.configPath) — no closure
// state, no cross-module shared variables. Everything is reconstructable
// from the context the CLI provides.
//
// Differences from the gateway-side invocation:
//   - `watchDirs` only includes user-configured dirs (`cfg.watchDirs`); the
//     auto-derived dirs (tmp, ~/Downloads, etc.) are a runtime concept.
//   - `credentialMode` is inferred from (a) presence of `cfg.apiKey` and
//     (b) presence of the persisted agent credentials file on disk.

const PLUGIN_ID = 'openclaw-plugin-vt-sentinel';

interface AuditCollectorCtx {
    config: any;
    sourceConfig: any;
    env: NodeJS.ProcessEnv;
    stateDir: string;
    configPath: string;
}

function extractPluginConfig(cfg: any): Record<string, unknown> | null {
    try {
        return cfg?.plugins?.entries?.[PLUGIN_ID]?.config ?? null;
    } catch { return null; }
}

function readAgentPublicHandle(stateDir: string): string | undefined {
    try {
        const raw = fs.readFileSync(path.join(stateDir, 'vt-sentinel-agent.json'), 'utf-8');
        const parsed = JSON.parse(raw);
        return typeof parsed?.publicHandle === 'string' ? parsed.publicHandle : undefined;
    } catch { return undefined; }
}

function credentialsFileExists(stateDir: string): boolean {
    try { return fs.statSync(path.join(stateDir, 'vt-sentinel-agent.json')).isFile(); }
    catch { return false; }
}

/**
 * Static security-audit collector. Pass this to OpenClaw via the plugin's
 * module-level default export (`securityAuditCollectors: [vtSentinelAuditCollector]`).
 */
export function vtSentinelAuditCollector(ctx: AuditCollectorCtx): AuditFinding[] {
    try {
        const staticCfg = extractPluginConfig(ctx.config) ?? extractPluginConfig(ctx.sourceConfig);
        const cm = new ConfigManager(staticCfg as any);
        const eff = cm.getEffective();

        const hasUserKey = typeof staticCfg?.['apiKey'] === 'string' && (staticCfg['apiKey'] as string).trim().length > 0;
        const hasCachedVtai = credentialsFileExists(ctx.stateDir);
        const credentialMode: CredentialMode = hasUserKey ? 'user_key' : (hasCachedVtai ? 'vtai' : 'none');

        const watchDirs = Array.isArray(eff.watchDirs) ? [...eff.watchDirs] : [];
        const snap = buildComplianceSnapshot({
            config: eff,
            stateDir: ctx.stateDir,
            credentialMode,
            watchDirs,
            agentPublicHandle: readAgentPublicHandle(ctx.stateDir),
            logModes: collectLogModes(ctx.stateDir),
        });
        return [...snap.baseline, ...snap.risks];
    } catch (err: any) {
        return [{
            checkId: 'vt-sentinel.audit-collector-error',
            severity: 'warn',
            title: 'VT Sentinel compliance snapshot failed to build',
            detail: `Collector threw while assembling audit findings: ${err?.message || String(err)}`,
        }];
    }
}
