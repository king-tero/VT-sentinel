import * as path from 'path';
import type { SensitiveFilePolicy } from './scanner';

// --- Types ---

export type NotifyLevel = 'all' | 'threats_only' | 'silent';
export type BlockMode = 'quarantine' | 'block_only' | 'log_only';
export type PresetName = 'balanced' | 'privacy_first' | 'strict_security';
export type AgentMetadataMode = 'minimal' | 'enhanced';

export interface FullConfig {
    // Existing (backward-compatible)
    apiKey?: string;
    watchDirs: string[];
    autoScan: boolean;
    maxFileSizeMb: number;
    sensitiveFilePolicy: SensitiveFilePolicy;
    semanticFilePolicy: SensitiveFilePolicy;
    // New
    notifyLevel: NotifyLevel;
    excludeDirs: string[];
    excludeGlobs: string[];
    blockMode: BlockMode;
    showCleanScanLogs: boolean;
    configPreset: PresetName;
    // Agent identity
    agentDisplayName?: string;
    agentHumanAlias?: string;
    agentBio?: string;
    agentContactEmail?: string;
    agentMetadataMode?: AgentMetadataMode;
}

export type ConfigOverrides = Partial<Omit<FullConfig, 'apiKey'>>;

export interface ConfigDiff {
    scannerNeedsRebuild: boolean;
    watcherNeedsUpdate: boolean;
    changedFields: string[];
}

// --- Presets ---

const PRESETS: Record<PresetName, ConfigOverrides> = {
    balanced: {
        autoScan: true,
        sensitiveFilePolicy: 'ask',
        semanticFilePolicy: 'hash_only',
        maxFileSizeMb: 32,
        notifyLevel: 'all',
        excludeDirs: [],
        excludeGlobs: [],
        blockMode: 'quarantine',
        showCleanScanLogs: true,
        configPreset: 'balanced',
    },
    privacy_first: {
        autoScan: true,
        sensitiveFilePolicy: 'hash_only',
        semanticFilePolicy: 'hash_only',
        maxFileSizeMb: 32,
        notifyLevel: 'threats_only',
        excludeDirs: [],
        excludeGlobs: [],
        blockMode: 'block_only',
        showCleanScanLogs: false,
        configPreset: 'privacy_first',
    },
    strict_security: {
        autoScan: true,
        sensitiveFilePolicy: 'always_upload',
        semanticFilePolicy: 'ask',
        maxFileSizeMb: 64,
        notifyLevel: 'all',
        excludeDirs: [],
        excludeGlobs: [],
        blockMode: 'quarantine',
        showCleanScanLogs: true,
        configPreset: 'strict_security',
    },
};

const BALANCED_DEFAULTS: FullConfig = {
    watchDirs: [],
    autoScan: true,
    maxFileSizeMb: 32,
    sensitiveFilePolicy: 'ask',
    semanticFilePolicy: 'hash_only',
    notifyLevel: 'all',
    excludeDirs: [],
    excludeGlobs: [],
    blockMode: 'quarantine',
    showCleanScanLogs: true,
    configPreset: 'balanced',
};

// --- Static config interface (existing plugin config shape) ---

export interface StaticConfig {
    apiKey?: string;
    watchDirs?: string[];
    autoScan?: boolean;
    maxFileSizeMb?: number;
    sensitiveFilePolicy?: SensitiveFilePolicy;
    semanticFilePolicy?: SensitiveFilePolicy;
    // New fields can also come from static config
    notifyLevel?: NotifyLevel;
    excludeDirs?: string[];
    excludeGlobs?: string[];
    blockMode?: BlockMode;
    showCleanScanLogs?: boolean;
    configPreset?: PresetName;
    // Agent identity
    agentDisplayName?: string;
    agentHumanAlias?: string;
    agentBio?: string;
    agentContactEmail?: string;
    agentMetadataMode?: AgentMetadataMode;
}

// --- Validation ---

const VALID_NOTIFY_LEVELS = new Set<string>(['all', 'threats_only', 'silent']);
const VALID_BLOCK_MODES = new Set<string>(['quarantine', 'block_only', 'log_only']);
const VALID_PRESETS = new Set<string>(['balanced', 'privacy_first', 'strict_security']);
const VALID_SENSITIVE_POLICIES = new Set<string>(['ask', 'ask_once', 'always_upload', 'hash_only']);
const VALID_METADATA_MODES = new Set<string>(['minimal', 'enhanced']);
const DISPLAY_NAME_RE = /^[a-zA-Z0-9 _-]+$/;
const HUMAN_ALIAS_RE = /^[a-zA-Z0-9_-]+$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
/**
 * Check if a resolved path is a dangerous filesystem root.
 * Handles Unix / and any Windows drive letter (C:\, d:/, E:\, etc.) case-insensitively.
 */
export function isDangerousRootPath(resolvedPath: string): boolean {
    const normalized = resolvedPath.replace(/\\/g, '/').toLowerCase();
    return normalized === '/' || /^[a-z]:[\\/]?$/.test(normalized);
}

// Kept for backward compatibility in tests; isDangerousRootPath is the canonical check.
export const DANGEROUS_ROOTS = ['/', 'C:\\', 'C:/', 'D:\\', 'D:/'];

export function validateOverrides(input: Record<string, unknown>): { valid: ConfigOverrides; errors: string[] } {
    const valid: ConfigOverrides = {};
    const errors: string[] = [];

    if ('notifyLevel' in input) {
        if (VALID_NOTIFY_LEVELS.has(input.notifyLevel as string)) {
            valid.notifyLevel = input.notifyLevel as NotifyLevel;
        } else {
            errors.push(`Invalid notifyLevel: "${input.notifyLevel}". Must be: all, threats_only, silent`);
        }
    }

    if ('blockMode' in input) {
        if (VALID_BLOCK_MODES.has(input.blockMode as string)) {
            valid.blockMode = input.blockMode as BlockMode;
        } else {
            errors.push(`Invalid blockMode: "${input.blockMode}". Must be: quarantine, block_only, log_only`);
        }
    }

    if ('configPreset' in input || 'preset' in input) {
        const preset = (input.configPreset || input.preset) as string;
        if (VALID_PRESETS.has(preset)) {
            valid.configPreset = preset as PresetName;
        } else {
            errors.push(`Invalid preset: "${preset}". Must be: balanced, privacy_first, strict_security`);
        }
    }

    if ('sensitiveFilePolicy' in input) {
        if (VALID_SENSITIVE_POLICIES.has(input.sensitiveFilePolicy as string)) {
            valid.sensitiveFilePolicy = input.sensitiveFilePolicy as SensitiveFilePolicy;
        } else {
            errors.push(`Invalid sensitiveFilePolicy: "${input.sensitiveFilePolicy}". Must be: ask, ask_once, always_upload, hash_only`);
        }
    }

    if ('semanticFilePolicy' in input) {
        if (VALID_SENSITIVE_POLICIES.has(input.semanticFilePolicy as string)) {
            valid.semanticFilePolicy = input.semanticFilePolicy as SensitiveFilePolicy;
        } else {
            errors.push(`Invalid semanticFilePolicy: "${input.semanticFilePolicy}". Must be: ask, ask_once, always_upload, hash_only`);
        }
    }

    if ('autoScan' in input) {
        if (typeof input.autoScan === 'boolean') {
            valid.autoScan = input.autoScan;
        } else {
            errors.push(`autoScan must be boolean`);
        }
    }

    if ('maxFileSizeMb' in input) {
        const val = Number(input.maxFileSizeMb);
        if (!isNaN(val) && val > 0 && val <= 650) {
            valid.maxFileSizeMb = val;
        } else {
            errors.push(`maxFileSizeMb must be a number between 1 and 650`);
        }
    }

    if ('showCleanScanLogs' in input) {
        if (typeof input.showCleanScanLogs === 'boolean') {
            valid.showCleanScanLogs = input.showCleanScanLogs;
        } else {
            errors.push(`showCleanScanLogs must be boolean`);
        }
    }

    // Array fields: watchDirs, excludeDirs, excludeGlobs
    for (const field of ['watchDirs', 'excludeDirs'] as const) {
        if (field in input) {
            const arr = input[field];
            if (Array.isArray(arr)) {
                const strings = arr.map((d: unknown) => String(d));
                // Check both raw input and resolved path for dangerous roots
                const dangerous = strings.filter(d => isDangerousRootPath(d) || isDangerousRootPath(path.resolve(d)));
                if (dangerous.length > 0) {
                    errors.push(`${field} contains dangerous root paths: ${dangerous.join(', ')}`);
                } else {
                    (valid as any)[field] = strings.map(d => path.resolve(d));
                }
            } else {
                errors.push(`${field} must be an array of strings`);
            }
        }
    }

    if ('excludeGlobs' in input) {
        if (Array.isArray(input.excludeGlobs)) {
            valid.excludeGlobs = (input.excludeGlobs as string[]).map(String);
        } else {
            errors.push(`excludeGlobs must be an array of strings`);
        }
    }

    // --- Agent identity fields ---
    // Empty string or null clears the field (sets to undefined in overrides).

    if ('agentDisplayName' in input) {
        const v = input.agentDisplayName;
        if (v === '' || v === null) {
            valid.agentDisplayName = undefined;
        } else if (typeof v === 'string' && v.length >= 1 && v.length <= 50 && DISPLAY_NAME_RE.test(v)) {
            valid.agentDisplayName = v;
        } else {
            errors.push('agentDisplayName must be 1-50 chars matching [a-zA-Z0-9 _-] (or empty to clear)');
        }
    }

    if ('agentHumanAlias' in input) {
        const v = input.agentHumanAlias;
        if (v === '' || v === null) {
            valid.agentHumanAlias = undefined;
        } else if (typeof v === 'string' && v.length >= 1 && v.length <= 50 && HUMAN_ALIAS_RE.test(v)) {
            valid.agentHumanAlias = v;
        } else {
            errors.push('agentHumanAlias must be 1-50 chars matching [a-zA-Z0-9_-] (or empty to clear)');
        }
    }

    if ('agentBio' in input) {
        const v = input.agentBio;
        if (v === '' || v === null) {
            valid.agentBio = undefined;
        } else if (typeof v === 'string' && v.length >= 1 && v.length <= 200) {
            valid.agentBio = v;
        } else {
            errors.push('agentBio must be 1-200 chars (or empty to clear)');
        }
    }

    if ('agentContactEmail' in input) {
        const v = input.agentContactEmail;
        if (v === '' || v === null) {
            valid.agentContactEmail = undefined;
        } else if (typeof v === 'string' && v.length <= 100 && EMAIL_RE.test(v)) {
            valid.agentContactEmail = v;
        } else {
            errors.push('agentContactEmail must be a valid email (or empty to clear)');
        }
    }

    if ('agentMetadataMode' in input) {
        const v = input.agentMetadataMode;
        if (v === '' || v === null) {
            valid.agentMetadataMode = undefined;
        } else if (VALID_METADATA_MODES.has(v as string)) {
            valid.agentMetadataMode = v as AgentMetadataMode;
        } else {
            errors.push('agentMetadataMode must be: minimal, enhanced (or empty to clear)');
        }
    }

    return { valid, errors };
}

// --- Glob matcher ---

/**
 * Simple glob matcher for excludeGlobs. Supports * and **.
 * Tests against the full file path.
 */
export function matchGlob(filePath: string, pattern: string): boolean {
    // Escape regex special chars except * and ?
    let re = pattern
        .replace(/[.+^${}()|[\]\\]/g, '\\$&')
        .replace(/\*\*/g, '\u0000')
        .replace(/\*/g, '[^/\\\\]*')
        .replace(/\u0000/g, '.*')
        .replace(/\?/g, '.');
    return new RegExp(`(?:^|[/\\\\])${re}$`).test(filePath);
}

// --- ConfigManager ---

export class ConfigManager {
    private staticConfig: StaticConfig | null;
    private runtimeOverrides: ConfigOverrides = {};
    private effectiveCache: FullConfig | null = null;

    constructor(staticConfig: StaticConfig | null) {
        this.staticConfig = staticConfig;
    }

    getEffective(): FullConfig {
        if (this.effectiveCache) return this.effectiveCache;

        // Layer 1: Start with balanced defaults
        const result: FullConfig = { ...BALANCED_DEFAULTS };

        // Layer 2: Apply preset (from static config or runtime override)
        const presetName = this.runtimeOverrides.configPreset
            || (this.staticConfig as any)?.configPreset
            || 'balanced';
        if (presetName !== 'balanced' && PRESETS[presetName as PresetName]) {
            Object.assign(result, PRESETS[presetName as PresetName]);
        }

        // Layer 3: Overlay static plugin config
        if (this.staticConfig) {
            const s = this.staticConfig;
            if (s.apiKey !== undefined) result.apiKey = s.apiKey;
            if (s.watchDirs !== undefined && s.watchDirs.length > 0) result.watchDirs = s.watchDirs;
            if (s.autoScan !== undefined) result.autoScan = s.autoScan;
            if (s.maxFileSizeMb !== undefined) result.maxFileSizeMb = s.maxFileSizeMb;
            if (s.sensitiveFilePolicy !== undefined) result.sensitiveFilePolicy = s.sensitiveFilePolicy;
            if (s.semanticFilePolicy !== undefined) result.semanticFilePolicy = s.semanticFilePolicy;
            if (s.notifyLevel !== undefined) result.notifyLevel = s.notifyLevel;
            if (s.excludeDirs !== undefined) result.excludeDirs = s.excludeDirs;
            if (s.excludeGlobs !== undefined) result.excludeGlobs = s.excludeGlobs;
            if (s.blockMode !== undefined) result.blockMode = s.blockMode;
            if (s.showCleanScanLogs !== undefined) result.showCleanScanLogs = s.showCleanScanLogs;
            // Identity
            if (s.agentDisplayName !== undefined) result.agentDisplayName = s.agentDisplayName;
            if (s.agentHumanAlias !== undefined) result.agentHumanAlias = s.agentHumanAlias;
            if (s.agentBio !== undefined) result.agentBio = s.agentBio;
            if (s.agentContactEmail !== undefined) result.agentContactEmail = s.agentContactEmail;
            if (s.agentMetadataMode !== undefined) result.agentMetadataMode = s.agentMetadataMode;
        }

        // Layer 4: Overlay runtime overrides
        const o = this.runtimeOverrides;
        if (o.watchDirs !== undefined) result.watchDirs = o.watchDirs;
        if (o.autoScan !== undefined) result.autoScan = o.autoScan;
        if (o.maxFileSizeMb !== undefined) result.maxFileSizeMb = o.maxFileSizeMb;
        if (o.sensitiveFilePolicy !== undefined) result.sensitiveFilePolicy = o.sensitiveFilePolicy;
        if (o.semanticFilePolicy !== undefined) result.semanticFilePolicy = o.semanticFilePolicy;
        if (o.notifyLevel !== undefined) result.notifyLevel = o.notifyLevel;
        if (o.excludeDirs !== undefined) result.excludeDirs = o.excludeDirs;
        if (o.excludeGlobs !== undefined) result.excludeGlobs = o.excludeGlobs;
        if (o.blockMode !== undefined) result.blockMode = o.blockMode;
        if (o.showCleanScanLogs !== undefined) result.showCleanScanLogs = o.showCleanScanLogs;
        if (o.configPreset !== undefined) result.configPreset = o.configPreset;
        // Identity
        if (o.agentDisplayName !== undefined) result.agentDisplayName = o.agentDisplayName;
        if (o.agentHumanAlias !== undefined) result.agentHumanAlias = o.agentHumanAlias;
        if (o.agentBio !== undefined) result.agentBio = o.agentBio;
        if (o.agentContactEmail !== undefined) result.agentContactEmail = o.agentContactEmail;
        if (o.agentMetadataMode !== undefined) result.agentMetadataMode = o.agentMetadataMode;

        this.effectiveCache = result;
        return result;
    }

    applyOverrides(overrides: ConfigOverrides): ConfigDiff {
        const before = this.getEffective();
        // Merge new overrides into existing
        Object.assign(this.runtimeOverrides, overrides);
        this.effectiveCache = null; // invalidate
        const after = this.getEffective();

        return this.computeDiff(before, after);
    }

    loadPersistedOverrides(overrides: ConfigOverrides): void {
        this.runtimeOverrides = { ...overrides };
        this.effectiveCache = null;
    }

    resetOverrides(): void {
        this.runtimeOverrides = {};
        this.effectiveCache = null;
    }

    getRuntimeOverrides(): ConfigOverrides {
        return { ...this.runtimeOverrides };
    }

    private computeDiff(before: FullConfig, after: FullConfig): ConfigDiff {
        const changedFields: string[] = [];
        let scannerNeedsRebuild = false;
        let watcherNeedsUpdate = false;

        for (const key of Object.keys(after) as (keyof FullConfig)[]) {
            const a = JSON.stringify(before[key]);
            const b = JSON.stringify(after[key]);
            if (a !== b) {
                changedFields.push(key);
                if (key === 'sensitiveFilePolicy' || key === 'semanticFilePolicy' || key === 'maxFileSizeMb') {
                    scannerNeedsRebuild = true;
                }
                if (key === 'watchDirs' || key === 'excludeDirs' || key === 'autoScan') {
                    watcherNeedsUpdate = true;
                }
            }
        }

        return { scannerNeedsRebuild, watcherNeedsUpdate, changedFields };
    }
}
