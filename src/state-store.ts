import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { ConfigOverrides } from './config-manager';

// --- Types ---

export interface AgentIdentityState {
    autoAgentName?: string;
}

export interface PersistedState {
    version: 2;
    firstRunShown: Record<string, boolean>;
    runtimeOverrides: ConfigOverrides;
    agentIdentity?: AgentIdentityState;
}

const DEFAULT_STATE: PersistedState = {
    version: 2,
    firstRunShown: {},
    runtimeOverrides: {},
    agentIdentity: {},
};

// --- StateStore ---

export class StateStore {
    private state: PersistedState;
    private filePath: string;

    constructor(stateDir?: string) {
        const dir = stateDir || process.env.OPENCLAW_STATE_DIR || path.join(os.homedir(), '.openclaw');
        this.filePath = path.join(dir, 'vt-sentinel-state.json');
        this.state = this.load();
    }

    // --- First-run flags ---

    isFirstRunShown(scope?: { workspaceDir?: string; profile?: string }): boolean {
        const key = this.scopeKey(scope);
        return this.state.firstRunShown[key] === true;
    }

    markFirstRunShown(scope?: { workspaceDir?: string; profile?: string }): void {
        const key = this.scopeKey(scope);
        this.state.firstRunShown[key] = true;
        this.save();
    }

    clearFirstRunFlags(): void {
        this.state.firstRunShown = {};
        this.save();
    }

    // --- Runtime overrides ---

    getPersistedOverrides(): ConfigOverrides {
        return { ...this.state.runtimeOverrides };
    }

    persistOverrides(overrides: ConfigOverrides): void {
        this.state.runtimeOverrides = { ...overrides };
        this.save();
    }

    clearPersistedOverrides(): void {
        this.state.runtimeOverrides = {};
        this.save();
    }

    // --- Agent Identity ---

    getAgentIdentity(): AgentIdentityState {
        return { ...(this.state.agentIdentity || {}) };
    }

    setAutoAgentName(name: string): void {
        if (!this.state.agentIdentity) this.state.agentIdentity = {};
        this.state.agentIdentity.autoAgentName = name;
        this.save();
    }

    getAutoAgentName(): string | undefined {
        return this.state.agentIdentity?.autoAgentName;
    }

    // --- Internals ---

    private scopeKey(scope?: { workspaceDir?: string; profile?: string }): string {
        if (scope?.workspaceDir) return `ws:${scope.workspaceDir}`;
        if (scope?.profile) return `profile:${scope.profile}`;
        return 'global';
    }

    private load(): PersistedState {
        try {
            const data = JSON.parse(fs.readFileSync(this.filePath, 'utf-8'));
            if (data && (data.version === 1 || data.version === 2)) {
                return {
                    version: 2,
                    firstRunShown: data.firstRunShown || {},
                    runtimeOverrides: data.runtimeOverrides || {},
                    agentIdentity: data.agentIdentity || {},
                };
            }
        } catch { /* missing or corrupt — use defaults */ }
        return { ...DEFAULT_STATE, firstRunShown: {}, runtimeOverrides: {}, agentIdentity: {} };
    }

    private save(): void {
        try {
            const dir = path.dirname(this.filePath);
            if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
            const tmpPath = this.filePath + '.tmp';
            fs.writeFileSync(tmpPath, JSON.stringify(this.state, null, 2), { mode: 0o600 });
            fs.renameSync(tmpPath, this.filePath);
        } catch { /* best-effort */ }
    }
}
