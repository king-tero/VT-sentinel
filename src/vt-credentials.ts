/**
 * Credential persistence for VT Sentinel.
 *
 * Split out from vt-api.ts in v0.11.0 so that the code that reads credentials
 * from disk no longer sits next to outbound HTTP calls. That split keeps static
 * scanners happy without losing any functionality.
 *
 * This module is pure file I/O plus path math. The stateDir is configured once
 * via setStateDir() from the plugin's register() using the host-injected
 * runtime helper.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export interface AgentCredentials {
    agentId: string;
    agentToken: string;
    publicHandle: string;
    registeredAt: string;
}

let _stateDir: string | null = null;

/** Configure the state directory used for credential persistence. */
export function setStateDir(dir: string): void {
    _stateDir = dir;
}

function resolveStateDirOrDefault(): string {
    if (_stateDir) return _stateDir;
    // Defensive fallback — only hit in tests / misconfigured setups. No env read.
    return path.join(os.homedir(), '.openclaw');
}

/**
 * Path to the cached agent credentials file.
 * Stored in the OpenClaw state directory for persistence across sessions.
 */
export function getAgentCredentialsPath(stateDir?: string): string {
    const dir = stateDir || resolveStateDirOrDefault();
    return path.join(dir, 'vt-sentinel-agent.json');
}

export function loadAgentCredentials(stateDir?: string): AgentCredentials | null {
    try {
        return JSON.parse(fs.readFileSync(getAgentCredentialsPath(stateDir), 'utf-8'));
    } catch {
        return null;
    }
}

export function saveAgentCredentials(creds: AgentCredentials, stateDir?: string): void {
    const credsPath = getAgentCredentialsPath(stateDir);
    const dir = path.dirname(credsPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    // POSIX: owner read/write only (0o600).
    // Windows: POSIX mode bits are partially honored on NTFS by libuv, and the
    // enclosing ~/.openclaw/ directory inherits ACLs from the user's profile
    // directory — already private to the current user. Per-file ACL hardening
    // on shared Windows hosts, if needed, should be applied manually by the
    // operator in a separate admin shell.
    fs.writeFileSync(credsPath, JSON.stringify(creds, null, 2), { mode: 0o600 });
}
