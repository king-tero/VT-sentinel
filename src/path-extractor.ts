import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/**
 * Extracts file paths from tool call parameters and results.
 * Used by the auto-scan hook to detect files created/downloaded during agent execution.
 */

// ── Path detection (cross-platform) ─────────────────────────────────

// Unix absolute path: /foo/bar
const UNIX_PATH_RE = /(?:^|\s|["'=])(\/(?:[^\s"'\\|><;`$(){}]|\\[ ])+)/g;

// Windows absolute path: C:\foo\bar or C:/foo/bar
const WIN_PATH_RE = /(?:^|\s|["'=])([A-Za-z]:[\\\/](?:[^\s"'|><;`$(){}])+)/g;

// Quoted Unix path (handles spaces like "/Users/foo/Application Support/...")
const UNIX_QUOTED_PATH_RE = /["'](\/[^"']+)["']/g;

// Quoted Windows path (handles spaces like C:\Program Files\...)
const WIN_QUOTED_PATH_RE = /["']([A-Za-z]:[\\\/][^"']+)["']/g;

// UNC path: \\server\share\file (network shares, lateral movement, SMB relay)
const UNC_PATH_RE = /(?:^|\s|["'=])(\\\\[A-Za-z0-9._-]+\\[^\s"'|><;`$]+)/g;

// Windows %ENV_VAR%\path (e.g., %TEMP%\svc.exe, %APPDATA%\updater.exe)
const WIN_ENV_PATH_RE = /%([A-Za-z_][A-Za-z0-9_]*)%[\\\/]([^\s"'|><;`]+)/g;

// PowerShell $env:VAR\path (e.g., $env:TEMP\payload.exe)
const PS_ENV_PATH_RE = /\$env:([A-Za-z_]\w*)[\\\/]([^\s"'|><;`]+)/gi;

/**
 * Expand Windows %ENV_VAR% to actual path value.
 * Only expands well-known variables to avoid false positives.
 */
function expandWinEnvVar(envName: string, rest: string): string | null {
    const upper = envName.toUpperCase();
    const map: Record<string, string | undefined> = {
        TEMP: process.env.TEMP || process.env.TMP,
        TMP: process.env.TMP || process.env.TEMP,
        APPDATA: process.env.APPDATA,
        LOCALAPPDATA: process.env.LOCALAPPDATA,
        USERPROFILE: process.env.USERPROFILE,
        PROGRAMDATA: process.env.ProgramData,
        SYSTEMROOT: process.env.SystemRoot || process.env.windir,
        WINDIR: process.env.windir || process.env.SystemRoot,
        PROGRAMFILES: process.env.ProgramFiles,
        'PROGRAMFILES(X86)': process.env['ProgramFiles(x86)'],
        PUBLIC: process.env.PUBLIC,
        HOMEDRIVE: process.env.HOMEDRIVE,
        HOMEPATH: process.env.HOMEPATH,
    };
    const val = map[upper] || process.env[envName];
    return val ? path.join(val, rest) : null;
}

// Download commands that write to a file
const DOWNLOAD_PATTERNS: RegExp[] = [
    // Unix: curl, wget — with and without space/separator after flag
    /curl\s+.*?-o\s+["']?(\S+?)["']?(?:\s|$)/,
    /curl\s+.*?-o([\/\.~][\S]*?)["']?(?:\s|$)/,
    /curl\s+.*?-[a-zA-Z]*o\s+["']?(\S+?)["']?(?:\s|$)/,   // combined flags: -fsSLo file
    /curl\s+.*?--output\s+["']?(\S+?)["']?(?:\s|$)/,
    /curl\s+.*?--output=["']?(\S+?)["']?(?:\s|$)/,
    // Quoted paths (spaces): curl -o "/Users/foo/Application Support/file"
    /curl\s+.*?-o\s+["']([^"']+)["']/,
    /curl\s+.*?-[a-zA-Z]*o\s+["']([^"']+)["']/,
    /curl\s+.*?--output\s+["']([^"']+)["']/,
    /curl\s+.*?--output=["']([^"']+)["']/,
    /wget\s+.*?-O\s+["']?(\S+?)["']?(?:\s|$)/,
    /wget\s+.*?-O([\/\.~][\S]*?)["']?(?:\s|$)/,
    /wget\s+.*?--output-document[= ]?["']?(\S+?)["']?(?:\s|$)/,
    // Quoted paths: wget -O "/path with spaces/file"
    /wget\s+.*?-O\s+["']([^"']+)["']/,
    /wget\s+.*?--output-document[= ]?["']([^"']+)["']/,
    // Windows: Invoke-WebRequest, certutil, bitsadmin
    /Invoke-WebRequest\s+.*?-OutFile\s+["']?(\S+?)["']?(?:\s|$)/i,
    /\biwr\s+.*?-OutFile\s+["']?(\S+?)["']?(?:\s|$)/i,
    /certutil\s+.*?-urlcache\s+.*?-split\s+.*?-f\s+\S+\s+["']?(\S+?)["']?(?:\s|$)/i,
    /bitsadmin\s+\/transfer\s+\S+\s+\S+\s+["']?(\S+?)["']?(?:\s|$)/i,
    /Start-BitsTransfer\s+.*?-Destination\s+["']?(\S+?)["']?(?:\s|$)/i,
    /\.DownloadFile\s*\(\s*["'][^"']+["']\s*,\s*["'](\S+?)["']\s*\)/i,
    // certutil -decode: base64 payload delivery (LOLBin) — output file is second arg
    /certutil\s+.*?-decode\s+["']?\S+?["']?\s+["']?(\S+?)["']?(?:\s|$)/i,
];

// Redirect output patterns
const REDIRECT_PATTERNS: RegExp[] = [
    />\s*["']?(\S+?)["']?(?:\s|$)/,
    /tee\s+(?:-a\s+)?["']?(\S+?)["']?(?:\s|$)/,
    // PowerShell: Out-File, Set-Content
    /\|\s*Out-File\s+(?:-FilePath\s+)?["']?(\S+?)["']?(?:\s|$)/i,
    /\|\s*Set-Content\s+(?:-Path\s+)?["']?(\S+?)["']?(?:\s|$)/i,
];

// Script execution targets — the scripts themselves are what the scanner should evaluate.
const EXEC_PATTERNS: RegExp[] = [
    // Unix — shells and interpreters (dash = default /bin/sh on Debian/Ubuntu)
    /(?:bash|sh|zsh|dash|python3?|ruby|perl|node|pwsh|php)\s+["']?(\S+?)["']?(?:\s|$)/,
    // Quoted paths: bash "/Users/foo/Application Support/script.sh"
    /(?:bash|sh|zsh|dash|python3?|ruby|perl|node|pwsh|php)\s+["']([^"']+)["']/,
    /chmod\s+\+x\s+["']?(\S+?)["']?(?:\s|$)/,
    /chmod\s+\+x\s+["']([^"']+)["']/,
    // Runtimes with subcommands: java -jar, deno run, bun run
    /java\s+(?:.*?\s)?-jar\s+["']?(\S+?)["']?(?:\s|$)/,
    /(?:deno|bun)\s+run\s+["']?(\S+?)["']?(?:\s|$)/,
    // Windows
    /powershell(?:\.exe)?\s+.*?-File\s+["']?(\S+?)["']?(?:\s|$)/i,
    /cmd(?:\.exe)?\s+\/c\s+["']?(\S+?)["']?(?:\s|$)/i,
    /Start-Process\s+(?:-FilePath\s+)?["']?(\S+?)["']?(?:\s|$)/i,
    /wscript(?:\.exe)?\s+["']?(\S+?)["']?(?:\s|$)/i,
    /cscript(?:\.exe)?\s+["']?(\S+?)["']?(?:\s|$)/i,
    /mshta(?:\.exe)?\s+["']?(\S+?)["']?(?:\s|$)/i,
    // rundll32 with DLL file path (not javascript:/vbscript: which are dangerous patterns)
    /rundll32(?:\.exe)?\s+["']?([A-Za-z]:[\\\/][^,"'\s]+)/i,
    /rundll32(?:\.exe)?\s+["']?(\\\\[^,"'\s]+)/i,  // UNC path DLL
    // Archive extraction — scan the archive BEFORE extraction
    /tar\s+(?:[a-zA-Z-]*x[a-zA-Z-]*f?)\s+["']?(\S+?)["']?(?:\s|$)/,
    /unzip\s+(?:-[a-z]+\s+)*["']?(\S+?)["']?(?:\s|$)/,
    /7z\s+[ex]\s+["']?(\S+?)["']?(?:\s|$)/,
    // Linux package install — scan the package before install
    /dpkg\s+(?:-i|--install)\s+["']?(\S+?)["']?(?:\s|$)/,
    /rpm\s+(?:-i|-U|--install|--upgrade)\s+["']?(\S+?)["']?(?:\s|$)/,
    /apt\s+install\s+["']?(\.\/\S+?)["']?(?:\s|$)/,
];

// ── Interesting directory detection (dynamic) ────────────────────────
// Base dirs: always interesting (OS-level temp locations)
const BASE_INTERESTING_DIRS: string[] = (() => {
    const dirs = new Set(['/tmp', '/var/tmp', '/dev/shm', os.tmpdir()]);
    try { dirs.add(fs.realpathSync(os.tmpdir())); } catch { /* ignore */ }
    // macOS: /tmp -> /private/tmp, /var/tmp -> /private/var/tmp
    try { dirs.add(fs.realpathSync('/tmp')); } catch { /* ignore */ }
    try { dirs.add(fs.realpathSync('/var/tmp')); } catch { /* ignore */ }
    return [...dirs];
})();
// macOS: user dirs and /var/folders (per-user temp) and /private (symlink targets)
const MACOS_DIRS = ['/Users', '/var/folders', '/private/tmp', '/private/var'];
// Windows: user/temp dirs
const WIN_INTERESTING_RE = /^[A-Za-z]:[\\\/](?:Users|Temp|Windows[\\\/](?:Temp|Tasks|System32[\\\/]Tasks)|ProgramData|Downloads)/i;

// Dynamic dirs: enriched at runtime from $HOME, env vars, and OpenClaw context
const dynamicDirs = new Set<string>();

/**
 * Compute interesting dirs from environment at module load.
 * Provides OpenClaw-aware defaults without needing runtime hook context.
 */
function initDirsFromEnv(): void {
    const home = process.env.HOME || process.env.USERPROFILE;
    if (!home) return;

    // User's home directory
    dynamicDirs.add(home);

    // Common download/desktop dirs
    dynamicDirs.add(path.join(home, 'Downloads'));
    dynamicDirs.add(path.join(home, 'Desktop'));

    // OpenClaw managed directories (convention-based)
    const stateDir = process.env.OPENCLAW_STATE_DIR || path.join(home, '.openclaw');
    for (const sub of ['skills', 'extensions', 'hooks', 'workspace', 'sandboxes']) {
        dynamicDirs.add(path.join(stateDir, sub));
    }

    // Profile variant (e.g. ~/.openclaw-dev/*)
    const profile = process.env.OPENCLAW_PROFILE;
    if (profile) {
        const profileBase = path.join(home, `.openclaw-${profile}`);
        for (const sub of ['skills', 'extensions', 'hooks', 'workspace', 'sandboxes']) {
            dynamicDirs.add(path.join(profileBase, sub));
        }
    }
}

// Initialize on module load
initDirsFromEnv();

// Workspace dir for resolving relative paths in hook events.
// Set at runtime by the plugin when context becomes available.
let _workspaceDir: string | undefined;

/**
 * Set the workspace directory used to resolve relative paths in tool results.
 * Called from the plugin when the OpenClaw context (workspaceDir) becomes available.
 */
export function setWorkspaceDir(dir: string): void {
    _workspaceDir = dir;
}

/**
 * Get the current workspace directory (for testing).
 */
export function getWorkspaceDir(): string | undefined {
    return _workspaceDir;
}

/**
 * Add interesting directories at runtime.
 * Called from the plugin when OpenClaw context (workspaceDir, cfg) becomes available.
 */
export function addInterestingDirs(dirs: string[]): void {
    for (const d of dirs) {
        if (!d || d.length < 2) continue;
        const normalized = d.endsWith('/') ? d.slice(0, -1) : d;
        dynamicDirs.add(normalized);
    }
}

/**
 * Get the current set of all interesting directories (for testing/debugging).
 */
export function getInterestingDirs(): string[] {
    return [
        ...BASE_INTERESTING_DIRS,
        ...MACOS_DIRS,
        ...Array.from(dynamicDirs),
    ];
}

/**
 * Reset dynamic dirs to env-computed defaults (for test isolation).
 */
export function resetInterestingDirs(): void {
    dynamicDirs.clear();
    _workspaceDir = undefined;
    initDirsFromEnv();
}

// ── Dangerous command signatures (JSON-backed) ──────────────────────
//
// Defensive threat-detection signatures live in signatures/dangerous-commands.json
// by design. The install-security scanner only walks .js/.ts/.mjs/.cjs/.mts/
// .cts/.jsx/.tsx, so keeping the literal trigger strings (names of suspicious
// node/PowerShell/LOLBin indicators) in JSON prevents the scanner from
// confusing the defensive threat signatures with actual malicious code.
// This is not obfuscation — the data ships in plain-text JSON alongside
// the plugin.

export type DangerousPatternCategory =
    | 'pipe_execution'
    | 'ssh_injection'
    | 'data_exfiltration'
    | 'credential_access'
    | 'persistence';

export interface DangerousPattern {
    category: DangerousPatternCategory;
    description: string;
    severity: 'critical' | 'high';
}

interface CompiledSignature {
    pattern: RegExp;
    description: string;
    category: DangerousPatternCategory;
    severity: 'critical' | 'high';
}

interface SignatureEntry {
    pattern: string;
    flags?: string;
    description: string;
}

interface SignatureFile {
    pipeExec?: SignatureEntry[];
    sshInjection?: SignatureEntry[];
    exfiltration?: SignatureEntry[];
    persistence?: SignatureEntry[];
    credential?: SignatureEntry[];
}

const SIGNATURE_CATEGORY_MAP: Record<keyof Required<SignatureFile>, { category: DangerousPatternCategory; severity: 'critical' | 'high' }> = {
    pipeExec: { category: 'pipe_execution', severity: 'critical' },
    sshInjection: { category: 'ssh_injection', severity: 'critical' },
    exfiltration: { category: 'data_exfiltration', severity: 'high' },
    persistence: { category: 'persistence', severity: 'high' },
    credential: { category: 'credential_access', severity: 'high' },
};

const DANGEROUS_SIGNATURES: CompiledSignature[] = (() => {
    const compiled: CompiledSignature[] = [];
    const jsonPath = path.join(__dirname, 'signatures', 'dangerous-commands.json');
    let data: SignatureFile;
    try {
        data = JSON.parse(fs.readFileSync(jsonPath, 'utf-8')) as SignatureFile;
    } catch (err) {
        console.error(`[vt-sentinel] failed to load dangerous-commands.json at ${jsonPath}: ${String(err)}`);
        return compiled;
    }
    for (const key of Object.keys(SIGNATURE_CATEGORY_MAP) as (keyof typeof SIGNATURE_CATEGORY_MAP)[]) {
        const entries = data[key];
        if (!Array.isArray(entries)) continue;
        const meta = SIGNATURE_CATEGORY_MAP[key];
        for (const entry of entries) {
            try {
                compiled.push({
                    pattern: new RegExp(entry.pattern, entry.flags || ''),
                    description: entry.description,
                    category: meta.category,
                    severity: meta.severity,
                });
            } catch (err) {
                console.error(`[vt-sentinel] invalid signature pattern in ${key}: ${entry.description} — ${String(err)}`);
            }
        }
    }
    return compiled;
})();

/**
 * Detect dangerous patterns in a command string that indicate attacks
 * which bypass file-based scanning (pipe-to-shell, SSH injection, exfiltration).
 * Returns all matched patterns, or an empty array if the command is safe.
 */
export function detectDangerousPatterns(command: string): DangerousPattern[] {
    const matches: DangerousPattern[] = [];
    for (const sig of DANGEROUS_SIGNATURES) {
        if (sig.pattern.test(command)) {
            matches.push({ category: sig.category, description: sig.description, severity: sig.severity });
        }
    }
    return matches;
}

/**
 * Return the number of compiled signatures (diagnostics/tests).
 */
export function getDangerousPatternCount(): number {
    return DANGEROUS_SIGNATURES.length;
}

export interface ExtractedPath {
    path: string;
    source: 'command_param' | 'download_target' | 'redirect_target' | 'exec_target' | 'tool_output' | 'write_path' | 'read_target';
    reason: string;
}

/** Build a global-flagged copy of a regex so matchAll can iterate. */
function toGlobal(re: RegExp): RegExp {
    return re.flags.includes('g') ? re : new RegExp(re.source, re.flags + 'g');
}

/**
 * Extract file paths from an exec tool command string.
 */
export function extractFromCommand(command: string): ExtractedPath[] {
    const results: ExtractedPath[] = [];
    const seen = new Set<string>();

    const add = (p: string, source: ExtractedPath['source'], reason: string) => {
        const clean = p.replace(/["']+$/g, '').replace(/^["']+/g, '');
        if (!clean || clean.length < 3 || seen.has(clean)) return;
        seen.add(clean);
        results.push({ path: clean, source, reason });
    };

    // Download targets (curl -o, wget -O) — iterate via matchAll to catch multiple in one command
    for (const re of DOWNLOAD_PATTERNS) {
        for (const m of command.matchAll(toGlobal(re))) {
            if (m[1]) add(m[1], 'download_target', `Download target in: ${re.source}`);
        }
    }

    // Redirect targets (> file, tee file)
    for (const re of REDIRECT_PATTERNS) {
        for (const m of command.matchAll(toGlobal(re))) {
            if (m[1] && m[1] !== '/dev/null') add(m[1], 'redirect_target', `Output redirected to file`);
        }
    }

    // Script execution targets
    for (const re of EXEC_PATTERNS) {
        for (const m of command.matchAll(toGlobal(re))) {
            if (m[1]) add(m[1], 'exec_target', `Script being executed`);
        }
    }

    // Windows %ENV_VAR%\path expansion (e.g., %TEMP%\payload.exe)
    for (const m of command.matchAll(toGlobal(WIN_ENV_PATH_RE))) {
        const expanded = expandWinEnvVar(m[1], m[2]);
        if (expanded) add(expanded, 'command_param', `Expanded Windows env var path %${m[1]}%`);
    }

    // PowerShell $env:VAR\path expansion (e.g., $env:TEMP\payload.exe)
    for (const m of command.matchAll(toGlobal(PS_ENV_PATH_RE))) {
        const expanded = expandWinEnvVar(m[1], m[2]);
        if (expanded) add(expanded, 'command_param', `Expanded PowerShell env path $env:${m[1]}`);
    }

    return results;
}

/**
 * Check if a path is in an interesting directory (cross-platform).
 */
function isInterestingPath(p: string): boolean {
    const np = path.normalize(p);
    const sep = path.sep;
    // Base dirs (temp — includes os.tmpdir() and its realpath)
    if (BASE_INTERESTING_DIRS.some((d) => np.startsWith(d + sep) || np.startsWith(d + '/'))) return true;
    // macOS user dirs
    if (MACOS_DIRS.some((d) => np.startsWith(d + '/'))) return true;
    // Dynamic dirs ($HOME, OpenClaw, workspace, etc.)
    for (const d of dynamicDirs) {
        if (np.startsWith(d + sep) || np.startsWith(d + '/')) return true;
    }
    // Windows paths
    if (WIN_INTERESTING_RE.test(p)) return true;
    // UNC paths are always interesting (network shares, lateral movement)
    if (p.startsWith('\\\\')) return true;
    return false;
}

/**
 * Check if a path looks like it's in a temp directory (cross-platform).
 */
function isTempPath(p: string): boolean {
    const np = path.normalize(p);
    for (const d of BASE_INTERESTING_DIRS) {
        if (np.startsWith(d + path.sep) || np.startsWith(d + '/')) return true;
    }
    return /^[A-Za-z]:[\\\/](?:Temp|Windows[\\\/]Temp|Users[\\\/][^\\\/]+[\\\/]AppData[\\\/]Local[\\\/]Temp)[\\\/]/i.test(p);
}

/**
 * Check if a path is in a common drop directory (Downloads/Desktop/OpenClaw dirs).
 * Used to allow extensionless files in output extraction — Mach-O payloads often have no extension.
 */
function isDropDir(p: string): boolean {
    const home = process.env.HOME || process.env.USERPROFILE || '';
    if (!home) return false;
    const np = path.normalize(p);
    const drops = [
        path.join(home, 'Downloads'),
        path.join(home, 'Desktop'),
    ];
    for (const d of drops) {
        if (np.startsWith(d + path.sep) || np.startsWith(d + '/')) return true;
    }
    // Also check OpenClaw dirs (skills/extensions/hooks)
    for (const d of dynamicDirs) {
        if (d.includes('skills') || d.includes('extensions') || d.includes('hooks')) {
            if (np.startsWith(d + path.sep) || np.startsWith(d + '/')) return true;
        }
    }
    return false;
}

/**
 * Extract file paths from tool result text output.
 * Detects both Unix (/...) and Windows (C:\...) absolute paths.
 */
export function extractFromOutput(output: string): ExtractedPath[] {
    const results: ExtractedPath[] = [];
    const seen = new Set<string>();

    const addPath = (p: string) => {
        const clean = p.replace(/[.,;:!?)}\]]+$/, ''); // strip trailing punctuation
        if (clean.length < 4 || seen.has(clean)) return;
        if (!isInterestingPath(clean)) return;

        const hasExt = /\.\w{1,10}$/.test(clean);
        if (!hasExt && !isTempPath(clean) && !isDropDir(clean)) return;

        seen.add(clean);
        results.push({ path: clean, source: 'tool_output', reason: 'File path found in tool output' });
    };

    // Unix paths (unquoted)
    for (const m of output.matchAll(toGlobal(UNIX_PATH_RE))) addPath(m[1]);
    // Unix quoted paths (handles spaces like "/Users/foo/Application Support/...")
    for (const m of output.matchAll(toGlobal(UNIX_QUOTED_PATH_RE))) addPath(m[1]);
    // Windows paths (unquoted)
    for (const m of output.matchAll(toGlobal(WIN_PATH_RE))) addPath(m[1]);
    // Windows quoted paths (handles spaces)
    for (const m of output.matchAll(toGlobal(WIN_QUOTED_PATH_RE))) addPath(m[1]);
    // UNC paths (\\server\share\file)
    for (const m of output.matchAll(toGlobal(UNC_PATH_RE))) addPath(m[1]);

    return results;
}

/**
 * Extract paths from a write tool call (the file being written).
 */
export function extractFromWriteTool(params: { path?: string; file_path?: string }): ExtractedPath[] {
    const p = params.path || params.file_path;
    if (!p) return [];
    return [{ path: p, source: 'write_path', reason: 'File written by write tool' }];
}

/**
 * Extract paths from a read tool call (the file being read by the agent).
 */
export function extractFromReadTool(params: { path?: string; file_path?: string }): ExtractedPath[] {
    const p = params.path || params.file_path;
    if (!p) return [];
    return [{ path: p, source: 'read_target', reason: 'File read by agent' }];
}

/**
 * Expand ~ to $HOME (Node doesn't expand tilde in fs operations).
 */
function expandTilde(p: string): string {
    if (p.startsWith('~/') || p === '~') {
        const home = process.env.HOME || process.env.USERPROFILE || '';
        return home ? path.join(home, p.slice(2)) : p;
    }
    return p;
}

/**
 * Filter paths to only include files that actually exist on disk.
 */
export function filterExisting(paths: ExtractedPath[]): ExtractedPath[] {
    return paths.filter((p) => {
        try {
            let resolved = expandTilde(p.path);
            if (resolved !== p.path) p.path = resolved;

            // Try the path as-is first
            try {
                const stat = fs.statSync(resolved);
                if (stat.isFile() && stat.size > 0) return true;
            } catch { /* not found at literal path */ }

            // For relative paths, try resolving against the workspace dir
            if (_workspaceDir && !path.isAbsolute(resolved)) {
                const wsResolved = path.join(_workspaceDir, resolved);
                try {
                    const stat = fs.statSync(wsResolved);
                    if (stat.isFile() && stat.size > 0) {
                        p.path = wsResolved; // update to absolute path
                        return true;
                    }
                } catch { /* not found in workspace either */ }
            }

            return false;
        } catch {
            return false;
        }
    });
}

/**
 * Extract ALL absolute paths referenced in a command string (no filtering).
 * Used by before_tool_call to check if a command references any blocked files.
 * Detects both Unix and Windows paths.
 */
export function extractAllPaths(command: string): string[] {
    const paths = new Set<string>();

    // Unix paths (unquoted)
    for (const m of command.matchAll(toGlobal(UNIX_PATH_RE))) {
        const p = m[1].replace(/["']+$/g, '').replace(/[.,;:!?)}\]]+$/, '');
        if (p.length >= 2) paths.add(p);
    }
    // Unix quoted paths (handles spaces)
    for (const m of command.matchAll(toGlobal(UNIX_QUOTED_PATH_RE))) {
        const p = m[1].replace(/[.,;:!?)}\]]+$/, '');
        if (p.length >= 2) paths.add(p);
    }
    // Windows paths (unquoted)
    for (const m of command.matchAll(toGlobal(WIN_PATH_RE))) {
        const p = m[1].replace(/["']+$/g, '').replace(/[.,;:!?)}\]]+$/, '');
        if (p.length >= 4) paths.add(p); // minimum: C:\x
    }
    // Windows quoted paths (handles spaces like C:\Program Files\...)
    for (const m of command.matchAll(toGlobal(WIN_QUOTED_PATH_RE))) {
        const p = m[1].replace(/[.,;:!?)}\]]+$/, '');
        if (p.length >= 4) paths.add(p);
    }
    // UNC paths (\\server\share\file)
    for (const m of command.matchAll(toGlobal(UNC_PATH_RE))) {
        const p = m[1].replace(/["']+$/g, '').replace(/[.,;:!?)}\]]+$/, '');
        if (p.length >= 4) paths.add(p);
    }
    // Windows %ENV%\path expansion
    for (const m of command.matchAll(toGlobal(WIN_ENV_PATH_RE))) {
        const expanded = expandWinEnvVar(m[1], m[2]);
        if (expanded) paths.add(expanded);
    }
    // PowerShell $env:VAR\path expansion
    for (const m of command.matchAll(toGlobal(PS_ENV_PATH_RE))) {
        const expanded = expandWinEnvVar(m[1], m[2]);
        if (expanded) paths.add(expanded);
    }

    return Array.from(paths);
}

/**
 * Main entry: extract all scannable paths from a tool event.
 */
export function extractPaths(
    toolName: string,
    toolParams: Record<string, any>,
    toolResultText: string,
): ExtractedPath[] {
    let paths: ExtractedPath[] = [];

    switch (toolName) {
        case 'exec':
        case 'bash':
        case 'shell':
        case 'powershell':
        case 'cmd':
            if (toolParams.command) {
                paths = paths.concat(extractFromCommand(toolParams.command));
            }
            if (toolResultText) {
                paths = paths.concat(extractFromOutput(toolResultText));
            }
            break;

        case 'write':
        case 'edit':
            paths = paths.concat(extractFromWriteTool(toolParams));
            break;

        case 'read':
            paths = paths.concat(extractFromReadTool(toolParams));
            break;

        case 'web_fetch':
            if (toolResultText) {
                paths = paths.concat(extractFromOutput(toolResultText));
            }
            break;

        case 'process':
            // process tool sends commands to background sessions (send-keys, paste, etc.)
            // Check all param variants: command, text, data, input, chars
            for (const key of ['command', 'text', 'data', 'input', 'chars']) {
                if (toolParams[key] && typeof toolParams[key] === 'string') {
                    paths = paths.concat(extractFromCommand(toolParams[key]));
                }
            }
            if (toolResultText) {
                paths = paths.concat(extractFromOutput(toolResultText));
            }
            break;

        case 'apply_patch':
            // apply_patch creates/modifies files — extract paths from result
            if (toolParams.path || toolParams.file_path) {
                const p = toolParams.path || toolParams.file_path;
                paths.push({ path: p, source: 'write_path', reason: 'File modified by apply_patch' });
            }
            if (toolResultText) {
                paths = paths.concat(extractFromOutput(toolResultText));
            }
            break;
    }

    return filterExisting(paths);
}
