import * as fs from 'fs';
import * as path from 'path';

/**
 * Simple rotating audit log.
 *
 * Entry format (v0.12.0+): `{ISO-8601}\t{SHA-256}\t{filePath or <sentinel>}\n`.
 * Empty filePath (e.g. EICAR detection from a memory buffer or an extracted
 * archive member whose original path was not surfaced) is recorded as
 * `<in-memory>` so the log stays self-describing.
 *
 * Permissions hardening (v0.12.0+):
 *  - Parent directory is created with mode 0o700 if missing.
 *  - Log file is pre-created with mode 0o600 before the first append so the
 *    owner-only posture doesn't depend on umask.
 *  - Rotations rewrite the file with an explicit mode 0o600.
 *
 * Rotation: when maxLines or maxBytes is exceeded the newest half is kept.
 */
export class AuditLog {
    private logPath: string;
    private maxLines: number;
    private maxBytes: number;
    private lineCount: number = 0;
    private approxSize: number = 0;
    private ensuredPermissions: boolean = false;

    constructor(logPath: string, maxLines: number = 1000, maxBytes: number = 1024 * 1024) {
        this.logPath = logPath;
        this.maxLines = maxLines;
        this.maxBytes = maxBytes;
        this.ensureContainerAndFile();
        this.seedCountersFromDisk();
    }

    /** Ensure parent dir exists at 0o700 and the log file exists at 0o600. */
    private ensureContainerAndFile(): void {
        try {
            const dir = path.dirname(this.logPath);
            if (!fs.existsSync(dir)) {
                fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
            } else {
                // Tighten permissions on the dir if it pre-existed wide-open (best-effort).
                try { fs.chmodSync(dir, 0o700); } catch { /* not a blocker */ }
            }
            if (!fs.existsSync(this.logPath)) {
                // Pre-create empty so the first append doesn't race default umask.
                fs.writeFileSync(this.logPath, '', { mode: 0o600 });
            } else {
                // Tighten permissions on the file if it pre-existed wide-open.
                try { fs.chmodSync(this.logPath, 0o600); } catch { /* not a blocker */ }
            }
            this.ensuredPermissions = true;
        } catch {
            // Best-effort — never crash the plugin for a log setup failure.
            this.ensuredPermissions = false;
        }
    }

    private seedCountersFromDisk(): void {
        try {
            const stat = fs.statSync(this.logPath);
            this.approxSize = stat.size;
            const content = fs.readFileSync(this.logPath, 'utf-8');
            this.lineCount = content.split('\n').filter(l => l.length > 0).length;
        } catch {
            this.lineCount = 0;
            this.approxSize = 0;
        }
    }

    /**
     * Append a record. `filePath` may be empty — in that case we record the
     * `<in-memory>` sentinel so the log doesn't emit an ambiguous trailing tab.
     */
    append(sha256: string, filePath: string): void {
        const displayPath = filePath && filePath.length > 0 ? filePath : '<in-memory>';
        const line = `${new Date().toISOString()}\t${sha256}\t${displayPath}\n`;
        try {
            if (!this.ensuredPermissions) {
                // Container or file didn't exist at construction — retry now.
                this.ensureContainerAndFile();
            }
            fs.appendFileSync(this.logPath, line);
            this.lineCount++;
            this.approxSize += Buffer.byteLength(line);

            if (this.lineCount > this.maxLines || this.approxSize > this.maxBytes) {
                this.rotate();
            }
        } catch { /* best-effort — never crash the plugin for a log write failure */ }
    }

    private rotate(): void {
        try {
            const content = fs.readFileSync(this.logPath, 'utf-8');
            const lines = content.split('\n').filter(l => l.length > 0);
            let keep = lines.slice(-Math.floor(this.maxLines / 2));
            const halfBytes = Math.floor(this.maxBytes / 2);
            while (keep.length > 1) {
                const size = Buffer.byteLength(keep.join('\n') + '\n');
                if (size <= halfBytes) break;
                keep.shift();
            }
            const newContent = keep.join('\n') + '\n';
            // Write with explicit owner-only mode — some Node versions reset
            // the file's mode on writeFileSync with content, so set it again
            // on the original descriptor path.
            fs.writeFileSync(this.logPath, newContent, { mode: 0o600 });
            try { fs.chmodSync(this.logPath, 0o600); } catch { /* ignore */ }
            this.lineCount = keep.length;
            this.approxSize = Buffer.byteLength(newContent);
        } catch { /* best-effort */ }
    }
}

/**
 * Returns the directory for VT Sentinel audit logs.
 *
 * v0.12.0 change: logs now live in a dedicated `<stateDir>/vt-sentinel-audit/`
 * subdirectory (pre-0.12 they were at the stateDir root). The subdir is
 * created at 0o700 on first write.
 *
 * The stateDir must be supplied by the caller (previously fell back to reading
 * the environment; that read has been removed to keep this module free of
 * `process.env` lookups that could co-occur with HTTP clients elsewhere).
 */
export function getLogDir(stateDir: string): string {
    return path.join(stateDir, 'vt-sentinel-audit');
}
