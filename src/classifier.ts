import * as fs from 'fs';
import * as path from 'path';

export enum FileCategory {
    HIGH_RISK = 'HIGH_RISK',
    SEMANTIC_RISK = 'SEMANTIC_RISK',
    SENSITIVE = 'SENSITIVE',
    MEDIA = 'MEDIA',
    SAFE = 'SAFE',
}

/**
 * Content-first file classifier.
 *
 * Classification priority:
 *   1. Magic bytes (binary formats — definitive)
 *   2. Shebang #! (executable scripts — definitive)
 *   3. OpenClaw semantic filenames (SKILL.md, HOOK.md, etc.)
 *   4. Text content analysis (script patterns in plain text)
 *   5. Default → SAFE
 *
 * Extensions are NEVER used as the sole classification signal.
 * This prevents both false positives (private PDF renamed .sh → would be uploaded)
 * and false negatives (PE binary renamed .txt → would be skipped).
 */
export class FileClassifier {

    // ── Magic byte signatures ──────────────────────────────────────────

    private static readonly MAGIC = {
        // Executables
        PE:           [0x4D, 0x5A],                         // MZ — Windows PE
        ELF:          [0x7F, 0x45, 0x4C, 0x46],             // .ELF — Linux
        MACH_O_32:    [0xFE, 0xED, 0xFA, 0xCE],             // Mach-O 32-bit
        MACH_O_64:    [0xFE, 0xED, 0xFA, 0xCF],             // Mach-O 64-bit
        MACH_O_REV:   [0xCE, 0xFA, 0xED, 0xFE],             // MH_CIGAM — Mach-O 32-bit reversed
        MACH_O_64_REV:[0xCF, 0xFA, 0xED, 0xFE],             // MH_CIGAM_64 — Mach-O 64-bit reversed (most common on Intel Mac)
        MACH_O_FAT:   [0xCA, 0xFE, 0xBA, 0xBE],             // FAT_MAGIC — Mach-O fat/universal
        MACH_O_FAT_REV:[0xBE, 0xBA, 0xFE, 0xCA],            // FAT_CIGAM — Mach-O fat reversed
        // Documents (potentially private)
        PDF:          [0x25, 0x50, 0x44, 0x46],              // %PDF
        OLE:          [0xD0, 0xCF, 0x11, 0xE0],              // OLE2 (legacy Office)
        ZIP:          [0x50, 0x4B, 0x03, 0x04],              // PK (zip, docx, xlsx, jar…)
        OOXML:        [0x50, 0x4B, 0x03, 0x04],              // Same as ZIP — modern Office
        // Compressed archives (can't peek inside — treat as SENSITIVE)
        GZIP:         [0x1F, 0x8B],                               // gzip (.gz, .tar.gz, .tgz)
        SEVENZ:       [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C],      // 7-Zip
        RAR:          [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07],       // Rar!..
        XZ:           [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00],       // .xz
        BZ2:          [0x42, 0x5A, 0x68],                          // BZh — bzip2
        // Linux package formats
        DEB:          [0x21, 0x3C, 0x61, 0x72, 0x63, 0x68, 0x3E, 0x0A], // !<arch>\n — Debian .deb (ar archive)
        RPM:          [0xED, 0xAB, 0xEE, 0xDB],                         // RPM package
        // macOS distribution formats
        XAR:          [0x78, 0x61, 0x72, 0x21],                    // xar! — macOS PKG installer
        // Windows containers (executable payloads)
        LNK:          [0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00,
                       0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x46],                    // Shell Link (.lnk) — 20-byte CLSID
        CHM:          [0x49, 0x54, 0x53, 0x46],                    // ITSF — Compiled HTML Help
        CAB:          [0x4D, 0x53, 0x43, 0x46],                    // MSCF — Cabinet archive
        // Media
        PNG:          [0x89, 0x50, 0x4E, 0x47],
        JPG:          [0xFF, 0xD8, 0xFF],
        GIF:          [0x47, 0x49, 0x46, 0x38],
        RIFF:         [0x52, 0x49, 0x46, 0x46],              // RIFF (WAV, WEBP, AVI)
        MKV:          [0x1A, 0x45, 0xDF, 0xA3],              // Matroska/WebM
        FLAC:         [0x66, 0x4C, 0x61, 0x43],              // fLaC
        OGG:          [0x4F, 0x67, 0x67, 0x53],              // OggS
        BMP:          [0x42, 0x4D],                           // BM
    };

    // OpenClaw ecosystem filenames that need semantic analysis
    private static readonly SEMANTIC_FILENAMES = new Set([
        'skill.md', 'hook.md', 'agents.md', 'soul.md',
        'bootstrap.md', 'boot.md', 'tools.md', 'heartbeat.md',
        'identity.md', 'user.md',
    ]);

    // ── Content-based script detection patterns ────────────────────────
    // Checked only on files that are valid UTF-8 text (no binary garbage).

    private static readonly SCRIPT_PATTERNS: RegExp[] = [
        /^#!.*\/(bash|sh|zsh|fish|dash)\b/m,           // Unix shell shebang
        /^#!.*\/(python|ruby|perl|node)\b/m,            // Interpreter shebang
        /^<\?php\b/m,                                    // PHP open tag
        /^\s*@echo\s+off\b/im,                           // Windows batch
        /^\s*Set-StrictMode\b/m,                         // PowerShell
        /^\s*\$ErrorActionPreference\b/m,                // PowerShell
        /^\s*param\s*\(/m,                               // PowerShell param block
        /^\s*Function\s+\w+/im,                          // VBScript / PowerShell
        /^\s*Dim\s+\w+/m,                                // VBScript
        /^\s*import\s+\w+/m,                             // Python / JS / TS
        /^\s*from\s+\w+\s+import\s/m,                    // Python
        /^\s*def\s+\w+\s*\(/m,                           // Python function
        /^\s*require\s*\(\s*['"][^'"]+['"]\s*\)/m,       // Node.js CJS
        /^\s*export\s+(default\s+)?function\b/m,         // JS/TS ESM
        /^\s*const\s+\w+\s*=\s*require\b/m,             // Node.js CJS
        // Shell scripting patterns (shebanless scripts)
        /^\s*(?:if|while|until)\s+\[/m,                  // Shell conditionals: if [ ... ], while [ ... ]
        /^\s*for\s+\w+\s+in\s/m,                         // Shell for loop: for x in ...
        /^\s*case\s+.*\s+in\s*$/m,                        // Shell case: case $x in
        /^\s*(?:export|readonly)\s+\w+=/m,                // Shell variable export/readonly
        /^\s*(?:source|\.)\s+[\/~"']/m,                   // Shell source: source /path or . /path
        /^\s*(?:exit|return)\s+\d/m,                      // Shell exit/return with code
    ];

    // Minimum number of pattern matches to classify as script
    private static readonly SCRIPT_PATTERN_THRESHOLD = 2;

    // Filenames inside ZIP that indicate an OpenClaw skill/hook package
    private static readonly ZIP_SKILL_MARKERS = [
        'skill.md', 'hook.md', 'agents.md', 'soul.md',
    ];

    // Filenames inside ZIP that indicate a binary/executable archive
    private static readonly ZIP_EXEC_EXTENSIONS = [
        '.exe', '.dll', '.com', '.so', '.dylib', '.bin', '.elf',
        '.ps1', '.bat', '.cmd', '.vbs',
    ];

    // Filenames inside ZIP that indicate an Office OOXML document
    private static readonly ZIP_OOXML_MARKERS = [
        '[content_types].xml', 'word/', 'xl/', 'ppt/',
        '_rels/', 'docprops/',
    ];

    // ── Low-level helpers ──────────────────────────────────────────────

    private static readHeader(filePath: string, length: number): Buffer | null {
        try {
            const fd = fs.openSync(filePath, 'r');
            const buf = Buffer.alloc(length);
            const bytesRead = fs.readSync(fd, buf, 0, length, 0);
            fs.closeSync(fd);
            return bytesRead < length ? buf.subarray(0, bytesRead) : buf;
        } catch {
            return null;
        }
    }

    private static matchMagic(buf: Buffer, magic: number[]): boolean {
        if (buf.length < magic.length) return false;
        for (let i = 0; i < magic.length; i++) {
            if (buf[i] !== magic[i]) return false;
        }
        return true;
    }

    private static isShebang(buf: Buffer): boolean {
        return buf.length >= 2 && buf[0] === 0x23 && buf[1] === 0x21;
    }

    private static isFtyp(buf: Buffer): boolean {
        return buf.length >= 8 &&
            buf[4] === 0x66 && buf[5] === 0x74 &&
            buf[6] === 0x79 && buf[7] === 0x70;
    }

    /**
     * Check if a buffer looks like valid UTF-8 text (no null bytes,
     * no control chars other than \t \n \r in the first chunk).
     */
    private static isLikelyText(buf: Buffer): boolean {
        for (let i = 0; i < buf.length; i++) {
            const b = buf[i];
            if (b === 0x00) return false;                 // null byte → binary
            if (b < 0x20 && b !== 0x09 && b !== 0x0A && b !== 0x0D) return false;
        }
        return true;
    }

    /**
     * Peek inside a ZIP file by reading its local file headers.
     * ZIP local file header: PK\x03\x04 ... filename at offset 30.
     * Reads enough bytes to scan the first ~50 entries without full decompression.
     *
     * Returns: 'skill' | 'executable' | 'office' | 'archive'
     */
    private static inspectZip(filePath: string): 'skill' | 'executable' | 'office' | 'archive' {
        // Read up to 64KB to scan ZIP directory entries
        const buf = this.readHeader(filePath, 65536);
        if (!buf || buf.length < 30) return 'archive';

        const entryNames: string[] = [];
        let offset = 0;

        // Walk through ZIP local file headers (PK\x03\x04)
        while (offset + 30 <= buf.length) {
            // Check local file header signature
            if (buf[offset] !== 0x50 || buf[offset + 1] !== 0x4B ||
                buf[offset + 2] !== 0x03 || buf[offset + 3] !== 0x04) {
                break;
            }

            const flags = buf.readUInt16LE(offset + 6);
            const compressedSize = buf.readUInt32LE(offset + 18);
            const nameLen = buf.readUInt16LE(offset + 26);
            const extraLen = buf.readUInt16LE(offset + 28);
            const hasDataDescriptor = (flags & 0x0008) !== 0;

            if (offset + 30 + nameLen > buf.length) break;

            const name = buf.subarray(offset + 30, offset + 30 + nameLen).toString('utf-8').toLowerCase();
            entryNames.push(name);

            if (compressedSize === 0 && hasDataDescriptor) {
                // Data descriptor: actual size follows the compressed data, not in the header.
                // Scan forward for the next local file header (PK\x03\x04) or central dir (PK\x01\x02).
                let nextOffset = offset + 30 + nameLen + extraLen;
                let found = false;
                while (nextOffset + 4 <= buf.length) {
                    if (buf[nextOffset] === 0x50 && buf[nextOffset + 1] === 0x4B &&
                        ((buf[nextOffset + 2] === 0x03 && buf[nextOffset + 3] === 0x04) ||
                         (buf[nextOffset + 2] === 0x01 && buf[nextOffset + 3] === 0x02))) {
                        offset = nextOffset;
                        found = true;
                        break;
                    }
                    nextOffset++;
                }
                if (!found) break;
            } else {
                // Normal entry: advance past header + name + extra + compressed data
                offset += 30 + nameLen + extraLen + compressedSize;
            }

            // Safety: stop after 100 entries
            if (entryNames.length >= 100) break;
        }

        if (entryNames.length === 0) return 'archive';

        // Check for skill/hook package markers
        for (const entry of entryNames) {
            const basename = entry.split('/').pop() || '';
            if (this.ZIP_SKILL_MARKERS.includes(basename)) {
                return 'skill';
            }
        }

        // Check for executables inside
        for (const entry of entryNames) {
            for (const ext of this.ZIP_EXEC_EXTENSIONS) {
                if (entry.endsWith(ext)) return 'executable';
            }
            // macOS .app bundle: Contents/MacOS/ contains the actual binary
            if (/\.app\/contents\/macos\//i.test(entry)) return 'executable';
        }

        // Check for OOXML (Office document)
        for (const entry of entryNames) {
            for (const marker of this.ZIP_OOXML_MARKERS) {
                if (entry === marker || entry.startsWith(marker)) return 'office';
            }
        }

        return 'archive';
    }

    /**
     * Read a larger chunk and test for script-like content patterns.
     */
    private static detectScriptContent(filePath: string): boolean {
        const chunk = this.readHeader(filePath, 4096);
        if (!chunk || chunk.length === 0) return false;
        if (!this.isLikelyText(chunk)) return false;

        const text = chunk.toString('utf-8');
        let matches = 0;
        for (const pat of this.SCRIPT_PATTERNS) {
            if (pat.test(text)) {
                matches++;
                if (matches >= this.SCRIPT_PATTERN_THRESHOLD) return true;
            }
        }
        return false;
    }

    // ── Main classifier ────────────────────────────────────────────────

    /**
     * Classify a file into a security category.
     * Uses ONLY magic bytes and content analysis — never extensions alone.
     */
    public static classify(filePath: string): FileCategory {
        const header = this.readHeader(filePath, 20);
        if (!header || header.length === 0) return FileCategory.SAFE;

        // ── Phase 1: Magic bytes (definitive binary identification) ────

        // 1a. Executable binaries → HIGH_RISK (auto-upload OK, no privacy concern)
        if (this.matchMagic(header, this.MAGIC.PE) ||
            this.matchMagic(header, this.MAGIC.ELF) ||
            this.matchMagic(header, this.MAGIC.MACH_O_32) ||
            this.matchMagic(header, this.MAGIC.MACH_O_64) ||
            this.matchMagic(header, this.MAGIC.MACH_O_REV) ||
            this.matchMagic(header, this.MAGIC.MACH_O_64_REV)) {
            return FileCategory.HIGH_RISK;
        }

        // 1a-bis. 0xCAFEBABE / 0xBEBAFECA: Mach-O fat/universal OR Java .class file.
        // Both are executable code → HIGH_RISK regardless.
        if (this.matchMagic(header, this.MAGIC.MACH_O_FAT) ||
            this.matchMagic(header, this.MAGIC.MACH_O_FAT_REV)) {
            return FileCategory.HIGH_RISK;
        }

        // 1a-ter. macOS PKG installer (XAR archive) → HIGH_RISK
        if (this.matchMagic(header, this.MAGIC.XAR)) {
            return FileCategory.HIGH_RISK;
        }

        // 1b. Documents → SENSITIVE (may contain private data, hash-only)
        if (this.matchMagic(header, this.MAGIC.PDF) ||
            this.matchMagic(header, this.MAGIC.OLE)) {
            return FileCategory.SENSITIVE;
        }

        // 1c. ZIP containers — inspect contents to decide
        if (this.matchMagic(header, this.MAGIC.ZIP)) {
            const zipType = this.inspectZip(filePath);
            switch (zipType) {
                case 'skill':      return FileCategory.SEMANTIC_RISK; // Skill/hook package → auto-upload + Code Insight
                case 'executable': return FileCategory.HIGH_RISK;     // Contains binaries → auto-upload
                case 'office':     return FileCategory.SENSITIVE;     // OOXML doc → user consent required
                default:           return FileCategory.SENSITIVE;     // Unknown archive → user consent required
            }
        }

        // 1d. Compressed archives → SENSITIVE (can't inspect contents, may be private)
        if (this.matchMagic(header, this.MAGIC.GZIP) ||
            this.matchMagic(header, this.MAGIC.SEVENZ) ||
            this.matchMagic(header, this.MAGIC.RAR) ||
            this.matchMagic(header, this.MAGIC.XZ) ||
            this.matchMagic(header, this.MAGIC.BZ2) ||
            this.matchMagic(header, this.MAGIC.DEB) ||
            this.matchMagic(header, this.MAGIC.RPM)) {
            return FileCategory.SENSITIVE;
        }

        // 1e. Windows executable containers → HIGH_RISK
        if (this.matchMagic(header, this.MAGIC.CHM) ||
            this.matchMagic(header, this.MAGIC.CAB)) {
            return FileCategory.HIGH_RISK;
        }

        // 1e-bis. Windows Shell Link (.lnk) — top malware delivery vector.
        // LNK files can embed arbitrary commands, PowerShell, download payloads.
        if (this.matchMagic(header, this.MAGIC.LNK)) {
            return FileCategory.HIGH_RISK;
        }

        // 1f. Media → MEDIA (skip scanning)
        if (this.matchMagic(header, this.MAGIC.PNG) ||
            this.matchMagic(header, this.MAGIC.JPG) ||
            this.matchMagic(header, this.MAGIC.GIF) ||
            this.matchMagic(header, this.MAGIC.RIFF) ||
            this.matchMagic(header, this.MAGIC.MKV) ||
            this.matchMagic(header, this.MAGIC.FLAC) ||
            this.matchMagic(header, this.MAGIC.OGG) ||
            this.matchMagic(header, this.MAGIC.BMP) ||
            this.isFtyp(header)) {
            return FileCategory.MEDIA;
        }

        // ── Phase 2: Shebang (definitive script identification) ────────

        if (this.isShebang(header)) {
            return FileCategory.HIGH_RISK;
        }

        // ── Phase 2b: Windows Registry script (definitive text header) ──
        //    .reg files can modify auto-run keys, disable security features,
        //    hijack file associations. Definitive prefix — not heuristic.
        //    Need 40+ bytes to match "Windows Registry Editor Version 5.00".
        if (this.isLikelyText(header)) {
            const textChunk = this.readHeader(filePath, 48);
            if (textChunk && textChunk.length >= 8) {
                const headerText = textChunk.toString('utf-8');
                if (headerText.startsWith('Windows Registry Editor') || headerText.startsWith('REGEDIT4')) {
                    return FileCategory.HIGH_RISK;
                }
            }
        }

        // ── Phase 3: OpenClaw semantic files (by canonical filename) ───

        const basename = path.basename(filePath).toLowerCase();
        if (this.SEMANTIC_FILENAMES.has(basename)) {
            return FileCategory.SEMANTIC_RISK;
        }

        // ── Phase 4: Content-based script detection ────────────────────
        //    Read a larger chunk, verify it's text, match script patterns.
        //    Requires ≥2 pattern matches to reduce false positives.

        if (this.detectScriptContent(filePath)) {
            return FileCategory.HIGH_RISK;
        }

        // ── Phase 5: Default → SAFE ────────────────────────────────────
        //    Unknown format. Don't upload, don't scan. Conservative default.

        return FileCategory.SAFE;
    }
}
