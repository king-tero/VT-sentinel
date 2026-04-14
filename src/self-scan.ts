/**
 * Pre-flight self-scan.
 *
 * Reimplements the rules enforced by the OpenClaw install-security scanner
 * (openclaw/dist/skill-scanner-*.js) against this plugin's own dist/*.js to
 * catch a blocking regression BEFORE `npm publish` or `plugins install`.
 *
 * Rule set is intentionally copy-faithful to the upstream scanner. If OpenClaw
 * adds or changes rules, update this file to match.
 *
 * Usage: `npm run scan` (exits non-zero if any shipped file triggers a rule
 * of configured severity).
 */

import * as fs from 'fs';
import * as path from 'path';

type Severity = 'critical' | 'warn';

interface LineRule {
    id: string;
    severity: Severity;
    message: string;
    pattern: RegExp;
    requiresContext?: RegExp;
}

interface SourceRule {
    id: string;
    severity: Severity;
    message: string;
    pattern: RegExp;
    requiresContext?: RegExp;
}

const LINE_RULES: LineRule[] = [
    {
        id: 'dangerous-exec',
        severity: 'critical',
        message: 'Shell command execution detected (child_process)',
        pattern: /\b(exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(/,
        requiresContext: /child_process/,
    },
    {
        id: 'dynamic-code-execution',
        severity: 'critical',
        message: 'Dynamic code execution detected',
        pattern: /\beval\s*\(|new\s+Function\s*\(/,
    },
    {
        id: 'crypto-mining',
        severity: 'critical',
        message: 'Possible crypto-mining reference detected',
        pattern: /stratum\+tcp|stratum\+ssl|coinhive|cryptonight|xmrig/i,
    },
];

const SOURCE_RULES: SourceRule[] = [
    {
        id: 'env-harvesting',
        severity: 'critical',
        message: 'Environment variable access combined with network send — possible credential harvesting',
        pattern: /process\.env/,
        requiresContext: /\bfetch\b|\bpost\b|http\.request/i,
    },
    {
        id: 'potential-exfiltration',
        severity: 'warn',
        message: 'File read combined with network send — possible data exfiltration',
        pattern: /readFileSync|readFile/,
        requiresContext: /\bfetch\b|\bpost\b|http\.request/i,
    },
    {
        id: 'obfuscated-code-hex',
        severity: 'warn',
        message: 'Hex-encoded string sequence detected (possible obfuscation)',
        pattern: /(\\x[0-9a-fA-F]{2}){6,}/,
    },
    {
        id: 'obfuscated-code-base64',
        severity: 'warn',
        message: 'Large base64 payload with decode call detected (possible obfuscation)',
        pattern: /(?:atob|Buffer\.from)\s*\(\s*["'][A-Za-z0-9+/=]{200,}["']/,
    },
];

const SCANNABLE_EXTENSIONS = new Set(['.js', '.ts', '.mjs', '.cjs', '.mts', '.cts', '.jsx', '.tsx']);

export interface Finding {
    ruleId: string;
    severity: Severity;
    file: string;
    line: number;
    message: string;
    evidence: string;
}

function isScannable(filePath: string): boolean {
    return SCANNABLE_EXTENSIONS.has(path.extname(filePath).toLowerCase());
}

function walk(dir: string): string[] {
    const out: string[] = [];
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        if (entry.name === 'node_modules' || entry.name.startsWith('.')) continue;
        const p = path.join(dir, entry.name);
        if (entry.isDirectory()) out.push(...walk(p));
        else if (entry.isFile() && isScannable(entry.name)) out.push(p);
    }
    return out;
}

function truncate(s: string, max = 120): string {
    const t = s.trim();
    return t.length <= max ? t : t.slice(0, max) + '…';
}

export function scanFile(filePath: string, source?: string): Finding[] {
    const findings: Finding[] = [];
    const src = source ?? fs.readFileSync(filePath, 'utf-8');
    const lines = src.split('\n');

    for (const rule of LINE_RULES) {
        if (rule.requiresContext && !rule.requiresContext.test(src)) continue;
        for (let i = 0; i < lines.length; i++) {
            if (rule.pattern.test(lines[i])) {
                findings.push({
                    ruleId: rule.id,
                    severity: rule.severity,
                    file: filePath,
                    line: i + 1,
                    message: rule.message,
                    evidence: truncate(lines[i]),
                });
                break;
            }
        }
    }

    for (const rule of SOURCE_RULES) {
        if (!rule.pattern.test(src)) continue;
        if (rule.requiresContext && !rule.requiresContext.test(src)) continue;
        let line = 1;
        let evidence = truncate(src);
        for (let i = 0; i < lines.length; i++) {
            if (rule.pattern.test(lines[i])) {
                line = i + 1;
                evidence = truncate(lines[i]);
                break;
            }
        }
        findings.push({
            ruleId: rule.id,
            severity: rule.severity,
            file: filePath,
            line,
            message: rule.message,
            evidence,
        });
    }
    return findings;
}

export function scanDirectory(dir: string, excludeFiles: string[] = []): Finding[] {
    const files = walk(dir);
    const findings: Finding[] = [];
    for (const f of files) {
        if (excludeFiles.some(x => f.endsWith(x))) continue;
        findings.push(...scanFile(f));
    }
    return findings;
}

export interface ScanSummary {
    critical: number;
    warn: number;
    total: number;
    findings: Finding[];
}

export function summarize(findings: Finding[]): ScanSummary {
    return {
        critical: findings.filter(f => f.severity === 'critical').length,
        warn: findings.filter(f => f.severity === 'warn').length,
        total: findings.length,
        findings,
    };
}

// CLI entry — only runs when executed directly (node dist/self-scan.js)
if (require.main === module) {
    // Only scan files that actually ship in the npm package — mirror the files[]
    // list in package.json. test_runner.js is compiled to dist/ but is excluded
    // from the published tarball, so the install scanner never sees it.
    const SHIPPED_PREFIXES = [
        'index.',
        'scanner.',
        'vt-api.',
        'vt-credentials.',
        'classifier.',
        'cache.',
        'path-extractor.',
        'audit-log.',
        'config-manager.',
        'state-store.',
        'status-renderer.',
        'env-access.',
        'version.',
        'update-commands.',
        'compliance-snapshot.',
    ];
    function isShipped(file: string): boolean {
        const base = path.basename(file);
        if (file.includes(path.join('dist', 'signatures'))) return false; // JSON only
        return SHIPPED_PREFIXES.some(p => base.startsWith(p));
    }

    const distDir = path.resolve(process.cwd(), 'dist');
    if (!fs.existsSync(distDir)) {
        console.error(`self-scan: dist directory not found at ${distDir} (run npm run build first)`);
        process.exit(2);
    }

    const allFindings = walk(distDir).filter(isShipped).flatMap(f => scanFile(f));
    const summary = summarize(allFindings);

    const jsonMode = process.argv.includes('--json');
    if (jsonMode) {
        console.log(JSON.stringify(summary, null, 2));
    } else {
        const byFile = new Map<string, Finding[]>();
        for (const f of summary.findings) {
            const rel = path.relative(process.cwd(), f.file);
            if (!byFile.has(rel)) byFile.set(rel, []);
            byFile.get(rel)!.push(f);
        }
        console.log(`self-scan: ${summary.critical} critical, ${summary.warn} warn, ${summary.total} total`);
        for (const [file, findings] of byFile) {
            console.log(`\n${file}`);
            for (const f of findings) {
                const tag = f.severity === 'critical' ? '  [CRITICAL]' : '  [warn]    ';
                console.log(`${tag} ${f.ruleId}:${f.line}  ${f.message}`);
                console.log(`             evidence: ${f.evidence}`);
            }
        }
        if (summary.critical === 0 && summary.warn === 0) {
            console.log('clean — nothing would trigger the install-security scanner');
        }
    }

    const allowWarn = process.argv.includes('--allow-warn');
    const failOnWarn = !allowWarn;
    const failed = summary.critical > 0 || (failOnWarn && summary.warn > 0);
    process.exit(failed ? 1 : 0);
}
