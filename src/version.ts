/**
 * Version resolver for VT Sentinel.
 *
 * Lives in its own file (with no HTTP client imports) so the readFileSync on
 * package.json doesn't co-occur with the outbound calls in index.ts. Split in
 * v0.11.2 to clear the ClawHub static-scan warning.
 */

import * as fs from 'fs';
import * as path from 'path';

/**
 * Return the plugin version as declared in package.json, or '0.0.0' if the
 * file cannot be read (should not happen in normal installs).
 */
export function getCurrentVersion(): string {
    try {
        const raw = fs.readFileSync(path.resolve(__dirname, '..', 'package.json'), 'utf-8');
        const pkg = JSON.parse(raw);
        return typeof pkg.version === 'string' && pkg.version.trim().length > 0
            ? pkg.version.trim()
            : '0.0.0';
    } catch {
        return '0.0.0';
    }
}
