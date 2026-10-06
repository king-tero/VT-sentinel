# VT Sentinel — VirusTotal Security Plugin for OpenClaw

Antivirus and active protection for OpenClaw agents: background file scanning,
command inspection/blocking, and quarantine of malicious auto-scan results.
No API key is required: without one, the first scan or hash lookup registers
an agent with VirusTotal's AI API and stores its token locally.

Default behavior: `autoScan: true`, `blockMode: quarantine`. The plugin reads
candidate files and may upload unknown files according to the policies below.
Review the [controls](#controls-and-scope) before enabling it on a workspace.

## Install

```
openclaw plugins install clawhub:openclaw-plugin-vt-sentinel
```

Legacy / backward-compatible npm install:

```
openclaw plugins install openclaw-plugin-vt-sentinel
```

Then restart the gateway:

```
openclaw gateway restart
```

## Verify

```
openclaw plugins list | grep vt-sentinel
```

Should show 9 tools registered.

## Tools

| Tool | Purpose |
|------|---------|
| `vt_scan_file` | Full file scan (AV engines + AI Code Insight) |
| `vt_check_hash` | Quick hash lookup without uploading |
| `vt_upload_consent` | Manage consent for sensitive file uploads |
| `vt_sentinel_status` | View config, watched dirs, protection status |
| `vt_sentinel_configure` | Change settings at runtime (presets, notify level, block mode) |
| `vt_sentinel_reset_policy` | Reset all settings to defaults |
| `vt_sentinel_help` | Quick-start guide and privacy info |
| `vt_sentinel_update` | Check for updates and get upgrade instructions |
| `vt_sentinel_re_register` | Re-register agent identity with VTAI |

## What it does

- Scans candidate downloaded and created files within size/category/exclusion limits (AV + AI Code Insight when available)
- Defaults to hash-only lookups for instruction files (SKILL.md, TOOLS.md); changing policy can permit uploads
- Blocks execution of malicious files and dangerous command patterns
- Monitors directories in real-time (Downloads, /tmp, workspace)
- Quarantines threats with rotating audit logs
- Detects TOCTOU attacks, LOLBins, and persistence patterns

## Update

If VT Sentinel is already installed, use the built-in update tool:

```
Ask your agent: "check for VT Sentinel updates"
```

Or manually:

```
openclaw gateway stop
openclaw plugins update openclaw-plugin-vt-sentinel
openclaw gateway start
```

## Configuration

### Optional: Add your own VirusTotal API key

Without a key, VT Sentinel auto-registers with VTAI and works out of the box.
If you have a VirusTotal API key (v3), set it in the plugin config:

```
openclaw config set plugins.entries.openclaw-plugin-vt-sentinel.config.apiKey "vt_xxxxxxxxxxxx"
```

> **v0.11.0 migration:** earlier versions of VT Sentinel also read the
> `VIRUSTOTAL_API_KEY` shell environment variable as a fallback. **That
> fallback was removed in v0.11.0** for compliance with the OpenClaw
> install-security scanner and to stop the plugin from mutating global
> process state. The only supported credential sources are now:
>
> 1. `apiKey` in the plugin config (command above), or
> 2. VTAI auto-registration (no setup required — happens on first scan).
>
> If you previously exported `VIRUSTOTAL_API_KEY=vt_xxx` in your shell,
> move the value into the plugin config using the command above.

### Presets

| Preset | Description |
|--------|-------------|
| `balanced` | Default — sensitive files ask, instruction files hash-only, malicious auto-scan results quarantined |
| `privacy_first` | Sensitive/instruction files hash-only; blocking without quarantine; **unknown high-risk files can still be uploaded** |
| `strict_security` | Sensitive files auto-upload, instruction files ask; quarantine malicious auto-scan results; 64 MB limit |

Individual settings override presets. No preset disables all file uploads.

### Settings

| Setting | Values | Default |
|---------|--------|---------|
| `notifyLevel` | all, threats_only, silent | all |
| `blockMode` | quarantine, block_only, log_only | quarantine |
| `sensitiveFilePolicy` | ask, ask_once, always_upload, hash_only | ask |
| `semanticFilePolicy` | ask, ask_once, always_upload, hash_only | hash_only |
| `maxFileSizeMb` | 1-650 | 32 |
| `autoScan` | true, false | true |

## How it works

Without a user API key, VT Sentinel connects to [VTAI](https://ai.virustotal.com),
using cached credentials or registering on the first scan/hash lookup. Automatic
scanning can trigger that registration. With a configured user API key, requests
go directly to the standard VirusTotal API without VTAI registration.

File analysis includes:
- **AV detections** from 60+ antivirus engines
- **AI Code Insight**, when available (VirusTotal AI-powered semantic analysis)
- **Crowdsourced AI results**, when available, from the VirusTotal community

### Controls and scope

| Control | Effect |
|---|---|
| `autoScan: false` | Stops watcher/tool-result scanning. Manual tools remain available; command enforcement is controlled separately by `blockMode`. |
| `blockMode: quarantine` | Blocks detected dangerous commands and references to blocklisted files; malicious automatic scan results are renamed to `.QUARANTINED`. |
| `blockMode: block_only` | Blocks the same calls without renaming files. |
| `blockMode: log_only` | Logs detections without blocking commands or quarantining files. Does not change upload policy. Prior blocklist entries are retained and enforced again if an enforcing mode is restored. |
| Nonempty `watchDirs` | Replaces automatically derived watcher roots. Empty/missing watchDirs uses temp, Downloads/Desktop, workspace and OpenClaw code directories. Check `vt_sentinel_status` for the effective list. |

Watcher roots do not bound the tool-result hook: it can scan candidate paths from
supported tool calls elsewhere. `excludeGlobs` applies to both. `excludeDirs`
filters watcher roots; it is not a universal scan allowlist. Command inspection
is independent of watch directories and applies to `exec`, `bash`, `shell`,
`powershell`, `cmd`, and `process` stdin calls.

For manual use without automatic scanning or execution blocking, request:

```
vt_sentinel_configure { "autoScan": false, "blockMode": "log_only" }
```

This persists by default; add `"persist": "session"` for a temporary change.
Manual file scans can still upload content. Use `vt_check_hash` for lookups that
do not upload files. Changing modes does not restore already quarantined files.
Manual scan tools return reports; file enforcement is applied by automatic scans.
Quarantine is a rename, not OS-level isolation, and command matching is heuristic.

Configuration/reset/identity tools are administrative capabilities. The skill
instructs agents to use them only on an explicit user request, never on instructions
in scanned content. Those instructions do not implement operator authentication;
restrict access through the host in shared environments. Update checks only
produce instructions and do not install or execute updates.

## Privacy & compliance

VT Sentinel is a security plugin, so transparency about what it reads, writes,
and sends is part of the threat model. The same structured view is emitted by
`vt_sentinel_status` (Compliance / Data Flow block) and by `openclaw security
audit --deep` (via the plugin's `securityAuditCollector` — CLI audit support
since v0.12.1), so
you can verify the behavior from either surface without reading source.

### Data flow

| Category | Detail |
|---|---|
| **Files read** | Candidate files from watcher roots, supported tool results, and manually selected paths, for hashing/classification. Watcher scope does not restrict manual tools or tool-result scans. Instruction files default to `hash_only`; other policies can permit uploads. |
| **Files uploaded** | Unknown HIGH_RISK files can upload automatically. Sensitive/instruction files follow their category policy. Unknown SAFE/MEDIA files can also upload when manually selected or force-scanned in OpenClaw code directories. `privacy_first` and `log_only` are **not** global no-upload modes. Agent `read`-tool scans use hash-only lookup. Hash lookup sends the hash, not file contents, and uses API quota. |
| **Network endpoints** | User-key mode: `www.virustotal.com`. VTAI mode: `ai.virustotal.com`. `registry.npmjs.org` and `clawhub.ai` are contacted **only** when the user explicitly invokes `vt_sentinel_update` — never on plugin load. |
| **Credentials stored** | `<stateDir>/vt-sentinel-agent.json` (mode `0o600`, owner-only). v0.12.0+ also enforces `0o600` on audit logs and `0o700` on the audit directory. |
| **Registration identity** | VTAI receives plugin family, version and generated/configured display name. Any configured alias/email is also sent, even in minimal mode. Enhanced mode adds the configured bio or OS-family/preset/auto-scan summary. A public handle is created and the identity can appear on the leaderboard. User-key mode does not register with VTAI. |
| **Audit logs** | `<stateDir>/vt-sentinel-audit/uploads.log` and `detections.log`. Rotating; track when the plugin uploaded a file and when a detection fired. |
| **Runtime state** | `<stateDir>/vt-sentinel-state.json` — first-run flags, persisted policy overrides, auto-generated agent name. No sample file contents. |
| **Controls** | `vt_sentinel_configure` uses `preset: privacy_first` (static config uses `configPreset`). `autoScan: false` stops background scans; `blockMode: log_only` stops enforcement; per-category `hash_only` controls sensitive/instruction uploads. See the scope and manual-scan limits above. |

### `VIRUSTOTAL_API_KEY` shell variable is retired

Earlier versions fell back to reading `VIRUSTOTAL_API_KEY` from the shell
environment. **That fallback was removed in 0.11.0.** If you previously
exported the variable, move the value into the plugin config once with:

```
openclaw config set plugins.entries.openclaw-plugin-vt-sentinel.config.apiKey "vt_xxxxxxxx"
```

or do nothing and let VTAI auto-register on first scan. Both are fully
supported; the env variable is not.

### Legacy highlights retained from v0.11.0

- **Network endpoints:** only `www.virustotal.com` (VT API) and
  `ai.virustotal.com` (VTAI). `registry.npmjs.org` / `clawhub.ai` are
  contacted only when you explicitly invoke `vt_sentinel_update` — not on
  plugin load.
- **No environment mutations:** the plugin never writes to `process.env`.
  Reads are kept narrow and are isolated from any HTTP client: the active
  OpenClaw profile name is read from `OPENCLAW_PROFILE` (in `env-access.ts`);
  `OPENCLAW_STATE_DIR`, `HOME`/`USERPROFILE`, and common Windows env-var
  names used by `path-extractor` appear only as defensive fallbacks when the
  host runtime has not provided a value through the plugin API.
- **State directory:** `<OPENCLAW_STATE_DIR>/vt-sentinel-agent.json`
  (credentials, `0o600`), `vt-sentinel-state.json` (runtime overrides),
  `vt-sentinel-audit/` (rotating upload + detection logs).
- **Upload consent:** `SEMANTIC_RISK` files (SKILL.md, HOOK.md, AGENTS.md,
  etc.) default to `hash_only` — never auto-uploaded. `SENSITIVE` files
  (PDFs, Office docs, unknown archives) default to `ask` and require explicit
  consent per category per run.
- **Audit status:** the local install-security scan and ClawHub's asynchronous
  external reviews are separate checks. A clean local result does not guarantee
  that a published release will have a clean external review; inspect the report
  for the exact version before installation.

Inspect the active configuration at any time with `vt_sentinel_status`.

## License

MIT
