# VT Sentinel — VirusTotal Security Plugin for OpenClaw

Automatic malware detection and AI-powered code analysis for OpenClaw agents.
Zero-config — no API key needed. Auto-registers with VirusTotal's AI API.

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

- Scans downloaded and created files automatically (AV + AI Code Insight)
- Protects instruction files (SKILL.md, TOOLS.md) from being uploaded without consent
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

### Optional: Add your own VirusTotal API key (higher rate limits)

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
| `balanced` | Default — scans everything, quarantines threats |
| `privacy_first` | Hash-only lookups, no file uploads |
| `strict_security` | Maximum protection, blocks on suspicion |

### Settings

| Setting | Values | Default |
|---------|--------|---------|
| `notifyLevel` | all, threats_only, silent | all |
| `blockMode` | quarantine, block_only, log_only | quarantine |
| `sensitiveFilePolicy` | ask, ask_once, always_upload, hash_only | ask |
| `semanticFilePolicy` | ask, ask_once, always_upload, hash_only | hash_only |
| `maxFileSizeMb` | 1-32 | 32 |
| `autoScan` | true, false | true |

## How it works

VT Sentinel connects to [VTAI](https://ai.virustotal.com) — VirusTotal's LLM-optimized proxy layer. On first run it auto-registers an agent identity and receives a permanent API token. All scans go through VTAI's minimized response format, optimized for LLM context windows.

File analysis includes:
- **AV detections** from 60+ antivirus engines
- **AI Code Insight** (VirusTotal AI-powered semantic analysis)
- **Crowdsourced AI results** from the VirusTotal community

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
| **Files read** | Candidate files under configured watch dirs — for hashing and classification. Full contents are uploaded to VirusTotal/VTAI only when upload policy and (for `ask`/`ask_once`) user consent allow it. Instruction files (`SKILL.md`, `HOOK.md`, `AGENTS.md`, etc.) default to `hash_only` and are never auto-uploaded. |
| **Files uploaded** | Hash lookups are free (no content sent). Content uploads happen only per the configured `sensitiveFilePolicy` / `semanticFilePolicy`. |
| **Network endpoints** | User-key mode: `www.virustotal.com`. VTAI mode: `ai.virustotal.com`. `registry.npmjs.org` and `clawhub.ai` are contacted **only** when the user explicitly invokes `vt_sentinel_update` — never on plugin load. |
| **Credentials stored** | `<stateDir>/vt-sentinel-agent.json` (mode `0o600`, owner-only). v0.12.0+ also enforces `0o600` on audit logs and `0o700` on the audit directory. |
| **Audit logs** | `<stateDir>/vt-sentinel-audit/uploads.log` and `detections.log`. Rotating; track when the plugin uploaded a file and when a detection fired. |
| **Runtime state** | `<stateDir>/vt-sentinel-state.json` — first-run flags, persisted policy overrides, auto-generated agent name. No sample file contents. |
| **Opt-outs** | `vt_sentinel_configure` → switch to `configPreset: privacy_first`, set `autoScan: false`, or switch per-category policy to `hash_only`. |

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
- **Passes the install-security scanner:** installs cleanly on OpenClaw
  2026.4.5 and later without `--dangerously-force-unsafe-install`.

Inspect the active configuration at any time with `vt_sentinel_status`.

## License

MIT
