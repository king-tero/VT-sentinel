---
name: vt-sentinel
description: >-
  Security scanner using VirusTotal. Use when the user asks to scan a file for
  malware, check if a downloaded file or script is safe, verify a file hash
  against threat intelligence, or assess the security of any file. Returns both
  antivirus engine detections AND AI-powered Code Insight analysis (when
  available) in a single unified report.
metadata:
  openclaw:
    emoji: "\U0001F6E1\uFE0F"
---

# VT Sentinel — VirusTotal Active Protection

Protects OpenClaw users with **active prevention**, not just detection:

1. **Antivirus engines** — 60+ vendors check file hashes for known malware
2. **AI Code Insight** — VirusTotal AI-powered semantic analysis for scripts, skills, binaries
3. **Active blocking** — Files detected as malicious are blocklisted and quarantined. Any subsequent attempt to execute them is automatically blocked before it runs.

Both AV and AI sources are always checked. The final verdict is the worst of the two. Malicious files are quarantined (renamed to `.QUARANTINED`) and added to a runtime blocklist that prevents their execution via `exec` or `bash` tools.

## Available Tools

### `vt_scan_file` — Full File Scan
Classifies the file, computes SHA-256, checks VT (AV + Code Insight), uploads if unknown.

```
vt_scan_file { "path": "/absolute/path/to/file" }
```

### `vt_check_hash` — Quick Hash Lookup
Fast check of a SHA-256 hash against VT. Returns AV detections + Code Insight if available.

```
vt_check_hash { "hash": "e3b0c44298fc1c149afbf4c8996fb924..." }
```

### `vt_upload_consent` — Confirm Sensitive File Upload
When `vt_scan_file` returns `needs_consent`, relay the user's decision.

```
vt_upload_consent { "path": "/path/to/document.pdf", "upload": true }
vt_upload_consent { "path": "/path/to/document.pdf", "upload": false }
```

## When to Use Which Tool

| Scenario | Tool |
|----------|------|
| User asks "is this file safe?" | `vt_scan_file` |
| User provides a SHA-256 hash | `vt_check_hash` |
| Evaluating a new SKILL.md or HOOK.md | `vt_scan_file` |
| Checking a downloaded script or binary | `vt_scan_file` |
| User said YES/NO to uploading a sensitive file | `vt_upload_consent` |

## Interpreting Results

Every result includes both AV detections and Code Insight (when available):

```
File: example.sh
Category: HIGH_RISK
Verdict: MALICIOUS
Detections: 12 malicious, 0 suspicious / 64 engines
Code Insight (Code Insight): MALICIOUS
Analysis: This script downloads and executes a remote payload...
VT Link: https://www.virustotal.com/gui/file/...
Summary: AV: 12/64 engines detected malware | AI: MALICIOUS — ...
```

### Verdicts
- **CLEAN** — No threats from AV engines or AI
- **MALICIOUS** — AV engines and/or AI flagged the file. Warn the user immediately.
- **SUSPICIOUS** — Some concerns raised. Recommend caution.
- **PENDING** — File uploaded, analysis not yet available. Check again later.
- **SKIPPED** — File classified as safe/media (auto-scan only; manual scans always check).
- **NEEDS_CONSENT** — Sensitive file. Hash checked (not found). Ask user before uploading.

### Code Insight
When present in the result, Code Insight provides:
- **Source**: Analysis engine (e.g., "Code Insight", "palm")
- **Verdict**: UNDETECTED / SUSPICIOUS / MALICIOUS
- **Analysis**: Free-text description of what the file does

Code Insight works on any file type VT can analyze — scripts, skills, binaries (decompiled), documents with macros, etc.

## File Categories

Classification uses magic bytes and content analysis (never extensions alone):
- **HIGH_RISK**: Binaries (PE, ELF, Mach-O), scripts (shebang/content patterns), ZIPs with executables → auto-scanned
- **SEMANTIC_RISK**: SKILL.md, HOOK.md, TOOLS.md, AGENTS.md, SOUL.md, skill ZIPs → hash checked, upload needs consent (default: hash_only)
- **SENSITIVE**: PDF, Office docs, unknown ZIPs → hash checked, upload needs consent (default: ask)
- **MEDIA/SAFE**: Images, video, audio, plain text → skipped in auto-scan, checked in manual scan

## Consent Flow for Sensitive / Semantic Files

When `vt_scan_file` returns `NEEDS_CONSENT`:

1. Tell the user: the file's hash was checked (no match), but the file was NOT uploaded.
2. Explain: uploading enables deep analysis (macros, embedded threats, AI), but content is shared with VirusTotal.
3. Ask: "Would you like me to upload this file for a full scan?"
4. Call `vt_upload_consent` with their answer.

**Note**: Files read by the agent (via the `read` tool) are only hash-checked, never auto-uploaded. This protects instruction files like TOOLS.md and AGENTS.md from being uploaded to VT during normal agent operations.

## Admin Tools

### `vt_sentinel_status` — Current Status
Shows effective configuration, monitored directories, policy matrix, active protections.

```
vt_sentinel_status {}
```

### `vt_sentinel_configure` — Change Config at Runtime
Update any setting immediately. Changes persist to disk by default.

```
vt_sentinel_configure { "preset": "privacy_first" }
vt_sentinel_configure { "sensitiveFilePolicy": "hash_only", "notifyLevel": "threats_only" }
vt_sentinel_configure { "semanticFilePolicy": "ask" }
vt_sentinel_configure { "watchDirsAdd": ["/extra/dir"], "excludeGlobs": ["*.log"] }
vt_sentinel_configure { "blockMode": "log_only", "persist": "session" }
```

**Presets**: `balanced` (default), `privacy_first` (hash-only, minimal logging), `strict_security` (auto-upload all, quarantine).

### `vt_sentinel_reset_policy` — Reset to Defaults
Clears runtime overrides. Optionally clears first-run flags or blocklist.

```
vt_sentinel_reset_policy {}
vt_sentinel_reset_policy { "clearBlocklist": true }
vt_sentinel_reset_policy { "clearFirstRun": true }
```

### `vt_sentinel_help` — Quick-Start Guide
Shows usage examples, privacy explanation, and available presets.

```
vt_sentinel_help {}
```

### `vt_sentinel_update` — Check for Updates
Checks npm for a newer version and generates upgrade instructions.

```
vt_sentinel_update {}
vt_sentinel_update { "confirm": true }
```

### `vt_sentinel_re_register` — Re-register Agent Identity
Re-registers with VTAI using current identity settings. Creates a new `public_handle`.
Use after changing `agentDisplayName` or other identity settings via `vt_sentinel_configure`.

```
vt_sentinel_re_register {}
vt_sentinel_re_register { "confirm": true }
```

## Agent Identity

Each VT Sentinel instance registers with VTAI and appears on the agent leaderboard.
By default, a unique name is auto-generated (e.g., `Sentinel-SwiftFalcon-a3f2`).

Configure identity via `vt_sentinel_configure`:
- `agentDisplayName`: Custom display name for the leaderboard
- `agentHumanAlias`: Human operator alias (no spaces)
- `agentBio`: Short description (maps to VTAI `define_your_self`)
- `agentContactEmail`: Optional contact email
- `agentMetadataMode`: `minimal` (default, display name only) or `enhanced` (adds OS, preset info — no personal data)

After changing identity settings, use `vt_sentinel_re_register { "confirm": true }` to apply.

## Active Protection

VT Sentinel automatically protects the system in real-time:

1. **Auto-scan**: Every file downloaded or created by tools (`exec`, `write`, `web_fetch`) is automatically scanned
2. **Blocklist**: Malicious and suspicious files are added to an in-memory blocklist
3. **Quarantine**: Malicious files are renamed to `.QUARANTINED` so they cannot be executed
4. **Execution blocking**: Any `exec`/`bash` command that references a blocked file is intercepted and prevented BEFORE execution
5. **Command pattern inspection**: Commands are analyzed for dangerous patterns BEFORE execution, even when no file is involved:
   - **Pipe-to-shell**: `curl | bash`, `wget | sh`, `base64 -d | bash` — remote code execution without touching disk
   - **SSH key injection**: Appending to `authorized_keys` — backdoor persistence
   - **Data exfiltration**: Sending data to webhook.site, requestbin, pipedream, etc.
   - **Credential theft**: Piping `.env`, SSH keys, or AWS credentials to network tools

If you see a "BLOCKED" message, it means VT Sentinel prevented a potentially dangerous operation. Do NOT attempt to work around the block — inform the user about the threat.

## Constraints

- Always use absolute file paths
- Never expose the VT API key in output
- Rate limit: 4 requests/minute (free tier) — handled automatically
- For SENSITIVE files, follow the consent flow — never upload without permission
- If verdict is MALICIOUS, always warn the user prominently
- Do not attempt to bypass quarantine or blocklist protections
