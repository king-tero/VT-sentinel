# Security Policy

## Supported Versions

Only the latest `0.12.x` release line receives security fixes. Earlier
versions are unsupported; upgrade via ClawHub or npm.

## Reporting a Vulnerability

**Do not open a public issue for security reports.**

Please report suspected vulnerabilities by email to the repository owner via
the GitHub profile contact method (`https://github.com/king-tero`). Include:

- A description of the vulnerability and its impact.
- Reproduction steps or a minimal proof of concept.
- Affected version(s).
- Your preferred disclosure timeline, if any.

You should receive an acknowledgement within 7 days. We aim to ship a fix
and a coordinated advisory within 30 days for high-severity issues, faster
when impact warrants it.

## Scope

In scope:

- The plugin itself (`src/**`, `dist/**`).
- The installer skill (`vt-sentinel-installer`).
- Interactions with `virustotal.com` and `ai.virustotal.com` endpoints.

Out of scope:

- Vulnerabilities in upstream VirusTotal services (report to VirusTotal).
- Vulnerabilities in OpenClaw itself (report to the OpenClaw project).
- Social engineering or physical attacks.

## Non-Vulnerabilities

The following behaviors are intentional and not security issues:

- Outbound HTTPS requests to `www.virustotal.com` / `ai.virustotal.com`.
- Reading files under configured watch directories to classify and hash them.
- Uploading files when consent has been granted (per the configured
  `sensitiveFilePolicy` / `semanticFilePolicy`).
- Storing a VTAI agent token on disk under `$OPENCLAW_STATE_DIR` with
  mode `0o600`.

## Hardening notes

- Audit logs are created under `$OPENCLAW_STATE_DIR/vt-sentinel-audit/`
  with the directory set to mode `0o700` and individual log files to `0o600`.
- The plugin does not mutate `process.env`.
- Threat-detection signatures live in JSON so that static scanners do not
  confuse defensive patterns with malicious code.
- Run `openclaw security audit --deep --json` to inspect what the plugin
  reads, writes, and sends. A structured "compliance snapshot" is emitted.
