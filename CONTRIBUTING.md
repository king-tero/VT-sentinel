# Contributing

Thanks for your interest in VT Sentinel. This guide covers the basics for
reporting issues, submitting patches, and building the plugin locally.

## Reporting issues

- Non-security bugs and feature requests: open a GitHub issue.
- Security vulnerabilities: see [`SECURITY.md`](./SECURITY.md).

When filing a bug, please include:

- VT Sentinel version (`openclaw plugins inspect openclaw-plugin-vt-sentinel`).
- OpenClaw version (`openclaw --version`).
- OS and Node.js version.
- The output of `openclaw security audit --deep --json` filtered to
  `vt-sentinel.*` findings, if relevant.

## Building locally

Requirements: Node.js >= 18, npm, TypeScript.

```bash
git clone https://github.com/king-tero/VT-sentinel.git
cd VT-sentinel
npm install
npm run build
npm test
npm run scan
```

`npm run scan` runs a local re-implementation of OpenClaw's install-security
scanner against the compiled `dist/`. A clean baseline is `0 critical, 0 warn`.
CI blocks on any finding.

## Code style

- TypeScript `strict`.
- No inline first-person narrative in comments (use neutral phrasing).
- No references to coding assistants or editors.
- Defensive threat-detection regex literals belong in
  `src/signatures/*.json`, not in `.ts` source — so static scanners do not
  mistake detection patterns for malicious code.
- Prefer host-runtime helpers (`api.runtime.*`) over direct environment
  reads. Any residual `process.env` usage must live in a module with no
  HTTP-client imports, to avoid tripping the install-security scanner's
  env-harvesting rule.

## Pull requests

- One logical change per PR.
- Update `CHANGELOG.md` under an `Unreleased` section if the change is user
  visible.
- `npm test` and `npm run scan` must pass.

## Release process (maintainers)

1. Bump `version` in `package.json` and `openclaw.plugin.json`.
2. Add a `CHANGELOG.md` entry.
3. `npm run build && npm test && npm run scan`.
4. `npm publish`.
5. Publish to ClawHub with `--source-commit <new commit SHA> --source-ref vX.Y.Z`.
6. Tag the release in git: `git tag vX.Y.Z && git push --tags`.
