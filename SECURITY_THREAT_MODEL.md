# Security Threat Model

Status: pass for current repository scope.

Review Date: 2026-08-30.

## Assets

- Scanner source code
- Bundled security gate rules
- Test fixtures
- CI workflow
- Public documentation
- Evidence and manifest templates

## Trust Boundary

- The scanner reads local project files but skips `.env*` working-tree contents.
- The scanner writes reports only to the configured output directory.
- Network access is disabled by default and is used only when `--registry-check` is explicitly set.
- External SAST, secret scanning, and package reputation tools are evidence sources, not embedded execution paths.

## Data Flow

1. User selects one or more local target directories.
2. Scanner inventories text files under those targets, excluding generated and high-noise directories.
3. Scanner produces JSON and Markdown reports in `--output-dir`.
4. Gate modes evaluate local findings plus required evidence documents.
5. Optional registry checks query npm or PyPI for package existence only.

## Threats

- Secret values committed to current files or git history
- Agent-readable instructions that trigger unsafe commands
- MCP server configuration with unreviewed command or network access
- Package hallucination, slopsquatting, or unreviewed package runners
- Public export of private files, logs, proof material, or scratch output
- Deployment without SAST or secret-scan evidence

## Controls

- Redact secret values and report only match type plus hash
- Skip `.env*` working-tree contents
- Block high-risk package, agent, export, deploy, and evidence gaps through gate modes
- Require SAST/code-security evidence for source-code deployments
- Require gitleaks, trufflehog, or equivalent secret-scan evidence for deployable projects
- Require package reputation evidence for dependency-bearing projects
- Require MCP server allowlist when MCP config exists
