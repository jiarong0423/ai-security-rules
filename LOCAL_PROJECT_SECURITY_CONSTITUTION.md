# Local Project Security Constitution

This constitution defines the minimum local project development rules for AI-assisted and agentic coding work. It applies before design, before implementation, before dependency changes, before agent execution, before public export, before deployment, and during project closeout.

## 1. Non-Negotiable Defaults

- Local-first inspection is the default.
- `.env` and `.env.*` contents must not be read by default.
- Secret values must not be printed, copied into reports, pasted into prompts, or committed.
- Project commands must not run during security inventory unless the operator explicitly chooses a separate external tool.
- Public export is default-deny.
- Evidence beats memory. A stage is not complete until its evidence file or manifest exists.

## 2. Pre-Design Gate

Any project with source code, dependencies, provider integrations, public endpoints, agent configuration, MCP configuration, or export intent must have a threat model before implementation.

Required evidence:

- `SECURITY_THREAT_MODEL.md` or `THREAT_MODEL.md`

The threat model must record:

- assets
- trust boundary
- data flow
- threats
- controls

## 3. Secret Boundary

Secrets belong behind a backend, local protected service, secret manager, or vault. Browser-readable code must not hold provider credentials.

Required evidence:

- `SECURITY.md`, `SECRETS.md`, or `RUNBOOK.md`
- `SECRET_SCAN_EVIDENCE.md`

Secret evidence must record:

- owner
- storage location by name only
- rotation path
- revoke path
- gitleaks, trufflehog, or equivalent secret-scan result

## 4. Agent And Rule Files

Agent-readable files are executable governance surface, not ordinary documentation. Treat `AGENTS.md`, `SKILL.md`, `CLAUDE.md`, `.cursor/`, `.claude/`, `.gemini/`, `.codex/`, `.vscode/`, and MCP configuration as code.

Required controls:

- review hidden config before opening the project with an agent
- allowlist any shell, package runner, process spawn, install hook, or network fetch
- block ambiguous auto-approval or bypass instructions

## 5. MCP Server Allowlist

Projects with MCP configuration must maintain an MCP allowlist.

Required evidence:

- `MCP_SERVER_ALLOWLIST.md` or `mcp-server-allowlist.json`

The allowlist must record:

- allowed servers
- command path or transport
- permission scope
- network behavior
- owner
- review date

## 6. Dependency And Package Reputation

Dependency changes are supply-chain changes. Package runners such as `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `pip install`, `uv pip`, and `poetry add` must not be executed by an agent without review.

Required evidence:

- `PACKAGE_REPUTATION_EVIDENCE.md`

Evidence must record:

- registry existence
- maintainer or publisher review
- release age
- lockfile diff
- hallucination or slopsquatting watchlist review
- accepted residual risk

## 7. Source Code Security

This tool does not replace SAST. Source-code projects must keep evidence from a SAST or equivalent code-security tool before deployment.

Required evidence:

- `SECURITY_SCAN_EVIDENCE.md`, `SAST_EVIDENCE.md`, or `CODE_SECURITY_EVIDENCE.md`

Acceptable tools include CodeQL, Semgrep, SonarQube, Fortify, Checkmarx, Bandit, gosec, or a language-appropriate equivalent.

## 8. Public Export

Public export is default-deny. Only reviewed allowlist paths may leave the local project.

Must not export:

- `.env*`
- credentials
- service account files
- private keys
- tokens
- raw proof
- private logs
- scratch output
- unreviewed scripts

Required evidence:

- public export manifest

## 9. Deployment Gate

Before deployment, record:

- endpoint exposure review
- auth/session boundary
- rate, quota, or budget gate
- SAST or code-security evidence
- gitleaks, trufflehog, or equivalent secret-scan evidence
- package reputation evidence for dependency-bearing projects

## 10. Closeout

Every security-relevant change must leave a short closeout record:

- what changed
- what was checked
- what failed and why
- what remains risky
- whether public export or deployment is allowed

## Plain-Language Rule

If a project would make an AI agent read it, run it, package it, publish it, or deploy it, the project must first prove that secrets, commands, dependencies, MCP servers, source scans, and export boundaries are under control.
