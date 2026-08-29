# Devpost Submission Draft

## Project Name

VibeGate: Agentic Security Gates for AI-Built Repos

## Tagline

Stop AI coding agents before they leak secrets, trust poisoned rules, install hallucinated packages, or export private project material.

## Inspiration

AI coding tools make it easy to build quickly, but they also introduce new failure modes before traditional security tools ever run. Agent rules, MCP configs, package runner commands, copied scratch files, and public export bundles can become security-sensitive surfaces. VibeGate was built to catch those risks before an agent starts work, before dependencies are installed, before a repo is published, and before deployment evidence is accepted.

## What It Does

VibeGate is a read-only local security gate for agentic coding workflows. It scans repositories for AI-specific risk surfaces and produces both human-readable reports and an agent-ready remediation queue.

Core gates:

- Pre-design gate: requires a threat model and secret ownership before risky implementation starts.
- Rules check: reviews agent-readable files, MCP configuration, package runners, and evidence gaps.
- Export gate: blocks public release packages that contain secret-like files, private proof material, scratch output, or unclassified artifacts.
- Deploy gate: requires fresh SAST, secret-scan, and package reputation evidence.
- Agent review queue: converts scanner and gate findings into P0/P1/P2 remediation items that an AI coding agent can safely consume.

## Why It Is Different

Traditional SAST focuses on source-code vulnerabilities. VibeGate focuses on the security problems around AI-assisted development:

- prompt-injection indicators in `AGENTS.md`, `SKILL.md`, `.cursor/`, `.claude/`, `.gemini/`, and `.vscode/`
- MCP over-privilege indicators such as `sudo`, broad filesystem access, and wildcard network scope
- package hallucination and slopsquatting watchlist hits
- evidence gates for gitleaks/trufflehog, Semgrep/CodeQL/SAST, and lockfile/package reputation review
- public export default-deny controls to prevent open-source pollution

It complements SAST and secret scanners instead of replacing them.

## AI Agent Requirement

The hackathon-facing feature is the `agent-review` mode. It turns scan and gate outputs into an agent-readable remediation queue with strict boundaries:

- P0: agent may prepare patches or manifests, but a human must approve release/export decisions.
- P1: agent may draft governance fixes and evidence templates, but blocked gates remain blocked until evidence exists.
- P2: agent may prepare low-risk documentation and cleanup suggestions.

This makes the project meaningful for agent reliability, security, and safety tooling rather than a plain static scanner.

## Built During The Hackathon

Disclose the baseline scanner as pre-existing open-source work. The hackathon submission should focus judging on the new agentic delivery layer:

- `agent-review` remediation queue
- Devpost-ready demo workflow
- clearer target-user positioning for AI-agent-assisted teams, DevSecOps, open-source maintainers, and governance-heavy teams
- prevention lanes for pre-development management, open-source pollution, hallucination/supply-chain risk, and release evidence

## How We Built It

The tool is a zero-dependency Python CLI. It uses conservative local static analysis, JSON rule files, evidence manifests, and Markdown/JSON reports. It intentionally avoids project command execution, dependency installation, provider API calls, and `.env` content reads.

## Challenges

The main design tradeoff is avoiding side effects while still being useful. Instead of trying to be a full SAST tool, VibeGate records missing evidence and blocks stage transitions when the evidence does not exist. This keeps the default behavior safe enough for local repos and CI.

## Accomplishments

- Read-only scanner with no dependency installation.
- `.env` content is skipped by default.
- Secret values are redacted and never printed.
- Agent/rules/MCP files are treated as code.
- Public export is default-deny.
- SAST, secret-scan, and package reputation are enforced as evidence gates.
- `agent-review` turns findings into an AI-agent-safe remediation queue.

## What Is Next

- Optional IDE extension for live rule feedback.
- Optional hosted dashboard for teams.
- Deeper package reputation scoring.
- SARIF output for GitHub code scanning integration.
- Optional LLM summarizer that consumes the local JSON queue without receiving secret values.

## Demo Commands

```bash
PYTHONPATH=src python3 -m ai_security_rules agent-review . --output-dir demo-reports
PYTHONPATH=src python3 -m ai_security_rules export-gate . --output-dir demo-reports
PYTHONPATH=src python3 -m ai_security_rules deploy-gate . --output-dir demo-reports
```

