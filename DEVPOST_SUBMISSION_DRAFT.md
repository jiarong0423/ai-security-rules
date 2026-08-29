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

## Best Challenge Fit

Primary fit:

- AI agent evaluation, reliability, security, and safety tooling.

Prize-track fit:

- Quirq - Build It: fits if the demo shows an observable agent workspace or review environment where risks, gates, and agent actions are visible.
- Code Registry Challenge: fits if positioned as protection for codebases before agent execution, public export, or deployment.

The strongest judging angle is reliability and safety: VibeGate prevents AI coding agents from acting on unsafe repo state.

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

## How AI Agents Are Used

The prototype is designed around a coding-agent workflow:

1. A developer runs VibeGate before letting an AI coding agent enter a repo.
2. VibeGate scans the repo without executing project code.
3. VibeGate produces a structured remediation queue that an AI coding agent can read.
4. The queue tells the agent which work is allowed, which work is blocked, and which items require human approval.
5. The developer or CI gate prevents export/deploy when P0/P1 items remain.

This is agentic because the tool controls the safety boundary around autonomous or semi-autonomous coding work.

## Built During The Hackathon

Disclose the baseline scanner as pre-existing open-source work. The hackathon submission should focus judging on the new agentic delivery layer:

- `agent-review` remediation queue
- Devpost-ready demo workflow
- clearer target-user positioning for AI-agent-assisted teams, DevSecOps, open-source maintainers, and governance-heavy teams
- prevention lanes for pre-development management, open-source pollution, hallucination/supply-chain risk, and release evidence

## Submission Requirements

Repository:

- https://github.com/jiarong0423/ai-security-rules

Demo video:

- Maximum length: 3 minutes.
- Show the working prototype running locally.
- Focus on `agent-review` and the generated remediation queue.
- Show the gate decision and explain why unsafe agent execution/export/deploy is blocked.

Team members:

- Replace with final participant name(s) before submission.

Major models, frameworks, APIs, tools, and datasets:

- Python 3.10+
- Git
- JSON rule engine
- Markdown and JSON report outputs
- Optional external evidence tools: gitleaks, trufflehog, Semgrep, CodeQL, SAST tools, dependency scanners
- Optional AI coding tools in workflow: Codex, Cursor, Claude Code, GitHub Copilot, Gemini CLI
- No required dataset
- No required paid API

Setup instructions:

```bash
git clone https://github.com/jiarong0423/ai-security-rules.git
cd ai-security-rules
PYTHONPATH=src python3 -m ai_security_rules agent-review . --output-dir demo-reports
open demo-reports/agentic_security_review_queue.md
```

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

## Judging Criteria Alignment

Technical execution:

- Working Python CLI with tests, structured reports, and stage gates.

Agent design:

- Produces an agent-readable remediation queue with explicit action boundaries.

Creativity:

- Moves security left from code scanning to pre-agent development management.

Impact and usefulness:

- Helps AI-assisted teams prevent unsafe agent execution, package hallucination, and open-source pollution.

Reliability and safety:

- Read-only design, no `.env` reads, no secret values printed, no project commands executed.

Demo completeness:

- Local prototype can be run from a public repository with no paid API.

## Demo Commands

```bash
PYTHONPATH=src python3 -m ai_security_rules agent-review . --output-dir demo-reports
PYTHONPATH=src python3 -m ai_security_rules export-gate . --output-dir demo-reports
PYTHONPATH=src python3 -m ai_security_rules deploy-gate . --output-dir demo-reports
```
