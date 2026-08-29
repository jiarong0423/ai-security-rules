# Security Scan Evidence

Status: pass for the current repository scope.

## Scope

- Project: `ai-security-rules`
- Purpose: read-only local gate for AI-assisted coding security risks
- Source scope: Python package, bundled JSON rules, tests, README, release checklist, and GitHub Actions workflow
- Excluded by design: `.env*` contents, external provider API calls, package installation, project command execution, and network registry validation

## Evidence

| Check | Command | Result |
|---|---|---|
| Unit tests | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests` | passed |
| Current tree AI security scan | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m ai_security_rules scan . --output-dir /private/tmp/ai-security-rules-v02-final-scan` | passed with critical=0 and high=0 |
| Local git history scan | `PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m ai_security_rules history-scan . --output-dir /private/tmp/ai-security-rules-v02-final-history` | passed with critical=0 and high=0 |
| Targeted sensitive string check | `rg` against private local paths, prior project names, personal Gmail, and common key patterns | passed with no matches |

## SAST Position

This repository does not implement deep source-level SAST. It is intentionally scoped to AI agent configuration, executable repo configuration, secret exposure indicators, package hallucination watchlists, public-export controls, and evidence gates.

For production use, pair this tool with at least one source-code SAST layer such as CodeQL, Semgrep, SonarQube, Fortify, Checkmarx, Bandit, gosec, or the language-specific scanner appropriate to the project.

## Residual Risk

- Pattern matching can produce false positives or miss context-dependent flaws.
- Offline mode cannot prove package registry ownership or maintainer reputation.
- This evidence records the current repo state only; downstream users should generate their own project evidence before release.
