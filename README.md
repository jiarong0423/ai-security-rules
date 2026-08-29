# ai-security-rules

Read-only local scanner and gate for AI coding security risks.

The tool focuses on security surfaces that are easy to miss in agentic coding workflows:

- agent-readable files such as `AGENTS.md`, `CLAUDE.md`, `SKILL.md`, `.mcp.json`, `.claude/`, `.cursor/`, `.gemini/`, and `.vscode/`;
- repo-borne executable config such as shell commands, package runners, install hooks, process spawning, and network fetches;
- secret exposure indicators without printing secret values;
- package hallucination and slopsquatting watchlist hits;
- public-export gates for demo packages, release bundles, and copied repositories.

## Safety Guarantees

- Does not read `.env` or `.env.*` contents.
- Does not print secret values.
- Does not execute project commands.
- Does not install dependencies.
- Does not modify the scanned project.
- Does not call provider APIs.
- Writes reports only to `--output-dir`.

## Install

From a local checkout:

```bash
python3 -m pip install .
```

For development without installation:

```bash
PYTHONPATH=src python3 -m ai_security_rules --help
```

## Usage

Scan one repository:

```bash
ai-security-rules scan /path/to/repo --output-dir reports
```

Run the design gate before implementation:

```bash
ai-security-rules pre-design /path/to/repo --output-dir reports
```

Run the full rule gate before opening a repository to an agent or before release:

```bash
ai-security-rules rules-check /path/to/repo --output-dir reports
```

Run the public export gate on a generated package or release directory:

```bash
ai-security-rules export-gate /path/to/public-package --output-dir reports
```

The legacy form is also supported:

```bash
ai-security-rules /path/to/repo --mode rules-check --output-dir reports
```

## Exit Codes

- `0`: gate passed, or scan found no high/critical findings.
- `1`: gate failed, or scan found high/critical findings.
- `2`: invalid path, invalid config, or invalid rules file.

## Reports

The scanner writes:

- `local_ai_security_portfolio_report.json`
- `local_ai_security_portfolio_report.md`
- `local_ai_security_scan_XX_<project>.md`

Gate modes also write:

- `local_security_design_gate_<mode>.json`
- `local_security_design_gate_<mode>.md`

## Rules

The default rules are bundled in:

```text
src/ai_security_rules/rules/security_design_gate_rules.json
```

You can supply a custom rules file:

```bash
ai-security-rules rules-check /path/to/repo --rules ./security_design_gate_rules.json --output-dir reports
```

## Design Philosophy

If browser JavaScript can read a value, it is not a secret. Provider calls that need real credentials should go through a protected backend proxy with session, JWT, role, or tenant validation. Long-lived and high-privilege credentials should live behind a secret manager or vault with IAM, audit logs, and revoke/rotate paths.

Public exports are default-deny. Export only reviewed allowlist paths, and keep `.env*`, credentials, private proof material, raw logs, generated scratch output, and unreviewed scripts out of public packages.

## Limitations

- Does not scan git history.
- Does not validate registry ownership over the network.
- Does not replace SAST, dependency scanners, or dedicated secret scanners.
- Uses conservative pattern matching, so findings require review.

## Development

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

Run a local smoke test:

```bash
PYTHONPATH=src python3 -m ai_security_rules rules-check . --output-dir /tmp/ai-security-rules-report
```
