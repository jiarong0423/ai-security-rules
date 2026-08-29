# Repo Release Checklist

Status: ready for Devpost submission after demo video URL is added.

## Included

- Python package under `src/ai_security_rules/`.
- Console command: `ai-security-rules`.
- Module command: `python3 -m ai_security_rules`.
- Modes: `scan`, `history-scan`, `pre-design`, `rules-check`, `export-gate`, `deploy-gate`.
- Agent review mode: `agent-review`, which emits `agentic_security_review_queue.json` and `agentic_security_review_queue.md`.
- SAST/code-security evidence gate via `SECURITY_SCAN_EVIDENCE.md`, `SAST_EVIDENCE.md`, or `CODE_SECURITY_EVIDENCE.md`.
- Git history secret-scan evidence gate via `SECRET_SCAN_EVIDENCE.md`, `GITLEAKS_EVIDENCE.md`, or `TRUFFLEHOG_EVIDENCE.md`.
- Lockfile/package reputation evidence gate via `PACKAGE_REPUTATION_EVIDENCE.md`.
- MCP server allowlist manifest gate via `MCP_SERVER_ALLOWLIST.md` or `mcp-server-allowlist.json`.
- Pre-design threat model gate via `SECURITY_THREAT_MODEL.md` or `THREAT_MODEL.md`.
- Local project development constitution: `LOCAL_PROJECT_SECURITY_CONSTITUTION.md`.
- Prompt-injection and invisible-character scanning for agent-readable files.
- MCP over-privilege scanning for `sudo`, root scope, home-directory scope, destructive permissions, and wildcard network access.
- Evidence freshness gate with configurable `--evidence-max-age-days`.
- Copy-ready integration templates under `templates/`.
- IDE extension integration contract under `integrations/`.
- Strands SDK agent demo under `strands_agent_demo/`.
- AWS AgentCore deployment guide under `aws_agentcore/`.
- Strands install extra via `pip install -e ".[strands]"`.
- Optional false-positive tuning via `--tuning`, limited to low/medium/info findings.
- Optional npm/PyPI package existence checks via `--registry-check`; disabled by default.
- Bundled rules: `src/ai_security_rules/rules/security_design_gate_rules.json`.
- Devpost submission draft, hackathon disclosure, and demo script.
- Architecture diagram in `ARCHITECTURE.md`.
- README with install, usage, reports, exit codes, target users, safety boundaries, and limitations.
- MIT license.
- GitHub Actions CI.
- Unit tests with synthetic fixtures only.

## Verified

Run from this directory:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests
```

Result:

```text
Ran 22 tests
OK
```

Self-scan:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m ai_security_rules scan . --output-dir /private/tmp/ai-security-rules-self-scan-final
```

Result:

```text
critical=0 high=0 medium=61
```

Latest hackathon self-scan after the submission gap checklist update:

```text
critical=0 high=0 medium=72
```

The remaining medium findings are expected because the scanner source, tests, Strands wrapper, demo script, hackathon rule-fit document, AWS AgentCore guide, and README describe shell commands, package runners, install hooks, synthetic secret fixtures, and permission concepts as rule text.

Agent review self-check:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m ai_security_rules agent-review . --output-dir /private/tmp/ai-security-rules-agent-review-self
```

Result:

```text
Gate: mode=rules-check decision=pass blocking=0 P0=0 P1=0 P2=0
Agent review: decision=pass items=61 P0=0 P1=0 P2=61 P3=0
```

Latest hackathon agent review after the submission gap checklist update:

```text
Gate: mode=rules-check decision=pass blocking=0 P0=0 P1=0 P2=0
Agent review: decision=pass items=72 P0=0 P1=0 P2=72 P3=0
```

Strands SDK dry-run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir /private/tmp/vibegate-strands-demo --clean-output
```

Result:

```text
Mode: deterministic dry-run
Strands SDK available: False
Tool Call: run_vibegate_agent_review
Tool Call: read_vibegate_queue
Tool Call: recommend_agent_next_action
```

History self-scan:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m ai_security_rules history-scan . --output-dir /private/tmp/ai-security-rules-v02-history-2
```

Result:

```text
critical=0 high=0 medium=22
```

Sanitization check:

```bash
rg -n -- "PRIVATE_LOCAL_PATH_PATTERN|PRIVATE_PROJECT_NAME|PRIVATE_OWNER|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}" .
```

Result: no matches.

## Before Public Push

1. Confirm `git status --short --branch` is clean.
2. Confirm `origin/main` contains the latest commit.
3. Confirm the public GitHub repository shows the MIT license, README, architecture image, `strands_agent_demo/`, and `aws_agentcore/`.
4. Run tests again.
5. Run self-scan again.
6. Commit only the files in this directory.
7. Do not include generated report directories, `.env*`, local test output, or private project reports.

## Devpost Submission Gaps

Required and already present:

- Public repository URL.
- MIT license.
- README with setup instructions.
- Architecture diagram file.
- Strands SDK wrapper and optional AgentCore deployment route.
- Local deterministic demo path without credentials.

Required and external to the repository:

- Demo video URL from YouTube or Vimeo.
- AWS Builder ID entered in the Devpost form.
- Submitter country and track selection.

Optional:

- Live demo link.
- Builder blog post.
