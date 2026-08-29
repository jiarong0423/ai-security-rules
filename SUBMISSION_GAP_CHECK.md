# Submission Gap Check

Updated: 2026-08-30 Asia/Taipei

## Current Gate Status

Local self-checks for the public repository:

```text
rules-check: pass
deploy-gate: pass
agent-review: pass
P0: 0
P1: 0
P2: 72 documentation/test-fixture governance reminders
```

The P2 items are expected because the repository documents security patterns, command examples, Strands usage, AgentCore commands, synthetic test fixtures, and permission concepts.

## Devpost Required Items

| Requirement | Status | Evidence |
|---|---|---|
| Public code repository | Done | `https://github.com/jiarong0423/ai-security-rules` |
| MIT or Apache license | Done | `LICENSE` |
| README | Done | `README.md` |
| Setup instructions | Done | `README.md`, `strands_agent_demo/README.md` |
| Strands Agents SDK usage | Done | `strands_agent_demo/vibegate_strands_agent.py`, `pyproject.toml` optional extra `strands` |
| Architecture diagram | Done | `assets/vibegate_architecture_upload.png`, `ARCHITECTURE.md` |
| AWS Builder ID | Form-only | Enter in Devpost, do not commit personal account details |
| Demo video URL | Still needed | Upload a public YouTube or Vimeo video, then paste the URL in Devpost |
| Track | Form-only | Recommended: `Professional Agents` |
| Country / submitter type | Form-only | Fill directly in Devpost |

## Safe Recording Flow

Use the public repository only:

```bash
cd ai-security-rules
PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir demo-reports --clean-output
sed -n '1,120p' demo-reports/agentic_security_review_queue.md
```

Show:

- GitHub repository page.
- README and MIT license.
- `strands_agent_demo/`.
- `aws_agentcore/`.
- Terminal output with `decision=pass`, `P0=0`, and `P1=0`.
- Generated `agentic_security_review_queue.md`.
- Architecture diagram.

Do not show:

- AWS console login, billing, IAM, or credentials pages.
- `.env` files.
- private repositories.
- local home directory listings.
- API keys, access tokens, account IDs, or personal email.

## Submission Positioning

Use this framing:

```text
VibeGate is a Strands SDK professional agent workflow that checks repositories before AI coding agents run. It helps developers and DevSecOps teams avoid unsafe agent rules, over-permissioned MCP tools, hallucinated packages, missing security evidence, and accidental public export of private material.
```

Do not claim:

- that the project is a full replacement for SAST, secret scanning, or dependency scanning.
- that it is already deployed on AWS AgentCore unless a deployment has actually been completed.
- that AWS credentials, billing, or private projects are required for the default demo.
