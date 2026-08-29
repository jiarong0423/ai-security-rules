# Demo Script

## Goal

Show that VibeGate catches risks before AI agents create security damage.

## Story

A team wants to use an AI coding agent to work on a repository. Before opening the repo to the agent, they run VibeGate. The tool blocks unsafe stages and produces an agent-readable remediation queue.

## Demo Flow

1. Run the agent review queue.

```bash
PYTHONPATH=src python3 -m ai_security_rules agent-review . --output-dir demo-reports
```

2. Open the generated queue.

```bash
open demo-reports/agentic_security_review_queue.md
```

3. Explain the lanes.

- `pre_development_management`: blocks risky agent/rules/MCP work before design or execution.
- `open_source_pollution_control`: blocks private material from public repos and release packages.
- `hallucination_and_supply_chain_control`: blocks unverified package runners and known hallucination/slopsquatting risks.
- `release_evidence_control`: blocks deployment when SAST, secret-scan, or package reputation evidence is missing or stale.

4. Run the export gate.

```bash
PYTHONPATH=src python3 -m ai_security_rules export-gate . --output-dir demo-reports
```

5. Run the deploy gate.

```bash
PYTHONPATH=src python3 -m ai_security_rules deploy-gate . --output-dir demo-reports
```

## Talk Track

VibeGate is not trying to replace SAST. It catches the stage mistakes that happen around AI-assisted development: poisoned rules, over-powered MCP configs, hallucinated package installs, stale evidence, and public export contamination.

The important part is that the output is safe for an AI coding agent to consume. It contains priorities, required actions, and agent boundaries, but it does not include secret values.

## Video Checklist

- Show the command.
- Show the generated Markdown queue.
- Show at least one P0/P1 blocking decision.
- Show that `.env` contents are never read.
- Explain how this complements SAST, gitleaks/trufflehog, and package reputation review.

