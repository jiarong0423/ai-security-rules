# Demo Script

## Goal

Show that VibeGate catches risks before AI agents create security damage.

Target length: 5 minutes maximum for Agents for Humans.

## Story

A team wants to use an AI coding agent to work on a repository. Before opening the repo to the agent, they run VibeGate. The tool blocks unsafe stages and produces an agent-readable remediation queue.

## Demo Flow

1. Run the agent review queue.

```bash
PYTHONPATH=src python3 -m ai_security_rules agent-review . --output-dir demo-reports
```

2. Run the Strands-compatible agent workflow.

```bash
PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir demo-reports --clean-output
```

3. Open the generated queue.

```bash
open demo-reports/agentic_security_review_queue.md
```

4. Explain the lanes.

- `pre_development_management`: blocks risky agent/rules/MCP work before design or execution.
- `open_source_pollution_control`: blocks private material from public repos and release packages.
- `hallucination_and_supply_chain_control`: blocks unverified package runners and known hallucination/slopsquatting risks.
- `release_evidence_control`: blocks deployment when SAST, secret-scan, or package reputation evidence is missing or stale.

5. Run the export gate.

```bash
PYTHONPATH=src python3 -m ai_security_rules export-gate . --output-dir demo-reports
```

6. Run the deploy gate.

```bash
PYTHONPATH=src python3 -m ai_security_rules deploy-gate . --output-dir demo-reports
```

## Talk Track

VibeGate is not trying to replace SAST. It catches the stage mistakes that happen around AI-assisted development: poisoned rules, over-powered MCP configs, hallucinated package installs, stale evidence, and public export contamination.

The important part is that the output is safe for an AI coding agent to consume. It contains priorities, required actions, and agent boundaries, but it does not include secret values.

## 3-Minute Video Structure

## 5-Minute Video Structure

0:00-0:35 Problem:

AI coding agents can read repo rules, start tools, install packages, and package code faster than humans review the security boundary.

0:35-1:05 Target users:

Developers, open-source maintainers, DevSecOps engineers, creators, and small teams using AI coding agents.

1:05-2:10 Working prototype:

Run the Strands-compatible wrapper and show `agentic_security_review_queue.md`.

2:10-3:15 Agentic behavior:

Explain that the wrapper exposes tools to run the review, read the queue, and recommend the next safe coding-agent action.

3:15-4:15 Safety:

Show the safety guarantees: no `.env` reads, no project command execution, no secret values printed, no provider API calls.

4:15-4:45 Architecture:

Show `ARCHITECTURE.md` and explain the scan, gate, queue, and recommendation flow.

4:45-5:00 Impact:

This gives teams a pre-development gate before agent execution, dependency installation, public export, or deployment.

## Video Checklist

- Show the command.
- Show the Strands-compatible wrapper.
- Show the generated Markdown queue.
- Show `ARCHITECTURE.md`.
- Show at least one P0/P1 blocking decision.
- Show that `.env` contents are never read.
- Explain how this complements SAST, gitleaks/trufflehog, and package reputation review.
- Name the tools used: Python, Git, JSON rules, Markdown/JSON reports, optional SAST/secret/dependency evidence tools.
- Mention the intended track: Professional Agents.
