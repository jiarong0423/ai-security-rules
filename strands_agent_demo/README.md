# VibeGate Strands Agent Demo

This demo wraps `ai-security-rules agent-review` as Strands-compatible tools.

It exists for hackathons that require a working AI agent or agent workflow. The core scanner remains read-only and local; the wrapper turns the scanner into a bounded coding-agent safety reviewer.

## What The Agent Does

The demo exposes three tools:

- `run_vibegate_agent_review`: runs the local VibeGate `agent-review` mode.
- `read_vibegate_queue`: reads the generated remediation queue.
- `recommend_agent_next_action`: decides whether a coding agent should stop, draft governance fixes, or proceed with low-risk cleanup.

## Safety Boundary

- Does not read `.env` or `.env.*` contents.
- Does not print secret values.
- Does not execute target project commands.
- Does not install dependencies.
- Does not modify the target repository.
- Does not call provider APIs.
- Uses deterministic dry-run by default.

## Run Without Strands Credentials

This mode is best for a demo video or first judge reproduction. It proves the agent workflow without requiring AWS credentials or a model provider.

```bash
PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir demo-reports --clean-output
```

## Run With Strands SDK

Install the SDK in a separate environment if you want the real Strands agent loop:

```bash
python3 -m pip install strands-agents
PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir demo-reports --use-strands
```

The default Strands model provider may require AWS credentials or another configured model provider. Do not put API keys in the repository.

## Hackathon Positioning

The judged feature is the agentic safety workflow:

1. A coding agent asks whether it can work on a repository.
2. VibeGate scans the repository without side effects.
3. VibeGate produces a queue with priorities, lanes, evidence, required actions, and agent boundaries.
4. The agent receives a safe next action instead of blindly running tools or exporting code.

