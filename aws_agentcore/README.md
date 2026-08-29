# AWS AgentCore Deployment Guide

This folder documents the AWS path for the VibeGate Strands Agent prototype.

The repository is safe to judge without AWS credentials because the default demo is deterministic and local. For the Agents for Humans hackathon, the stronger AWS path is:

1. Install VibeGate with the Strands extra.
2. Verify the real Strands SDK path locally.
3. Create an Amazon Bedrock AgentCore project.
4. Copy or reference the VibeGate Strands entrypoint.
5. Run `agentcore dev`.
6. Deploy only after AWS account, region, IAM, model access, and cost boundaries are confirmed.

## Local Strands Run

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -e ".[strands]"
PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir demo-reports --use-strands --clean-output
```

Do not commit `.venv`, AWS credentials, API keys, `.env` files, or generated private reports.

## AgentCore Prerequisites

You need:

- AWS account with credentials configured outside the repository.
- AWS Builder ID for the Devpost submission.
- Node.js 20 or newer.
- Python 3.10 or newer.
- AWS CDK installed.
- IAM permissions for AgentCore deployment.
- Amazon Bedrock model access in the selected AWS region.

## Create An AgentCore Project

Run this outside the public repository or in a separate deployment workspace:

```bash
npm install -g @aws/agentcore
agentcore create --name VibeGate --framework Strands --protocol HTTP --model-provider Bedrock --memory none --build CodeZip
```

After the scaffold is created, install this repository as the agent dependency or copy the Strands entrypoint into the generated app package.

## Agent Entrypoint

Use this command as the functional smoke test before packaging:

```bash
PYTHONPATH=src python3 strands_agent_demo/vibegate_strands_agent.py . --output-dir demo-reports --use-strands --clean-output
```

Expected result:

- VibeGate runs a repository review.
- `demo-reports/agentic_security_review_queue.json` is written.
- `demo-reports/agentic_security_review_queue.md` is written.
- The Strands agent summarizes the gate decision and the next allowed action.

## Local AgentCore Dev

Inside the generated AgentCore project:

```bash
agentcore dev --no-browser
```

Then invoke the local HTTP runtime from another terminal using the prompt that asks VibeGate to review the repository and return a gate decision.

## Deploy

Only deploy after verifying AWS permissions, model access, and cost boundaries:

```bash
agentcore deploy --dry-run
agentcore deploy
```

For the hackathon submission, AgentCore deployment is useful evidence for technical implementation, but it is not required for the project to be a valid Strands-based prototype.
