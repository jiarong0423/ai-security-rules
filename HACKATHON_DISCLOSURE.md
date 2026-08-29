# Hackathon Disclosure

## Pre-Existing Work

This repository existed before the hackathon as an open-source local scanner and rule gate for AI-assisted development security.

Pre-existing baseline:

- read-only local repository scan
- `.env` content skip behavior
- redacted secret indicators
- agent/rules/MCP file scanning
- package hallucination and slopsquatting watchlist
- public export gate
- SAST, secret-scan, and package reputation evidence gates
- pre-commit and GitHub Actions templates
- local project security constitution

## New Hackathon-Facing Work

The work that should be judged for an AI Agent Hackathon submission is the agentic delivery layer built on top of the baseline scanner:

- `agent-review` mode
- agent-readable remediation queue in JSON and Markdown
- queue lanes for pre-development management, open-source pollution control, hallucination/supply-chain control, and release evidence control
- priority boundaries that define what an AI coding agent may and may not do
- Devpost-ready project story and demo flow

## Why This Is Eligible

The rules allow existing open-source libraries, developer tools, boilerplate, AI tools, and general-purpose infrastructure when disclosed. The submitted value is the new significant functionality that turns static scanner output into an agentic safety workflow for AI coding agents.

## Submission Requirement Notes

The Devpost submission should include:

- public repository link
- 3-minute maximum demo video
- short project description
- list of major models, frameworks, APIs, tools, and datasets
- all team member names
- setup instructions
- clear disclosure of pre-existing baseline versus hackathon-built agentic workflow

## Safety Statement

The project does not read `.env` contents, does not print secret values, does not run target project commands, does not install dependencies, does not modify the scanned project, and does not call provider APIs. Optional package registry checks require explicit opt-in.
