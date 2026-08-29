# Hackathon Rule Fit

## Decision

This project can fit the AI Agent Hackathon if the submission is positioned as an agent reliability, security, and safety tool, and if the judged work focuses on new agentic functionality built during the hackathon.

The best fit is not a generic scanner category. The best fit is pre-agent safety infrastructure: before an AI agent reads a repo, runs tools, installs dependencies, exports code, or deploys, VibeGate checks whether the repo is safe enough to proceed.

## Rule Fit Matrix

| Rule area | Fit | Evidence / positioning |
|---|---|---|
| Eligibility | Fits if submitted by an eligible individual or team. | Open to developers, designers, students, founders, researchers, and builders interested in AI agents. |
| Team size | Fits. | Can be submitted solo or by a team of 1 to 5. |
| Project development | Conditional fit. | The repository existed before the hackathon, so the submission must disclose pre-existing work and focus judging on significant new functionality such as `agent-review`. |
| AI agent requirement | Fits if framed correctly. | The strongest fit is agent evaluation, reliability, security, and safety tooling. The `agent-review` queue gives coding agents bounded remediation work. |
| Original work | Fits. | Code is owned by repository contributors and uses a permissive MIT license. Any external tools or APIs used in the demo must be disclosed. |
| Open source and external tools | Fits. | The rules allow open-source software, AI development tools, coding assistants, and developer tools unless a challenge adds stricter requirements. |
| Submission | Needs final packaging. | Devpost should include repo link, project description, demo video, runnable commands, and disclosure of pre-existing work. |
| Demo requirement | Fits after prototype demo. | Demo should show `agent-review` generating a remediation queue and blocking unsafe agent/export/deploy stages. |
| Safe and responsible use | Fits. | The project is defensive, read-only, avoids unauthorized access, does not deploy malware, and does not collect private information. |
| Infrastructure and cost | Fits. | The local CLI has no required cloud/API cost. Optional LLM or registry checks must be opt-in and should avoid exposing API keys. |
| Judging | Fits with focused story. | Emphasize technical implementation, meaningful AI-agent safety workflow, practicality, reliability, and impact on AI-assisted development. |

## Judging Criteria Fit

| Criteria | How to present VibeGate |
|---|---|
| Technical execution | Working CLI, tests, JSON rule engine, Markdown/JSON evidence output, CI/pre-commit templates. |
| Agent design | Agent-readable remediation queue with priorities, lanes, required actions, and allowed-action boundaries. |
| Innovation and creativity | Shifts security from after-code scanning to before-agent execution and before public export. |
| Impact and usefulness | Solves a real AI-assisted development problem: unsafe repo state before autonomous coding work. |
| Reliability and safety | Defensive tool, no `.env` reads, no secret values printed, no target project commands executed. |
| Demo and completeness | Public repo can run locally without paid API or cloud setup. |

## Prize Track Fit

| Track | Fit | Notes |
|---|---|---|
| General AI Agent Hackathon | Strong | Security and reliability tooling for coding agents is explicitly in scope. |
| Quirq - Build It | Conditional | Stronger if the demo shows an observable workspace where gate decisions, queue items, and agent boundaries are visually clear. |
| Quirq Bounty - Break It | Weak to medium | Could be used to demonstrate how unsafe agent workflows break, but the current project is a defensive builder tool. |
| Code Registry Challenge | Medium to strong | Strong if presented as protection for repositories before agent execution, public export, or deployment. |

## Submission Boundary

Pre-existing baseline:

- scanner
- rule gate framework
- safety guarantees
- evidence gate concept
- public export and deployment controls

Hackathon-judged work:

- `agent-review` mode
- agent-readable remediation queue
- safety lanes for pre-development management, open-source pollution control, hallucination/supply-chain control, and release evidence control
- demo script and Devpost packaging

## Plain-language Positioning

Do not submit it as a generic vulnerability scanner. Submit it as a pre-development safety gate for AI coding agents.

The project answers this problem:

> Before an AI agent reads a repo, runs tools, installs packages, exports code, or deploys, who checks that the repo is not poisoned, over-permissioned, leaking private material, or missing evidence?

VibeGate is that check.
