# IDE Extension Specification

Status: design-ready; intentionally not bundled into the Python CLI.

## Goal

Provide a lightweight VS Code or Cursor extension that shows `ai-security-rules` gate status while editing agent-readable files.

## Watched Files

- `AGENTS.md`
- `CLAUDE.md`
- `SKILL.md`
- `.mcp.json`
- `mcp.json`
- `.cursor/**`
- `.claude/**`
- `.gemini/**`
- `.codex/**`
- `.vscode/settings.json`
- `.vscode/tasks.json`

## Local Command Contract

The extension should shell out to the installed CLI:

```bash
ai-security-rules rules-check . --output-dir .ai-security-rules
```

The extension must not:

- read `.env*` contents directly
- print secret values
- install packages
- run project commands other than the scanner command configured by the user
- bypass CLI exit codes

## UI States

| CLI Result | Status Bar | Problem Severity |
|---|---|---|
| exit 0 | AI Gate: pass | none |
| exit 1 | AI Gate: blocked | warning or error by finding severity |
| exit 2 | AI Gate: config error | error |

## Diagnostics Mapping

- `critical` and `high`: error
- `medium`: warning
- `low` and `info`: information
- gate `blocked=true`: error

## Security Boundary

The extension is only a viewer and launcher for the local scanner. The CLI remains the source of truth for gate decisions.
