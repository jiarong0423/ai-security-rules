# Package Runner Allowlist

Status: pass for current repository scope.

## Policy

Package runners are not allowed by default. Any `npx`, `bunx`, `pnpm dlx`, `yarn dlx`, `pip install`, `uv pip`, or `poetry add` command must be reviewed before agent execution.

## Allowed Commands

| Command | Scope | Owner | Review Date | Notes |
|---|---|---|---|---|
| `python3 -m pip install .` | local installation from this checked-out repository | maintainers | 2026-08-30 | documented install path; not for automatic agent execution |

## Not Allowed

- Unpinned package runner commands copied from agent output
- Unknown one-shot package runners
- Install hooks triggered by unreviewed dependencies
- Commands that combine package installation with script execution

## Residual Risk

This allowlist records documentation-safe commands. It does not grant automatic execution permission to agents.
