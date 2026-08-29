# MCP Server Allowlist

Status: pass for current repository scope.

## Policy

No MCP server is allowed by default. A project must explicitly record any allowed MCP server before agent execution.

## Allowed Servers

| Server | Command or Transport | Permission Scope | Network Behavior | Owner | Review Date |
|---|---|---|---|---|---|
| none | none | none | none | maintainers | 2026-08-30 |

## Required Review For Additions

- exact server name
- exact command path or transport URL
- filesystem scope
- network scope
- secret access scope
- operator approval requirement
- owner and review date

## Residual Risk

- This repository currently has no MCP server config.
- Any future `.mcp.json`, `mcp.json`, or MCP config directory must update this allowlist before agent execution.
