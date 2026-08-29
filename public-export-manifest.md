# Public Export Manifest

Status: pass for current repository scope.

Review Date: 2026-08-30.

## Policy

Public export is default-deny. Only files required for the open-source security gate tool may be exported.

## Allowed Public Paths

| Path | Classification | Reason |
|---|---|---|
| `.github/workflows/ci.yml` | public-export | CI test workflow |
| `.gitignore` | public-export | repository hygiene |
| `LICENSE` | public-export | license |
| `README.md` | public-export | user documentation |
| `REPO_RELEASE_CHECKLIST.md` | public-export | release evidence |
| `SECURITY.md` | public-export | security governance |
| `SECURITY_SCAN_EVIDENCE.md` | public-export | code-security evidence |
| `SECRET_SCAN_EVIDENCE.md` | public-export | secret-scan evidence |
| `PACKAGE_REPUTATION_EVIDENCE.md` | public-export | dependency review evidence |
| `MCP_SERVER_ALLOWLIST.md` | public-export | MCP policy evidence |
| `SECURITY_THREAT_MODEL.md` | public-export | threat model evidence |
| `LOCAL_PROJECT_SECURITY_CONSTITUTION.md` | public-export | local project development constitution |
| `ai-security-rules-tuning.example.json` | public-export | tuning example |
| `package-runner-allowlist.md` | public-export | package runner review evidence |
| `public-export-manifest.md` | public-export | export allowlist |
| `pyproject.toml` | public-export | Python package metadata |
| `src/ai_security_rules/**` | public-export | package source |
| `tests/**` | public-export | synthetic tests |
| `templates/**` | public-export | integration templates |
| `integrations/**` | public-export | extension integration contracts |

## Denied Public Paths

- `.env*`
- credentials and service account files
- private keys
- raw local reports
- private logs
- scratch output
- local screenshots
- user-specific project notes

## Residual Risk

Any new file must be added to this manifest before public export.
