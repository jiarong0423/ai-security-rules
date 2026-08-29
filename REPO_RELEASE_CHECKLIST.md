# Repo Release Checklist

Status: ready for initial GitHub repository import.

## Included

- Python package under `src/ai_security_rules/`.
- Console command: `ai-security-rules`.
- Module command: `python3 -m ai_security_rules`.
- Bundled rules: `src/ai_security_rules/rules/security_design_gate_rules.json`.
- README with install, usage, reports, exit codes, safety boundaries, and limitations.
- MIT license.
- GitHub Actions CI.
- Unit tests with synthetic fixtures only.

## Verified

Run from this directory:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m unittest discover -s tests
```

Result:

```text
Ran 3 tests
OK
```

Self-scan:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python3 -m ai_security_rules scan . --output-dir /private/tmp/ai-security-rules-self-scan-final
```

Result:

```text
critical=0 high=0 medium=18
```

The remaining medium findings are expected because the scanner source and README describe shell commands, package runners, install hooks, and permission concepts as rule text.

Sanitization check:

```bash
rg -n -- "PRIVATE_LOCAL_PATH_PATTERN|PRIVATE_PROJECT_NAME|PRIVATE_OWNER|sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}" .
```

Result: no matches.

## Before Public Push

1. Create a new empty GitHub repository.
2. Review `README.md` and package name.
3. Run tests again.
4. Run self-scan again.
5. Commit only the files in this directory.
6. Do not include generated report directories, `.env*`, local test output, or private project reports.
