# Security Governance

## Secret Ownership

Owner: maintainers.

Storage location: this repository must not store secret values. Only secret names, environment variable names, and evidence references may appear in tracked files.

Rotation path: if a real credential is suspected in current files, generated artifacts, git history, CI logs, or public exports, revoke and rotate it at the provider first, then repair repository state.

Revoke path: revoke provider-side tokens, invalidate service account keys, remove affected deployment variables, and regenerate credentials through the relevant secret manager or provider console.

## Reporting

Open an issue or private maintainer channel with:

- affected file path or commit hash
- secret type only
- whether the value was exposed publicly
- whether rotation is already complete

Do not include secret values in reports.
