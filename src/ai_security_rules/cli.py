#!/usr/bin/env python3
"""
Read-only AI coding security portfolio scanner.

Scope:
- Agent / MCP / rules-file attack surface
- Repo-borne executable config
- Secret exposure indicators
- Package hallucination / slopsquatting watchlist
- Basic project hardening posture

This tool does not delete, modify, install, execute project code, or call the network.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable


EXCLUDED_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".next",
    ".nuxt",
    "dist",
    "build",
    "coverage",
    "reports",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".terraform",
}

EXCLUDED_DIR_PREFIXES = {
    ".venv",
    "venv",
}

EXCLUDED_FILE_PREFIXES = {
    ".env",
    "local_ai_security_portfolio_report",
    "local_ai_security_scan_",
    "local_ai_security_scanner",
}

EXCLUDED_FILE_SUFFIXES = {
    ".pyc",
    ".pyo",
}

MAX_FILE_BYTES = 2_000_000
MAX_TEXT_CHARS = 250_000
REGISTRY_TIMEOUT_SECONDS = 5

AGENT_CONFIG_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp.config.json",
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
    "copilot-instructions.md",
    "settings.json",
    "tasks.json",
    "launch.json",
    "SKILL.md",
}

AGENT_CONFIG_DIR_PARTS = {
    ".claude",
    ".cursor",
    ".gemini",
    ".codex",
    ".github",
    ".vscode",
}

EXECUTABLE_CONFIG_PATTERNS = [
    ("shell_command", re.compile(r"\b(bash|sh|zsh|powershell|pwsh|cmd\.exe)\b", re.I)),
    ("network_fetch", re.compile(r"\b(curl|wget|Invoke-WebRequest|fetch\(|axios\.|requests\.)\b", re.I)),
    ("package_runner", re.compile(r"\b(npx|bunx|pnpm\s+dlx|yarn\s+dlx|pip\s+install|uv\s+pip|poetry\s+add)\b", re.I)),
    ("install_hook", re.compile(r"\b(preinstall|install|postinstall|prepare|prepublish|setup\.py)\b", re.I)),
    ("process_spawn", re.compile(r"\b(child_process|execSync|spawn\(|subprocess\.|os\.system|Runtime\.getRuntime)\b", re.I)),
    ("credential_terms", re.compile(r"\b(token|secret|api[_-]?key|credential|password|private[_-]?key)\b", re.I)),
    ("agent_permission", re.compile(r"\b(allow|permission|bypass|dangerously|auto[_-]?approve|trust|workspace)\b", re.I)),
]

SECRET_PATTERNS = [
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("private_key_header", re.compile(r"-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("generic_assignment", re.compile(r"\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*['\"][^'\"]{12,}['\"]", re.I)),
]

KNOWN_HALLUCINATION_OR_SLOPSQUAT_NAMES = {
    "huggingface-cli": "Known package hallucination case; validate official Hugging Face CLI install path.",
    "react-codeshift": "Reported hallucinated npx command in Agent Skills; validate before running.",
    "unused-imports": "Reported malicious slopsquatting / package-hallucination-related package; validate carefully.",
}

PACKAGE_FILES = {
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "Pipfile",
    "Pipfile.lock",
    "Cargo.toml",
    "Cargo.lock",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
}

PROJECT_MARKER_FILES = PACKAGE_FILES | {
    ".mcp.json",
    "mcp.json",
    "CLAUDE.md",
    "AGENTS.md",
    ".cursorrules",
    "copilot-instructions.md",
    "docker-compose.yml",
    "Dockerfile",
    "terraform.tf",
    "main.tf",
    ".gitignore",
    "requirements.txt",
    "pyproject.toml",
    "package.json",
}

RISK_WEIGHTS = {
    "critical": 100,
    "high": 40,
    "medium": 12,
    "low": 4,
    "info": 1,
}


@dataclass
class Finding:
    severity: str
    category: str
    file: str
    line: int | None
    title: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class TuningRule:
    category: str
    file: str | None
    title_contains: str | None
    reason: str
    expires: str | None


@dataclass
class ScanSummary:
    target: str
    generated_at: str
    files_seen: int
    files_scanned: int
    findings_total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    risk_score: int
    risk_band: str


@dataclass
class ProjectProfile:
    target: str
    project_markers: list[str]
    agent_surface: bool
    package_surface: bool
    ci_surface: bool
    infra_surface: bool
    secret_surface: bool


@dataclass
class ProjectReport:
    summary: ScanSummary
    profile: ProjectProfile
    findings: list[Finding]


@dataclass
class RegistryPackage:
    ecosystem: str
    name: str
    source_file: str


@dataclass
class RegistryCheck:
    ecosystem: str
    package: str
    source_file: str
    status: str
    evidence: str


@dataclass
class GateFinding:
    stage: str
    rule_id: str
    severity: str
    target: str
    blocked: bool
    title: str
    evidence: str
    required_control: str


@dataclass
class GateSummary:
    mode: str
    generated_at: str
    rules_path: str
    projects_evaluated: int
    gate_findings_total: int
    blocking_findings: int
    p0: int
    p1: int
    p2: int
    decision: str


@dataclass
class PortfolioSummary:
    generated_at: str
    targets_requested: list[str]
    projects_scanned: int
    files_seen: int
    files_scanned: int
    findings_total: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    risk_score: int
    highest_risk_band: str


def is_binary_sample(data: bytes) -> bool:
    if b"\x00" in data:
        return True
    if not data:
        return False
    textish = sum(1 for byte in data[:4096] if byte in b"\n\r\t\b" or 32 <= byte <= 126)
    return textish / min(len(data), 4096) < 0.70


def iter_paths(root: Path, *, skip_excluded_files: bool) -> Iterable[Path]:
    for current_root, dirs, files in os.walk(root):
        dirs[:] = [
            name
            for name in dirs
            if name not in EXCLUDED_DIRS and not any(name.startswith(prefix) for prefix in EXCLUDED_DIR_PREFIXES)
        ]
        current = Path(current_root)
        for name in files:
            if skip_excluded_files and any(name.startswith(prefix) for prefix in EXCLUDED_FILE_PREFIXES):
                continue
            if skip_excluded_files and any(name.endswith(suffix) for suffix in EXCLUDED_FILE_SUFFIXES):
                continue
            yield current / name


def iter_files(root: Path) -> Iterable[Path]:
    yield from iter_paths(root, skip_excluded_files=True)


def iter_inventory_files(root: Path) -> Iterable[Path]:
    yield from iter_paths(root, skip_excluded_files=False)


def is_secret_file_name(name: str) -> bool:
    return name == ".env" or name.startswith(".env.")


def safe_relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def read_text_file(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
        if is_binary_sample(data):
            return None
        text = data.decode("utf-8", errors="replace")
        return text[:MAX_TEXT_CHARS]
    except OSError:
        return None


def load_tuning_rules(path: Path | None) -> list[TuningRule]:
    if path is None:
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read tuning file: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid tuning JSON: {path}: {exc}") from exc
    entries = payload.get("allowed_false_positives", [])
    if not isinstance(entries, list):
        raise ValueError("Tuning JSON allowed_false_positives must be an array.")
    rules: list[TuningRule] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ValueError(f"Tuning entry #{index} must be an object.")
        category = entry.get("category")
        reason = entry.get("reason")
        if not isinstance(category, str) or not category:
            raise ValueError(f"Tuning entry #{index} must contain category.")
        if not isinstance(reason, str) or len(reason.strip()) < 8:
            raise ValueError(f"Tuning entry #{index} must contain a meaningful reason.")
        file_value = entry.get("file")
        title_value = entry.get("title_contains")
        expires_value = entry.get("expires")
        if file_value is not None and not isinstance(file_value, str):
            raise ValueError(f"Tuning entry #{index} file must be a string.")
        if title_value is not None and not isinstance(title_value, str):
            raise ValueError(f"Tuning entry #{index} title_contains must be a string.")
        if expires_value is not None and not isinstance(expires_value, str):
            raise ValueError(f"Tuning entry #{index} expires must be a string.")
        if not file_value and not title_value:
            raise ValueError(f"Tuning entry #{index} must contain file or title_contains.")
        if expires_value:
            try:
                expiry = dt.date.fromisoformat(expires_value)
            except ValueError as exc:
                raise ValueError(f"Tuning entry #{index} expires must use YYYY-MM-DD.") from exc
            if expiry < dt.datetime.now(dt.timezone.utc).date():
                continue
        rules.append(
            TuningRule(
                category=category,
                file=file_value,
                title_contains=title_value,
                reason=reason.strip(),
                expires=expires_value,
            )
        )
    return rules


def tuning_rule_matches(rule: TuningRule, finding: Finding) -> bool:
    if finding.severity in {"critical", "high"}:
        return False
    if finding.category != rule.category:
        return False
    if rule.file and finding.file != rule.file:
        return False
    if rule.title_contains and rule.title_contains.lower() not in finding.title.lower():
        return False
    return True


def apply_tuning_rules(findings: list[Finding], rules: list[TuningRule]) -> tuple[list[Finding], int]:
    if not rules:
        return findings, 0
    kept: list[Finding] = []
    suppressed = 0
    for finding in findings:
        if any(tuning_rule_matches(rule, finding) for rule in rules):
            suppressed += 1
            continue
        kept.append(finding)
    return kept, suppressed


def redact_line(line: str) -> str:
    lowered = line.lower()
    if "private_key" in lowered or "begin " in lowered or "credential" in lowered:
        return "[REDACTED_SENSITIVE_LINE]"
    redacted = line.strip()
    for _, pattern in SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED_SECRET]", redacted)
    if len(redacted) > 180:
        redacted = redacted[:177] + "..."
    return redacted


def line_number_for_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def line_at(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def is_agent_config(path: Path) -> bool:
    if path.name in AGENT_CONFIG_NAMES:
        return True
    parts = set(path.parts)
    return bool(parts & AGENT_CONFIG_DIR_PARTS)


def severity_rank(severity: str) -> int:
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(severity, 5)


def recompute_summary(summary: ScanSummary, findings: list[Finding]) -> ScanSummary:
    counts = {severity: 0 for severity in ["critical", "high", "medium", "low", "info"]}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    score = sum(counts[severity] * RISK_WEIGHTS[severity] for severity in RISK_WEIGHTS)
    return ScanSummary(
        target=summary.target,
        generated_at=summary.generated_at,
        files_seen=summary.files_seen,
        files_scanned=summary.files_scanned,
        findings_total=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        risk_score=score,
        risk_band=risk_band(score, counts["critical"], counts["high"]),
    )


def risk_band(score: int, critical: int, high: int) -> str:
    if critical > 0:
        return "critical"
    if high > 0 or score >= 160:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "clean_by_this_scanner"


def project_profile(root: Path) -> ProjectProfile:
    markers: list[str] = []
    for path in iter_inventory_files(root):
        rel = safe_relative(path, root)
        if is_secret_file_name(path.name) or path.name in PROJECT_MARKER_FILES or any(part in AGENT_CONFIG_DIR_PARTS for part in path.parts):
            markers.append(rel)
        if len(markers) >= 80:
            break
    marker_set = set(markers)
    return ProjectProfile(
        target=str(root),
        project_markers=markers,
        agent_surface=any(name in marker_set or f"/{name}" in f"/{item}" for item in markers for name in AGENT_CONFIG_NAMES) or any(
            part in item.split("/") for item in markers for part in AGENT_CONFIG_DIR_PARTS
        ),
        package_surface=any(Path(item).name in PACKAGE_FILES for item in markers),
        ci_surface=any(item.startswith(".github/") or ".github/workflows" in item for item in markers),
        infra_surface=any(Path(item).name in {"Dockerfile", "docker-compose.yml", "main.tf", "terraform.tf"} or item.endswith(".tf") for item in markers),
        secret_surface=any(is_secret_file_name(Path(item).name) for item in markers),
    )


def scan_agent_config(path: Path, root: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = safe_relative(path, root)
    if path.name in GOVERNANCE_DOC_NAMES:
        return findings
    if is_agent_config(path):
        findings.append(
            Finding(
                severity="medium",
                category="agent_config",
                file=rel,
                line=None,
                title="Agent or workspace configuration file present",
                evidence="This file can influence AI coding tools, IDE behavior, MCP servers, or repo-level instructions.",
                recommendation="Review it before opening the repo with an agent. Treat rules files and project settings as code.",
            )
        )

    for label, pattern in EXECUTABLE_CONFIG_PATTERNS:
        for match in pattern.finditer(text):
            line_no = line_number_for_offset(text, match.start())
            line = redact_line(line_at(text, line_no))
            if label == "credential_terms":
                line = "[REDACTED_CREDENTIAL_CONTEXT]"
            severity = "high" if is_agent_config(path) and label in {"shell_command", "package_runner", "process_spawn", "install_hook"} else "medium"
            findings.append(
                Finding(
                    severity=severity,
                    category="repo_borne_executable_config",
                    file=rel,
                    line=line_no,
                    title=f"Executable or sensitive config indicator: {label}",
                    evidence=line,
                    recommendation="Verify this cannot auto-run from workspace trust, agent startup, hooks, task runners, or package install scripts.",
                )
            )
            break
    return findings


def scan_secrets(path: Path, root: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    rel = safe_relative(path, root)
    for label, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            line_no = line_number_for_offset(text, match.start())
            digest = hashlib.sha256(match.group(0).encode("utf-8", errors="ignore")).hexdigest()[:12]
            findings.append(
                Finding(
                    severity="critical" if label != "generic_assignment" else "high",
                    category="secret_exposure",
                    file=rel,
                    line=line_no,
                    title=f"Potential secret exposure: {label}",
                    evidence=f"Sensitive value suppressed by scanner. match_type={label} match_hash={digest}",
                    recommendation="Do not commit literal secrets. Move secrets to env vars or a secret manager, rotate exposed values, and scan git history.",
                )
            )
    return findings


def scan_package_risk(path: Path, root: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    if path.name not in PACKAGE_FILES and not is_agent_config(path):
        return findings
    rel = safe_relative(path, root)
    lower = text.lower()
    for package_name, note in KNOWN_HALLUCINATION_OR_SLOPSQUAT_NAMES.items():
        if package_name in lower:
            findings.append(
                Finding(
                    severity="high",
                    category="package_hallucination_or_slopsquatting",
                    file=rel,
                    line=None,
                    title=f"Known hallucination/slopsquatting watchlist package: {package_name}",
                    evidence=note,
                    recommendation="Before installing or running, verify the official package name, registry owner, publish time, maintainers, and lockfile diff.",
                )
            )
    if re.search(r"\b(npx|bunx|pnpm\s+dlx|yarn\s+dlx)\s+[A-Za-z0-9@/_-]+", text, re.I):
        findings.append(
            Finding(
                severity="medium",
                category="package_runner",
                file=rel,
                line=None,
                title="Package runner command present",
                evidence="Detected npx/bunx/pnpm dlx/yarn dlx usage.",
                recommendation="Treat package-runner commands as executable code. Validate package identity before agent execution.",
            )
        )
    return findings


def parse_python_requirement(line: str) -> str | None:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or stripped.startswith(("-", ".")):
        return None
    name = re.split(r"\s*(?:==|>=|<=|~=|!=|>|<|\[|;)\s*", stripped, maxsplit=1)[0].strip()
    if re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        return name
    return None


def extract_toml_dependency_entries(text: str) -> list[str]:
    entries: list[str] = []
    in_dependencies = False
    in_optional_dependencies = False
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("["):
            in_optional_dependencies = line == "[project.optional-dependencies]"
            in_dependencies = False
            continue
        if line.startswith("dependencies") and "=" in line:
            in_dependencies = True
            value = line.split("=", 1)[1]
        elif in_optional_dependencies and "=" in line:
            in_dependencies = True
            value = line.split("=", 1)[1]
        elif in_dependencies:
            value = line
        else:
            continue
        entries.extend(match.group(1) for match in re.finditer(r"['\"]([^'\"]+)['\"]", value))
        if "]" in value:
            in_dependencies = False
    return entries


def package_names_from_project_file(path: Path, root: Path, text: str) -> list[RegistryPackage]:
    rel = safe_relative(path, root)
    packages: list[RegistryPackage] = []
    if path.name == "requirements.txt":
        for line in text.splitlines():
            name = parse_python_requirement(line)
            if name:
                packages.append(RegistryPackage(ecosystem="pypi", name=name, source_file=rel))
    elif path.name == "pyproject.toml":
        for entry in extract_toml_dependency_entries(text):
            name = parse_python_requirement(entry)
            if name and name not in {"python"}:
                packages.append(RegistryPackage(ecosystem="pypi", name=name, source_file=rel))
    elif path.name == "package.json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            return packages
        for section in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]:
            values = payload.get(section, {})
            if isinstance(values, dict):
                for name in values:
                    if isinstance(name, str) and re.fullmatch(r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+", name):
                        packages.append(RegistryPackage(ecosystem="npm", name=name, source_file=rel))
    return packages


def collect_registry_packages(root: Path) -> list[RegistryPackage]:
    packages: list[RegistryPackage] = []
    seen: set[tuple[str, str, str]] = set()
    for path in iter_files(root):
        if path.name not in {"requirements.txt", "pyproject.toml", "package.json"}:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        for package in package_names_from_project_file(path, root, text):
            marker = (package.ecosystem, package.name.lower(), package.source_file)
            if marker in seen:
                continue
            seen.add(marker)
            packages.append(package)
    return packages


def registry_url(ecosystem: str, package: str) -> str:
    if ecosystem == "npm":
        safe_package = urllib.parse.quote(package, safe="@/")
        return f"https://registry.npmjs.org/{safe_package}"
    safe_package = urllib.parse.quote(package, safe="")
    return f"https://pypi.org/pypi/{safe_package}/json"


def check_registry_package(package: RegistryPackage) -> RegistryCheck:
    url = registry_url(package.ecosystem, package.name)
    request = urllib.request.Request(url, headers={"User-Agent": "ai-security-rules/0.4"})
    try:
        with urllib.request.urlopen(request, timeout=REGISTRY_TIMEOUT_SECONDS) as response:
            status_code = getattr(response, "status", 0)
            if 200 <= int(status_code) < 300:
                return RegistryCheck(
                    ecosystem=package.ecosystem,
                    package=package.name,
                    source_file=package.source_file,
                    status="found",
                    evidence=f"{package.ecosystem} registry returned HTTP {status_code}.",
                )
            return RegistryCheck(
                ecosystem=package.ecosystem,
                package=package.name,
                source_file=package.source_file,
                status="unknown",
                evidence=f"{package.ecosystem} registry returned HTTP {status_code}.",
            )
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return RegistryCheck(
                ecosystem=package.ecosystem,
                package=package.name,
                source_file=package.source_file,
                status="missing",
                evidence=f"{package.ecosystem} registry returned HTTP 404.",
            )
        return RegistryCheck(
            ecosystem=package.ecosystem,
            package=package.name,
            source_file=package.source_file,
            status="unknown",
            evidence=f"{package.ecosystem} registry returned HTTP {exc.code}.",
        )
    except (OSError, urllib.error.URLError, TimeoutError) as exc:
        return RegistryCheck(
            ecosystem=package.ecosystem,
            package=package.name,
            source_file=package.source_file,
            status="unknown",
            evidence=f"Registry request failed: {exc.__class__.__name__}.",
        )


def registry_checks_to_findings(checks: list[RegistryCheck]) -> list[Finding]:
    findings: list[Finding] = []
    for check in checks:
        if check.status == "found":
            continue
        severity = "high" if check.status == "missing" else "medium"
        findings.append(
            Finding(
                severity=severity,
                category="registry_validation",
                file=check.source_file,
                line=None,
                title=f"Registry validation {check.status}: {check.ecosystem}:{check.package}",
                evidence=check.evidence,
                recommendation="Verify the official package name, registry owner, maintainer history, release age, and lockfile diff before install or agent execution.",
            )
        )
    return findings


PROVIDER_TERMS = {
    "openai",
    "gemini",
    "anthropic",
    "stripe",
    "paypal",
    "notion",
    "github",
    "gmail",
    "sendgrid",
    "s3",
    "gcs",
    "firebase",
    "firestore",
}

FRONTEND_DIR_PARTS = {
    "pages",
    "components",
    "public",
    "static",
    "client",
    "web",
}

BACKEND_PROXY_MARKERS = {
    "api",
    "server",
    "backend",
    "functions",
    "workers",
    "routes",
    "controllers",
}

SECRET_OWNER_DOC_NAMES = {
    "SECURITY.md",
    "security.md",
    "SECRETS.md",
    "secrets.md",
    "RUNBOOK.md",
    "runbook.md",
}

SAST_EVIDENCE_DOC_NAMES = {
    "SECURITY_SCAN_EVIDENCE.md",
    "security_scan_evidence.md",
    "SAST_EVIDENCE.md",
    "sast_evidence.md",
    "CODE_SECURITY_EVIDENCE.md",
    "code_security_evidence.md",
}

SECRET_SCAN_EVIDENCE_DOC_NAMES = {
    "SECRET_SCAN_EVIDENCE.md",
    "secret_scan_evidence.md",
    "GITLEAKS_EVIDENCE.md",
    "gitleaks_evidence.md",
    "TRUFFLEHOG_EVIDENCE.md",
    "trufflehog_evidence.md",
}

PACKAGE_REPUTATION_EVIDENCE_DOC_NAMES = {
    "PACKAGE_REPUTATION_EVIDENCE.md",
    "package_reputation_evidence.md",
    "DEPENDENCY_REPUTATION_EVIDENCE.md",
    "dependency_reputation_evidence.md",
    "LOCKFILE_REVIEW_EVIDENCE.md",
    "lockfile_review_evidence.md",
}

MCP_ALLOWLIST_MANIFEST_NAMES = {
    "MCP_SERVER_ALLOWLIST.md",
    "mcp_server_allowlist.md",
    "mcp-server-allowlist.json",
    "mcp_server_allowlist.json",
}

THREAT_MODEL_DOC_NAMES = {
    "SECURITY_THREAT_MODEL.md",
    "security_threat_model.md",
    "THREAT_MODEL.md",
    "threat_model.md",
}

PUBLIC_EXPORT_MANIFEST_NAMES = {
    "public-export-manifest.json",
    "public-export-manifest.md",
    "public_export_manifest.json",
    "public_export_manifest.md",
    "export-manifest.json",
    "export-manifest.md",
    "public-github-allowlist-manifest-20260825.json",
}

GOVERNANCE_DOC_NAMES = SECRET_OWNER_DOC_NAMES | PUBLIC_EXPORT_MANIFEST_NAMES | {
    "package-runner-allowlist.md",
    "package_runner_allowlist.md",
    "dependency-allowlist.md",
    "dependency_allowlist.md",
} | SAST_EVIDENCE_DOC_NAMES | SECRET_SCAN_EVIDENCE_DOC_NAMES | PACKAGE_REPUTATION_EVIDENCE_DOC_NAMES | MCP_ALLOWLIST_MANIFEST_NAMES | THREAT_MODEL_DOC_NAMES


def has_path_part(path_text: str, candidates: set[str]) -> bool:
    parts = set(Path(path_text).parts)
    return bool(parts & candidates)


def is_browser_readable_path(path_text: str) -> bool:
    path = Path(path_text)
    parts = path.parts
    part_set = set(parts)
    suffix = path.suffix.lower()
    if part_set & {"public", "static", "client", "components"}:
        return True
    if "pages" in part_set and "api" not in part_set:
        return True
    if "app" in part_set and "api" not in part_set and suffix in {".js", ".jsx", ".ts", ".tsx", ".css"}:
        return True
    if suffix in {".html", ".css"} and not (part_set & {"server", "api", "backend", "lib"}):
        return True
    return False


def file_name_has_secret_material(path: Path) -> bool:
    lowered = path.name.lower()
    suffix = path.suffix.lower()
    if is_secret_file_name(path.name):
        return True
    if lowered in {"credentials.json", "service_account.json", "service-account.json"}:
        return True
    if "private" in lowered and suffix in {".key", ".pem", ".p8", ".p12"}:
        return True
    if lowered.endswith((".key", ".pem")) and any(term in lowered for term in {"secret", "token", "credential", "cert"}):
        return True
    return False


def project_has_file_name(root: Path, names: set[str]) -> bool:
    for path in iter_inventory_files(root):
        if path.name in names:
            return True
    return False


def project_has_backend_proxy_marker(root: Path) -> bool:
    for path in iter_inventory_files(root):
        rel = safe_relative(path, root)
        if has_path_part(rel, BACKEND_PROXY_MARKERS):
            return True
        if Path(rel).name in {"server.js", "server.ts", "server.py", "main.py", "app.py"}:
            return True
    return False


def project_has_provider_intent(root: Path) -> bool:
    integration_markers = {
        "process.env",
        "os.environ",
        "fetch(",
        "axios.",
        "requests.",
        "require(",
        "new ",
        "client",
        "sdk",
    }
    for path in iter_files(root):
        rel = safe_relative(path, root)
        if rel.startswith("tests/"):
            continue
        if path.name in GOVERNANCE_DOC_NAMES or path.name == "security_design_gate_rules.json":
            continue
        if path.name not in PACKAGE_FILES and path.suffix.lower() not in {
            ".js",
            ".jsx",
            ".ts",
            ".tsx",
            ".py",
            ".json",
            ".toml",
            ".yaml",
            ".yml",
        }:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if path.name in PACKAGE_FILES and any(term in lowered for term in PROVIDER_TERMS):
            return True
        for source_line in lowered.splitlines():
            if any(term in source_line for term in PROVIDER_TERMS) and any(marker in source_line for marker in integration_markers):
                return True
    return False


def project_has_public_export_manifest(root: Path) -> bool:
    for path in iter_inventory_files(root):
        if path.name in PUBLIC_EXPORT_MANIFEST_NAMES:
            return True
        lowered = path.name.lower()
        if "manifest" in lowered and "public" in lowered and ("export" in lowered or "allowlist" in lowered):
            return True
    return False


def project_has_secret_owner_record(root: Path) -> bool:
    if not project_has_file_name(root, SECRET_OWNER_DOC_NAMES):
        return False
    for path in iter_files(root):
        if path.name not in SECRET_OWNER_DOC_NAMES:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if ("owner" in lowered or "負責" in lowered) and ("rotate" in lowered or "rotation" in lowered or "輪替" in lowered):
            return True
    return False


def project_has_code_surface(root: Path) -> bool:
    source_suffixes = {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".go",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".mjs",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".swift",
        ".ts",
        ".tsx",
    }
    for path in iter_files(root):
        rel = safe_relative(path, root)
        if path.suffix.lower() in source_suffixes and not rel.startswith("tests/"):
            return True
    return False


def project_has_sast_evidence(root: Path) -> bool:
    evidence_terms = {"sast", "semgrep", "codeql", "sonarqube", "sonar", "fortify", "checkmarx", "bandit", "gosec"}
    for path in iter_files(root):
        if path.name not in SAST_EVIDENCE_DOC_NAMES:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if any(term in lowered for term in evidence_terms) and ("pass" in lowered or "passed" in lowered or "通過" in lowered or "clean" in lowered):
            return True
    return False


def project_has_secret_scan_evidence(root: Path) -> bool:
    evidence_terms = {"gitleaks", "trufflehog", "secret scan", "secret scanning", "history scan", "history-scan"}
    result_terms = {"pass", "passed", "clean", "critical=0", "high=0", "通過"}
    for path in iter_files(root):
        if path.name not in SECRET_SCAN_EVIDENCE_DOC_NAMES and path.name not in SAST_EVIDENCE_DOC_NAMES:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if any(term in lowered for term in evidence_terms) and any(term in lowered for term in result_terms):
            return True
    return False


def project_has_package_reputation_evidence(root: Path) -> bool:
    evidence_terms = {"lockfile", "package reputation", "registry", "maintainer", "publish", "pypi", "npm", "dependency"}
    result_terms = {"pass", "passed", "reviewed", "clean", "accepted", "通過", "已審核"}
    for path in iter_files(root):
        if path.name not in PACKAGE_REPUTATION_EVIDENCE_DOC_NAMES:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if any(term in lowered for term in evidence_terms) and any(term in lowered for term in result_terms):
            return True
    return False


def project_has_package_runner_allowlist(root: Path) -> bool:
    allowlist_names = {
        "package-runner-allowlist.md",
        "package_runner_allowlist.md",
        "dependency-allowlist.md",
        "dependency_allowlist.md",
    }
    for path in iter_files(root):
        if path.name not in allowlist_names:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if ("allowlist" in lowered or "allowed" in lowered or "允許" in lowered) and (
            "npx" in lowered or "pip install" in lowered or "package runner" in lowered or "command" in lowered
        ):
            return True
    return False


def project_has_mcp_surface(root: Path) -> bool:
    for path in iter_inventory_files(root):
        rel = safe_relative(path, root)
        if path.name in {".mcp.json", "mcp.json", "mcp.config.json"}:
            return True
        if ".mcp" in Path(rel).parts:
            return True
    return False


def project_has_mcp_allowlist_manifest(root: Path) -> bool:
    for path in iter_files(root):
        if path.name not in MCP_ALLOWLIST_MANIFEST_NAMES:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if ("allowlist" in lowered or "allowed" in lowered or "允許" in lowered) and ("command" in lowered or "server" in lowered or "mcp" in lowered):
            return True
    return False


def project_has_threat_model(root: Path) -> bool:
    required_terms = ["assets", "trust boundary", "data flow", "threats", "controls"]
    zh_required_terms = ["資產", "信任邊界", "資料流", "威脅", "控制"]
    for path in iter_files(root):
        if path.name not in THREAT_MODEL_DOC_NAMES:
            continue
        text = read_text_file(path)
        if text is None:
            continue
        lowered = text.lower()
        if all(term in lowered for term in required_terms) or all(term in text for term in zh_required_terms):
            return True
    return False


def load_gate_rules(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"Cannot read rules file: {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid rules JSON: {path}: {exc}") from exc
    stages = payload.get("stages")
    if not isinstance(stages, list):
        raise ValueError("Rules JSON must contain a stages array.")
    return payload


def rule_lookup(rules: dict[str, Any], stage_id: str, rule_id: str) -> dict[str, Any]:
    for stage in rules.get("stages", []):
        if stage.get("id") != stage_id:
            continue
        for rule in stage.get("blocks", []):
            if rule.get("id") == rule_id:
                return rule
    return {
        "id": rule_id,
        "severity": "P1",
        "rule": rule_id,
        "required_control": "Review and document the required control.",
    }


def make_gate_finding(
    rules: dict[str, Any],
    report: ProjectReport,
    stage: str,
    rule_id: str,
    evidence: str,
    *,
    blocked: bool = True,
) -> GateFinding:
    rule = rule_lookup(rules, stage, rule_id)
    severity = str(rule.get("severity", "P1"))
    return GateFinding(
        stage=stage,
        rule_id=rule_id,
        severity=severity,
        target=report.summary.target,
        blocked=blocked,
        title=str(rule.get("rule", rule_id)),
        evidence=evidence,
        required_control=str(rule.get("required_control", "Review and document the required control.")),
    )


def evaluate_project_gates(report: ProjectReport, rules: dict[str, Any], mode: str) -> list[GateFinding]:
    root = Path(report.summary.target)
    findings = report.findings
    gate_findings: list[GateFinding] = []
    enabled_stages = {
        "pre-design": {"pre_design"},
        "export-gate": {"pre_public_export"},
        "deploy-gate": {"pre_deploy"},
        "rules-check": {str(stage.get("id")) for stage in rules.get("stages", []) if isinstance(stage, dict)},
    }.get(mode, set())

    if "pre_design" in enabled_stages:
        frontend_secret_hits = [
            item
            for item in findings
            if item.category == "secret_exposure" and is_browser_readable_path(item.file)
        ]
        if frontend_secret_hits:
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_design",
                    "frontend_provider_secret",
                    f"{len(frontend_secret_hits)} frontend/browser-readable secret exposure indicator(s).",
                )
            )
        provider_intent = project_has_provider_intent(root)
        backend_proxy = project_has_backend_proxy_marker(root)
        if provider_intent and not backend_proxy:
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_design",
                    "missing_backend_proxy",
                    "Provider/cloud/payment integration terms detected, but no backend/API/server proxy marker was found.",
                )
            )
        needs_secret_owner = report.profile.secret_surface or any(
            item.category in {"secret_exposure", "repo_borne_executable_config"} and "credential" in item.title.lower()
            for item in findings
        )
        if needs_secret_owner and not project_has_secret_owner_record(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_design",
                    "missing_secret_owner",
                    "Secret-like files or credential indicators exist, but no SECURITY/SECRETS/RUNBOOK owner+rotation record was found.",
                )
            )
        needs_threat_model = project_has_code_surface(root) or project_has_provider_intent(root) or report.profile.agent_surface or report.profile.package_surface
        if needs_threat_model and not project_has_threat_model(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_design",
                    "missing_pre_design_threat_model",
                    "Project surface exists, but no pre-design threat model document was found.",
                )
            )

    if "pre_implementation" in enabled_stages:
        high_agent_hits = [
            item
            for item in findings
            if item.category == "repo_borne_executable_config" and item.severity == "high"
        ]
        if report.profile.agent_surface and high_agent_hits:
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_implementation",
                    "hidden_agent_config_not_reviewed",
                    f"{len(high_agent_hits)} high-risk executable indicator(s) in agent/workspace-readable config.",
                )
            )

    if "pre_dependency" in enabled_stages:
        runner_hits = [
            item
            for item in findings
            if item.category == "package_runner"
            or (item.category == "repo_borne_executable_config" and "package_runner" in item.title)
        ]
        if runner_hits:
            if not project_has_package_runner_allowlist(root):
                gate_findings.append(
                    make_gate_finding(
                        rules,
                        report,
                        "pre_dependency",
                        "unverified_package_runner",
                        f"{len(runner_hits)} package-runner indicator(s) require verification before execution.",
                    )
                )
        watchlist_hits = [item for item in findings if item.category == "package_hallucination_or_slopsquatting"]
        if watchlist_hits:
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_dependency",
                    "hallucination_watchlist_hit",
                    f"{len(watchlist_hits)} known hallucination/slopsquatting watchlist hit(s).",
                )
            )
        if report.profile.package_surface and not project_has_package_reputation_evidence(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_dependency",
                    "missing_lockfile_package_reputation_evidence",
                    "Package/dependency surface detected, but no lockfile/package reputation evidence document was found.",
                )
            )

    if "pre_agent_run" in enabled_stages:
        mcp_shell_hits = [
            item
            for item in findings
            if item.severity == "high"
            and item.category == "repo_borne_executable_config"
            and any(token in item.title for token in {"shell_command", "process_spawn", "package_runner", "install_hook"})
        ]
        if mcp_shell_hits:
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_agent_run",
                    "mcp_or_agent_shell_without_allowlist",
                    f"{len(mcp_shell_hits)} shell/process/package/install indicator(s) found in agent-relevant config.",
                )
            )
        if project_has_mcp_surface(root) and not project_has_mcp_allowlist_manifest(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_agent_run",
                    "missing_mcp_server_allowlist_manifest",
                    "MCP configuration detected, but no MCP server allowlist manifest was found.",
                )
            )

    if "pre_public_export" in enabled_stages:
        secret_file_names = [safe_relative(path, root) for path in iter_inventory_files(root) if file_name_has_secret_material(path)]
        if secret_file_names or report.summary.critical > 0:
            evidence = f"secret-like filenames={len(secret_file_names)}, critical_findings={report.summary.critical}"
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_public_export",
                    "public_export_secret_material",
                    evidence,
                )
            )
        if not project_has_public_export_manifest(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_public_export",
                    "public_export_unclassified_artifact",
                    "No public-export manifest was found in the evaluated export root.",
                )
            )

    if "pre_deploy" in enabled_stages:
        if project_has_provider_intent(root) and not project_has_backend_proxy_marker(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_deploy",
                    "public_endpoint_without_auth_or_rate_gate",
                    "Provider/cloud/payment integration detected without backend/API/server marker for auth/rate/quota gate evidence.",
                )
            )
        if project_has_code_surface(root) and not project_has_sast_evidence(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_deploy",
                    "missing_sast_or_code_security_scan",
                    "Source-code surface detected, but no SAST/code-security evidence document was found.",
                )
            )
        if (project_has_code_surface(root) or report.profile.package_surface or report.profile.secret_surface) and not project_has_secret_scan_evidence(root):
            gate_findings.append(
                make_gate_finding(
                    rules,
                    report,
                    "pre_deploy",
                    "missing_gitleaks_or_trufflehog_evidence",
                    "Release-relevant surface detected, but no gitleaks/trufflehog/secret-scan evidence document was found.",
                )
            )

    return gate_findings


def build_gate_summary(mode: str, rules_path: Path, gate_findings: list[GateFinding], reports: list[ProjectReport]) -> GateSummary:
    blocked = [item for item in gate_findings if item.blocked]
    counts = {"P0": 0, "P1": 0, "P2": 0}
    for item in blocked:
        counts[item.severity] = counts.get(item.severity, 0) + 1
    return GateSummary(
        mode=mode,
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        rules_path=str(rules_path),
        projects_evaluated=len(reports),
        gate_findings_total=len(gate_findings),
        blocking_findings=len(blocked),
        p0=counts.get("P0", 0),
        p1=counts.get("P1", 0),
        p2=counts.get("P2", 0),
        decision="fail" if blocked else "pass",
    )


def markdown_gate_report(summary: GateSummary, gate_findings: list[GateFinding]) -> str:
    lines: list[str] = []
    lines.append("# Local Security Design Gate Report")
    lines.append("")
    lines.append(f"- Mode: `{summary.mode}`")
    lines.append(f"- Generated UTC: `{summary.generated_at}`")
    lines.append(f"- Rules: `{summary.rules_path}`")
    lines.append(f"- Projects evaluated: `{summary.projects_evaluated}`")
    lines.append(f"- Gate findings: `{summary.gate_findings_total}`")
    lines.append(f"- Blocking findings: `{summary.blocking_findings}`")
    lines.append(f"- Severity: P0 `{summary.p0}`, P1 `{summary.p1}`, P2 `{summary.p2}`")
    lines.append(f"- Decision: `{summary.decision}`")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not gate_findings:
        lines.append("No blocking gate finding from the selected mode.")
        lines.append("")
    else:
        lines.append("| Blocked | Severity | Stage | Rule | Target | Evidence | Required control |")
        lines.append("|---|---|---|---|---|---|---|")
        for item in gate_findings:
            target = item.target.replace("|", "\\|")
            evidence = item.evidence.replace("|", "\\|")
            title = item.title.replace("|", "\\|")
            control = item.required_control.replace("|", "\\|")
            lines.append(
                f"| {item.blocked} | {item.severity} | {item.stage} | {item.rule_id}: {title} | `{target}` | `{evidence}` | {control} |"
            )
        lines.append("")
    lines.append("## Plain-language Decision")
    lines.append("")
    if summary.decision == "fail":
        lines.append("這個 gate 失敗，代表目前不能進入下一階段。不是刪掉警告就好，而是要補上規則要求的控制證據。")
    else:
        lines.append("這個 gate 通過，代表本模式沒有命中阻擋條件；仍需依專案性質搭配正式 SAST、dependency scan、secret scan。")
    lines.append("")
    return "\n".join(lines)


def scan_project(root: Path) -> tuple[ScanSummary, list[Finding]]:
    findings: list[Finding] = []
    files_seen = 0
    files_scanned = 0
    for path in iter_files(root):
        files_seen += 1
        text = read_text_file(path)
        if text is None:
            continue
        files_scanned += 1
        findings.extend(scan_agent_config(path, root, text))
        findings.extend(scan_secrets(path, root, text))
        findings.extend(scan_package_risk(path, root, text))

    findings.sort(key=lambda item: (severity_rank(item.severity), item.file, item.line or 0, item.title))
    counts = {severity: 0 for severity in ["critical", "high", "medium", "low", "info"]}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    score = sum(counts[severity] * RISK_WEIGHTS[severity] for severity in RISK_WEIGHTS)
    summary = ScanSummary(
        target=str(root),
        generated_at=dt.datetime.now(dt.timezone.utc).isoformat(),
        files_seen=files_seen,
        files_scanned=files_scanned,
        findings_total=len(findings),
        critical=counts["critical"],
        high=counts["high"],
        medium=counts["medium"],
        low=counts["low"],
        info=counts["info"],
        risk_score=score,
        risk_band=risk_band(score, counts["critical"], counts["high"]),
    )
    return summary, findings


def run_git(root: Path, args: list[str], *, binary: bool = False) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=not binary,
        check=False,
    )


def is_git_work_tree(root: Path) -> bool:
    result = run_git(root, ["rev-parse", "--is-inside-work-tree"])
    return result.returncode == 0 and isinstance(result.stdout, str) and result.stdout.strip() == "true"


def git_blob_size(root: Path, object_name: str) -> int | None:
    result = run_git(root, ["cat-file", "-s", object_name])
    if result.returncode != 0 or not isinstance(result.stdout, str):
        return None
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def git_blob_bytes(root: Path, object_name: str) -> bytes | None:
    result = run_git(root, ["show", object_name], binary=True)
    if result.returncode != 0 or not isinstance(result.stdout, bytes):
        return None
    return result.stdout


def scan_git_history(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    if not is_git_work_tree(root):
        return findings

    log_result = run_git(root, ["log", "--all", "--format=commit:%H", "--name-only", "--"])
    if log_result.returncode != 0 or not isinstance(log_result.stdout, str):
        findings.append(
            Finding(
                severity="low",
                category="git_history_scan",
                file=str(root),
                line=None,
                title="Git history scan could not read commit file list",
                evidence="git log returned a non-zero status.",
                recommendation="Run the scanner from a valid local git checkout and inspect git command availability.",
            )
        )
        return findings

    current_commit = ""
    seen_objects: set[tuple[str, str]] = set()
    for raw_line in log_result.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("commit:"):
            current_commit = line.removeprefix("commit:")
            continue
        if not current_commit:
            continue
        rel = line
        marker = (current_commit, rel)
        if marker in seen_objects:
            continue
        seen_objects.add(marker)
        rel_path = Path(rel)
        file_label = f"{current_commit[:12]}:{rel}"
        if file_name_has_secret_material(rel_path):
            findings.append(
                Finding(
                    severity="critical",
                    category="git_history_sensitive_file",
                    file=file_label,
                    line=None,
                    title="Sensitive filename present in git history",
                    evidence="Sensitive file contents were not read or emitted.",
                    recommendation="Assume the historical value may be exposed. Rotate affected secrets and rewrite/remove history before public release if required.",
                )
            )
            continue
        if any(rel_path.name.startswith(prefix) for prefix in EXCLUDED_FILE_PREFIXES):
            continue
        if any(rel_path.name.endswith(suffix) for suffix in EXCLUDED_FILE_SUFFIXES):
            continue

        object_name = f"{current_commit}:{rel}"
        size = git_blob_size(root, object_name)
        if size is None or size > MAX_FILE_BYTES:
            continue
        data = git_blob_bytes(root, object_name)
        if data is None or is_binary_sample(data):
            continue
        text = data.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS]
        for label, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                line_no = line_number_for_offset(text, match.start())
                digest = hashlib.sha256(match.group(0).encode("utf-8", errors="ignore")).hexdigest()[:12]
                findings.append(
                    Finding(
                        severity="critical" if label != "generic_assignment" else "high",
                        category="git_history_secret_exposure",
                        file=file_label,
                        line=line_no,
                        title=f"Potential secret exposure in git history: {label}",
                        evidence=f"Sensitive value suppressed by scanner. match_type={label} match_hash={digest}",
                        recommendation="Rotate the value if real, then decide whether history rewrite is required before public release.",
                    )
                )
    return findings


def markdown_project_report(summary: ScanSummary, profile: ProjectProfile, findings: list[Finding]) -> str:
    lines: list[str] = []
    lines.append("# Local AI Security Scan Report")
    lines.append("")
    lines.append(f"- Target: `{summary.target}`")
    lines.append(f"- Generated UTC: `{summary.generated_at}`")
    lines.append(f"- Files seen: `{summary.files_seen}`")
    lines.append(f"- Files scanned: `{summary.files_scanned}`")
    lines.append(f"- Findings: `{summary.findings_total}`")
    lines.append(f"- Severity: critical `{summary.critical}`, high `{summary.high}`, medium `{summary.medium}`, low `{summary.low}`, info `{summary.info}`")
    lines.append(f"- Risk score: `{summary.risk_score}`")
    lines.append(f"- Risk band: `{summary.risk_band}`")
    lines.append("")
    lines.append("## Project Profile")
    lines.append("")
    lines.append(f"- Agent surface: `{profile.agent_surface}`")
    lines.append(f"- Package surface: `{profile.package_surface}`")
    lines.append(f"- CI surface: `{profile.ci_surface}`")
    lines.append(f"- Infra surface: `{profile.infra_surface}`")
    lines.append(f"- Secret-file surface: `{profile.secret_surface}`")
    lines.append(f"- Marker files sampled: `{len(profile.project_markers)}`")
    lines.append("")
    lines.append("## Method")
    lines.append("")
    lines.append("- Read-only scan. No install, no project command execution, no network calls, no deletion.")
    lines.append("- Focus: agent config, MCP config, repo-borne executable config, secrets, package hallucination/slopsquatting indicators.")
    lines.append("- This is a local hardening gate. It should complement SAST, dependency scanning, and secret scanning, not replace them.")
    lines.append("")
    lines.append("## Findings")
    lines.append("")
    if not findings:
        lines.append("No findings from this scanner. Residual risk remains: hidden binary files, generated bundles, and external package registry reputation may still need separate validation.")
        lines.append("")
    else:
        lines.append("| Severity | Category | File | Line | Title | Evidence | Recommendation |")
        lines.append("|---|---|---|---:|---|---|---|")
        for item in findings:
            file_text = item.file.replace("|", "\\|")
            title = item.title.replace("|", "\\|")
            evidence = item.evidence.replace("|", "\\|")
            recommendation = item.recommendation.replace("|", "\\|")
            line_text = "" if item.line is None else str(item.line)
            lines.append(f"| {item.severity} | {item.category} | `{file_text}` | {line_text} | {title} | `{evidence}` | {recommendation} |")
        lines.append("")
    lines.append("## Plain-language Decision")
    lines.append("")
    if summary.critical > 0:
        lines.append("有 critical：先假設密鑰已暴露。不要只移除字串，必須 rotate secret 並掃 git history。")
    elif summary.high > 0:
        lines.append("有 high：先不要用 AI agent 直接開這個 repo，也不要執行 install/task/hook。先人工審 agent config 與 package runner。")
    elif summary.medium > 0:
        lines.append("有 medium：目前像是可控風險，但仍要把 agent config、MCP、rules files 當成 code review 項目。")
    else:
        lines.append("這一輪沒有命中明顯 AI coding security 指標；仍需搭配正式 SAST、dependency scan、secret scan 與權限測試。")
    lines.append("")
    lines.append("## Three-dimensional Defense")
    lines.append("")
    lines.append("| Dimension | Direct cause checked | Root cause controlled |")
    lines.append("|---|---|---|")
    lines.append("| Cleanup / Prune | 掃描 literal secrets、舊設定、可疑 log 內容 | 避免歷史 artifact 混進正式交付或 repo |")
    lines.append("| Producer / CLI | 掃描 package runner、install hook、task command | 避免 agent/CLI 從文件或 config 背景執行未知套件 |")
    lines.append("| Architecture / Hierarchy | 掃描 project-level agent/MCP/workspace settings | 把資料夾信任、工具啟動、secret 存取拆成不同 gate |")
    lines.append("")
    return "\n".join(lines)


def markdown_portfolio_report(portfolio: PortfolioSummary, reports: list[ProjectReport]) -> str:
    lines: list[str] = []
    lines.append("# Local AI Security Portfolio Report")
    lines.append("")
    lines.append(f"- Generated UTC: `{portfolio.generated_at}`")
    lines.append(f"- Projects scanned: `{portfolio.projects_scanned}`")
    lines.append(f"- Files seen: `{portfolio.files_seen}`")
    lines.append(f"- Files scanned: `{portfolio.files_scanned}`")
    lines.append(f"- Findings: `{portfolio.findings_total}`")
    lines.append(f"- Severity: critical `{portfolio.critical}`, high `{portfolio.high}`, medium `{portfolio.medium}`, low `{portfolio.low}`, info `{portfolio.info}`")
    lines.append(f"- Aggregate risk score: `{portfolio.risk_score}`")
    lines.append(f"- Highest risk band: `{portfolio.highest_risk_band}`")
    lines.append("")
    lines.append("## Project Risk Table")
    lines.append("")
    lines.append("| Risk band | Score | Critical | High | Medium | Project | Surfaces |")
    lines.append("|---|---:|---:|---:|---:|---|---|")
    for report in sorted(reports, key=lambda item: (severity_rank(item.summary.risk_band), -item.summary.risk_score, item.summary.target)):
        surfaces = []
        if report.profile.agent_surface:
            surfaces.append("agent")
        if report.profile.package_surface:
            surfaces.append("package")
        if report.profile.ci_surface:
            surfaces.append("ci")
        if report.profile.infra_surface:
            surfaces.append("infra")
        if report.profile.secret_surface:
            surfaces.append("secret-file")
        surface_text = ", ".join(surfaces) if surfaces else "none_detected"
        lines.append(
            f"| {report.summary.risk_band} | {report.summary.risk_score} | {report.summary.critical} | {report.summary.high} | {report.summary.medium} | `{report.summary.target}` | {surface_text} |"
        )
    lines.append("")
    lines.append("## Governance Gaps")
    lines.append("")
    governance_rows = []
    for report in reports:
        gaps: list[str] = []
        if report.profile.agent_surface and report.summary.high > 0:
            gaps.append("agent config contains executable or sensitive indicators")
        if report.profile.package_surface and any(item.category == "package_hallucination_or_slopsquatting" for item in report.findings):
            gaps.append("package hallucination/slopsquatting watchlist hit")
        if report.summary.critical > 0:
            gaps.append("possible literal secret exposure")
        if report.profile.secret_surface:
            gaps.append("secret-like file present in project tree")
        if not gaps:
            gaps.append("no high-priority AI-specific governance gap from this scanner")
        governance_rows.append((report.summary.risk_band, report.summary.risk_score, report.summary.target, gaps))
    lines.append("| Project | Gaps |")
    lines.append("|---|---|")
    for _, _, target, gaps in sorted(governance_rows, key=lambda row: (severity_rank(row[0]), -row[1], row[2])):
        lines.append(f"| `{target}` | {'; '.join(gaps)} |")
    lines.append("")
    lines.append("## Attack Topology View")
    lines.append("")
    topology_counts: dict[str, int] = {
        "repo_borne_executable_config": 0,
        "secret_exposure": 0,
        "agent_config": 0,
        "package_hallucination_or_slopsquatting": 0,
        "package_runner": 0,
    }
    for report in reports:
        for finding in report.findings:
            if finding.category in topology_counts:
                topology_counts[finding.category] += 1
    lines.append("| Topology | Finding count | Decision |")
    lines.append("|---|---:|---|")
    lines.append(f"| Repo-borne executable config | {topology_counts['repo_borne_executable_config']} | Review before opening with agent or IDE trust. |")
    lines.append(f"| Secret exposure | {topology_counts['secret_exposure']} | Rotate if real; scan git history. |")
    lines.append(f"| Agent / MCP / rules files | {topology_counts['agent_config']} | Treat as code, not documentation. |")
    lines.append(f"| Package hallucination / slopsquatting | {topology_counts['package_hallucination_or_slopsquatting']} | Verify registry identity before install. |")
    lines.append(f"| Package runner | {topology_counts['package_runner']} | Do not let agents run unverified npx/bunx/dlx commands. |")
    lines.append("")
    lines.append("## Plain-language Decision")
    lines.append("")
    if portfolio.critical > 0:
        lines.append("最高層級判斷：有疑似密鑰外洩。優先 rotate、掃 git history，再談其他修補。")
    elif portfolio.high > 0:
        lines.append("最高層級判斷：有可執行設定或高風險 agent/package 指標。先暫停自動 agent 開 repo 與自動 install。")
    elif portfolio.medium > 0:
        lines.append("最高層級判斷：目前主要是治理缺口。把 agent config、MCP、rules files、package runner 納入 PR gate。")
    else:
        lines.append("最高層級判斷：本掃描器未命中明顯 AI coding security 風險，但仍需搭配 SAST、secret scan、dependency scan、越權測試。")
    lines.append("")
    lines.append("## Three-dimensional Defense")
    lines.append("")
    lines.append("| Dimension | Portfolio-level control |")
    lines.append("|---|---|")
    lines.append("| Cleanup / Prune | 每個專案固定掃 secrets、舊 config、raw artifact，避免歷史材料混進 active repo。 |")
    lines.append("| Producer / CLI | 禁止未驗證 package runner、install hook、agent startup command 自動執行。 |")
    lines.append("| Architecture / Hierarchy | 把 active project、scratch/dryrun、AI agent trust、secret storage 分層治理。 |")
    lines.append("")
    return "\n".join(lines)


def safe_report_stem(target: Path, index: int) -> str:
    name = target.name or "root"
    clean = re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "project"
    return f"{index:02d}_{clean}"


def build_portfolio_summary(requested: list[str], reports: list[ProjectReport]) -> PortfolioSummary:
    generated_at = dt.datetime.now(dt.timezone.utc).isoformat()
    totals = {severity: 0 for severity in ["critical", "high", "medium", "low", "info"]}
    for report in reports:
        totals["critical"] += report.summary.critical
        totals["high"] += report.summary.high
        totals["medium"] += report.summary.medium
        totals["low"] += report.summary.low
        totals["info"] += report.summary.info
    score = sum(report.summary.risk_score for report in reports)
    highest = "clean_by_this_scanner"
    if reports:
        highest = sorted((report.summary.risk_band for report in reports), key=severity_rank)[0]
    return PortfolioSummary(
        generated_at=generated_at,
        targets_requested=requested,
        projects_scanned=len(reports),
        files_seen=sum(report.summary.files_seen for report in reports),
        files_scanned=sum(report.summary.files_scanned for report in reports),
        findings_total=sum(report.summary.findings_total for report in reports),
        critical=totals["critical"],
        high=totals["high"],
        medium=totals["medium"],
        low=totals["low"],
        info=totals["info"],
        risk_score=score,
        highest_risk_band=highest,
    )


def write_outputs(output_dir: Path, reports: list[ProjectReport], requested: list[str]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "local_ai_security_portfolio_report.json"
    md_path = output_dir / "local_ai_security_portfolio_report.md"
    portfolio = build_portfolio_summary(requested, reports)
    payload: dict[str, Any] = {
        "portfolio": asdict(portfolio),
        "projects": [
            {
                "summary": asdict(report.summary),
                "profile": asdict(report.profile),
                "findings": [asdict(item) for item in report.findings],
            }
            for report in reports
        ],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown_portfolio_report(portfolio, reports), encoding="utf-8")
    for index, report in enumerate(reports, start=1):
        project_path = Path(report.summary.target)
        stem = safe_report_stem(project_path, index)
        project_md = output_dir / f"local_ai_security_scan_{stem}.md"
        project_md.write_text(markdown_project_report(report.summary, report.profile, report.findings), encoding="utf-8")
    return json_path, md_path


def write_gate_outputs(output_dir: Path, summary: GateSummary, gate_findings: list[GateFinding]) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = f"local_security_design_gate_{summary.mode.replace('-', '_')}"
    json_path = output_dir / f"{stem}.json"
    md_path = output_dir / f"{stem}.md"
    payload = {
        "summary": asdict(summary),
        "findings": [asdict(item) for item in gate_findings],
    }
    json_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    md_path.write_text(markdown_gate_report(summary, gate_findings), encoding="utf-8")
    return json_path, md_path


def default_rules_path() -> Path:
    return Path(__file__).resolve().parent / "rules" / "security_design_gate_rules.json"


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Read-only local AI coding security portfolio scanner")
    modes = {"scan", "quick", "deep", "history-scan", "pre-design", "rules-check", "export-gate", "deploy-gate"}
    if argv and argv[0] in modes:
        mode = argv[0]
        argv = argv[1:]
    else:
        mode = "scan"
    parser.add_argument("targets", nargs="*", default=["."], help="One or more project directories to scan")
    parser.add_argument("--output-dir", default=".", help="Directory for JSON and Markdown reports")
    parser.add_argument(
        "--mode",
        choices=["scan", "quick", "deep", "history-scan", "pre-design", "rules-check", "export-gate", "deploy-gate"],
        default=mode,
        help="scan writes the original portfolio report; history-scan also inspects git history; gate modes also evaluate blocking design/export rules",
    )
    parser.add_argument(
        "--rules",
        default=str(default_rules_path()),
        help="Path to security_design_gate_rules.json",
    )
    parser.add_argument(
        "--tuning",
        default=None,
        help="Optional JSON file with reviewed false-positive tuning rules. Cannot suppress high/critical findings or gate failures.",
    )
    parser.add_argument(
        "--registry-check",
        action="store_true",
        help="Opt-in network check for npm/PyPI package existence. Does not install or execute packages.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    args = parse_args(argv)
    output_dir = Path(args.output_dir).expanduser().resolve()
    rules_path = Path(args.rules).expanduser().resolve()
    tuning_path = Path(args.tuning).expanduser().resolve() if args.tuning else None
    try:
        tuning_rules = load_tuning_rules(tuning_path)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    reports: list[ProjectReport] = []
    requested = list(args.targets)
    for raw_target in args.targets:
        target = Path(raw_target).expanduser().resolve()
        if not target.exists():
            print(f"Target does not exist: {target}", file=sys.stderr)
            return 2
        if not target.is_dir():
            print(f"Target is not a directory: {target}", file=sys.stderr)
            return 2
        summary, findings = scan_project(target)
        if args.registry_check:
            registry_packages = collect_registry_packages(target)
            registry_checks = [check_registry_package(package) for package in registry_packages]
            findings.extend(registry_checks_to_findings(registry_checks))
        if args.mode == "history-scan":
            findings.extend(scan_git_history(target))
            findings.sort(key=lambda item: (severity_rank(item.severity), item.file, item.line or 0, item.title))
        findings, suppressed = apply_tuning_rules(findings, tuning_rules)
        if suppressed:
            findings.append(
                Finding(
                    severity="info",
                    category="tuning",
                    file=str(tuning_path) if tuning_path else "",
                    line=None,
                    title="Reviewed false-positive findings suppressed",
                    evidence=f"suppressed_findings={suppressed}",
                    recommendation="Review tuning expiry dates and keep high/critical findings outside suppression.",
                )
            )
        findings.sort(key=lambda item: (severity_rank(item.severity), item.file, item.line or 0, item.title))
        summary = recompute_summary(summary, findings)
        reports.append(ProjectReport(summary=summary, profile=project_profile(target), findings=findings))
    json_path, md_path = write_outputs(output_dir, reports, requested)
    portfolio = build_portfolio_summary(requested, reports)
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {md_path}")
    print(
        "Portfolio: "
        f"projects={portfolio.projects_scanned} findings={portfolio.findings_total} "
        f"critical={portfolio.critical} high={portfolio.high} medium={portfolio.medium} "
        f"risk_score={portfolio.risk_score} highest_band={portfolio.highest_risk_band}"
    )
    if args.mode in {"pre-design", "rules-check", "export-gate", "deploy-gate"}:
        try:
            rules = load_gate_rules(rules_path)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        gate_findings: list[GateFinding] = []
        for report in reports:
            gate_findings.extend(evaluate_project_gates(report, rules, args.mode))
        gate_summary = build_gate_summary(args.mode, rules_path, gate_findings, reports)
        gate_json_path, gate_md_path = write_gate_outputs(output_dir, gate_summary, gate_findings)
        print(f"Gate JSON report: {gate_json_path}")
        print(f"Gate Markdown report: {gate_md_path}")
        print(
            "Gate: "
            f"mode={gate_summary.mode} decision={gate_summary.decision} "
            f"blocking={gate_summary.blocking_findings} P0={gate_summary.p0} P1={gate_summary.p1} P2={gate_summary.p2}"
        )
        return 1 if gate_summary.decision == "fail" else 0
    return 1 if portfolio.critical or portfolio.high else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
