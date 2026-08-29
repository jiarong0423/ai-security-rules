import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ai_security_rules.cli import package_names_from_project_file


REPO_ROOT = Path(__file__).resolve().parents[1]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "ai_security_rules", *args],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": str(REPO_ROOT / "src")},
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


class CliTests(unittest.TestCase):
    def test_pyproject_registry_parser_reads_only_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir:
            root = Path(root_dir)
            path = root / "pyproject.toml"
            text = """
[project]
name = "not-a-dependency"
description = "mentions requests but is not a dependency"
dependencies = [
  "requests>=2",
  "rich",
]

[project.optional-dependencies]
dev = [
  "pytest",
]
"""
            path.write_text(text, encoding="utf-8")
            packages = package_names_from_project_file(path, root, text)
            names = {package.name for package in packages}
            self.assertEqual(names, {"requests", "rich", "pytest"})

    def test_env_contents_are_not_read_or_emitted(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            marker = "THIS_ENV_FILE_CONTENT_MUST_NOT_APPEAR_ANYWHERE_1234567890"
            (root / ".env").write_text(f"OPENAI_API_KEY={marker}\n", encoding="utf-8")
            result = run_cli("scan", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = (Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8")
            self.assertNotIn(marker, report)
            payload = json.loads(report)
            self.assertEqual(payload["portfolio"]["findings_total"], 0)

    def test_rules_check_fails_on_public_export_secret_material(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "public-export-manifest.json").write_text('{"policy":"default-deny"}\n', encoding="utf-8")
            (root / "service_account.json").write_text('{"private_key":"placeholder"}\n', encoding="utf-8")
            result = run_cli("rules-check", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_rules_check.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("public_export_secret_material", rule_ids)

    def test_local_security_files_satisfy_owner_and_public_manifest_gates(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "credentials").mkdir()
            (root / "credentials" / "credentials.json").write_text('{"private_key":"placeholder"}\n', encoding="utf-8")
            (root / "SECURITY_SECRET_ROTATION_EVIDENCE.md").write_text(
                "Owner: project owner\nRotation path: provider console\n",
                encoding="utf-8",
            )
            (root / "LOCAL_SECURITY_CLASSIFICATION_MANIFEST.md").write_text(
                "Default decision: public-export-deny\n",
                encoding="utf-8",
            )
            result = run_cli("rules-check", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_rules_check.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("public_export_secret_material", rule_ids)
            self.assertNotIn("missing_secret_owner", rule_ids)
            self.assertNotIn("public_export_unclassified_artifact", rule_ids)

    def test_ignored_owner_only_runtime_secret_is_not_active_p0_scan(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            subprocess.run(["git", "init"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            (root / ".gitignore").write_text("credentials/\n", encoding="utf-8")
            (root / "credentials").mkdir()
            secret_file = root / "credentials" / "credentials.json"
            secret_file.write_text('{"private_key":"-----BEGIN PRIVATE KEY-----\\nredacted\\n-----END PRIVATE KEY-----"}\n', encoding="utf-8")
            secret_file.chmod(0o600)
            result = run_cli("scan", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            payload = json.loads((Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8"))
            portfolio = payload["portfolio"]
            categories = {
                finding["category"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertEqual(portfolio["critical"], 0)
            self.assertIn("local_runtime_secret", categories)

    def test_ignored_owner_only_runtime_secret_still_blocks_public_export(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            subprocess.run(["git", "init"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            (root / ".gitignore").write_text("credentials/\n", encoding="utf-8")
            (root / "credentials").mkdir()
            secret_file = root / "credentials" / "credentials.json"
            secret_file.write_text('{"private_key":"-----BEGIN PRIVATE KEY-----\\nredacted\\n-----END PRIVATE KEY-----"}\n', encoding="utf-8")
            secret_file.chmod(0o600)
            (root / "LOCAL_SECURITY_CLASSIFICATION_MANIFEST.md").write_text("Date: 2099-12-31\nDefault decision: public-export-deny\n", encoding="utf-8")
            result = run_cli("rules-check", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_rules_check.json").read_text(encoding="utf-8"))
            findings = gate["findings"]
            rule_ids = {finding["rule_id"] for finding in findings}
            public_export = [finding for finding in findings if finding["rule_id"] == "public_export_secret_material"]
            self.assertIn("public_export_secret_material", rule_ids)
            self.assertEqual(public_export[0]["severity"], "P0")

    def test_empty_pre_design_passes(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            result = run_cli("pre-design", root_dir, "--output-dir", report_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_pre_design.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["summary"]["decision"], "pass")

    def test_deploy_gate_requires_sast_evidence_for_source_projects(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            result = run_cli("deploy-gate", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_deploy_gate.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("missing_sast_or_code_security_scan", rule_ids)

    def test_pre_design_requires_threat_model_for_source_projects(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            result = run_cli("pre-design", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_pre_design.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("missing_pre_design_threat_model", rule_ids)

    def test_deploy_gate_requires_secret_scan_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "SECURITY_SCAN_EVIDENCE.md").write_text("SAST: Semgrep pass. Result: clean.\n", encoding="utf-8")
            result = run_cli("deploy-gate", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_deploy_gate.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("missing_gitleaks_or_trufflehog_evidence", rule_ids)

    def test_dependency_gate_requires_package_reputation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "pyproject.toml").write_text("[project]\ndependencies = []\n", encoding="utf-8")
            result = run_cli("rules-check", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_rules_check.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("missing_lockfile_package_reputation_evidence", rule_ids)

    def test_mcp_surface_requires_allowlist_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / ".mcp.json").write_text('{"servers":{}}\n', encoding="utf-8")
            result = run_cli("rules-check", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_rules_check.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("missing_mcp_server_allowlist_manifest", rule_ids)

    def test_prompt_injection_hidden_character_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            hidden = chr(0x200B)
            (root / "AGENTS.md").write_text("Normal instruction." + hidden + " Hidden instruction.\n", encoding="utf-8")
            result = run_cli("scan", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            payload = json.loads((Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8"))
            categories = {
                finding["category"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertIn("prompt_injection_surface", categories)

    def test_redacted_test_secret_fixture_is_not_critical(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            tests_dir = root / "tests"
            tests_dir.mkdir()
            (tests_dir / "test_fixture.py").write_text(
                'SAMPLE = "-----BEGIN PRIVATE KEY-----\\nredacted\\n-----END PRIVATE KEY-----"\n',
                encoding="utf-8",
            )
            result = run_cli("scan", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 0)
            payload = json.loads((Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["portfolio"]["critical"], 0)
            categories = {
                finding["category"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertIn("synthetic_secret_fixture", categories)

    def test_mcp_overprivileged_command_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / ".mcp.json").write_text('{"servers":{"bad":{"command":"sudo tool","args":["/"]}}}\n', encoding="utf-8")
            result = run_cli("scan", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            payload = json.loads((Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8"))
            categories = {
                finding["category"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertIn("mcp_overprivileged_config", categories)

    def test_deploy_gate_rejects_stale_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "SECURITY_SCAN_EVIDENCE.md").write_text(
                "Review Date: 2020-01-01. SAST: Semgrep pass. Result: clean.\n",
                encoding="utf-8",
            )
            (root / "SECRET_SCAN_EVIDENCE.md").write_text(
                "Review Date: 2020-01-01. gitleaks pass. trufflehog passed. high=0 critical=0.\n",
                encoding="utf-8",
            )
            result = run_cli("deploy-gate", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_deploy_gate.json").read_text(encoding="utf-8"))
            rule_ids = {finding["rule_id"] for finding in gate["findings"]}
            self.assertIn("stale_or_mismatched_security_evidence", rule_ids)

    def test_deploy_gate_accepts_sast_evidence_for_source_projects(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "SECURITY_SCAN_EVIDENCE.md").write_text(
                "Review Date: 2099-12-31. SAST: Semgrep pass. CodeQL passed. Result: clean.\n",
                encoding="utf-8",
            )
            (root / "SECRET_SCAN_EVIDENCE.md").write_text(
                "Review Date: 2099-12-31. gitleaks pass. trufflehog passed. high=0 critical=0.\n",
                encoding="utf-8",
            )
            result = run_cli("deploy-gate", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_deploy_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["summary"]["decision"], "pass")

    def test_agent_review_writes_remediation_queue(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            result = run_cli("agent-review", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            queue_path = Path(report_dir) / "agentic_security_review_queue.json"
            self.assertTrue(queue_path.exists())
            payload = json.loads(queue_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["decision"], "fail")
            lanes = {item["lane"] for item in payload["queue"]}
            rules = {item["rule_or_category"] for item in payload["queue"]}
            self.assertIn("pre_development_management", lanes)
            self.assertIn("release_evidence_control", lanes)
            self.assertIn("missing_pre_design_threat_model", rules)
            self.assertIn("missing_sast_or_code_security_scan", rules)

    def test_strands_demo_dry_run_writes_queue(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "strands_agent_demo" / "vibegate_strands_agent.py"),
                    str(root),
                    "--output-dir",
                    report_dir,
                    "--clean-output",
                ],
                cwd=REPO_ROOT,
                env={"PYTHONPATH": str(REPO_ROOT / "src")},
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("Mode: deterministic dry-run", result.stdout)
            queue_path = Path(report_dir) / "agentic_security_review_queue.json"
            self.assertTrue(queue_path.exists())
            payload = json.loads(queue_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["summary"]["decision"], "fail")

    def test_tuning_suppresses_reviewed_medium_findings(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "AGENTS.md").write_text("Review changes before committing.\n", encoding="utf-8")
            tuning = root / "tuning.json"
            tuning.write_text(
                json.dumps(
                    {
                        "allowed_false_positives": [
                            {
                                "category": "agent_config",
                                "file": "AGENTS.md",
                                "title_contains": "Agent or workspace configuration file present",
                                "reason": "Reviewed minimal instruction-only AGENTS.md fixture.",
                                "expires": "2999-12-31",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = run_cli("scan", str(root), "--tuning", str(tuning), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads((Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8"))
            categories = {
                finding["category"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertNotIn("agent_config", categories)
            self.assertIn("tuning", categories)

    def test_tuning_cannot_suppress_high_findings(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            fake_secret = "sk-" + ("B" * 32)
            (root / "main.py").write_text("value = '" + fake_secret + "'\n", encoding="utf-8")
            tuning = root / "tuning.json"
            tuning.write_text(
                json.dumps(
                    {
                        "allowed_false_positives": [
                            {
                                "category": "secret_exposure",
                                "file": "main.py",
                                "title_contains": "Potential secret exposure",
                                "reason": "Attempted high finding suppression should not work.",
                                "expires": "2999-12-31",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = run_cli("scan", str(root), "--tuning", str(tuning), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            report = (Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8")
            self.assertNotIn(fake_secret, report)
            payload = json.loads(report)
            severities = {
                finding["severity"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertIn("critical", severities)

    def test_history_scan_redacts_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            subprocess.run(["git", "init"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            subprocess.run(["git", "config", "user.name", "Test User"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=root, check=True)
            fake_secret = "sk-" + ("A" * 32)
            (root / "client.js").write_text("const value = '" + fake_secret + "';\n", encoding="utf-8")
            subprocess.run(["git", "add", "client.js"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "add synthetic secret"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
            (root / "client.js").write_text("const token = process.env.OPENAI_API_KEY;\n", encoding="utf-8")
            subprocess.run(["git", "add", "client.js"], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "remove synthetic secret"], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)

            result = run_cli("history-scan", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 1)
            report = (Path(report_dir) / "local_ai_security_portfolio_report.json").read_text(encoding="utf-8")
            self.assertNotIn(fake_secret, report)
            payload = json.loads(report)
            categories = {
                finding["category"]
                for project in payload["projects"]
                for finding in project["findings"]
            }
            self.assertIn("git_history_secret_exposure", categories)


if __name__ == "__main__":
    unittest.main()
