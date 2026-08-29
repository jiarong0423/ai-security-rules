import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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

    def test_deploy_gate_accepts_sast_evidence_for_source_projects(self) -> None:
        with tempfile.TemporaryDirectory() as root_dir, tempfile.TemporaryDirectory() as report_dir:
            root = Path(root_dir)
            (root / "main.py").write_text("print('hello')\n", encoding="utf-8")
            (root / "SECURITY_SCAN_EVIDENCE.md").write_text(
                "SAST: Semgrep pass. CodeQL passed. Result: clean.\n",
                encoding="utf-8",
            )
            result = run_cli("deploy-gate", str(root), "--output-dir", report_dir)
            self.assertEqual(result.returncode, 0, result.stderr)
            gate = json.loads((Path(report_dir) / "local_security_design_gate_deploy_gate.json").read_text(encoding="utf-8"))
            self.assertEqual(gate["summary"]["decision"], "pass")

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
