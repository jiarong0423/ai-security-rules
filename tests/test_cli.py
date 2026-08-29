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


if __name__ == "__main__":
    unittest.main()
