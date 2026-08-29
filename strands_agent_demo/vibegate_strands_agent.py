#!/usr/bin/env python3
"""
Strands Agent demo wrapper for VibeGate.

Default mode is deterministic dry-run so judges can run the prototype without
AWS credentials, paid API keys, or a configured model provider. When the
Strands SDK and model credentials are available, pass --use-strands to run the
same tools through a real Strands Agent.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from strands import Agent, tool

    STRANDS_AVAILABLE = True
except ImportError:
    Agent = None  # type: ignore[assignment]
    STRANDS_AVAILABLE = False

    def tool(func: Callable[..., Any]) -> Callable[..., Any]:
        return func


@tool
def run_vibegate_agent_review(target: str, output_dir: str) -> str:
    """Run VibeGate agent-review against a repository and return the queue summary."""

    from ai_security_rules.cli import main as vibegate_main

    target_path = Path(target).expanduser().resolve()
    output_path = Path(output_dir).expanduser().resolve()
    exit_code = vibegate_main(["agent-review", str(target_path), "--output-dir", str(output_path)])
    queue_path = output_path / "agentic_security_review_queue.json"
    if not queue_path.exists():
        return json.dumps(
            {
                "exit_code": exit_code,
                "status": "error",
                "message": "agentic_security_review_queue.json was not generated",
            },
            indent=2,
        )
    payload = json.loads(queue_path.read_text(encoding="utf-8"))
    summary = payload.get("summary", {})
    return json.dumps(
        {
            "exit_code": exit_code,
            "status": "ok",
            "queue_path": str(queue_path),
            "summary": summary,
        },
        indent=2,
    )


@tool
def read_vibegate_queue(output_dir: str, limit: int = 10) -> str:
    """Read the VibeGate remediation queue and return the highest-priority items."""

    output_path = Path(output_dir).expanduser().resolve()
    queue_path = output_path / "agentic_security_review_queue.json"
    if not queue_path.exists():
        return json.dumps({"status": "error", "message": "queue file not found"}, indent=2)
    payload = json.loads(queue_path.read_text(encoding="utf-8"))
    queue = payload.get("queue", [])
    if not isinstance(queue, list):
        queue = []
    return json.dumps(
        {
            "status": "ok",
            "queue_path": str(queue_path),
            "items": queue[: max(0, limit)],
        },
        indent=2,
    )


@tool
def recommend_agent_next_action(queue_json: str) -> str:
    """Convert queue JSON into a safe next-action recommendation for a coding agent."""

    try:
        payload = json.loads(queue_json)
    except json.JSONDecodeError:
        return "Cannot parse queue JSON. Stop and ask for a valid VibeGate queue."
    items = payload.get("items", [])
    if not isinstance(items, list):
        return "Queue payload is malformed. Stop before agent execution."
    p0 = [item for item in items if item.get("priority") == "P0"]
    p1 = [item for item in items if item.get("priority") == "P1"]
    if p0:
        return "Stop automatic agent execution. P0 items exist; prepare only manifests or patches and require human approval before export or release."
    if p1:
        return "Do not export or deploy. The agent may draft governance fixes, evidence templates, or allowlists, but gates remain blocked until evidence exists."
    if items:
        return "Proceed with low-risk cleanup and documentation. Keep public export and deployment evidence checks enabled."
    return "No queue items found. Proceed only if separate SAST, secret scan, and dependency evidence are also current."


def run_deterministic_demo(target: Path, output_dir: Path) -> int:
    result_text = run_vibegate_agent_review(str(target), str(output_dir))
    queue_text = read_vibegate_queue(str(output_dir), limit=12)
    recommendation = recommend_agent_next_action(queue_text)
    print("# VibeGate Strands Agent Demo")
    print("")
    print("Mode: deterministic dry-run")
    print("Strands SDK available:", STRANDS_AVAILABLE)
    print("")
    print("## Tool Call: run_vibegate_agent_review")
    print(result_text)
    print("")
    print("## Tool Call: read_vibegate_queue")
    print(queue_text)
    print("")
    print("## Tool Call: recommend_agent_next_action")
    print(recommendation)
    return 0


def run_strands_agent(target: Path, output_dir: Path) -> int:
    if not STRANDS_AVAILABLE or Agent is None:
        print("Strands SDK is not installed. Install strands-agents or run without --use-strands.", file=sys.stderr)
        return 2
    system_prompt = """
You are VibeGate, a defensive coding-agent safety reviewer.
Use only the provided tools. Do not ask for secrets. Do not read .env values.
Run the VibeGate review, read the queue, and summarize whether an AI coding
agent may safely continue. Keep the answer concise and action-oriented.
"""
    agent = Agent(
        system_prompt=system_prompt,
        tools=[run_vibegate_agent_review, read_vibegate_queue, recommend_agent_next_action],
    )
    prompt = (
        f"Review target repository {target}. Write reports to {output_dir}. "
        "Use the VibeGate tools, then state the gate decision and next allowed action."
    )
    response = agent(prompt)
    print(response)
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run VibeGate through a Strands-compatible agent wrapper.")
    parser.add_argument("target", nargs="?", default=".", help="Repository to review")
    parser.add_argument("--output-dir", default="strands-agent-reports", help="Directory for generated VibeGate reports")
    parser.add_argument("--use-strands", action="store_true", help="Run through the real Strands Agent instead of deterministic dry-run")
    parser.add_argument("--clean-output", action="store_true", help="Remove known generated VibeGate report files before running")
    return parser.parse_args(argv)


def clean_known_outputs(output_dir: Path) -> None:
    names = {
        "agentic_security_review_queue.json",
        "agentic_security_review_queue.md",
        "local_ai_security_portfolio_report.json",
        "local_ai_security_portfolio_report.md",
        "local_security_design_gate_rules_check.json",
        "local_security_design_gate_rules_check.md",
    }
    if not output_dir.exists():
        return
    for path in output_dir.iterdir():
        if path.is_file() and (path.name in names or path.name.startswith("local_ai_security_scan_")):
            path.unlink()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    target = Path(args.target).expanduser().resolve()
    output_dir = Path(args.output_dir).expanduser().resolve()
    if not target.exists() or not target.is_dir():
        print(f"Target is not a directory: {target}", file=sys.stderr)
        return 2
    if args.clean_output and output_dir.exists():
        clean_known_outputs(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    if args.use_strands:
        return run_strands_agent(target, output_dir)
    return run_deterministic_demo(target, output_dir)


if __name__ == "__main__":
    raise SystemExit(main())
