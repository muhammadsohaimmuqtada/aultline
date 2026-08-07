from __future__ import annotations

import argparse
import json
from pathlib import Path

from aultline import __version__
from aultline.analysis import AnalysisEngine
from aultline.importers import DedsecImporter
from aultline.planner import TestPlanner
from aultline.policy import ExecutionPolicy
from aultline.priority import PriorityEngine


def _write_json(path: str, payload: dict) -> None:
    destination = Path(path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aultline",
        description="Evidence-driven application security analysis and validation planning.",
    )
    parser.add_argument("--version", action="version", version=f"Aultline v{__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a DEDSEC schema-3 report")
    analyze.add_argument("report", help="Path to a DEDSEC schema-3 JSON report")
    analyze.add_argument("--output", help="Write Aultline analysis JSON to this path")
    analyze.add_argument(
        "--scope-declared",
        action="store_true",
        help="Mark that the operator has declared an authorized test scope",
    )

    graph = subparsers.add_parser("graph", help="Import and summarize a DEDSEC surface graph")
    graph.add_argument("report", help="Path to a DEDSEC schema-3 JSON report")
    graph.add_argument("--output", help="Write normalized graph JSON to this path")
    return parser


def _analyze(args: argparse.Namespace) -> int:
    imported = DedsecImporter().load(args.report)
    graph = imported.graph
    hypotheses = AnalysisEngine().analyze(graph)
    ranked = PriorityEngine().rank(hypotheses, graph)
    planner = TestPlanner()
    policy = ExecutionPolicy()

    rendered = []
    for item in ranked:
        hypothesis = item.hypothesis
        plan = planner.build(hypothesis, graph)
        hypothesis.plan = plan
        decision = policy.evaluate(plan, scope_declared=bool(args.scope_declared))
        rendered.append(
            {
                "score": item.score,
                "priority_reasons": list(item.reasons),
                "hypothesis": hypothesis.public_dict(),
                "policy": {"allowed": decision.allowed, "reason": decision.reason},
            }
        )

    payload = {
        "aultline_version": __version__,
        "source": {
            "type": "dedsec-schema-3",
            "path": imported.source_path,
            "scan_id": imported.scan_id,
            "schema_version": imported.schema_version,
            "warnings": list(imported.warnings),
        },
        "graph": graph.snapshot()["counts"],
        "hypotheses": rendered,
        "summary": {
            "total_hypotheses": len(rendered),
            "verified": 0,
            "note": (
                "Aultline does not promote imported surface signals to verified vulnerabilities "
                "without reproducible validation evidence."
            ),
        },
    }

    if args.output:
        _write_json(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _graph(args: argparse.Namespace) -> int:
    imported = DedsecImporter().load(args.report)
    payload = imported.graph.snapshot()
    payload["source"] = {
        "scan_id": imported.scan_id,
        "schema_version": imported.schema_version,
        "warnings": list(imported.warnings),
    }
    if args.output:
        _write_json(args.output, payload)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "analyze":
        return _analyze(args)
    if args.command == "graph":
        return _graph(args)
    parser.error("unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
