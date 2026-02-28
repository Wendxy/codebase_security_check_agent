from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from .dedup import merge_findings
from .discovery import collect_files, load_codebase
from .explain import explain_finding, resolve_run_dir
from .model_client import OpenAIConfig, OpenAIModelClient
from .passes import run_all_lenses, run_operational_realism_pass
from .redaction import redact_codebase
from .reporter import (
    assign_finding_ids,
    create_run_dir,
    create_run_id,
    latest_run_dir,
    list_run_dirs,
    write_critical_alert,
    write_report_files,
)
from .schemas import Finding, RunMetadata, Severity


class CriticalAlerter:
    def __init__(self) -> None:
        self.has_alerted = False
        self.critical_seen = 0

    def on_critical(self, finding: Finding) -> None:
        self.critical_seen += 1
        if self.has_alerted:
            return
        self.has_alerted = True
        file_hint = finding.evidence[0].file if finding.evidence else "unknown"
        print("\n!!! CRITICAL SECURITY FINDING DETECTED !!!", file=sys.stderr)
        print(f"Title: {finding.title}", file=sys.stderr)
        print(f"File: {file_hint}", file=sys.stderr)
        print("Scan will continue to produce a complete report.\n", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="security-agent", description="AI security codebase analyzer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a target path")
    scan_parser.add_argument("target_path", nargs="?", default=".")
    scan_parser.add_argument("--model", default="gpt-5")
    scan_parser.add_argument("--max-files", type=int, default=None)
    scan_parser.add_argument("--include", action="append", default=[])
    scan_parser.add_argument("--exclude", action="append", default=[])
    scan_parser.add_argument("--output-dir", default=".security-agent/runs")
    scan_parser.add_argument("--top-findings", type=int, default=25)
    scan_parser.add_argument("--fail-on", choices=["critical"], default="critical")
    scan_parser.add_argument("--format", default="md,json", help="Comma separated: md,json")

    explain_parser = subparsers.add_parser("explain", help="Explain one finding by ID")
    explain_parser.add_argument("finding_id")
    explain_parser.add_argument("--run-id", default="latest")
    explain_parser.add_argument("--output-dir", default=".security-agent/runs")
    explain_parser.add_argument(
        "--rescan",
        action="store_true",
        help="Re-run scan on current directory before explaining.",
    )

    runs_parser = subparsers.add_parser("runs", help="Manage past runs")
    runs_sub = runs_parser.add_subparsers(dest="runs_command", required=True)
    runs_list_parser = runs_sub.add_parser("list", help="List run directories")
    runs_list_parser.add_argument("--output-dir", default=".security-agent/runs")

    report_parser = subparsers.add_parser("report", help="Show report content")
    report_sub = report_parser.add_subparsers(dest="report_command", required=True)
    report_show_parser = report_sub.add_parser("show", help="Display markdown report")
    report_show_parser.add_argument("--run-id", default="latest")
    report_show_parser.add_argument("--output-dir", default=".security-agent/runs")

    return parser


def parse_formats(raw: str) -> set[str]:
    formats = {value.strip() for value in raw.split(",") if value.strip()}
    if not formats:
        raise ValueError("At least one output format is required")
    unknown = formats - {"md", "json"}
    if unknown:
        raise ValueError(f"Unknown format(s): {', '.join(sorted(unknown))}")
    return formats


def run_scan_command(args: argparse.Namespace) -> int:
    run_started = time.perf_counter()
    target = Path(args.target_path).resolve()
    output_root = Path(args.output_dir).resolve()
    run_id = create_run_id()
    run_dir = create_run_dir(output_root, run_id)

    formats = parse_formats(args.format)

    io_started = time.perf_counter()
    file_paths = collect_files(
        str(target),
        include_globs=args.include,
        exclude_globs=args.exclude,
        max_files=args.max_files,
    )
    loaded = load_codebase(file_paths, target if target.is_dir() else target.parent)
    redacted_files, redaction_stats = redact_codebase(loaded)
    io_elapsed = time.perf_counter() - io_started

    print(f"Analyzing {len(redacted_files)} files with model {args.model}...")
    print(f"[timing] discovery + load + redaction completed in {io_elapsed:.1f}s")
    if redaction_stats.replacements:
        print(f"Applied {redaction_stats.replacements} secret redactions before model prompts.")

    client_started = time.perf_counter()
    client = OpenAIModelClient(OpenAIConfig(model=args.model))
    print(f"[timing] model client initialization completed in {time.perf_counter() - client_started:.1f}s")
    alerter = CriticalAlerter()

    analysis_started = time.perf_counter()
    pass_output = run_all_lenses(client, redacted_files, critical_callback=alerter.on_critical)
    print(f"[timing] AI analysis passes completed in {time.perf_counter() - analysis_started:.1f}s")
    dedup_input = pass_output.offensive + pass_output.defensive + pass_output.privacy

    post_started = time.perf_counter()
    dedup = merge_findings(dedup_input)
    findings = run_operational_realism_pass(client, dedup.findings)
    findings = assign_finding_ids(findings)
    print(
        f"[timing] deduplication + realism + id assignment completed in {time.perf_counter() - post_started:.1f}s"
    )

    critical_findings = [finding for finding in findings if finding.severity == Severity.CRITICAL]

    status = "critical" if critical_findings else "ok"
    metadata = RunMetadata(
        run_id=run_id,
        target_path=str(target),
        model=args.model,
        file_count=len(redacted_files),
        generated_at=datetime.now(timezone.utc).isoformat(),
        status=status,
    )

    write_report_files(
        run_dir,
        findings,
        metadata,
        formats=formats,
        top_findings=args.top_findings,
    )
    write_critical_alert(run_dir, critical_findings)
    print(f"[timing] report artifacts written to {run_dir}")

    summary = {
        "run_id": run_id,
        "findings_total": len(findings),
        "critical": len(critical_findings),
        "deduplicated": dedup.merged_count,
        "run_dir": str(run_dir),
        "total_seconds": round(time.perf_counter() - run_started, 2),
    }
    print(json.dumps(summary, indent=2))

    if critical_findings and args.fail_on == "critical":
        return 2
    return 0


def run_explain_command(args: argparse.Namespace) -> int:
    output_root = Path(args.output_dir).resolve()

    if args.rescan:
        scan_args = argparse.Namespace(
            target_path=".",
            model="gpt-5",
            max_files=None,
            include=[],
            exclude=[],
            output_dir=str(output_root),
            top_findings=25,
            fail_on="critical",
            format="md,json",
        )
        run_scan_command(scan_args)

    run_dir = resolve_run_dir(output_root, args.run_id)
    details = explain_finding(run_dir, args.finding_id)
    print(details)
    return 0


def run_runs_list_command(args: argparse.Namespace) -> int:
    output_root = Path(args.output_dir).resolve()
    runs = list_run_dirs(output_root)
    if not runs:
        print("No runs found.")
        return 0
    for run in runs:
        print(run.name)
    return 0


def run_report_show_command(args: argparse.Namespace) -> int:
    output_root = Path(args.output_dir).resolve()
    run_dir = resolve_run_dir(output_root, args.run_id)
    report_file = run_dir / "security-report.md"
    if report_file.exists():
        print(report_file.read_text(encoding="utf-8"))
        return 0

    findings_file = run_dir / "findings.json"
    if findings_file.exists():
        print(findings_file.read_text(encoding="utf-8"))
        return 0

    raise FileNotFoundError(f"No report artifacts found in {run_dir}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "scan":
            return run_scan_command(args)
        if args.command == "explain":
            return run_explain_command(args)
        if args.command == "runs" and args.runs_command == "list":
            return run_runs_list_command(args)
        if args.command == "report" and args.report_command == "show":
            return run_report_show_command(args)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
