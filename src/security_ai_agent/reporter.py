from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .schemas import Finding, RunMetadata, SEVERITY_RANK, Severity


@dataclass(slots=True)
class RenderedReport:
    markdown: str
    findings_json: str
    metadata_json: str


def create_run_id(now: datetime | None = None) -> str:
    dt = now or datetime.now(timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


def create_run_dir(base_output_dir: Path, run_id: str) -> Path:
    run_dir = base_output_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def assign_finding_ids(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], -f.confidence, f.title.lower()))
    for idx, finding in enumerate(ordered, start=1):
        finding.finding_id = f"R-{idx:03d}"
    return ordered


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


def render_markdown(
    findings: list[Finding],
    metadata: RunMetadata,
    top_findings: int,
) -> str:
    counts = severity_counts(findings)
    lines: list[str] = []
    lines.append("# Security AI Agent Report")
    lines.append("")
    lines.append(f"- Run ID: `{metadata.run_id}`")
    lines.append(f"- Generated (UTC): `{metadata.generated_at}`")
    lines.append(f"- Target: `{metadata.target_path}`")
    lines.append(f"- Model: `{metadata.model}`")
    lines.append(f"- Files analyzed: `{metadata.file_count}`")
    lines.append("")
    lines.append("## Severity Summary")
    for severity in ("critical", "high", "medium", "low", "info"):
        lines.append(f"- {severity.title()}: `{counts[severity]}`")
    lines.append("")
    lines.append("## Findings")

    inline = findings[:top_findings]
    appendix = findings[top_findings:]

    if not inline:
        lines.append("No findings identified.")

    for finding in inline:
        lines.extend(_render_finding_block(finding))

    if appendix:
        lines.append("")
        lines.append("## Appendix")
        lines.append("Remaining findings after top-priority section.")
        for finding in appendix:
            lines.extend(_render_finding_block(finding))

    return "\n".join(lines).rstrip() + "\n"


def _render_finding_block(finding: Finding) -> list[str]:
    lines: list[str] = []
    fid = finding.finding_id or "R-???"
    lines.append("")
    lines.append(f"### {fid} - {finding.title}")
    lines.append(f"- Severity: `{finding.severity.value}`")
    lines.append(
        "- Perspectives: "
        + ", ".join(f"`{perspective.value}`" for perspective in finding.perspectives)
    )
    lines.append(f"- Confidence: `{finding.confidence:.2f}`")
    lines.append(
        f"- Operational Realism: score `{finding.operational_realism.practicality_score}` / "
        f"theater `{str(finding.operational_realism.theater_flag).lower()}`"
    )
    lines.append(f"- Realism Notes: {finding.operational_realism.notes}")
    lines.append("")
    lines.append(f"Description: {finding.description}")
    lines.append("")
    lines.append(f"Attack/Failure Scenario: {finding.attack_or_failure_scenario}")
    lines.append("")
    lines.append(f"Recommendation: {finding.recommendation}")
    lines.append("")
    lines.append("Evidence:")
    for evidence in finding.evidence:
        lines.append(
            f"- `{evidence.file}:{evidence.start_line}`-{evidence.end_line}: "
            f"`{_trim_snippet(evidence.snippet_redacted)}`"
        )
    return lines


def _trim_snippet(snippet: str, limit: int = 180) -> str:
    compact = " ".join(snippet.split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def render_json(findings: list[Finding], metadata: RunMetadata) -> str:
    payload = {
        "metadata": metadata.model_dump(),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }
    return json.dumps(payload, indent=2)


def write_report_files(
    run_dir: Path,
    findings: list[Finding],
    metadata: RunMetadata,
    formats: set[str],
    top_findings: int,
) -> RenderedReport:
    markdown = render_markdown(findings, metadata, top_findings=top_findings)
    findings_json = render_json(findings, metadata)
    metadata_json = json.dumps(metadata.model_dump(), indent=2)

    (run_dir / "metadata.json").write_text(metadata_json + "\n", encoding="utf-8")

    if "md" in formats:
        (run_dir / "security-report.md").write_text(markdown, encoding="utf-8")
    if "json" in formats:
        (run_dir / "findings.json").write_text(findings_json + "\n", encoding="utf-8")

    return RenderedReport(markdown=markdown, findings_json=findings_json, metadata_json=metadata_json)


def write_critical_alert(run_dir: Path, critical_findings: list[Finding]) -> None:
    if not critical_findings:
        return
    first = critical_findings[0]
    file_hint = first.evidence[0].file if first.evidence else "unknown"
    payload = {
        "critical_count": len(critical_findings),
        "first_critical": {
            "finding_id": first.finding_id,
            "title": first.title,
            "file": file_hint,
        },
        "all_critical_ids": [f.finding_id for f in critical_findings],
    }
    (run_dir / "critical_alert.json").write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def list_run_dirs(base_output_dir: Path) -> list[Path]:
    if not base_output_dir.exists():
        return []
    return sorted([p for p in base_output_dir.iterdir() if p.is_dir()])


def latest_run_dir(base_output_dir: Path) -> Path:
    runs = list_run_dirs(base_output_dir)
    if not runs:
        raise FileNotFoundError(f"No runs found in {base_output_dir}")
    return runs[-1]
