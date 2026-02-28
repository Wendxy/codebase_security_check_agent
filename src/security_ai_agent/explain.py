from __future__ import annotations

import json
from pathlib import Path

from .reporter import latest_run_dir
from .schemas import Finding, FindingList


def resolve_run_dir(base_output_dir: Path, run_id: str) -> Path:
    if run_id == "latest":
        return latest_run_dir(base_output_dir)
    run_dir = base_output_dir / run_id
    if not run_dir.exists() or not run_dir.is_dir():
        raise FileNotFoundError(f"Run not found: {run_id}")
    return run_dir


def load_findings(run_dir: Path) -> list[Finding]:
    findings_file = run_dir / "findings.json"
    if not findings_file.exists():
        raise FileNotFoundError(f"findings.json not found in run {run_dir.name}")

    payload = json.loads(findings_file.read_text(encoding="utf-8"))
    findings = payload.get("findings", [])
    return FindingList.model_validate({"findings": findings}).findings


def explain_finding(run_dir: Path, finding_id: str) -> str:
    findings = load_findings(run_dir)
    target = next((finding for finding in findings if finding.finding_id == finding_id), None)
    if target is None:
        available = ", ".join(f.finding_id or "<none>" for f in findings[:20])
        raise ValueError(f"Finding ID not found: {finding_id}. Available: {available}")

    lines: list[str] = []
    lines.append(f"# Deep Dive: {target.finding_id} - {target.title}")
    lines.append("")
    lines.append(f"- Severity: `{target.severity.value}`")
    lines.append(f"- Confidence: `{target.confidence:.2f}`")
    lines.append(
        "- Perspectives: " + ", ".join(f"`{perspective.value}`" for perspective in target.perspectives)
    )
    lines.append("")
    lines.append("## Full Narrative")
    lines.append(target.description)
    lines.append("")
    lines.append("## Attack / Failure Scenario")
    lines.append(target.attack_or_failure_scenario)
    lines.append("")
    lines.append("## Recommendation")
    lines.append(target.recommendation)
    lines.append("")
    lines.append("## Operational Realism")
    lines.append(f"- Practicality score: `{target.operational_realism.practicality_score}`")
    lines.append(f"- Theater flag: `{str(target.operational_realism.theater_flag).lower()}`")
    lines.append(f"- Notes: {target.operational_realism.notes}")
    lines.append("")
    lines.append("## Evidence")
    for evidence in target.evidence:
        lines.append(f"- `{evidence.file}:{evidence.start_line}`-{evidence.end_line}")
        lines.append(f"  - Snippet: `{evidence.snippet_redacted}`")
    lines.append("")
    lines.append("## Verification Checklist")
    lines.append("- Reproduce the issue in a controlled environment.")
    lines.append("- Apply the recommendation in the affected code path.")
    lines.append("- Add tests and/or guardrails preventing recurrence.")
    lines.append("- Re-run `security-agent scan` and confirm closure.")
    return "\n".join(lines).rstrip() + "\n"
