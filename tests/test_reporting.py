from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from security_ai_agent.reporter import assign_finding_ids, render_markdown, write_report_files
from security_ai_agent.schemas import Evidence, Finding, Perspective, RunMetadata, Severity


def _finding(idx: int, severity: Severity) -> Finding:
    return Finding(
        title=f"Issue {idx}",
        severity=severity,
        perspectives=[Perspective.OFFENSIVE],
        description="desc",
        attack_or_failure_scenario="scenario",
        recommendation="recommend",
        evidence=[Evidence(file="app.py", start_line=idx, end_line=idx, snippet_redacted="x")],
        confidence=0.5,
    )


def test_assign_ids_and_appendix_rendering() -> None:
    findings = [_finding(i, Severity.HIGH) for i in range(1, 5)]
    findings = assign_finding_ids(findings)
    metadata = RunMetadata(
        run_id="20260228T000000Z",
        target_path="/repo",
        model="gpt-5",
        file_count=4,
        generated_at=datetime.now(timezone.utc).isoformat(),
        status="ok",
    )

    markdown = render_markdown(findings, metadata, top_findings=2)

    assert "### R-001" in markdown
    assert "## Appendix" in markdown


def test_write_report_files_outputs_artifacts(tmp_path: Path) -> None:
    findings = assign_finding_ids([_finding(1, Severity.CRITICAL)])
    metadata = RunMetadata(
        run_id="20260228T000000Z",
        target_path="/repo",
        model="gpt-5",
        file_count=1,
        generated_at=datetime.now(timezone.utc).isoformat(),
        status="critical",
    )

    write_report_files(tmp_path, findings, metadata, formats={"md", "json"}, top_findings=25)

    assert (tmp_path / "security-report.md").exists()
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "metadata.json").exists()
