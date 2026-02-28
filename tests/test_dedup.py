from __future__ import annotations

from security_ai_agent.dedup import merge_findings
from security_ai_agent.schemas import Evidence, Finding, Perspective, Severity


def _finding(title: str, severity: Severity, perspective: Perspective) -> Finding:
    return Finding(
        title=title,
        severity=severity,
        perspectives=[perspective],
        description="desc",
        attack_or_failure_scenario="scenario",
        recommendation="fix it",
        evidence=[Evidence(file="app.py", start_line=10, end_line=10, snippet_redacted="x")],
        confidence=0.7,
    )


def test_merge_findings_merges_duplicates_and_keeps_highest_severity() -> None:
    a = _finding("SQL Injection", Severity.HIGH, Perspective.OFFENSIVE)
    b = _finding("SQL Injection", Severity.CRITICAL, Perspective.DEFENSIVE)

    merged = merge_findings([a, b])

    assert len(merged.findings) == 1
    assert merged.merged_count == 1
    assert merged.findings[0].severity == Severity.CRITICAL
    assert set(merged.findings[0].perspectives) == {Perspective.OFFENSIVE, Perspective.DEFENSIVE}
