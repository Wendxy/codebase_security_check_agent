from __future__ import annotations

import json
from pathlib import Path

import pytest

from security_ai_agent.explain import explain_finding, resolve_run_dir
from security_ai_agent.schemas import (
    Evidence,
    Finding,
    OperationalRealism,
    Perspective,
    Severity,
)


def _write_findings(run_dir: Path) -> None:
    finding = Finding(
        finding_id="R-001",
        title="Hardcoded secret",
        severity=Severity.CRITICAL,
        perspectives=[Perspective.PRIVACY],
        operational_realism=OperationalRealism(
            practicality_score=70,
            theater_flag=False,
            notes="Use secret manager",
        ),
        description="Secret appears in code",
        attack_or_failure_scenario="Attacker reads repository",
        recommendation="Move secret to env",
        evidence=[
            Evidence(
                file="app.py",
                start_line=3,
                end_line=3,
                snippet_redacted='DB_PASSWORD = "[REDACTED_SECRET]"',
            )
        ],
        confidence=0.9,
    )
    payload = {"metadata": {"run_id": run_dir.name}, "findings": [finding.model_dump(mode="json")]}
    (run_dir / "findings.json").write_text(json.dumps(payload), encoding="utf-8")


def test_explain_finding_returns_detailed_report(tmp_path: Path) -> None:
    run_dir = tmp_path / "20260228T010101Z"
    run_dir.mkdir(parents=True)
    _write_findings(run_dir)

    details = explain_finding(run_dir, "R-001")

    assert "Deep Dive: R-001" in details
    assert "Operational Realism" in details
    assert "app.py:3" in details


def test_resolve_run_dir_latest(tmp_path: Path) -> None:
    old = tmp_path / "20260228T000000Z"
    new = tmp_path / "20260228T010000Z"
    old.mkdir(parents=True)
    new.mkdir(parents=True)

    latest = resolve_run_dir(tmp_path, "latest")
    assert latest.name == "20260228T010000Z"


def test_explain_finding_missing_id_raises(tmp_path: Path) -> None:
    run_dir = tmp_path / "20260228T010101Z"
    run_dir.mkdir(parents=True)
    _write_findings(run_dir)

    with pytest.raises(ValueError):
        explain_finding(run_dir, "R-999")
