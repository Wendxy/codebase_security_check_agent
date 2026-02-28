from __future__ import annotations

import argparse
from pathlib import Path

from security_ai_agent.cli import run_scan_command
from security_ai_agent.passes import PassOutput
from security_ai_agent.schemas import Evidence, Finding, Perspective, Severity


def _critical_finding() -> Finding:
    return Finding(
        title="SQL injection in user lookup",
        severity=Severity.CRITICAL,
        perspectives=[Perspective.OFFENSIVE],
        description="desc",
        attack_or_failure_scenario="scenario",
        recommendation="fix",
        evidence=[Evidence(file="app.py", start_line=1, end_line=1, snippet_redacted="danger")],
        confidence=0.9,
    )


def test_scan_fails_on_critical_and_writes_alert(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    target = tmp_path / "repo"
    target.mkdir()
    (target / "app.py").write_text("print('hello')", encoding="utf-8")

    critical = _critical_finding()

    def fake_run_all_lenses(model, files, critical_callback=None):
        if critical_callback:
            critical_callback(critical)
        return PassOutput(
            comprehension=[],
            offensive=[critical],
            defensive=[],
            privacy=[],
        )

    monkeypatch.setattr("security_ai_agent.cli.OpenAIModelClient", lambda config: object())
    monkeypatch.setattr("security_ai_agent.cli.run_all_lenses", fake_run_all_lenses)
    monkeypatch.setattr("security_ai_agent.cli.run_operational_realism_pass", lambda model, findings: findings)

    args = argparse.Namespace(
        target_path=str(target),
        model="gpt-5",
        max_files=None,
        include=[],
        exclude=[],
        output_dir=str(tmp_path / "runs"),
        top_findings=25,
        fail_on="critical",
        format="md,json",
    )

    code = run_scan_command(args)

    assert code == 2
    run_dirs = [p for p in (tmp_path / "runs").iterdir() if p.is_dir()]
    assert run_dirs
    assert (run_dirs[0] / "critical_alert.json").exists()

    captured = capsys.readouterr()
    assert "CRITICAL SECURITY FINDING" in captured.err
