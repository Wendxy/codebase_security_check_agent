from __future__ import annotations

import json

from security_ai_agent.passes import run_all_lenses, run_operational_realism_pass
from security_ai_agent.schemas import Perspective, Severity


class FakeModel:
    def chat_json(self, system_prompt: str, user_prompt: str) -> dict:
        if "Read the provided code chunk" in system_prompt:
            return {
                "summary": "Builds SQL with user input and logs payment data.",
                "suspicious_points": ["Unsanitized SQL", "Sensitive logging"],
            }

        if "Analyze from the" in system_prompt:
            payload = json.loads(user_prompt)
            lens = payload["lens"]
            if lens == "offensive":
                return {
                    "findings": [
                        {
                            "title": "SQL injection in user lookup",
                            "severity": "critical",
                            "perspectives": ["offensive"],
                            "description": "Query uses raw input interpolation.",
                            "attack_or_failure_scenario": "Attacker injects SQL payload.",
                            "recommendation": "Use parameterized queries.",
                            "evidence": [
                                {
                                    "file": "app.py",
                                    "start_line": 6,
                                    "end_line": 6,
                                    "snippet_redacted": "query = f\"SELECT ... {user_input}\"",
                                }
                            ],
                            "confidence": 0.95,
                        }
                    ]
                }
            if lens == "defensive":
                return {
                    "findings": [
                        {
                            "title": "Missing input validation guard",
                            "severity": "high",
                            "perspectives": ["defensive"],
                            "description": "No validation before DB query.",
                            "attack_or_failure_scenario": "Malformed input bypasses logic.",
                            "recommendation": "Add strict validation.",
                            "evidence": [
                                {
                                    "file": "app.py",
                                    "start_line": 5,
                                    "end_line": 6,
                                    "snippet_redacted": "def find_user(user_input)",
                                }
                            ],
                            "confidence": 0.8,
                        }
                    ]
                }
            return {
                "findings": [
                    {
                        "title": "Card data appears in logs",
                        "severity": "high",
                        "perspectives": ["privacy"],
                        "description": "PAN-like values are logged.",
                        "attack_or_failure_scenario": "Log compromise leaks card data.",
                        "recommendation": "Mask sensitive fields in logs.",
                        "evidence": [
                            {
                                "file": "logging.py",
                                "start_line": 4,
                                "end_line": 4,
                                "snippet_redacted": "logging.info(... card=%s)",
                            }
                        ],
                        "confidence": 0.9,
                    }
                ]
            }

        if "operational realism" in system_prompt.lower():
            return {
                "entries": [
                    {
                        "title": "SQL injection in user lookup",
                        "practicality_score": 92,
                        "theater_flag": False,
                        "notes": "Parameterized queries are straightforward.",
                    },
                    {
                        "title": "Missing input validation guard",
                        "practicality_score": 85,
                        "theater_flag": False,
                        "notes": "Validation is feasible at API boundary.",
                    },
                    {
                        "title": "Card data appears in logs",
                        "practicality_score": 60,
                        "theater_flag": True,
                        "notes": "Blanket logging bans are often theater; targeted masking is practical.",
                    },
                ]
            }

        return {}


def test_passes_tag_findings_with_expected_perspectives() -> None:
    files = {"app.py": "print('x')", "logging.py": "print('y')"}
    output = run_all_lenses(FakeModel(), files)

    assert output.offensive[0].severity == Severity.CRITICAL
    assert output.offensive[0].perspectives == [Perspective.OFFENSIVE]
    assert output.defensive[0].perspectives == [Perspective.DEFENSIVE]
    assert output.privacy[0].perspectives == [Perspective.PRIVACY]


def test_operational_realism_updates_findings() -> None:
    files = {"app.py": "print('x')", "logging.py": "print('y')"}
    output = run_all_lenses(FakeModel(), files)
    findings = output.offensive + output.defensive + output.privacy

    assessed = run_operational_realism_pass(FakeModel(), findings)
    privacy = next(item for item in assessed if item.title == "Card data appears in logs")

    assert privacy.operational_realism.theater_flag is True
    assert privacy.operational_realism.practicality_score == 60
