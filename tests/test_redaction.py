from __future__ import annotations

from security_ai_agent.redaction import redact_codebase, redact_text


def test_redact_text_masks_likely_secrets() -> None:
    text = 'api_key="abc123456789"\npassword = hunter2\n'
    redacted, stats = redact_text(text)

    assert "abc123456789" not in redacted
    assert "hunter2" not in redacted
    assert redacted.count("[REDACTED_SECRET]") >= 2
    assert stats.replacements >= 2


def test_redact_codebase_aggregates_stats() -> None:
    files = {
        "a.py": 'token="abcdefghi123"',
        "b.py": 'secret="mysecretvalue"',
    }
    redacted, stats = redact_codebase(files)

    assert all("[REDACTED_SECRET]" in value for value in redacted.values())
    assert stats.replacements == 2
