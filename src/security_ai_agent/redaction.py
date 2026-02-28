from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class RedactionStats:
    replacements: int


PATTERNS = [
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*[\"']?)([A-Za-z0-9_\-]{10,})([\"']?)"),
    re.compile(r"(?i)(secret\s*[=:]\s*[\"']?)([A-Za-z0-9_\-]{8,})([\"']?)"),
    re.compile(r"(?i)(token\s*[=:]\s*[\"']?)([A-Za-z0-9_\-]{8,})([\"']?)"),
    re.compile(r"(?i)(password\s*[=:]\s*[\"']?)([^\"'\n\r\s]{6,})([\"']?)"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,48}\b"),
]


def redact_text(text: str) -> tuple[str, RedactionStats]:
    redacted = text
    replacements = 0

    for pattern in PATTERNS:
        if pattern.groups >= 2:
            def repl(match: re.Match[str]) -> str:
                nonlocal replacements
                replacements += 1
                prefix = match.group(1)
                suffix = match.group(3) if match.lastindex and match.lastindex >= 3 else ""
                return f"{prefix}[REDACTED_SECRET]{suffix}"

            redacted = pattern.sub(repl, redacted)
            continue

        redacted, count = pattern.subn("[REDACTED_SECRET]", redacted)
        replacements += count

    return redacted, RedactionStats(replacements=replacements)


def redact_codebase(files: dict[str, str]) -> tuple[dict[str, str], RedactionStats]:
    out: dict[str, str] = {}
    total = 0
    for path, content in files.items():
        redacted, stats = redact_text(content)
        out[path] = redacted
        total += stats.replacements
    return out, RedactionStats(replacements=total)
