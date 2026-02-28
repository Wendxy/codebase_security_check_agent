from __future__ import annotations

import re
from dataclasses import dataclass

from .schemas import Evidence, Finding, SEVERITY_RANK


@dataclass(slots=True)
class DedupResult:
    findings: list[Finding]
    merged_count: int


def _normalize(text: str) -> str:
    return re.sub(r"\W+", " ", text.lower()).strip()


def _evidence_key(evidence: Evidence) -> tuple[str, int, int]:
    return (evidence.file, evidence.start_line, evidence.end_line)


def finding_fingerprint(finding: Finding) -> str:
    evidence_anchor = ""
    if finding.evidence:
        first = finding.evidence[0]
        evidence_anchor = f"{first.file}:{first.start_line}:{first.end_line}"
    return f"{_normalize(finding.title)}|{evidence_anchor}|{_normalize(finding.recommendation)[:120]}"


def merge_findings(findings: list[Finding]) -> DedupResult:
    by_key: dict[str, Finding] = {}
    merged_count = 0

    for finding in findings:
        key = finding_fingerprint(finding)
        current = by_key.get(key)
        if current is None:
            by_key[key] = finding
            continue

        merged_count += 1

        if SEVERITY_RANK[finding.severity] < SEVERITY_RANK[current.severity]:
            current.severity = finding.severity

        current.confidence = max(current.confidence, finding.confidence)
        current.perspectives = list(dict.fromkeys(current.perspectives + finding.perspectives))

        existing_evidence = {_evidence_key(e) for e in current.evidence}
        for evidence in finding.evidence:
            key_e = _evidence_key(evidence)
            if key_e not in existing_evidence:
                current.evidence.append(evidence)
                existing_evidence.add(key_e)

        if len(finding.description) > len(current.description):
            current.description = finding.description
        if len(finding.attack_or_failure_scenario) > len(current.attack_or_failure_scenario):
            current.attack_or_failure_scenario = finding.attack_or_failure_scenario

    sorted_findings = sorted(
        by_key.values(),
        key=lambda f: (SEVERITY_RANK[f.severity], -f.confidence, f.title.lower()),
    )

    return DedupResult(findings=sorted_findings, merged_count=merged_count)
