from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Callable, Protocol

from pydantic import ValidationError

from .chunking import FileChunk, chunk_files
from .schemas import (
    ComprehensionSummary,
    Finding,
    FindingList,
    OperationalRealism,
    OperationalRealismList,
    Perspective,
    Severity,
)


class JsonModelClient(Protocol):
    def chat_json(self, system_prompt: str, user_prompt: str) -> dict:
        ...


def _serialize_chunk(chunk: FileChunk) -> str:
    return (
        f"File: {chunk.file}\n"
        f"Chunk: {chunk.chunk_index}/{chunk.total_chunks}\n"
        f"Code:\n{chunk.content}\n"
    )


COMPREHENSION_SYSTEM_PROMPT = """
You are a senior application security engineer.
Read the provided code chunk and summarize security-relevant behavior.
Return JSON with keys: summary (string), suspicious_points (array of strings).
Focus on concrete code behavior, not generic advice.
""".strip()


LENS_SYSTEM_PROMPT_TEMPLATE = """
You are a senior security reviewer. Analyze from the {lens} perspective only.
Return strict JSON object with key findings, where findings is an array.
Each finding object must include:
- title
- severity (critical|high|medium|low|info)
- perspectives (array containing only allowed values: offensive, defensive, privacy)
- description
- attack_or_failure_scenario
- recommendation
- evidence (array of objects with file, start_line, end_line, snippet_redacted)
- confidence (0 to 1)
Do not include operational realism in this pass.
""".strip()


REALISM_SYSTEM_PROMPT = """
You are a pragmatic security operations lead.
Assess each finding for operational realism (practicality vs security theater).
Return JSON: {"entries": [{"title": ..., "practicality_score": 0-100, "theater_flag": bool, "notes": ...}]}
""".strip()


@dataclass(slots=True)
class PassOutput:
    comprehension: list[ComprehensionSummary]
    offensive: list[Finding]
    defensive: list[Finding]
    privacy: list[Finding]


def run_comprehension_pass(model: JsonModelClient, files: dict[str, str]) -> list[ComprehensionSummary]:
    chunks = chunk_files(files)
    by_file: dict[str, list[tuple[str, list[str]]]] = defaultdict(list)

    for chunk in chunks:
        payload = model.chat_json(
            COMPREHENSION_SYSTEM_PROMPT,
            _serialize_chunk(chunk),
        )
        summary = str(payload.get("summary", "")).strip()
        suspicious = [str(x).strip() for x in payload.get("suspicious_points", []) if str(x).strip()]
        if not summary:
            summary = "No notable behavior reported for this chunk."
        by_file[chunk.file].append((summary, suspicious))

    summaries: list[ComprehensionSummary] = []
    for file_path in sorted(by_file):
        file_summaries = by_file[file_path]
        merged_summary = "\n".join(entry[0] for entry in file_summaries)
        suspicious_points: list[str] = []
        for _, points in file_summaries:
            suspicious_points.extend(points)
        summaries.append(
            ComprehensionSummary(
                file=file_path,
                summary=merged_summary,
                suspicious_points=list(dict.fromkeys(suspicious_points)),
            )
        )

    return summaries


def _batch_summaries(
    summaries: list[ComprehensionSummary],
    max_chars: int = 40000,
) -> list[list[ComprehensionSummary]]:
    batches: list[list[ComprehensionSummary]] = []
    current: list[ComprehensionSummary] = []
    size = 0

    for summary in summaries:
        encoded = json.dumps(summary.model_dump(), ensure_ascii=True)
        if current and size + len(encoded) > max_chars:
            batches.append(current)
            current = []
            size = 0
        current.append(summary)
        size += len(encoded)

    if current:
        batches.append(current)

    return batches


def _normalize_perspectives(
    existing: list[Perspective],
    enforced: Perspective,
) -> list[Perspective]:
    out = list(dict.fromkeys(existing + [enforced]))
    return out


def run_lens_pass(
    model: JsonModelClient,
    summaries: list[ComprehensionSummary],
    lens: Perspective,
    critical_callback: Callable[[Finding], None] | None = None,
) -> list[Finding]:
    system_prompt = LENS_SYSTEM_PROMPT_TEMPLATE.format(lens=lens.value)
    findings: list[Finding] = []

    for batch in _batch_summaries(summaries):
        user_prompt = json.dumps(
            {
                "lens": lens.value,
                "summaries": [s.model_dump() for s in batch],
                "instruction": "Find concrete issues with evidence from the provided summaries.",
            },
            ensure_ascii=True,
        )

        payload = model.chat_json(system_prompt, user_prompt)
        parsed = _parse_findings(payload, enforced_lens=lens)
        for finding in parsed:
            findings.append(finding)
            if critical_callback and finding.severity == Severity.CRITICAL:
                critical_callback(finding)

    return findings


def _parse_findings(payload: dict, enforced_lens: Perspective) -> list[Finding]:
    findings_payload = payload
    if "findings" not in findings_payload:
        findings_payload = {"findings": []}

    try:
        parsed = FindingList.model_validate(findings_payload)
    except ValidationError:
        return []

    normalized: list[Finding] = []
    for finding in parsed.findings:
        finding.perspectives = _normalize_perspectives(finding.perspectives, enforced_lens)
        finding.finding_id = None
        finding.operational_realism = OperationalRealism(
            practicality_score=50,
            theater_flag=False,
            notes="Operational realism not assessed yet.",
        )
        normalized.append(finding)

    return normalized


def run_operational_realism_pass(
    model: JsonModelClient,
    findings: list[Finding],
) -> list[Finding]:
    if not findings:
        return findings

    prompt_payload = {
        "findings": [
            {
                "title": f.title,
                "severity": f.severity.value,
                "description": f.description,
                "recommendation": f.recommendation,
            }
            for f in findings
        ]
    }

    payload = model.chat_json(REALISM_SYSTEM_PROMPT, json.dumps(prompt_payload, ensure_ascii=True))
    try:
        realism = OperationalRealismList.model_validate(payload)
    except ValidationError:
        return findings

    by_title = {entry.title.strip().lower(): entry for entry in realism.entries}

    for finding in findings:
        key = finding.title.strip().lower()
        entry = by_title.get(key)
        if not entry:
            continue
        finding.operational_realism = OperationalRealism(
            practicality_score=entry.practicality_score,
            theater_flag=entry.theater_flag,
            notes=entry.notes,
        )

    return findings


def run_all_lenses(
    model: JsonModelClient,
    files: dict[str, str],
    critical_callback: Callable[[Finding], None] | None = None,
) -> PassOutput:
    summaries = run_comprehension_pass(model, files)
    offensive = run_lens_pass(model, summaries, Perspective.OFFENSIVE, critical_callback)
    defensive = run_lens_pass(model, summaries, Perspective.DEFENSIVE, critical_callback)
    privacy = run_lens_pass(model, summaries, Perspective.PRIVACY, critical_callback)
    return PassOutput(
        comprehension=summaries,
        offensive=offensive,
        defensive=defensive,
        privacy=privacy,
    )
