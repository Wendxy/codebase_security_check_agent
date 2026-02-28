from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Perspective(str, Enum):
    OFFENSIVE = "offensive"
    DEFENSIVE = "defensive"
    PRIVACY = "privacy"


class Evidence(BaseModel):
    file: str
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    snippet_redacted: str


class OperationalRealism(BaseModel):
    practicality_score: int = Field(ge=0, le=100)
    theater_flag: bool
    notes: str


class Finding(BaseModel):
    finding_id: str | None = None
    title: str
    severity: Severity
    perspectives: list[Perspective]
    operational_realism: OperationalRealism = Field(
        default_factory=lambda: OperationalRealism(
            practicality_score=50,
            theater_flag=False,
            notes="Operational realism not assessed yet.",
        )
    )
    description: str
    attack_or_failure_scenario: str
    recommendation: str
    evidence: list[Evidence]
    confidence: float = Field(ge=0.0, le=1.0)

    @field_validator("perspectives")
    @classmethod
    def _validate_perspectives(cls, value: list[Perspective]) -> list[Perspective]:
        if not value:
            raise ValueError("perspectives must not be empty")
        return list(dict.fromkeys(value))


class FindingList(BaseModel):
    findings: list[Finding]


class ComprehensionSummary(BaseModel):
    file: str
    summary: str
    suspicious_points: list[str] = Field(default_factory=list)


class ComprehensionSummaryList(BaseModel):
    summaries: list[ComprehensionSummary]


class OperationalRealismEntry(BaseModel):
    title: str
    practicality_score: int = Field(ge=0, le=100)
    theater_flag: bool
    notes: str


class OperationalRealismList(BaseModel):
    entries: list[OperationalRealismEntry]


class RunMetadata(BaseModel):
    run_id: str
    target_path: str
    model: str
    file_count: int
    generated_at: str
    status: Literal["ok", "critical"]


SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}
