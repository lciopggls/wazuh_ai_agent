from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from agents.report_scoring.dimensions import (
    SCORING_DIMENSION_LABELS,
)
from agents.report_scoring.schemas import ScoreCandidate

RelativePath = Annotated[str, StringConstraints(min_length=1, max_length=240)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-fA-F]{64}$")]
TestCaseId = Annotated[str, StringConstraints(pattern=r"^SIM-[0-9]{3}$")]


class ScoringFingerprint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    standard_sha256: Sha256
    scoring_context_sha256: Sha256


class TestCaseManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    test_case_id: TestCaseId
    display_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    enabled: bool
    scoring_standard_version: Literal["v3.0"]
    scoring_standard_path: RelativePath
    input_path: RelativePath
    anchor_path: RelativePath
    ground_truth_path: RelativePath
    telemetry_boundary_paths: list[RelativePath] = Field(min_length=1)
    expected_report_path: RelativePath
    input_sha256: Sha256
    standard_sha256: Sha256
    compatible_scoring_fingerprints: list[ScoringFingerprint] = Field(default_factory=list)


class AgentDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
    display_name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
    aliases: list[Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]] = Field(
        default_factory=list
    )


class AgentCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    agents: list[AgentDefinition] = Field(min_length=1)


class TestCaseSummary(BaseModel):
    test_case_id: str
    display_name: str
    scoring_standard_version: str
    input_sha256: str


class AgentSummary(BaseModel):
    agent_id: str
    display_name: str


WritableReportSource = Literal["ai_chat", "upload"]
StoredReportSource = Literal["ai_chat", "studio", "upload", "local_import"]
AuditId = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=160)]
AuditNote = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=1000)]


class ScoringRegistration(BaseModel):
    model_config = ConfigDict(extra="forbid")

    test_case_id: TestCaseId
    agent_id: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=64)]
    thread_id: AuditId | None = None
    run_id: AuditId | None = None
    note: AuditNote | None = None


class ReportRegistrationInput(ScoringRegistration):
    """Validated repository input before a report directory is allocated."""

    filename: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    source_type: WritableReportSource


class ReportRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Schema 2 was written by the removed dynamic case-preparation prototype.
    # Keep read compatibility so preserved report/score history still loads.
    schema_version: Literal[1, 2] = 1
    report_id: Annotated[str, StringConstraints(pattern=r"^rpt_[0-9a-f]{32}$")]
    test_case_id: TestCaseId
    agent_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
    source_type: StoredReportSource
    original_filename: Annotated[str, StringConstraints(min_length=1, max_length=255)]
    stored_path: RelativePath
    report_sha256: Sha256
    input_sha256: Sha256
    imported_at: datetime
    thread_id: AuditId | None = None
    run_id: AuditId | None = None
    note: AuditNote | None = None
    attack_run_id: AuditId | None = None
    anchor_sha256: Sha256 | None = None
    confirmation_actor: AuditId | None = None
    confirmed_at: datetime | None = None


class ReportListItem(ReportRecord):
    latest_attempt_status: Literal["not_scored", "running", "succeeded", "failed"] = "not_scored"
    latest_attempt_id: str | None = None
    latest_score_id: str | None = None
    latest_total_score: float | None = Field(default=None, ge=0, le=100)


class ReportListResponse(BaseModel):
    items: list[ReportListItem]
    total: int
    offset: int
    limit: int


class ScoreRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: UUID


class ScoringAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    attempt_id: Annotated[str, StringConstraints(pattern=r"^att_[0-9a-f]{32}$")]
    request_id: UUID
    report_id: Annotated[str, StringConstraints(pattern=r"^rpt_[0-9a-f]{32}$")]
    test_case_id: TestCaseId
    agent_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
    operation: Literal["score", "rescore"]
    scoring_contract_version: str | None = None
    status: Literal["running", "succeeded", "failed"]
    started_at: datetime
    completed_at: datetime | None = None
    score_id: Annotated[str, StringConstraints(pattern=r"^scr_[0-9a-f]{32}$")] | None = None
    error_code: str | None = None
    error_message: str | None = None


class ScoreResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    score_id: Annotated[str, StringConstraints(pattern=r"^scr_[0-9a-f]{32}$")]
    attempt_id: Annotated[str, StringConstraints(pattern=r"^att_[0-9a-f]{32}$")]
    report_id: Annotated[str, StringConstraints(pattern=r"^rpt_[0-9a-f]{32}$")]
    test_case_id: TestCaseId
    agent_id: Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_]{1,63}$")]
    report_sha256: Sha256
    input_sha256: Sha256
    standard_sha256: Sha256
    scoring_context_sha256: Sha256 | None = None
    scoring_standard_version: Literal["v3.0"]
    model_name: str
    scoring_agent_version: str
    prompt_version: str
    scoring_contract_version: str | None = None
    completed_at: datetime
    total_score: float = Field(ge=0, le=100)
    score: ScoreCandidate


class ScoreInvocationResponse(BaseModel):
    attempt: ScoringAttempt
    result: ScoreResult
    reused: bool


class ScoreHistoryItem(BaseModel):
    attempt: ScoringAttempt
    result: ScoreResult | None = None


class DimensionAverages(BaseModel):
    anchor_accuracy: float | None = Field(
        description=f"{SCORING_DIMENSION_LABELS['anchor_accuracy']}平均分"
    )
    evidence_recall: float | None = Field(
        description=f"{SCORING_DIMENSION_LABELS['evidence_recall']}平均分"
    )
    timeline: float | None = Field(description=f"{SCORING_DIMENSION_LABELS['timeline']}平均分")
    process_chain: float | None = Field(
        description=f"{SCORING_DIMENSION_LABELS['process_chain']}平均分"
    )
    mitre_mapping: float | None = Field(
        description=f"{SCORING_DIMENSION_LABELS['mitre_mapping']}平均分"
    )
    negative_findings: float | None = Field(
        description=f"{SCORING_DIMENSION_LABELS['negative_findings']}平均分"
    )


class ComparisonReportScore(BaseModel):
    report_id: str
    score_id: str
    total_score: float = Field(ge=0, le=100)


class ComparisonAgent(BaseModel):
    agent_id: str
    display_name: str
    registered_report_count: int = Field(ge=0)
    successfully_scored_report_count: int = Field(ge=0)
    report_scores: list[ComparisonReportScore]
    average_total: float | None = Field(default=None, ge=0, le=100)
    minimum_total: float | None = Field(default=None, ge=0, le=100)
    maximum_total: float | None = Field(default=None, ge=0, le=100)
    dimension_averages: DimensionAverages


class ComparisonResponse(BaseModel):
    test_case_id: TestCaseId
    scoring_standard_version: Literal["v3.0"]
    agents: list[ComparisonAgent]
