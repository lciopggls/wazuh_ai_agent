from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .dimensions import SCORING_DIMENSION_LABELS, SCORING_DIMENSION_MAXIMUMS

Reason = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
BehaviorId = Annotated[
    str,
    StringConstraints(pattern=r"^non_action_[a-z0-9_]{1,64}$"),
]
DimensionName = Literal[
    "anchor_accuracy",
    "evidence_recall",
    "timeline",
    "process_chain",
    "mitre_mapping",
    "negative_findings",
]


class AnchorSubscores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_identity: float = Field(ge=0, le=2)
    process_relationship: float = Field(ge=0, le=3)
    command_objects: float = Field(ge=0, le=3)
    event_action: float = Field(ge=0, le=2)


class TimelineSubscores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relative_order: float = Field(ge=0, le=3)
    internal_consistency: float = Field(ge=0, le=1)
    no_fabricated_time: float = Field(ge=0, le=1)


class ProcessChainSubscores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    core_chain: float = Field(ge=0, le=12)
    behavior_state: float = Field(ge=0, le=5)
    causal_boundary: float = Field(ge=0, le=3)


class MitreQualitySubscores(BaseModel):
    model_config = ConfigDict(extra="forbid")

    core_coverage: float = Field(ge=0, le=6)
    behavior_accuracy: float = Field(ge=0, le=6)
    technique_precision: float = Field(ge=0, le=3)


class FixedDimensionScore(BaseModel):
    model_config = ConfigDict(extra="forbid")

    score: float
    reason: Reason
    report_evidence: list[Reason] = Field(min_length=1)


class AnchorScore(FixedDimensionScore):
    score: float = Field(ge=0, le=10)
    subscores: AnchorSubscores


class EvidenceRecallScore(FixedDimensionScore):
    score: float = Field(ge=0, le=20)


class TimelineScore(FixedDimensionScore):
    score: float = Field(ge=0, le=5)
    subscores: TimelineSubscores


class ProcessChainScore(FixedDimensionScore):
    score: float = Field(ge=0, le=20)
    subscores: ProcessChainSubscores


class MitreScore(FixedDimensionScore):
    score: float = Field(ge=0, le=30)
    base_expression: Literal[0, 5, 15]
    timeline_coverage: Reason
    quality_subscores: MitreQualitySubscores


class CorrectNegativeFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Optional only so historical persisted v1 results remain readable. New
    # candidates are required to provide it by validate_score_candidate().
    behavior_id: BehaviorId | None = None
    behavior: Reason
    base_score: float
    evidence_score: float
    reason: Reason


class IncorrectNegativeFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    behavior_id: BehaviorId | None = None
    behavior: Reason
    severity: Literal["further_investigation", "suspected", "explicit", "core_claim"]
    deduction: float = Field(ge=0, le=3)
    reason: Reason


class NegativeFindingsScore(FixedDimensionScore):
    score: float = Field(ge=0, le=15)
    correct_findings: list[CorrectNegativeFinding]
    incorrect_findings: list[IncorrectNegativeFinding]


class RootCauseImpact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    root_cause_id: Annotated[str, StringConstraints(pattern=r"^[a-zA-Z0-9_-]{1,64}$")]
    description: Reason
    affected_dimensions: list[DimensionName] = Field(min_length=1)


class ScoreCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    anchor_accuracy: AnchorScore = Field(
        description=(
            f"{SCORING_DIMENSION_LABELS['anchor_accuracy']}，"
            f"满分 {SCORING_DIMENSION_MAXIMUMS['anchor_accuracy']} 分"
        )
    )
    evidence_recall: EvidenceRecallScore = Field(
        description=(
            f"{SCORING_DIMENSION_LABELS['evidence_recall']}，"
            f"满分 {SCORING_DIMENSION_MAXIMUMS['evidence_recall']} 分"
        )
    )
    timeline: TimelineScore = Field(
        description=(
            f"{SCORING_DIMENSION_LABELS['timeline']}，"
            f"满分 {SCORING_DIMENSION_MAXIMUMS['timeline']} 分"
        )
    )
    process_chain: ProcessChainScore = Field(
        description=(
            f"{SCORING_DIMENSION_LABELS['process_chain']}，"
            f"满分 {SCORING_DIMENSION_MAXIMUMS['process_chain']} 分"
        )
    )
    mitre_mapping: MitreScore = Field(
        description=(
            f"{SCORING_DIMENSION_LABELS['mitre_mapping']}，"
            f"满分 {SCORING_DIMENSION_MAXIMUMS['mitre_mapping']} 分"
        )
    )
    negative_findings: NegativeFindingsScore = Field(
        description=(
            f"{SCORING_DIMENSION_LABELS['negative_findings']}，"
            f"满分 {SCORING_DIMENSION_MAXIMUMS['negative_findings']} 分"
        )
    )
    root_causes: list[RootCauseImpact]
    strengths: list[Reason]
    major_issues: list[Reason]
    model_total: float | None = Field(default=None, ge=0, le=100)
