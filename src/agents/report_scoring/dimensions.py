from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True)
class ScoringDimension:
    field: str
    label: str
    maximum: int


SCORING_DIMENSIONS: Final[tuple[ScoringDimension, ...]] = (
    ScoringDimension("anchor_accuracy", "初始事件识别准确性", 10),
    ScoringDimension("evidence_recall", "关键证据检索与覆盖度", 20),
    ScoringDimension("timeline", "事件时间线准确性", 5),
    ScoringDimension("process_chain", "攻击链重建与因果分析", 20),
    ScoringDimension("mitre_mapping", "MITRE ATT&CK 映射质量", 30),
    ScoringDimension("negative_findings", "未发生行为核验", 15),
)

SCORING_DIMENSION_LABELS: Final = {
    dimension.field: dimension.label for dimension in SCORING_DIMENSIONS
}
SCORING_DIMENSION_MAXIMUMS: Final = {
    dimension.field: dimension.maximum for dimension in SCORING_DIMENSIONS
}
SCORING_DIMENSION_FIELDS: Final = tuple(dimension.field for dimension in SCORING_DIMENSIONS)
