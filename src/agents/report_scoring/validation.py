from collections.abc import Collection, Mapping
from dataclasses import dataclass

from pydantic import ValidationError

from .schemas import ScoreCandidate


@dataclass(frozen=True)
class ValidatedScore:
    candidate: ScoreCandidate
    total_score: float


class ScoreValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors))
        self.errors = errors


def _is_half_step(value: float) -> bool:
    return abs(value * 2 - round(value * 2)) < 1e-8


def _sum_values(model) -> float:
    return sum(float(value) for value in model.model_dump().values())


def validate_score_candidate(
    value: ScoreCandidate | dict,
    *,
    negative_behavior_catalog: Collection[Mapping[str, str]],
) -> ValidatedScore:
    try:
        candidate = (
            value if isinstance(value, ScoreCandidate) else ScoreCandidate.model_validate(value)
        )
    except ValidationError as exc:
        raise ScoreValidationError(
            [
                f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}"
                for error in exc.errors()
            ]
        ) from None

    errors: list[str] = []
    half_step_values: list[tuple[str, float]] = [
        ("anchor_accuracy.score", candidate.anchor_accuracy.score),
        ("evidence_recall.score", candidate.evidence_recall.score),
        ("timeline.score", candidate.timeline.score),
        ("process_chain.score", candidate.process_chain.score),
        ("mitre_mapping.score", candidate.mitre_mapping.score),
        ("negative_findings.score", candidate.negative_findings.score),
    ]
    for prefix, subscores in (
        ("anchor_accuracy.subscores", candidate.anchor_accuracy.subscores),
        ("timeline.subscores", candidate.timeline.subscores),
        ("process_chain.subscores", candidate.process_chain.subscores),
        ("mitre_mapping.quality_subscores", candidate.mitre_mapping.quality_subscores),
    ):
        half_step_values.extend(
            (f"{prefix}.{name}", float(score)) for name, score in subscores.model_dump().items()
        )
    for index, finding in enumerate(candidate.negative_findings.correct_findings):
        half_step_values.extend(
            [
                (f"negative_findings.correct_findings[{index}].base_score", finding.base_score),
                (
                    f"negative_findings.correct_findings[{index}].evidence_score",
                    finding.evidence_score,
                ),
            ]
        )
    for index, finding in enumerate(candidate.negative_findings.incorrect_findings):
        half_step_values.append(
            (f"negative_findings.incorrect_findings[{index}].deduction", finding.deduction)
        )
    if candidate.model_total is not None:
        half_step_values.append(("model_total", candidate.model_total))
    errors.extend(
        f"{name} 必须使用 0.5 分粒度"
        for name, score in half_step_values
        if not _is_half_step(score)
    )

    fixed_dimensions = (
        ("anchor_accuracy", candidate.anchor_accuracy.score, candidate.anchor_accuracy.subscores),
        ("timeline", candidate.timeline.score, candidate.timeline.subscores),
        ("process_chain", candidate.process_chain.score, candidate.process_chain.subscores),
    )
    for name, score, subscores in fixed_dimensions:
        if abs(_sum_values(subscores) - score) > 1e-8:
            errors.append(f"{name} 子项之和必须等于维度得分")

    mitre_quality = _sum_values(candidate.mitre_mapping.quality_subscores)
    expected_mitre = candidate.mitre_mapping.base_expression + mitre_quality
    if abs(expected_mitre - candidate.mitre_mapping.score) > 1e-8:
        errors.append("mitre_mapping 必须等于基础表达与映射质量子项之和")

    canonical_behaviors = {
        item["behavior_id"]: item["behavior"] for item in negative_behavior_catalog
    }
    correct_behavior_ids: set[str] = set()
    incorrect_behavior_ids: set[str] = set()
    positive = 0.0
    for index, finding in enumerate(candidate.negative_findings.correct_findings):
        behavior_id = finding.behavior_id
        countable = False
        if behavior_id is None:
            errors.append(f"correct_findings[{index}].behavior_id 必填")
        elif behavior_id not in canonical_behaviors:
            errors.append(f"correct_findings[{index}].behavior_id 不属于当前案例")
        elif behavior_id in correct_behavior_ids:
            errors.append(f"correct_findings[{index}].behavior_id 重复")
        else:
            correct_behavior_ids.add(behavior_id)
            countable = True
            if finding.behavior != canonical_behaviors[behavior_id]:
                errors.append(f"correct_findings[{index}].behavior 与受控目录不一致")
                countable = False
        if finding.base_score != 2:
            errors.append(f"correct_findings[{index}].base_score 只能为 2")
        if finding.evidence_score not in (0, 1):
            errors.append(f"correct_findings[{index}].evidence_score 只能为 0 或 1")
        if countable:
            positive += finding.base_score + finding.evidence_score

    severity_ranges = {
        "further_investigation": (0, 1),
        "suspected": (0.5, 1.5),
        "explicit": (1, 2),
        "core_claim": (2, 3),
    }
    deduction = 0.0
    for index, finding in enumerate(candidate.negative_findings.incorrect_findings):
        behavior_id = finding.behavior_id
        countable = False
        if behavior_id is None:
            errors.append(f"incorrect_findings[{index}].behavior_id 必填")
        elif behavior_id not in canonical_behaviors:
            errors.append(f"incorrect_findings[{index}].behavior_id 不属于当前案例")
        elif behavior_id in incorrect_behavior_ids:
            errors.append(f"incorrect_findings[{index}].behavior_id 重复")
        else:
            incorrect_behavior_ids.add(behavior_id)
            countable = True
            if finding.behavior != canonical_behaviors[behavior_id]:
                errors.append(f"incorrect_findings[{index}].behavior 与受控目录不一致")
                countable = False
        low, high = severity_ranges[finding.severity]
        if not low <= finding.deduction <= high:
            errors.append(
                f"incorrect_findings[{index}].deduction 不符合 {finding.severity} 严重度区间"
            )
        if countable:
            deduction += finding.deduction
    for behavior_id in sorted(correct_behavior_ids & incorrect_behavior_ids):
        errors.append(f"behavior_id {behavior_id} 不能同时作为正确和错误结论")
    expected_negative = min(15.0, max(0.0, positive - deduction))
    if abs(expected_negative - candidate.negative_findings.score) > 1e-8:
        errors.append("negative_findings 得分必须等于规则计算结果")

    seen_root_causes: set[str] = set()
    for root_cause in candidate.root_causes:
        if root_cause.root_cause_id in seen_root_causes:
            errors.append(f"root_cause_id {root_cause.root_cause_id} 重复")
        seen_root_causes.add(root_cause.root_cause_id)
        if len(set(root_cause.affected_dimensions)) != len(root_cause.affected_dimensions):
            errors.append(f"root_cause_id {root_cause.root_cause_id} 的影响维度重复")
        if len(set(root_cause.affected_dimensions)) > 2:
            errors.append(f"root_cause_id {root_cause.root_cause_id} 不得影响三个及以上维度")

    total = round(
        candidate.anchor_accuracy.score
        + candidate.evidence_recall.score
        + candidate.timeline.score
        + candidate.process_chain.score
        + candidate.mitre_mapping.score
        + candidate.negative_findings.score,
        1,
    )
    if candidate.model_total is not None and abs(candidate.model_total - total) > 1e-8:
        errors.append("model_total 与程序计算总分不一致")

    if errors:
        raise ScoreValidationError(errors)
    return ValidatedScore(candidate=candidate, total_score=total)
