import copy
from pathlib import Path

import pytest

from agents.report_scoring.dimensions import SCORING_DIMENSIONS
from agents.report_scoring.schemas import ScoreCandidate
from agents.report_scoring.validation import ScoreValidationError, validate_score_candidate
from service.report_scoring.case_registry import CaseRegistry

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


def test_dimension_contract_keeps_stable_fields_with_official_labels_and_weights():
    assert [
        (dimension.field, dimension.label, dimension.maximum) for dimension in SCORING_DIMENSIONS
    ] == [
        ("anchor_accuracy", "初始事件识别准确性", 10),
        ("evidence_recall", "关键证据检索与覆盖度", 20),
        ("timeline", "事件时间线准确性", 5),
        ("process_chain", "攻击链重建与因果分析", 20),
        ("mitre_mapping", "MITRE ATT&CK 映射质量", 30),
        ("negative_findings", "未发生行为核验", 15),
    ]
    assert sum(dimension.maximum for dimension in SCORING_DIMENSIONS) == 100

    properties = ScoreCandidate.model_json_schema()["properties"]
    for dimension in SCORING_DIMENSIONS:
        description = properties[dimension.field]["description"]
        assert dimension.label in description
        assert f"满分 {dimension.maximum} 分" in description


def test_valid_candidate_total_is_computed_by_program(valid_score_dict, negative_behavior_catalog):
    validated = validate_score_candidate(
        valid_score_dict,
        negative_behavior_catalog=negative_behavior_catalog,
    )

    assert validated.total_score == 100.0


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (
            lambda score: score["evidence_recall"].update(score=19.7),
            "0.5 分粒度",
        ),
        (
            lambda score: score["anchor_accuracy"].update(score=9.5),
            "子项之和",
        ),
        (
            lambda score: score["mitre_mapping"].update(base_expression=10),
            "Input should be 0, 5 or 15",
        ),
        (
            lambda score: score["mitre_mapping"].update(score=29.5),
            "基础表达与映射质量",
        ),
        (
            lambda score: score["negative_findings"].update(score=14.5),
            "规则计算结果",
        ),
        (
            lambda score: score["negative_findings"]["correct_findings"][0].update(base_score=1.5),
            "base_score 只能为 2",
        ),
        (
            lambda score: score["negative_findings"].update(
                incorrect_findings=[
                    {
                        "behavior": "错误声称下载",
                        "severity": "suspected",
                        "deduction": 2,
                        "reason": "超出疑似档位。",
                    }
                ]
            ),
            "不符合 suspected 严重度区间",
        ),
        (
            lambda score: score.update(
                root_causes=[
                    {
                        "root_cause_id": "same-error",
                        "description": "同一错误。",
                        "affected_dimensions": [
                            "anchor_accuracy",
                            "evidence_recall",
                            "timeline",
                        ],
                    }
                ]
            ),
            "不得影响三个及以上维度",
        ),
        (
            lambda score: score.update(model_total=99.5),
            "程序计算总分不一致",
        ),
        (
            lambda score: score["anchor_accuracy"].update(score=10.5),
            "less than or equal to 10",
        ),
    ],
)
def test_invalid_candidates_are_rejected(
    valid_score_dict, negative_behavior_catalog, mutation, message
):
    candidate = copy.deepcopy(valid_score_dict)
    mutation(candidate)

    with pytest.raises(ScoreValidationError, match=message):
        validate_score_candidate(
            candidate,
            negative_behavior_catalog=negative_behavior_catalog,
        )


@pytest.mark.parametrize("case", ["duplicate_correct", "duplicate_incorrect", "both", "unknown"])
def test_negative_behavior_ids_are_unique_known_and_mutually_exclusive(
    valid_score_dict, negative_behavior_catalog, case
):
    candidate = copy.deepcopy(valid_score_dict)
    first = copy.deepcopy(candidate["negative_findings"]["correct_findings"][0])
    if case == "duplicate_correct":
        candidate["negative_findings"]["correct_findings"].append(first)
    elif case == "duplicate_incorrect":
        candidate["negative_findings"]["incorrect_findings"] = [
            {
                "behavior_id": first["behavior_id"],
                "behavior": first["behavior"],
                "severity": "suspected",
                "deduction": 1,
                "reason": "错误项。",
            },
            {
                "behavior_id": first["behavior_id"],
                "behavior": first["behavior"],
                "severity": "suspected",
                "deduction": 1,
                "reason": "重复错误项。",
            },
        ]
    elif case == "both":
        candidate["negative_findings"]["incorrect_findings"] = [
            {
                "behavior_id": first["behavior_id"],
                "behavior": first["behavior"],
                "severity": "suspected",
                "deduction": 1,
                "reason": "与正确项冲突。",
            }
        ]
    else:
        candidate["negative_findings"]["correct_findings"][0][
            "behavior_id"
        ] = "non_action_not_in_catalog"

    with pytest.raises(ScoreValidationError):
        validate_score_candidate(
            candidate,
            negative_behavior_catalog=negative_behavior_catalog,
        )


@pytest.mark.parametrize("finding_type", ["correct_findings", "incorrect_findings"])
def test_negative_behavior_id_must_match_canonical_text(
    valid_score_dict, negative_behavior_catalog, finding_type
):
    candidate = copy.deepcopy(valid_score_dict)
    first = copy.deepcopy(candidate["negative_findings"]["correct_findings"][0])
    if finding_type == "correct_findings":
        candidate["negative_findings"][finding_type][0][
            "behavior"
        ] = "NOT_IN_GROUND_TRUTH: lateral movement"
    else:
        candidate["negative_findings"]["correct_findings"] = []
        candidate["negative_findings"][finding_type] = [
            {
                "behavior_id": first["behavior_id"],
                "behavior": "NOT_IN_GROUND_TRUTH: lateral movement",
                "severity": "suspected",
                "deduction": 1,
                "reason": "文本与 ID 错配。",
            }
        ]
        candidate["negative_findings"]["score"] = 0
        candidate["model_total"] = 85

    with pytest.raises(ScoreValidationError, match="behavior 与受控目录不一致"):
        validate_score_candidate(
            candidate,
            negative_behavior_catalog=negative_behavior_catalog,
        )


@pytest.mark.parametrize(
    ("case_id", "atom_count"), [("SIM-204", 5), ("SIM-205", 6), ("SIM-206", 5)]
)
def test_each_case_atomic_catalog_can_reach_v3_negative_cap(valid_score_dict, case_id, atom_count):
    catalog = CaseRegistry(PROJECT_CATALOG).get_case(case_id).negative_behavior_catalog
    candidate = copy.deepcopy(valid_score_dict)
    candidate["negative_findings"]["correct_findings"] = [
        {
            "behavior_id": item["behavior_id"],
            "behavior": item["behavior"],
            "base_score": 2,
            "evidence_score": 1,
            "reason": "报告给出肯定结论及查询依据。",
        }
        for item in catalog
    ]

    validated = validate_score_candidate(
        candidate,
        negative_behavior_catalog=catalog,
    )

    assert len(catalog) == atom_count
    assert validated.candidate.negative_findings.score == 15
    assert validated.total_score == 100
