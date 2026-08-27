import copy
import json
from pathlib import Path

import pytest

from agents.report_scoring.negative_behaviors import build_negative_behavior_catalog

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


@pytest.fixture
def negative_behavior_catalog():
    ground_truth = json.loads(
        (PROJECT_CATALOG / "cases" / "SIM-204" / "ground_truth.json").read_text(encoding="utf-8")
    )
    return build_negative_behavior_catalog(ground_truth)


@pytest.fixture
def valid_score_dict(negative_behavior_catalog):
    """A maximum SIM-204 candidate that satisfies every v3.0 structural rule."""

    value = {
        "anchor_accuracy": {
            "score": 10,
            "subscores": {
                "agent_identity": 2,
                "process_relationship": 3,
                "command_objects": 3,
                "event_action": 2,
            },
            "reason": "锚点字段完整且准确。",
            "report_evidence": ["报告明确给出 Agent、进程关系、命令和动作。"],
        },
        "evidence_recall": {
            "score": 20,
            "reason": "报告呈现全部可见关键证据。",
            "report_evidence": ["报告列出父子进程及文件事件。"],
        },
        "timeline": {
            "score": 5,
            "subscores": {
                "relative_order": 3,
                "internal_consistency": 1,
                "no_fabricated_time": 1,
            },
            "reason": "时间线顺序正确且自洽。",
            "report_evidence": ["报告按创建、执行、验证顺序描述。"],
        },
        "process_chain": {
            "score": 20,
            "subscores": {"core_chain": 12, "behavior_state": 5, "causal_boundary": 3},
            "reason": "进程链与因果边界准确。",
            "report_evidence": ["报告区分文件创建与后续执行。"],
        },
        "mitre_mapping": {
            "score": 30,
            "base_expression": 15,
            "timeline_coverage": "全部攻击时间线项目均在同一项目内包含时间、T 编号和行为。",
            "quality_subscores": {
                "core_coverage": 6,
                "behavior_accuracy": 6,
                "technique_precision": 3,
            },
            "reason": "全部攻击时间线项目均有合理映射。",
            "report_evidence": ["每个时间线项目同项包含时间、T 编号和行为。"],
        },
        "negative_findings": {
            "score": 15,
            "correct_findings": [
                {
                    "behavior_id": item["behavior_id"],
                    "behavior": item["behavior"],
                    "base_score": 2,
                    "evidence_score": 1,
                    "reason": "报告给出肯定结论及查询依据。",
                }
                for item in negative_behavior_catalog
            ],
            "incorrect_findings": [],
            "reason": "五项 Ground Truth 原子负面行为均正确且有依据。",
            "report_evidence": ["报告明确记录零命中查询。"],
        },
        "root_causes": [],
        "strengths": ["证据链完整。"],
        "major_issues": [],
        "model_total": 100,
    }
    return copy.deepcopy(value)
