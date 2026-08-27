import copy
import json
import uuid
from pathlib import Path

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.report_repository import ReportRepository
from service.report_scoring.score_repository import ScoreRepository
from service.report_scoring.scoring_service import ScoringService

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


class QueueModel(BaseChatModel):
    responses: list[str]
    calls: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        response = self.responses[self.calls]
        self.calls += 1
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=response))])

    @property
    def _llm_type(self):
        return "queue-scoring-model"


def score_with_total(base, total):
    value = copy.deepcopy(base)
    evidence = 20 - (100 - total)
    value["evidence_recall"]["score"] = evidence
    value["model_total"] = total
    return value


def test_comparison_uses_each_report_latest_success_once(tmp_path, valid_score_dict):
    candidates = [
        score_with_total(valid_score_dict, 100),
        score_with_total(valid_score_dict, 90),
        score_with_total(valid_score_dict, 80),
    ]
    registry = CaseRegistry(PROJECT_CATALOG)
    reports = ReportRepository(tmp_path / "runtime", registry)
    scores = ScoreRepository(tmp_path / "runtime")
    model = QueueModel(responses=[json.dumps(value, ensure_ascii=False) for value in candidates])
    service = ScoringService(registry, reports, scores, model)
    report_a = reports.create_report(
        content=b"report a",
        filename="a.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )
    report_b = reports.create_report(
        content=b"report b",
        filename="b.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )
    reports.create_report(
        content=b"unscored",
        filename="unscored.md",
        test_case_id="SIM-204",
        agent_id="baseline_agent_simple",
        source_type="upload",
    )
    service.score(report_a.report_id, str(uuid.uuid4()))
    service.score(report_b.report_id, str(uuid.uuid4()))
    service.score(report_a.report_id, str(uuid.uuid4()), rescore=True)

    comparison = service.comparison("SIM-204")

    attack = next(
        item for item in comparison["agents"] if item["agent_id"] == "attack_attribution_agent"
    )
    baseline = next(
        item for item in comparison["agents"] if item["agent_id"] == "baseline_agent_simple"
    )
    assert attack["registered_report_count"] == 2
    assert attack["successfully_scored_report_count"] == 2
    assert sorted(item["total_score"] for item in attack["report_scores"]) == [80, 90]
    assert attack["average_total"] == 85.0
    assert attack["minimum_total"] == 80
    assert attack["maximum_total"] == 90
    assert attack["dimension_averages"]["evidence_recall"] == 5.0
    assert baseline["registered_report_count"] == 1
    assert baseline["successfully_scored_report_count"] == 0
    assert baseline["average_total"] is None
    assert baseline["minimum_total"] is None


def test_comparison_rejects_mixed_standard_request(tmp_path, valid_score_dict):
    registry = CaseRegistry(PROJECT_CATALOG)
    reports = ReportRepository(tmp_path / "runtime", registry)
    service = ScoringService(
        registry,
        reports,
        ScoreRepository(tmp_path / "runtime"),
        QueueModel(responses=[json.dumps(valid_score_dict)]),
    )

    from service.report_scoring.errors import ReportScoringError

    try:
        service.comparison("SIM-204", "v2.0")
    except ReportScoringError as exc:
        assert exc.code == "INVALID_SCORING_STANDARD"
    else:  # pragma: no cover
        raise AssertionError("v2.0 comparison should be rejected")
