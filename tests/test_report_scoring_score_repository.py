import copy
import json
import threading
import uuid
from pathlib import Path
from typing import Any

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import Field

from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.errors import ReportScoringError
from service.report_scoring.report_repository import ReportRepository
from service.report_scoring.score_repository import ScoreRepository
from service.report_scoring.scoring_service import ScoringService

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


class MutableScoringModel(BaseChatModel):
    responses: list[str]
    calls: int = 0
    started: Any = Field(default=None, exclude=True)
    release: Any = Field(default=None, exclude=True)

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.started is not None:
            self.started.set()
        if self.release is not None:
            assert self.release.wait(timeout=5)
        response = self.responses[min(self.calls, len(self.responses) - 1)]
        self.calls += 1
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=response))])

    @property
    def _llm_type(self):
        return "mutable-scoring-model"


def make_service(tmp_path, candidate):
    registry = CaseRegistry(PROJECT_CATALOG)
    reports = ReportRepository(tmp_path / "runtime", registry)
    scores = ScoreRepository(tmp_path / "runtime")
    model = MutableScoringModel(responses=[json.dumps(candidate, ensure_ascii=False)])
    service = ScoringService(registry, reports, scores, model)
    report = reports.create_report(
        content=b"report one",
        filename="one.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )
    return service, report, model


def test_score_persists_attempt_result_and_markdown(tmp_path, valid_score_dict):
    service, report, _ = make_service(tmp_path, valid_score_dict)

    response = service.score(report.report_id, str(uuid.uuid4()))

    attempt_dir = (
        service.score_repository.attempts_root / report.report_id / response.attempt.attempt_id
    )
    assert response.result.total_score == 100
    assert response.attempt.status == "succeeded"
    assert (attempt_dir / "attempt.json").is_file()
    assert (attempt_dir / "result.json").is_file()
    score_markdown = (attempt_dir / "score.md").read_text(encoding="utf-8")
    assert "**100.0**" in score_markdown
    assert "| 初始事件识别准确性 | 10.0 |" in score_markdown
    assert "| 未发生行为核验 | 15.0 |" in score_markdown


def test_request_id_and_first_score_are_idempotent(tmp_path, valid_score_dict):
    service, report, model = make_service(tmp_path, valid_score_dict)
    request_id = str(uuid.uuid4())
    first = service.score(report.report_id, request_id)

    retried = service.score(report.report_id, request_id)
    new_first_request = service.score(report.report_id, str(uuid.uuid4()))

    assert retried.reused is True
    assert retried.attempt.attempt_id == first.attempt.attempt_id
    assert new_first_request.reused is True
    assert model.calls == 1


def test_v1_result_remains_in_history_but_is_not_current_or_reused(tmp_path, valid_score_dict):
    service, report, model = make_service(tmp_path, valid_score_dict)
    old_request_id = str(uuid.uuid4())
    old_response = service.score(report.report_id, old_request_id)
    attempt_dir = (
        service.score_repository.attempts_root / report.report_id / old_response.attempt.attempt_id
    )
    attempt_payload = json.loads((attempt_dir / "attempt.json").read_text(encoding="utf-8"))
    attempt_payload.pop("scoring_contract_version")
    (attempt_dir / "attempt.json").write_text(
        json.dumps(attempt_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    result_payload = json.loads((attempt_dir / "result.json").read_text(encoding="utf-8"))
    result_payload.pop("scoring_contract_version")
    result_payload.pop("scoring_context_sha256")
    result_payload["scoring_agent_version"] = "report-scoring-agent-v1"
    result_payload["prompt_version"] = "report-scoring-v3.0-1"
    for finding in result_payload["score"]["negative_findings"]["correct_findings"]:
        finding.pop("behavior_id")
    (attempt_dir / "result.json").write_text(
        json.dumps(result_payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    reloaded_scores = ScoreRepository(tmp_path / "runtime")
    reloaded = ScoringService(
        service.case_registry,
        service.report_repository,
        reloaded_scores,
        model,
    )

    history = reloaded_scores.history(report.report_id)
    assert len(history) == 1
    assert history[0].result.score_id == old_response.result.score_id
    assert history[0].result.score.negative_findings.correct_findings[0].behavior_id is None
    assert reloaded.latest_current_success(report.report_id) is None
    assert reloaded.latest_current_attempt(report.report_id) is None
    comparison = reloaded.comparison("SIM-204")
    attack = next(
        item for item in comparison["agents"] if item["agent_id"] == "attack_attribution_agent"
    )
    assert attack["successfully_scored_report_count"] == 0
    assert attack["average_total"] is None

    with pytest.raises(ReportScoringError) as exc_info:
        reloaded.score(report.report_id, old_request_id)
    assert exc_info.value.code == "SCORING_RESULT_OUTDATED"

    current = reloaded.score(report.report_id, str(uuid.uuid4()))
    assert current.reused is False
    assert current.result.scoring_contract_version == "report-scoring-contract-v3"
    assert model.calls == 2
    assert len(reloaded_scores.history(report.report_id)) == 2
    assert reloaded.latest_current_success(report.report_id).score_id == current.result.score_id


def test_rescore_keeps_success_history_and_later_failure_does_not_hide_it(
    tmp_path, valid_score_dict
):
    service, report, model = make_service(tmp_path, valid_score_dict)
    first = service.score(report.report_id, str(uuid.uuid4()))
    model.responses = ["not json"]
    model.calls = 0

    with pytest.raises(ReportScoringError) as exc_info:
        service.score(report.report_id, str(uuid.uuid4()), rescore=True)

    assert exc_info.value.code == "SCORING_OUTPUT_INVALID"
    history = service.score_repository.history(report.report_id)
    assert [item.attempt.status for item in history] == ["succeeded", "failed"]
    assert (
        service.score_repository.latest_success(report.report_id).score_id == first.result.score_id
    )
    assert not any(
        (
            service.score_repository.attempts_root
            / report.report_id
            / item.attempt.attempt_id
            / "result.json"
        ).exists()
        for item in history
        if item.attempt.status == "failed"
    )


def test_failed_request_retry_does_not_call_model_again(tmp_path, valid_score_dict):
    service, report, model = make_service(tmp_path, valid_score_dict)
    model.responses = ["invalid"]
    request_id = str(uuid.uuid4())

    with pytest.raises(ReportScoringError):
        service.score(report.report_id, request_id)
    calls_after_failure = model.calls
    with pytest.raises(ReportScoringError):
        service.score(report.report_id, request_id)

    assert model.calls == calls_after_failure == 3


def test_duplicate_negative_behavior_never_creates_result(tmp_path, valid_score_dict):
    duplicate = copy.deepcopy(valid_score_dict)
    duplicate["negative_findings"]["correct_findings"].append(
        copy.deepcopy(duplicate["negative_findings"]["correct_findings"][0])
    )
    service, report, model = make_service(tmp_path, duplicate)

    with pytest.raises(ReportScoringError) as exc_info:
        service.score(report.report_id, str(uuid.uuid4()))

    assert exc_info.value.code == "SCORING_OUTPUT_INVALID"
    assert model.calls == 3
    history = service.score_repository.history(report.report_id)
    assert len(history) == 1
    attempt_dir = (
        service.score_repository.attempts_root / report.report_id / history[0].attempt.attempt_id
    )
    assert history[0].attempt.status == "failed"
    assert not (attempt_dir / "result.json").exists()


def test_running_attempt_is_marked_interrupted_on_restart(tmp_path, valid_score_dict):
    service, report, _ = make_service(tmp_path, valid_score_dict)
    attempt = service.score_repository.create_attempt(
        report_id=report.report_id,
        test_case_id=report.test_case_id,
        agent_id=report.agent_id,
        request_id=str(uuid.uuid4()),
        operation="score",
    )

    reloaded = ScoreRepository(tmp_path / "runtime")

    recovered = reloaded.get_attempt(attempt.attempt_id)
    assert recovered.status == "failed"
    assert recovered.error_code == "SCORING_INTERRUPTED"


def test_score_repository_rejects_reparse_report_directory(tmp_path, monkeypatch):
    from service.report_scoring import score_repository as score_repository_module

    runtime = tmp_path / "runtime"
    unsafe = runtime / "scoring_attempts" / ("rpt_" + "f" * 32)
    unsafe.mkdir(parents=True)
    original_check = score_repository_module.is_reparse_point
    monkeypatch.setattr(
        score_repository_module,
        "is_reparse_point",
        lambda path: Path(path) == unsafe or original_check(Path(path)),
    )

    with pytest.raises(ReportScoringError) as exc_info:
        ScoreRepository(runtime)

    assert exc_info.value.code == "INVALID_SCORING_RECORD"
    assert "reparse point" in exc_info.value.message


def test_same_running_request_returns_in_progress(tmp_path, valid_score_dict):
    service, report, _ = make_service(tmp_path, valid_score_dict)
    request_id = str(uuid.uuid4())
    attempt = service.score_repository.create_attempt(
        report_id=report.report_id,
        test_case_id=report.test_case_id,
        agent_id=report.agent_id,
        request_id=request_id,
        operation="score",
    )

    with pytest.raises(ReportScoringError) as exc_info:
        service.score(report.report_id, request_id)

    assert exc_info.value.code == "SCORING_IN_PROGRESS"
    assert exc_info.value.details == {"attempt_id": attempt.attempt_id}


def test_same_report_rejects_concurrent_scoring(tmp_path, valid_score_dict):
    service, report, model = make_service(tmp_path, valid_score_dict)
    model.started = threading.Event()
    model.release = threading.Event()
    errors = []

    def first_score():
        try:
            service.score(report.report_id, str(uuid.uuid4()))
        except Exception as exc:  # pragma: no cover - assertion below exposes unexpected failures
            errors.append(exc)

    worker = threading.Thread(target=first_score)
    worker.start()
    assert model.started.wait(timeout=5)

    with pytest.raises(ReportScoringError) as exc_info:
        service.score(report.report_id, str(uuid.uuid4()), rescore=True)

    assert exc_info.value.code == "SCORING_IN_PROGRESS"
    model.release.set()
    worker.join(timeout=5)
    assert not errors


def test_different_reports_can_score_while_first_report_is_running(tmp_path, valid_score_dict):
    service, first_report, _ = make_service(tmp_path, valid_score_dict)
    second_report = service.report_repository.create_report(
        content=b"report two",
        filename="two.md",
        test_case_id="SIM-204",
        agent_id="baseline_agent_simple",
        source_type="upload",
    )
    first_started = threading.Event()
    release_first = threading.Event()
    call_lock = threading.Lock()
    call_count = 0

    class FirstCallBlockingGraph:
        def invoke(self, _state):
            nonlocal call_count
            with call_lock:
                call_count += 1
                call_number = call_count
            if call_number == 1:
                first_started.set()
                assert release_first.wait(timeout=5)
            return {
                "status": "succeeded",
                "candidate": valid_score_dict,
                "total_score": 100,
            }

    service.graph = FirstCallBlockingGraph()
    errors = []

    def first_score():
        try:
            service.score(first_report.report_id, str(uuid.uuid4()))
        except Exception as exc:  # pragma: no cover - assertion below exposes failures
            errors.append(exc)

    worker = threading.Thread(target=first_score)
    worker.start()
    assert first_started.wait(timeout=5)

    second = service.score(second_report.report_id, str(uuid.uuid4()))

    assert second.result.total_score == 100
    release_first.set()
    worker.join(timeout=5)
    assert not errors


def test_score_result_does_not_persist_secret_configuration(tmp_path, valid_score_dict):
    service, report, _ = make_service(tmp_path, valid_score_dict)

    response = service.score(report.report_id, str(uuid.uuid4()))
    result_path = (
        service.score_repository.attempts_root
        / report.report_id
        / response.attempt.attempt_id
        / "result.json"
    )
    serialized = result_path.read_text(encoding="utf-8").lower()

    assert "api_key" not in serialized
    assert "base_url" not in serialized
