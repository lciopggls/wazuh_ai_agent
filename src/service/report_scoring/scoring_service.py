import logging
import threading
import uuid
from datetime import UTC, datetime

from agents.report_scoring.dimensions import SCORING_DIMENSION_FIELDS
from agents.report_scoring.graph import get_report_scoring_graph
from agents.report_scoring.prompt import (
    PROMPT_VERSION,
    SCORING_AGENT_VERSION,
    SCORING_CONTRACT_VERSION,
)
from agents.report_scoring.validation import ScoreValidationError, validate_score_candidate

from .api_models import ScoreInvocationResponse, ScoreResult
from .case_registry import CaseRegistry
from .context_loader import ScoringContextLoader
from .errors import ReportScoringError
from .report_repository import ReportRepository
from .score_repository import ScoreRepository

logger = logging.getLogger(__name__)


class ScoringService:
    def __init__(
        self,
        case_registry: CaseRegistry,
        report_repository: ReportRepository,
        score_repository: ScoreRepository,
        model,
    ) -> None:
        self.case_registry = case_registry
        self.report_repository = report_repository
        self.score_repository = score_repository
        self.model = model
        self.context_loader = ScoringContextLoader(case_registry, report_repository)
        self.graph = get_report_scoring_graph(model, self.context_loader)
        self._locks_guard = threading.Lock()
        self._report_locks: dict[str, threading.Lock] = {}

    def _lock_for(self, report_id: str) -> threading.Lock:
        with self._locks_guard:
            return self._report_locks.setdefault(report_id, threading.Lock())

    def _model_name(self) -> str:
        return str(
            getattr(self.model, "model_name", None)
            or getattr(self.model, "model", None)
            or getattr(self.model, "_llm_type", "unknown")
        )

    @staticmethod
    def _is_current_result(result: ScoreResult, report, case) -> bool:
        if not (
            result.scoring_contract_version == SCORING_CONTRACT_VERSION
            and result.scoring_agent_version == SCORING_AGENT_VERSION
            and result.prompt_version == PROMPT_VERSION
            and result.report_id == report.report_id
            and result.test_case_id == report.test_case_id
            and result.agent_id == report.agent_id
            and result.report_sha256.lower() == report.report_sha256.lower()
            and result.input_sha256.lower() == case.manifest.input_sha256.lower()
            and result.standard_sha256.lower() == case.manifest.standard_sha256.lower()
            and result.scoring_context_sha256 == case.scoring_context_sha256
            and result.scoring_standard_version == case.manifest.scoring_standard_version
        ):
            return False
        try:
            validated = validate_score_candidate(
                result.score,
                negative_behavior_catalog=case.negative_behavior_catalog,
            )
        except ScoreValidationError:
            return False
        return abs(validated.total_score - result.total_score) < 1e-8

    def _latest_current_success(self, report, case) -> ScoreResult | None:
        results = [
            item.result
            for item in self.score_repository.history(report.report_id)
            if item.result is not None and self._is_current_result(item.result, report, case)
        ]
        if not results:
            return None
        return max(results, key=lambda result: (result.completed_at, result.score_id))

    def latest_current_success(self, report_id: str) -> ScoreResult | None:
        report = self.report_repository.get_report(report_id)
        case = self.case_registry.get_case(report.test_case_id)
        return self._latest_current_success(report, case)

    def latest_current_attempt(self, report_id: str):
        report = self.report_repository.get_report(report_id)
        case = self.case_registry.get_case(report.test_case_id)
        attempts = []
        for item in self.score_repository.history(report_id):
            if item.attempt.scoring_contract_version != SCORING_CONTRACT_VERSION:
                continue
            if item.attempt.status == "succeeded" and (
                item.result is None or not self._is_current_result(item.result, report, case)
            ):
                continue
            attempts.append(item.attempt)
        if not attempts:
            return None
        return max(attempts, key=lambda attempt: (attempt.started_at, attempt.attempt_id))

    def _existing_response(self, history, report, case) -> ScoreInvocationResponse:
        if history.result is None:
            if history.attempt.status == "running":
                raise ReportScoringError(
                    "SCORING_IN_PROGRESS",
                    "该评分请求正在进行",
                    status_code=409,
                    details={"attempt_id": history.attempt.attempt_id},
                )
            raise ReportScoringError(
                history.attempt.error_code or "SCORING_OUTPUT_INVALID",
                history.attempt.error_message or "评分尝试失败",
                status_code=502,
                details={"attempt_id": history.attempt.attempt_id},
            )
        if not self._is_current_result(history.result, report, case):
            raise ReportScoringError(
                "SCORING_RESULT_OUTDATED",
                "该 request_id 对应旧评分合同结果，请使用新的 request_id 重新评分",
                status_code=409,
                details={"attempt_id": history.attempt.attempt_id},
            )
        return ScoreInvocationResponse(attempt=history.attempt, result=history.result, reused=True)

    def score(self, report_id: str, request_id: str, *, rescore: bool = False):
        report = self.report_repository.get_report(report_id)
        case = self.case_registry.get_case(report.test_case_id)
        request_id = str(request_id)
        existing_request = self.score_repository.find_by_request(report_id, request_id)
        if existing_request is not None:
            return self._existing_response(existing_request, report, case)

        if not rescore:
            existing_result = self._latest_current_success(report, case)
            if existing_result is not None:
                attempt = self.score_repository.get_attempt(existing_result.attempt_id)
                return ScoreInvocationResponse(attempt=attempt, result=existing_result, reused=True)

        report_lock = self._lock_for(report_id)
        if not report_lock.acquire(blocking=False):
            raise ReportScoringError(
                "SCORING_IN_PROGRESS", "该报告已有评分正在进行", status_code=409
            )
        try:
            existing_request = self.score_repository.find_by_request(report_id, request_id)
            if existing_request is not None:
                return self._existing_response(existing_request, report, case)
            if not rescore:
                existing_result = self._latest_current_success(report, case)
                if existing_result is not None:
                    attempt = self.score_repository.get_attempt(existing_result.attempt_id)
                    return ScoreInvocationResponse(
                        attempt=attempt, result=existing_result, reused=True
                    )

            attempt = self.score_repository.create_attempt(
                report_id=report.report_id,
                test_case_id=report.test_case_id,
                agent_id=report.agent_id,
                request_id=request_id,
                operation="rescore" if rescore else "score",
                scoring_contract_version=SCORING_CONTRACT_VERSION,
            )
            state = {
                "input_mode": "internal",
                "report_id": report.report_id,
                "attempt_id": attempt.attempt_id,
            }
            try:
                final_state = self.graph.invoke(state)
            except Exception as exc:
                logger.exception(
                    "Scoring graph invocation failed",
                    extra={
                        "attempt_id": attempt.attempt_id,
                        "report_id": report.report_id,
                        "request_id": request_id,
                        "error_type": type(exc).__name__,
                    },
                )
                safe_message = "评分模型调用失败"
                self.score_repository.complete_failure(
                    attempt.attempt_id, "SCORING_MODEL_ERROR", safe_message
                )
                raise ReportScoringError(
                    "SCORING_MODEL_ERROR",
                    safe_message,
                    status_code=502,
                    details={"attempt_id": attempt.attempt_id},
                ) from None

            if final_state.get("status") != "succeeded":
                safe_message = str(final_state.get("final_error") or "评分候选输出无效")[:1000]
                self.score_repository.complete_failure(
                    attempt.attempt_id, "SCORING_OUTPUT_INVALID", safe_message
                )
                raise ReportScoringError(
                    "SCORING_OUTPUT_INVALID",
                    safe_message,
                    status_code=502,
                    details={"attempt_id": attempt.attempt_id},
                )

            result = ScoreResult(
                score_id=f"scr_{uuid.uuid4().hex}",
                attempt_id=attempt.attempt_id,
                report_id=report.report_id,
                test_case_id=report.test_case_id,
                agent_id=report.agent_id,
                report_sha256=report.report_sha256,
                input_sha256=report.input_sha256,
                standard_sha256=case.manifest.standard_sha256.lower(),
                scoring_context_sha256=case.scoring_context_sha256,
                scoring_standard_version=case.manifest.scoring_standard_version,
                model_name=self._model_name(),
                scoring_agent_version=SCORING_AGENT_VERSION,
                prompt_version=PROMPT_VERSION,
                scoring_contract_version=SCORING_CONTRACT_VERSION,
                completed_at=datetime.now(UTC),
                total_score=final_state["total_score"],
                score=final_state["candidate"],
            )
            completed_attempt = self.score_repository.complete_success(attempt.attempt_id, result)
            return ScoreInvocationResponse(attempt=completed_attempt, result=result, reused=False)
        finally:
            report_lock.release()

    def comparison(self, test_case_id: str, standard_version: str = "v3.0") -> dict:
        self.case_registry.get_case(test_case_id)
        if standard_version != "v3.0":
            raise ReportScoringError(
                "INVALID_SCORING_STANDARD", "第一版只支持 v3.0", field="standard_version"
            )
        reports, _ = self.report_repository.list_reports(test_case_id=test_case_id, limit=1_000_000)
        agents = []
        for agent in self.case_registry.list_agents():
            agent_reports = [report for report in reports if report.agent_id == agent.agent_id]
            latest = [
                result
                for report in agent_reports
                if (result := self.latest_current_success(report.report_id)) is not None
                and result.scoring_standard_version == standard_version
            ]
            totals = [result.total_score for result in latest]
            dimension_averages = {
                dimension: (
                    round(
                        sum(getattr(result.score, dimension).score for result in latest)
                        / len(latest),
                        1,
                    )
                    if latest
                    else None
                )
                for dimension in SCORING_DIMENSION_FIELDS
            }
            agents.append(
                {
                    "agent_id": agent.agent_id,
                    "display_name": agent.display_name,
                    "registered_report_count": len(agent_reports),
                    "successfully_scored_report_count": len(latest),
                    "report_scores": [
                        {
                            "report_id": result.report_id,
                            "score_id": result.score_id,
                            "total_score": result.total_score,
                        }
                        for result in latest
                    ],
                    "average_total": round(sum(totals) / len(totals), 1) if totals else None,
                    "minimum_total": min(totals) if totals else None,
                    "maximum_total": max(totals) if totals else None,
                    "dimension_averages": dimension_averages,
                }
            )
        return {
            "test_case_id": test_case_id,
            "scoring_standard_version": standard_version,
            "agents": agents,
        }
