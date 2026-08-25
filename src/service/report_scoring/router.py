from typing import Annotated, Literal

from fastapi import APIRouter, File, Form, Query, UploadFile
from starlette.concurrency import run_in_threadpool

from .api_models import (
    ComparisonResponse,
    ReportListItem,
    ReportListResponse,
    ReportRecord,
    ReportSource,
    ScoreHistoryItem,
    ScoreInvocationResponse,
    ScoreRequest,
    ScoreResult,
    StudioImportRequest,
)
from .case_registry import CaseRegistry
from .errors import ReportScoringError
from .report_repository import MAX_REPORT_BYTES, ReportRepository
from .scoring_service import ScoringService


def create_report_scoring_router(
    case_registry: CaseRegistry,
    report_repository: ReportRepository,
    scoring_service: ScoringService | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/api/report-scoring", tags=["report-scoring"])

    def enrich_report(record: ReportRecord) -> ReportListItem:
        if scoring_service is None:
            return ReportListItem.model_validate(record.model_dump())
        latest_attempt = scoring_service.latest_current_attempt(record.report_id)
        latest_result = scoring_service.latest_current_success(record.report_id)
        return ReportListItem(
            **record.model_dump(),
            latest_attempt_status=(latest_attempt.status if latest_attempt else "not_scored"),
            latest_attempt_id=latest_attempt.attempt_id if latest_attempt else None,
            latest_score_id=latest_result.score_id if latest_result else None,
            latest_total_score=latest_result.total_score if latest_result else None,
        )

    @router.get("/test-cases")
    def list_test_cases():
        return case_registry.list_cases()

    @router.get("/agents")
    def list_agents():
        return case_registry.list_agents()

    @router.post("/reports/upload", response_model=ReportRecord, status_code=201)
    async def upload_report(
        file: Annotated[UploadFile, File()],
        test_case_id: Annotated[str, Form()],
        agent_id: Annotated[str, Form()],
        thread_id: Annotated[str | None, Form()] = None,
        run_id: Annotated[str | None, Form()] = None,
        note: Annotated[str | None, Form()] = None,
    ):
        content = await file.read(MAX_REPORT_BYTES + 1)
        return report_repository.create_report(
            content=content,
            filename=file.filename or "report.md",
            test_case_id=test_case_id,
            agent_id=agent_id,
            source_type="upload",
            thread_id=thread_id,
            run_id=run_id,
            note=note,
        )

    @router.post("/reports/studio-import", response_model=ReportRecord, status_code=201)
    def import_studio_report(request: StudioImportRequest):
        return report_repository.import_studio_report(**request.model_dump())

    @router.get("/reports", response_model=ReportListResponse)
    def list_reports(
        test_case_id: str | None = None,
        agent_id: str | None = None,
        source_type: ReportSource | None = None,
        scoring_status: Literal["not_scored", "running", "succeeded", "failed"] | None = None,
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ):
        records, _ = report_repository.list_reports(
            test_case_id=test_case_id,
            agent_id=agent_id,
            source_type=source_type,
            limit=1_000_000,
        )
        items = [enrich_report(record) for record in records]
        if scoring_status is not None:
            items = [item for item in items if item.latest_attempt_status == scoring_status]
        total = len(items)
        items = items[offset : offset + limit]
        return ReportListResponse(items=items, total=total, offset=offset, limit=limit)

    @router.get("/reports/{report_id}", response_model=ReportListItem)
    def get_report(report_id: str):
        return enrich_report(report_repository.get_report(report_id))

    if scoring_service is not None:

        @router.post(
            "/reports/{report_id}/score",
            response_model=ScoreInvocationResponse,
        )
        async def score_report(report_id: str, request: ScoreRequest):
            return await run_in_threadpool(
                scoring_service.score, report_id, str(request.request_id), rescore=False
            )

        @router.post(
            "/reports/{report_id}/rescore",
            response_model=ScoreInvocationResponse,
        )
        async def rescore_report(report_id: str, request: ScoreRequest):
            return await run_in_threadpool(
                scoring_service.score, report_id, str(request.request_id), rescore=True
            )

        @router.get(
            "/reports/{report_id}/scores",
            response_model=list[ScoreHistoryItem],
        )
        def score_history(report_id: str):
            scoring_service.report_repository.get_report(report_id)
            return scoring_service.score_repository.history(report_id)

        @router.get(
            "/reports/{report_id}/scores/latest",
            response_model=ScoreResult,
        )
        def latest_score(report_id: str):
            scoring_service.report_repository.get_report(report_id)
            result = scoring_service.latest_current_success(report_id)
            if result is None:
                raise ReportScoringError(
                    "SCORING_ATTEMPT_NOT_FOUND", "报告没有成功评分", status_code=404
                )
            return result

        @router.get("/scores/{score_id}", response_model=ScoreResult)
        def get_score(score_id: str):
            return scoring_service.score_repository.get_score(score_id)

        @router.get("/comparisons", response_model=ComparisonResponse)
        def comparison(test_case_id: str, standard_version: str = "v3.0"):
            return scoring_service.comparison(test_case_id, standard_version)

    return router


def create_unavailable_report_scoring_router() -> APIRouter:
    """Expose a stable 503 contract when the optional scoring subsystem cannot start."""

    router = APIRouter(prefix="/api/report-scoring", tags=["report-scoring"])

    @router.api_route("", methods=["GET", "POST"])
    @router.api_route("/{path:path}", methods=["GET", "POST"])
    def unavailable_report_scoring(path: str = ""):
        raise ReportScoringError(
            "SCORING_UNAVAILABLE",
            "报告评分服务当前不可用，核心聊天和报告保存仍可使用",
            status_code=503,
        )

    return router
