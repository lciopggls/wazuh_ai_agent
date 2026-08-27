import importlib
import json
import logging
import uuid
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.errors import ReportScoringError
from service.report_scoring.report_repository import ReportRepository
from service.report_scoring.router import create_report_scoring_router
from service.report_scoring.score_repository import ScoreRepository
from service.report_scoring.scoring_service import ScoringService

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


class ApiScoringModel(BaseChatModel):
    response: str
    calls: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls += 1
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.response))])

    @property
    def _llm_type(self):
        return "api-scoring-model"


class FailingApiScoringModel(BaseChatModel):
    calls: int = 0

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        self.calls += 1
        raise RuntimeError("provider unavailable")

    @property
    def _llm_type(self):
        return "failing-api-scoring-model"


def make_client(tmp_path):
    registry = CaseRegistry(PROJECT_CATALOG)
    repository = ReportRepository(tmp_path / "runtime", registry)
    app = FastAPI()

    @app.exception_handler(ReportScoringError)
    async def handle_error(_request, exc):
        return JSONResponse(status_code=exc.status_code, content=exc.as_dict())

    app.include_router(create_report_scoring_router(registry, repository))
    return TestClient(app), repository


def make_scoring_client(tmp_path, candidate):
    registry = CaseRegistry(PROJECT_CATALOG)
    repository = ReportRepository(tmp_path / "runtime", registry)
    score_repository = ScoreRepository(tmp_path / "runtime")
    model = ApiScoringModel(response=json.dumps(candidate, ensure_ascii=False))
    service = ScoringService(registry, repository, score_repository, model)
    app = FastAPI()

    @app.exception_handler(ReportScoringError)
    async def handle_error(_request, exc):
        return JSONResponse(status_code=exc.status_code, content=exc.as_dict())

    app.include_router(create_report_scoring_router(registry, repository, service))
    return TestClient(app), repository, model


def test_catalog_endpoints_do_not_expose_scoring_material(tmp_path):
    client, _ = make_client(tmp_path)

    response = client.get("/api/report-scoring/test-cases")

    assert response.status_code == 200
    case_ids = {item["test_case_id"] for item in response.json()}
    assert {"SIM-204", "SIM-205", "SIM-206"} <= case_ids
    serialized = response.text.lower()
    assert "ground_truth" not in serialized
    assert "telemetry" not in serialized
    assert "expected_report" not in serialized


def test_upload_and_list_report(tmp_path):
    client, _ = make_client(tmp_path)

    response = client.post(
        "/api/report-scoring/reports/upload",
        files={"file": ("low-quality.md", "没有任何安全字段", "text/markdown")},
        data={"test_case_id": "SIM-204", "agent_id": "baseline_agent_simple"},
    )

    assert response.status_code == 201
    report_id = response.json()["report_id"]
    listed = client.get("/api/report-scoring/reports", params={"test_case_id": "SIM-204"})
    assert listed.status_code == 200
    assert listed.json()["items"][0]["report_id"] == report_id


def test_upload_returns_structured_duplicate_error(tmp_path):
    client, _ = make_client(tmp_path)
    request = {
        "files": {"file": ("report.md", "same", "text/markdown")},
        "data": {"test_case_id": "SIM-204", "agent_id": "baseline_agent_simple"},
    }
    assert client.post("/api/report-scoring/reports/upload", **request).status_code == 201

    response = client.post("/api/report-scoring/reports/upload", **request)

    assert response.status_code == 409
    assert response.json()["code"] == "DUPLICATE_REPORT"


def test_invalid_multipart_audit_field_returns_422_without_orphan(tmp_path):
    client, repository = make_client(tmp_path)
    before = {path.name for path in repository.reports_root.iterdir()}

    response = client.post(
        "/api/report-scoring/reports/upload",
        files={"file": ("report.md", "valid body", "text/markdown")},
        data={
            "test_case_id": "SIM-204",
            "agent_id": "baseline_agent_simple",
            "note": "n" * 1001,
        },
    )

    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_REPORT_REGISTRATION"
    assert {path.name for path in repository.reports_root.iterdir()} == before
    assert client.get("/api/report-scoring/reports").json()["total"] == 0

    legal = client.post(
        "/api/report-scoring/reports/upload",
        files={"file": ("report.md", "valid body", "text/markdown")},
        data={"test_case_id": "SIM-204", "agent_id": "baseline_agent_simple"},
    )
    assert legal.status_code == 201


def test_removed_studio_import_route_is_not_exposed(tmp_path):
    client, _ = make_client(tmp_path)

    response = client.post(
        "/api/report-scoring/reports/studio-import",
        json={
            "relative_path": "studio.md",
            "test_case_id": "SIM-204",
            "agent_id": "attack_attribution_agent",
        },
    )

    assert response.status_code == 405


def test_existing_save_report_response_is_unchanged_without_registration(tmp_path, monkeypatch):
    from service import memory

    monkeypatch.setattr(memory, "REPORT_OUTPUT_DIR", str(tmp_path / "knowledge"))
    response = TestClient(memory.app).post(
        "/api/report/save", json={"content": "legacy", "filename": "legacy"}
    )

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "filepath": str(tmp_path / "knowledge" / "legacy.md"),
        "filename": "legacy.md",
        "message": "报告已保存: legacy.md",
    }


def test_local_save_is_idempotent_and_never_overwrites_different_content(tmp_path, monkeypatch):
    from service import memory

    output_dir = tmp_path / "knowledge"
    monkeypatch.setattr(memory, "REPORT_OUTPUT_DIR", str(output_dir))
    client = TestClient(memory.app)

    first = client.post(
        "/api/report/save", json={"content": "first", "filename": "fixed.md"}
    ).json()
    repeated = client.post(
        "/api/report/save", json={"content": "first", "filename": "fixed.md"}
    ).json()
    second = client.post(
        "/api/report/save", json={"content": "second", "filename": "fixed.md"}
    ).json()

    assert first["filepath"] == repeated["filepath"]
    assert second["filename"] == "fixed-2.md"
    assert (output_dir / "fixed.md").read_text(encoding="utf-8") == "first"
    assert (output_dir / "fixed-2.md").read_text(encoding="utf-8") == "second"


@pytest.mark.parametrize(
    ("content", "expected_code"),
    [("  \n", "EMPTY_REPORT"), ("x" * (1024 * 1024 + 1), "FILE_TOO_LARGE")],
    ids=["blank", "oversized"],
)
def test_local_save_rejects_invalid_report_content(tmp_path, monkeypatch, content, expected_code):
    from service import memory

    output_dir = tmp_path / "knowledge"
    monkeypatch.setattr(memory, "REPORT_OUTPUT_DIR", str(output_dir))

    response = TestClient(memory.app).post(
        "/api/report/save", json={"content": content, "filename": "invalid.md"}
    )

    assert response.status_code == 200
    assert response.json()["status"] == "error"
    assert response.json()["code"] == expected_code
    assert not output_dir.exists() or not any(output_dir.iterdir())


def test_production_save_registers_report_against_prepared_case(tmp_path, monkeypatch):
    from service import memory

    registry = CaseRegistry(PROJECT_CATALOG)
    repository = ReportRepository(tmp_path / "runtime", registry)
    monkeypatch.setattr(memory, "REPORT_OUTPUT_DIR", str(tmp_path / "knowledge"))
    monkeypatch.setattr(memory, "report_repository", repository)

    response = TestClient(memory.app).post(
        "/api/report/save",
        json={
            "content": "report for a prepared local case",
            "filename": "prepared-case-report",
            "scoring_registration": {
                "test_case_id": "SIM-204",
                "agent_id": "attack_attribution_agent",
                "thread_id": "thread-204",
            },
        },
    )

    assert response.status_code == 200
    registration = response.json()["scoring_registration"]
    assert registration["status"] == "ok"
    report = repository.get_report(registration["report"]["report_id"])
    assert report.test_case_id == "SIM-204"
    assert report.agent_id == "attack_attribution_agent"
    assert report.thread_id == "thread-204"


@pytest.mark.parametrize(
    ("registration", "expected_code"),
    [
        ({}, "INVALID_REPORT_REGISTRATION"),
        ("not-an-object", "INVALID_REPORT_REGISTRATION"),
        (
            {
                "test_case_id": "SIM-204",
                "agent_id": "attack_attribution_agent",
                "note": "n" * 1001,
            },
            "INVALID_REPORT_REGISTRATION",
        ),
        (
            {"test_case_id": "SIM-999", "agent_id": "attack_attribution_agent"},
            "INVALID_TEST_CASE",
        ),
        (
            {"test_case_id": "SIM-204", "agent_id": "unknown_agent"},
            "INVALID_AGENT",
        ),
    ],
)
def test_invalid_optional_scoring_registration_does_not_block_core_save(
    tmp_path, monkeypatch, registration, expected_code
):
    from service import memory

    registry = CaseRegistry(PROJECT_CATALOG)
    repository = ReportRepository(tmp_path / "runtime", registry)
    output_dir = tmp_path / "knowledge"
    monkeypatch.setattr(memory, "REPORT_OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(memory, "report_repository", repository)

    response = TestClient(memory.app).post(
        "/api/report/save",
        json={
            "content": "core report survives optional registration failure",
            "filename": "partial-success",
            "scoring_registration": registration,
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert Path(payload["filepath"]).is_file()
    assert payload["scoring_registration"]["status"] == "error"
    assert payload["scoring_registration"]["error"]["code"] == expected_code
    assert "原报告已" in payload["scoring_registration"]["error"]["message"]
    assert (output_dir / "partial-success.md").read_text(encoding="utf-8") == (
        "core report survives optional registration failure"
    )
    assert repository.list_reports(limit=10)[1] == 0


def test_unavailable_scoring_registration_does_not_block_core_save(tmp_path, monkeypatch):
    from service import memory

    output_dir = tmp_path / "knowledge"
    monkeypatch.setattr(memory, "REPORT_OUTPUT_DIR", str(output_dir))
    monkeypatch.setattr(memory, "report_repository", None)

    response = TestClient(memory.app).post(
        "/api/report/save",
        json={
            "content": "core report",
            "filename": "scoring-unavailable",
            "scoring_registration": {
                "test_case_id": "SIM-204",
                "agent_id": "attack_attribution_agent",
            },
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["scoring_registration"]["status"] == "error"
    assert payload["scoring_registration"]["error"]["code"] == "SCORING_UNAVAILABLE"
    assert "报告已" in payload["scoring_registration"]["error"]["message"]
    assert (output_dir / "scoring-unavailable.md").is_file()


def test_scoring_startup_failure_does_not_block_core_save(tmp_path, monkeypatch):
    from service import memory
    from service.report_scoring import bootstrap

    class BrokenCaseRegistry:
        def __init__(self, _catalog_root):
            raise ReportScoringError("INVALID_TEST_CASE", "broken catalog", status_code=500)

    with monkeypatch.context() as context:
        context.setattr(bootstrap, "CaseRegistry", BrokenCaseRegistry)
        isolated_memory = importlib.reload(memory)
        context.setattr(isolated_memory, "REPORT_OUTPUT_DIR", str(tmp_path / "knowledge"))
        client = TestClient(isolated_memory.app)

        saved = client.post("/api/report/save", json={"content": "legacy", "filename": "isolated"})
        unavailable = client.get("/api/report-scoring/test-cases")

        assert saved.status_code == 200
        assert saved.json()["status"] == "ok"
        assert unavailable.status_code == 503
        assert unavailable.json()["code"] == "SCORING_UNAVAILABLE"

    importlib.reload(memory)


def test_score_history_and_comparison_gets_do_not_call_model(tmp_path, valid_score_dict):
    client, repository, model = make_scoring_client(tmp_path, valid_score_dict)
    report = repository.create_report(
        content=b"api report",
        filename="api.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )
    score_response = client.post(
        f"/api/report-scoring/reports/{report.report_id}/score",
        json={"request_id": str(uuid.uuid4())},
    )

    assert score_response.status_code == 200
    assert score_response.json()["result"]["total_score"] == 100
    scored_reports = client.get(
        "/api/report-scoring/reports", params={"scoring_status": "succeeded"}
    )
    assert scored_reports.status_code == 200
    assert scored_reports.json()["total"] == 1
    assert scored_reports.json()["items"][0]["latest_total_score"] == 100
    assert (
        client.get("/api/report-scoring/reports", params={"scoring_status": "not_scored"}).json()[
            "total"
        ]
        == 0
    )
    calls_after_score = model.calls
    assert client.get(f"/api/report-scoring/reports/{report.report_id}/scores").status_code == 200
    assert (
        client.get(f"/api/report-scoring/reports/{report.report_id}/scores/latest").status_code
        == 200
    )
    assert (
        client.get(
            "/api/report-scoring/comparisons", params={"test_case_id": "SIM-204"}
        ).status_code
        == 200
    )
    assert model.calls == calls_after_score == 1


def test_invalid_model_output_returns_failure_without_fake_score(tmp_path, valid_score_dict):
    client, repository, model = make_scoring_client(tmp_path, valid_score_dict)
    model.response = "not json"
    report = repository.create_report(
        content=b"bad output target",
        filename="bad.md",
        test_case_id="SIM-204",
        agent_id="attack_attribution_agent",
        source_type="upload",
    )

    response = client.post(
        f"/api/report-scoring/reports/{report.report_id}/score",
        json={"request_id": str(uuid.uuid4())},
    )

    assert response.status_code == 502
    assert response.json()["code"] == "SCORING_OUTPUT_INVALID"
    assert "score" not in response.json()
    history = client.get(f"/api/report-scoring/reports/{report.report_id}/scores").json()
    assert history[0]["attempt"]["status"] == "failed"
    assert history[0]["result"] is None


def test_model_exception_is_logged_with_safe_attempt_context(tmp_path, caplog):
    registry = CaseRegistry(PROJECT_CATALOG)
    repository = ReportRepository(tmp_path / "runtime", registry)
    score_repository = ScoreRepository(tmp_path / "runtime")
    model = FailingApiScoringModel()
    service = ScoringService(registry, repository, score_repository, model)
    report = repository.create_report(
        content=b"provider failure target",
        filename="failure.md",
        test_case_id="SIM-204",
        agent_id="baseline_agent_plus",
        source_type="upload",
    )
    request_id = str(uuid.uuid4())

    with caplog.at_level(logging.ERROR, logger="service.report_scoring.scoring_service"):
        with pytest.raises(ReportScoringError) as raised:
            service.score(report.report_id, request_id)

    assert raised.value.code == "SCORING_MODEL_ERROR"
    history = score_repository.history(report.report_id)
    assert len(history) == 1
    assert history[0].attempt.status == "failed"
    record = caplog.records[-1]
    assert record.message == "Scoring graph invocation failed"
    assert record.attempt_id == history[0].attempt.attempt_id
    assert record.report_id == report.report_id
    assert record.request_id == request_id
    assert record.error_type == "RuntimeError"
