import json
from pathlib import Path

import pytest

from service.report_scoring.case_registry import CaseRegistry
from service.report_scoring.errors import ReportScoringError
from service.report_scoring.report_repository import MAX_REPORT_BYTES, ReportRepository

PROJECT_CATALOG = Path(__file__).parents[1] / "report_scoring_data" / "catalog"


@pytest.fixture
def repository(tmp_path):
    return ReportRepository(tmp_path / "runtime", CaseRegistry(PROJECT_CATALOG))


def create(repository, **overrides):
    values = {
        "content": "一份很差但有效的报告，没有 PID 或 MITRE。".encode(),
        "filename": "report.md",
        "test_case_id": "SIM-204",
        "agent_id": "attack_attribution_agent",
        "source_type": "upload",
    }
    values.update(overrides)
    return repository.create_report(**values)


def test_report_registration_persists_metadata_after_body(repository):
    record = create(repository, thread_id="thread-1", run_id="run-1")

    report_dir = repository.runtime_root / "reports" / record.report_id
    metadata = json.loads((report_dir / "metadata.json").read_text(encoding="utf-8"))

    assert repository.read_report(record.report_id).startswith("一份很差")
    assert metadata["report_id"] == record.report_id
    assert metadata["thread_id"] == "thread-1"
    assert record.stored_path == f"reports/{record.report_id}/report.md"


def test_original_filename_cannot_control_storage_path_and_blank_audit_fields_normalize(
    repository,
):
    record = create(
        repository,
        filename="../outside.md",
        thread_id="   ",
        run_id=" ",
        note="  ",
    )

    assert record.original_filename == "outside.md"
    assert record.thread_id is None
    assert record.run_id is None
    assert record.note is None
    assert (repository.runtime_root / record.stored_path).is_file()


def test_both_current_sources_share_report_record(repository):
    upload = create(repository, content=b"upload", filename="upload.txt")
    chat = create(
        repository,
        content=b"chat",
        filename="chat.md",
        source_type="ai_chat",
        agent_id="baseline_agent_simple",
    )
    assert {upload.source_type, chat.source_type} == {"upload", "ai_chat"}


def test_removed_source_cannot_be_used_for_new_registration(repository):
    with pytest.raises(ReportScoringError) as exc_info:
        create(repository, source_type="studio")

    assert exc_info.value.code == "INVALID_REPORT_REGISTRATION"


def test_removed_prototype_metadata_remains_readable(tmp_path):
    runtime = tmp_path / "runtime"
    registry = CaseRegistry(PROJECT_CATALOG)
    writer = ReportRepository(runtime, registry)
    report = create(writer)
    metadata_path = runtime / "reports" / report.report_id / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "schema_version": 2,
            "source_type": "local_import",
            "attack_run_id": "run-legacy",
            "anchor_sha256": "a" * 64,
            "confirmation_actor": "tester",
            "confirmed_at": "2026-08-26T00:00:00Z",
        }
    )
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    loaded = ReportRepository(runtime, registry).get_report(report.report_id)

    assert loaded.schema_version == 2
    assert loaded.source_type == "local_import"
    assert loaded.attack_run_id == "run-legacy"


def test_duplicate_hash_is_scoped_to_case_and_agent(repository):
    original = create(repository)

    with pytest.raises(ReportScoringError) as exc_info:
        create(repository)

    assert exc_info.value.code == "DUPLICATE_REPORT"
    assert exc_info.value.details == {"report_id": original.report_id}
    assert create(repository, agent_id="baseline_agent_simple").report_id != original.report_id


@pytest.mark.parametrize(
    ("overrides", "code"),
    [
        ({"content": b"\xff"}, "INVALID_UTF8"),
        ({"content": b" "}, "EMPTY_REPORT"),
        ({"content": b"x" * (MAX_REPORT_BYTES + 1)}, "FILE_TOO_LARGE"),
        ({"filename": "report.pdf"}, "INVALID_FILE_TYPE"),
        ({"test_case_id": "SIM-999"}, "INVALID_TEST_CASE"),
        ({"agent_id": "unknown_agent"}, "INVALID_AGENT"),
    ],
)
def test_report_validation(repository, overrides, code):
    with pytest.raises(ReportScoringError) as exc_info:
        create(repository, **overrides)

    assert exc_info.value.code == code


@pytest.mark.parametrize(
    "overrides",
    [
        {"thread_id": "t" * 161},
        {"run_id": "r" * 161},
        {"note": "n" * 1001},
        {"source_type": "untrusted"},
    ],
)
def test_invalid_registration_is_rejected_before_directory_allocation(repository, overrides):
    before = {path.name for path in repository.reports_root.iterdir()}

    with pytest.raises(ReportScoringError) as exc_info:
        create(repository, **overrides)

    assert exc_info.value.code == "INVALID_REPORT_REGISTRATION"
    assert exc_info.value.status_code == 422
    assert {path.name for path in repository.reports_root.iterdir()} == before
    assert repository.list_reports()[0] == []

    valid = create(repository)
    assert repository.read_report(valid.report_id)


def test_incomplete_directory_without_metadata_is_ignored(tmp_path):
    runtime = tmp_path / "runtime"
    orphan = runtime / "reports" / "rpt_orphan"
    orphan.mkdir(parents=True)
    orphan.joinpath("report.md").write_text("partial", encoding="utf-8")

    repository = ReportRepository(runtime, CaseRegistry(PROJECT_CATALOG))

    assert repository.list_reports()[0] == []


def test_long_lived_repository_loads_report_created_by_another_process(tmp_path):
    runtime = tmp_path / "runtime"
    registry = CaseRegistry(PROJECT_CATALOG)
    reader = ReportRepository(runtime, registry)
    writer = ReportRepository(runtime, registry)

    record = create(writer)

    assert reader.get_report(record.report_id) == record
    assert reader.read_report(record.report_id).startswith("一份很差")


def test_persisted_report_id_must_match_its_directory(tmp_path):
    runtime = tmp_path / "runtime"
    repository = ReportRepository(runtime, CaseRegistry(PROJECT_CATALOG))
    record = create(repository)
    metadata_path = runtime / "reports" / record.report_id / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["report_id"] = "rpt_" + "f" * 32
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(ReportScoringError) as exc_info:
        ReportRepository(runtime, CaseRegistry(PROJECT_CATALOG))

    assert exc_info.value.code == "INVALID_REPORT_RECORD"
