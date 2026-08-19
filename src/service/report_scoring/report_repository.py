import hashlib
import json
import os
import threading
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from .api_models import ReportRecord, ReportRegistrationInput, ReportSource
from .case_registry import CaseRegistry
from .errors import ReportScoringError
from .safe_paths import UnsafePathError, is_reparse_point, resolve_path_within_root

MAX_REPORT_BYTES = 1024 * 1024
ALLOWED_REPORT_EXTENSIONS = {".md", ".txt"}


def atomic_write(path: Path, content: bytes) -> None:
    """Durably replace a file without exposing partially written content."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    try:
        with temp_path.open("xb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink()


class ReportRepository:
    """Single-process repository for normalized report registrations."""

    def __init__(
        self,
        runtime_root: Path | str,
        studio_inbox: Path | str,
        case_registry: CaseRegistry,
    ) -> None:
        configured_runtime_root = Path(runtime_root)
        configured_studio_inbox = Path(studio_inbox)
        if is_reparse_point(configured_runtime_root) or is_reparse_point(configured_studio_inbox):
            raise ReportScoringError(
                "PATH_OUTSIDE_ALLOWED_ROOT", "报告存储目录包含 reparse point", status_code=500
            )
        self.runtime_root = configured_runtime_root.resolve()
        self.reports_root = self.runtime_root / "reports"
        self.studio_inbox = configured_studio_inbox.resolve()
        self.case_registry = case_registry
        self.reports_root.mkdir(parents=True, exist_ok=True)
        self.studio_inbox.mkdir(parents=True, exist_ok=True)
        try:
            resolve_path_within_root(self.reports_root, self.runtime_root, strict=True)
            resolve_path_within_root(self.studio_inbox, self.studio_inbox, strict=True)
        except UnsafePathError:
            raise ReportScoringError(
                "PATH_OUTSIDE_ALLOWED_ROOT", "报告存储目录包含 reparse point", status_code=500
            ) from None
        self._lock = threading.RLock()
        self._records: dict[str, ReportRecord] = {}
        self._duplicate_index: dict[tuple[str, str, str], str] = {}
        self._load_existing_records()

    @staticmethod
    def _is_reparse_point(path: Path) -> bool:
        return is_reparse_point(path)

    def _load_existing_records(self) -> None:
        for report_dir in sorted(self.reports_root.iterdir(), key=lambda item: item.name):
            if not report_dir.is_dir() or self._is_reparse_point(report_dir):
                continue
            metadata_path = report_dir / "metadata.json"
            if not metadata_path.is_file():
                continue
            try:
                record = ReportRecord.model_validate_json(metadata_path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, ValidationError, ValueError) as exc:
                raise ReportScoringError(
                    "INVALID_REPORT_RECORD",
                    "已保存的报告元数据无效",
                    status_code=500,
                    details={"report_id": report_dir.name},
                ) from exc
            report_path = self.runtime_root / record.stored_path
            expected_report_path = report_dir / "report.md"
            try:
                resolved_report_path = resolve_path_within_root(
                    report_path, self.runtime_root, strict=True
                )
            except UnsafePathError:
                raise ReportScoringError(
                    "INVALID_REPORT_RECORD",
                    "已保存的报告路径无效",
                    status_code=500,
                    details={"report_id": record.report_id},
                ) from None
            if (
                record.report_id != report_dir.name
                or resolved_report_path != expected_report_path.resolve(strict=True)
                or self._is_reparse_point(report_path)
            ):
                raise ReportScoringError(
                    "INVALID_REPORT_RECORD",
                    "已保存的报告记录与目录不一致",
                    status_code=500,
                    details={"report_id": report_dir.name},
                )
            self._register_loaded(record)

    def _register_loaded(self, record: ReportRecord) -> None:
        if record.report_id in self._records:
            raise ReportScoringError("INVALID_REPORT_RECORD", "报告 ID 重复", status_code=500)
        duplicate_key = (record.test_case_id, record.agent_id, record.report_sha256.lower())
        if duplicate_key in self._duplicate_index:
            raise ReportScoringError(
                "INVALID_REPORT_RECORD", "持久化目录包含重复报告记录", status_code=500
            )
        self._records[record.report_id] = record
        self._duplicate_index[duplicate_key] = record.report_id

    @staticmethod
    def _validate_filename(filename: str) -> str:
        safe_name = Path(filename).name
        extension = Path(safe_name).suffix.lower()
        if extension not in ALLOWED_REPORT_EXTENSIONS:
            raise ReportScoringError(
                "INVALID_FILE_TYPE",
                "报告只支持 .md 或 .txt 文件",
                field="filename",
            )
        if not safe_name or len(safe_name) > 255:
            raise ReportScoringError("INVALID_FILE_TYPE", "报告文件名无效", field="filename")
        return safe_name

    @staticmethod
    def _validate_content(content: bytes) -> str:
        if len(content) > MAX_REPORT_BYTES:
            raise ReportScoringError("FILE_TOO_LARGE", "报告文件不能超过 1 MiB", status_code=400)
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            raise ReportScoringError("INVALID_UTF8", "报告必须使用 UTF-8 编码") from None
        if not text.strip():
            raise ReportScoringError("EMPTY_REPORT", "报告内容不能为空")
        return text

    @staticmethod
    def _validation_error(exc: ValidationError) -> ReportScoringError:
        return ReportScoringError(
            "INVALID_REPORT_REGISTRATION",
            "报告登记字段无效",
            status_code=422,
            details={
                "errors": [
                    {
                        "field": ".".join(str(part) for part in error["loc"]),
                        "message": error["msg"],
                    }
                    for error in exc.errors()
                ]
            },
        )

    def create_report(
        self,
        *,
        content: bytes,
        filename: str,
        test_case_id: str,
        agent_id: str,
        source_type: ReportSource,
        thread_id: str | None = None,
        run_id: str | None = None,
        note: str | None = None,
        allow_agent_alias: bool = False,
    ) -> ReportRecord:
        safe_name = self._validate_filename(filename)
        self._validate_content(content)
        thread_id = (thread_id.strip() or None) if thread_id is not None else None
        run_id = (run_id.strip() or None) if run_id is not None else None
        note = (note.strip() or None) if note is not None else None
        try:
            registration = ReportRegistrationInput(
                filename=safe_name,
                source_type=source_type,
                test_case_id=test_case_id,
                agent_id=agent_id,
                thread_id=thread_id,
                run_id=run_id,
                note=note,
            )
        except ValidationError as exc:
            raise self._validation_error(exc) from None
        case = self.case_registry.get_case(test_case_id)
        canonical_agent = self.case_registry.canonicalize_agent_id(
            agent_id, allow_alias=allow_agent_alias
        )
        report_hash = hashlib.sha256(content).hexdigest()
        duplicate_key = (test_case_id, canonical_agent, report_hash)

        with self._lock:
            existing_id = self._duplicate_index.get(duplicate_key)
            if existing_id is not None:
                raise ReportScoringError(
                    "DUPLICATE_REPORT",
                    "同一案例和智能体下已登记相同报告",
                    status_code=409,
                    details={"report_id": existing_id},
                )

            for _ in range(10):
                report_id = f"rpt_{uuid.uuid4().hex}"
                report_dir = self.reports_root / report_id
                report_path = report_dir / "report.md"
                stored_path = report_path.relative_to(self.runtime_root).as_posix()
                try:
                    record = ReportRecord(
                        report_id=report_id,
                        test_case_id=registration.test_case_id,
                        agent_id=canonical_agent,
                        source_type=registration.source_type,
                        original_filename=registration.filename,
                        stored_path=stored_path,
                        report_sha256=report_hash,
                        input_sha256=case.manifest.input_sha256.lower(),
                        imported_at=datetime.now(UTC),
                        thread_id=registration.thread_id,
                        run_id=registration.run_id,
                        note=registration.note,
                    )
                except ValidationError as exc:
                    raise self._validation_error(exc) from None
                try:
                    report_dir.mkdir(exist_ok=False)
                except FileExistsError:
                    continue
                break
            else:
                raise ReportScoringError("REPORT_STORAGE_ERROR", "无法分配报告 ID", status_code=500)

            atomic_write(report_path, content)
            metadata = json.dumps(
                record.model_dump(mode="json"), ensure_ascii=False, indent=2
            ).encode("utf-8")
            atomic_write(report_dir / "metadata.json", metadata)
            self._register_loaded(record)
            return record

    def import_studio_report(
        self,
        *,
        relative_path: str,
        test_case_id: str,
        agent_id: str,
        thread_id: str | None = None,
        run_id: str | None = None,
        note: str | None = None,
    ) -> ReportRecord:
        relative = Path(relative_path)
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise self._studio_path_error(relative_path)
        unresolved = self.studio_inbox / relative
        try:
            source = resolve_path_within_root(unresolved, self.studio_inbox, strict=True)
        except UnsafePathError:
            raise self._studio_path_error(relative_path) from None
        if not source.is_file():
            raise self._studio_path_error(relative_path)
        try:
            content = source.read_bytes()
        except OSError:
            raise ReportScoringError("INVALID_STUDIO_REPORT", "无法读取 Studio 报告") from None
        return self.create_report(
            content=content,
            filename=source.name,
            test_case_id=test_case_id,
            agent_id=agent_id,
            source_type="studio",
            thread_id=thread_id,
            run_id=run_id,
            note=note,
            allow_agent_alias=True,
        )

    @staticmethod
    def _studio_path_error(relative_path: str) -> ReportScoringError:
        return ReportScoringError(
            "PATH_OUTSIDE_ALLOWED_ROOT",
            "Studio 报告路径无效或超出 inbox",
            field="relative_path",
            details={"path": relative_path},
        )

    def get_report(self, report_id: str) -> ReportRecord:
        try:
            return self._records[report_id]
        except KeyError:
            raise ReportScoringError("REPORT_NOT_FOUND", "报告不存在", status_code=404) from None

    def read_report(self, report_id: str) -> str:
        record = self.get_report(report_id)
        path = self.runtime_root / record.stored_path
        try:
            content = path.read_bytes()
        except OSError:
            raise ReportScoringError(
                "REPORT_STORAGE_ERROR", "报告正文无法读取", status_code=500
            ) from None
        if hashlib.sha256(content).hexdigest() != record.report_sha256.lower():
            raise ReportScoringError(
                "REPORT_STORAGE_ERROR", "报告正文哈希与元数据不一致", status_code=500
            )
        return content.decode("utf-8")

    def list_reports(
        self,
        *,
        test_case_id: str | None = None,
        agent_id: str | None = None,
        source_type: ReportSource | None = None,
        offset: int = 0,
        limit: int = 50,
    ) -> tuple[list[ReportRecord], int]:
        records: Iterable[ReportRecord] = self._records.values()
        if test_case_id is not None:
            records = (record for record in records if record.test_case_id == test_case_id)
        if agent_id is not None:
            canonical_agent = self.case_registry.canonicalize_agent_id(agent_id)
            records = (record for record in records if record.agent_id == canonical_agent)
        if source_type is not None:
            records = (record for record in records if record.source_type == source_type)
        ordered = sorted(
            records, key=lambda record: (record.imported_at, record.report_id), reverse=True
        )
        return ordered[offset : offset + limit], len(ordered)
