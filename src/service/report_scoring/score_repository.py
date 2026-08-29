import json
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path

from pydantic import ValidationError

from agents.report_scoring.dimensions import SCORING_DIMENSIONS

from .api_models import ScoreHistoryItem, ScoreResult, ScoringAttempt
from .errors import ReportScoringError
from .report_repository import atomic_write
from .safe_paths import UnsafePathError, is_reparse_point, resolve_path_within_root


class ScoreRepository:
    """Append-only attempt/result repository with restart recovery."""

    def __init__(self, runtime_root: Path | str) -> None:
        configured_root = Path(runtime_root)
        if is_reparse_point(configured_root):
            raise ReportScoringError(
                "INVALID_SCORING_RECORD", "评分历史根目录不安全", status_code=500
            )
        self.runtime_root = configured_root.resolve()
        self.attempts_root = self.runtime_root / "scoring_attempts"
        self.attempts_root.mkdir(parents=True, exist_ok=True)
        self._require_safe_path(self.attempts_root, strict=True)
        self._lock = threading.RLock()
        self._attempts: dict[str, ScoringAttempt] = {}
        self._results: dict[str, ScoreResult] = {}
        self._request_index: dict[tuple[str, str], str] = {}
        self._load_existing()

    def _require_safe_path(self, path: Path, *, strict: bool) -> Path:
        try:
            return resolve_path_within_root(path, self.runtime_root, strict=strict)
        except UnsafePathError:
            raise self._unsafe_path_error(path) from None

    @staticmethod
    def _unsafe_path_error(path: Path) -> ReportScoringError:
        return ReportScoringError(
            "INVALID_SCORING_RECORD",
            "评分历史路径无效或包含 reparse point",
            status_code=500,
            details={"path": path.name},
        )

    @staticmethod
    def _json_bytes(model) -> bytes:
        return json.dumps(model.model_dump(mode="json"), ensure_ascii=False, indent=2).encode(
            "utf-8"
        )

    def _load_existing(self) -> None:
        for report_dir in sorted(self.attempts_root.iterdir(), key=lambda path: path.name):
            if is_reparse_point(report_dir):
                raise self._unsafe_path_error(report_dir)
            if not report_dir.is_dir():
                continue
            self._require_safe_path(report_dir, strict=True)
            for attempt_dir in sorted(report_dir.iterdir(), key=lambda path: path.name):
                if is_reparse_point(attempt_dir):
                    raise self._unsafe_path_error(attempt_dir)
                if not attempt_dir.is_dir():
                    continue
                self._require_safe_path(attempt_dir, strict=True)
                attempt_path = attempt_dir / "attempt.json"
                if not attempt_path.is_file():
                    continue
                self._require_safe_path(attempt_path, strict=True)
                try:
                    attempt = ScoringAttempt.model_validate_json(
                        attempt_path.read_text(encoding="utf-8")
                    )
                except (OSError, UnicodeDecodeError, ValidationError, ValueError) as exc:
                    raise ReportScoringError(
                        "INVALID_SCORING_RECORD",
                        "评分尝试元数据无效",
                        status_code=500,
                        details={"attempt_id": attempt_dir.name},
                    ) from exc
                if attempt.report_id != report_dir.name or attempt.attempt_id != attempt_dir.name:
                    raise ReportScoringError(
                        "INVALID_SCORING_RECORD",
                        "评分尝试与持久化目录不一致",
                        status_code=500,
                        details={"attempt_id": attempt_dir.name},
                    )
                if attempt.status == "running":
                    attempt = attempt.model_copy(
                        update={
                            "status": "failed",
                            "completed_at": datetime.now(UTC),
                            "error_code": "SCORING_INTERRUPTED",
                            "error_message": "服务重启时发现未完成的评分尝试",
                        }
                    )
                    atomic_write(attempt_path, self._json_bytes(attempt))
                self._index_attempt(attempt)
                if attempt.status == "succeeded" and attempt.score_id:
                    result_path = attempt_dir / "result.json"
                    self._require_safe_path(result_path, strict=True)
                    try:
                        result = ScoreResult.model_validate_json(
                            result_path.read_text(encoding="utf-8")
                        )
                    except (OSError, UnicodeDecodeError, ValidationError, ValueError) as exc:
                        raise ReportScoringError(
                            "INVALID_SCORING_RECORD",
                            "成功评分缺少有效结果",
                            status_code=500,
                            details={"attempt_id": attempt.attempt_id},
                        ) from exc
                    if (
                        result.attempt_id != attempt.attempt_id
                        or result.report_id != attempt.report_id
                        or result.test_case_id != attempt.test_case_id
                        or result.agent_id != attempt.agent_id
                        or result.score_id != attempt.score_id
                    ):
                        raise ReportScoringError(
                            "INVALID_SCORING_RECORD",
                            "评分结果与评分尝试不一致",
                            status_code=500,
                            details={"attempt_id": attempt.attempt_id},
                        )
                    self._results[result.score_id] = result

    def _index_attempt(self, attempt: ScoringAttempt) -> None:
        if attempt.attempt_id in self._attempts:
            raise ReportScoringError("INVALID_SCORING_RECORD", "评分尝试 ID 重复", status_code=500)
        request_key = (attempt.report_id, str(attempt.request_id))
        if request_key in self._request_index:
            raise ReportScoringError(
                "INVALID_SCORING_RECORD", "评分 request_id 重复", status_code=500
            )
        self._attempts[attempt.attempt_id] = attempt
        self._request_index[request_key] = attempt.attempt_id

    def _attempt_directory(self, report_id: str, attempt_id: str) -> Path:
        path = self.attempts_root / report_id / attempt_id
        self._require_safe_path(path, strict=path.exists())
        return path

    def find_by_request(self, report_id: str, request_id: str) -> ScoreHistoryItem | None:
        attempt_id = self._request_index.get((report_id, str(request_id)))
        if attempt_id is None:
            return None
        attempt = self._attempts[attempt_id]
        result = self._results.get(attempt.score_id) if attempt.score_id else None
        return ScoreHistoryItem(attempt=attempt, result=result)

    def create_attempt(
        self,
        *,
        report_id: str,
        test_case_id: str,
        agent_id: str,
        request_id: str,
        operation: str,
        scoring_contract_version: str | None = None,
    ) -> ScoringAttempt:
        with self._lock:
            if self.find_by_request(report_id, request_id) is not None:
                raise ReportScoringError(
                    "DUPLICATE_SCORING_REQUEST", "评分 request_id 已存在", status_code=409
                )
            report_root = self.attempts_root / report_id
            report_root.mkdir(parents=True, exist_ok=True)
            self._require_safe_path(report_root, strict=True)
            for _ in range(10):
                attempt_id = f"att_{uuid.uuid4().hex}"
                attempt_dir = report_root / attempt_id
                try:
                    attempt_dir.mkdir(exist_ok=False)
                except FileExistsError:
                    continue
                self._require_safe_path(attempt_dir, strict=True)
                break
            else:
                raise ReportScoringError(
                    "SCORING_STORAGE_ERROR", "无法分配评分尝试 ID", status_code=500
                )
            attempt = ScoringAttempt(
                attempt_id=attempt_id,
                request_id=request_id,
                report_id=report_id,
                test_case_id=test_case_id,
                agent_id=agent_id,
                operation=operation,
                scoring_contract_version=scoring_contract_version,
                status="running",
                started_at=datetime.now(UTC),
            )
            attempt_path = attempt_dir / "attempt.json"
            self._require_safe_path(attempt_path, strict=False)
            atomic_write(attempt_path, self._json_bytes(attempt))
            self._index_attempt(attempt)
            return attempt

    def complete_success(self, attempt_id: str, result: ScoreResult) -> ScoringAttempt:
        with self._lock:
            attempt = self.get_attempt(attempt_id)
            if attempt.status != "running":
                raise ReportScoringError("SCORING_STORAGE_ERROR", "评分尝试已终止", status_code=500)
            attempt_dir = self._attempt_directory(attempt.report_id, attempt.attempt_id)
            result_path = attempt_dir / "result.json"
            markdown_path = attempt_dir / "score.md"
            self._require_safe_path(result_path, strict=result_path.exists())
            self._require_safe_path(markdown_path, strict=markdown_path.exists())
            atomic_write(result_path, self._json_bytes(result))
            atomic_write(markdown_path, self._render_markdown(result).encode("utf-8"))
            completed = attempt.model_copy(
                update={
                    "status": "succeeded",
                    "completed_at": result.completed_at,
                    "score_id": result.score_id,
                }
            )
            attempt_path = attempt_dir / "attempt.json"
            self._require_safe_path(attempt_path, strict=True)
            atomic_write(attempt_path, self._json_bytes(completed))
            self._attempts[attempt_id] = completed
            self._results[result.score_id] = result
            return completed

    def complete_failure(self, attempt_id: str, code: str, message: str) -> ScoringAttempt:
        with self._lock:
            attempt = self.get_attempt(attempt_id)
            if attempt.status != "running":
                return attempt
            completed = attempt.model_copy(
                update={
                    "status": "failed",
                    "completed_at": datetime.now(UTC),
                    "error_code": code,
                    "error_message": message[:1000],
                }
            )
            path = self._attempt_directory(attempt.report_id, attempt.attempt_id) / "attempt.json"
            self._require_safe_path(path, strict=True)
            atomic_write(path, self._json_bytes(completed))
            self._attempts[attempt_id] = completed
            return completed

    @staticmethod
    def _render_markdown(result: ScoreResult) -> str:
        score = result.score.model_dump(mode="json")
        rows = [
            (dimension.label, score[dimension.field]["score"]) for dimension in SCORING_DIMENSIONS
        ]
        body = "\n".join(f"| {name} | {value:.1f} |" for name, value in rows)
        return (
            f"# 报告评分 {result.score_id}\n\n"
            f"- 案例：`{result.test_case_id}`\n"
            f"- 智能体：`{result.agent_id}`\n"
            f"- 标准：`{result.scoring_standard_version}`\n\n"
            "| 维度 | 得分 |\n|---|---:|\n"
            f"{body}\n| **总分** | **{result.total_score:.1f}** |\n"
        )

    def get_attempt(self, attempt_id: str) -> ScoringAttempt:
        try:
            return self._attempts[attempt_id]
        except KeyError:
            raise ReportScoringError(
                "SCORING_ATTEMPT_NOT_FOUND", "评分尝试不存在", status_code=404
            ) from None

    def get_score(self, score_id: str) -> ScoreResult:
        try:
            return self._results[score_id]
        except KeyError:
            raise ReportScoringError(
                "SCORING_ATTEMPT_NOT_FOUND", "评分结果不存在", status_code=404
            ) from None

    def history(self, report_id: str) -> list[ScoreHistoryItem]:
        items = [
            ScoreHistoryItem(
                attempt=attempt,
                result=self._results.get(attempt.score_id) if attempt.score_id else None,
            )
            for attempt in self._attempts.values()
            if attempt.report_id == report_id
        ]
        return sorted(items, key=lambda item: (item.attempt.started_at, item.attempt.attempt_id))

    def latest_success(self, report_id: str) -> ScoreResult | None:
        results = [result for result in self._results.values() if result.report_id == report_id]
        if not results:
            return None
        return max(results, key=lambda result: (result.completed_at, result.score_id))

    def latest_attempt(self, report_id: str) -> ScoringAttempt | None:
        attempts = [
            attempt for attempt in self._attempts.values() if attempt.report_id == report_id
        ]
        if not attempts:
            return None
        return max(attempts, key=lambda attempt: (attempt.started_at, attempt.attempt_id))
