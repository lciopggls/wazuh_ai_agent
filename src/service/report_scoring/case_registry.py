import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from agents.report_scoring.negative_behaviors import build_negative_behavior_catalog

from .api_models import (
    AgentCatalog,
    AgentDefinition,
    AgentSummary,
    TestCaseManifest,
    TestCaseSummary,
)
from .errors import ReportScoringError
from .safe_paths import UnsafePathError, is_reparse_point, resolve_path_within_root


@dataclass(frozen=True)
class RegisteredTestCase:
    manifest: TestCaseManifest
    case_root: Path
    input_text: str
    anchor: dict[str, Any]
    ground_truth: dict[str, Any]
    negative_behavior_catalog: tuple[dict[str, str], ...]
    telemetry_boundaries: tuple[str, ...]
    scoring_standard: str
    scoring_context_sha256: str
    expected_report: str


class CaseRegistry:
    """Strict loader for version-controlled report-scoring cases and agents."""

    def __init__(self, catalog_root: Path | str) -> None:
        configured_root = Path(catalog_root)
        if is_reparse_point(configured_root):
            raise ReportScoringError("INVALID_TEST_CASE", "案例目录不存在或不安全")
        self.catalog_root = configured_root.resolve(strict=True)
        self._cases: dict[str, RegisteredTestCase] = {}
        self._agents: dict[str, AgentDefinition] = {}
        self._agent_aliases: dict[str, str] = {}
        self._load_agents()
        self._load_cases()

    @staticmethod
    def _sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _is_reparse_point(path: Path) -> bool:
        return is_reparse_point(path)

    def _resolve_file(
        self,
        base: Path,
        relative_value: str,
        *,
        field: str,
        extensions: set[str],
    ) -> Path:
        relative = Path(relative_value)
        if relative.is_absolute() or relative.drive or ".." in relative.parts:
            raise self._invalid_path(field, relative_value)

        unresolved = base / relative
        try:
            resolved = resolve_path_within_root(unresolved, base, strict=True)
        except UnsafePathError:
            raise self._invalid_path(field, relative_value) from None

        if not resolved.is_file() or resolved.suffix.lower() not in extensions:
            raise self._invalid_path(field, relative_value)
        return resolved

    @staticmethod
    def _invalid_path(field: str, value: str) -> ReportScoringError:
        return ReportScoringError(
            "PATH_OUTSIDE_ALLOWED_ROOT",
            "案例文件路径无效或超出允许目录",
            field=field,
            details={"path": value},
        )

    @staticmethod
    def _read_utf8(path: Path, field: str) -> tuple[str, bytes]:
        try:
            raw = path.read_bytes()
            return raw.decode("utf-8"), raw
        except UnicodeDecodeError:
            raise ReportScoringError(
                "INVALID_TEST_CASE", "案例文件不是有效 UTF-8", field=field
            ) from None
        except OSError:
            raise ReportScoringError("INVALID_TEST_CASE", "无法读取案例文件", field=field) from None

    @staticmethod
    def _read_json(path: Path, field: str) -> tuple[dict[str, Any], bytes]:
        text, raw = CaseRegistry._read_utf8(path, field)
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            raise ReportScoringError(
                "INVALID_TEST_CASE", "案例 JSON 文件格式无效", field=field
            ) from None
        if not isinstance(value, dict):
            raise ReportScoringError("INVALID_TEST_CASE", "案例 JSON 顶层必须是对象", field=field)
        return value, raw

    def _load_agents(self) -> None:
        agents_path = self._resolve_file(
            self.catalog_root,
            "agents.json",
            field="agents",
            extensions={".json"},
        )
        payload, _ = self._read_json(agents_path, "agents")
        try:
            catalog = AgentCatalog.model_validate(payload)
        except ValidationError as exc:
            raise ReportScoringError(
                "INVALID_AGENT", "智能体目录格式无效", details={"errors": exc.errors()}
            ) from None

        names: set[str] = set()
        for agent in catalog.agents:
            all_names = [agent.agent_id, *agent.aliases]
            if any(name in names for name in all_names) or len(set(all_names)) != len(all_names):
                raise ReportScoringError("INVALID_AGENT", "智能体 ID 或别名重复")
            names.update(all_names)
            self._agents[agent.agent_id] = agent
            for alias in agent.aliases:
                self._agent_aliases[alias] = agent.agent_id

    def _load_cases(self) -> None:
        cases_root = self.catalog_root / "cases"
        if not cases_root.is_dir() or self._is_reparse_point(cases_root):
            raise ReportScoringError("INVALID_TEST_CASE", "案例目录不存在或不安全")

        loaded: list[RegisteredTestCase] = []
        for case_root in sorted(cases_root.iterdir(), key=lambda item: item.name):
            if not case_root.is_dir():
                continue
            if self._is_reparse_point(case_root):
                raise self._invalid_path("case_root", case_root.name)
            loaded.append(self._load_case(case_root))

        ids = [case.manifest.test_case_id for case in loaded]
        duplicate_ids = sorted({case_id for case_id in ids if ids.count(case_id) > 1})
        if duplicate_ids:
            raise ReportScoringError(
                "INVALID_TEST_CASE",
                "存在重复的测试案例 ID",
                field="test_case_id",
                details={"test_case_ids": duplicate_ids},
            )
        for case in loaded:
            if case.manifest.test_case_id != case.case_root.name:
                raise ReportScoringError(
                    "INVALID_TEST_CASE",
                    "案例目录名与 test_case_id 不一致",
                    field="test_case_id",
                    details={"case_directory": case.case_root.name},
                )
        self._cases = {case.manifest.test_case_id: case for case in loaded}

    def _load_case(self, case_root: Path) -> RegisteredTestCase:
        manifest_path = self._resolve_file(
            case_root, "manifest.json", field="manifest", extensions={".json"}
        )
        manifest_payload, _ = self._read_json(manifest_path, "manifest")
        try:
            manifest = TestCaseManifest.model_validate(manifest_payload)
        except ValidationError as exc:
            raise ReportScoringError(
                "INVALID_TEST_CASE",
                "测试案例 manifest 格式无效",
                details={"case_directory": case_root.name, "errors": exc.errors()},
            ) from None

        input_path = self._resolve_file(
            case_root, manifest.input_path, field="input_path", extensions={".txt", ".json"}
        )
        anchor_path = self._resolve_file(
            case_root, manifest.anchor_path, field="anchor_path", extensions={".json"}
        )
        ground_truth_path = self._resolve_file(
            case_root,
            manifest.ground_truth_path,
            field="ground_truth_path",
            extensions={".json"},
        )
        expected_report_path = self._resolve_file(
            case_root,
            manifest.expected_report_path,
            field="expected_report_path",
            extensions={".md", ".txt"},
        )
        standard_path = self._resolve_file(
            self.catalog_root,
            manifest.scoring_standard_path,
            field="scoring_standard_path",
            extensions={".md"},
        )
        telemetry_paths = [
            self._resolve_file(
                case_root,
                path,
                field=f"telemetry_boundary_paths[{index}]",
                extensions={".md", ".txt", ".json"},
            )
            for index, path in enumerate(manifest.telemetry_boundary_paths)
        ]

        input_text, input_raw = self._read_utf8(input_path, "input_path")
        anchor, _ = self._read_json(anchor_path, "anchor_path")
        ground_truth, ground_truth_raw = self._read_json(ground_truth_path, "ground_truth_path")
        expected_report, _ = self._read_utf8(expected_report_path, "expected_report_path")
        standard, standard_raw = self._read_utf8(standard_path, "scoring_standard_path")
        telemetry_material = tuple(
            self._read_utf8(path, f"telemetry_boundary_paths[{index}]")
            for index, path in enumerate(telemetry_paths)
        )
        telemetry_boundaries = tuple(text for text, _ in telemetry_material)
        scoring_context_sha256 = self._sha256(
            b"\0".join(
                [input_raw, ground_truth_raw, *(raw for _, raw in telemetry_material), standard_raw]
            )
        )

        if self._sha256(input_raw) != manifest.input_sha256.lower():
            raise ReportScoringError(
                "INVALID_TEST_CASE", "输入文件 SHA256 不匹配", field="input_sha256"
            )
        if self._sha256(standard_raw) != manifest.standard_sha256.lower():
            raise ReportScoringError(
                "INVALID_TEST_CASE", "评分标准 SHA256 不匹配", field="standard_sha256"
            )
        if ground_truth.get("scenario_id") != manifest.test_case_id:
            raise ReportScoringError(
                "INVALID_TEST_CASE", "Ground Truth scenario_id 与案例不一致", field="scenario_id"
            )
        if (
            ground_truth.get("visibility") != "scoring_only"
            or ground_truth.get("must_not_be_provided_to_tested_agent") is not True
        ):
            raise ReportScoringError("INVALID_TEST_CASE", "Ground Truth 缺少评分侧可见性保护字段")
        try:
            negative_behavior_catalog = tuple(build_negative_behavior_catalog(ground_truth))
        except ValueError as exc:
            raise ReportScoringError(
                "INVALID_TEST_CASE",
                str(exc),
                status_code=500,
                field="negative_behavior_catalog",
            ) from None

        return RegisteredTestCase(
            manifest=manifest,
            case_root=case_root.resolve(),
            input_text=input_text,
            anchor=anchor,
            ground_truth=ground_truth,
            negative_behavior_catalog=negative_behavior_catalog,
            telemetry_boundaries=telemetry_boundaries,
            scoring_standard=standard,
            scoring_context_sha256=scoring_context_sha256,
            expected_report=expected_report,
        )

    def list_cases(self) -> list[TestCaseSummary]:
        return [
            TestCaseSummary(
                test_case_id=case.manifest.test_case_id,
                display_name=case.manifest.display_name,
                scoring_standard_version=case.manifest.scoring_standard_version,
                input_sha256=case.manifest.input_sha256.lower(),
            )
            for case in self._cases.values()
            if case.manifest.enabled
        ]

    def get_case(self, test_case_id: str, *, require_enabled: bool = True) -> RegisteredTestCase:
        case = self._cases.get(test_case_id)
        if case is None:
            raise ReportScoringError(
                "INVALID_TEST_CASE", "未知测试案例", status_code=404, field="test_case_id"
            )
        if require_enabled and not case.manifest.enabled:
            raise ReportScoringError(
                "DISABLED_TEST_CASE", "测试案例已禁用", status_code=409, field="test_case_id"
            )
        return case

    def list_agents(self) -> list[AgentSummary]:
        return [
            AgentSummary(agent_id=agent.agent_id, display_name=agent.display_name)
            for agent in self._agents.values()
        ]

    def canonicalize_agent_id(self, agent_id: str, *, allow_alias: bool = False) -> str:
        if agent_id in self._agents:
            return agent_id
        if allow_alias and agent_id in self._agent_aliases:
            return self._agent_aliases[agent_id]
        raise ReportScoringError(
            "INVALID_AGENT", "未知被测智能体", field="agent_id", status_code=400
        )
