import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .case_registry import CaseRegistry
from .errors import ReportScoringError
from .report_repository import MAX_REPORT_BYTES, ReportRepository


@dataclass(frozen=True)
class ScoringContext:
    test_case_id: str
    agent_id: str
    final_report: str
    original_input: str
    ground_truth: dict[str, Any]
    negative_behavior_catalog: tuple[dict[str, str], ...]
    telemetry_boundaries: tuple[str, ...]
    scoring_standard: str
    report_sha256: str
    input_sha256: str
    standard_sha256: str

    def as_state_update(self) -> dict[str, Any]:
        return {
            "test_case_id": self.test_case_id,
            "agent_id": self.agent_id,
            "final_report": self.final_report,
            "original_input": self.original_input,
            "ground_truth": self.ground_truth,
            "negative_behavior_catalog": [dict(item) for item in self.negative_behavior_catalog],
            "telemetry_boundaries": list(self.telemetry_boundaries),
            "scoring_standard": self.scoring_standard,
            "report_sha256": self.report_sha256,
            "input_sha256": self.input_sha256,
            "standard_sha256": self.standard_sha256,
        }


class ScoringContextLoader:
    """Read-only boundary shared by API scoring and direct Studio runs."""

    def __init__(self, case_registry: CaseRegistry, report_repository: ReportRepository) -> None:
        self.case_registry = case_registry
        self.report_repository = report_repository

    @staticmethod
    def _validate_temporary_report(final_report: str) -> tuple[str, str]:
        if not final_report.strip():
            raise ReportScoringError("EMPTY_REPORT", "最终报告不能为空")
        content = final_report.encode("utf-8")
        if len(content) > MAX_REPORT_BYTES:
            raise ReportScoringError("FILE_TOO_LARGE", "临时最终报告不能超过 1 MiB")
        return final_report, hashlib.sha256(content).hexdigest()

    def load_registered(self, report_id: str) -> ScoringContext:
        report = self.report_repository.get_report(report_id)
        case = self.case_registry.get_case(report.test_case_id)
        expected_input_hash = case.manifest.input_sha256.lower()
        if report.input_sha256.lower() != expected_input_hash:
            raise ReportScoringError(
                "INVALID_REPORT_RECORD",
                "报告绑定的测试输入与当前案例不一致",
                status_code=409,
                field="input_sha256",
                details={"report_id": report.report_id},
            )
        return ScoringContext(
            test_case_id=report.test_case_id,
            agent_id=report.agent_id,
            final_report=self.report_repository.read_report(report.report_id),
            original_input=case.input_text,
            ground_truth=case.ground_truth,
            negative_behavior_catalog=case.negative_behavior_catalog,
            telemetry_boundaries=case.telemetry_boundaries,
            scoring_standard=case.scoring_standard,
            report_sha256=report.report_sha256.lower(),
            input_sha256=expected_input_hash,
            standard_sha256=case.manifest.standard_sha256.lower(),
        )

    def load_temporary(self, test_case_id: str, agent_id: str, final_report: str) -> ScoringContext:
        case = self.case_registry.get_case(test_case_id)
        canonical_agent = self.case_registry.canonicalize_agent_id(agent_id)
        final_report, report_hash = self._validate_temporary_report(final_report)
        return ScoringContext(
            test_case_id=case.manifest.test_case_id,
            agent_id=canonical_agent,
            final_report=final_report,
            original_input=case.input_text,
            ground_truth=case.ground_truth,
            negative_behavior_catalog=case.negative_behavior_catalog,
            telemetry_boundaries=case.telemetry_boundaries,
            scoring_standard=case.scoring_standard,
            report_sha256=report_hash,
            input_sha256=case.manifest.input_sha256.lower(),
            standard_sha256=case.manifest.standard_sha256.lower(),
        )


def create_default_scoring_context_loader() -> ScoringContextLoader:
    project_root = Path(__file__).resolve().parents[3]
    data_root = project_root / "report_scoring_data"
    registry = CaseRegistry(data_root / "catalog")
    repository = ReportRepository(data_root / "runtime", registry)
    return ScoringContextLoader(registry, repository)
