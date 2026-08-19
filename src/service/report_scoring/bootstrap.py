from dataclasses import dataclass
from pathlib import Path

from .case_registry import CaseRegistry
from .report_repository import ReportRepository
from .score_repository import ScoreRepository
from .scoring_service import ScoringService


@dataclass(frozen=True)
class ReportScoringRuntime:
    case_registry: CaseRegistry
    report_repository: ReportRepository
    score_repository: ScoreRepository
    scoring_service: ScoringService


def create_report_scoring_runtime(data_root: Path, model) -> ReportScoringRuntime:
    """Create the optional report-scoring subsystem behind one startup boundary."""

    case_registry = CaseRegistry(data_root / "catalog")
    report_repository = ReportRepository(
        data_root / "runtime",
        data_root / "studio_inbox",
        case_registry,
    )
    score_repository = ScoreRepository(data_root / "runtime")
    scoring_service = ScoringService(
        case_registry,
        report_repository,
        score_repository,
        model,
    )
    return ReportScoringRuntime(
        case_registry=case_registry,
        report_repository=report_repository,
        score_repository=score_repository,
        scoring_service=scoring_service,
    )
