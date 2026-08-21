from typing import Any

from agents.baseline.state import BaselineCommonState


class BaselinePlusState(BaselineCommonState, total=False):
    alert_start_time: str
    alert_end_time: str
    alert_logs: list[dict[str, Any]]
    alert_summary: str
    selected_alert_count: int
    alert_error: str | None
