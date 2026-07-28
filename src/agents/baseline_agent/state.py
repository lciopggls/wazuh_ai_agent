from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class BaselineState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    initial_input: str
    agent_id: str
    start_time: str
    end_time: str
    time_display: str
    anchor_time: str
    alert_start_time: str
    alert_end_time: str
    total_logs: int
    processed_logs: int
    is_truncated: bool
    batch_number: int
    search_after: list[Any] | None
    current_raw_logs: list[dict[str, Any]]
    batch_notes: list[str]
    alert_logs: list[dict[str, Any]]
    alert_summary: str
    selected_alert_count: int
    archive_error: str | None
    alert_error: str | None
    error: str | None
    # 暂停记录完整分析时间；当前不使用基线智能体作为时间比对对象。
    # analysis_started_at: float
    final_report: str
