from typing import Annotated, Any, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class BaselineCommonState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    initial_input: str
    agent_id: str
    start_time: str
    end_time: str
    time_display: str
    anchor_time: str
    total_logs: int
    processed_logs: int
    is_truncated: bool
    batch_number: int
    search_after: list[Any] | None
    current_raw_logs: list[dict[str, Any]]
    batch_notes: list[str]
    archive_error: str | None
    error: str | None
    final_report: str
