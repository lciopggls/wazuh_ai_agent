from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages


class ScoringState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    input_mode: Literal["internal", "registered", "temporary"]
    test_case_id: str
    agent_id: str
    report_id: str
    attempt_id: str
    final_report: str
    original_input: str
    ground_truth: dict[str, Any]
    negative_behavior_catalog: list[dict[str, str]]
    telemetry_boundaries: list[str]
    scoring_standard: str
    report_sha256: str
    input_sha256: str
    standard_sha256: str
    prepared_prompt: str
    raw_output: str
    candidate: dict[str, Any]
    total_score: float
    validation_errors: list[str]
    repair_count: int
    status: Literal["succeeded", "failed"]
    final_error: str
