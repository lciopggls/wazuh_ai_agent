from functools import partial

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, StateGraph

from agents.baseline.baseline_agent_plus import nodes
from agents.baseline.baseline_agent_plus.state import BaselinePlusState


def route_after_prepare(state: BaselinePlusState) -> str:
    if state.get("error"):
        return "final_report"
    if state.get("archive_error") or state.get("total_logs", 0) == 0:
        return "fetch_alerts"
    return "fetch_batch"


def route_after_fetch(state: BaselinePlusState) -> str:
    if state.get("archive_error") or not state.get("current_raw_logs"):
        return "fetch_alerts"
    return "analyze_batch"


def route_after_analysis(state: BaselinePlusState) -> str:
    if state.get("archive_error"):
        return "fetch_alerts"
    if (
        state.get("processed_logs", 0) >= state.get("total_logs", 0)
        or state.get("batch_number", 0) >= nodes.MAX_BATCHES
    ):
        return "fetch_alerts"
    return "fetch_batch"


def route_after_alert_fetch(state: BaselinePlusState) -> str:
    if state.get("alert_logs"):
        return "analyze_alerts"
    return "final_report"


def get_baseline_agent_plus(model: BaseChatModel, checkpointer=None):
    """创建带附近告警补充的固定窗口攻击溯源基线。"""
    graph = StateGraph(BaselinePlusState)
    graph.add_node("prepare_investigation", nodes.prepare_investigation_node)
    graph.add_node("fetch_batch", nodes.fetch_batch_node)
    graph.add_node("analyze_batch", partial(nodes.analyze_batch_node, model=model))
    graph.add_node("fetch_alerts", nodes.fetch_alerts_node)
    graph.add_node("analyze_alerts", partial(nodes.analyze_alerts_node, model=model))
    graph.add_node("final_report", partial(nodes.final_report_node, model=model))

    graph.set_entry_point("prepare_investigation")
    graph.add_conditional_edges(
        "prepare_investigation",
        route_after_prepare,
        {
            "fetch_batch": "fetch_batch",
            "fetch_alerts": "fetch_alerts",
            "final_report": "final_report",
        },
    )
    graph.add_conditional_edges(
        "fetch_batch",
        route_after_fetch,
        {
            "analyze_batch": "analyze_batch",
            "fetch_alerts": "fetch_alerts",
        },
    )
    graph.add_conditional_edges(
        "analyze_batch",
        route_after_analysis,
        {
            "fetch_batch": "fetch_batch",
            "fetch_alerts": "fetch_alerts",
        },
    )
    graph.add_conditional_edges(
        "fetch_alerts",
        route_after_alert_fetch,
        {
            "analyze_alerts": "analyze_alerts",
            "final_report": "final_report",
        },
    )
    graph.add_edge("analyze_alerts", "final_report")
    graph.add_edge("final_report", END)

    return graph.compile(checkpointer=checkpointer).with_config(
        {"configurable": {"model": model}, "recursion_limit": 50}
    )
