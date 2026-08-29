from functools import partial

from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.graph import END, StateGraph

from .nodes import (
    fail_score_node,
    finalize_score_node,
    load_scoring_context_node,
    prepare_context_node,
    repair_score_node,
    resolve_input_node,
    route_after_input,
    route_after_validation,
    score_report_node,
    validate_score_node,
)
from .state import ScoringState


def get_report_scoring_graph(model: BaseChatModel, context_loader):
    graph = StateGraph(ScoringState)
    graph.add_node("Resolve_Input_Node", resolve_input_node)
    graph.add_node(
        "Load_Scoring_Context_Node",
        partial(load_scoring_context_node, context_loader=context_loader),
    )
    graph.add_node("Prepare_Context_Node", prepare_context_node)
    graph.add_node("Score_Report_Node", partial(score_report_node, model=model))
    graph.add_node("Validate_Score_Node", validate_score_node)
    graph.add_node("Repair_Score_Node", partial(repair_score_node, model=model))
    graph.add_node("Finalize_Score_Node", finalize_score_node)
    graph.add_node("Fail_Score_Node", fail_score_node)

    graph.set_entry_point("Resolve_Input_Node")
    graph.add_conditional_edges(
        "Resolve_Input_Node",
        route_after_input,
        {"continue": "Load_Scoring_Context_Node", "fail": "Fail_Score_Node"},
    )
    graph.add_conditional_edges(
        "Load_Scoring_Context_Node",
        route_after_input,
        {"continue": "Prepare_Context_Node", "fail": "Fail_Score_Node"},
    )
    graph.add_edge("Prepare_Context_Node", "Score_Report_Node")
    graph.add_edge("Score_Report_Node", "Validate_Score_Node")
    graph.add_conditional_edges(
        "Validate_Score_Node",
        route_after_validation,
        {
            "finalize": "Finalize_Score_Node",
            "repair": "Repair_Score_Node",
            "fail": "Fail_Score_Node",
        },
    )
    graph.add_edge("Repair_Score_Node", "Validate_Score_Node")
    graph.add_edge("Finalize_Score_Node", END)
    graph.add_edge("Fail_Score_Node", END)
    return graph.compile()
