from typing import Annotated, Any, Literal, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field


def merge_kb(left: dict[str, str], right: dict[str, str]) -> dict[str, str]:
    """合并 MITRE 知识库"""
    if not left:
        left = {}
    if not right:
        return left
    new_kb = left.copy()
    new_kb.update(right)
    return new_kb


def merge_executed_queries(
    left: list[dict[str, Any]], right: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """追加已执行查询指纹"""
    if not left:
        left = []
    if not right:
        return left
    return left + right


def merge_graph_data(
    left: dict[str, Any] | None, right: dict[str, Any] | None
) -> dict[str, Any] | None:
    """合并攻击图谱数据，按 id 去重实体、按 (source, target, relation) 去重关系。
    若 right 包含 `_replace: True`，则直接替换而非合并。
    """
    if not left:
        return right
    if not right:
        return left
    if right.get("_replace"):
        return {"entities": right.get("entities", []), "relations": right.get("relations", [])}
    l_entities = left.get("entities", [])
    r_entities = right.get("entities", [])
    l_relations = left.get("relations", [])
    r_relations = right.get("relations", [])

    seen_ids: set[str] = set()
    merged_entities: list[dict[str, Any]] = []
    for e in l_entities + r_entities:
        eid = e.get("id", "")
        if eid and eid not in seen_ids:
            seen_ids.add(eid)
            merged_entities.append(e)

    seen_rels: set[tuple[str, str, str]] = set()
    merged_relations: list[dict[str, Any]] = []
    for r in l_relations + r_relations:
        key = (r.get("source", ""), r.get("target", ""), r.get("relation", ""))
        if key not in seen_rels:
            seen_rels.add(key)
            merged_relations.append(r)

    return {"entities": merged_entities, "relations": merged_relations}


class PlannerActionCommand(BaseModel):
    target: Literal["Simple_Log_Query_Node", "Attribution_Decision_Node"] = Field(
        description="The target node to route to from Planner_Node."
    )
    instruction: str = Field(default="", description="Optional instruction for the target node.")


class DecisionActionCommand(BaseModel):
    target: Literal["User_Input_Node", "Attribution_Planner_Node", "Attribution_Decision_Node"] = (
        Field(description="The target node to route to from Attribution_Decision_Node.")
    )
    instruction: str = Field(default="", description="Optional instruction for the target node.")


class AttributionPlannerActionCommand(BaseModel):
    target: Literal["Log_Retrieval_Node", "MITRE_Expert_Node", "Reporter_Node"] = Field(
        description="The target node to route to from Attribution_Planner_Node."
    )
    instruction: str = Field(
        description="The specific instruction or query to pass to the target node. YOU MUST PROVIDE THIS."
    )


# 状态定义
class AttributionState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]

    # 前端传入的可视化请求，以及本次调查开始时锁定的不可变快照
    visualization_requested: bool | None
    visualization_enabled_for_investigation: bool | None

    # 攻击溯源分析计时（不包含 Reporter_Node 之后的可视化处理）
    analysis_started_at_ns: int | None
    analysis_elapsed_seconds: float | None

    next_action_fromPlannerNode: PlannerActionCommand | None
    next_action_fromDecisionNode: DecisionActionCommand | None
    next_action_fromAttributionPlannerNode: AttributionPlannerActionCommand | None

    # 原始日志暂存
    current_raw_logs: list[dict[str, Any]] | None

    # 已执行查询指纹 (防重复查询)
    executed_queries: Annotated[list[dict[str, Any]], merge_executed_queries]

    # 外部知识库
    mitre_knowledge_base: Annotated[dict[str, str], merge_kb]

    # 报告
    final_report: str | None

    # 是否已完成完整攻击溯源（Reporter_Node 设置）
    is_full_attribution_complete: bool | None

    # 用户自定义配置相关
    investigation_clue: str | None
    is_clue_confirmed: bool | None
    pending_question_type: str | None
    requires_mitre_kb: bool | None

    ## 日志查询默认参数
    default_start_time: str = Field(
        description="调查窗口的起始时间，ISO8601格式 (北京时间/UTC+8)。"
    )
    default_end_time: str = Field(description="调查窗口的结束时间，ISO8601格式 (北京时间/UTC+8)。")
    default_agent_id: str = Field(description="提取到的被攻击 Agent ID (如 '005')。")

    # 可视化展示：SVG攻击时间线图
    svg_chart: str | None

    # 攻击调查概要（JSON dict）
    attack_abstract: dict[str, Any] | None

    # 网状图
    attack_graph: str | None
    attack_graph_data: Annotated[dict[str, Any] | None, merge_graph_data]
