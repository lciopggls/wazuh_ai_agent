import json
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage

from agents.baseline.archive_tools import (
    count_raw_archives_by_time,
    get_raw_archives_by_time,
)
from agents.baseline.baseline_agent_plus.alert_tools import (
    MAX_ALERTS,
    get_nearby_alerts,
)
from agents.baseline.baseline_agent_plus.prompt import (
    ALERT_ANALYSIS_PROMPT,
    BATCH_ANALYSIS_PROMPT,
    FINAL_REPORT_PROMPT,
)
from agents.baseline.baseline_agent_plus.state import BaselinePlusState
from agents.baseline.utils import (
    extract_agent_ids_from_logs,
    extract_beijing_time_from_logs,
)

BATCH_SIZE = 5
MAX_BATCHES = 10
MAX_LOGS = BATCH_SIZE * MAX_BATCHES
BATCH_NOTE_MAX_TOKENS = 1000
ALERT_NOTE_MAX_TOKENS = 1000
FINAL_REPORT_MAX_TOKENS = 12000
NO_ALERTS_SUMMARY = "未查询到符合条件的附近告警。"


def _first_human_text(messages: list[BaseMessage]) -> str:
    for message in messages:
        if isinstance(message, HumanMessage) and isinstance(message.content, str):
            return message.content
    return ""


def _message_text(message: BaseMessage) -> str:
    if isinstance(message.content, str):
        return message.content
    return json.dumps(message.content, ensure_ascii=False)


def _invoke_model(
    model: BaseChatModel,
    messages: list[BaseMessage],
    *,
    max_tokens: int,
) -> str:
    response = model.bind(max_tokens=max_tokens).invoke(messages)
    return _message_text(response)


def prepare_investigation_node(state: BaselinePlusState) -> dict[str, Any]:
    initial_input = _first_human_text(state.get("messages", []))
    time_info = extract_beijing_time_from_logs(initial_input)
    agent_ids = extract_agent_ids_from_logs(initial_input)

    if not initial_input:
        return {"error": "未找到用户提供的初始日志。"}
    if not time_info:
        return {
            "initial_input": initial_input,
            "error": "未能从初始日志的 _source.timestamp 提取带时区的有效时间。",
        }
    if len(agent_ids) != 1:
        return {
            "initial_input": initial_input,
            "error": "必须从初始日志中提取到唯一的 Agent ID。",
        }

    agent_id = agent_ids[0]
    archive_error = None
    try:
        total_logs = count_raw_archives_by_time(
            agent_id=agent_id,
            start_time=time_info["beijing_start"],
            end_time=time_info["beijing_end"],
        )
    except Exception as exc:
        total_logs = 0
        archive_error = f"归档日志统计失败：{exc}"

    return {
        "initial_input": initial_input,
        "agent_id": agent_id,
        "anchor_time": time_info["beijing_anchor"],
        "start_time": time_info["beijing_start"],
        "end_time": time_info["beijing_end"],
        "time_display": time_info["beijing_display"],
        "alert_start_time": time_info["alert_start"],
        "alert_end_time": time_info["alert_end"],
        "total_logs": total_logs,
        "processed_logs": 0,
        "is_truncated": total_logs > MAX_LOGS,
        "batch_number": 0,
        "search_after": None,
        "current_raw_logs": [],
        "batch_notes": [],
        "alert_logs": [],
        "alert_summary": "",
        "selected_alert_count": 0,
        "archive_error": archive_error,
        "alert_error": None,
        "error": None,
    }


def _append_run_statistics(report: str, state: BaselinePlusState) -> str:
    statistics = (
        "---\n\n"
        "运行统计\n\n"
        f"- 查询到的日志总数：{state.get('total_logs', 0)} 条\n"
        f"- 实际调查的日志总数：{state.get('processed_logs', 0)} 条"
    )
    return f"{report.rstrip()}\n\n{statistics}"


def fetch_batch_node(state: BaselinePlusState) -> dict[str, Any]:
    try:
        page = get_raw_archives_by_time(
            agent_id=state["agent_id"],
            start_time=state["start_time"],
            end_time=state["end_time"],
            search_after=state.get("search_after"),
            batch_size=BATCH_SIZE,
        )
    except Exception as exc:
        return {
            "current_raw_logs": [],
            "archive_error": f"归档日志查询失败：{exc}",
        }

    logs = page["logs"]

    if not logs and state.get("processed_logs", 0) < state.get("total_logs", 0):
        return {
            "current_raw_logs": [],
            "archive_error": "分页查询在读取全部归档日志之前提前结束，调查结果不完整。",
        }

    return {
        "current_raw_logs": logs,
        "search_after": page["search_after"],
        "batch_number": state.get("batch_number", 0) + (1 if logs else 0),
    }


def analyze_batch_node(
    state: BaselinePlusState,
    *,
    model: BaseChatModel,
) -> dict[str, Any]:
    batch_number = state["batch_number"]
    logs = state["current_raw_logs"]
    batch_context = {
        "batch_number": batch_number,
        "total_batches": min(
            (state["total_logs"] + BATCH_SIZE - 1) // BATCH_SIZE,
            MAX_BATCHES,
        ),
        "time_range": {
            "start": state["start_time"],
            "end": state["end_time"],
        },
        "logs": logs,
    }
    try:
        note = _invoke_model(
            model,
            [
                SystemMessage(content=BATCH_ANALYSIS_PROMPT),
                HumanMessage(
                    content=(
                        f"初始告警日志：\n{state['initial_input']}\n\n"
                        f"当前批次原始日志：\n"
                        f"{json.dumps(batch_context, ensure_ascii=False)}"
                    )
                ),
            ],
            max_tokens=BATCH_NOTE_MAX_TOKENS,
        )
    except Exception as exc:
        return {
            "current_raw_logs": [],
            "archive_error": f"归档日志批次摘要失败：{exc}",
        }

    return {
        "batch_notes": [*state.get("batch_notes", []), note],
        "processed_logs": state.get("processed_logs", 0) + len(logs),
        "current_raw_logs": [],
    }


def fetch_alerts_node(state: BaselinePlusState) -> dict[str, Any]:
    try:
        alerts, supplement_error = get_nearby_alerts(
            agent_id=state["agent_id"],
            anchor_time=state["anchor_time"],
            start_time=state["alert_start_time"],
            end_time=state["alert_end_time"],
        )
    except Exception as exc:
        return {
            "alert_logs": [],
            "alert_summary": f"附近告警查询失败：{exc}",
            "selected_alert_count": 0,
            "alert_error": f"附近告警查询失败：{exc}",
        }

    if not alerts:
        return {
            "alert_logs": [],
            "alert_summary": NO_ALERTS_SUMMARY,
            "selected_alert_count": 0,
            "alert_error": supplement_error,
        }

    return {
        "alert_logs": alerts,
        "alert_summary": "",
        "selected_alert_count": len(alerts),
        "alert_error": supplement_error,
    }


def analyze_alerts_node(
    state: BaselinePlusState,
    *,
    model: BaseChatModel,
) -> dict[str, Any]:
    alert_context = {
        "time_range": {
            "start": state["alert_start_time"],
            "end": state["alert_end_time"],
        },
        "selection": {
            "maximum_alerts": MAX_ALERTS,
        },
        "alerts": state["alert_logs"],
    }
    try:
        summary = _invoke_model(
            model,
            [
                SystemMessage(content=ALERT_ANALYSIS_PROMPT),
                HumanMessage(
                    content=(
                        f"初始日志（最重要的调查锚点）：\n{state['initial_input']}\n\n"
                        "附近 Wazuh 告警：\n"
                        f"{json.dumps(alert_context, ensure_ascii=False)}"
                    )
                ),
            ],
            max_tokens=ALERT_NOTE_MAX_TOKENS,
        )
    except Exception as exc:
        return {
            "alert_logs": [],
            "alert_summary": f"附近告警摘要失败：{exc}",
            "alert_error": f"附近告警摘要失败：{exc}",
        }

    return {
        "alert_logs": [],
        "alert_summary": summary,
    }


def final_report_node(
    state: BaselinePlusState,
    *,
    model: BaseChatModel,
) -> dict[str, Any]:
    error = state.get("error")
    if error:
        report = (
            "## 事件概览\n\n"
            f"{error}\n\n"
            "## 攻击痕迹与来源分析\n\n未执行日志分析。\n\n"
            "## 攻击时间线与执行流程\n\n未执行日志分析。\n\n"
            "## 总结与建议\n\n请调整固定时间范围或处理上限后重新调查。"
        )
    else:
        archive_context = {
            "agent_id": state["agent_id"],
            "time_range": {
                "display": state["time_display"],
                "start": state["start_time"],
                "end": state["end_time"],
            },
            "total_logs": state["total_logs"],
            "processed_logs": state.get("processed_logs", 0),
            "is_truncated": state.get("is_truncated", False),
            "max_logs": MAX_LOGS,
            "batch_count": state.get("batch_number", 0),
            "archive_error": state.get("archive_error"),
            "batch_notes": state.get("batch_notes", []),
        }
        alert_context = {
            "time_range": {
                "start": state["alert_start_time"],
                "end": state["alert_end_time"],
            },
            "alert_error": state.get("alert_error"),
            "alert_summary": state.get("alert_summary", NO_ALERTS_SUMMARY),
        }
        report = _invoke_model(
            model,
            [
                SystemMessage(content=FINAL_REPORT_PROMPT),
                HumanMessage(
                    content=(
                        f"第一部分——初始日志（绝对核心）：\n{state['initial_input']}\n\n"
                        "第二部分——归档日志调查信息与批次摘要：\n"
                        f"{json.dumps(archive_context, ensure_ascii=False)}\n\n"
                        "第三部分——附近告警摘要：\n"
                        f"{json.dumps(alert_context, ensure_ascii=False)}"
                    )
                ),
            ],
            max_tokens=FINAL_REPORT_MAX_TOKENS,
        )

    report_with_statistics = _append_run_statistics(report, state)
    return {
        "final_report": report_with_statistics,
        "current_raw_logs": [],
        "alert_logs": [],
        "messages": [AIMessage(content=report_with_statistics)],
    }
