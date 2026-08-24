import json
import re

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage
from langchain_core.output_parsers import PydanticOutputParser

from .prompt import CONTEXT_TEMPLATE, REPAIR_TEMPLATE, SYSTEM_PROMPT
from .schemas import ScoreCandidate
from .state import ScoringState
from .validation import ScoreValidationError, validate_score_candidate

_REGISTERED_INPUT = re.compile(
    r"\A\s*请对已登记报告进行评分\s*\r?\n"
    r"\s*report_id\s*:\s*(?P<report_id>rpt_[0-9a-f]{32})\s*\Z",
    re.IGNORECASE,
)
_TEMPORARY_INPUT = re.compile(
    r"\A\s*请对以下攻击溯源报告进行评分\s*\r?\n"
    r"\s*test_case_id\s*:\s*(?P<test_case_id>SIM-[0-9]{3})\s*\r?\n"
    r"\s*agent_id\s*:\s*(?P<agent_id>[a-z][a-z0-9_]{1,63})\s*\r?\n"
    r"\s*---BEGIN_FINAL_REPORT---\s*\r?\n"
    r"(?P<final_report>.*?)\r?\n\s*---END_FINAL_REPORT---\s*\Z",
    re.IGNORECASE | re.DOTALL,
)
_INTERNAL_CONTEXT_FIELDS = (
    "final_report",
    "original_input",
    "ground_truth",
    "negative_behavior_catalog",
    "telemetry_boundaries",
    "scoring_standard",
    "report_sha256",
    "input_sha256",
    "standard_sha256",
)


def _message_content(message) -> str:
    content = getattr(message, "content", message)
    if isinstance(content, str):
        return content
    return json.dumps(content, ensure_ascii=False)


def _input_failure(code: str, message: str) -> dict:
    return {
        "status": "failed",
        "final_error": f"{code}: {message}",
        "validation_errors": [message],
    }


def resolve_input_node(state: ScoringState) -> dict:
    """Resolve trusted API context or one of the two fixed Studio inputs."""

    if state.get("input_mode") == "internal" and state.get("report_id"):
        injected_fields = sorted(field for field in _INTERNAL_CONTEXT_FIELDS if field in state)
        if injected_fields:
            return _input_failure(
                "UNTRUSTED_SCORING_CONTEXT",
                "内部评分上下文只能由受控 loader 加载",
            )
        return {"validation_errors": [], "final_error": ""}

    messages = state.get("messages") or []
    human_message = next(
        (message for message in reversed(messages) if isinstance(message, HumanMessage)), None
    )
    if human_message is None:
        return _input_failure("INVALID_STUDIO_INPUT", "缺少 HumanMessage 评分输入")
    content = _message_content(human_message)

    registered_match = _REGISTERED_INPUT.fullmatch(content)
    if registered_match:
        return {
            "input_mode": "registered",
            "report_id": registered_match.group("report_id").lower(),
            "validation_errors": [],
            "final_error": "",
        }

    temporary_match = _TEMPORARY_INPUT.fullmatch(content)
    if not temporary_match:
        return _input_failure(
            "INVALID_STUDIO_INPUT",
            "输入格式无效；请使用已登记 report_id 或固定的完整报告标记格式",
        )
    final_report = temporary_match.group("final_report")
    if not final_report.strip():
        return _input_failure("EMPTY_REPORT", "BEGIN/END 标记之间的最终报告不能为空")
    return {
        "input_mode": "temporary",
        "test_case_id": temporary_match.group("test_case_id").upper(),
        "agent_id": temporary_match.group("agent_id").lower(),
        "final_report": final_report,
        "validation_errors": [],
        "final_error": "",
    }


def load_scoring_context_node(state: ScoringState, context_loader) -> dict:
    """Load scoring-only context; human input cannot supply or override it."""

    try:
        if state.get("input_mode") in {"internal", "registered"}:
            context = context_loader.load_registered(state["report_id"])
        elif state.get("input_mode") == "temporary":
            context = context_loader.load_temporary(
                state["test_case_id"], state["agent_id"], state["final_report"]
            )
        else:
            return _input_failure("INVALID_STUDIO_INPUT", "无法识别评分输入模式")
    except Exception as exc:
        from service.report_scoring.errors import ReportScoringError

        if isinstance(exc, ReportScoringError):
            return _input_failure(exc.code, exc.message)
        return _input_failure("SCORING_CONTEXT_LOAD_ERROR", "无法加载受控评分案例资料")

    return {
        **context.as_state_update(),
        "validation_errors": [],
        "final_error": "",
    }


def prepare_context_node(state: ScoringState) -> dict:
    parser = PydanticOutputParser(pydantic_object=ScoreCandidate)
    telemetry = "\n\n".join(
        f"--- boundary {index + 1} ---\n{boundary}"
        for index, boundary in enumerate(state["telemetry_boundaries"])
    )
    prompt = CONTEXT_TEMPLATE.format(
        final_report=state["final_report"],
        original_input=state["original_input"],
        ground_truth=json.dumps(state["ground_truth"], ensure_ascii=False, indent=2),
        negative_behavior_catalog=json.dumps(
            state["negative_behavior_catalog"], ensure_ascii=False, indent=2
        ),
        telemetry_boundaries=telemetry,
        scoring_standard=state["scoring_standard"],
        format_instructions=parser.get_format_instructions(),
    )
    return {
        "prepared_prompt": prompt,
        "repair_count": 0,
        "validation_errors": [],
        "final_error": "",
    }


def score_report_node(state: ScoringState, model) -> dict:
    message = model.invoke(
        [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=state["prepared_prompt"])]
    )
    return {"raw_output": _message_content(message)}


def validate_score_node(state: ScoringState) -> dict:
    parser = PydanticOutputParser(pydantic_object=ScoreCandidate)
    try:
        candidate = parser.parse(state["raw_output"])
        validated = validate_score_candidate(
            candidate,
            negative_behavior_catalog=state["negative_behavior_catalog"],
        )
    except Exception as exc:
        if isinstance(exc, ScoreValidationError):
            errors = exc.errors
        else:
            errors = [str(exc)]
        return {"validation_errors": errors}
    return {
        "candidate": validated.candidate.model_dump(mode="json"),
        "total_score": validated.total_score,
        "validation_errors": [],
    }


def repair_score_node(state: ScoringState, model) -> dict:
    parser = PydanticOutputParser(pydantic_object=ScoreCandidate)
    prompt = REPAIR_TEMPLATE.format(
        raw_output=state["raw_output"],
        validation_errors="\n".join(f"- {error}" for error in state["validation_errors"]),
        format_instructions=parser.get_format_instructions(),
    )
    message = model.invoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
    return {
        "raw_output": _message_content(message),
        "repair_count": state.get("repair_count", 0) + 1,
    }


def finalize_score_node(state: ScoringState) -> dict:
    candidate = state["candidate"]
    dimensions = (
        ("锚点准确性", "anchor_accuracy"),
        ("证据召回", "evidence_recall"),
        ("时间线", "timeline"),
        ("进程链", "process_chain"),
        ("MITRE 映射", "mitre_mapping"),
        ("负面结论", "negative_findings"),
    )
    dimension_text = "\n".join(
        f"- {label}: {candidate[key]['score']:.1f}" for label, key in dimensions
    )
    strengths = "；".join(candidate.get("strengths") or ["无"])
    issues = "；".join(candidate.get("major_issues") or ["无"])
    summary = (
        f"评分完成，总分 {state['total_score']:.1f}/100。\n"
        f"{dimension_text}\n"
        f"优点：{strengths}\n"
        f"主要问题：{issues}"
    )
    return {
        "status": "succeeded",
        "final_error": "",
        "messages": [AIMessage(content=summary)],
    }


def fail_score_node(state: ScoringState) -> dict:
    errors = state.get("validation_errors") or ["评分候选输出无效"]
    final_error = state.get("final_error") or "; ".join(errors)
    return {
        "status": "failed",
        "final_error": final_error,
        "messages": [AIMessage(content=f"评分失败：{final_error}")],
    }


def route_after_input(state: ScoringState) -> str:
    return "fail" if state.get("final_error") else "continue"


def route_after_validation(state: ScoringState) -> str:
    if not state.get("validation_errors") and state.get("candidate") is not None:
        return "finalize"
    if state.get("repair_count", 0) < 2:
        return "repair"
    return "fail"
