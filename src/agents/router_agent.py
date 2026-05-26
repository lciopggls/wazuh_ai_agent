import json
import logging
from typing import Any

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.config import get_config

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.rule_generator.rule_generator import get_rule_generator_agent

logger = logging.getLogger(__name__)


def _get_thread_id() -> str:
    try:
        config = get_config()
    except RuntimeError:
        return "default"
    if not isinstance(config, dict):
        return "default"
    configurable = config.get("configurable", {})
    if isinstance(configurable, dict) and configurable.get("thread_id"):
        return str(configurable["thread_id"])
    return "default"


def _get_thread_session(
    session_cache_by_thread: dict[str, dict[str, Any]],
    thread_id: str,
) -> dict[str, Any]:
    """保留这个函数，用于记录主控的最新计划（Plan）和已执行步骤"""
    if thread_id not in session_cache_by_thread:
        session_cache_by_thread[thread_id] = {
            "latest_plan_summary": None,
            "latest_plan_steps": [],
            "executed_steps": [],
            # 注意：删除了写死的内存状态缓存，因为我们将改用 LangGraph 的 checkpointer
        }
    return session_cache_by_thread[thread_id]


def _normalize_message_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        text_parts = []
        for block in content:
            if isinstance(block, dict) and "text" in block:
                text_parts.append(str(block["text"]))
            else:
                text_parts.append(str(block))
        return "".join(text_parts)
    return str(content)


def _extract_latest_ai_content(messages: list[Any] | None) -> str:
    if not messages:
        return ""
    for msg in reversed(messages):
        if getattr(msg, "type", "") == "ai":
            content = _normalize_message_content(getattr(msg, "content", ""))
            if content.strip():
                return content.strip()
        # 兼容字典格式的消息
        elif isinstance(msg, dict) and msg.get("role") == "assistant":
            if msg.get("content"):
                return msg["content"].strip()
    return ""


def _is_high_risk_rule_task(task: str) -> bool:
    high_risk_keywords = [
        "验证", "apply", "应用", "上传", "重启", "restart", 
        "删除", "cleanup", "覆盖", "overwrite", "启用规则", "停用规则",
    ]
    lowered_task = task.lower()
    return any(keyword in task or keyword in lowered_task for keyword in high_risk_keywords)


def _has_explicit_user_authorization(task: str) -> bool:
    approval_markers = [
        "已获用户明确授权", "用户已明确授权", "用户已确认执行", 
        "用户明确同意执行", "已获得用户授权",
    ]
    return any(marker in task for marker in approval_markers)


def _summarize_rule_state(rule_state: dict[str, Any] | None) -> str:
    if not rule_state:
        return "无进行中的规则生成工作流。"

    summary = {
        "has_generated_rule": bool(rule_state.get("generated_rule")),
        "rule_id": rule_state.get("rule_id"),
        "missing_parameters": rule_state.get("missing_parameters"),
        "is_feasible": rule_state.get("is_feasible"),
        "logtest_passed": rule_state.get("logtest_passed"),
        "validation_error": rule_state.get("validation_error"),
        "verification_feedback": rule_state.get("verification_feedback"),
        "latest_reply": _extract_latest_ai_content(rule_state.get("messages")),
    }
    return json.dumps(summary, ensure_ascii=False)


def _summarize_attack_state(attack_state: dict[str, Any] | None) -> str:
    if not attack_state:
        return "无进行中的攻击溯源工作流。"

    summary = {
        "investigation_clue": attack_state.get("investigation_clue"),
        "is_clue_confirmed": attack_state.get("is_clue_confirmed"),
        "pending_question_type": attack_state.get("pending_question_type"),
        "requires_mitre_kb": attack_state.get("requires_mitre_kb"),
        "has_final_report": bool(attack_state.get("final_report")),
        "latest_reply": _extract_latest_ai_content(attack_state.get("messages")),
    }
    return json.dumps(summary, ensure_ascii=False)


def _invoke_specialist(
    specialist_name: str,
    session_cache_by_thread: dict[str, dict[str, Any]],
    specialist_app,
    task: str,
    reset_context: bool,
) -> str:
    thread_id = _get_thread_id()
    session = _get_thread_session(session_cache_by_thread, thread_id)
    
    # 🌟 关键修改 1：构造带有当前 thread_id 的 config
    # 这样子智能体在执行时，就能自动从你传入的 checkpointer 里读写历史记忆了！
    config = {"configurable": {"thread_id": thread_id}}

    # 🌟 关键修改 2：处理上下文重置与组装
    next_state = {}
    
    if reset_context:
        # 如果需要重置，我们传一个空消息列表，并且可以考虑清除该 thread 对应的检查点（可选）
        logger.info(f"Resetting context for specialist {specialist_name} under thread {thread_id}")
        existing_messages = []
    else:
        # 如果不重置，先获取子智能体当前在 checkpointer 里的最新状态
        try:
            current_state = specialist_app.get_state(config)
            existing_messages = list(current_state.values.get("messages", [])) if current_state.values else []
        except Exception:
            existing_messages = []

    # 组装任务输入
    plan_summary = session.get("latest_plan_summary")
    plan_steps = session.get("latest_plan_steps") or []
    if plan_summary:
        step_lines = "\n".join(f"{idx + 1}. {step}" for idx, step in enumerate(plan_steps))
        enriched_task = (
            f"[当前任务计划摘要]\n{plan_summary}\n\n"
            f"[计划步骤]\n{step_lines or '1. 直接执行当前子任务'}\n\n"
            f"[当前执行子任务]\n{task}"
        )
    else:
        enriched_task = task

    existing_messages.append({"role": "user", "content": enriched_task})
    next_state["messages"] = existing_messages

    # 🌟 关键修改 3：调用子智能体时传入 config 激活检查点记忆
    result = specialist_app.invoke(next_state, config=config)
    
    # 记录执行历史到主控 session 缓存
    reply = _extract_latest_ai_content(result.get("messages"))
    session["executed_steps"].append(
        {
            "specialist": specialist_name,
            "task": task,
            "reply": reply or f"{specialist_name} 未返回可展示内容。",
        }
    )

    if specialist_name == "rule_generator":
        state_summary = _summarize_rule_state(result)
    else:
        state_summary = _summarize_attack_state(result)

    return json.dumps(
        {
            "specialist": specialist_name,
            "thread_id": thread_id,
            "task": task,
            "reset_context": reset_context,
            "plan_summary": plan_summary,
            "plan_steps": plan_steps,
            "reply": reply or f"{specialist_name} 未返回可展示内容。",
            "state_summary": json.loads(state_summary),
            "executed_steps": session["executed_steps"],
        },
        ensure_ascii=False,
    )


# 🌟 关键修改 4：让主控图编译函数接收 checkpointer 参数
def get_router_agent(
    router_model: BaseChatModel,
    rule_model: BaseChatModel | None = None,
    attack_model: BaseChatModel | None = None,
    checkpointer=None,  # 注入你的内存/数据库检查点（例如 MemorySaver()）
):
    # 🌟 关键修改 5：把 checkpointer 同步透传给两个子智能体
    rule_agent = get_rule_generator_agent(rule_model or router_model, checkpointer=checkpointer)
    attack_agent = get_attack_attribution_agent(attack_model or router_model, checkpointer=checkpointer)
    
    session_cache_by_thread: dict[str, dict[str, Any]] = {}

    @tool
    def write_task_plan(
        plan_summary: str,
        steps: list[str],
    ) -> str:
        """为当前线程会话记录任务计划..."""
        thread_id = _get_thread_id()
        session = _get_thread_session(session_cache_by_thread, thread_id)
        session["latest_plan_summary"] = plan_summary
        session["latest_plan_steps"] = steps
        session["executed_steps"] = []
        return json.dumps(
            {
                "thread_id": thread_id,
                "plan_summary": plan_summary,
                "steps": steps,
                "message": "任务计划已记录，将按此计划执行。",
            },
            ensure_ascii=False,
        )

    @tool
    def delegate_rule_generator(
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将单个 Wazuh 规则相关子任务委派给 `rule_generator`..."""
        logger.info(
            "Delegating task to rule_generator. reset_context=%s task=%s", reset_context, task
        )
        if _is_high_risk_rule_task(task) and not _has_explicit_user_authorization(task):
            return json.dumps(
                {
                    "specialist": "rule_generator",
                    "thread_id": _get_thread_id(),
                    "task": task,
                    "approval_required": True,
                    "reply": (
                        "当前子任务涉及高风险操作，可能触发规则上传、覆盖、删除或重启 Wazuh manager。"
                        "在执行前必须先取得用户明确授权。"
                    ),
                    "required_user_action": (
                        "请先向用户明确说明风险，并询问是否继续。"
                        "只有在用户明确同意后，后续工具调用才能执行，且任务文本中必须包含“已获用户明确授权”。"
                    ),
                },
                ensure_ascii=False,
            )
        return _invoke_specialist(
            specialist_name="rule_generator",
            session_cache_by_thread=session_cache_by_thread,
            specialist_app=rule_agent,
            task=task,
            reset_context=reset_context,
        )

    @tool
    def delegate_attack_attribution(
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将单个攻击溯源相关子任务委派给 `attack_attribution`..."""
        logger.info(
            "Delegating task to attack_attribution. reset_context=%s task=%s",
            reset_context,
            task,
        )
        return _invoke_specialist(
            specialist_name="attack_attribution",
            session_cache_by_thread=session_cache_by_thread,
            specialist_app=attack_agent,
            task=task,
            reset_context=reset_context,
        )

    system_prompt = """
你是 Wazuh 多智能体总控代理，采用 ReAct 风格工作...
（此处保持学长原有的 system_prompt 不变）
"""

    # 🌟 关键修改 6：主控 Agent 同样需要包裹 checkpointer 
    # 因为 LangChain 的 create_agent 背后也是一个图，支持传入 checkpointer 维护主路由的 ReAct 记忆
    return create_agent(
        model=router_model,
        tools=[write_task_plan, delegate_rule_generator, delegate_attack_attribution],
        system_prompt=system_prompt,
        checkpointer=checkpointer,  # 👈 直接在这里挂载检查点
    )