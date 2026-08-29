import json
import logging
import re
from typing import Any, Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langgraph.config import get_config

from agents.attack_attribution.attack_attributor import get_attack_attribution_agent
from agents.attack_attribution.utils import (
    extract_agent_ip_mapping,
    format_attribution_report_message,
)
from agents.response_agent import get_response_agent
from agents.rule_agent.rule_agent import get_rule_agent

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


def _get_visualization_requested() -> bool:
    """Read the frontend preference from run config without involving the router model."""
    try:
        config = get_config()
    except RuntimeError:
        return False
    if not isinstance(config, dict):
        return False
    configurable = config.get("configurable", {})
    if not isinstance(configurable, dict):
        return False
    return bool(configurable.get("visualization_requested", False))


def _get_thread_session(
    session_cache_by_thread: dict[str, dict[str, Any]],
    thread_id: str,
) -> dict[str, Any]:
    if thread_id not in session_cache_by_thread:
        session_cache_by_thread[thread_id] = {
            "latest_plan_summary": None,
            "latest_plan_steps": [],
            "executed_steps": [],
            "specialist_state_cache": {
                "rule_agent": None,
                "attack_attribution": None,
                "response_agent": None,
            },
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
    return ""


def _is_high_risk_rule_task(task: str) -> bool:
    high_risk_keywords = [
        "验证",
        "apply",
        "应用",
        "上传",
        "重启",
        "restart",
        "删除",
        "cleanup",
        "覆盖",
        "overwrite",
        "启用规则",
        "停用规则",
    ]
    lowered_task = task.lower()
    return any(keyword in task or keyword in lowered_task for keyword in high_risk_keywords)


ResponseOperation = Literal[
    "block_ip",
    "block_ip_bulk",
    "unblock_ip",
    "query_blocked_ips",
    "block_port",
    "unblock_port",
    "query_blocked_port",
    "query_process",
    "terminate_process",
    "query_local_account",
    "disable_local_account",
    "enable_local_account",
]

_HIGH_RISK_RESPONSE_OPERATIONS = {
    "block_ip",
    "block_ip_bulk",
    "block_port",
    "terminate_process",
    "disable_local_account",
}

_RESPONSE_OPERATION_LABELS = {
    "block_ip": "封禁 IP",
    "block_ip_bulk": "批量封禁 IP",
    "unblock_ip": "解封 IP",
    "query_blocked_ips": "查询 IP 封禁状态",
    "block_port": "封禁端口",
    "unblock_port": "解封端口",
    "query_blocked_port": "查询端口封禁状态",
    "query_process": "查询进程",
    "terminate_process": "终止进程",
    "query_local_account": "查询本地账户",
    "disable_local_account": "禁用本地账户",
    "enable_local_account": "启用本地账户",
}


def _is_high_risk_response_operation(operation: ResponseOperation) -> bool:
    return operation in _HIGH_RISK_RESPONSE_OPERATIONS


def _contains_any(text: str, markers: tuple[str, ...]) -> bool:
    return any(marker in text for marker in markers)


def _infer_response_operations(task: str) -> set[str]:
    """Infer explicit response intents to catch operation/task mismatches."""
    lowered = task.lower()
    is_query = _contains_any(lowered, ("查询", "查看", "检查", "是否", "状态", "query", "check"))
    is_process = _contains_any(lowered, ("进程", "pid", "process", "notepad"))
    is_account = _contains_any(lowered, ("账户", "账号", "用户", "account", "demo_user"))
    is_port = _contains_any(lowered, ("端口", "port", "tcp", "54321"))
    is_ip = bool(re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", lowered)) or _contains_any(
        lowered,
        (" ip", "ip ", "ip地址", "ip 地址", "封禁规则"),
    )
    has_followup = _contains_any(lowered, ("然后", "随后", "再", "并且", "并执行", "接着"))
    is_unblock = _contains_any(
        lowered,
        ("解封", "解除封禁", "撤销封禁", "移除封禁", "unblock", "remove block"),
    ) or bool(re.search(r"(?:解除|撤销|移除).*?封禁", lowered))
    is_block = _contains_any(lowered, ("封禁", "阻断", "block", "ban"))
    is_terminate = _contains_any(lowered, ("终止", "结束进程", "kill", "terminate process"))
    is_disable = _contains_any(lowered, ("禁用", "停用", "disable account"))
    is_enable = _contains_any(
        lowered,
        ("启用", "恢复账户", "解禁账户", "enable account"),
    )

    operations: set[str] = set()
    if is_query:
        if is_process:
            operations.add("query_process")
        elif is_account:
            operations.add("query_local_account")
        elif is_port:
            operations.add("query_blocked_port")
        elif is_ip or is_block:
            operations.add("query_blocked_ips")

    allow_mutation = not is_query or has_followup
    if is_unblock and allow_mutation:
        operations.add("unblock_port" if is_port else "unblock_ip")
    if is_enable and is_account and allow_mutation:
        operations.add("enable_local_account")
    if is_terminate and is_process and allow_mutation:
        operations.add("terminate_process")
    if is_disable and is_account and allow_mutation:
        operations.add("disable_local_account")
    if is_block and not is_unblock and allow_mutation:
        if is_port:
            operations.add("block_port")
        elif is_ip:
            bulk_markers = ("批量", "多个 agent", "多台", "agents", "bulk")
            operation = "block_ip_bulk" if _contains_any(lowered, bulk_markers) else "block_ip"
            operations.add(operation)
    return operations


def _response_operation_task_mismatch(operation: ResponseOperation, task: str) -> str | None:
    inferred = _infer_response_operations(task)
    if not inferred:
        return "任务文本缺少足以识别响应动作的完整参数或动作描述。"

    compatible = {operation}
    if operation in {"block_ip", "block_ip_bulk"}:
        compatible = {"block_ip", "block_ip_bulk"}
    if not inferred & compatible:
        inferred_text = "、".join(sorted(inferred))
        return f"operation={operation} 与任务文本识别出的操作（{inferred_text}）不一致。"
    if len(inferred) > 1:
        inferred_text = "、".join(sorted(inferred))
        return f"单次委派只能包含一个响应动作，当前识别到：{inferred_text}。"
    return None


def _has_explicit_user_authorization(task: str) -> bool:
    approval_markers = [
        "已获用户明确授权",
        "用户已明确授权",
        "用户已确认执行",
        "用户明确同意执行",
        "已获得用户授权",
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
        "is_full_attribution_complete": bool(attack_state.get("is_full_attribution_complete")),
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
    specialist_state_cache = session["specialist_state_cache"]
    current_state = None if reset_context else specialist_state_cache.get(specialist_name)
    next_state = dict(current_state or {})
    existing_messages = list(next_state.get("messages", []))

    if specialist_name == "attack_attribution":
        next_state["visualization_requested"] = _get_visualization_requested()

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

    result = specialist_app.invoke(next_state, {"recursion_limit": 100})
    specialist_state_cache[specialist_name] = result
    session["executed_steps"].append(
        {
            "specialist": specialist_name,
            "task": task,
            "reply": _extract_latest_ai_content(result.get("messages")),
        }
    )

    reply = _extract_latest_ai_content(result.get("messages"))
    if specialist_name == "rule_agent":
        state_summary = _summarize_rule_state(result)
    elif specialist_name == "attack_attribution":
        state_summary = _summarize_attack_state(result)
    else:
        state_summary = "{}"

    artifacts = None
    analysis_elapsed_seconds = (
        result.get("analysis_elapsed_seconds") if specialist_name == "attack_attribution" else None
    )
    if specialist_name == "attack_attribution" and result.get("is_full_attribution_complete"):
        final_report = result.get("final_report")
        if not final_report:
            raise RuntimeError("Completed attack attribution state is missing final_report")
        if analysis_elapsed_seconds is None:
            raise RuntimeError(
                "Completed attack attribution state is missing analysis_elapsed_seconds"
            )
        reply = format_attribution_report_message(final_report, analysis_elapsed_seconds)
        visualization_enabled = result.get("visualization_enabled_for_investigation")
        if visualization_enabled is None:
            # 兼容升级前已存在、尚未写入锁定字段的调查状态。
            visualization_enabled = any(
                result.get(key) is not None
                for key in ("svg_chart", "attack_abstract", "attack_graph")
            )
        if visualization_enabled:
            artifacts = {
                "svg_chart": result.get("svg_chart"),
                "attack_abstract": result.get("attack_abstract"),
                "attack_graph": result.get("attack_graph"),
            }

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
            "artifacts": artifacts,
            "executed_steps": session["executed_steps"],
        },
        ensure_ascii=False,
    )


def get_router_agent(
    router_model: BaseChatModel,
    rule_model: BaseChatModel | None = None,
    attack_model: BaseChatModel | None = None,
    response_model: BaseChatModel | None = None,
    checkpointer=None,
):
    rule_agent = get_rule_agent(rule_model or router_model)
    attack_agent = get_attack_attribution_agent(attack_model or router_model)
    response_agent = get_response_agent(response_model or router_model)
    agent_ip_mapping = extract_agent_ip_mapping()
    agent_ip_mapping_json = (
        json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2) if agent_ip_mapping else "{}"
    )
    session_cache_by_thread: dict[str, dict[str, Any]] = {}

    @tool
    def write_task_plan(
        plan_summary: str,
        steps: list[str],
    ) -> str:
        """为当前线程会话记录任务计划。
        当用户请求包含两个及以上动作时，你必须先调用本工具，再开始执行 specialist 工具。
        `plan_summary` 是一句话总目标，`steps` 是按顺序排列的可执行步骤列表。
        """

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
    def delegate_rule_agent(
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将单个 Wazuh 规则相关子任务委派给 `rule_agent`。
        适用于创建、修改、解释、查询、列出、验证、删除规则，以及查询规则文件、规则组和 requirement 相关规则。一次只处理一个明确子任务。
        如果用户请求包含多个规则动作，请拆分后多次调用本工具。
        当这是一个新的独立规则工作流时，将 `reset_context` 设为 true。
        """

        logger.info("Delegating task to rule_agent. reset_context=%s task=%s", reset_context, task)
        if _is_high_risk_rule_task(task) and not _has_explicit_user_authorization(task):
            return json.dumps(
                {
                    "specialist": "rule_agent",
                    "thread_id": _get_thread_id(),
                    "task": task,
                    "approval_required": True,
                    "reply": (
                        "当前子任务涉及高风险操作，可能触发规则上传、覆盖、删除或重启 Wazuh manager。"
                        "在执行前必须先取得用户明确授权。"
                    ),
                    "required_user_action": (
                        "请先向用户明确说明风险，并询问是否继续。"
                        '只有在用户明确同意后，后续工具调用才能执行，且任务文本中必须包含"已获用户明确授权"。'
                    ),
                },
                ensure_ascii=False,
            )
        return _invoke_specialist(
            specialist_name="rule_agent",
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
        """将攻击溯源或日志查询任务委派给 `attack_attribution`。
        系统会自动判断任务类型：
        - 简单日志查询（如"查询agent001最近1天的日志"）→ 直接返回原始日志
        - 攻击溯源调查（如"调查agent005的告警"）→ 启动完整调查流程
        注意：attack_attribution 内部有自主规划节点，会自行制定具体的调查策略。
        你只需将用户的原始请求原样传入 `task`，不要进一步拆解用户的需求。
        当这是一个新的独立任务时，将 `reset_context` 设为 true。
        """

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

    @tool
    def delegate_response_agent(
        operation: ResponseOperation,
        task: str,
        reset_context: bool = False,
    ) -> str:
        """将事件响应任务委派给 `response_agent`。

        `operation` 必须是 response_agent 的一个明确工具名称，`task` 必须包含完整操作参数。
        封禁 IP、批量封禁 IP、封禁端口、终止进程和禁用账户需要用户明确授权。
        查询、解封 IP、解封端口和启用账户可以直接委派。
        当这是一个新的独立响应任务时，将 `reset_context` 设为 true。
        """

        logger.info(
            "Delegating task to response_agent. operation=%s reset_context=%s task=%s",
            operation,
            reset_context,
            task,
        )
        mismatch_reason = _response_operation_task_mismatch(operation, task)
        if mismatch_reason:
            return json.dumps(
                {
                    "specialist": "response_agent",
                    "thread_id": _get_thread_id(),
                    "operation": operation,
                    "task": task,
                    "error_code": "operation_task_mismatch",
                    "approval_required": False,
                    "reply": "操作类型与任务内容不一致，已拒绝委派。",
                    "error_message": mismatch_reason,
                    "required_user_action": (
                        "请重新生成单一、明确的 operation，并在 task 中保留完整 Agent、目标和时长参数。"
                    ),
                },
                ensure_ascii=False,
            )
        if _is_high_risk_response_operation(operation) and not _has_explicit_user_authorization(
            task
        ):
            operation_label = _RESPONSE_OPERATION_LABELS[operation]
            return json.dumps(
                {
                    "specialist": "response_agent",
                    "thread_id": _get_thread_id(),
                    "operation": operation,
                    "task": task,
                    "approval_required": True,
                    "reply": (
                        f"当前子任务涉及高风险响应操作（{operation_label}），可能改变目标主机状态。"
                        "在执行前必须先取得用户明确授权。"
                    ),
                    "required_user_action": (
                        "请向用户完整说明目标 Agent、操作对象及相关参数并询问是否继续。"
                        '用户确认后，task 必须包含"已获用户明确授权"和全部原始操作参数。'
                    ),
                },
                ensure_ascii=False,
            )
        return _invoke_specialist(
            specialist_name="response_agent",
            session_cache_by_thread=session_cache_by_thread,
            specialist_app=response_agent,
            task=task,
            reset_context=reset_context,
        )

    system_prompt = """
你是 Wazuh 多智能体总控代理，采用 ReAct 风格工作：
1. 先理解用户目标。
2. 如果请求是多步骤任务，先显式生成计划摘要与步骤。
3. 再逐步调用合适工具执行。
4. 观察工具结果后决定下一步，直到任务完成。
5. 最后用中文向用户做整合回复。

══════════════════════════════════════════════════════
Agent → IP 映射表
══════════════════════════════════════════════════════
```json
{agent_ip_mapping_json}
```

- key 为 agent_id，value 为该 Agent 的 IP 地址
- 用户使用 IP 指代 Agent 时，查表解析为 agent_id，优先使用查到的 agent_id 而非 IP 本身

══════════════════════════════════════════════════════
一、可用工具
══════════════════════════════════════════════════════
- `write_task_plan`：为当前线程会话记录任务计划摘要与步骤。多步骤请求必须先调用它。
- `delegate_rule_agent`：处理 Wazuh 规则创建、修改、解释、查询、列出、验证、删除；也处理规则文件、规则组、requirement 相关规则查询。
- `delegate_attack_attribution`：处理攻击溯源、调查、线索确认、报告生成，也支持简单日志查询
  （如关键词搜索、按文件/进程查日志）。系统内部会自动判断任务类型并选择合适的处理路径。
- `delegate_response_agent`：处理 IP、端口、进程和本地账户事件响应动作。

══════════════════════════════════════════════════════
二、通用规则
══════════════════════════════════════════════════════
【任务规划】
  - 对复合请求必须主动拆分，不要只执行其中一步。
  - 只要请求包含两个及以上动作，你必须先调用 `write_task_plan`，明确列出步骤，再开始执行。

【工具调用】
  - 同一轮中可以多次调用同一个工具，也可以先后调用不同工具。
  - 每次工具调用只传一个清晰、可执行的子任务，不要把多个动作塞进一次调用。
  - 如果问题不需要 specialist，直接回答，不要强行调工具。
  - 工具返回的是 specialist 的结果和状态摘要。你要根据这些结果继续规划，而不是机械转述。

【会话管理】
  - 工具按 `thread_id` 自动隔离会话状态。继续同一线程时复用上下文，不同线程之间不得串用。
  - 继续同一 specialist 的上下文时 `reset_context=false`；新独立任务时 `reset_context=true`。

══════════════════════════════════════════════════════
三、委托规则智能体 (delegate_rule_agent)
══════════════════════════════════════════════════════
【任务分类】
  - 只读任务（低风险，无需授权）：规则查询、列出规则、列出规则文件、查看某个规则文件、列出规则组、查询 requirement 相关规则。此类任务通常是新的独立任务，除非用户明确说"继续刚才的查询"，否则 `reset_context=true`。
  - 高风险任务（必须授权）：规则验证、应用、上传、覆盖、删除、清理、重启 Wazuh manager、启用/停用规则。

【任务透传（CRITICAL — 严禁拆分用户输入）】
  当用户提供原始 JSON 日志并要求基于日志生成规则时，你的 `task` 必须传入用户的**完整原始输入**，一字不改、不增不减。
  对 JSON + 指令组合（如 {json日志} 基于该日志生成规则），**整段原样传入**。
  严禁只传 JSON 而丢弃指令，或只传指令而丢弃 JSON。
  不要对 JSON 做任何预处理——不要提取字段、不要重新排版、不要按字段分类整理、不要添加你的理解或注释。
  让 specialist 自己决定怎么做。

【高风险操作授权】
  对上述高风险动作，你必须先向用户说明风险并询问是否继续，获得明确同意后才能执行。
  用户同意后，传入的 `task` 文本中必须包含"已获用户明确授权"这句标记。
  如果忘记先确认，`delegate_rule_agent` 会返回 `approval_required=true`，此时必须停止并向用户征求授权。

【示例：高风险多步骤任务】
  - 用户说“先删除 id 为 100100 的规则，再去验证，最后生成说明”
  你应先说明这包含高风险动作，需要用户确认。
  - 用户确认后，你可以先调用 `write_task_plan(...)` 列出三步，
  再调用 `delegate_rule_agent(task="已获用户明确授权：删除 id 为 100100 的规则", reset_context=true)`，
  然后调用 `delegate_rule_agent(task="已获用户明确授权：验证刚才处理的规则", reset_context=false)`，
  最后调用 `delegate_rule_agent(task="基于前面执行结果生成处理说明", reset_context=false)`，
  再汇总结果。

══════════════════════════════════════════════════════
四、委托攻击溯源 (delegate_attack_attribution)
══════════════════════════════════════════════════════
【任务透传（CRITICAL — 严禁拆分用户输入）】
  attack_attribution 内部有专业的攻击溯源规划节点，会自主制定调查策略。
  当你收到日志查询、搜索或攻击溯源请求时，统一使用本工具。
  你的 `task` 必须传入用户的**完整原始输入**，一字不改、不增不减。
  对 JSON + 指令组合（如 {json日志} 对该日志进行攻击溯源），**整段原样传入**。
  严禁只传 JSON 而丢弃后面的指令，或只传指令而丢弃 JSON——这会导致下游 Planner_Node 误判任务类型。
  不要加工、拆解或细化（如添加 MITRE ID、调查步骤清单、进程追踪方向等）。
  让 specialist 自己决定怎么做。

【原始 JSON 日志透传（CRITICAL）】
  严禁对 JSON 做任何预处理，包括但不限于：提取字段重新排版、将 timestamp 中的 UTC 时间（Z 结尾）转换为北京时间、按字段分类整理、添加你的理解或注释。
  attack_attribution 内部有专门的时区处理逻辑（extract_beijing_time_from_logs），你的任何预处理都会破坏这条链路。

【输出规则】
  A. 线索确认消息透传：
     当 `state_summary` 中 `pending_question_type` 为 "CLUE" 时，说明攻击溯源等待用户确认线索。
     你必须将 `reply` 逐字原样输出给用户，严禁重新排版、总结、提取要点、Markdown 表格或分段概括。
     收到用户回复后将用户原话作为 `task` 传入，`reset_context=false`。

     CLUE 消息样例：
     ┌─────────────────────────────────────────────────
     │ 系统检测到原始日志输入。我为您提取了如下调查线索：
     │
     │ 『Agent 003 触发了 Level 12 的告警（Rule 57100: Suspicious process
     │   execution by wmic.exe）。告警显示进程 wmic.exe (PID 8840) 调用了
     │   cmd.exe (PID 9012) 执行了异常脚本，操作用户为 WORKGROUP\\admin。
     │   时间范围限定在北京时间 2026-03-10 09:15 至 09:35 之间（北京时间）。』
     │
     │ 请问该线索是否符合您的要求？（同意请回复"是"；如需修改请直接指出）
     └─────────────────────────────────────────────────
     → 正确做法：原文一字不改地发给用户。
     → 错误做法：用 Markdown 表格列出"受感染主机 / 告警规则 / 可疑进程 / MITRE 技术"。

  B. 日志查询结果透传：
     当 `reply` 中包含原始 JSON 日志数据（通常以 `[{"` 开头）时，说明这是一次日志查询结果。
     你必须将 `reply` 逐字原样输出给用户。
     严禁提取字段做成表格、按 agent/rule/level 分类汇总、转换为 Markdown、
     或输出"共查询到 N 条日志，涉及多个 agent..."等摘要。
     JSON 中有多少条、多少字段，就完整输出多少。

══════════════════════════════════════════════════════
五、委托事件响应 (delegate_response_agent)
══════════════════════════════════════════════════════
【适用场景】
  response_agent 提供以下操作；调用时 operation 必须使用对应名称：
  - `block_ip` / `block_ip_bulk` / `unblock_ip` / `query_blocked_ips`
  - `block_port` / `unblock_port` / `query_blocked_port`
  - `query_process` / `terminate_process`
  - `query_local_account` / `disable_local_account` / `enable_local_account`

【授权分类】
  以下高风险操作必须先向用户说明完整目标和参数，取得明确授权：
  - block_ip、block_ip_bulk、block_port、terminate_process、disable_local_account

  以下操作可以直接委派：
  - unblock_ip、query_blocked_ips、unblock_port、query_blocked_port
  - query_process、query_local_account、enable_local_account

  用户确认后，task 必须同时包含：
  1. 固定授权标记“已获用户明确授权”；
  2. 原请求中的完整 Agent、IP/端口/PID/账户、方向和时长参数。
  严禁只传“执行刚才操作”之类缺少参数的文本。

【参数与操作一致性】
  - operation 是明确的单一操作类型；task 一次只能包含一个响应动作。
  - operation 必须与 task 中的真实意图一致，否则委派函数会返回
    error_code=operation_task_mismatch，此时不得执行，必须重新生成正确调用。
  - 不得修正、替换或猜测用户给出的 Agent、IP、端口、PID、账户或时长。
  - 即使参数超出白名单，也要原样交给 response_agent，由后端权限校验返回拒绝结果。

【参数说明】
  - operation：上述一个明确的工具名称。
  - task：完整的单一响应任务；高风险操作在用户确认后加授权标记。
  - reset_context：新的、参数完整的任务设为 true；只有用户明确说“继续”“查询刚才”
    “解封刚才”等依赖前文时才设为 false。高风险任务确认后第一次正式委派仍设为 true。

【多步骤响应任务】
  - 两个及以上动作必须先调用 write_task_plan。
  - 将所有高风险动作及完整参数一次性列出并统一征求用户授权。
  - 用户确认后，每个动作分别调用一次 delegate_response_agent。
  - 每个高风险子任务都必须带授权标记和完整参数。
  - 任一步失败后，停止依赖该结果的后续步骤，并汇报已执行、失败和未执行项目。

【结果汇报】
  - response_agent 返回的 reply 是权威执行结果。可以整理格式，但不得改变目标、状态码、
    失败原因或验证证据。
  - reply 中包含“进程处置耗时”或“计时范围”时，最终回复必须原样保留对应字段和值，
    不得省略、改写或重新计算。
  - 不得把 unknown 改写为成功或失败，不得把“命令已投递”改写为“已验证成功”。
  - 多步骤任务必须分别展示每一步结果，不得笼统声称“全部完成”。

【示例：封禁 IP】
  - 用户说"帮我在 agent 006 上封禁 192.168.109.114"
  你应先说明将要封禁的 IP、目标 Agent 和封禁时长（默认 10 分钟），询问用户是否继续。
  - 用户确认后，调用
    `delegate_response_agent(operation="block_ip", task="已获用户明确授权：在 agent 006 上双向封禁 192.168.109.114，持续10分钟", reset_context=true)`，
  然后向用户汇报结果。

【示例：查询已封禁 IP】
  - 用户说"帮我查一下 agent 006 上有哪些 IP 被封了"
  直接调用 `delegate_response_agent(operation="query_blocked_ips", task="查询 agent 006 上已封禁的 IP 列表", reset_context=true)`，
  无需用户授权。

【示例：端口、进程和账户】
  - 这些操作支持任意有效的数字 Agent ID；目标 Agent 必须已部署对应脚本和日志采集配置。
  - 查询 Agent 005 的 54321 端口：operation=query_blocked_port，直接委派。
  - 封禁 Agent 005 的 54321 端口：operation=block_port，先确认 Agent、端口和时长。
  - 查询 Agent 005 的 PID：operation=query_process，直接委派。
  - 终止 Agent 005 的 PID：operation=terminate_process，先确认 Agent 和 PID。
  - 查询 Agent 005 上的 demo_user：operation=query_local_account，直接委派。
  - 禁用 Agent 005 上的 demo_user：operation=disable_local_account，先确认 Agent 和账户。
  - 启用 Agent 005 上的 demo_user：operation=enable_local_account，直接委派。
"""

    system_prompt = system_prompt.replace("{agent_ip_mapping_json}", agent_ip_mapping_json)

    return create_agent(
        model=router_model,
        tools=[
            write_task_plan,
            delegate_rule_agent,
            delegate_attack_attribution,
            delegate_response_agent,
        ],
        system_prompt=system_prompt,
        checkpointer=checkpointer,
    )
