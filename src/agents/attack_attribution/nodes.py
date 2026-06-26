import json
import logging
import re
import time
from collections import deque
from pathlib import Path
from typing import Any

import httpx
from langchain.agents import create_agent
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.output_parsers import PydanticOutputParser
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.runnables import RunnableConfig

from .log_retrieval_helper import get_archives_by_eventid, get_archives_by_keyword
from .prompt import attribution_investigation_prompt_long
from .schemas import (
    AttackAbstractModel,
    InitialClueAnalysis,
    QueryIntent,
    SynthesizedFindings,
)
from .state import AttributionPlannerActionCommand, AttributionState
from .utils import (
    _fix_svg_viewbox_height,
    eids_to_investigation,
    extract_beijing_time_from_logs,
    fp_target,
    get_agents_identity,
    load_mitre,
    load_skill,
)

# from .utils import extract_agent_ip_mapping

logger = logging.getLogger(__name__)

CURRENT_DIR = Path(__file__).parent
# SKILL_FILE_PATH = (
#     CURRENT_DIR.parent.parent / "documents" / "skill" / "attribution_skills" / "report_format.md"
# )
SKILL_FILE_PATH_CN = (
    CURRENT_DIR.parent.parent / "documents" / "skill" / "attribution_skills" / "report_format_cn.md"
)
MITRE_KB_FILE_PATH = (
    CURRENT_DIR.parent.parent
    / "documents"
    / "skill"
    / "attribution_skills"
    / "mitre_knowledgebase.md"
)


"""
Nodes:
0. Planner_Node — routes between simple log query and attack attribution
1. Attribution_Decision_Node
2. Attribution_Planner_Node
3. Log_Retrieval_Node
4. Information_Synthesizer_Node
5. MITRE_Expert_Node - optional
6. Reporter_Node
7. User_Input_Node
8. Visualization_Node
9. Simple_Log_Query_Node
10. Attack_Abstract_Node
11. Graph_Filter_Node
12. Attack_Graph_Node
"""


def planner_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 0: Planner Node — determines task type and routes accordingly."""
    logger.info("Executing Planner Node...")

    # 检查是否已有进行中的攻击溯源会话，若是则跳过意图判断直接续接
    if state.get("investigation_clue") or state.get("pending_question_type"):
        logger.info("Ongoing attribution session detected. Routing to Attribution_Decision_Node.")
        return {
            "next_action_fromPlannerNode": {
                "target": "Attribution_Decision_Node",
                "instruction": "",
            },
        }

    messages = state.get("messages", [])
    last_message = messages[-1] if messages else None
    is_human = last_message.type == "human" if last_message else False
    user_text = last_message.content if is_human else ""

    if not is_human or not user_text:
        logger.info("No valid user input. Defaulting to attack attribution.")
        return {
            "next_action_fromPlannerNode": {
                "target": "Attribution_Decision_Node",
                "instruction": user_text,
            },
        }

    query_intent_parser = PydanticOutputParser(pydantic_object=QueryIntent)
    intent_prompt = ChatPromptTemplate.from_messages(
        [
            (
                "system",
                """判断用户输入是"简单日志查询"还是"攻击溯源调查"。

简单日志查询的特征：
- 用户只是想查询/搜索/查看日志，不涉及攻击行为分析、攻击链追踪、溯源归因
- 示例："查询agent001最近1天的日志"、"搜索包含abc.txt的日志"、"查看agent003的进程创建日志"、"agent005最近24小时与mimikatz相关的日志"
- 输入中不包含原始 JSON 日志内容（只有自然语言查询意图）

攻击溯源调查的特征：
- 涉及攻击行为分析、攻击链追踪、溯源归因、安全事件调查
- 示例："对上面的日志进行攻击溯源"、"分析这个安全事件"、"这个告警是什么原因造成的"
- **若输入中包含原始 JSON 日志（大段 {{}} 结构），且同时有"攻击溯源""调查""分析"等指令，必须判定为攻击溯源**

{format_instructions}""",
            ),
            ("human", "{user_text}"),
        ]
    )

    try:
        intent_result = (intent_prompt | model | query_intent_parser).invoke(
            {
                "user_text": user_text,
                "format_instructions": query_intent_parser.get_format_instructions(),
            }
        )
        if intent_result.is_simple_query:
            logger.info("Detected simple log query. Routing to Simple_Log_Query_Node.")
            return {
                "next_action_fromPlannerNode": {
                    "target": "Simple_Log_Query_Node",
                    "instruction": user_text,
                },
            }
    except Exception as e:
        logger.warning("Query intent detection failed, defaulting to attack attribution: %s", e)

    logger.info("Detected attack attribution request. Routing to Attribution_Decision_Node.")
    return {
        "next_action_fromPlannerNode": {
            "target": "Attribution_Decision_Node",
            "instruction": user_text,
        },
    }


def attribution_decision_node(
    state: AttributionState, config: RunnableConfig, model: BaseChatModel
):
    """Node 1: Attribution Decision Node — handles attack attribution clue extraction and routing."""
    logger.info("Executing Attribution Decision Node...")

    is_clue_confirmed = state.get("is_clue_confirmed")
    requires_mitre_kb = state.get("requires_mitre_kb")
    investigation_clue = state.get("investigation_clue")
    pending_type = state.get("pending_question_type")
    messages = state.get("messages", [])

    # 多主机场景相关逻辑已按需求暂时注释/禁用
    multi_host_updates = {}
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}
    # if is_multi_host is None:
    #     agent_ip_mapping = extract_agent_ip_mapping()
    #     is_multi_host = len(agent_ip_mapping) > 1
    # if is_multi_host and not agent_ip_mapping:
    #     agent_ip_mapping = extract_agent_ip_mapping()
    #
    # multi_host_updates = {
    #     "is_multi_host": is_multi_host,
    #     "agent_ip_mapping": agent_ip_mapping,
    # }

    last_message = messages[-1] if messages else None
    is_human = last_message.type == "human" if last_message else False
    user_text = last_message.content if is_human else ""

    parser = PydanticOutputParser(pydantic_object=InitialClueAnalysis)
    format_instructions = parser.get_format_instructions()

    if not is_clue_confirmed:
        if not investigation_clue:
            logger.info("Phase 1: Analyzing initial input...")

            # 代码层提取 fields.@timestamp 并转为北京时间，不再依赖 LLM 判断时区
            precomputed_time = extract_beijing_time_from_logs(user_text)
            time_context = ""
            if precomputed_time:
                time_context = (
                    f"日志事件发生的北京时间为: {precomputed_time['beijing_display']}。\n"
                )

            system_prompt = """
            You are a Cybersecurity Triage Expert.
            Analyze the user's input and extract all relevant security entities.

            A valid clue should describe the alert, the compromised agent, the malicious behavior, and a strict time boundary.
            Example: "Agent 012 触发了 Level 14 的告警（Rule 61532: Suspicious PowerShell execution）。告警显示进程 powershell.exe (PID 5192) 异常执行了编码命令，并在 Public 目录下释放了 payload.exe。请启动攻击溯源调查。时间范围限定在北京时间的 2026年3月25日的 14:00 到 14:20 之间。"

            [INSTRUCTIONS]
            1. Generate the `refined_clue` string:
               - If the input is a raw JSON log: Extract core entities (Agent ID, Rule, PID, File, Time) and rewrite them into a professional attack clue in Chinese.
               - If the input is already a natural language clue: Polish it lightly for professional tone, preserving all original facts. Do not fabricate or add information.
            2. TIME WINDOW (CRITICAL):
               - If the system has pre-extracted a Beijing time window (see below), you MUST use it DIRECTLY for start_time_utc8 and end_time_utc8. Do NOT recalculate or reinterpret the timezone.
               - If NO pre-extracted time window is provided, extract the time from the user's natural language input. Create a 20-minute investigation window (+/- 10 mins) around the stated time.
               - Output into 'start_time_utc8' and 'end_time_utc8' using ISO8601 format with +08:00 suffix (e.g., '2026-04-27T17:15:00+08:00').
               - In ALL cases, append "（北京时间）" to the time boundary in 'refined_clue'.

            {time_context}
            {format_instructions}
            """

            prompt = ChatPromptTemplate.from_messages(
                [("system", system_prompt), ("human", "{user_text}")]
            )

            llm_msg = (prompt | model).invoke(
                {
                    "user_text": user_text,
                    "time_context": time_context,
                    "format_instructions": format_instructions,
                }
            )
            raw_text = getattr(llm_msg, "content", str(llm_msg))

            try:
                analysis = parser.parse(raw_text)
            except Exception as parse_e:
                logger.warning(
                    "Phase 1 parsing failed, triggering repair mechanism. Error: %s", parse_e
                )
                repair_prompt = ChatPromptTemplate.from_messages(
                    [
                        (
                            "system",
                            "Convert the input into exactly one valid JSON object matching this schema.\nCRITICAL OVERRIDE: Return the flat object directly.\n{format_instructions}",
                        ),
                        ("human", "{raw_text}"),
                    ]
                )
                repaired = (repair_prompt | model).invoke(
                    {"raw_text": raw_text, "format_instructions": format_instructions}
                )
                repaired_text = getattr(repaired, "content", str(repaired))
                analysis = parser.parse(repaired_text)

            # 代码预计算的时间优先，覆盖 LLM 输出（消除时区误判）
            if precomputed_time:
                derived_start = precomputed_time["beijing_start"]
                derived_end = precomputed_time["beijing_end"]
            else:
                derived_start = analysis.start_time_utc8
                derived_end = analysis.end_time_utc8

            # 统一要求用户确认，不依赖 LLM 自主判断是否跳过确认
            return {
                **multi_host_updates,
                "investigation_clue": analysis.refined_clue,
                "default_agent_id": analysis.agent_id,
                "default_start_time": derived_start,
                "default_end_time": derived_end,
                "pending_question_type": "CLUE",
                "next_action_fromDecisionNode": {
                    "target": "User_Input_Node",
                    "instruction": "ASK_CLUE",
                },
                "next_action_fromAttributionPlannerNode": None,
            }
        else:
            if is_human and pending_type == "CLUE":
                logger.info("Parsing user feedback on clue...")

                system_prompt = """You are an intent parsing and rewriting assistant.
                Evaluate the user's feedback regarding the 'Original Clue'.
                1. If user agrees/confirms (e.g., '是', 'yes', '确认', 'ok'), output exactly 'AGREE'.
                2. If user wants to modify, rewrite the clue COMPLETELY incorporating their feedback. Output ONLY the new revised clue.

                [CRITICAL REWRITE RULES]
                - ZERO DATA LOSS: You MUST preserve all original details (Agent ID, Rule, PID, filenames, etc.) that the user did NOT ask to change.
                - NO DELTA OUTPUT: Do NOT just output the user's modifications. You MUST output the full, standalone, readable revised clue.
                - NO FILLER: Output ONLY the final revised clue text. Do not add phrases like "已修改：" or "Here is the revised clue:".

                [CONTEXT]
                Original Clue:
                {clue}
                """

                prompt = ChatPromptTemplate.from_messages(
                    [("system", system_prompt), ("human", "{user_text}")]
                )
                result = (prompt | model).invoke(
                    {"clue": investigation_clue, "user_text": user_text}
                )
                intent = result.content.strip()

                if intent.upper() == "AGREE":
                    return {
                        **multi_host_updates,
                        "is_clue_confirmed": True,
                        "pending_question_type": None,
                        "next_action_fromDecisionNode": {"target": "Attribution_Decision_Node"},
                        "next_action_fromAttributionPlannerNode": None,
                    }
                else:
                    logger.info("User modified clue. Re-extracting default parameters...")
                    extract_prompt = ChatPromptTemplate.from_messages(
                        [
                            (
                                "system",
                                "Extract the Agent ID, start_time_utc8, and end_time_utc8 from the following revised clue. Place the revised clue verbatim into refined_clue.\n{format_instructions}",
                            ),
                            ("human", "{intent}"),
                        ]
                    )
                    extract_msg = (extract_prompt | model).invoke(
                        {"intent": intent, "format_instructions": format_instructions}
                    )
                    raw_text = getattr(extract_msg, "content", str(extract_msg))

                    try:
                        analysis = parser.parse(raw_text)
                    except Exception:
                        repair_prompt = ChatPromptTemplate.from_messages(
                            [
                                ("system", "Convert to valid JSON.\n{format_instructions}"),
                                ("human", "{raw_text}"),
                            ]
                        )
                        repaired = (repair_prompt | model).invoke(
                            {"raw_text": raw_text, "format_instructions": format_instructions}
                        )
                        analysis = parser.parse(getattr(repaired, "content", str(repaired)))

                    return {
                        **multi_host_updates,
                        "investigation_clue": intent,
                        "default_agent_id": analysis.agent_id,
                        "default_start_time": analysis.start_time_utc8,
                        "default_end_time": analysis.end_time_utc8,
                        "is_clue_confirmed": False,
                        "next_action_fromDecisionNode": {
                            "target": "User_Input_Node",
                            "instruction": "ASK_CLUE_MODIFIED",
                        },
                        "next_action_fromAttributionPlannerNode": None,
                    }

    if is_clue_confirmed and requires_mitre_kb is None:
        return {
            **multi_host_updates,
            "requires_mitre_kb": True,
            "pending_question_type": None,
            "messages": [AIMessage(content="开启 MITRE 专家知识库辅助攻击溯源调查...")],
            "next_action_fromDecisionNode": {"target": "Attribution_Planner_Node"},
            "next_action_fromAttributionPlannerNode": None,
        }

    logger.info("Initialization complete. Routing to Attribution Planner Node.")
    return {
        **multi_host_updates,
        "next_action_fromDecisionNode": {"target": "Attribution_Planner_Node"},
        "next_action_fromAttributionPlannerNode": None,
    }


def attribution_planner_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """
    Node 2: Attribution Planner Node.
    """
    logger.info("Executing Attribution Planner Node")

    use_mitre = state.get("requires_mitre_kb")
    state.get("investigation_clue", "未提供有效初始线索")

    messages = state.get("messages", [])
    mitre_kb = state.get("mitre_knowledge_base", {})
    executed_queries = state.get("executed_queries") or []
    default_start = state.get("default_start_time", "")
    default_end = state.get("default_end_time", "")
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}
    # agent_ip_mapping_str = (
    #     json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2) if agent_ip_mapping else "{}"
    # )

    attribution_investigation_prompt: str = attribution_investigation_prompt_long

    # --- build query fingerprint history table ---
    if executed_queries:
        rows = [
            "| # | Agent | Target | Investigation | Time Range | Logs |",
            "|---|-------|--------|--------------|------------|------|",
        ]
        for i, q in enumerate(executed_queries, 1):
            agent = q.get("agent", "")
            target = q.get("target", "-")
            investigation = q.get("investigation", "-")
            count = q.get("count", 0)
            start = q.get("start", "")
            end = q.get("end", "")
            time_range = f"{start}~{end}" if start or end else "-"
            rows.append(f"| {i} | {agent} | {target} | {investigation} | {time_range} | {count} |")
        query_history = "\n".join(rows)
    else:
        query_history = "_No queries executed yet._"

    try:
        if mitre_kb:
            kb_paragraphs = []
            for tid, content in mitre_kb.items():
                kb_paragraphs.append(f"【{tid}】 \n{content}")
            kb_str = "\n\n".join(kb_paragraphs)
        else:
            kb_str = "No external knowledge retrieved yet."
    except Exception as e:
        logger.error("Error formatting state context: %s", e)
        kb_str = str(mitre_kb)

    mitre_instructions = ""
    if use_mitre:
        mitre_instructions = """
  - 'MITRE_Expert_Node': Routes to a knowledge base to retrieve specific MITRE ATT&CK technique details.
  - **How to instruct**: Explicitly mention the MITRE ATT&CK ID (e.g., T1059 or T1003.001) in your instruction.
  - **Rule 1 (Explicit SIEM Tags)**: Whenever you encounter a MITRE ATT&CK ID in a raw log's `rule.mitre.id` field, you MUST call this node using that ID, UNLESS it has already been queried.
  - **Rule 2 (Implicit Behaviors - CRITICAL)**: While SIEM labels provide a useful baseline, they can sometimes be incomplete or false positives. You MUST proactively analyze process names, command-line arguments, and systemic behaviors. Use your cybersecurity expertise to independently deduce the true underlying attack techniques and query this node for them, UNLESS they have already been queried.
  - **Rule 3 (Deduplication & State Awareness - ABSOLUTE MANDATORY)**: Before routing to this node, you MUST check the **MITRE Knowledge Base** section in the CURRENT CASE CONTEXT section. If the TID you intend to query is ALREADY listed there, you are STRICTLY FORBIDDEN from calling this node for that exact TID again.
"""

    multi_host_instructions = ""
    # if is_multi_host:
    #     multi_host_instructions = f"""
    #
    # ### MULTI-HOST MODE
    # Agent ID -> IP Mapping (JSON):
    # {agent_ip_mapping_str}
    #
    # Rules:
    # 1. If you need to pivot by an IP address and that IP exists in the mapping, you MUST translate it into the corresponding Agent ID and query that Agent ID.
    # 2. If you see evidence that "Agent A" interacted with "IP B" and IP B maps to "Agent B", you MUST pivot and query Agent B in a subsequent step (do NOT stop after only querying Agent A).
    # 3. You MUST NOT create dead loops. At most one cross-host pivot per planning turn.
    # """

    system_prompt = (
        """\
You are an elite Cybersecurity Chief Attribution Planner.
Your role is to orchestrate a complex attack forensics investigation. You do NOT query
databases directly. Instead, you analyze the intelligence gathered so far and delegate
specific tasks to specialized subordinate nodes.

## YOUR ARSENAL (TARGET NODES)
- 'Log_Retrieval_Node': Routes to a specialized AI agent equipped with Wazuh API tools.
  - **How to instruct**: Provide clear, natural language instructions detailing *what* you
    want to find. You MUST explicitly mention *the Agent ID* in your instruction.
  - *Example*: "Investigate PID 6536 on Agent 005 for File Creation. Apply time range
    2026-03-25T10:00:00Z to 2026-03-25T11:00:00Z."
  - IMPORTANT: The Log_Retrieval_Node will execute exactly what you ask. It will NOT
    automatically translate IP addresses into Agent IDs for you.
- 'Reporter_Node': Routes to the reporting engine to close the case.
  - When to use (STRICT EXHAUSTION TEST): You are STRICTLY FORBIDDEN from choosing this
    node until all applicable checks in the Attack Chain Completeness Verification
    (section 4) have been ATTEMPTED. The key word is ATTEMPTED — if a query returned no
    data, that dimension is exhausted and you can move on.
  - **How to instruct**: Provide a brief narrative summary of the attack chain and key
    findings. This summary will be passed as context to the Reporter, which has its OWN
    strict report format template.
  - **ABSOLUTE PROHIBITION**: You MUST NOT prescribe ANY output format, JSON schema,
    field names (e.g., "scenario_id", "attack_path", "timeline"), section structure, or
    markup requirements in your instruction. The Reporter automatically applies its own
    professional forensic report template. Prescribing a conflicting format will corrupt
    the final report.
{mitre_instructions}\
{multi_host_instructions}\

"""
        + """\
### CURRENT CASE CONTEXT
- **Default Start Time**: {default_start}
- **Default End Time**: {default_end}
- **MITRE Knowledge Base**:
{kb_str}

### QUERY FINGERPRINT HISTORY (READ-ONLY — DO NOT REPEAT)
Every query already executed against Wazuh Indexer is recorded below. Cross-check your
intended query against this table before routing to Log_Retrieval_Node.

{query_history}

"""
        + attribution_investigation_prompt
        + """\
### OUTPUT FORMAT
{format_instructions}
"""
    )

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
        ]
    )

    parser = PydanticOutputParser(pydantic_object=AttributionPlannerActionCommand)
    format_instructions = parser.get_format_instructions()

    MAX_RETRIES = 2
    RETRY_DELAY = 2

    llm_msg = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            if attempt == 0:
                current_model = model
            else:
                logger.warning(
                    "Retry attempt %d/%d: switching to non-streaming mode",
                    attempt,
                    MAX_RETRIES,
                )
                if hasattr(model, "model_copy"):
                    current_model = model.model_copy(update={"streaming": False})
                else:
                    import copy as _copy

                    current_model = _copy.deepcopy(model)
                    current_model.streaming = False

            llm_msg = (prompt | current_model).invoke(
                {
                    "messages": messages,
                    "mitre_instructions": mitre_instructions,
                    "multi_host_instructions": multi_host_instructions,
                    "query_history": query_history,
                    "kb_str": kb_str,
                    "default_start": default_start,
                    "default_end": default_end,
                    "format_instructions": format_instructions,
                }
            )
            break
        except httpx.RemoteProtocolError as e:
            if attempt < MAX_RETRIES:
                logger.warning(
                    "RemoteProtocolError on attempt %d/%d, retrying in %ds: %s",
                    attempt + 1,
                    MAX_RETRIES + 1,
                    RETRY_DELAY,
                    e,
                )
                time.sleep(RETRY_DELAY)
            else:
                raise

    raw_text = getattr(llm_msg, "content", str(llm_msg))

    try:

        # 如果 raw_text 是 JSON 数组，只取第一个元素
        stripped = raw_text.strip()
        if stripped.startswith("["):
            try:
                parsed_array = json.loads(stripped)
                if isinstance(parsed_array, list) and parsed_array:
                    raw_text = json.dumps(parsed_array[0], ensure_ascii=False)
                    logger.warning(
                        "Planner output an array of %d actions. Taking only the first (%s).",
                        len(parsed_array),
                        parsed_array[0].get("target", ""),
                    )
            except json.JSONDecodeError:
                pass

        try:
            result = parser.parse(raw_text)
        except Exception as parse_e:
            logger.warning(
                "Planner initial parsing failed, triggering repair mechanism. Error: %s", parse_e
            )

            repair_prompt = ChatPromptTemplate.from_messages(
                [
                    (
                        "system",
                        "You are repairing a malformed output from an attack forensics planner agent. "
                        "Determine which node the planner intended to route to:\n"
                        "- 'Log_Retrieval_Node': Route here if the raw text describes a log data QUERY to be executed "
                        "(contains parameters like agent, PID, query_type, event_ids, time range, or FETCH DATA blocks). "
                        "The query has NOT been run yet — you MUST route to Log_Retrieval_Node with the query description as instruction.\n"
                        "- 'MITRE_Expert_Node': Route here if the text mentions a MITRE ATT&CK technique ID (Txxxx).\n"
                        "- 'Reporter_Node': Route ONLY if the text explicitly says the investigation is complete and "
                        "wants to generate a final report. Do NOT route here if the text describes a data query.\n\n"
                        "CRITICAL OVERRIDE: You MUST NOT wrap the result in a 'properties' dictionary. Return the flat object directly.\n"
                        "Convert the input into exactly one valid JSON object matching this schema:\n"
                        "{format_instructions}",
                    ),
                    ("human", "{raw_text}"),
                ]
            )
            repaired = (repair_prompt | model).invoke(
                {"raw_text": raw_text, "format_instructions": format_instructions}
            )
            repaired_text = getattr(repaired, "content", str(repaired))
            result = parser.parse(repaired_text)

        logger.info("Planner decision successful. Target: %s", result.target)

        return {
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": {
                "target": result.target,
                "instruction": result.instruction,
            },
        }

    except Exception as final_e:
        logger.error("Error in attribution planner node: %s", final_e)
        return {
            "next_action_fromAttributionPlannerNode": None,
            "messages": [
                AIMessage(
                    content="攻击溯源规划器执行失败，与 LLM 服务器的连接出现异常。请稍后重试。\n"
                    f"错误详情：{final_e}"
                )
            ],
        }


def log_retrieval_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 3: Log Retrieval Node"""
    logger.info("Executing Log Retrieval Node")

    next_action = state.get("next_action_fromAttributionPlannerNode")
    if not next_action or next_action.get("target") != "Log_Retrieval_Node":
        logger.warning("Invalid route to Log Retrieval Node.")
        return {"current_raw_logs": [], "next_action_fromAttributionPlannerNode": None}

    default_agent = state.get("default_agent_id", "未知")
    default_start = state.get("default_start_time", "未知")
    default_end = state.get("default_end_time", "未知")

    instruction = next_action.get("instruction", "")

    tools = [get_archives_by_keyword, get_archives_by_eventid]

    system_prompt = f"""You are an elite Data Access & API Agent for the Wazuh Indexer.
Your primary role is to translate the Chief Planner's natural language investigation instructions into precise Wazuh API queries and fetch raw security telemetry.

### BEHAVIOR → EVENT ID MAPPING (CRITICAL)
The Planner will describe investigation targets in natural language (e.g., "child processes", "file drops", "DNS resolution"). You MUST map these descriptions to the correct `event_ids` using the table below. Choose ALL event_ids groups that match the Planner's described behaviors, but do NOT combine unrelated behaviors into a single call.

| Planner describes...                                 | event_ids | query_type hint (decide based on target entity) |
|------------------------------------------------------|-----------|-------------------------------------------------|
| Process creation — upward / ancestor / who created PID X | ["1"] | PROCESS_ID (PID), FILE_PATH, USER_ACCOUNT |
| Process creation — downward / descendant / what PID X created | ["1"] | PARENT_PROCESS_ID (PID), FILE_PATH, USER_ACCOUNT |
| Network connection, DNS resolution, network logon | ["3","22","4624"] | PID, IP_ADDRESS, PORT, FILE_PATH, USER_ACCOUNT |
| File creation, DLL / module loads | ["7","11"] | PID, FILE_PATH, USER_ACCOUNT |
| Process injection, process access, process tampering (memory) | ["8","10","25"] | PID, FILE_PATH, USER_ACCOUNT |
| Registry key / value modification | ["12","13","14"] | PID, REGISTRY_PATH, FILE_PATH, USER_ACCOUNT |
| Service installation | ["7045"] | SERVICE_NAME, FILE_PATH, USER_ACCOUNT |
| Explicit credential logon (runas / PSRemote) | ["4648"] | PID, FILE_PATH, USER_ACCOUNT, IP_ADDRESS, LOGON_ID |
| Special logon / privilege assignment | ["4672"] | LOGON_ID, SECURITY_ID, USER_ACCOUNT |
| Account management, group membership, user auditing | ["4720","4722","4724","4725","4726","4728","4732","4738","4740","4798","4704","4719"] | USER_ACCOUNT, LOGON_ID, SECURITY_ID |

### TOOL SELECTION LOGIC
- **Use `get_archives_by_eventid`** when the instruction mentions a specific PID, file path, IP, user account, registry path, service name, logon ID, SID, domain name, or any behavior from the mapping table above.
  - The `query_type` parameter is a separate dimension from `event_ids`. Match `query_type` to the entity you are searching FOR (e.g., if searching BY a PID for file creation behavior, use `query_type="PROCESS_ID"` and `event_ids=["7","11"]`).
  - For upward trace ("who created PID X"): `query_type="PROCESS_ID"`, `event_ids=["1"]`.
  - For downward trace ("what did PID X create"): `query_type="PARENT_PROCESS_ID"`, `event_ids=["1"]`.
- **Use `get_archives_by_keyword`** when the instruction asks to search for a raw text string, filename, or IP that does NOT map to any specific structured entity or behavior. Also use it as a fallback (see below).

### AUTO-FALLBACK RULE (CRITICAL)
If `get_archives_by_eventid` returns 0 results or a `search_feedback` message for a PID-based or file-path-based query, you MUST automatically attempt ONE fallback call using `get_archives_by_keyword` with the same PID or filename as the keyword. This catches cases where the relevant logs use non-standard field names or the target does not appear in the expected structured fields.
- If the keyword fallback also returns 0 results, report the `search_feedback` and stop.
- Do NOT perform more than ONE fallback call per Planner instruction.
- Do NOT fall back to keyword if the original query already returned data — the auto-fallback is only for empty results.

### PATH RETRY RULE (FILE & REGISTRY)
If you execute a `FILE_PATH` or `REGISTRY_PATH` query using a full path and the tool returns a `search_feedback` error, you MUST automatically extract the last part of the path (the filename or the specific Key name) and execute a SECOND tool call using ONLY that fragment as the `query_value`.

### DATA HANDLING & ROLE BOUNDARIES (CRITICAL):
You are exclusively a raw data retrieval pipeline. You MUST adhere strictly to these constraints:
1. **ZERO HALLUCINATION**: You MUST NOT generate, simulate, or mock any JSON data.
2. **ZERO MODIFICATION**: When the tool returns the JSON logs, you MUST NOT summarize, filter, analyze, or explain them.
3. **NO EXPANSIVE RETRIES**: Beyond the AUTO-FALLBACK and PATH RETRY rules above, you are a single-shot execution agent.
   - DO NOT remove or expand the time boundaries to search historical data.
   - DO NOT retry with different `query_type` values unless covered by the AUTO-FALLBACK rule.
   - If all attempts (eventid + keyword fallback) return no data, stop and report the `search_feedback`.
4. **RESPONSE FORMAT**:
   - **If data is found**: Respond with a brief confirmation (e.g., "Data successfully retrieved and passed to the next node.") and immediately stop. Leave all analysis to the Information Synthesizer node.
   - **If no data is found**: Output the `search_feedback` message and stop. Leave the tactical pivot decisions to the Chief Planner.

### Query DEFAULT VALUES (CRITICAL):
If the Planner's instruction does NOT explicitly include an Agent ID and/or a time range, you MUST use the following default values when calling tools:
(CRITICAL OVERRIDE: The default times provided below are strictly in Beijing Time / UTC+8)
- Default Agent ID(s) (pass as list, e.g. ["{default_agent}"]): {default_agent}
- Default Start Time: {default_start}
- Default End Time: {default_end}
"""

    agent = create_agent(model, tools, system_prompt=system_prompt)

    logger.info("Dispatching task to Log Retrieval Agent...")
    raw_logs_buffer = []
    new_queries: list[dict[str, Any]] = []

    try:
        result = agent.invoke(
            {"messages": [("human", f"Chief Planner Instruction:\n{instruction}")]}
        )

        pending_tool_calls: dict[str, dict] = {}

        for msg in result["messages"]:
            if isinstance(msg, AIMessage):
                tcs = getattr(msg, "tool_calls", None) or []
                for tc in tcs:
                    tc_id = tc.get("id") if isinstance(tc, dict) else getattr(tc, "id", "")
                    tc_name = tc.get("name") if isinstance(tc, dict) else getattr(tc, "name", "")
                    tc_args = tc.get("args") if isinstance(tc, dict) else getattr(tc, "args", {})
                    if tc_id:
                        pending_tool_calls[tc_id] = {"name": tc_name, "args": tc_args}

            elif isinstance(msg, ToolMessage):
                tc_id = getattr(msg, "tool_call_id", "")
                tc_info = pending_tool_calls.pop(tc_id, None)

                # --- log collection (existing logic) ---
                try:
                    parsed_logs = json.loads(msg.content)

                    if isinstance(parsed_logs, list):
                        raw_logs_buffer.extend(parsed_logs)
                    elif isinstance(parsed_logs, dict) and "search_feedback" not in parsed_logs:
                        raw_logs_buffer.append(parsed_logs)
                    elif isinstance(parsed_logs, dict) and "search_feedback" in parsed_logs:
                        logger.info(
                            "Tool returned search feedback: %s", parsed_logs["search_feedback"]
                        )

                except json.JSONDecodeError:
                    logger.error(
                        "Failed to parse tool observation as JSON. Observation snippet: %s",
                        str(msg.content)[:100],
                    )

                # --- query fingerprint extraction ---
                if tc_info:
                    log_count = 0
                    try:
                        parsed = json.loads(msg.content)
                        if isinstance(parsed, list):
                            log_count = len(parsed)
                        elif isinstance(parsed, dict) and "search_feedback" not in parsed:
                            log_count = 1
                    except (json.JSONDecodeError, TypeError):
                        pass

                    tool_name = tc_info["name"]
                    args = tc_info["args"]

                    agent_arg = args.get("agent_id", "")
                    if isinstance(agent_arg, list):
                        agent_display = ",".join(agent_arg)
                    else:
                        agent_display = str(agent_arg) if agent_arg else ""

                    fp: dict[str, Any] = {
                        "agent": agent_display,
                        "tool": "by_keyword" if "keyword" in tool_name else "by_eventid",
                        "count": log_count,
                        "target": fp_target(tool_name, args),
                    }

                    if "keyword" in tool_name:
                        fp["kw"] = (args.get("keyword") or "")[:120]
                        fp["investigation"] = "Keyword search"
                    else:
                        fp["qtype"] = args.get("query_type", "")
                        fp["qval"] = (args.get("query_value") or "")[:120]
                        fp["eids"] = args.get("event_ids", [])
                        fp["investigation"] = eids_to_investigation(fp["eids"])

                    fp["start"] = (args.get("start_time") or "")[:25]
                    fp["end"] = (args.get("end_time") or "")[:25]

                    new_queries.append(fp)

    except Exception as e:
        logger.error("Agent execution failed: %s", e)

    if raw_logs_buffer:
        logger.info("Log Retrieval successful. Captured %d raw logs.", len(raw_logs_buffer))
    else:
        logger.info("Log Retrieval returned 0 logs.")

    return {"current_raw_logs": raw_logs_buffer, "executed_queries": new_queries}


def information_synthesizer_node(
    state: AttributionState, config: RunnableConfig, model: BaseChatModel
):
    """Node 4: Information Synthesizer Node."""
    logger.info("Executing Information Synthesizer Node")

    raw_logs = state.get("current_raw_logs")
    next_action = state.get("next_action_fromAttributionPlannerNode")
    mitre_kb = state.get("mitre_knowledge_base", {})
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}

    instruction = (
        next_action.get("instruction", "未命名调查任务") if next_action else "未命名调查任务"
    )

    if not raw_logs:
        logger.info("No raw logs provided. Skipping synthesis.")
        failure_feedback = f"""
        针对指令”{instruction}』“的查询未返回任何日志数据，针对该特定维度的线索的查询可能不存在对应的日志。
        可尝试切换至其他行为类型或者查询条件进行查询日志， 以获取更多相关信息。
        """
        return {
            "current_raw_logs": None,
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": None,
            "attack_graph_data": None,
            "messages": [AIMessage(content=failure_feedback)],
        }

    try:
        logs_str = json.dumps(raw_logs[:20], ensure_ascii=False, indent=2)

        if mitre_kb:
            kb_paragraphs = []
            for tid, content in mitre_kb.items():
                kb_paragraphs.append(f"【{tid}】\n{content}")
            kb_str = "\n\n".join(kb_paragraphs)
        else:
            kb_str = "No MITRE context available."
    except Exception as e:
        logger.error("Error formatting logs or KB: %s", e)
        logs_str = str(raw_logs[:20])
        kb_str = str(mitre_kb)

    parser = PydanticOutputParser(pydantic_object=SynthesizedFindings)
    format_instructions = parser.get_format_instructions()

    multi_host_instructions = ""
    # if is_multi_host:
    #     agent_ip_mapping_str = json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2)
    #     multi_host_instructions = f"""
    #
    # ### MULTI-HOST MODE (CRITICAL)
    # You MUST use the Agent ID -> IP mapping to translate IP addresses into Agent IDs when describing cross-host activity. If an IP appears in the logs and exists in the mapping, you MUST explicitly mention the mapped Agent ID.
    #
    # ### MULTI-HOST CONTEXT
    # - **Agent ID -> IP Mapping (JSON)**:
    # {agent_ip_mapping_str}
    # """

    system_prompt = """You are an elite Cybersecurity Information Synthesizer.
Your task is to exhaustively analyze raw JSON logs retrieved by the Data Agent, extract exact Indicators of Compromise (IOCs), and write a definitive tactical summary for the Chief Planner.

### YOUR INPUTS
1. **Original Instruction**: What the Data Agent was asked to look for.
2. **Raw JSON Logs**: The actual data retrieved from the SIEM.
3. **MITRE Knowledge Base**: Threat intelligence to help you correctly label attacker behaviors.

### CRITICAL RULES & STRICT OVERRIDES
1. **Comprehensive Expert Synthesis (Anti-Bias & Zero-Drop)**: Your final extraction MUST be exhaustive. You MUST explicitly include the events of ALL isolated artifacts verified during the hunt. Categorize every event using the precise technical definitions from the MITRE Expert Knowledge, strictly overriding any misleading or generic SIEM alert descriptions.
2. **CRITICAL TIME REQUIREMENT**: You MUST provide a strict chronological timeline in your summary. For EVERY single extracted evidence item, you MUST copy-paste its EXACT timestamp directly from the raw JSON logs (e.g., "2026-03-10T09:32:30.571Z"). Ensure zero temporal hallucinations.
3. **RAW EVIDENCE VAULT (ZERO-LOSS RULE - CRITICAL)**: You MUST NOT summarize away low-level technical evidence. Explicitly extract and preserve exact values, specifically including:
   - **Exact Parameters:** Explicit hex codes (e.g., 0x1f3fff), registry paths, or network ports.
   - **Complete Artifacts:** EVERY single file created or modified, including intermediate/temp files, with full absolute paths.
   - **Raw Execution:** Unredacted, complete command-line arguments and payloads. Do not truncate.
   - **Entity Identifiers:** Exact numerical PIDs, ProcessGuids, or IP addresses for all involved actors and victims.
   - Call Trace & Memory Anomalies: You MUST actively inspect `callTrace` fields (especially in EventID 10). Explicitly extract and highlight any frames originating from unbacked memory, specifically looking for `UNKNOWN` or unmapped memory regions. This is critical for identifying memory injection and shellcode execution.
   *NEVER generalize into vague actions like "accessed a process", "modified the registry", or "dropped files".*
4. **CONFIDENT EXPERT TONE**: When your investigation confirms an attack's execution, state the success affirmatively without using hedging language (e.g., avoid "possibly", "might have").
5. **LANGUAGE**: The `summary` field MUST be written in Chinese".

### DATA EVALUATION RULES (CRITICAL)
1. **TRUST THE TIME**: The provided logs have already passed strict backend time filtering. You MUST NOT calculate timestamps or exclude any log for being "out of bounds" or "outside the time range."
2. **FILTER BY RELEVANCE**: While all logs are temporally valid, you must evaluate their relevance to the attack. You SHOULD exclude or deprioritize logs that are clearly normal system background noise unrelated to the investigation intent.
3. **REPORTING**: Present event times in Beijing Time (UTC+8). Do not comment on whether a log fits the requested time boundaries; focus entirely on its security implications and relationship to the attack trace.

### Lineage & Access Mask Audit (CRITICAL)
Do not automatically classify parent-to-child high-privilege access (e.g., 0x1fffff) as benign. You MUST differentiate based on the execution context:
- **BENIGN (Filter Noise)**: The Source process has a clean, disk-backed `callTrace` (originating from known/signed modules) AND the Target process executes routine, expected commands.
- **MALICIOUS (Extract IOC)**: Classify as malicious if the Source's `callTrace` originates from unmapped or unbacked memory (e.g., `UNKNOWN` frames), OR if the Target child process executes anomalous, high-risk behavior (e.g., system discovery, evasion, credential access), regardless of their parent-child relationship.

### ANTI-HALLUCINATION: OS BACKGROUND NOISE & COM EXECUTIONS (CRITICAL)
Modern Windows architectures (e.g., Start Menu, UWP apps, Windows Terminal) routinely use system broker processes to proxy-launch interactive shells.
- **RuntimeBroker.exe / sihost.exe / svchost.exe**: When you observe these processes launching `powershell.exe`, `cmd.exe`, or `wt.exe` (often with `-Embedding` parameters or via COM calls), DO NOT blindly classify this as malicious "Initial Access" or "COM Hijacking".
- **The Exemption Rule**: Treat `RuntimeBroker.exe -> powershell.exe` as NORMAL user interaction (e.g., the user manually opening a terminal) UNLESS you observe explicit injected memory indicators in the broker, or the spawned shell immediately executes an encoded/malicious payload (e.g., `powershell -enc ...`).

### GRAPH ENTITY & RELATION EXTRACTION (CRITICAL)

In addition to the narrative findings, you MUST populate `graph_entities` and `graph_relations` with structured data for the attack graph.

**Entity ID Convention (STRICT):**
- Process: `proc_<pid>` (e.g., `proc_5324`)
- File: `file_<N>` where N is sequential starting from 1 (e.g., `file_1`, `file_2`)
- IP: `ip_<address>` (e.g., `ip_192.168.1.100`)
- Registry: `reg_<N>` where N is sequential starting from 1 (e.g., `reg_1`)
- User account: `user_<name>` (e.g., `user_Administrator`)
- Other: `other_<N>` where N is sequential starting from 1

**Properties per entity type:**
- process: `{{"pid": <int>, "image": "<exe path>", "command_line": "<cmdline or null>"}}`
- file: `{{"path": "<full file path>"}}`
- ip: `{{"address": "<ip>", "port": <int or null>}}`
- registry: `{{"key_path": "<registry key>", "value_name": "<value or null>"}}`
- user_account: `{{"username": "<name>", "domain": "<domain or null>"}}`
- other: `{{}}` (empty dict)

**Relation types (STRICT — choose exactly one):**
- `create` — spawned child process OR created/wrote a file (creating new entities)
- `modify` — modified a file OR modified a registry key (tampering with existing state)
- `execute` — loaded a DLL OR injected into another process (in-memory payload operations, process→process only)
- `instantiate` — static file was instantiated by the system loader into a running process (file→process only)
- `communicate` — connected to network address OR DNS resolved to IP (network channel establishment)
- `authenticate` — process ran under a user account (credential use / privilege verification)
- `access` — process read/loaded/accessed a file as input data (e.g., encode/decode source, config file, data dump)

**Entity type constraints per relation (CRITICAL — DO NOT violate):**
Use the source entity's `type` and the target entity's `type` to choose the correct relation.
| Source type | Relation | Target type | Description |
|-------------|----------|-------------|-------------|
| process | create | process | spawned a child process |
| process | create | file | created/wrote a file |
| process | modify | file | modified a file |
| process | modify | registry | modified a registry key |
| process | execute | process | injected into / loaded DLL into another process |
| file | instantiate | process | file was instantiated by the system loader into a running process |
| process | communicate | ip | connected to remote address |
| ip | communicate | ip | DNS resolved to IP |
| process | authenticate | user_account | ran under a user account |
| process | access | file | read/loaded/accessed a file as input data |

If the (source_type, target_type) pair does NOT match any row in the above table, DO NOT create a relation between those two entities. For example, process → file with `communicate` is INVALID — use `create` or `modify` instead.

**Rules:**
1. Every entity mentioned in `detailed_findings` MUST appear in `graph_entities`, UNLESS it is obvious system noise (see rule 6).
2. Every observable behavior between entities (process→file, process→IP, process→process, etc.) MUST appear in `graph_relations`.
3. Use the EXACT timestamps from the raw logs. Do not hallucinate timestamps.
4. If no timestamp is available for an entity or relation, set it to `null`.
5. Each entity's `name` should be a human-readable label like `powershell.exe (PID: 5324)` or `cmd.exe (PID: 5508)`. For file entities, use only the filename (e.g., `payload.exe`), full path goes in `properties.path`. For IP entities, use only the address (e.g., `192.168.1.100`), port goes in `properties.port`.
6. **Noise filter (CRITICAL):** Do NOT include entities or relations that are clearly system background noise (e.g., `svchost.exe` routine activity, `RuntimeBroker.exe` launching normal windows, internal-only IPs with no malicious context). If uncertain whether an entity is attack-related or noise, keep it — better to include a borderline entity than drop a real IOC.

### CONTEXT
- **Original Instruction**: {instruction}
- **MITRE Knowledge**:
{kb_str}
{multi_host_instructions}

{format_instructions}

### STRICT OUTPUT SCHEMA FOR `detailed_findings` (CRITICAL FORMATTING)
You MUST structure the `detailed_findings` field using the following generalized Markdown template.

**[FORMAT TEMPLATE]**
### [序号] [事件类型简述]
> **基础信息**
> - **时间**: `timestamp` (UTC+8)  [注：若为连续重复事件，请使用时间范围，例如 "2026-04-27T14:52:04 - 14:52:23"]
> - **事件类型**: [明确描述行为及ID，例如："进程创建 (EventID: 1)" 或 "网络连接 (EventID: 3)"]
> - **触发告警**: [SIEM 规则 ID 及名称]

- **操作主体**: [发起动作的源头，例如：`Image (PID)` 或 `Source IP`]
- **操作对象**: [承受动作的目标，例如：`ChildImage (PID)`、`IP:Port` 或 `Registry_Path`]
- **核心细节*:
  - [按需提取核心参数，如：命令行、协议、权限掩码、服务配置等。如果是命令行，必须使用 ```cmd 包裹]
  - [如果是连续重复事件，请在此处注明 "执行次数: X次"]

- **溯源判定**:
  - **MITRE 映射**: [Txxxx: 技术名称]
  - **初步结论**: [基于客观行为简述该事件的性质与溯源状态。示例：属于系统正常调用的背景噪音 / 确认执行了具有隐蔽特征的恶意载荷 ]

**[DYNAMIC RULES - CRITICAL]**
1. **GLOBAL OMISSION RULE**: If ANY field (e.g., `触发告警`, `操作对象`, `MITRE 映射`) is missing from the logs, logically inapplicable, or lacks definitive evidence, you MUST COMPLETELY OMIT that specific bullet point. DO NOT write "N/A", "不适用", or "None".
2. **ROLE BOUNDARY**: ROLE BOUNDARY (OBJECTIVE ANALYSIS): You are strictly forbidden from forcefully assigning MITRE Tactic IDs or malicious intent to ambiguous system behaviors. BEWARE OF SIEM FALSE POSITIVES: Do not blindly trust SIEM MITRE tags, as they might mislabel normal system activities. You MUST independently evaluate the execution context. Only output `MITRE 映射` if the log explicitly contains a SIEM MITRE tag AND you have independently verified that the malicious intent is undeniable. If the behavior resembles normal system background noise , state it objectively in `初步结论` and completely omit the MITRE mapping, ignoring the inaccurate SIEM tag.
3. **AGGREGATION RULE (CRITICAL)**: If multiple logs describe the EXACT SAME repetitive automated behavior within a short time window (e.g., the same Actor executing the exact same Target/Command like `hostname.exe` or `whoami.exe` multiple times), DO NOT create separate blocks for each log. You MUST aggregate them into a SINGLE block. Represent the `时间` as a range (e.g., "14:52:04 - 14:52:23"), list the distinct PIDs if applicable, and explicitly state the total execution count in the `核心细节` or `初步结论`.
"""

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            ("human", "Here are the raw logs to analyze:\n```json\n{logs_str}\n```"),
        ]
    )

    try:
        logger.info("Synthesizing %d logs...", len(raw_logs))

        llm_msg = (prompt | model).invoke(
            {
                "instruction": instruction,
                "kb_str": kb_str,
                "multi_host_instructions": multi_host_instructions,
                "logs_str": logs_str,
                "format_instructions": format_instructions,
            }
        )

        raw_text = getattr(llm_msg, "content", str(llm_msg))

        try:
            result = parser.parse(raw_text)
        except Exception as parse_e:
            logger.warning(
                "Initial parsing failed, triggering repair mechanism. Error: %s", parse_e
            )

            repair_prompt = ChatPromptTemplate.from_messages(
                [
                    (
                        "system",
                        "Convert the input into exactly one valid JSON object matching this schema.\n"
                        "CRITICAL OVERRIDE: You MUST NOT wrap the result in a 'properties' dictionary. Return the flat object directly.\n"
                        "{format_instructions}",
                    ),
                    ("human", "{raw_text}"),
                ]
            )
            repaired_msg = (repair_prompt | model).invoke(
                {"raw_text": raw_text, "format_instructions": format_instructions}
            )
            repaired_text = getattr(repaired_msg, "content", str(repaired_msg))
            result = parser.parse(repaired_text)

        task_desc = getattr(result, "task_description", "未提取到指令")
        findings = getattr(result, "detailed_findings", "解析完成，未发现异常。")
        graph_entities = getattr(result, "graph_entities", [])
        graph_relations = getattr(result, "graph_relations", [])

        summary = f"【执行指令描述】\n{task_desc}\n\n【调查总结与IOC清单】\n{findings}"

        logger.info("Synthesis complete. Structured note generated.")

        return {
            "current_raw_logs": None,
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": None,
            "attack_graph_data": (
                {
                    "entities": [e.model_dump() for e in graph_entities],
                    "relations": [r.model_dump() for r in graph_relations],
                }
                if graph_entities or graph_relations
                else None
            ),
            "messages": [AIMessage(content=summary)],
        }

    except Exception as e:
        logger.error("Error during synthesis (even after repair): %s", e)
        return {
            "current_raw_logs": None,
            "next_action_fromDecisionNode": None,
            "next_action_fromAttributionPlannerNode": None,
            "attack_graph_data": None,
            "messages": [
                AIMessage(
                    content=f"[审查官汇报] 针对指令『{instruction}』的日志解析失败。异常信息: {e}"
                )
            ],
        }


def mitre_expert_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 5: MITRE Expert Node."""
    logger.info("Executing MITRE Expert Node")

    next_action = state.get("next_action_fromAttributionPlannerNode")
    instruction = next_action.get("instruction", "") if next_action else ""
    technique_ids = re.findall(r"T\d{4}(?:\.\d{3})?", instruction.upper())

    new_knowledge = {}
    existing_kb = state.get("mitre_knowledge_base", {})

    messages_to_append = []

    if not technique_ids:
        logger.warning("No MITRE ID found in the instruction: %s", instruction)
        messages_to_append.append(
            AIMessage(
                content="[MITRE Query Info] 指令中未包含有效的 Txxxx 编号，无法执行查询。请重新检查指令。"
            )
        )
    else:
        unique_ids = list(set(technique_ids))

        for tid in unique_ids:
            if tid in existing_kb:
                logger.info("MITRE ID %s is already in the global knowledge base. Skipping.", tid)
                messages_to_append.append(
                    AIMessage(
                        content=f"[MITRE Query Info] 战术 {tid} 已存在于底层知识库中，无需重复查询。"
                    )
                )
                continue

            logger.info("Obtaining knowledge from MITRE KB for: %s", tid)
            try:
                knowledge = load_mitre(MITRE_KB_FILE_PATH, tid)
                if knowledge:
                    new_knowledge[tid] = f"--- External Knowledge FOR {tid} ---\n{knowledge}"
                    messages_to_append.append(
                        AIMessage(
                            content=f"[MITRE Query Info] 已成功提取并加载战术 {tid} 的情报，底层知识库已更新。"
                        )
                    )
                else:
                    new_knowledge[tid] = (
                        f"No detailed expert guidelines found for {tid}. Please proceed using your general cybersecurity knowledge."
                    )
                    messages_to_append.append(
                        AIMessage(
                            content=f"[MITRE Query Info] 本地知识库中未找到战术 {tid} 的详细情报。"
                        )
                    )
            except Exception as e:
                logger.error("Error retrieving MITRE KB for %s: %s", tid, e)
                new_knowledge[tid] = f"Failed to retrieve knowledge for {tid} due to system error."
                messages_to_append.append(
                    AIMessage(content=f"[MITRE Query Info] 提取战术 {tid} 时发生系统级异常。")
                )

    if new_knowledge:
        logger.info("Successfully retrieved knowledge for %s techniques.", len(new_knowledge))

    return {
        "mitre_knowledge_base": new_knowledge,
        "next_action_fromAttributionPlannerNode": None,
        "messages": messages_to_append,
    }


def reporter_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 6: Reporter Node."""
    logger.info("Executing Reporter Node: Formatting the final report...")

    next_action = state.get("next_action_fromAttributionPlannerNode")
    mitre_kb = state.get("mitre_knowledge_base", {})
    messages = state.get("messages", [])
    initial_clue = state.get("investigation_clue", "未记录初始线索。")
    # 多主机场景相关逻辑已按需求暂时注释/禁用
    # is_multi_host = state.get("is_multi_host")
    # agent_ip_mapping = state.get("agent_ip_mapping") or {}

    draft_instruction = (
        next_action.get(
            "instruction",
            "Summarize the investigation findings and generate an attack attribution report.",
        )
        if next_action
        else "Summarize the investigation findings and generate an attack attribution report."
    )

    investigation_notes_list = []
    for msg in messages:
        if msg.type == "ai" and "【调查总结与IOC清单】" in msg.content:
            investigation_notes_list.append(msg.content)

    if investigation_notes_list:
        investigation_notes = "\n\n---\n\n".join(investigation_notes_list)
    else:
        investigation_notes = "No detailed investigation notes found in the history."

    skill_data = load_skill(SKILL_FILE_PATH_CN)
    format_rules = (
        skill_data.get("content")
        or "Please generate a structured and professional forensic report."
    )

    multi_host_instructions = ""
    multi_host_section = ""
    # if is_multi_host:
    #     agent_ip_mapping_str = json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2)
    #     multi_host_instructions = f"""
    #
    # **CRITICAL RULE 6 (MULTI-HOST MAPPING)**: You MUST use the provided Agent ID -> IP mapping to translate any referenced IP addresses into the corresponding Agent IDs in your narrative (e.g., "10.0.0.2 (Agent 002)"). Do NOT invent mappings.
    # """
    #     multi_host_section = (
    #         "### MULTI-HOST MODE\n"
    #         f"Agent ID -> IP Mapping (JSON):\n{agent_ip_mapping_str}\n\n"
    #     )

    reporter_system_prompt = """You are a highly professional Cyber Security Technical Writer.
Your task is to take the raw investigation findings provided by the Forensic Detective and format them into a strict, highly polished Attack Attribution Investigation Report (攻击溯源调查报告).

**CRITICAL RULE 1 (Language)**: You MUST generate the entire final report in Simplified Chinese (简体中文). Please translate the narrative and analysis into natural, professional Chinese cybersecurity terminology. However, you MUST keep exact entities (such as PIDs, IP addresses, exact filenames, ProcessGuids, and specific command-line arguments) in their original format.
**CRITICAL RULE 2 (Factuality)**: You MUST NOT hallucinate, invent, or add any new facts or PIDs. Use ONLY the information provided in the Investigation Notes.
**CRITICAL RULE 3 (Temporal Accuracy)**: You MUST NOT alter, format, or hallucinate any dates or timestamps. Copy the EXACT timestamps provided in the raw findings.
**CRITICAL RULE 3.5 (Process Tree Format)**: The process tree MUST be plain-text ASCII using `└──`/`├──`/`│`. **NO Mermaid, no code fences, no structured formats.** This overrides any default tendency to output Mermaid for tree structures.
**CRITICAL RULE 4 (Zero-Loss Formatting - CRITICAL)**: You MUST preserve ALL granular technical evidence provided by the Detective. You are STRICTLY FORBIDDEN from summarizing or abstracting low-level details. You MUST seamlessly integrate exact technical parameters (e.g., hex codes, ports, registry paths), complete file paths/names, unredacted command-line arguments, and exact entity IDs (PIDs, IPs, Guids) into your professional narrative. Do NOT use vague generalizations like "accessed a process", "dropped malicious files", or "executed a script".
**CRITICAL RULE 5 (KNOWLEDGE OVERRIDE & AUDIT - ABSOLUTE PRIORITY)**: The Forensic Detective's Investigation Notes represent preliminary analysis. They may occasionally misinterpret native OS behaviors, engine initializations, or benign system noise as malicious tactics. You act as the final QA Auditor. You MUST cross-reference all reported behaviors against the provided `MITRE TACTICS CONTEXT`. If the Detective's qualitative classification conflicts with the specific exclusions, false-positive warnings, or strict definitions outlined in the MITRE KB, the MITRE KB takes absolute precedence. You MUST autonomously correct any misclassifications and apply the MITRE KB's definitive judgment in your final report.
**CRITICAL RULE 6 (ATTACK LOGIC MATCHING & ORPHAN FILTERING — ABSOLUTE PRIORITY)**:
The report MUST only contain content causally linked to the trigger source defined in
`INITIAL TRIGGER`. Before including ANY process, event, or artifact in ANY section of
the report (PROCESS EXECUTION TREE, ATTACK TIMELINE & EXECUTION FLOW, ATTACK ARTIFACTS,
or SUMMARY), you MUST apply the following causal connection test. If an artifact is
excluded by this rule, it MUST NOT appear anywhere in the report.

  1. **Identify the trigger source** from `INITIAL TRIGGER`: extract the specific
     alerting process (name + PID if available), the compromised agent, and the
     malicious behavior described. This is the root of the attack chain you are
     investigating.

  2. **For each candidate process/event**: verify it has a causal link to the trigger
     source. A causal link is established by ANY of the following:
     a) **Process lineage**: the candidate is an ancestor or descendant of the trigger
        process via ParentProcessId chain.
     b) **IPC interaction**: the candidate has documented process injection, process
        access, or process tampering FROM or TO a trigger-chain process.
     c) **Resource interaction**: the candidate operates on the SAME file path, SAME
        registry key, or SAME network endpoint as a trigger-chain process.

  3. **Orphan filtering — EXCLUDE (HARD)**. A process that fails ALL three causal tests
     above is an orphan and MUST be excluded, along with all of its descendants.
     Typical orphan patterns:
     - explorer.exe 直接派生的孤立 PowerShell/Cmd 进程，与触发链无任何交互
     - WmiPrvSE.exe / svchost.exe / taskhostw.exe 派生的独立进程，与触发链无交互
     - 与触发链仅有时间重叠但无进程血缘、IPC、资源交互的独立执行流

  4. **INCLUDE**:
     - All processes/artifacts directly in the causal lineage of the trigger chain.
     - In incomplete log scenarios, a process that shares the same user context + close
       time window + consistent command pattern with confirmed trigger-chain processes
       may be treated as "probably linked" and included with an explanatory note — do
       NOT drop evidence due to log gaps.
     - A causally-linked process with no children and no side effects is still valid
       evidence — isolation does not make it an orphan.

### RESPONSE FORMAT (攻击溯源调查报告)
{format_rules}
{multi_host_instructions}
"""

    try:
        if mitre_kb:
            kb_paragraphs = []
            for tid, content in mitre_kb.items():
                kb_paragraphs.append(f"【{tid}】\n{content}")
            kb_str = "\n\n".join(kb_paragraphs)
        else:
            kb_str = "No MITRE context available."
    except Exception as e:
        logger.error("Error formatting vault or KB: %s", e)
        kb_str = str(mitre_kb)

    human_prompt = (
        "### INITIAL TRIGGER (THE STARTING POINT)\n"
        "{initial_clue}\n\n"
        "{multi_host_section}"
        "### CHIEF PLANNER's DRAFT & NARRATIVE FOCUS\n"
        "{draft_instruction}\n\n"
        "### INVESTIGATION NOTES (THE HARD FACTS - DO NOT LOSE ANY DETAILS)\n"
        "{investigation_notes}\n\n"
        "### MITRE TACTICS CONTEXT (For your reference to sound professional)\n"
        "{kb_str}\n\n"
        "Please synthesize the above intelligence and format it exactly according to the requested Report Format."
    )

    prompt_template = ChatPromptTemplate.from_messages(
        [("system", reporter_system_prompt), ("human", human_prompt)]
    )

    logger.info("Generating final report...")
    try:
        reporter_chain = prompt_template | model
        final_report_msg = reporter_chain.invoke(
            {
                "format_rules": format_rules,
                "initial_clue": initial_clue,
                "multi_host_instructions": multi_host_instructions,
                "multi_host_section": multi_host_section,
                "draft_instruction": draft_instruction,
                "investigation_notes": investigation_notes,
                "kb_str": kb_str,
            }
        )

        logger.info("Final report generated successfully.")

        return {
            "final_report": final_report_msg.content,
            "is_full_attribution_complete": True,
            "next_action_fromAttributionPlannerNode": None,
            "messages": [AIMessage(content=f"报告已生成完毕。\n\n{final_report_msg.content}")],
        }
    except Exception as e:
        logger.error("Error generating final report: %s", e)
        return {
            "next_action_fromAttributionPlannerNode": None,
            "messages": [AIMessage(content=f"报告生成失败，发生异常: {e}")],
        }


def user_input_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 7: User Input Node."""
    logger.info("Executing User Input Node (Suspending...)")

    next_action = state.get("next_action_fromDecisionNode")
    instruction = next_action.get("instruction") if next_action else ""
    clue = state.get("investigation_clue", "")

    if instruction == "ASK_CLUE":
        return {
            "messages": [
                AIMessage(
                    content=f"系统检测到原始日志输入。我为您提取了如下调查线索：\n\n『{clue}』\n\n请问该线索是否符合您的要求？（如果您同意，请回复“是”；如需修改时间范围等信息，请直接指出）"
                )
            ],
            "next_action_fromDecisionNode": None,
        }
    elif instruction == "ASK_CLUE_MODIFIED":
        return {
            "messages": [
                AIMessage(
                    content=f"已根据您的意见修改线索如下：\n\n『{clue}』\n\n请问现在的线索是否符合您的要求？"
                )
            ],
            "next_action_fromDecisionNode": None,
        }
    # elif instruction == "ASK_MITRE":
    #     return {
    #         "messages": [
    #             AIMessage(
    #                 content="调查线索已锁定。为了更精准地识别攻击手法，您是否希望开启 MITRE 专家知识库辅助分析？(输入是或否)"
    #             )
    #         ],
    #         "next_action_fromDecisionNode": None,
    #     }

    return {"next_action_fromDecisionNode": None}


def visualization_node(state: AttributionState, config: RunnableConfig, model):
    """Node 8: Visualization Node (SVG Flowchart)."""
    logger.info("Executing Visualization Node: Generating SVG chart...")

    final_report = state.get("final_report")
    if not final_report:
        logger.warning("No final report found. Skipping visualization.")
        return {
            "svg_chart": None,
            "messages": [AIMessage(content="[Visualizer] 缺少最终报告，无法生成攻击拓扑图。")],
        }

    visualizer_system_prompt = """You are a Cybersecurity Visualization Agent operating as a specialized node within an automated incident response workflow. Your sole objective is to convert the `ATTACK TIMELINE & EXECUTION FLOW` section of an upstream forensic report into a highly accurate, structured SVG vector graphic representing a vertical timeline.

**Instructions:**
1. **Extract Core Elements (Zero-Loss Formatting):** Parse the input text and extract the exact Timestamp, MITRE ATT&CK T-code (e.g., T1059.003), executing process, and the specific malicious action. Preserve all technical indicators (PIDs, paths, arguments) perfectly.
2. **MITRE Tag Format:** ALWAYS use the format `[T-code / English Technique]`. Example: `[T1059.003 / Windows Command Shell]`. The MITRE tag MUST be placed on its own line BELOW the timestamp line, NOT on the same line as the timestamp.
3. **SVG Structure & Canvas (CRITICAL — DYNAMIC HEIGHT):**
   - Create a `<svg>` tag with `xmlns="http://www.w3.org/2000/svg"` and `viewBox="0 0 1000 DYNAMIC_TOTAL_HEIGHT"`.
   - **HEIGHT CALCULATION (STEP BY STEP):**
     a) For EACH event, estimate its content depth first:
        - Count how many distinct text blocks it has (timestamp line, MITRE tag line, description paragraph, command-line code block, etc.).
        - For each additional code block or wrapped long line beyond the basic 3 (timestamp + MITRE + description), add 35px of extra height.
        - Each event height = **90 + (extra_blocks * 35) + 20 padding**. Minimum 130px per event.
     b) Y position: **DO NOT use a fixed increment.** Start at `y = 50` for the first event. For event N, `y = previous_event_y + previous_event_height + 30 (gap)`.
     c) After placing all events, compute `total_height = last_event_y + last_event_height + 80 (bottom margin)`.
     d) Set `viewBox="0 0 1000 {{total_height}}"`.
     e) Extend the timeline line (`y2`) to `last_event_center_y + (last_event_height / 2) + 20`.
4. **Vertical Timeline Layout:** Draw a vertical connecting line at `x="50"`. Place a circle at each event's center Y. Position `foreignObject` at `x="80"`.
5. **Text Wrapping:** Use `<foreignObject>` with `<div xmlns="http://www.w3.org/1999/xhtml">`. Do NOT set a fixed `height` on the foreignObject — let it expand naturally, or set `height` equal to your estimated event height. Do NOT use `overflow: hidden` or `overflow-y: auto` on the div.
6. **Visual Styling:**
    - Standard events: light blue/gray borders and backgrounds.
    - Malicious events: light red backgrounds and red borders.
    Apply the malicious style to nodes representing explicit malicious actions, payload downloads, or credential dumping.
7. **Output Format:** Output strictly the raw `<svg>...</svg>` XML code block.
8. **FINAL CHECK (CRITICAL):** After generating the SVG, verify: the bottom of the LAST event's foreignObject + 80px margin MUST be ≤ viewBox height. If it exceeds, increase the viewBox height accordingly before outputting.

**Example Input (ATTACK TIMELINE & EXECUTION FLOW):**
- **[2026-04-27 14:52:23.194]** - **[Execution / T1059.003]**: powershell.exe (PID: 5324) 创建 cmd.exe (PID: 5508)，触发告警。命令行: cmd.exe /c C:\\AtomicRedTeam\\atomics\\..\\ExternalPayloads\\nanodump.x64.exe --silent-process-exit "%temp%\\SilentProcessExit"
- **[2026-04-27 14:52:23.195]** - **[Credential Access / T1003.001]**: cmd.exe 启动 nanodump.x64.exe (PID: 13116) 转储 LSASS 内存。

**Example Output:**
```xml
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 580" width="100%" height="100%">
    <style>
        .timeline-line {{ stroke: #cbd5e1; stroke-width: 4px; }}
        .node-dot {{ fill: #3b82f6; stroke: #fff; stroke-width: 2px; }}
        .node-dot-malicious {{ fill: #ef4444; stroke: #fff; stroke-width: 2px; }}
        .title {{ font-family: sans-serif; font-size: 18px; font-weight: bold; fill: #1e293b; }}
    </style>

    <text x="50" y="30" class="title">攻击时间线与执行流程</text>
    <line x1="50" y1="50" x2="50" y2="560" class="timeline-line" />

    <!-- Event 1 — 4 text blocks (timestamp + MITRE + desc + cmdline) → 90+35+20=145, use 180 -->
    <circle cx="50" cy="140" r="8" class="node-dot" />
    <foreignObject x="80" y="50" width="850" height="180">
        <div xmlns="http://www.w3.org/1999/xhtml" style="border: 1px solid #cbd5e1; background: #f8fafc; border-radius: 6px; padding: 12px; font-family: sans-serif; box-sizing: border-box;">
            <div style="margin-bottom: 6px;">
                <span style="font-family: monospace; color: #64748b; font-size: 13px;">[2026-04-27 14:52:23.194]</span>
            </div>
            <div style="margin-bottom: 8px;">
                <strong style="color: #0f172a; font-size: 14px;">[T1059.003 / Windows Command Shell]</strong>
            </div>
            <div style="font-size: 14px; color: #334155; margin-bottom: 6px; line-height: 1.4;">powershell.exe (PID: 5324) 创建 cmd.exe (PID: 5508)，触发告警。</div>
            <div style="font-family: monospace; font-size: 12px; color: #64748b; word-wrap: break-word; background: #e2e8f0; padding: 4px 8px; border-radius: 4px;">命令行: cmd.exe /c C:\\AtomicRedTeam\\atomics\\..\\ExternalPayloads\\nanodump.x64.exe --silent-process-exit "%temp%\\SilentProcessExit"</div>
        </div>
    </foreignObject>

    <!-- Event 2 — 3 text blocks (timestamp + MITRE + desc) → 90+0+20=110, use 130 -->
    <!-- Y = 50 + 180 + 30 = 260 -->
    <circle cx="50" cy="325" r="8" class="node-dot-malicious" />
    <foreignObject x="80" y="260" width="850" height="130">
        <div xmlns="http://www.w3.org/1999/xhtml" style="border: 2px solid #ef4444; background: #fee2e2; border-radius: 6px; padding: 12px; font-family: sans-serif; box-sizing: border-box;">
            <div style="margin-bottom: 6px;">
                <span style="font-family: monospace; color: #64748b; font-size: 13px;">[2026-04-27 14:52:23.195]</span>
            </div>
            <div style="margin-bottom: 8px;">
                <strong style="color: #991b1b; font-size: 14px;">[T1003.001 / LSASS Memory]</strong>
            </div>
            <div style="font-size: 14px; color: #7f1d1d; line-height: 1.4;">cmd.exe 启动 nanodump.x64.exe (PID: 13116) 转储 LSASS 内存。</div>
        </div>
    </foreignObject>
</svg>
"""

    human_prompt = "Here is the Upstream Forensic Report. Please locate the specific section titled '#### **ATTACK TIMELINE & EXECUTION FLOW**', extract the chronological events from that section only, and convert them into a vertical SVG timeline:\n\n{final_report}"

    prompt_template = ChatPromptTemplate.from_messages(
        [("system", visualizer_system_prompt), ("human", human_prompt)]
    )

    try:
        visualizer_chain = prompt_template | model
        result = visualizer_chain.invoke({"final_report": final_report})

        raw_content = result.content
        if isinstance(raw_content, list):
            text_parts = []
            for block in raw_content:
                if isinstance(block, dict) and "text" in block:
                    text_parts.append(block["text"])
                elif isinstance(block, str):
                    text_parts.append(block)
            raw_content = "".join(text_parts)
        elif not isinstance(raw_content, str):
            raw_content = str(raw_content)

        match = re.search(r"(<svg.*?>.*?</svg>)", raw_content, re.DOTALL | re.IGNORECASE)
        if match:
            svg_code = match.group(1).strip()
        else:
            svg_code = re.sub(
                r"^```(?:xml|svg|html)?\n|\n```$", "", raw_content.strip(), flags=re.MULTILINE
            )

        # --- post-process: fix viewBox height to prevent truncation ---
        svg_code = _fix_svg_viewbox_height(svg_code)

        logger.info("SVG chart generated successfully.")

        return {
            "svg_chart": svg_code,
            "messages": [
                AIMessage(content=f"攻击链路可视化视图(SVG)已生成：\n\n```xml\n{svg_code}\n```")
            ],
        }

    except Exception as e:
        logger.error("Error generating SVG chart: %s", e)
        return {"messages": [AIMessage(content=f"攻击链路图(SVG)生成失败，发生异常: {e}")]}


def simple_log_query_node(state: AttributionState, config: RunnableConfig, model: BaseChatModel):
    """Node 9: 简单日志查询节点 — 直接查询 Wazuh Indexer 中的日志并返回原始结果。

    适用于用户请求如：
    - "查询agent001最近1天与文件abc.txt相关的日志"
    - "搜索agent005包含mimikatz关键词的日志"
    - "查看agent003最近24小时的进程创建日志"

    日志数据直接从 ToolMessage 提取，不经过 LLM 输出，避免模型输出截断。
    截断在日志条目边界进行，确保返回的每条日志都是完整的。
    """
    logger.info("Executing Simple Log Query Node")

    # 简单日志查询默认最大条数
    MAX_RAW_LOGS = 10

    messages = state.get("messages", [])
    user_input = messages[-1].content if messages else ""

    # 获取 Agent 身份映射，用于将用户的主机名/IP 指代自动转换为 agent_id
    agent_identities = get_agents_identity()
    agent_identity_json = (
        json.dumps(agent_identities, ensure_ascii=False, indent=2) if agent_identities else "[]"
    )

    tools = [get_archives_by_keyword, get_archives_by_eventid]

    system_prompt = f"""你是 Wazuh 日志查询助手。将用户的自然语言查询翻译为合适的工具调用。

工具的详细参数说明请参考各工具自身的文档，以下是工具文档未涵盖的补充规则。

### Agent 身份映射表（CRITICAL）
当用户使用主机名、IP 地址、连接状态或操作系统指代 Agent 时，你必须使用下表将用户描述转换为对应的 agent_id：
```json
{agent_identity_json}
```

字段说明：
- id: Agent 编号（工具调用的 agent_id 参数使用此值）
- name: 主机名
- ip: IP 地址
- status: 连接状态 — "active"=在线，"disconnected"=离线
- os_platform: 操作系统平台（"ubuntu"、"windows" 等）

转换规则：
- 用户提到主机名（如 "win10"）→ 在表中查找 name 字段，使用该行的 id 作为 agent_id；支持模糊匹配（如 "win10" 可匹配 "win10" 或 "win10_node2"），选最匹配的行
- 用户提到 IP 地址（如 "192.168.109.1"）→ 在表中查找 ip 字段，使用该行的 id 作为 agent_id
- 用户提到状态（如 "在线的"、"离线的"、"active"、"disconnected"）→ 筛选 status 匹配的行，取这些行的 id 列表
- 用户进行组合条件查询时（如 "在线的 win"、"Ubuntu 离线机器"）→ 对不同条件各自查询匹配的结果取交集，交集为空则告知用户无匹配的 Agent
- 用户已明确给出 agent_id（如 "agent005"、"agent_005" 或 "005"）→ 直接使用该 id（去掉前缀 "agent" 或 "agent_"），无需查表
- 如果查到的 Agent status 为 "disconnected"，在回复中告知用户该 Agent 当前离线，查到的是历史日志

时间表达式转换（CRITICAL）：
- 工具同时支持相对时间和绝对时间两种格式，优先使用相对时间
- "今天"/"最近1天"/"最近24小时" → start_time="now-1d", end_time="now"
- "最近3天" → start_time="now-3d", end_time="now"
- "最近1周"/"最近7天" → start_time="now-7d", end_time="now"
- 默认时区与年份（用户未明确说明时自动应用）：
  · 时区默认北京时间（UTC+8），年份默认 2026 年
  · 先将用户时间视为 UTC+8，再转换为 UTC 并以 Z 结尾输出
  · 例："5月19日下午3点" → 视为 2026-05-19T15:00:00+08:00 → 转为 UTC → "2026-05-19T07:00:00Z"
  · 例："3月10日早上9点到9点半" → start="2026-03-10T01:00:00Z", end="2026-03-10T01:30:00Z"
- 用户明确给出时区或年份时，以用户为准

工具选择策略：
- 用户提到具体文件名、路径、进程名、PID、IP、端口、服务名、用户名、注册表路径、域名等结构化字段 → 用 get_archives_by_eventid，query_type 按如下映射：
  · 文件路径/文件名 → FILE_PATH
  · 进程 PID（查该进程自身）→ PROCESS_ID；查某进程的子进程 → PARENT_PROCESS_ID
  · IP 地址 → IP_ADDRESS
  · 端口号 → PORT
  · 服务名称 → SERVICE_NAME
  · 用户账号 → USER_ACCOUNT
  · 注册表路径 → REGISTRY_PATH
  · 登录会话 ID → LOGON_ID
  · 安全标识符 SID → SECURITY_ID
  · 域名/DNS 查询 → DNS_QUERY
- 用户只描述了行为类型但未给出具体值 → 用 get_archives_by_eventid，仅传 event_ids，不传 query_type/query_value
  例："查文件创建的日志" → event_ids=["7","11"], 不传 query_type
  例："查最近1天agent001的网络连接日志" → event_ids=["3","22","4624"], 不传 query_type
  例："查DNS查询日志" → event_ids=["22"], 不传 query_type
- 用户仅描述通用关键词（无明确结构化字段也无行为类型）→ 用 get_archives_by_keyword

日志完整性（CRITICAL）：
- 调用 get_archives_by_keyword 和 get_archives_by_eventid 时，**必须传 simplify=False**，以获取完整的原始日志字段，不得精简

响应格式：
- 只需用一行中文简要确认已执行的操作（如"已查询 agent001 最近 1 天的文件创建日志"），无需输出日志内容本身（日志内容将由系统自动拼接）"""

    agent = create_agent(model, tools, system_prompt=system_prompt)

    try:
        result = agent.invoke({"messages": [("human", user_input)]})
    except Exception as e:
        logger.error("Simple log query agent execution failed: %s", e)
        return {
            "messages": [AIMessage(content=f"日志查询执行失败：{e}")],
            "next_action_fromDecisionNode": None,
        }

    # 直接从 ToolMessage 提取日志数据，绕过 LLM 输出 token 限制
    raw_logs: list[dict] = []
    search_feedback: list[str] = []

    for msg in result.get("messages", []):
        if isinstance(msg, ToolMessage):
            try:
                parsed = json.loads(msg.content)
                if isinstance(parsed, list):
                    raw_logs.extend(parsed)
                elif isinstance(parsed, dict) and "search_feedback" not in parsed:
                    raw_logs.append(parsed)
                elif isinstance(parsed, dict) and "search_feedback" in parsed:
                    search_feedback.append(parsed["search_feedback"])
            except json.JSONDecodeError:
                logger.warning("Failed to parse ToolMessage content as JSON")

    # 提取 Agent 的确认语句
    agent_summary = ""
    for msg in reversed(result.get("messages", [])):
        if isinstance(msg, AIMessage):
            content = getattr(msg, "content", "")
            if isinstance(content, str) and content.strip():
                agent_summary = content.strip()
                break

    # 组装最终响应
    if raw_logs:
        total = len(raw_logs)
        shown = raw_logs[:MAX_RAW_LOGS]
        lines = [f"查询完成，共返回 {total} 条日志。"]
        if total > MAX_RAW_LOGS:
            lines.append(
                f"（由于日志较长，仅展示最近 {MAX_RAW_LOGS} 条完整日志，省略 {total - MAX_RAW_LOGS} 条）"
            )
        lines.append("")
        lines.append(json.dumps(shown, ensure_ascii=False, indent=2))
        reply = "\n".join(lines)
    elif search_feedback:
        feedback_text = "; ".join(search_feedback)
        reply = f"查询未返回匹配日志。\n详细信息：{feedback_text}\n建议扩大时间范围或调整查询条件。"
    else:
        reply = agent_summary or "日志查询未返回结果。"

    return {
        "messages": [AIMessage(content=reply)],
        "next_action_fromDecisionNode": None,
    }


def attack_abstract_node(state: AttributionState, config: RunnableConfig, model):
    """Node 10: Attack Abstract Node — 从最终报告中提取攻击调查概要。"""
    logger.info("Executing Attack Abstract Node: Generating investigation abstract...")

    final_report = state.get("final_report")
    if not final_report:
        logger.warning("No final report found. Skipping abstract generation.")
        return {"attack_abstract": None}

    parser = PydanticOutputParser(pydantic_object=AttackAbstractModel)

    abstract_system_prompt = """You are a Cybersecurity Intelligence Summarizer. Read the Attack Attribution Investigation Report and output a structured JSON object.

**LANGUAGE RULE (CRITICAL)**: All string values MUST be in Simplified Chinese. The ONLY exceptions are technical identifiers: file paths, process names, domain names, IP addresses, command-line arguments. All descriptions, annotations, and array elements MUST be in Chinese.

**Extraction Rules:**

1. **hosts**: List ALL host identifiers in the format "主机名（Agent ID）". Example: "WEB-SRV01（Agent 005）". If the report uses Agent IDs like "005", "001" etc., include them. If a host only has an IP, use "IP地址（Agent ID 未明确）". Skip duplicates. Keep the list ordered by first appearance in the attack chain.

2. **start_time / end_time / duration**: Extract from the ATTACK TIMELINE section. Format start_time/end_time as "YYYY-MM-DD HH:MM:SS". Calculate duration as "X时X分X秒".

3. **ioc_files / ioc_domains / ioc_processes**: Extract real IOCs from the report:
   - ioc_files: Suspicious file paths. Exclude benign system files (svchost.exe, cmd.exe) UNLESS used maliciously. Empty list if none.
   - ioc_domains: External C2/IPs/exfil endpoints. Exclude internal infrastructure IPs. Empty list if none.
   - ioc_processes: Malicious/exploited process names with key context (e.g., PID, behavior). Empty list if none.
   - Filter out benign system noise. Each entry must be traceable to the report. Use empty list [], not a placeholder string.

4. **tactics / tactics_count**: Identify distinct ATT&CK Tactics from the report. tactics must ONLY contain Chinese names from this closed set: ["初始访问", "执行", "持久化", "权限提升", "防御规避", "凭证访问", "发现", "横向移动", "收集", "数据窃取", "命令与控制", "影响"]. NO TA numbers, NO English. tactics_count is len(tactics).

{format_instructions}

**Example output:**
```json
{{
  "hosts": ["WEB-SRV01（Agent 005）", "DB-SRV02（Agent 003）"],
  "start_time": "2024-05-20 10:15:00",
  "end_time": "2024-05-20 10:45:30",
  "duration": "0时30分30秒",
  "ioc_files": ["C:\\\\Windows\\\\Temp\\\\mimikatz.exe", "C:\\\\Users\\\\Public\\\\Documents\\\\reverse.dll"],
  "ioc_domains": ["185.xx.xx.xx:4444（C2 服务器）", "evil.exfil.com（数据外传端点）"],
  "ioc_processes": ["powershell.exe（TCP 反弹 Shell, PID: 1234）", "rundll32.exe（通过 comsvcs.dll 转储 LSASS, PID: 5678）", "PsExec.exe（横向移动, PID: 9012）"],
  "tactics": ["初始访问", "执行", "凭证访问", "横向移动", "命令与控制"],
  "tactics_count": 5
}}
```"""

    human_prompt = (
        "Please read the following Attack Attribution Investigation Report and extract "
        "a structured JSON abstract according to the format_instructions.\n\n"
        "### ATTACK ATTRIBUTION INVESTIGATION REPORT\n\n"
        "{final_report}"
    )

    prompt_template = ChatPromptTemplate.from_messages(
        [("system", abstract_system_prompt), ("human", human_prompt)]
    )

    try:
        abstract_chain = prompt_template | model | parser
        abstract_model: AttackAbstractModel = abstract_chain.invoke(
            {
                "final_report": final_report,
                "format_instructions": parser.get_format_instructions(),
            }
        )
        abstract_dict = abstract_model.model_dump()

        logger.info("Attack abstract generated successfully: %s", abstract_dict)

        return {"attack_abstract": abstract_dict}

    except Exception as e:
        logger.error("Error generating attack abstract: %s", e)
        return {"attack_abstract": None}


def graph_filter_node(state: AttributionState, config: RunnableConfig, model):
    """Node 11: Graph Filter Node"""
    logger.info("Executing Graph Filter Node: Reconstructing attack_graph_data from report...")

    graph_data = state.get("attack_graph_data")
    if not graph_data:
        return {"attack_graph_data": None}

    entities: list[dict] = graph_data.get("entities", [])
    relations: list[dict] = graph_data.get("relations", [])

    if not entities:
        return {"attack_graph_data": None}

    final_report = state.get("final_report", "")
    investigation_clue = state.get("investigation_clue", "")

    entity_list_str = json.dumps(
        [
            {
                "id": e["id"],
                "type": e["type"],
                "name": e["name"],
                "properties": e.get("properties", {}),
            }
            for e in entities
        ],
        ensure_ascii=False,
        indent=2,
    )
    relation_list_str = json.dumps(
        [
            {
                "source": r["source"],
                "target": r["target"],
                "relation": r["relation"],
                "timestamp": r.get("timestamp"),
            }
            for r in relations
        ],
        ensure_ascii=False,
        indent=2,
    )

    system_prompt = """You are a cybersecurity entity graph reconstructor. Your primary input is the final attack attribution REPORT. The provided entity/relation list from raw logs is supplementary reference.

**Entity format:**
{{
    "id": "proc_<pid> | file_<N> | ip_<addr> | reg_<N> | user_<name> | other_<N>",
    "type": "process | file | ip | registry | user_account | other",
    "name": "<human readable label>",
    "properties": {{}}
}}

**Relation format:**
{{
    "source": "<entity id>",
    "target": "<entity id>",
    "relation": "create | modify | execute | instantiate | communicate | authenticate | access"
}}

**Relation types (with entity type constraints):**
- create: process→process (spawn) OR process→file (create/write)
- modify: process→file OR process→registry
- execute: process→process (inject/DLL) — in-memory operations only, NEVER file→process
- instantiate: file→process (file instantiated into a running process by the system loader)
- communicate: process→ip (connection) OR ip→ip (DNS) — NEVER process→file
- authenticate: process→user_account
- access: process→file (read/load/access as data) — use when the process reads a file as INPUT DATA (e.g., encode/decode source, config file, data dump), NOT for executing or creating the file. Do NOT use for process→process or process→ip.

**Your task (in order):**

1. **Report-first filtering**: The REPORT is the ground truth. Only keep entities and relations that are explicitly or implicitly described in the report. Drop anything not traceable to the report.
   - System noise (svchost.exe routine, RuntimeBroker.exe normal windows, explorer.exe benign) → REMOVE.
   - Internal-only infrastructure with no attack relevance → REMOVE.
   - **Orphan check**: The `INVESTIGATION CLUE` below defines the attack's trigger source. Any entity that has NO relation path to a trigger-chain process and is not mentioned in the report → REMOVE. The report has already been filtered by causal relevance; use it as the authority.
   - When in doubt, KEEP.

2. **Deduplication**: Merge duplicate entities that represent the same real-world object. For example, if file_2 and file_3 both point to the same file path, merge them into one entity and update all relations to use the surviving ID. Remove duplicate relations (same source, target, relation).

3. **Trim auxiliary nodes**: For user_account entities and authenticate relations, apply this strict gate:
   - **GATE CHECK**: Only keep user_account / authenticate if the report explicitly describes an authentication-centric attack action — credential dumping (e.g., mimikatz, LSASS access), privilege escalation via explicit logon (e.g., runas, PSRemote, token manipulation), account creation/modification, or brute-force logon attempts.
   - **PASSIVE INHERITANCE = REMOVE**: When a process simply runs under the logged-in user's context (double-click a script, type a command in CMD), the authentication happened at Windows login and is NOT an attack action. In this case, remove ALL user_account entities and ALL authenticate relations entirely. The attack graph should focus on the process→process, process→file, and process→network chains.
   - If a user_account node ends up with zero relations after this check, remove it entirely.

4. **Report-driven supplementation (CRITICAL — focus on FILES and IPs)**: The REPORT is the ground truth. After filtering, re-scan the report and:
   - **Files**: For ANY file path or filename mentioned in the report that is NOT already in the entity list → CREATE a new file entity with a unique `file_<N>` id (use the next available N). For `name`, use just the filename. In `properties`, fill `path` with the full path from the report. If the path is incomplete or missing, set `path` to an empty string `""`.
   - **IPs / Domains**: For ANY external IP address or domain mentioned in the report that is NOT already in the entity list → CREATE a new ip entity with `id` = `ip_<address>` (or `ip_<domain>` for domains). For `name`, use the IP/domain as-is. In `properties`, fill `address` with the IP/domain from the report. If port info is available, add `port`; otherwise omit it.
   - **Relations for new entities**: For each newly created file or ip entity, infer its relationship to existing process entities from the report context:
     * If report says a process created/wrote/downloaded the file → add `create` relation (source=process, target=file).
     * If report says a process connected to the IP/domain → add `communicate` relation (source=process, target=ip).
     * If report says a file was instantiated/executed as a process → add `instantiate` relation (source=file, target=process).
     * If report says a process read/accessed/loaded the file as input data (e.g., encode/decode source, config read, data parsing) → add `access` relation (source=process, target=file).
     * If the relation direction or source/target is unclear, make your best guess based on typical attack patterns and set `timestamp` to `null`.
   - **Missing parameters**: If the report does not provide certain properties (e.g., no PID, no full path, no port), simply leave those fields empty or omit them. Do NOT hallucinate values.
   - **Noise check for new entities**: Apply the same noise filter — do NOT add well-known benign system files (svchost.exe, explorer.exe, etc.) as new entities unless they are explicitly flagged as abused/malicious in the report.

**Output ONLY a JSON object:**
{{"entities": [...], "relations": [...]}}

Example output:
{{"entities": [
    {{"id": "proc_7672", "type": "process", "name": "powershell.exe (PID: 7672)", "properties": {{"pid": 7672}}}},
    {{"id": "file_1", "type": "file", "name": "payload.dll", "properties": {{"path": "C:\\\\Users\\\\Public\\\\payload.dll"}}}}
],
"relations": [
    {{"source": "proc_7672", "target": "file_1", "relation": "create"}}
]}}
"""

    human_prompt = (
        "### INVESTIGATION CLUE (TRIGGER SOURCE)\n{investigation_clue}\n\n"
        "### CURRENT ENTITIES\n```json\n{entity_list}\n```\n\n"
        "### CURRENT RELATIONS\n```json\n{relation_list}\n```\n\n"
        "### ATTACK ATTRIBUTION REPORT (GROUND TRUTH)\n{report}\n\n"
        "Reconstruct the entities and relations based on the report. "
        "Remove noise, merge duplicates, trim unnecessary auxiliary connections, "
        "and supplement any missing files/IPs mentioned in the report but absent from the current entity list."
    )

    prompt_template = ChatPromptTemplate.from_messages(
        [("system", system_prompt), ("human", human_prompt)]
    )

    try:
        chain = prompt_template | model
        result = chain.invoke(
            {
                "investigation_clue": investigation_clue,
                "entity_list": entity_list_str,
                "relation_list": relation_list_str,
                "report": final_report[:10000],
            }
        )

        raw = result.content
        if isinstance(raw, list):
            raw = "".join(b.get("text", "") if isinstance(b, dict) else str(b) for b in raw)

        json_match = re.search(r"\{[\s\S]*\}", str(raw))
        if json_match:
            parsed = json.loads(json_match.group())
            filtered_entities = parsed.get("entities", entities)
            filtered_relations = parsed.get("relations", relations)
        else:
            filtered_entities = entities
            filtered_relations = relations

        logger.info(
            "Graph filter: %d entities, %d relations → %d entities, %d relations.",
            len(entities),
            len(relations),
            len(filtered_entities),
            len(filtered_relations),
        )

        return {
            "attack_graph_data": (
                {
                    "_replace": True,
                    "entities": filtered_entities,
                    "relations": filtered_relations,
                }
                if filtered_entities
                else None
            ),
        }

    except Exception as e:
        logger.error("Graph filter failed, keeping original data: %s", e)
        return {
            "attack_graph_data": {"_replace": True, "entities": entities, "relations": relations}
        }


def attack_graph_node(state: AttributionState, config: RunnableConfig, model):
    """Node 12: Attack Graph Node — 基于 attack_graph_data 生成攻击实体关系网状图 SVG"""
    logger.info(
        "Executing Attack Graph Node (Node 12): Generating entity relationship graph SVG from structured data..."
    )

    graph_data = state.get("attack_graph_data")
    if not graph_data:
        logger.warning("No attack_graph_data found. Skipping attack graph generation.")
        return {
            "attack_graph": None,
            "messages": [
                AIMessage(content="[Attack Graph] 缺少攻击图谱数据，无法生成实体关系图。")
            ],
        }

    entities: list[dict] = graph_data.get("entities", [])
    relations: list[dict] = graph_data.get("relations", [])

    if not entities:
        return {
            "attack_graph": None,
            "messages": [AIMessage(content="[Attack Graph] 图谱数据为空。")],
        }

    # --- remove orphan entities (no relation edges) ---
    connected_ids: set[str] = set()
    for rel in relations:
        connected_ids.add(rel.get("source", ""))
        connected_ids.add(rel.get("target", ""))
    entities = [e for e in entities if e.get("id", "") in connected_ids]
    relations = [
        r
        for r in relations
        if r.get("source", "") in connected_ids and r.get("target", "") in connected_ids
    ]

    if not entities:
        return {
            "attack_graph": None,
            "messages": [AIMessage(content="[Attack Graph] 所有实体均为孤立节点，无法生成攻击实体关系网状图。")],
        }

    # --- build lookup & adjacency ---
    entity_map: dict[str, dict] = {e["id"]: e for e in entities}
    in_degree: dict[str, int] = {e["id"]: 0 for e in entities}
    adj: dict[str, list[str]] = {e["id"]: [] for e in entities}

    for rel in relations:
        src = rel.get("source", "")
        tgt = rel.get("target", "")
        if src in adj and tgt in entity_map:
            adj[src].append(tgt)
            in_degree[tgt] = in_degree.get(tgt, 0) + 1

    # --- topological BFS to assign layers ---
    layers: dict[str, int] = {}
    queue: deque[str] = deque()

    # --- Kahn-based longest-path DAG layering ---
    layers: dict[str, int] = {}
    indeg: dict[str, int] = dict(in_degree)
    queue: deque[str] = deque()

    for eid, deg in indeg.items():
        if deg == 0:
            layers[eid] = 0
            queue.append(eid)

    while queue:
        current = queue.popleft()
        for neighbor in adj.get(current, []):
            # longest path: layer must be strictly greater than all parent layers
            candidate = layers[current] + 1
            if candidate > layers.get(neighbor, -1):
                layers[neighbor] = candidate
            indeg[neighbor] -= 1
            if indeg[neighbor] == 0:
                queue.append(neighbor)

    # handle disconnected / cycle nodes
    # Use layered BFS on the residual graph so that nodes in the same
    # dependency cycle stay in the same (or adjacent) layers instead of
    # each being assigned its own layer.
    remaining: set[str] = {eid for eid in entity_map if eid not in layers}
    if remaining:
        base_layer = max(layers.values()) + 1 if layers else 0
        residual_indeg: dict[str, int] = {eid: 0 for eid in remaining}
        for src, targets in adj.items():
            if src in remaining:
                for tgt in targets:
                    if tgt in remaining:
                        residual_indeg[tgt] = residual_indeg.get(tgt, 0) + 1
        current_layer = base_layer
        while remaining:
            batch = {eid for eid in remaining if residual_indeg.get(eid, 0) == 0}
            if not batch:
                # true cycle — break by putting all remaining in the current layer
                batch = set(remaining)
            for eid in batch:
                layers[eid] = current_layer
                if eid in adj:
                    for tgt in adj[eid]:
                        if tgt in residual_indeg:
                            residual_indeg[tgt] = max(0, residual_indeg[tgt] - 1)
            remaining -= batch
            current_layer += 1

    # --- group by layer ---
    layer_groups: dict[int, list[str]] = {}
    for eid, layer in layers.items():
        layer_groups.setdefault(layer, []).append(eid)

    # --- clustering: reorder each layer so interconnected entities are adjacent ---
    # Build same-layer adjacency subgraph
    same_layer_adj: dict[str, set[str]] = {eid: set() for eid in entity_map}
    for rel in relations:
        src, tgt = rel.get("source", ""), rel.get("target", "")
        if src in entity_map and tgt in entity_map:
            if layers.get(src) == layers.get(tgt):
                same_layer_adj[src].add(tgt)
                same_layer_adj[tgt].add(src)

    for layer_num in sorted(layer_groups.keys()):
        ids = layer_groups[layer_num]
        if len(ids) <= 1:
            continue
        visited: set[str] = set()
        ordered: list[str] = []
        # Start BFS from nodes with the most same-layer connections
        seeds = sorted(ids, key=lambda e: -len(same_layer_adj.get(e, set())))
        for seed in seeds:
            if seed in visited:
                continue
            queue: deque[str] = deque([seed])
            while queue:
                cur = queue.popleft()
                if cur in visited:
                    continue
                visited.add(cur)
                ordered.append(cur)
                neighbors = sorted(
                    same_layer_adj.get(cur, set()),
                    key=lambda n: -len(same_layer_adj.get(n, set())),
                )
                for neighbor in neighbors:
                    if neighbor not in visited:
                        queue.append(neighbor)
        # Append any remaining unvisited nodes (isolated within this layer)
        for eid in ids:
            if eid not in visited:
                ordered.append(eid)
        layer_groups[layer_num] = ordered

    # --- layout constants ---
    NODE_WIDTH = 230
    NODE_HEIGHT = 62
    LAYER_GAP_X = 400
    GAP_CLOSE = 24   # standard gap between unrelated nodes in the same column
    GAP_LINKED = 70  # larger gap when an edge exists between the two nodes
    MARGIN = 40
    TITLE_H = 36
    LEGEND_H = 90

    # legend layout constants (used for minimum-width guarantees)
    BEHAVIOR_LEGEND_ITEMS = 7
    ENTITY_LEGEND_ITEMS = 6
    LEGEND_ITEM_WIDTH = 90
    LEGEND_BOX_PAD = 16
    BEHAVIOR_LEGEND_START = 50
    BEHAVIOR_LEGEND_WIDTH = BEHAVIOR_LEGEND_ITEMS * LEGEND_ITEM_WIDTH + LEGEND_BOX_PAD  # 646
    ENTITY_LEGEND_WIDTH = ENTITY_LEGEND_ITEMS * LEGEND_ITEM_WIDTH + LEGEND_BOX_PAD  # 556
    ENTITY_LEGEND_LEFT_PAD = 8
    ENTITY_LEGEND_RIGHT_MARGIN = 32
    ENTITY_LEGEND_SLOT = (
        ENTITY_LEGEND_LEFT_PAD + ENTITY_LEGEND_WIDTH + ENTITY_LEGEND_RIGHT_MARGIN
    )  # 596
    LEGEND_GAP = 40

    # quick lookup: do two entities in the same layer have at least one edge between them?
    def _same_layer_connected(a: str, b: str) -> bool:
        sa = same_layer_adj.get(a, set())
        sb = same_layer_adj.get(b, set())
        return b in sa or a in sb

    # --- two-pass positioning (dynamic gap) ---
    # Pass 1: compute raw total heights per layer
    layer_total_heights: dict[int, int] = {}
    layer_y_offsets: dict[int, list[tuple[str, int]]] = {}
    for layer_num in sorted(layer_groups.keys()):
        ids = layer_groups[layer_num]
        y_cursor = 0
        prev_eid: str | None = None
        offsets: list[tuple[str, int]] = []
        for eid in ids:
            if prev_eid is not None:
                y_cursor += GAP_LINKED if _same_layer_connected(prev_eid, eid) else GAP_CLOSE
            offsets.append((eid, y_cursor))
            y_cursor += NODE_HEIGHT
            prev_eid = eid
        layer_total_heights[layer_num] = y_cursor
        layer_y_offsets[layer_num] = offsets

    # canvas dimensions
    max_layer_height = max(layer_total_heights.values()) if layer_total_heights else 1
    body_height = max_layer_height + MARGIN * 2 + TITLE_H
    graph_width = max(layer_groups.keys()) * LAYER_GAP_X + NODE_WIDTH if layer_groups else 0
    min_for_nodes = MARGIN * 2 + graph_width
    min_for_legends = (
        BEHAVIOR_LEGEND_START + BEHAVIOR_LEGEND_WIDTH + LEGEND_GAP + ENTITY_LEGEND_SLOT + MARGIN
    )
    canvas_width = max(min_for_nodes, min_for_legends)
    canvas_height = max(400, body_height + LEGEND_H)
    center_offset_x = max(0, (canvas_width - graph_width) // 2)
    legend_base_y = canvas_height - 70

    # Pass 2: center and assign final positions
    node_pos: dict[str, tuple[int, int]] = {}
    for layer_num in sorted(layer_groups.keys()):
        total_h = layer_total_heights[layer_num]
        safe_top = MARGIN + TITLE_H
        safe_bottom = legend_base_y - 20
        safe_height = safe_bottom - safe_top
        start_y = safe_top + max(0, (safe_height - total_h) // 2)
        x = center_offset_x + layer_num * LAYER_GAP_X
        for eid, y_off in layer_y_offsets[layer_num]:
            node_pos[eid] = (x, start_y + y_off)

    # --- color scheme ---
    type_colors: dict[str, dict[str, str]] = {
        "process": {"bg": "#fee2e2", "border": "#ef4444", "text": "#991b1b", "arrow": "arrow-red"},
        "file": {"bg": "#fff7ed", "border": "#f97316", "text": "#9a3412", "arrow": "arrow-orange"},
        "ip": {"bg": "#eff6ff", "border": "#3b82f6", "text": "#1e40af", "arrow": "arrow-blue"},
        "registry": {
            "bg": "#f0fdf4",
            "border": "#22c55e",
            "text": "#166534",
            "arrow": "arrow-green",
        },
        "user_account": {
            "bg": "#faf5ff",
            "border": "#a855f7",
            "text": "#6b21a8",
            "arrow": "arrow-purple",
        },
        "other": {"bg": "#f1f5f9", "border": "#94a3b8", "text": "#475569", "arrow": "arrow-gray"},
    }

    rel_labels: dict[str, str] = {
        "create": "创建",
        "modify": "修改",
        "execute": "执行",
        "instantiate": "实例化",
        "communicate": "通信",
        "authenticate": "认证",
        "access": "访问",
    }
    # edge style per relation: (stroke-width, stroke-dasharray, color, arrow-marker-id)
    rel_styles: dict[str, tuple[str, str, str, str]] = {
        "create": ("3", "none", "#22c55e", "arrow-create"),  # thick solid green
        "modify": ("2", "6,4", "#f59e0b", "arrow-modify"),  # dashed amber
        "execute": ("2", "2,3", "#ef4444", "arrow-execute"),  # dotted red
        "instantiate": ("3", "none", "#f97316", "arrow-instantiate"),  # thick solid orange
        "communicate": ("2", "none", "#3b82f6", "arrow-communicate"),  # normal solid blue
        "authenticate": ("1.5", "4,3", "#a855f7", "arrow-authenticate"),  # thin dashed purple
        "access": ("2", "2,6", "#14b8a6", "arrow-access"),  # medium dot-dash teal
    }



    # --- build SVG ---
    lines: list[str] = []

    lines.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {canvas_width} {canvas_height}" width="100%" height="100%">'
    )
    lines.append("<style>")
    lines.append(".legend-text { font-family: sans-serif; font-size: 10px; fill: #334155; }")
    lines.append("</style>")
    lines.append(f'<rect width="{canvas_width}" height="{canvas_height}" fill="#f1f5f9"/>')
    lines.append(
        f'<text x="{canvas_width // 2}" y="26" text-anchor="middle" font-size="15" font-weight="bold" fill="#0f172a" font-family="sans-serif">攻击实体关系图</text>'
    )

    # arrow markers (entity type arrows + relation type arrows)
    lines.append("<defs>")
    ent_arrows = [
        ("arrow-red", "#ef4444"),
        ("arrow-orange", "#f97316"),
        ("arrow-blue", "#3b82f6"),
        ("arrow-green", "#22c55e"),
        ("arrow-purple", "#a855f7"),
        ("arrow-gray", "#94a3b8"),
    ]
    rel_arrows = [
        ("arrow-create", "#22c55e"),
        ("arrow-modify", "#f59e0b"),
        ("arrow-execute", "#ef4444"),
        ("arrow-instantiate", "#f97316"),
        ("arrow-communicate", "#3b82f6"),
        ("arrow-authenticate", "#a855f7"),
        ("arrow-access", "#14b8a6"),
    ]
    for name, color in ent_arrows + rel_arrows:
        lines.append(
            f'<marker id="{name}" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto">'
        )
        lines.append(f'<path d="M 0 0 L 10 5 L 0 10 z" fill="{color}"/>')
        lines.append("</marker>")
    lines.append("</defs>")

    # edges — separate same-layer from cross-layer
    REL_PRIORITY = {
        "instantiate": 7,  # 实例化 (生命周期 - 最高)
        "create": 6,       # 创建 (生命周期)
        "execute": 5,      # 执行 (控制流)
        "modify": 4,       # 修改 (状态改变)
        "authenticate": 3, # 认证
        "communicate": 2,  # 通信
        "access": 1,       # 访问 (被动读取 - 最低)
    }

    same_layer_pairs: dict[tuple[str, str], tuple[str, str | None]] = {}
    cross_layer_relations: list[dict] = []
    for rel in relations:
        src, tgt = rel.get("source", ""), rel.get("target", "")
        if src not in node_pos or tgt not in node_pos:
            continue
        x1, _ = node_pos[src]
        x2, _ = node_pos[tgt]
        if x1 == x2:
            pair = tuple(sorted([src, tgt]))  # undirected — dedup both directions
            rel_type = rel.get("relation", "")
            ts = rel.get("timestamp")
            existing = same_layer_pairs.get(pair)
            existing_prio = REL_PRIORITY.get(existing[0], 0) if existing else 0
            if REL_PRIORITY.get(rel_type, 0) > existing_prio:
                same_layer_pairs[pair] = (rel_type, ts)
        else:
            cross_layer_relations.append(rel)

    edge_paths: list[str] = []
    edge_labels: list[str] = []

    # --- same-layer edges: vertical lines ---
    for (src, tgt), (rel_type, _ts) in same_layer_pairs.items():
        x1, y1 = node_pos[src]
        x2, y2 = node_pos[tgt]
        if y1 > y2:
            src, tgt = tgt, src
            y1, y2 = y2, y1
        cx = x1 + NODE_WIDTH // 2
        top_y = y1 + NODE_HEIGHT  # bottom edge of upper node
        bot_y = y2  # top edge of lower node

        sw, dash, edge_color, arrow_id = rel_styles.get(
            rel_type, ("2", "none", "#94a3b8", "arrow-gray")
        )
        dash_attr = f' stroke-dasharray="{dash}"' if dash != "none" else ""

        edge_paths.append(
            f'<line x1="{cx}" y1="{top_y}" x2="{cx}" y2="{bot_y}" stroke="{edge_color}" stroke-width="{sw}"{dash_attr} marker-end="url(#{arrow_id})"/>'
        )

        label = rel_labels.get(rel_type, rel_type)
        mid_y = (top_y + bot_y) / 2
        edge_labels.append(
            f'<text x="{cx + 12}" y="{mid_y}" font-family="sans-serif" font-size="10" fill="#334155" stroke="#f1f5f9" stroke-width="4" paint-order="stroke fill" text-anchor="start" dominant-baseline="central">{label}</text>'
        )

    # --- cross-layer edges: L-shaped routing ---
    target_entry_slots: dict[str, int] = {}
    for rel in cross_layer_relations:
        src, tgt = rel.get("source", ""), rel.get("target", "")
        x1, y1 = node_pos[src]
        x2, y2 = node_pos[tgt]
        sx, sy = x1 + NODE_WIDTH, y1 + NODE_HEIGHT // 2
        tx, ty_base = x2, y2 + NODE_HEIGHT // 2

        rel_type = rel.get("relation", "")
        sw, dash, edge_color, arrow_id = rel_styles.get(
            rel_type, ("2", "none", "#94a3b8", "arrow-gray")
        )
        dash_attr = f' stroke-dasharray="{dash}"' if dash != "none" else ""

        slot = target_entry_slots.get(tgt, 0)
        target_entry_slots[tgt] = slot + 1
        offset_sign = 1 if slot % 2 == 0 else -1
        offset_idx = (slot + 1) // 2
        ty = ty_base + offset_sign * offset_idx * 20
        corner_x = tx - 90 - offset_sign * offset_idx * 8

        edge_paths.append(
            f'<path d="M {sx} {sy} L {corner_x} {sy} L {corner_x} {ty} L {tx} {ty}" fill="none" stroke="{edge_color}" stroke-width="{sw}"{dash_attr} marker-end="url(#{arrow_id})"/>'
        )
        label = rel_labels.get(rel_type, rel_type)
        lx = (corner_x + tx) / 2
        edge_labels.append(
            f'<text x="{lx}" y="{ty}" font-family="sans-serif" font-size="10" fill="#334155" stroke="#f1f5f9" stroke-width="4" paint-order="stroke fill" text-anchor="middle" dominant-baseline="central">{label}</text>'
        )

    lines.extend(edge_paths)
    lines.extend(edge_labels)

    # nodes
    for entity in entities:
        eid = entity.get("id", "")
        if eid not in node_pos:
            continue
        x, y = node_pos[eid]
        etype = entity.get("type", "other")
        tc = type_colors.get(etype, type_colors["other"])
        name = (
            (entity.get("name") or eid)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        dash = "5,4" if etype != "process" else "none"

        lines.append(f'<foreignObject x="{x}" y="{y}" width="{NODE_WIDTH}" height="{NODE_HEIGHT}">')
        lines.append(
            f'<div xmlns="http://www.w3.org/1999/xhtml" style="border:2px {tc["border"]}; border-style:solid; border-radius:8px; background:{tc["bg"]}; padding:6px 10px; font-family:sans-serif; font-size:11px; box-sizing:border-box; height:100%; display:flex; flex-direction:column; justify-content:center; overflow:hidden; stroke-dasharray:{dash};">'
        )
        lines.append(
            f'<div style="font-weight:bold; color:{tc["text"]}; font-size:11px; word-wrap:break-word;">{name}</div>'
        )
        props = entity.get("properties", {})
        detail = ""
        etype = entity.get("type", "")
        if etype == "ip":
            port = props.get("port")
            if port is not None:
                detail = f"端口: {port}"
        elif etype == "registry":
            vn = props.get("value_name")
            if vn:
                detail = vn
        if detail:
            detail = (
                detail.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )
            lines.append(
                f'<div style="color:{tc["text"]}; font-size:9px; opacity:0.75; margin-top:2px; word-wrap:break-word; line-height:1.2;">{detail[:40]}</div>'
            )
        lines.append("</div>")
        lines.append("</foreignObject>")

    # --- legend ---
    # entity legend (right side)
    ent_items = [
        ("process", "进程"),
        ("file", "文件"),
        ("ip", "网络"),
        ("registry", "注册表"),
        ("user_account", "用户账户"),
        ("other", "其他"),
    ]
    ent_start_x = canvas_width - ENTITY_LEGEND_SLOT + ENTITY_LEGEND_RIGHT_MARGIN
    ent_box_w = ENTITY_LEGEND_WIDTH
    # entity legend: box + title first, then items
    lines.append(
        f'<rect x="{ent_start_x - 8}" y="{legend_base_y}" width="{ent_box_w}" height="46" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
    )
    lines.append(
        f'<text x="{ent_start_x - 2}" y="{legend_base_y + 14}" font-size="9" fill="#0f172a" font-weight="bold" font-family="sans-serif">实体</text>'
    )
    for i, (key, label) in enumerate(ent_items):
        lx = ent_start_x + i * LEGEND_ITEM_WIDTH
        tc = type_colors[key]
        lines.append(
            f'<rect x="{lx}" y="{legend_base_y + 24}" width="14" height="14" rx="3" fill="{tc["bg"]}" stroke="{tc["border"]}" stroke-width="1.5"/>'
        )
        lines.append(
            f'<text x="{lx + 19}" y="{legend_base_y + 35}" font-size="10" fill="#334155" font-family="sans-serif">{label}</text>'
        )

    # behavior legend (left side)
    act_items = [
        ("create", "创建"),
        ("modify", "修改"),
        ("execute", "执行"),
        ("instantiate", "实例化"),
        ("communicate", "通信"),
        ("authenticate", "认证"),
        ("access", "访问"),
    ]
    act_start_x = BEHAVIOR_LEGEND_START
    act_box_w = BEHAVIOR_LEGEND_WIDTH
    # behavior legend: box + title first, then items
    lines.append(
        f'<rect x="{act_start_x - 8}" y="{legend_base_y}" width="{act_box_w}" height="46" rx="5" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
    )
    lines.append(
        f'<text x="{act_start_x - 2}" y="{legend_base_y + 14}" font-size="9" fill="#0f172a" font-weight="bold" font-family="sans-serif">行为</text>'
    )
    for i, (rel_type, label) in enumerate(act_items):
        lx = act_start_x + i * LEGEND_ITEM_WIDTH
        sw, dash, color, _ = rel_styles[rel_type]
        dash_attr = f' stroke-dasharray="{dash}"' if dash != "none" else ""
        lines.append(
            f'<line x1="{lx}" y1="{legend_base_y + 31}" x2="{lx + 40}" y2="{legend_base_y + 31}" stroke="{color}" stroke-width="{sw}"{dash_attr}/>'
        )
        lines.append(
            f'<text x="{lx + 48}" y="{legend_base_y + 35}" font-size="10" fill="#334155" font-family="sans-serif">{label}</text>'
        )

    lines.append("</svg>")

    svg_code = "\n".join(lines)

    logger.info(
        "Attack graph SVG generated successfully from structured data (%d entities, %d relations).",
        len(entities),
        len(relations),
    )

    return {
        "attack_graph": svg_code,
        "messages": [
            AIMessage(content=f"攻击实体关系网状图(SVG)已生成：\n\n```xml\n{svg_code}\n```")
        ],
    }
