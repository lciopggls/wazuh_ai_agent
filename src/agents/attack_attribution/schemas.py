"""LLM output schemas (BaseModel) used by attack attribution nodes in nodes.py for structured parsing."""

from typing import Literal

from pydantic import BaseModel, Field


class InitialClueAnalysis(BaseModel):
    agent_id: str = Field(description="提取到的被攻击 Agent ID (如 '005')。若未找到则留空。")
    start_time_utc8: str = Field(description="调查窗口的起始时间，ISO8601格式 (北京时间/UTC+8)。")
    end_time_utc8: str = Field(description="调查窗口的结束时间，ISO8601格式 (北京时间/UTC+8)。")
    refined_clue: str = Field(description="专业中文攻击线索描述（包含北京时间）。")


class QueryIntent(BaseModel):
    is_simple_query: bool = Field(
        description="True if the user is only querying/searching/viewing logs without asking for attack analysis. "
        "False if this is an attack investigation, attribution, or forensics request."
    )


class GraphEntity(BaseModel):
    """攻击实体节点。"""

    id: str = Field(
        description=(
            "Unique entity ID. Must follow the convention: "
            "process → 'proc_<pid>' (e.g., 'proc_5324'), "
            "file → 'file_<N>' (e.g., 'file_1'), "
            "ip → 'ip_<address>' (e.g., 'ip_192.168.1.100'), "
            "registry → 'reg_<N>' (e.g., 'reg_1'), "
            "user_account → 'user_<name>' (e.g., 'user_Administrator'), "
            "other → 'other_<N>' (e.g., 'other_1'). "
            "N is a sequential integer starting from 1 per type."
        )
    )
    type: Literal["process", "file", "ip", "registry", "user_account", "other"] = Field(
        description="Entity type."
    )
    name: str = Field(description="Human-readable entity name, e.g., 'powershell.exe (PID: 5324)'.")
    timestamp: str | None = Field(
        default=None, description="First observed ISO8601 timestamp for this entity."
    )
    properties: dict = Field(
        default_factory=dict,
        description=(
            "Type-specific key-value dict. "
            "process: {pid (int), image (str), command_line (str|None)}. "
            "file: {path (str)}. "
            "ip: {address (str), port (int|None)}. "
            "registry: {key_path (str), value_name (str|None)}. "
            "user_account: {username (str), domain (str|None)}. "
            "other: {} (empty). "
            "Omit keys whose values are missing from the raw logs."
        ),
    )


class GraphRelation(BaseModel):
    """攻击实体间的关系边。"""

    source: str = Field(description="Source entity ID (must match a GraphEntity.id).")
    target: str = Field(description="Target entity ID (must match a GraphEntity.id).")
    relation: Literal[
        "create",
        "modify",
        "execute",
        "communicate",
        "authenticate",
        "access",
        "instantiate",
    ] = Field(
        description=(
            "Relationship type (simplified): "
            "create = spawned child process OR created/wrote a file; "
            "modify = modified a file OR modified a registry key; "
            "execute = loaded a DLL OR injected into another process (in-memory operations); "
            "communicate = connected to network address OR DNS resolved to IP; "
            "authenticate = process ran under a user account (credential use / privilege verification); "
            "access = process read/loaded/accessed a file as input data (e.g., encode/decode source, config file, data dump); "
            "instantiate = static file was instantiated by the system loader into a running process (file→process only)."
        )
    )
    timestamp: str | None = Field(
        default=None, description="ISO8601 timestamp when the relationship was observed."
    )


class InvestigationFindings(BaseModel):
    task_description: str = Field(
        description="Briefly restate the exact investigation instruction you are executing (e.g., 'Downward tracking of PID 10484 on Agent 005 for Process Creation'). DO NOT include any prefixes or markdown headers. Must be in Chinese."
    )
    detailed_findings: str = Field(
        description="""A strict chronological timeline and factual summary of the events.
        CRITICAL ZERO-LOSS RULE: You MUST embed all exact technical Evidence/IOCs directly into this narrative.
        Whenever you mention an event, you MUST include its exact timestamp, exact PID, full absolute file path, unredacted command line, and any related IPs/Ports.

        ### ANTI-HALLUCINATION PROTOCOL (CRITICAL) ###
        1. GROUNDING RULE: You are STRICTLY FORBIDDEN from inventing, inferring, or generating ANY data (timestamps, PIDs, IPs, filenames, actions) that is not EXPLICITLY present in the provided Raw JSON Logs.
        2. MISSING EVIDENCE RULE: If the Raw Logs do NOT contain the exact behavior requested in the instruction (e.g., the instruction asks for Process Creation, but logs only show File Creation), you MUST explicitly state the discrepancy.
        3. NULL RESPONSE RULE: If the Raw Logs are empty, irrelevant, or insufficient to fulfill the instruction, you MUST output EXACTLY: "日志检索结果未包含符合预期的行为证据。发现的孤立事件为：[简述实际发现的内容]。" DO NOT fabricate a story.

        ROLE BOUNDARY (CRITICAL): You are a Fact Extractor, NOT the final judge. DO NOT forcefully assign MITRE Tactic IDs unless explicitly supported by the 'MITRE Knowledge'. If in doubt, just describe the objective behavior.
        FORMATTING RULE: You MUST strictly use the hierarchical Markdown template defined in the System Prompt (using ###, >, -, and ```cmd). Must be in Chinese. """
    )


class SynthesizedFindings(InvestigationFindings):
    graph_entities: list[GraphEntity] = Field(
        default_factory=list,
        description="Structured attack graph entity nodes extracted from the raw logs. Include every distinct process, file, IP, registry key, and user account observed.",
    )
    graph_relations: list[GraphRelation] = Field(
        default_factory=list,
        description="Structured attack graph relationship edges linking entities. Every entity in graph_entities that acts as source or target of an observable behavior MUST have at least one relation.",
    )


class AttackAbstractModel(BaseModel):
    """攻击调查概要结构，用于 attack_abstract_node 的 PydanticOutputParser 解析。"""

    hosts: list[str] = Field(description="涉及的主机列表，格式：主机名（Agent ID）")
    start_time: str = Field(description="攻击起始时间，如 '2024-05-20 10:15:00'")
    end_time: str = Field(description="攻击结束时间，如 '2024-05-20 10:45:30'")
    duration: str = Field(description="攻击持续时长，如 '0时30分30秒'")
    ioc_files: list[str] = Field(
        description="涉及的文件名IOC列表（含路径），无则空列表。排除明确的系统良性文件。"
    )
    ioc_domains: list[str] = Field(
        description="涉及的域名/IP IOC列表，无则空列表。排除纯内网基础设施IP。"
    )
    ioc_processes: list[str] = Field(
        description="涉及的恶意/被利用进程名IOC列表，含PID等关键上下文，无则空列表。"
    )
    tactics: list[str] = Field(
        description=(
            "涉及的ATT&CK战术阶段中文名列表，仅限以下12个："
            "初始访问、执行、持久化、权限提升、防御规避、凭证访问、"
            "发现、横向移动、收集、数据窃取、命令与控制、影响"
        )
    )
    tactics_count: int = Field(description="涉及的不同战术阶段总数")
