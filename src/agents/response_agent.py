import ipaddress
import json
import logging
import time
from datetime import datetime
from typing import Literal, NotRequired

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, AgentState
from langchain.tools import ToolRuntime, tool
from langchain_core.language_models.chat_models import BaseChatModel

from agents.attack_attribution.utils import extract_agent_ip_mapping
from wazuh_api.server_api import (
    block_ip_and_verify_on_agent,
    block_ip_on_agent,
    block_port_and_verify_on_agent,
    disable_local_account_on_agent,
    enable_local_account_on_agent,
    list_blocked_ips_on_agent,
    query_blocked_port_on_agent,
    query_local_account_on_agent,
    query_process_on_agent,
    terminate_process_on_agent,
    unblock_ip_and_verify_on_agent,
    unblock_port_and_verify_on_agent,
)

logger = logging.getLogger(__name__)


class ResponseAgentState(AgentState):
    """State shared by response tools during one response-agent invocation."""

    response_started_at_epoch: NotRequired[float]


class ResponseTimingMiddleware(AgentMiddleware[ResponseAgentState]):
    """Record when the response agent receives each delegated task."""

    state_schema = ResponseAgentState

    def before_agent(self, state, runtime):
        return {"response_started_at_epoch": time.time()}

    async def abefore_agent(self, state, runtime):
        return {"response_started_at_epoch": time.time()}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_DURATION_LABEL: dict[str, str] = {
    "block-ip600": "10 minutes",
    "block-ip3600": "1 hour",
    "block-ip86400": "1 day",
    "block-ip0": "permanent",
    "netsh600": "10 minutes",
    "netsh3600": "1 hour",
    "netsh86400": "1 day",
    "netsh0": "permanent",
}


def _validate_ip(ip: str) -> None:
    """Validate IP address format; raises ValueError with a Chinese message on failure."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(f"无效的 IP 地址格式：'{ip}'。请提供合法的 IPv4 或 IPv6 地址。") from exc


def _format_tool_result(
    action: str,
    agent_id: str,
    target_ip: str,
    result: dict,
    *,
    direction: str | None = None,
) -> str:
    """Produce a human-readable Chinese summary string from a block/unblock result dict."""
    verification = result.get("verification")
    if isinstance(verification, dict):
        dispatch_label = "成功" if result.get("dispatch_success") else "失败"
        rule_lines = _format_rule_evidence(
            verification.get("rules", []),
            status=verification.get("status"),
        )
        lines = [
            "✅ 执行结果" if result.get("success") else "⚠️ 执行结果",
            f"- Agent：{agent_id}",
            f"- IP：{target_ip}",
            f"- 命令投递：{dispatch_label}",
        ]
        if action == "block":
            dir_label = {
                "srcip": "源地址（入站）",
                "dstip": "目的地址（出站）",
                "both": "双向",
            }.get(direction or "", direction or "")
            lines.extend(
                [
                    f"- 方向：{dir_label}",
                    f"- 时长：{result.get('duration', 'unknown')}",
                ]
            )
        lines.extend(
            [
                f"- 实际验证：{verification.get('display_status', 'unknown（状态未知）')}",
                *rule_lines,
            ]
        )
        if verification.get("recommendation"):
            lines.append(f"- 建议：{verification['recommendation']}")
        return "\n".join(lines)

    success = result.get("success", False)
    details = result.get("details", [])

    if success:
        if action == "block":
            dur = result.get("duration", "unknown")
            dir_label = {
                "srcip": "源地址（入站）",
                "dstip": "目的地址（出站）",
                "both": "双向",
            }.get(direction or "", direction or "")
            return (
                f"✅ 封禁命令已发送\n"
                f"- Agent：{agent_id}\n"
                f"- IP：{target_ip}\n"
                f"- 方向：{dir_label}\n"
                f"- 时长：{dur}\n"
                f"- 详情：{json.dumps(details, ensure_ascii=False)}"
            )
        elif action == "unblock":
            return (
                f"✅ 解封命令已发送\n"
                f"- Agent：{agent_id}\n"
                f"- IP：{target_ip}\n"
                f"- 详情：{json.dumps(details, ensure_ascii=False)}"
            )
        return json.dumps(result, ensure_ascii=False, indent=2)
    else:
        error_msg = result.get("error_message", "未知错误")
        return f"❌ 操作失败：{error_msg}\n原始响应：{json.dumps(result, ensure_ascii=False)}"


def _format_rule_evidence(rules: list[dict], *, status: str | None = None) -> list[str]:
    if not rules:
        if status == "unknown":
            return ["- 防火墙证据：未能取得实际防火墙状态"]
        return ["- 防火墙证据：未发现匹配的 Wazuh AI 封禁规则"]

    direction_labels = {"in": "入站", "out": "出站"}
    lines = ["- 防火墙证据："]
    for rule in rules:
        direction = direction_labels.get(rule.get("direction"), rule.get("direction", "未知"))
        enabled = "已启用" if rule.get("enabled") else "未启用"
        action = "阻断" if rule.get("action") == "block" else rule.get("action", "未知")
        lines.append(
            f"  - {direction}：{rule.get('ip', '未知 IP')}，{enabled}，动作={action}，"
            f"规则={rule.get('rule_name', '未知')}"
        )
    return lines


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------


@tool
def block_ip(
    agent_id: str,
    target_ip: str,
    direction: Literal["srcip", "dstip", "both"] = "srcip",
    command_name: Literal[
        "block-ip600", "block-ip3600", "block-ip86400", "block-ip0"
    ] = "block-ip600",
) -> str:
    """在指定 Agent 上封禁指定 IP 地址。

    支持按流量方向封禁，适用于入站攻击、出站 C2 通信和横向移动等多种场景。

    Args:
        agent_id: Agent ID，如 "006"。
        target_ip: 需要封禁的 IP 地址，如 "192.168.109.137"。
        direction:
            "srcip" — 作为源 IP 封禁（阻断来自该 IP 的入站流量，适用于外部攻击者）。
            "dstip" — 作为目的 IP 封禁（阻断发往该 IP 的出站流量，适用于 C2 服务器 / 横向移动目标）。
            "both"  — 双向封禁（同时阻断入站和出站流量）。
        command_name: 封禁时长控制命令。
            block-ip600  → 封禁 10 分钟（默认）
            block-ip3600 → 封禁 1 小时
            block-ip86400 → 封禁 1 天
            block-ip0    → 永久封禁
    """
    _validate_ip(target_ip)

    logger.info(
        "Tool block_ip called: agent_id=%s, target_ip=%s, direction=%s, command_name=%s",
        agent_id,
        target_ip,
        direction,
        command_name,
    )
    result = block_ip_and_verify_on_agent(
        agent_id=agent_id,
        target_ip=target_ip,
        direction=direction,
        command_name=command_name,
    )
    logger.info("Tool block_ip completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_tool_result("block", agent_id, target_ip, result, direction=direction)


@tool
def unblock_ip(
    agent_id: str,
    target_ip: str,
) -> str:
    """解除指定 Agent 上对某个 IP 的防火墙封禁规则。

    用于撤销之前通过 block_ip 添加的封禁规则，适用于误封恢复或威胁解除后的清理。

    Args:
        agent_id: Agent ID，如 "006"。
        target_ip: 需要解封的 IP 地址，如 "192.168.109.137"。
    """
    _validate_ip(target_ip)

    logger.info(
        "Tool unblock_ip called: agent_id=%s, target_ip=%s",
        agent_id,
        target_ip,
    )
    result = unblock_ip_and_verify_on_agent(
        agent_id=agent_id,
        target_ip=target_ip,
    )
    logger.info("Tool unblock_ip completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_tool_result("unblock", agent_id, target_ip, result)


@tool
def query_blocked_ips(agent_id: str, target_ip: str | None = None) -> str:
    """查询指定 Agent 上真实存在的 Wazuh AI Windows Firewall 封禁规则。

    Args:
        agent_id: Agent ID，如 "001"。
        target_ip: 可选。指定时验证该 IP；省略时查询全部 Wazuh AI 管理的封禁规则。
    """
    logger.info("Tool query_blocked_ips called: agent_id=%s target_ip=%s", agent_id, target_ip)
    result = list_blocked_ips_on_agent(agent_id=agent_id, target_ip=target_ip)
    logger.info("Tool query_blocked_ips completed: %s", json.dumps(result, ensure_ascii=False))

    lines = [
        "🔎 防火墙封禁查询结果",
        f"- Agent：{agent_id}",
        f"- 查询目标：{target_ip or '全部 Wazuh AI 管理的 IP'}",
        f"- 查询命令投递：{'成功' if result.get('dispatch_success') else '失败'}",
        f"- 最终状态：{result.get('display_status', 'unknown（状态未知）')}",
        *_format_rule_evidence(result.get("rules", []), status=result.get("status")),
    ]
    if result.get("recommendation"):
        lines.append(f"- 建议：{result['recommendation']}")
    return "\n".join(lines)


def _format_port_rule_evidence(rules: list[dict], *, status: str) -> list[str]:
    if not rules:
        if status == "unknown":
            return ["- 防火墙证据：未能取得实际防火墙状态"]
        return ["- 防火墙证据：未发现入站 TCP 54321 阻断规则"]

    lines = ["- 防火墙证据："]
    for rule in rules:
        enabled = "已启用" if rule.get("enabled") else "未启用"
        action = "阻断" if rule.get("action") == "block" else rule.get("action", "未知")
        lines.append(
            f"  - 入站 TCP {rule.get('port', 54321)}，{enabled}，动作={action}，"
            f"规则={rule.get('rule_name', '未知')}"
        )
    return lines


def _format_port_response(action: str, result: dict) -> str:
    verification = result.get("verification", result)
    status = verification.get("status", "unknown")
    if result.get("success"):
        heading = "✅ 端口响应结果"
    elif status == "unknown":
        heading = "⚠️ 端口响应结果"
    else:
        heading = "❌ 端口响应结果"

    action_labels = {
        "block": "封禁端口",
        "unblock": "解封端口",
        "query": "查询端口",
    }
    lines = [
        heading,
        f"- 操作：{action_labels[action]}",
        f"- Agent：{result.get('agent_id', '001')}",
        f"- 端口：TCP {result.get('target_port', 54321)}",
        "- 方向：入站",
    ]
    if action == "block":
        lines.append(f"- 时长：{result.get('duration_seconds', 30)} 秒")
    lines.extend(
        [
            f"- 命令投递：{'成功' if result.get('dispatch_success') else '失败'}",
            f"- 最终状态：{verification.get('display_status', 'unknown（状态未知）')}",
            *_format_port_rule_evidence(
                verification.get("rules", []),
                status=status,
            ),
        ]
    )
    if result.get("error_message"):
        lines.append(f"- 失败原因：{result['error_message']}")
    if verification.get("recommendation"):
        lines.append(f"- 建议：{verification['recommendation']}")
    if action == "unblock" and result.get("reblock_notice"):
        lines.append(f"- 再次封禁提示：{result['reblock_notice']}")
    return "\n".join(lines)


def _format_port_rejection(error: ValueError) -> str:
    return (
        "❌ 端口操作被拒绝\n"
        f"- 原因：{error}\n"
        "- 允许范围：Agent 001、入站 TCP 54321、封禁时长 30/60/300 秒"
    )


@tool
def block_port(agent_id: str, target_port: int, duration_seconds: int = 30) -> str:
    """封禁演示端口；只授权 Agent 001 的入站 TCP 54321，支持 30/60/300 秒。

    Args:
        agent_id: 必须明确提供；当前只授权 "001"。
        target_port: 必须明确提供；当前只授权 54321。
        duration_seconds: 封禁秒数，支持 30、60、300，默认 30。
    """
    try:
        result = block_port_and_verify_on_agent(
            agent_id=agent_id,
            target_port=target_port,
            duration_seconds=duration_seconds,
        )
    except ValueError as error:
        return _format_port_rejection(error)
    logger.info("Tool block_port completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_port_response("block", result)


@tool
def unblock_port(agent_id: str, target_port: int) -> str:
    """解封演示端口；只授权 Agent 001 的入站 TCP 54321。"""
    try:
        result = unblock_port_and_verify_on_agent(
            agent_id=agent_id,
            target_port=target_port,
        )
    except ValueError as error:
        return _format_port_rejection(error)
    logger.info("Tool unblock_port completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_port_response("unblock", result)


@tool
def query_blocked_port(agent_id: str, target_port: int) -> str:
    """查询演示端口的真实防火墙状态；只授权 Agent 001 的入站 TCP 54321。"""
    try:
        result = query_blocked_port_on_agent(
            agent_id=agent_id,
            target_port=target_port,
        )
    except ValueError as error:
        return _format_port_rejection(error)
    logger.info("Tool query_blocked_port completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_port_response("query", result)


_ENDPOINT_ACTION_LABELS = {
    "query_process": "查询进程",
    "terminate_process": "终止可疑进程",
    "query_account": "查询本地账户",
    "disable_account": "禁用本地账户",
    "enable_account": "启用本地账户",
}


def _format_endpoint_response(result: dict) -> str:
    status = result.get("status", "unknown")
    if status == "success":
        heading = "✅ 端点响应结果"
    elif status == "failed":
        heading = "❌ 端点响应结果"
    else:
        heading = "⚠️ 端点响应结果"

    evidence = result.get("evidence", {})
    lines = [
        heading,
        f"- Agent：{result.get('agent_id', '001')}",
        f"- 执行动作：{_ENDPOINT_ACTION_LABELS.get(result.get('action'), result.get('action'))}",
        f"- 命令投递：{'成功' if result.get('dispatch_success') else '失败'}",
        f"- 最终状态：{result.get('display_status', 'unknown（状态未知）')}",
    ]

    elapsed_seconds = result.get("process_action_elapsed_seconds")
    if (
        result.get("action") == "terminate_process"
        and status == "success"
        and isinstance(elapsed_seconds, (int, float))
    ):
        lines.extend(
            [
                f"- 进程处置耗时：{elapsed_seconds:.2f} 秒",
                "- 计时范围：从响应智能体接收任务到 Agent 确认进程关闭",
            ]
        )

    if "process_id" in evidence:
        lines.append(f"- PID：{evidence['process_id']}")
    if evidence.get("process_name"):
        lines.append(f"- 进程名称：{evidence['process_name']}")
    if "exists" in evidence:
        lines.append(f"- 进程当前存在：{'是' if evidence['exists'] else '否'}")
    if evidence.get("account_name"):
        lines.append(f"- 本地账户：{evidence['account_name']}")
    if "account_enabled" in evidence:
        lines.append(f"- 账户当前状态：{'启用' if evidence['account_enabled'] else '禁用'}")
    if evidence.get("account_sid"):
        lines.append(f"- 账户 SID：{evidence['account_sid']}")
    if "changed" in evidence:
        changed = "已发生变更" if evidence["changed"] else "无需变更，原状态已符合要求"
        lines.append(f"- 状态变更：{changed}")
    if result.get("error_message"):
        lines.append(f"- 失败原因：{result['error_message']}")
    return "\n".join(lines)


@tool
def query_process(agent_id: str, pid: int) -> str:
    """查询 Agent 001 上指定 PID；第一版只允许查询 notepad.exe 演示进程。

    Args:
        agent_id: 必须是 "001"。
        pid: 大于 0 的进程 ID。
    """
    result = query_process_on_agent(agent_id=agent_id, process_id=pid)
    logger.info("Tool query_process completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_endpoint_response(result)


@tool
def terminate_process(agent_id: str, pid: int, runtime: ToolRuntime) -> str:
    """终止 Agent 001 上指定 PID 的 notepad.exe，并验证该 PID 已不存在。

    Args:
        agent_id: 必须是 "001"。
        pid: 用户明确提供的 notepad.exe 进程 ID；禁止仅凭进程名批量终止。
    """
    started_at = runtime.state.get("response_started_at_epoch")
    if not isinstance(started_at, (int, float)):
        started_at = time.time()

    result = terminate_process_on_agent(agent_id=agent_id, process_id=pid)
    if result.get("status") == "success":
        closed_at = result.get("evidence", {}).get("process_closed_at_utc")
        if isinstance(closed_at, str):
            try:
                closed_at_epoch = datetime.fromisoformat(
                    closed_at.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                logger.warning("Invalid process_closed_at_utc value: %s", closed_at)
            else:
                elapsed_seconds = closed_at_epoch - started_at
                if elapsed_seconds >= 0:
                    result["process_action_elapsed_seconds"] = elapsed_seconds
                else:
                    logger.warning(
                        "Agent clock precedes response backend clock by %.3f seconds",
                        abs(elapsed_seconds),
                    )
    logger.info("Tool terminate_process completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_endpoint_response(result)


@tool
def query_local_account(agent_id: str, account_name: str) -> str:
    """查询 Agent 001 上固定本地演示账户 demo_user 的实际启用状态。"""
    result = query_local_account_on_agent(agent_id=agent_id, account_name=account_name)
    logger.info("Tool query_local_account completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_endpoint_response(result)


@tool
def disable_local_account(agent_id: str, account_name: str) -> str:
    """禁用 Agent 001 上固定本地账户 demo_user，并验证实际状态；不会强制注销会话。"""
    result = disable_local_account_on_agent(agent_id=agent_id, account_name=account_name)
    logger.info("Tool disable_local_account completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_endpoint_response(result)


@tool
def enable_local_account(agent_id: str, account_name: str) -> str:
    """启用 Agent 001 上固定本地账户 demo_user，并验证实际状态。"""
    result = enable_local_account_on_agent(agent_id=agent_id, account_name=account_name)
    logger.info("Tool enable_local_account completed: %s", json.dumps(result, ensure_ascii=False))
    return _format_endpoint_response(result)


@tool
def block_ip_bulk(
    agent_ids: list[str],
    target_ip: str,
    direction: Literal["srcip", "dstip", "both"] = "srcip",
    command_name: Literal[
        "block-ip600", "block-ip3600", "block-ip86400", "block-ip0"
    ] = "block-ip600",
) -> str:
    """在多个 Agent 上同时封禁指定 IP 地址。

    适用于横向移动场景 —— 攻击者同时在多台主机上活动时，一键批量封禁。

    Args:
        agent_ids: Agent ID 列表，如 ["004", "005", "006"]。
        target_ip: 需要封禁的 IP 地址。
        direction: 封禁方向，同 block_ip 的 direction 参数。
        command_name: 封禁时长控制命令，同 block_ip 的 command_name 参数。
    """
    _validate_ip(target_ip)
    if not agent_ids:
        return "❌ 批量封禁失败：未提供任何 agent_id。"

    dur = _DURATION_LABEL.get(command_name, command_name)
    dir_label = {"srcip": "源地址（入站）", "dstip": "目的地址（出站）", "both": "双向"}.get(
        direction, direction
    )

    logger.info(
        "Tool block_ip_bulk called: agent_ids=%s, target_ip=%s, direction=%s, command_name=%s",
        agent_ids,
        target_ip,
        direction,
        command_name,
    )

    results: list[dict] = []
    for aid in agent_ids:
        try:
            r = block_ip_on_agent(
                agent_id=str(aid).strip(),
                target_ip=target_ip,
                direction=direction,
                command_name=command_name,
            )
            results.append({"agent_id": aid, "result": r})
        except ValueError as exc:
            results.append(
                {"agent_id": aid, "result": {"success": False, "error_message": str(exc)}}
            )

    success_count = sum(1 for r in results if r["result"].get("success"))
    fail_count = len(results) - success_count

    summary = (
        f"批量封禁完成：{success_count} 成功 / {fail_count} 失败\n"
        f"- 目标 IP：{target_ip}\n"
        f"- 方向：{dir_label}\n"
        f"- 时长：{dur}\n"
        f"- 详情：{json.dumps(results, ensure_ascii=False, indent=2)}"
    )
    logger.info("Tool block_ip_bulk completed: %s", summary)
    return summary


# ---------------------------------------------------------------------------
# system prompt & agent factory
# ---------------------------------------------------------------------------

SYSTEM_PROMPT_TEMPLATE = """
你是事件响应智能体，负责执行 IP 与端口防火墙响应、进程处置和本地账户控制。

══════════════════════════════════════════════════════
一、Agent → IP 映射表
══════════════════════════════════════════════════════
当用户使用 IP 地址指代 Agent 时，你必须使用下表将 IP 转换为对应的 agent_id：
```json
{agent_ip_mapping_json}
```

- key 为 agent_id，value 为该 Agent 的 IP 地址
- 用户提到 IP 地址 → 在表中查找 value 匹配的行，使用对应的 key 作为 agent_id
- 用户已明确给出 agent_id（如 "006"）→ 直接使用该 id，无需查表
- 如果查不到匹配的 IP，告知用户无法找到对应 Agent

══════════════════════════════════════════════════════
二、可用工具
══════════════════════════════════════════════════════
- `block_ip`：在指定 Agent 上封禁指定 IP 地址（支持 srcip/dstip/both 方向）。
- `unblock_ip`：解除指定 Agent 上对某个 IP 的入站和出站封禁规则。
- `query_blocked_ips`：查询 Agent 上真实存在的 Wazuh AI Windows Firewall 封禁规则。
- `block_ip_bulk`：在多个 Agent 上同时封禁同一 IP。
- `block_port`：封禁 Agent 001 上固定的入站 TCP 54321 演示端口。
- `unblock_port`：解除 Agent 001 上固定演示端口的封禁。
- `query_blocked_port`：查询 Agent 001 上固定演示端口的真实防火墙状态。
- `query_process`：查询 Agent 001 上指定 PID 的 notepad.exe 演示进程。
- `terminate_process`：终止指定 PID 的 notepad.exe 并验证进程已经消失。
- `query_local_account`：查询 Agent 001 上本地演示账户 demo_user 的状态。
- `disable_local_account`：禁用 Agent 001 上的 demo_user 并验证状态。
- `enable_local_account`：启用 Agent 001 上的 demo_user 并验证状态。

══════════════════════════════════════════════════════
三、工具具体说明
══════════════════════════════════════════════════════

3.1 block_ip（封禁 IP 地址）
  封禁时长由 `command_name` 参数控制：
    - block-ip600  → 封禁 10 分钟（默认）
    - block-ip3600 → 封禁 1 小时
    - block-ip86400 → 封禁 1 天
    - block-ip0    → 永久封禁

  封禁方向由 `direction` 参数控制：
    - "srcip" → 来自该 IP 的入站流量（外部攻击者）
    - "dstip" → 发往该 IP 的出站流量（C2 服务器 / 横向移动目标）
    - "both"  → 同时阻断入站和出站

  执行规则：
    - 缺少 agent_id、IP、方向或时长时，只询问缺失的信息，不得猜测。
    - 参数完整时直接调用工具，不需要二次确认。
    - 封禁完成后，用中文向用户汇报执行结果。

3.2 unblock_ip（解封 IP 地址）
  撤销之前通过 block_ip 添加的封禁规则。
  适用于误封恢复或威胁解除后的清理。
  执行规则：
    - agent_id 和 IP 完整时直接调用工具，不需要二次确认。
    - 解封完成后，用中文向用户汇报执行结果。

3.3 query_blocked_ips（查询或验证已封禁 IP）
  - target_ip 为空时查询全部 Wazuh AI 管理的封禁规则。
  - target_ip 有值时验证指定 IP 的实际入站和出站状态。
  - 查询是只读操作，无需用户授权。
  - 必须展示工具返回的英文状态码、中文解释、防火墙证据和后续建议。

3.4 block_ip_bulk（批量封禁 IP）
  在多个 Agent 上同时封禁同一 IP。
  适用于横向移动场景，一次调用完成多台主机的封禁。

  执行规则：
    - 如果用户指定的 Agent 数量超过 10 个，先向用户确认。
    - 汇总所有 Agent 的执行结果，用中文汇报成功/失败数量。

3.5 端口封禁、解封和查询
  - 三个端口工具都必须显式传入用户给出的 agent_id 和 target_port，不得擅自改写。
  - 后端只授权 Agent 001、入站 TCP 54321；其他 Agent 或端口仍将原始参数传给工具，
    由工具返回无权限结果，不得绕过工具自行声称成功。
  - block_port 的 duration_seconds 只支持 30、60、300；用户未指定时默认传入 30。
  - 端口功能固定为入站 TCP，不询问方向或协议。
  - 参数完整时直接调用工具，不需要二次确认。
  - 端口状态只使用 blocked（已封禁）、unblocked（未封禁）、unknown（状态未知）。
  - 必须展示真实防火墙证据；只有目标状态与操作一致时才能汇报成功。
  - 手动解封后提醒用户等待原封禁时长结束再重新封禁。

3.6 进程查询与终止
  - 只允许 Agent 001，并且用户必须提供 PID；不得猜测 PID。
  - 后端只允许 PID 对应 notepad.exe，不得改为按进程名批量查询或终止。
  - 参数完整时直接调用 query_process 或 terminate_process，不需要二次确认。
  - 必须展示 success、failed、unknown 状态码、中文解释和真实进程证据。
  - 只有 success 可以汇报为已验证成功。
  - terminate_process 成功时，必须原样保留工具返回的“进程处置耗时”和“计时范围”；
    不得省略、改写或重新计算耗时。

3.7 本地账户查询、禁用与启用
  - 只允许 Agent 001 上固定的本地演示账户 demo_user。
  - 参数完整时直接调用对应工具，不需要二次确认。
  - 不得创建账户、修改密码、删除账户或强制注销会话。
  - 必须展示 success、failed、unknown 状态码、中文解释和真实账户证据。
  - 只有 success 可以汇报为已验证成功。

3.8 通用结果规则
  - 必须根据工具返回的真实结果汇报成功或失败，不得虚构 API 请求或执行结果。
  - 工具返回 unknown 时只能汇报状态未知，不得解释为成功、失败或目标不存在。
"""


def get_response_agent(model: BaseChatModel, checkpointer=None):
    """创建覆盖网络、进程和账户处置的事件响应智能体。"""
    agent_ip_mapping = extract_agent_ip_mapping()
    agent_ip_mapping_json = (
        json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2) if agent_ip_mapping else "{}"
    )
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(agent_ip_mapping_json=agent_ip_mapping_json)
    return create_agent(
        model=model,
        tools=[
            block_ip,
            unblock_ip,
            query_blocked_ips,
            block_ip_bulk,
            block_port,
            unblock_port,
            query_blocked_port,
            query_process,
            terminate_process,
            query_local_account,
            disable_local_account,
            enable_local_account,
        ],
        system_prompt=system_prompt,
        middleware=[ResponseTimingMiddleware()],
        checkpointer=checkpointer,
    )


if __name__ == "__main__":
    import logging as log_mod

    log_mod.basicConfig(
        level=log_mod.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    from langchain_openai import ChatOpenAI

    from core.config import settings

    model = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )
    agent = get_response_agent(model)

    # Quick smoke-test: block an IP
    for chunk in agent.stream(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "请帮我在 agent 006 上封禁 IP 192.168.109.114，封禁1小时",
                }
            ]
        },
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
