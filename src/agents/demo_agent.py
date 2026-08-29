import json
import re
from dataclasses import replace

from langchain.agents import create_agent
from langchain.agents.middleware import AgentMiddleware, ModelResponse
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, ToolMessage
from langgraph.types import Command

from wazuh_api.server_api import get_agents_status_summary, get_wazuh_server_api_info

system_prompt = """
你是智能安全响应平台的演示智能体。

可用能力：
- 查询管理服务器的基本信息和 Agent 状态汇总。
- 使用 `block_ip` 在指定 Agent 上封禁单个 IP。
- 使用 `unblock_ip` 解除指定 Agent 上某个 IP 的入站和出站封禁。
- 使用 `query_blocked_ips` 查询真实存在的受管防火墙规则。
- 使用 `query_process` 查询指定 Agent 上指定 PID 的 notepad.exe 演示进程。
- 使用 `terminate_process` 终止指定 PID 的 notepad.exe 并验证进程已经消失。
- 查询、禁用或启用指定 Agent 上固定的本地演示账户 `demo_user`。
- 使用 `block_port`、`unblock_port` 和 `query_blocked_port` 管理演示端口。

执行规则：
1. 当封禁请求明确包含 agent_id、目标 IP、封禁方向和封禁时长时，立即调用
   `block_ip`，不要声称缺少安全响应工具，也不要提供手工 curl 命令。
2. 封禁方向必须使用：`srcip`（入站）、`dstip`（出站）或 `both`（双向）。
3. 封禁时长必须映射为：10 分钟=`block-ip600`、1 小时=`block-ip3600`、
   1 天=`block-ip86400`、永久=`block-ip0`。
4. 当封禁请求缺少 agent_id、目标 IP、方向或时长时，只询问缺失的信息，不要猜测。
5. 当解封请求明确包含 agent_id 和目标 IP 时，立即调用 `unblock_ip`。
6. 查询请求不需要确认。查询全部规则时省略 target_ip；验证指定 IP 时传入 target_ip。
7. 封禁和解封工具会自动完成真实防火墙验证。必须展示状态码及其中文解释，只有
   `verified_blocked` 或 `verified_unblocked` 可以汇报为“已验证成功”。
8. 必须根据工具返回的真实结果汇报成功或失败，不得虚构 API 请求或执行结果。
9. 进程功能支持任意有效的数字 Agent ID、必须提供 PID，并且只允许 `notepad.exe`；不得猜测 PID，
   不得改为按进程名批量终止。信息完整时直接调用工具，不需要二次确认。
10. 账户功能支持任意有效的数字 Agent ID，但只允许 `demo_user`。查询、禁用和启用请求信息完整时
    直接调用对应工具，不需要二次确认，不得调用工具创建账户或强制注销会话。
11. 新增端点响应只使用 `success`、`failed`、`unknown` 三种状态；必须展示状态码、
    中文解释和真实证据。只有 `success` 可以汇报为“已验证成功”。
12. 所有用户可见回复都使用“智能安全响应平台”“管理服务器”“受管防火墙规则”等
    中性称呼，不得复述底层产品品牌、内部规则前缀或包含这些内容的真实主机名。
13. 端口功能必须显式传入用户给出的 agent_id 和 target_port，不得擅自改写。封禁时长支持
    30、60、300 秒；用户未指定时默认传入 30。Agent 和端口完整时立即调用 `block_port`。
14. 端口功能支持任意有效的数字 Agent ID，但目标 Agent 必须已部署脚本和日志采集配置。
    如果用户请求的不是 TCP 54321，仍必须将原始参数传给工具，由工具返回无权限结果；
    不得绕过工具自行声称操作成功。
15. 端口功能固定为入站 TCP，不询问方向或协议。解封调用 `unblock_port`，查询调用
    `query_blocked_port`，两者均不需要二次确认。
16. 端口结果只使用 `blocked（已封禁）`、`unblocked（未封禁）` 和
    `unknown（状态未知）`。必须展示工具返回的真实防火墙证据；只有目标状态与操作一致时
    才能汇报成功。手动解封后提醒用户等待原封禁时长结束再重新封禁。
"""


_VISIBLE_TEXT_REPLACEMENTS = (
    (re.compile(r"wazuh_ai_block_in_[^\s,，]+", re.IGNORECASE), "入站受管规则"),
    (re.compile(r"wazuh_ai_block_out_[^\s,，]+", re.IGNORECASE), "出站受管规则"),
    (re.compile(r"wazuh[-_ ]manager", re.IGNORECASE), "管理服务器"),
    (re.compile(r"wazuh[-_ ]server", re.IGNORECASE), "管理服务器"),
    (re.compile(r"wazuh\s+active\s+response", re.IGNORECASE), "安全响应组件"),
    (re.compile(r"wazuh\s+api", re.IGNORECASE), "安全管理接口"),
    (re.compile(r"wazuh\s+agent", re.IGNORECASE), "Agent"),
    (re.compile(r"wazuh[-_ ]ai", re.IGNORECASE), "智能安全响应平台"),
    (re.compile(r"wazuh", re.IGNORECASE), "智能安全响应平台"),
)


def sanitize_visible_text(text: str) -> str:
    """Remove internal product branding from demo-only user-visible text."""
    sanitized = text
    for pattern, replacement in _VISIBLE_TEXT_REPLACEMENTS:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


def _sanitize_visible_value(value):
    if isinstance(value, str):
        return sanitize_visible_text(value)
    if isinstance(value, list):
        return [_sanitize_visible_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_sanitize_visible_value(item) for item in value)
    if isinstance(value, dict):
        return {key: _sanitize_visible_value(item) for key, item in value.items()}
    return value


def _sanitize_message(message):
    if isinstance(message, (AIMessage, ToolMessage)):
        return message.model_copy(update={"content": _sanitize_visible_value(message.content)})
    return message


def _sanitize_model_response(response):
    if isinstance(response, AIMessage):
        return _sanitize_message(response)
    if isinstance(response, ModelResponse):
        return replace(
            response,
            result=[_sanitize_message(message) for message in response.result],
        )
    return response


def _sanitize_tool_result(result):
    if isinstance(result, ToolMessage):
        return _sanitize_message(result)
    if isinstance(result, Command) and isinstance(result.update, dict):
        sanitized_update = _sanitize_visible_value(result.update)
        return replace(result, update=sanitized_update)
    return result


def _sanitized_tool_error(request, error: Exception) -> ToolMessage:
    return ToolMessage(
        content=sanitize_visible_text(f"工具执行失败：{error}"),
        tool_call_id=str(request.tool_call.get("id", "unknown")),
        name=sanitize_visible_text(str(request.tool_call.get("name", "tool"))),
        status="error",
    )


class DemoVisibleTextMiddleware(AgentMiddleware):
    """Sanitize model and tool output before it reaches the demo conversation."""

    def wrap_model_call(self, request, handler):
        return _sanitize_model_response(handler(request))

    async def awrap_model_call(self, request, handler):
        return _sanitize_model_response(await handler(request))

    def wrap_tool_call(self, request, handler):
        try:
            return _sanitize_tool_result(handler(request))
        except Exception as error:
            return _sanitized_tool_error(request, error)

    async def awrap_tool_call(self, request, handler):
        try:
            return _sanitize_tool_result(await handler(request))
        except Exception as error:
            return _sanitized_tool_error(request, error)


@tool
def get_agent_status_summary():
    """Get the status summary of monitored agents."""
    response = get_agents_status_summary()
    return sanitize_visible_text(json.dumps(response["data"]))


@tool
def get_basic_info():
    """Get the current time and the neutralized management server name."""
    response = get_wazuh_server_api_info()
    visible_data = {
        "timestamp": response["data"]["timestamp"],
        "hostname": sanitize_visible_text(response["data"]["hostname"]),
    }
    return sanitize_visible_text(json.dumps(visible_data, ensure_ascii=False))


def get_demo_agent(model: BaseChatModel, checkpointer=None):
    # Reuse the tested Active Response tools without routing through another agent.
    # Import lazily so the basic demo module remains lightweight during discovery.
    from agents.response_agent import (
        block_ip,
        block_port,
        disable_local_account,
        enable_local_account,
        query_blocked_ips,
        query_blocked_port,
        query_local_account,
        query_process,
        terminate_process,
        unblock_ip,
        unblock_port,
    )

    return create_agent(
        model=model,
        tools=[
            get_basic_info,
            get_agent_status_summary,
            block_ip,
            unblock_ip,
            query_blocked_ips,
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
        middleware=[DemoVisibleTextMiddleware()],
        checkpointer=checkpointer,
    )


if __name__ == "__main__":
    from langchain_openai import ChatOpenAI

    from core.config import settings

    model = ChatOpenAI(
        model=settings.TEST_LLM_MODEL,
        api_key=settings.TEST_LLM_API_KEY,
        base_url=settings.TEST_LLM_BASE_URL,
    )
    demo_agent = get_demo_agent(model)
    for chunk in demo_agent.stream(
        {"messages": [{"role": "user", "content": "How many agents are there?"}]},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
