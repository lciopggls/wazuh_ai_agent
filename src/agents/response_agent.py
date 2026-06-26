import json
import logging
from typing import Literal

from langchain.agents import create_agent
from langchain.tools import tool
from langchain_core.language_models.chat_models import BaseChatModel

from agents.attack_attribution.utils import extract_agent_ip_mapping
from wazuh_api.server_api import block_ip_on_agent

logger = logging.getLogger(__name__)

SYSTEM_PROMPT_TEMPLATE = """
你是事件响应智能体，负责执行封禁 IP 等自动化响应动作。

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
- `block_ip`：在指定 Agent 上封禁指定 IP 地址。

══════════════════════════════════════════════════════
三、工具具体说明
══════════════════════════════════════════════════════
3.1 block_ip （封禁IP地址）
  封禁时长由 `command_name` 参数控制，有效取值：
    - netsh600  → 封禁 10 分钟（默认）
    - netsh3600 → 封禁 1 小时
    - netsh86400 → 封禁 1 天
    - netsh0    → 永久封禁

  执行规则：
    - 缺少 agent_id 或 IP 时，向用户询问缺失的信息。
    - 封禁完成后，用中文向用户汇报执行结果（成功/失败及原因）。
"""


@tool
def block_ip(
    agent_id: str,
    target_ip: str,
    command_name: Literal["netsh600", "netsh3600", "netsh86400", "netsh0"] = "netsh600",
) -> str:
    """在指定 Agent 上封禁指定 IP 地址。

    Args:
        agent_id: Agent ID，如 "006"。
        target_ip: 需要封禁的 IP 地址，如 "192.168.109.137"。
        command_name: 封禁时长控制命令。
            netsh600  → 封禁 10 分钟（默认）
            netsh3600 → 封禁 1 小时
            netsh86400 → 封禁 1 天
            netsh0    → 永久封禁
    """
    logger.info(
        "Tool block_ip called: agent_id=%s, target_ip=%s, command_name=%s",
        agent_id,
        target_ip,
        command_name,
    )
    response = block_ip_on_agent(
        agent_id=agent_id,
        target_ip=target_ip,
        command_name=command_name,
    )
    logger.info("Tool block_ip completed: %s", json.dumps(response, ensure_ascii=False))
    return json.dumps(response, ensure_ascii=False)


def get_response_agent(model: BaseChatModel, checkpointer=None):
    """创建事件响应智能体，用于执行封禁 IP 等自动化响应动作。"""
    agent_ip_mapping = extract_agent_ip_mapping()
    agent_ip_mapping_json = (
        json.dumps(agent_ip_mapping, ensure_ascii=False, indent=2) if agent_ip_mapping else "{}"
    )
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(agent_ip_mapping_json=agent_ip_mapping_json)
    return create_agent(
        model=model,
        tools=[block_ip],
        system_prompt=system_prompt,
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
    for chunk in agent.stream(
        {"messages": [{"role": "user", "content": "请帮我在 agent 006 上封禁 IP 192.168.109.114，封禁1小时"}]},
        stream_mode="values",
    ):
        latest_message = chunk["messages"][-1]
        if latest_message.content:
            print(f"Agent: {latest_message.content}")
        elif latest_message.tool_calls:
            print(f"Calling tools: {[tc['name'] for tc in latest_message.tool_calls]}")
