import asyncio
import importlib
import re
import sys
from unittest.mock import MagicMock, patch

import pytest
from langchain.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.outputs import ChatGeneration, ChatResult

_MISSING = object()
_HIDDEN_BRAND = re.compile("wazuh", re.IGNORECASE)


def _assert_demo_outputs_are_neutral(messages):
    for message in messages:
        if isinstance(message, (AIMessage, ToolMessage)):
            assert _HIDDEN_BRAND.search(str(message.content)) is None
            if isinstance(message, AIMessage):
                assert all(
                    _HIDDEN_BRAND.search(str(tool_call.get("name", ""))) is None
                    for tool_call in message.tool_calls
                )


class MockDemoModel(BaseChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tool_messages = [message for message in messages if message.type == "tool"]
        human_messages = [message for message in messages if message.type == "human"]
        latest_request = str(human_messages[-1].content) if human_messages else ""

        if not tool_messages and "How many" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[{"id": "call_summary", "name": "get_agent_status_summary", "args": {}}],
            )
        elif not tool_messages and "basic info" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[{"id": "call_basic", "name": "get_basic_info", "args": {}}],
            )
        elif not tool_messages and "端口" in latest_request and "解封" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_unblock_port",
                        "name": "unblock_port",
                        "args": {"agent_id": "001", "target_port": 54321},
                    }
                ],
            )
        elif not tool_messages and "端口" in latest_request and "查询" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_query_port",
                        "name": "query_blocked_port",
                        "args": {"agent_id": "001", "target_port": 54321},
                    }
                ],
            )
        elif not tool_messages and "端口" in latest_request and "封禁" in latest_request:
            target_port = 54322 if "54322" in latest_request else 54321
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_block_port",
                        "name": "block_port",
                        "args": {
                            "agent_id": "001",
                            "target_port": target_port,
                            "duration_seconds": 30,
                        },
                    }
                ],
            )
        elif not tool_messages and "终止" in latest_request and "PID" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_terminate_process",
                        "name": "terminate_process",
                        "args": {"agent_id": "001", "pid": 4321},
                    }
                ],
            )
        elif not tool_messages and "禁用" in latest_request and "demo_user" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_disable_account",
                        "name": "disable_local_account",
                        "args": {"agent_id": "001", "account_name": "demo_user"},
                    }
                ],
            )
        elif not tool_messages and "启用" in latest_request and "demo_user" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_enable_account",
                        "name": "enable_local_account",
                        "args": {"agent_id": "001", "account_name": "demo_user"},
                    }
                ],
            )
        elif not tool_messages and "查询" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_query",
                        "name": "query_blocked_ips",
                        "args": {"agent_id": "001", "target_ip": "203.0.113.10"},
                    }
                ],
            )
        elif not tool_messages and "封禁" in latest_request:
            message = AIMessage(
                content="",
                tool_calls=[
                    {
                        "id": "call_block",
                        "name": "block_ip",
                        "args": {
                            "agent_id": "001",
                            "target_ip": "203.0.113.10",
                            "direction": "both",
                            "command_name": "block-ip600",
                        },
                    }
                ],
            )
        else:
            message = AIMessage(content="WAZUH AI 操作已根据工具返回结果完成。")

        return ChatResult(generations=[ChatGeneration(message=message)])

    @property
    def _llm_type(self):
        return "mock-demo-agent"


@pytest.fixture
def demo_model():
    return MockDemoModel()


def _load_demo_agent_for_test():
    fake_server_api = MagicMock()
    fake_server_api.get_agents_status_summary.return_value = {
        "data": {
            "connection": {
                "active": 0,
                "disconnected": 1,
                "never_connected": 0,
                "pending": 0,
                "total": 1,
            },
            "configuration": {"synced": 1, "not_synced": 0, "total": 1},
        }
    }
    fake_server_api.get_wazuh_server_api_info.return_value = {
        "data": {"timestamp": "2026-01-01T00:00:00Z", "hostname": "wazuh-manager"}
    }
    mocked_modules = {
        "wazuh_api": MagicMock(),
        "wazuh_api.server_api": fake_server_api,
    }
    original_modules = {name: sys.modules.get(name, _MISSING) for name in mocked_modules}
    original_demo_module = sys.modules.pop("agents.demo_agent", _MISSING)
    sys.modules.update(mocked_modules)
    try:
        demo_agent_module = importlib.import_module("agents.demo_agent")
    finally:
        for name, original_module in original_modules.items():
            if original_module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module
        if original_demo_module is not _MISSING:
            sys.modules["agents.demo_agent"] = original_demo_module
    return demo_agent_module


def test_demo_agent(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    agent = demo_agent_module.get_demo_agent(demo_model)
    result = agent.invoke({"messages": [HumanMessage(content="How many wazuh agents are there?")]})

    assert result["messages"][1].tool_calls[0]["name"] == "get_agent_status_summary"
    assert isinstance(result["messages"][2], ToolMessage)
    assert '"total": 1' in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_hides_brand_from_real_hostname_and_final_model_reply(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    agent = demo_agent_module.get_demo_agent(demo_model)
    result = agent.invoke({"messages": [HumanMessage(content="Show basic info")]})

    assert isinstance(result["messages"][2], ToolMessage)
    assert "管理服务器" in result["messages"][2].content
    assert "智能安全响应平台" in result["messages"][3].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_async_path_also_hides_brand(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    agent = demo_agent_module.get_demo_agent(demo_model)
    result = asyncio.run(agent.ainvoke({"messages": [HumanMessage(content="Show basic info")]}))

    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_sanitizes_tool_exceptions_without_hiding_error_details(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    with patch.object(
        demo_agent_module,
        "get_agents_status_summary",
        side_effect=RuntimeError("WAZUH API connection failed on wazuh-manager"),
    ):
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="How many monitored agents are there?")]}
        )

    tool_message = result["messages"][2]
    assert isinstance(tool_message, ToolMessage)
    assert tool_message.status == "error"
    assert "connection failed" in tool_message.content
    assert "管理服务器" in tool_message.content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_visible_text_sanitizer_handles_case_hostnames_rules_and_errors():
    demo_agent_module = _load_demo_agent_for_test()

    source = (
        "WAZUH API on wazuh-manager; Wazuh Active Response; "
        "Wazuh_AI_Block_In_203.0.113.10; wAzUh connection failed"
    )
    result = demo_agent_module.sanitize_visible_text(source)

    assert _HIDDEN_BRAND.search(result) is None
    assert "安全管理接口" in result
    assert "管理服务器" in result
    assert "安全响应组件" in result
    assert "入站受管规则" in result
    assert "connection failed" in result


def test_demo_agent_dispatches_explicit_block_request(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    api_result = {
        "success": True,
        "dispatch_success": True,
        "duration": "10 minutes",
        "details": {"affected_items": ["001"]},
        "verification": {
            "status": "verified_blocked",
            "display_status": "verified_blocked（已验证封禁：要求的防火墙规则均已存在）",
            "rules": [
                {
                    "ip": "203.0.113.10",
                    "direction": "in",
                    "enabled": True,
                    "action": "block",
                    "rule_name": "Wazuh_AI_Block_In_203.0.113.10",
                },
                {
                    "ip": "203.0.113.10",
                    "direction": "out",
                    "enabled": True,
                    "action": "block",
                    "rule_name": "Wazuh_AI_Block_Out_203.0.113.10",
                },
            ],
            "recommendation": None,
        },
    }
    with patch.object(
        response_agent_module,
        "block_ip_and_verify_on_agent",
        return_value=api_result,
    ) as block_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="在 Agent 001 上双向封禁 203.0.113.10，持续10分钟")]}
        )

    block_api.assert_called_once_with(
        agent_id="001",
        target_ip="203.0.113.10",
        direction="both",
        command_name="block-ip600",
    )
    assert result["messages"][1].tool_calls[0]["name"] == "block_ip"
    assert "verified_blocked（已验证封禁" in result["messages"][2].content
    assert "入站受管规则" in result["messages"][2].content
    assert "出站受管规则" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_queries_real_firewall_state(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    query_result = {
        "dispatch_success": True,
        "display_status": "partial（部分生效：当前只有入站规则存在）",
        "rules": [
            {
                "ip": "203.0.113.10",
                "direction": "in",
                "enabled": True,
                "action": "block",
                "rule_name": "Wazuh_AI_Block_In_203.0.113.10",
            }
        ],
        "recommendation": "检查缺失方向的防火墙规则。",
    }
    with patch.object(
        response_agent_module,
        "list_blocked_ips_on_agent",
        return_value=query_result,
    ) as query_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="查询 Agent 001 是否封禁了 203.0.113.10")]}
        )

    query_api.assert_called_once_with(agent_id="001", target_ip="203.0.113.10")
    assert result["messages"][1].tool_calls[0]["name"] == "query_blocked_ips"
    assert "partial（部分生效" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_query_unknown_does_not_claim_no_matching_firewall_rules(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    query_result = {
        "status": "unknown",
        "dispatch_success": True,
        "display_status": "unknown（状态未知：查询超时）",
        "rules": [],
        "recommendation": "检查 Indexer 连接。",
    }
    with patch.object(
        response_agent_module,
        "list_blocked_ips_on_agent",
        return_value=query_result,
    ):
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="查询 Agent 001 是否封禁了 203.0.113.10")]}
        )

    tool_output = result["messages"][2].content
    assert "防火墙证据：未能取得实际防火墙状态" in tool_output
    assert "未发现匹配的受管防火墙规则" not in tool_output
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_blocks_fixed_demo_port_and_shows_real_verification(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    api_result = {
        "action": "block_port",
        "success": True,
        "dispatch_success": True,
        "agent_id": "001",
        "target_port": 54321,
        "duration_seconds": 30,
        "verification": {
            "status": "blocked",
            "display_status": "blocked（已封禁：入站 TCP 54321 阻断规则已生效。）",
            "rules": [
                {
                    "port": 54321,
                    "protocol": "tcp",
                    "direction": "in",
                    "enabled": True,
                    "action": "block",
                    "rule_name": "Demo_Block_In_TCP_54321",
                }
            ],
        },
    }
    with patch.object(
        response_agent_module,
        "block_port_and_verify_on_agent",
        return_value=api_result,
    ) as block_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="封禁 Agent 001 的 54321 端口 30 秒")]}
        )

    block_api.assert_called_once_with(
        agent_id="001",
        target_port=54321,
        duration_seconds=30,
    )
    assert result["messages"][1].tool_calls[0]["name"] == "block_port"
    assert "blocked（已封禁" in result["messages"][2].content
    assert "入站 TCP 54321" in result["messages"][2].content
    assert "Demo_Block_In_TCP_54321" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_returns_permission_denied_for_other_port_without_dispatch(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    with patch.object(
        response_agent_module,
        "block_port_and_verify_on_agent",
        side_effect=ValueError("没有权限操作 TCP 54322；仅授权入站 TCP 54321。"),
    ) as block_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="封禁 Agent 001 的 54322 端口 30 秒")]}
        )

    block_api.assert_called_once_with(
        agent_id="001",
        target_port=54322,
        duration_seconds=30,
    )
    assert "端口操作被拒绝" in result["messages"][2].content
    assert "仅授权入站 TCP 54321" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_queries_fixed_demo_port(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    api_result = {
        "action": "query_port",
        "success": True,
        "dispatch_success": True,
        "agent_id": "001",
        "target_port": 54321,
        "status": "unblocked",
        "display_status": "unblocked（未封禁：未发现入站 TCP 54321 阻断规则。）",
        "rules": [],
    }
    with patch.object(
        response_agent_module,
        "query_blocked_port_on_agent",
        return_value=api_result,
    ) as query_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="查询 Agent 001 的 54321 端口是否被封禁")]}
        )

    query_api.assert_called_once_with(agent_id="001", target_port=54321)
    assert result["messages"][1].tool_calls[0]["name"] == "query_blocked_port"
    assert "unblocked（未封禁" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_terminates_whitelisted_process_and_shows_verification(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    api_result = {
        "action": "terminate_process",
        "status": "success",
        "display_status": "success（已验证成功：PID 4321 的 notepad.exe 已经不存在。）",
        "success": True,
        "agent_id": "001",
        "dispatch_success": True,
        "evidence": {
            "process_id": 4321,
            "process_name": "notepad.exe",
            "exists": False,
            "changed": True,
        },
    }
    with patch.object(
        response_agent_module,
        "terminate_process_on_agent",
        return_value=api_result,
    ) as terminate_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke(
            {"messages": [HumanMessage(content="终止 Agent 001 上 PID 4321 的可疑进程")]}
        )

    terminate_api.assert_called_once_with(agent_id="001", process_id=4321)
    assert result["messages"][1].tool_calls[0]["name"] == "terminate_process"
    assert "success（已验证成功" in result["messages"][2].content
    assert "notepad.exe" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_disables_fixed_demo_account(demo_model):
    demo_agent_module = _load_demo_agent_for_test()

    from agents import response_agent as response_agent_module

    api_result = {
        "action": "disable_account",
        "status": "success",
        "display_status": "success（已验证成功：本地账户 demo_user 当前已禁用。）",
        "success": True,
        "agent_id": "001",
        "dispatch_success": True,
        "evidence": {
            "account_name": "demo_user",
            "account_enabled": False,
            "account_sid": "S-1-5-21-1000",
            "changed": True,
        },
    }
    with patch.object(
        response_agent_module,
        "disable_local_account_on_agent",
        return_value=api_result,
    ) as disable_api:
        agent = demo_agent_module.get_demo_agent(demo_model)
        result = agent.invoke({"messages": [HumanMessage(content="禁用 Agent 001 上的 demo_user")]})

    disable_api.assert_called_once_with(agent_id="001", account_name="demo_user")
    assert result["messages"][1].tool_calls[0]["name"] == "disable_local_account"
    assert "账户当前状态：禁用" in result["messages"][2].content
    _assert_demo_outputs_are_neutral(result["messages"])


def test_demo_agent_exposes_demo_response_tools(monkeypatch):
    demo_agent_module = _load_demo_agent_for_test()
    captured = {}
    expected_agent = object()

    def fake_create_agent(*, model, tools, system_prompt, middleware, checkpointer):
        captured.update(
            model=model,
            tools=tools,
            system_prompt=system_prompt,
            middleware=middleware,
            checkpointer=checkpointer,
        )
        return expected_agent

    monkeypatch.setattr(demo_agent_module, "create_agent", fake_create_agent)

    model = object()
    checkpointer = object()
    result = demo_agent_module.get_demo_agent(model, checkpointer=checkpointer)

    assert result is expected_agent
    assert captured["model"] is model
    assert captured["checkpointer"] is checkpointer
    assert [tool.name for tool in captured["tools"]] == [
        "get_basic_info",
        "get_agent_status_summary",
        "block_ip",
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
    assert "立即调用" in captured["system_prompt"]
    assert "不要提供手工 curl 命令" in captured["system_prompt"]
    assert "支持任意有效的数字 Agent ID" in captured["system_prompt"]
    assert "只允许 Agent 001" not in captured["system_prompt"]
    assert _HIDDEN_BRAND.search(captured["system_prompt"]) is None
    assert len(captured["middleware"]) == 1
    assert isinstance(captured["middleware"][0], demo_agent_module.DemoVisibleTextMiddleware)
