import os
import sys
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.append(os.path.join(os.getcwd(), "src"))

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

_MISSING = object()


class MockRouterReActModel(BaseChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tool_messages = [msg for msg in messages if getattr(msg, "type", "") == "tool"]
        human_messages = [msg for msg in messages if getattr(msg, "type", "") == "human"]
        latest_user_input = str(human_messages[-1].content) if human_messages else ""

        if "先删除id为100100的规则，再去验证，最后生成一段处理说明" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_1",
                                        "name": "write_task_plan",
                                        "args": {
                                            "plan_summary": "处理规则 100100 的删除、验证与结果说明",
                                            "steps": [
                                                "删除规则 100100",
                                                "验证刚才处理的规则",
                                                "基于执行结果生成处理说明",
                                            ],
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if len(tool_messages) == 1:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_2",
                                        "name": "delegate_rule_agent",
                                        "args": {
                                            "task": "已获用户明确授权：删除 id 为 100100 的规则",
                                            "reset_context": True,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if len(tool_messages) == 2:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_3",
                                        "name": "delegate_rule_agent",
                                        "args": {
                                            "task": "已获用户明确授权：验证刚才处理的规则",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if len(tool_messages) == 3:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_4",
                                        "name": "delegate_rule_agent",
                                        "args": {
                                            "task": "基于前面执行结果生成处理说明",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[
                    ChatGeneration(
                        message=AIMessage(
                            content="已按计划完成规则 100100 的删除、验证，并生成处理说明。"
                        )
                    )
                ]
            )

        if "攻击溯源分析" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_1",
                                        "name": "delegate_attack_attribution",
                                        "args": {
                                            "task": "请先提炼调查线索并启动攻击溯源分析",
                                            "reset_context": True,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[
                    ChatGeneration(message=AIMessage(content="已启动攻击溯源并给出线索确认。"))
                ]
            )

        if "列出规则组" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_rule_query",
                                        "name": "delegate_rule_agent",
                                        "args": {
                                            "task": "列出 Wazuh 规则组",
                                            "reset_context": True,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="已列出 Wazuh 规则组。"))]
            )

        if "继续验证刚才处理的规则" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_verify",
                                        "name": "delegate_rule_agent",
                                        "args": {
                                            "task": "已获用户明确授权：验证刚才处理的规则",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="继续验证步骤已执行完毕。"))]
            )

        if "直接验证并重启manager" in latest_user_input:
            if len(tool_messages) == 0:
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="",
                                tool_calls=[
                                    {
                                        "id": "call_risky",
                                        "name": "delegate_rule_agent",
                                        "args": {
                                            "task": "验证刚才生成的规则并重启 Wazuh manager",
                                            "reset_context": False,
                                        },
                                    }
                                ],
                            )
                        )
                    ]
                )
            if any(
                '"approval_required": true' in str(msg.content).lower() for msg in tool_messages
            ):
                return ChatResult(
                    generations=[
                        ChatGeneration(
                            message=AIMessage(
                                content="该操作会触发高风险变更，我需要先取得你的明确授权后才能继续执行。"
                            )
                        )
                    ]
                )
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="危险操作已执行。"))]
            )

        if "继续调查" in latest_user_input:
            if any("报告已生成完毕。" in str(msg.content) for msg in tool_messages):
                return ChatResult(
                    generations=[ChatGeneration(message=AIMessage(content="报告已生成完毕。"))]
                )
            return ChatResult(
                generations=[
                    ChatGeneration(
                        message=AIMessage(
                            content="",
                            tool_calls=[
                                {
                                    "id": "call_3",
                                    "name": "delegate_attack_attribution",
                                    "args": {
                                        "task": "根据刚才的线索继续调查并生成报告",
                                        "reset_context": False,
                                    },
                                }
                            ],
                        )
                    )
                ]
            )

        return ChatResult(
            generations=[
                ChatGeneration(message=AIMessage(content="这是普通问题，直接由路由大模型回答。"))
            ]
        )

    @property
    def _llm_type(self):
        return "mock-router-react"


class FakeRuleAgent:
    def invoke(self, state, config=None):
        messages = list(state.get("messages", []))
        latest_message = messages[-1] if messages else {}
        latest_request = (
            latest_message.get("content", "")
            if isinstance(latest_message, dict)
            else getattr(latest_message, "content", "")
        )
        current_task = (
            latest_request.split("[当前执行子任务]\n", 1)[-1]
            if "[当前执行子任务]\n" in latest_request
            else latest_request
        )

        if "删除" in current_task and "100100" in current_task:
            messages.append(AIMessage(content="规则 100100 已删除。"))
            return {
                **state,
                "messages": messages,
                "deleted_rule_id": 100100,
                "verification_feedback": "规则 100100 已删除。",
            }
        if "验证" in current_task:
            deleted_rule_id = state.get("deleted_rule_id")
            messages.append(
                AIMessage(
                    content=(
                        "已基于刚才删除后的上下文完成验证。"
                        if deleted_rule_id == 100100
                        else "缺少待验证规则上下文。"
                    )
                )
            )
            return {
                **state,
                "messages": messages,
                "rule_id": deleted_rule_id,
                "logtest_passed": deleted_rule_id == 100100,
            }
        if "说明" in current_task:
            deleted_rule_id = state.get("deleted_rule_id")
            logtest_passed = state.get("logtest_passed")
            messages.append(
                AIMessage(
                    content=(
                        f"处理说明：规则 {deleted_rule_id} 已删除，随后完成验证，验证结果为通过。"
                        if deleted_rule_id == 100100 and logtest_passed
                        else "处理说明：由于缺少上下文，暂时无法生成准确说明。"
                    )
                )
            )
            return {
                **state,
                "messages": messages,
                "verification_feedback": messages[-1].content,
            }

        if "列出" in current_task and "规则组" in current_task:
            messages.append(
                AIMessage(content="查询到 1 条匹配的 Wazuh 规则组：\n- Group: sshd; Rules: 12")
            )
            return {
                **state,
                "messages": messages,
                "rule_query_result_type": "groups",
                "rule_query_result": {
                    "total_affected_items": 1,
                    "items": [{"name": "sshd", "count": 12}],
                },
                "rule_query_params": {"limit": 10},
            }

        messages.append(AIMessage(content="规则已生成，请确认是否验证。"))
        return {
            **state,
            "messages": messages,
            "generated_rule": "<rule id='110001'/>",
            "rule_id": 110001,
            "logtest_passed": False,
        }


class FakeAttackAgent:
    def invoke(self, state, config=None):
        messages = list(state.get("messages", []))
        latest_message = messages[-1] if messages else {}
        latest_request = (
            latest_message.get("content", "")
            if isinstance(latest_message, dict)
            else getattr(latest_message, "content", "")
        )

        if state.get("pending_question_type") == "CLUE" and (
            "继续" in latest_request or "确认" in latest_request or "生成报告" in latest_request
        ):
            messages.append(AIMessage(content="报告已生成完毕。"))
            return {
                **state,
                "messages": messages,
                "investigation_clue": "检测到可疑进程链路。",
                "is_clue_confirmed": True,
                "pending_question_type": None,
                "final_report": "攻击溯源调查报告",
            }

        messages.append(AIMessage(content="已提炼攻击线索，请确认。"))
        return {
            **state,
            "messages": messages,
            "investigation_clue": "检测到可疑进程链路。",
            "is_clue_confirmed": False,
            "pending_question_type": "CLUE",
            "final_report": None,
        }


class FakeResponseAgent:
    def __init__(self):
        self.calls = []

    def invoke(self, state, config=None):
        messages = list(state.get("messages", []))
        latest_message = messages[-1] if messages else {}
        latest_request = (
            latest_message.get("content", "")
            if isinstance(latest_message, dict)
            else getattr(latest_message, "content", "")
        )
        current_task = (
            latest_request.split("[当前执行子任务]\n", 1)[-1]
            if "[当前执行子任务]\n" in latest_request
            else latest_request
        )
        self.calls.append(current_task)
        messages.append(AIMessage(content=f"响应智能体已执行：{current_task}"))
        return {**state, "messages": messages}


class MockResponseRouterModel(BaseChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tool_messages = [message for message in messages if getattr(message, "type", "") == "tool"]
        human_messages = [
            message for message in messages if getattr(message, "type", "") == "human"
        ]
        latest_request = str(human_messages[-1].content) if human_messages else ""

        if tool_messages:
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content=tool_messages[-1].content))]
            )

        if "查询端口路由" in latest_request:
            operation = "query_blocked_port"
            task = "查询 Agent 001 的 54321 端口是否被封禁"
        elif "未授权终止路由" in latest_request:
            operation = "terminate_process"
            task = "终止 Agent 001 上 PID 4321 的 notepad.exe 进程"
        elif "已授权终止路由" in latest_request:
            operation = "terminate_process"
            task = "已获用户明确授权：终止 Agent 001 上 PID 4321 的 notepad.exe 进程"
        elif "错配操作路由" in latest_request:
            operation = "query_process"
            task = "终止 Agent 001 上 PID 4321 的 notepad.exe 进程"
        else:
            return ChatResult(
                generations=[ChatGeneration(message=AIMessage(content="无需响应委派。"))]
            )

        return ChatResult(
            generations=[
                ChatGeneration(
                    message=AIMessage(
                        content="",
                        tool_calls=[
                            {
                                "id": "call_response",
                                "name": "delegate_response_agent",
                                "args": {
                                    "operation": operation,
                                    "task": task,
                                    "reset_context": True,
                                },
                            }
                        ],
                    )
                )
            ]
        )

    @property
    def _llm_type(self):
        return "mock-response-router"


def _load_router_agent_for_test():
    mocked_wazuh_modules = {
        "wazuh_api": MagicMock(),
        "wazuh_api.server_api": MagicMock(),
        "wazuh_api.indexer_api": MagicMock(),
    }
    original_modules = {name: sys.modules.get(name, _MISSING) for name in mocked_wazuh_modules}
    sys.modules.update(mocked_wazuh_modules)
    try:
        from agents import router_agent as router_agent_module
    finally:
        for name, original_module in original_modules.items():
            if original_module is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = original_module
    return router_agent_module


def test_router_agent_plans_and_executes_three_step_rule_chain_in_one_turn():
    router_agent_module = _load_router_agent_for_test()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
    ):
        app = router_agent_module.get_router_agent(MockRouterReActModel())

        state = {
            "messages": [
                HumanMessage(
                    content="我已明确授权你执行相关变更。你先删除id为100100的规则，再去验证，最后生成一段处理说明"
                )
            ]
        }
        result = app.invoke(state)

        tool_messages = [msg for msg in result["messages"] if getattr(msg, "type", "") == "tool"]
        assert len(tool_messages) == 4
        assert (
            "已按计划完成规则 100100 的删除、验证，并生成处理说明。"
            in result["messages"][-1].content
        )
        assert "任务计划已记录" in tool_messages[0].content
        assert "规则 100100 已删除" in tool_messages[1].content
        assert "已基于刚才删除后的上下文完成验证" in tool_messages[2].content
        assert (
            "处理说明：规则 100100 已删除，随后完成验证，验证结果为通过。"
            in tool_messages[3].content
        )
        assert (
            '"steps": ["删除规则 100100", "验证刚才处理的规则", "基于执行结果生成处理说明"]'
            in tool_messages[0].content
        )


def test_router_agent_preserves_attack_specialist_state_across_turns():
    router_agent_module = _load_router_agent_for_test()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
    ):
        app = router_agent_module.get_router_agent(MockRouterReActModel())

        state = {"messages": [HumanMessage(content="请帮我对这条异常进程告警做攻击溯源分析")]}
        result = app.invoke(state)

        assert "已启动攻击溯源并给出线索确认。" in result["messages"][-1].content

        result["messages"].append(HumanMessage(content="是，继续调查"))
        continued = app.invoke(result)

        tool_messages = [msg for msg in continued["messages"] if getattr(msg, "type", "") == "tool"]
        assert "报告已生成完毕。" in tool_messages[-1].content
        assert "报告已生成完毕。" in continued["messages"][-1].content


def test_router_agent_isolates_specialist_state_by_thread_id():
    router_agent_module = _load_router_agent_for_test()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
    ):
        app = router_agent_module.get_router_agent(MockRouterReActModel())

        app.invoke(
            {
                "messages": [
                    HumanMessage(
                        content="我已明确授权你执行相关变更。你先删除id为100100的规则，再去验证，最后生成一段处理说明"
                    )
                ]
            },
            config={"configurable": {"thread_id": "thread-a"}},
        )

        isolated = app.invoke(
            {"messages": [HumanMessage(content="我已明确授权，请继续验证刚才处理的规则")]},
            config={"configurable": {"thread_id": "thread-b"}},
        )
        continued = app.invoke(
            {"messages": [HumanMessage(content="我已明确授权，请继续验证刚才处理的规则")]},
            config={"configurable": {"thread_id": "thread-a"}},
        )

        isolated_tools = [msg for msg in isolated["messages"] if getattr(msg, "type", "") == "tool"]
        continued_tools = [
            msg for msg in continued["messages"] if getattr(msg, "type", "") == "tool"
        ]

        assert "缺少待验证规则上下文。" in isolated_tools[-1].content
        assert "已基于刚才删除后的上下文完成验证。" in continued_tools[-1].content


def test_router_agent_requires_user_confirmation_before_high_risk_rule_actions():
    router_agent_module = _load_router_agent_for_test()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
    ):
        app = router_agent_module.get_router_agent(MockRouterReActModel())
        result = app.invoke({"messages": [HumanMessage(content="帮我直接验证并重启manager")]})

        tool_messages = [msg for msg in result["messages"] if getattr(msg, "type", "") == "tool"]
        assert '"approval_required": true' in tool_messages[-1].content.lower()
        assert "先取得你的明确授权" in result["messages"][-1].content


def test_router_agent_routes_readonly_rule_queries_without_confirmation():
    router_agent_module = _load_router_agent_for_test()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
    ):
        app = router_agent_module.get_router_agent(MockRouterReActModel())
        result = app.invoke({"messages": [HumanMessage(content="帮我列出规则组")]})

        tool_messages = [msg for msg in result["messages"] if getattr(msg, "type", "") == "tool"]
        assert len(tool_messages) == 1
        assert '"approval_required": true' not in tool_messages[-1].content.lower()
        assert "Group: sshd" in tool_messages[-1].content
        assert "已列出 Wazuh 规则组" in result["messages"][-1].content


def test_router_agent_answers_directly_when_no_specialist_is_needed():
    router_agent_module = _load_router_agent_for_test()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
    ):
        app = router_agent_module.get_router_agent(MockRouterReActModel())
        result = app.invoke({"messages": [HumanMessage(content="帮我查一下今天上海天气")]})

        assert "直接由路由大模型回答" in result["messages"][-1].content


def test_response_operation_risk_and_task_consistency_helpers():
    router_agent_module = _load_router_agent_for_test()

    assert router_agent_module._is_high_risk_response_operation("block_port") is True
    assert router_agent_module._is_high_risk_response_operation("terminate_process") is True
    assert router_agent_module._is_high_risk_response_operation("query_blocked_port") is False
    assert router_agent_module._is_high_risk_response_operation("enable_local_account") is False

    assert (
        router_agent_module._response_operation_task_mismatch(
            "query_blocked_ips",
            "查询 Agent 001 是否封禁了 203.0.113.10",
        )
        is None
    )
    assert (
        router_agent_module._response_operation_task_mismatch(
            "query_process",
            "终止 Agent 001 上 PID 4321 的 notepad.exe 进程",
        )
        is not None
    )
    assert (
        router_agent_module._response_operation_task_mismatch(
            "unblock_ip",
            "解除 Agent 001 对 203.0.113.10 的封禁",
        )
        is None
    )
    assert (
        router_agent_module._response_operation_task_mismatch(
            "unblock_port",
            "解除 Agent 001 上 54321 端口的封禁",
        )
        is None
    )
    assert (
        router_agent_module._response_operation_task_mismatch(
            "disable_local_account",
            "查询 Agent 001 上 demo_user 的账户状态，然后禁用该账户",
        )
        is not None
    )


def test_router_delegates_readonly_port_query_without_confirmation():
    router_agent_module = _load_router_agent_for_test()
    fake_response = FakeResponseAgent()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
        patch.object(router_agent_module, "get_response_agent", return_value=fake_response),
    ):
        app = router_agent_module.get_router_agent(MockResponseRouterModel())
        result = app.invoke({"messages": [HumanMessage(content="查询端口路由")]})

    tool_messages = [
        message for message in result["messages"] if getattr(message, "type", "") == "tool"
    ]
    assert len(fake_response.calls) == 1
    assert "查询 Agent 001 的 54321 端口" in fake_response.calls[0]
    assert '"approval_required": true' not in tool_messages[-1].content.lower()
    assert "响应智能体已执行" in result["messages"][-1].content


def test_router_blocks_high_risk_response_without_authorization():
    router_agent_module = _load_router_agent_for_test()
    fake_response = FakeResponseAgent()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
        patch.object(router_agent_module, "get_response_agent", return_value=fake_response),
    ):
        app = router_agent_module.get_router_agent(MockResponseRouterModel())
        result = app.invoke({"messages": [HumanMessage(content="未授权终止路由")]})

    tool_messages = [
        message for message in result["messages"] if getattr(message, "type", "") == "tool"
    ]
    assert fake_response.calls == []
    assert '"approval_required": true' in tool_messages[-1].content.lower()
    assert "终止进程" in tool_messages[-1].content


def test_router_delegates_high_risk_response_after_authorization():
    router_agent_module = _load_router_agent_for_test()
    fake_response = FakeResponseAgent()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
        patch.object(router_agent_module, "get_response_agent", return_value=fake_response),
    ):
        app = router_agent_module.get_router_agent(MockResponseRouterModel())
        result = app.invoke({"messages": [HumanMessage(content="已授权终止路由")]})

    assert len(fake_response.calls) == 1
    assert "已获用户明确授权" in fake_response.calls[0]
    assert "响应智能体已执行" in result["messages"][-1].content


def test_router_rejects_operation_task_mismatch_before_delegation():
    router_agent_module = _load_router_agent_for_test()
    fake_response = FakeResponseAgent()

    with (
        patch.object(router_agent_module, "get_rule_agent", return_value=FakeRuleAgent()),
        patch.object(
            router_agent_module, "get_attack_attribution_agent", return_value=FakeAttackAgent()
        ),
        patch.object(router_agent_module, "get_response_agent", return_value=fake_response),
    ):
        app = router_agent_module.get_router_agent(MockResponseRouterModel())
        result = app.invoke({"messages": [HumanMessage(content="错配操作路由")]})

    tool_messages = [
        message for message in result["messages"] if getattr(message, "type", "") == "tool"
    ]
    assert fake_response.calls == []
    assert "operation_task_mismatch" in tool_messages[-1].content


def test_router_prompt_documents_all_response_operations(monkeypatch):
    router_agent_module = _load_router_agent_for_test()
    captured = {}

    def fake_create_agent(*, model, tools, system_prompt, checkpointer):
        captured["tools"] = tools
        captured["system_prompt"] = system_prompt
        return object()

    monkeypatch.setattr(router_agent_module, "create_agent", fake_create_agent)
    monkeypatch.setattr(router_agent_module, "get_rule_agent", lambda _: FakeRuleAgent())
    monkeypatch.setattr(
        router_agent_module,
        "get_attack_attribution_agent",
        lambda _: FakeAttackAgent(),
    )
    monkeypatch.setattr(
        router_agent_module,
        "get_response_agent",
        lambda _: FakeResponseAgent(),
    )

    router_agent_module.get_router_agent(object())

    prompt = captured["system_prompt"]
    for operation in router_agent_module._RESPONSE_OPERATION_LABELS:
        assert operation in prompt
    delegate_tool = next(
        tool for tool in captured["tools"] if tool.name == "delegate_response_agent"
    )
    assert "operation" in delegate_tool.args
    assert "operation_task_mismatch" in prompt
    assert "reply 是权威执行结果" in prompt
    assert "进程处置耗时" in prompt
    assert "不得省略、改写或重新计算" in prompt
    assert "支持任意有效的数字 Agent ID" in prompt
