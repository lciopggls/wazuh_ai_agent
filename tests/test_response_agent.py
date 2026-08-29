from langchain.messages import AIMessage, HumanMessage
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.outputs import ChatGeneration, ChatResult

from agents import response_agent


class FakeToolRuntime:
    def __init__(self, state):
        self.state = state


class MockTerminateProcessModel(BaseChatModel):
    def bind_tools(self, tools, *, tool_choice=None, **kwargs):
        return self

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        tool_messages = [message for message in messages if message.type == "tool"]
        if tool_messages:
            message = AIMessage(content=str(tool_messages[-1].content))
        else:
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
        return ChatResult(generations=[ChatGeneration(message=message)])

    @property
    def _llm_type(self):
        return "mock-terminate-process"


def test_response_agent_exposes_all_confirmed_response_tools(monkeypatch):
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

    monkeypatch.setattr(response_agent, "create_agent", fake_create_agent)
    monkeypatch.setattr(response_agent, "extract_agent_ip_mapping", lambda: {"001": "10.0.0.1"})

    model = object()
    checkpointer = object()
    result = response_agent.get_response_agent(model, checkpointer=checkpointer)

    assert result is expected_agent
    assert captured["model"] is model
    assert captured["checkpointer"] is checkpointer
    assert len(captured["middleware"]) == 1
    assert isinstance(captured["middleware"][0], response_agent.ResponseTimingMiddleware)
    assert [tool.name for tool in captured["tools"]] == [
        "block_ip",
        "unblock_ip",
        "query_blocked_ips",
        "block_ip_bulk",
        "block_port",
        "unblock_port",
        "query_blocked_port",
        "query_process",
        "terminate_process",
        "query_local_account",
        "disable_local_account",
        "enable_local_account",
    ]
    terminate_tool = next(tool for tool in captured["tools"] if tool.name == "terminate_process")
    assert "runtime" not in terminate_tool.args


def test_response_agent_prompt_matches_demo_execution_and_scope_rules(monkeypatch):
    captured = {}

    def fake_create_agent(*, model, tools, system_prompt, middleware, checkpointer):
        captured["system_prompt"] = system_prompt
        return object()

    monkeypatch.setattr(response_agent, "create_agent", fake_create_agent)
    monkeypatch.setattr(response_agent, "extract_agent_ip_mapping", lambda: {})

    response_agent.get_response_agent(object())
    prompt = captured["system_prompt"]

    assert "参数完整时直接调用工具，不需要二次确认" in prompt
    assert "支持任意有效的数字 Agent ID" in prompt
    assert "只允许 Agent 001" not in prompt
    assert "只授权 Agent 001" not in prompt
    assert "30、60、300" in prompt
    assert "notepad.exe" in prompt
    assert "demo_user" in prompt
    assert "不得创建账户、修改密码、删除账户或强制注销会话" in prompt
    assert "blocked（已封禁）、unblocked（未封禁）、unknown（状态未知）" in prompt
    assert "success、failed、unknown" in prompt
    assert "进程处置耗时" in prompt
    assert "不得省略、改写或重新计算耗时" in prompt


def test_response_timing_middleware_records_each_agent_invocation(monkeypatch):
    monkeypatch.setattr(response_agent.time, "time", lambda: 1735689600.0)
    middleware = response_agent.ResponseTimingMiddleware()

    assert middleware.before_agent({}, None) == {"response_started_at_epoch": 1735689600.0}


def test_terminate_process_success_displays_response_elapsed_time(monkeypatch):
    result = {
        "status": "success",
        "display_status": "success（执行成功）",
        "action": "terminate_process",
        "agent_id": "001",
        "dispatch_success": True,
        "evidence": {
            "process_id": 4321,
            "process_name": "notepad.exe",
            "process_closed_at_utc": "2025-01-01T00:00:04.870000Z",
            "exists": False,
        },
    }
    monkeypatch.setattr(
        response_agent,
        "terminate_process_on_agent",
        lambda **_: result,
    )
    output = response_agent.terminate_process.func(
        agent_id="001",
        pid=4321,
        runtime=FakeToolRuntime({"response_started_at_epoch": 1735689600.0}),
    )

    assert "- 进程处置耗时：4.87 秒" in output
    assert "- 计时范围：从响应智能体接收任务到 Agent 确认进程关闭" in output
    assert "约" not in output
    assert output.index("- 进程处置耗时：") < output.index("- PID：4321")


def test_terminate_process_failure_does_not_display_response_elapsed_time(monkeypatch):
    result = {
        "status": "failed",
        "display_status": "failed（执行失败）",
        "action": "terminate_process",
        "agent_id": "001",
        "dispatch_success": True,
        "error_message": "目标进程仍然存在。",
        "evidence": {"process_id": 4321, "exists": True},
    }
    monkeypatch.setattr(
        response_agent,
        "terminate_process_on_agent",
        lambda **_: result,
    )

    output = response_agent.terminate_process.func(
        agent_id="001",
        pid=4321,
        runtime=FakeToolRuntime({"response_started_at_epoch": 1735689600.0}),
    )

    assert "进程处置耗时" not in output
    assert "计时范围" not in output


def test_response_agent_measures_from_invocation_through_verified_termination(monkeypatch):
    result = {
        "status": "success",
        "display_status": "success（执行成功）",
        "action": "terminate_process",
        "agent_id": "001",
        "dispatch_success": True,
        "evidence": {
            "process_id": 4321,
            "process_name": "notepad.exe",
            "process_closed_at_utc": "2025-01-01T00:00:04.870000Z",
            "exists": False,
        },
    }
    monkeypatch.setattr(response_agent, "extract_agent_ip_mapping", lambda: {})
    monkeypatch.setattr(
        response_agent,
        "terminate_process_on_agent",
        lambda **_: result,
    )
    monkeypatch.setattr(response_agent.time, "time", lambda: 1735689600.0)

    agent = response_agent.get_response_agent(MockTerminateProcessModel())
    output = agent.invoke({"messages": [HumanMessage(content="终止 Agent 001 上 PID 4321 的进程")]})

    assert "- 进程处置耗时：4.87 秒" in output["messages"][-1].content
    assert "- 计时范围：从响应智能体接收任务到 Agent 确认进程关闭" in output["messages"][-1].content
