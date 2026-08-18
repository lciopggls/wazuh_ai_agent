import inspect
import json
import pathlib
import re
from urllib.parse import parse_qs, urlparse

import pytest


@pytest.fixture
def mock_auth(requests_mock):
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/security/user/authenticate/?$"),
        json={"data": {"token": "mock_token"}},
        status_code=200,
    )


@pytest.fixture
def demo_wazuh_api_response():
    def _load_api_response(key):
        path = pathlib.Path(__file__).parent / "fixtures" / "wazuh_api_responses.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)[key]

    return _load_api_response


@pytest.mark.usefixtures("mock_auth")
def test_get_wazuh_server_api_info(demo_wazuh_api_response, requests_mock):
    demo_api_info = demo_wazuh_api_response("api_info")
    requests_mock.get(re.compile(r"^https?://[^/:]+:\d+/?$"), json=demo_api_info)
    from wazuh_api.server_api import get_wazuh_server_api_info

    response = get_wazuh_server_api_info()
    assert "api_version" in response["data"]
    assert "hostname" in response["data"]


@pytest.mark.usefixtures("mock_auth")
def test_get_agents_status_summary(demo_wazuh_api_response, requests_mock):
    demo_agents_status_summary = demo_wazuh_api_response("agents_status_summary")
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/agents/summary/status/?$"),
        json=demo_agents_status_summary,
    )
    from wazuh_api.server_api import get_agents_status_summary

    response = get_agents_status_summary()
    assert "connection" in response["data"]
    assert "configuration" in response["data"]


@pytest.mark.usefixtures("mock_auth")
def test_get_rule_info_exists(demo_wazuh_api_response, requests_mock):
    demo_rule_info = demo_wazuh_api_response("rule_info_exists")
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules\?rule_ids=1002$"), json=demo_rule_info
    )
    from wazuh_api.server_api import get_rule_info

    response = get_rule_info(1002)
    assert response["data"]["total_affected_items"] == 1
    assert response["data"]["affected_items"][0]["id"] == 1002


@pytest.mark.usefixtures("mock_auth")
def test_get_rule_info_not_exists(demo_wazuh_api_response, requests_mock):
    demo_rule_info = demo_wazuh_api_response("rule_info_not_exists")
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules\?rule_ids=9999$"), json=demo_rule_info
    )
    from wazuh_api.server_api import get_rule_info

    response = get_rule_info(9999)
    assert response["data"]["total_affected_items"] == 0


@pytest.mark.usefixtures("mock_auth")
def test_query_rules_with_filters(demo_wazuh_api_response, requests_mock):
    demo_rules = demo_wazuh_api_response("rules_query_response")
    requests_mock.get(re.compile(r"^https?://[^/:]+:\d+/rules.*$"), json=demo_rules)
    from wazuh_api.server_api import query_rules

    response = query_rules(
        rule_ids=[5764, 5710],
        search="ssh",
        group="sshd",
        level="8-12",
        filename=["0575-win-base_rules.xml"],
        mitre="T1110",
        limit=5,
        select="id,level,description",
        sort="+id",
    )

    assert response["data"]["total_affected_items"] == 1
    query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert query_params["rule_ids"] == ["5764,5710"]
    assert query_params["search"] == ["ssh"]
    assert query_params["group"] == ["sshd"]
    assert query_params["level"] == ["8-12"]
    assert query_params["filename"] == ["0575-win-base_rules.xml"]
    assert query_params["mitre"] == ["T1110"]
    assert query_params["limit"] == ["5"]
    assert query_params["select"] == ["id,level,description"]
    assert query_params["sort"] == ["+id"]


@pytest.mark.usefixtures("mock_auth")
def test_rule_collection_endpoints(requests_mock):
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/files(\?.*)?$"),
        json={"data": {"affected_items": [{"filename": "local_rules.xml"}]}, "error": 0},
    )
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/groups(\?.*)?$"),
        json={"data": {"affected_items": [{"name": "sshd"}]}, "error": 0},
    )
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/requirement/pci_dss(\?.*)?$"),
        json={"data": {"affected_items": [{"id": 5764}]}, "error": 0},
    )
    from wazuh_api.server_api import get_rules_by_requirement, list_rule_files, list_rule_groups

    list_rule_files(search="local", limit=3)
    file_query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert requests_mock.last_request.path == "/rules/files"
    assert file_query_params["search"] == ["local"]
    assert file_query_params["limit"] == ["3"]

    list_rule_groups(limit=2)
    group_query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert requests_mock.last_request.path == "/rules/groups"
    assert group_query_params["limit"] == ["2"]

    get_rules_by_requirement("pci_dss", limit=1)
    requirement_query_params = parse_qs(urlparse(requests_mock.last_request.url).query)
    assert requests_mock.last_request.path == "/rules/requirement/pci_dss"
    assert requirement_query_params["limit"] == ["1"]


@pytest.mark.usefixtures("mock_auth")
def test_get_rule_file_endpoint(requests_mock):
    requests_mock.get(
        re.compile(r"^https?://[^/:]+:\d+/rules/files/local_rules\.xml(\?.*)?$"),
        json={"data": {"affected_items": [{"filename": "local_rules.xml"}]}, "error": 0},
    )
    from wazuh_api.server_api import get_rule_file

    response = get_rule_file("local_rules.xml")

    assert response["error"] == 0
    assert requests_mock.last_request.path == "/rules/files/local_rules.xml"


@pytest.mark.usefixtures("mock_auth")
def test_block_ip_uses_custom_script_and_preserves_direction(requests_mock):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=006$"),
        json={
            "data": {
                "affected_items": ["006"],
                "failed_items": [],
                "total_affected_items": 1,
                "total_failed_items": 0,
            },
            "message": "AR command was sent",
            "error": 0,
        },
    )
    from wazuh_api.server_api import block_ip_on_agent

    result = block_ip_on_agent(
        agent_id="006",
        target_ip="203.0.113.10",
        direction="dstip",
        command_name="netsh3600",
    )

    payload = requests_mock.last_request.json()
    assert payload == {
        "command": "block-ip3600",
        "arguments": [],
        "alert": {
            "data": {
                "action": "block",
                "dstip": "203.0.113.10",
            }
        },
    }
    assert result["success"] is True
    assert result["status"] == "dispatched"
    assert result["duration"] == "1 hour"


@pytest.mark.usefixtures("mock_auth")
def test_block_ip_both_sends_both_direction_fields(requests_mock):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=006$"),
        json={"data": {"affected_items": ["006"], "failed_items": []}, "error": 0},
    )
    from wazuh_api.server_api import block_ip_on_agent

    block_ip_on_agent(
        agent_id="006",
        target_ip="2001:db8::10",
        direction="both",
        command_name="block-ip600",
    )

    data = requests_mock.last_request.json()["alert"]["data"]
    assert data == {
        "action": "block",
        "srcip": "2001:db8::10",
        "dstip": "2001:db8::10",
    }


@pytest.mark.usefixtures("mock_auth")
def test_unblock_ip_reuses_custom_script_for_both_directions(requests_mock):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=006$"),
        json={"data": {"affected_items": ["006"], "failed_items": []}, "error": 0},
    )
    from wazuh_api.server_api import unblock_ip_on_agent

    result = unblock_ip_on_agent("006", "203.0.113.10")

    assert requests_mock.last_request.json() == {
        "command": "block-ip0",
        "arguments": [],
        "alert": {
            "data": {
                "action": "unblock",
                "srcip": "203.0.113.10",
                "dstip": "203.0.113.10",
            }
        },
    }
    assert result["success"] is True
    assert result["status"] == "dispatched"


@pytest.mark.usefixtures("mock_auth")
def test_active_response_rejects_invalid_targets_before_dispatch(requests_mock):
    from wazuh_api.server_api import block_ip_on_agent

    before = requests_mock.call_count
    with pytest.raises(ValueError, match="Invalid IP address"):
        block_ip_on_agent("006", "203.0.113.10 & whoami")
    with pytest.raises(ValueError, match="Invalid agent ID"):
        block_ip_on_agent("all", "203.0.113.10")
    with pytest.raises(ValueError, match="Unsupported block direction"):
        block_ip_on_agent("006", "203.0.113.10", direction="sideways")
    assert requests_mock.call_count == before


@pytest.mark.usefixtures("mock_auth")
def test_query_blocked_ips_returns_verified_firewall_state(requests_mock, monkeypatch):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    events = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "data": {
                            "event_type": "wazuh_ai_block_query_rule",
                            "request_id": "ignored-by-parser",
                            "ip": "203.0.113.10",
                            "direction": "in",
                            "enabled": True,
                            "firewall_action": "block",
                            "rule_name": "Wazuh_AI_Block_In_203.0.113.10",
                        }
                    }
                },
                {
                    "_source": {
                        "data": {
                            "event_type": "wazuh_ai_block_query_rule",
                            "request_id": "ignored-by-parser",
                            "ip": "203.0.113.10",
                            "direction": "out",
                            "enabled": True,
                            "firewall_action": "block",
                            "rule_name": "Wazuh_AI_Block_Out_203.0.113.10",
                        }
                    }
                },
                {
                    "_source": {
                        "data": {
                            "event_type": "wazuh_ai_block_query_complete",
                            "query_status": "ok",
                            "rule_count": 2,
                        }
                    }
                },
            ]
        }
    }
    monkeypatch.setattr(server_api, "active_response_query_events", lambda *_, **__: events)

    result = server_api.list_blocked_ips_on_agent(
        "001",
        "203.0.113.10",
        wait_timeout=0,
        poll_interval=0,
    )

    payload = requests_mock.last_request.json()["alert"]["data"]
    assert payload["action"] == "list"
    assert payload["target_ip"] == "203.0.113.10"
    assert payload["request_id"]
    assert result["status"] == "verified_blocked"
    assert result["success"] is True
    assert {rule["direction"] for rule in result["rules"]} == {"in", "out"}


@pytest.mark.parametrize(
    ("rules", "expected_action", "expected_status"),
    [
        ([], None, "verified_unblocked"),
        (
            [{"ip": "203.0.113.10", "direction": "in", "enabled": True, "action": "block"}],
            None,
            "partial",
        ),
        ([], "block", "not_applied"),
        ([], "unblock", "verified_unblocked"),
    ],
)
def test_firewall_query_status_classification(rules, expected_action, expected_status):
    from wazuh_api.server_api import _classify_query_rules

    assert (
        _classify_query_rules(
            rules,
            expected_action=expected_action,
            expected_direction="both",
        )
        == expected_status
    )


@pytest.mark.usefixtures("mock_auth")
def test_query_timeout_is_unknown_not_failure_claim(requests_mock, monkeypatch):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    monkeypatch.setattr(
        server_api,
        "active_response_query_events",
        lambda *_, **__: {"hits": {"hits": []}},
    )

    result = server_api.list_blocked_ips_on_agent(
        "001",
        "203.0.113.10",
        wait_timeout=0,
        poll_interval=0,
    )

    assert result["status"] == "unknown"
    assert result["query_completed"] is False
    assert "Timed out" in result["error_message"]


def test_firewall_query_default_wait_timeout_is_30_seconds():
    from wazuh_api.server_api import list_blocked_ips_on_agent

    signature = inspect.signature(list_blocked_ips_on_agent)

    assert signature.parameters["wait_timeout"].default == 30


def test_block_and_unblock_high_level_functions_require_verified_state(monkeypatch):
    from wazuh_api import server_api

    monkeypatch.setattr(
        server_api,
        "block_ip_on_agent",
        lambda *_: {
            "action": "block",
            "success": True,
            "status": "dispatched",
            "agent_id": "001",
            "target_ip": "203.0.113.10",
            "direction": "both",
            "duration": "10 minutes",
            "details": [],
        },
    )
    monkeypatch.setattr(
        server_api,
        "unblock_ip_on_agent",
        lambda *_: {
            "action": "unblock",
            "success": True,
            "status": "dispatched",
            "agent_id": "001",
            "target_ip": "203.0.113.10",
            "details": [],
        },
    )
    verification_statuses = iter(["partial", "verified_unblocked"])

    def fake_query(*args, **kwargs):
        status = next(verification_statuses)
        return {
            "status": status,
            "display_status": status,
            "rules": [],
        }

    monkeypatch.setattr(server_api, "list_blocked_ips_on_agent", fake_query)

    blocked = server_api.block_ip_and_verify_on_agent("001", "203.0.113.10", "both", "block-ip600")
    unblocked = server_api.unblock_ip_and_verify_on_agent("001", "203.0.113.10")

    assert blocked["dispatch_success"] is True
    assert blocked["success"] is False
    assert blocked["status"] == "partial"
    assert unblocked["dispatch_success"] is True
    assert unblocked["success"] is True
    assert unblocked["status"] == "verified_unblocked"


@pytest.mark.usefixtures("mock_auth")
def test_block_port_dispatches_fixed_inbound_tcp_rule_with_selected_duration(requests_mock):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api.server_api import block_port_on_agent

    result = block_port_on_agent("001", 54321, 60)

    assert requests_mock.last_request.json() == {
        "command": "block-port60",
        "arguments": [],
        "alert": {
            "data": {
                "action": "block",
                "target_port": "54321",
                "protocol": "tcp",
                "direction": "in",
                "duration_seconds": "60",
            }
        },
    }
    assert result["dispatch_success"] is True
    assert result["duration_seconds"] == 60
    assert result["direction"] == "in"


@pytest.mark.usefixtures("mock_auth")
def test_unblock_port_uses_non_timed_command(requests_mock):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api.server_api import unblock_port_on_agent

    result = unblock_port_on_agent("001", 54321)

    assert requests_mock.last_request.json() == {
        "command": "block-port0",
        "arguments": [],
        "alert": {
            "data": {
                "action": "unblock",
                "target_port": "54321",
                "protocol": "tcp",
                "direction": "in",
            }
        },
    }
    assert result["dispatch_success"] is True


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.parametrize(
    ("agent_id", "target_port", "duration", "message"),
    [
        ("002", 54321, 30, "仅授权 Agent 001"),
        ("001", 54322, 30, "仅授权入站 TCP 54321"),
        ("001", 54321, 45, "仅支持 30、60 或 300 秒"),
    ],
)
def test_block_port_rejects_unauthorized_scope_before_dispatch(
    requests_mock,
    agent_id,
    target_port,
    duration,
    message,
):
    from wazuh_api.server_api import block_port_on_agent

    before = requests_mock.call_count
    with pytest.raises(ValueError, match=message):
        block_port_on_agent(agent_id, target_port, duration)
    assert requests_mock.call_count == before


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.parametrize(
    ("with_rule", "expected_status"), [(True, "blocked"), (False, "unblocked")]
)
def test_query_blocked_port_returns_real_firewall_state(
    requests_mock,
    monkeypatch,
    with_rule,
    expected_status,
):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    hits = []
    if with_rule:
        hits.append(
            {
                "_source": {
                    "data": {
                        "event_type": "wazuh_ai_port_query_rule",
                        "target_port": 54321,
                        "protocol": "tcp",
                        "direction": "in",
                        "enabled": True,
                        "firewall_action": "block",
                        "rule_name": "Demo_Block_In_TCP_54321",
                    }
                }
            }
        )
    hits.append(
        {
            "_source": {
                "data": {
                    "event_type": "wazuh_ai_port_query_complete",
                    "query_status": "ok",
                    "rule_count": int(with_rule),
                }
            }
        }
    )
    monkeypatch.setattr(
        server_api,
        "active_response_query_events",
        lambda *_, **__: {"hits": {"hits": hits}},
    )

    result = server_api.query_blocked_port_on_agent(
        "001",
        54321,
        wait_timeout=0,
        poll_interval=0,
    )

    payload = requests_mock.last_request.json()
    assert payload["command"] == "block-port0"
    assert payload["alert"]["data"]["action"] == "list"
    assert payload["alert"]["data"]["target_port"] == "54321"
    assert payload["alert"]["data"]["request_id"]
    assert result["status"] == expected_status
    assert result["success"] is True


def test_port_high_level_functions_require_matching_verified_state(monkeypatch):
    from wazuh_api import server_api

    monkeypatch.setattr(
        server_api,
        "block_port_on_agent",
        lambda *_: {
            "action": "block_port",
            "success": True,
            "status": "dispatched",
            "dispatch_success": True,
            "agent_id": "001",
            "target_port": 54321,
            "duration_seconds": 30,
        },
    )
    monkeypatch.setattr(
        server_api,
        "unblock_port_on_agent",
        lambda *_: {
            "action": "unblock_port",
            "success": True,
            "status": "dispatched",
            "dispatch_success": True,
            "agent_id": "001",
            "target_port": 54321,
        },
    )
    statuses = iter(["unblocked", "unblocked"])
    monkeypatch.setattr(
        server_api,
        "query_blocked_port_on_agent",
        lambda *_: {
            "status": next(statuses),
            "display_status": "unblocked（未封禁）",
            "rules": [],
        },
    )

    blocked = server_api.block_port_and_verify_on_agent("001", 54321, 30)
    unblocked = server_api.unblock_port_and_verify_on_agent("001", 54321)

    assert blocked["success"] is False
    assert blocked["status"] == "unblocked"
    assert unblocked["success"] is True
    assert unblocked["status"] == "unblocked"
    assert "等待原封禁时长结束" in unblocked["reblock_notice"]


@pytest.mark.usefixtures("mock_auth")
def test_terminate_demo_process_dispatches_and_returns_verified_result(requests_mock, monkeypatch):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    events = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "data": {
                            "event_type": "wazuh_ai_endpoint_response_result",
                            "operation_status": "success",
                            "action": "terminate_process",
                            "process_id": 4321,
                            "process_name": "notepad.exe",
                            "exists": False,
                            "changed": True,
                        }
                    }
                }
            ]
        }
    }
    monkeypatch.setattr(server_api, "active_response_query_events", lambda *_, **__: events)

    result = server_api.terminate_process_on_agent("001", 4321, wait_timeout=0, poll_interval=0)

    payload = requests_mock.last_request.json()
    assert payload["command"] == "endpoint-response0"
    assert payload["alert"]["data"]["action"] == "terminate_process"
    assert payload["alert"]["data"]["process_id"] == 4321
    assert payload["alert"]["data"]["request_id"]
    assert result["status"] == "success"
    assert result["success"] is True
    assert result["evidence"] == {
        "process_id": 4321,
        "process_name": "notepad.exe",
        "exists": False,
        "changed": True,
    }
    assert "已验证成功" in result["display_status"]


@pytest.mark.usefixtures("mock_auth")
def test_endpoint_script_failure_is_reported_as_failed_not_unknown(requests_mock, monkeypatch):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    events = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "data": {
                            "event_type": "wazuh_ai_endpoint_response_result",
                            "operation_status": "failed",
                            "action": "terminate_process",
                            "process_id": 99,
                            "reason_code": "process_not_allowed",
                            "error_message": "Process 99 is powershell.exe, not notepad.exe",
                        }
                    }
                }
            ]
        }
    }
    monkeypatch.setattr(server_api, "active_response_query_events", lambda *_, **__: events)

    result = server_api.terminate_process_on_agent("001", 99, wait_timeout=0, poll_interval=0)

    assert result["status"] == "failed"
    assert result["query_completed"] is True
    assert "不在 notepad.exe" in result["error_message"]
    assert "powershell.exe" in result["technical_details"]


@pytest.mark.usefixtures("mock_auth")
@pytest.mark.parametrize(
    ("function_name", "expected_action", "enabled", "changed"),
    [
        ("query_local_account_on_agent", "query_account", True, False),
        ("disable_local_account_on_agent", "disable_account", False, True),
        ("enable_local_account_on_agent", "enable_account", True, True),
    ],
)
def test_demo_account_actions_use_fixed_account_and_verify_state(
    requests_mock,
    monkeypatch,
    function_name,
    expected_action,
    enabled,
    changed,
):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    events = {
        "hits": {
            "hits": [
                {
                    "_source": {
                        "data": {
                            "event_type": "wazuh_ai_endpoint_response_result",
                            "operation_status": "success",
                            "action": expected_action,
                            "account_name": "demo_user",
                            "account_enabled": enabled,
                            "account_sid": "S-1-5-21-1000",
                            "changed": changed,
                        }
                    }
                }
            ]
        }
    }
    monkeypatch.setattr(server_api, "active_response_query_events", lambda *_, **__: events)

    function = getattr(server_api, function_name)
    result = function("001", "demo_user", wait_timeout=0, poll_interval=0)

    data = requests_mock.last_request.json()["alert"]["data"]
    assert requests_mock.last_request.json()["command"] == "endpoint-response0"
    assert data["action"] == expected_action
    assert data["account_name"] == "demo_user"
    assert result["status"] == "success"
    assert result["evidence"]["account_enabled"] is enabled


@pytest.mark.usefixtures("mock_auth")
def test_endpoint_demo_scope_rejects_other_agents_accounts_and_invalid_pids(requests_mock):
    from wazuh_api import server_api

    before = requests_mock.call_count
    wrong_agent = server_api.terminate_process_on_agent("002", 1234)
    wrong_account = server_api.disable_local_account_on_agent("001", "Administrator")
    invalid_pid = server_api.terminate_process_on_agent("001", 0)

    assert requests_mock.call_count == before
    assert wrong_agent["status"] == "failed"
    assert wrong_agent["reason_code"] == "invalid_agent"
    assert wrong_account["reason_code"] == "account_not_allowed"
    assert invalid_pid["reason_code"] == "invalid_process_id"


@pytest.mark.usefixtures("mock_auth")
def test_endpoint_response_timeout_is_unknown(requests_mock, monkeypatch):
    requests_mock.put(
        re.compile(r"^https?://[^/:]+:\d+/active-response\?agents_list=001$"),
        json={"data": {"affected_items": ["001"], "failed_items": []}, "error": 0},
    )
    from wazuh_api import server_api

    monkeypatch.setattr(
        server_api,
        "active_response_query_events",
        lambda *_, **__: {"hits": {"hits": []}},
    )

    result = server_api.query_process_on_agent("001", 4321, wait_timeout=0, poll_interval=0)

    assert result["status"] == "unknown"
    assert result["dispatch_success"] is True
    assert result["query_completed"] is False
    assert "30 秒" in result["error_message"]


def test_endpoint_response_functions_default_to_30_second_verification():
    from wazuh_api.server_api import (
        disable_local_account_on_agent,
        query_process_on_agent,
        terminate_process_on_agent,
    )

    for function in (
        query_process_on_agent,
        terminate_process_on_agent,
        disable_local_account_on_agent,
    ):
        assert inspect.signature(function).parameters["wait_timeout"].default == 30
