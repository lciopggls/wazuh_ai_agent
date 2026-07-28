import json

from langchain_core.messages import AIMessage, HumanMessage

from agents.baseline_agent import baseline_agent as baseline_module
from agents.baseline_agent import nodes as baseline_nodes
from agents.baseline_agent import tools as baseline_tools
from agents.baseline_agent.prompt import FINAL_REPORT_PROMPT
from agents.baseline_agent.utils import (
    extract_agent_ids_from_logs,
    extract_beijing_time_from_logs,
)


def _initial_input() -> str:
    log = {
        "_index": "wazuh-archives-4.x-2026.07.26",
        "_id": "initial",
        "_source": {
            "timestamp": "2026-07-26T10:00:00.000+08:00",
            "agent": {"id": "005"},
        },
    }
    return f"请对该日志进行攻击溯源：{json.dumps(log, ensure_ascii=False)}"


def test_extract_baseline_query_context():
    user_input = _initial_input()

    assert extract_agent_ids_from_logs(user_input) == ["005"]
    assert extract_beijing_time_from_logs(user_input) == {
        "beijing_anchor": "2026-07-26T10:00:00+08:00",
        "beijing_start": "2026-07-26T09:50:00+08:00",
        "beijing_end": "2026-07-26T10:10:00+08:00",
        "alert_start": "2026-07-26T09:59:00+08:00",
        "alert_end": "2026-07-26T10:01:00+08:00",
        "beijing_display": "2026-07-26 09:50:00 至 2026-07-26 10:10:00（北京时间）",
    }


def test_extract_context_from_dashboard_pasted_log():
    user_input = r"""对该日志进行攻击溯源{
        "_index": "wazuh-alerts-4.x-2026.07.23",
        "_source": {
            "agent": {
                "ip": "192.168.109.137",
                "name": "win10",
                "id": "005"
            },
            "data": {
                "image": "C:\Windows\SysWOW64\reg.exe",
                "parentCommandLine": ""C:\Windows\System32\cmd.exe" /c reg add HKCU\SOFTWARE\SystemUpdate"
            },
            "timestamp": "2026-07-23T11:04:21.309+0800"
        }
    }"""

    assert extract_agent_ids_from_logs(user_input) == ["005"]
    assert extract_beijing_time_from_logs(user_input) == {
        "beijing_anchor": "2026-07-23T11:04:21.309000+08:00",
        "beijing_start": "2026-07-23T10:54:21.309000+08:00",
        "beijing_end": "2026-07-23T11:14:21.309000+08:00",
        "alert_start": "2026-07-23T11:03:21.309000+08:00",
        "alert_end": "2026-07-23T11:05:21.309000+08:00",
        "beijing_display": "2026-07-23 10:54:21 至 2026-07-23 11:14:21（北京时间）",
    }


def test_baseline_report_does_not_require_process_tree():
    assert "进程执行树" not in FINAL_REPORT_PROMPT

    result = baseline_nodes.final_report_node(
        {
            "error": "测试错误",
            "total_logs": 0,
            "processed_logs": 0,
        },
        model=FakeModel(),
    )

    assert "进程执行树" not in result["final_report"]


def test_count_raw_archives_by_time_uses_exact_time_window(monkeypatch):
    captured_payload = {}

    def fake_agent_archives(*, agent_id, payload):
        assert agent_id == "005"
        captured_payload.update(payload)
        return {"hits": {"total": {"value": 17, "relation": "eq"}, "hits": []}}

    monkeypatch.setattr(baseline_tools, "agent_archives", fake_agent_archives)

    total = baseline_tools.count_raw_archives_by_time(
        agent_id="005",
        start_time="2026-07-26T09:50:00+08:00",
        end_time="2026-07-26T10:10:00+08:00",
    )

    assert total == 17
    assert captured_payload["size"] == 0
    assert captured_payload["track_total_hits"] is True
    assert captured_payload["query"]["bool"]["filter"] == [
        {"term": {"agent.id": "005"}},
        {
            "range": {
                "timestamp": {
                    "gte": "2026-07-26T09:50:00+08:00",
                    "lte": "2026-07-26T10:10:00+08:00",
                }
            }
        },
    ]


def test_get_raw_archives_by_time_is_chronological_and_capped(monkeypatch):
    captured_payload = {}
    hit = {
        "_index": "wazuh-archives-4.x-2026.07.26",
        "_id": "log-10",
        "_source": {"timestamp": "2026-07-26T09:51:00.000+08:00"},
        "sort": [1785030660000, "log-10"],
    }

    def fake_agent_archives(*, agent_id, payload):
        assert agent_id == "005"
        captured_payload.update(payload)
        return {"hits": {"hits": [hit]}}

    monkeypatch.setattr(baseline_tools, "agent_archives", fake_agent_archives)

    page = baseline_tools.get_raw_archives_by_time(
        agent_id="005",
        start_time="2026-07-26T09:50:00+08:00",
        end_time="2026-07-26T10:10:00+08:00",
        search_after=[1785030600000, "log-9"],
        batch_size=100,
    )

    assert captured_payload["size"] == 10
    assert captured_payload["sort"] == [
        {"timestamp": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]
    assert captured_payload["search_after"] == [1785030600000, "log-9"]
    assert page == {"logs": [hit], "search_after": [1785030660000, "log-10"]}


def test_get_high_level_alerts_selects_by_level_then_distance(monkeypatch):
    captured_payloads = []

    def alert(alert_id, timestamp):
        return {
            "_index": "wazuh-alerts-4.x-2026.07.26",
            "_id": alert_id,
            "_source": {
                "timestamp": timestamp,
                "rule": {"level": 10},
            },
        }

    before_hits = [
        alert(
            f"before-{distance:02d}",
            f"2026-07-26T09:59:{60 - distance:02d}+08:00",
        )
        for distance in range(1, 11)
    ]
    after_hits = [
        alert(
            f"after-{distance:02d}",
            f"2026-07-26T10:00:{distance:02d}+08:00",
        )
        for distance in range(1, 4)
    ]

    def fake_agent_alerts(*, agent_id, payload):
        assert agent_id == "005"
        captured_payloads.append(payload)
        hits = before_hits if len(captured_payloads) == 1 else after_hits
        return {"hits": {"hits": hits}}

    monkeypatch.setattr(baseline_tools, "agent_alerts", fake_agent_alerts)

    alerts = baseline_tools.get_high_level_alerts_near_time(
        agent_id="005",
        anchor_time="2026-07-26T10:00:00+08:00",
        start_time="2026-07-26T09:59:00+08:00",
        end_time="2026-07-26T10:01:00+08:00",
    )

    assert len(alerts) == 10
    assert [item["_id"] for item in alerts] == [
        "before-07",
        "before-06",
        "before-05",
        "before-04",
        "before-03",
        "before-02",
        "before-01",
        "after-01",
        "after-02",
        "after-03",
    ]
    assert captured_payloads[0]["sort"][1] == {"timestamp": {"order": "desc"}}
    assert captured_payloads[1]["sort"][1] == {"timestamp": {"order": "asc"}}
    assert {
        "range": {
            "timestamp": {"gte": "2026-07-26T09:59:00+08:00", "lte": "2026-07-26T10:00:00+08:00"}
        }
    } in captured_payloads[0]["query"]["bool"]["filter"]
    assert {
        "range": {
            "timestamp": {"gt": "2026-07-26T10:00:00+08:00", "lte": "2026-07-26T10:01:00+08:00"}
        }
    } in captured_payloads[1]["query"]["bool"]["filter"]
    for payload in captured_payloads:
        assert {"range": {"rule.level": {"gte": 9}}} in payload["query"]["bool"]["filter"]


class FakeModel:
    def __init__(self):
        self.calls = []
        self.max_tokens = None

    def bind(self, **kwargs):
        self.max_tokens = kwargs["max_tokens"]
        return self

    def invoke(self, messages):
        self.calls.append({"messages": messages, "max_tokens": self.max_tokens})
        if self.max_tokens == baseline_nodes.BATCH_NOTE_MAX_TOKENS:
            return AIMessage(content=f"第 {len(self.calls)} 批调查笔记")
        return AIMessage(content="最终调查报告")


def test_baseline_agent_analyzes_ten_logs_per_batch(monkeypatch):
    pages = [
        {
            "logs": [
                {
                    "_id": f"log-{index}",
                    "_source": {"timestamp": f"2026-07-26T09:50:{index:02d}+08:00"},
                    "sort": [index, f"log-{index}"],
                }
                for index in range(10)
            ],
            "search_after": [9, "log-9"],
        },
        {
            "logs": [
                {
                    "_id": f"log-{index}",
                    "_source": {"timestamp": f"2026-07-26T09:51:{index:02d}+08:00"},
                    "sort": [index, f"log-{index}"],
                }
                for index in range(10, 12)
            ],
            "search_after": [11, "log-11"],
        },
    ]
    requested_pages = []

    monkeypatch.setattr(
        baseline_nodes,
        "count_raw_archives_by_time",
        lambda **kwargs: 12,
    )

    def fake_get_raw_archives_by_time(**kwargs):
        requested_pages.append(kwargs)
        return pages[len(requested_pages) - 1]

    monkeypatch.setattr(
        baseline_nodes,
        "get_raw_archives_by_time",
        fake_get_raw_archives_by_time,
    )
    monkeypatch.setattr(
        baseline_nodes,
        "get_high_level_alerts_near_time",
        lambda **kwargs: [],
    )

    model = FakeModel()
    agent = baseline_module.get_baseline_agent(model)
    result = agent.invoke({"messages": [HumanMessage(content=_initial_input())]})

    assert [request["batch_size"] for request in requested_pages] == [10, 10]
    assert requested_pages[0]["search_after"] is None
    assert requested_pages[1]["search_after"] == [9, "log-9"]
    assert result["processed_logs"] == 12
    assert result["batch_number"] == 2
    assert result["current_raw_logs"] == []
    assert result["alert_summary"] == baseline_nodes.NO_ALERTS_SUMMARY
    assert len(result["batch_notes"]) == 2
    assert result["final_report"] == (
        "最终调查报告\n\n"
        "---\n\n"
        "运行统计\n\n"
        "- 查询到的日志总数：12 条\n"
        "- 实际调查的日志总数：12 条"
    )
    assert "完整分析时间" not in result["final_report"]
    assert result["messages"][-1].content == result["final_report"]
    assert [call["max_tokens"] for call in model.calls] == [1000, 1000, 12000]


def test_baseline_agent_analyzes_first_twenty_batches_when_total_exceeds_limit(monkeypatch):
    monkeypatch.setattr(
        baseline_nodes,
        "count_raw_archives_by_time",
        lambda **kwargs: 201,
    )

    requested_pages = []

    def fake_get_raw_archives_by_time(**kwargs):
        requested_pages.append(kwargs)
        page_number = len(requested_pages)
        start_index = (page_number - 1) * 10
        logs = [
            {
                "_id": f"log-{index}",
                "_source": {"timestamp": "2026-07-26T10:00:00+08:00"},
                "sort": [index, f"log-{index}"],
            }
            for index in range(start_index, start_index + 10)
        ]
        return {
            "logs": logs,
            "search_after": logs[-1]["sort"],
        }

    monkeypatch.setattr(
        baseline_nodes,
        "get_raw_archives_by_time",
        fake_get_raw_archives_by_time,
    )
    monkeypatch.setattr(
        baseline_nodes,
        "get_high_level_alerts_near_time",
        lambda **kwargs: [],
    )

    model = FakeModel()
    agent = baseline_module.get_baseline_agent(model)
    result = agent.invoke({"messages": [HumanMessage(content=_initial_input())]})

    assert result["total_logs"] == 201
    assert result["processed_logs"] == 200
    assert result["batch_number"] == 20
    assert result["is_truncated"] is True
    assert len(requested_pages) == 20
    assert "完整分析时间" not in result["final_report"]
    assert "- 查询到的日志总数：201 条" in result["final_report"]
    assert "- 实际调查的日志总数：200 条" in result["final_report"]
    assert len(model.calls) == 21


def test_baseline_agent_analyzes_alerts_when_archives_are_empty(monkeypatch):
    nearby_alert = {
        "_index": "wazuh-alerts-4.x-2026.07.26",
        "_id": "nearby-alert",
        "_source": {
            "timestamp": "2026-07-26T10:00:05+08:00",
            "agent": {"id": "005"},
            "rule": {"level": 12, "description": "Nearby alert"},
        },
    }
    monkeypatch.setattr(
        baseline_nodes,
        "count_raw_archives_by_time",
        lambda **kwargs: 0,
    )
    monkeypatch.setattr(
        baseline_nodes,
        "get_high_level_alerts_near_time",
        lambda **kwargs: [nearby_alert],
    )

    model = FakeModel()
    agent = baseline_module.get_baseline_agent(model)
    result = agent.invoke({"messages": [HumanMessage(content=_initial_input())]})

    assert result["processed_logs"] == 0
    assert result["selected_alert_count"] == 1
    assert len(model.calls) == 2
    assert model.calls[0]["max_tokens"] == baseline_nodes.ALERT_NOTE_MAX_TOKENS
    final_input = model.calls[-1]["messages"][-1].content
    assert final_input.index("第一部分——初始日志") < final_input.index("第二部分——归档日志调查信息")
    assert final_input.index("第二部分——归档日志调查信息") < final_input.index(
        "第三部分——附近高等级告警摘要"
    )


def test_archive_failure_does_not_skip_alert_query(monkeypatch):
    def fail_archive_count(**kwargs):
        raise RuntimeError("archive unavailable")

    alert_queries = []
    monkeypatch.setattr(
        baseline_nodes,
        "count_raw_archives_by_time",
        fail_archive_count,
    )
    monkeypatch.setattr(
        baseline_nodes,
        "get_high_level_alerts_near_time",
        lambda **kwargs: alert_queries.append(kwargs) or [],
    )

    model = FakeModel()
    result = baseline_module.get_baseline_agent(model).invoke(
        {"messages": [HumanMessage(content=_initial_input())]}
    )

    assert len(alert_queries) == 1
    assert result["archive_error"] == "归档日志统计失败：archive unavailable"
    assert result["alert_summary"] == baseline_nodes.NO_ALERTS_SUMMARY
    assert len(model.calls) == 1


def test_alert_failure_does_not_abort_final_report(monkeypatch):
    monkeypatch.setattr(
        baseline_nodes,
        "count_raw_archives_by_time",
        lambda **kwargs: 0,
    )

    def fail_alert_query(**kwargs):
        raise RuntimeError("alerts unavailable")

    monkeypatch.setattr(
        baseline_nodes,
        "get_high_level_alerts_near_time",
        fail_alert_query,
    )

    model = FakeModel()
    result = baseline_module.get_baseline_agent(model).invoke(
        {"messages": [HumanMessage(content=_initial_input())]}
    )

    assert result["alert_error"] == "附近高等级告警查询失败：alerts unavailable"
    assert result["final_report"].startswith("最终调查报告")
    assert len(model.calls) == 1
