import json
import pathlib
import re

import pytest
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from agents.attack_attribution import nodes as attribution_nodes
from agents.attack_attribution.utils import format_attribution_report_message


class StaticReportModel(BaseChatModel):
    response: str = "纯报告内容"
    failure: str | None = None

    def _generate(self, messages, stop=None, run_manager=None, **kwargs):
        if self.failure:
            raise RuntimeError(self.failure)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content=self.response))])

    @property
    def _llm_type(self):
        return "static-report"


@pytest.fixture
def demo_wazuh_api_response():
    def _load_api_response(key: str):
        path = pathlib.Path(__file__).parent / "fixtures" / "wazuh_api_responses.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)[key]

    return _load_api_response


def test_get_archives_by_eventid(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("attribution_archives")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:9200/wazuh-archives-.*/_search$"),
        json=demo_response,
    )

    from agents.attack_attribution.log_retrieval_helper import QueryType, get_archives_by_eventid

    result = get_archives_by_eventid.invoke(
        {
            "agent_id": ["005"],
            "query_type": QueryType.FILE_PATH.value,
            "query_value": "lsass.exe-(PID-712).dmp",
            "event_ids": ["11"],
        }
    )
    logs = json.loads(result)

    assert isinstance(logs, list)
    assert len(logs) >= 1
    assert any(
        any(
            "lsass.exe-(PID-712).dmp"
            in str(log.get("data", {}).get("win", {}).get("eventdata", {}).get(field, ""))
            for field in (
                "image",
                "imageLoaded",
                "sourceImage",
                "targetImage",
                "targetFilename",
                "imagePath",
                "commandLine",
            )
        )
        for log in logs
    )


def test_get_archives_by_keyword(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("attribution_archives")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:9200/wazuh-archives-.*/_search$"),
        json=demo_response,
    )

    from agents.attack_attribution.log_retrieval_helper import get_archives_by_keyword

    result = get_archives_by_keyword.invoke(
        {"agent_id": ["005"], "keyword": "CertUtil.exe", "x_limit": 10}
    )
    logs = json.loads(result)

    assert isinstance(logs, list)
    assert len(logs) >= 2
    assert any("CertUtil.exe" in json.dumps(log, ensure_ascii=False) for log in logs)


def test_decision_starts_analysis_timer_only_when_entering_planner(monkeypatch):
    timer_calls = []

    def fake_perf_counter_ns():
        timer_calls.append(True)
        return 123_456_789

    monkeypatch.setattr(attribution_nodes.time, "perf_counter_ns", fake_perf_counter_ns)

    initial_state = {
        "messages": [],
        "is_clue_confirmed": True,
        "requires_mitre_kb": None,
    }
    first_result = attribution_nodes.attribution_decision_node(
        initial_state,
        {},
        StaticReportModel(),
    )

    assert first_result["analysis_started_at_ns"] == 123_456_789
    assert first_result["next_action_fromDecisionNode"]["target"] == "Attribution_Planner_Node"

    resumed_state = {**initial_state, **first_result}
    second_result = attribution_nodes.attribution_decision_node(
        resumed_state,
        {},
        StaticReportModel(),
    )

    assert "analysis_started_at_ns" not in second_result
    assert timer_calls == [True]


def test_format_report_duration_truncates_to_one_decimal_place():
    message = format_attribution_report_message("报告正文", 59.99)

    assert message == "攻击溯源调查耗时0分钟59.9秒。调查报告如下：\n\n报告正文"


def test_reporter_records_elapsed_time_without_modifying_final_report(monkeypatch):
    monkeypatch.setattr(
        attribution_nodes.time,
        "perf_counter_ns",
        lambda: 66_290_000_000,
    )

    result = attribution_nodes.reporter_node(
        {
            "messages": [],
            "analysis_started_at_ns": 1_000_000_000,
            "analysis_elapsed_seconds": None,
            "investigation_clue": "测试线索",
            "mitre_knowledge_base": {},
        },
        {},
        StaticReportModel(response="纯报告内容"),
    )

    assert result["analysis_elapsed_seconds"] == pytest.approx(65.29)
    assert result["final_report"] == "纯报告内容"
    assert result["messages"][-1].content == (
        "攻击溯源调查耗时1分钟5.2秒。调查报告如下：\n\n纯报告内容"
    )


def test_reporter_records_elapsed_time_when_report_generation_fails(monkeypatch):
    monkeypatch.setattr(
        attribution_nodes.time,
        "perf_counter_ns",
        lambda: 13_340_000_000,
    )

    result = attribution_nodes.reporter_node(
        {
            "messages": [],
            "analysis_started_at_ns": 1_000_000_000,
            "analysis_elapsed_seconds": None,
            "investigation_clue": "测试线索",
            "mitre_knowledge_base": {},
        },
        {},
        StaticReportModel(failure="model unavailable"),
    )

    assert result["analysis_elapsed_seconds"] == pytest.approx(12.34)
    assert "final_report" not in result
    assert result["messages"][-1].content == "报告生成失败，发生异常: model unavailable"


def test_reporter_requires_analysis_timer():
    with pytest.raises(
        RuntimeError,
        match="Reporter_Node requires analysis_started_at_ns",
    ):
        attribution_nodes.reporter_node(
            {
                "messages": [],
                "investigation_clue": "测试线索",
                "mitre_knowledge_base": {},
            },
            {},
            StaticReportModel(),
        )
