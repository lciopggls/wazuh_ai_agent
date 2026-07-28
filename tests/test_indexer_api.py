import json
import pathlib
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest


@pytest.fixture
def demo_wazuh_api_response():
    def _load_api_response(key):
        path = pathlib.Path(__file__).parent / "fixtures" / "wazuh_api_responses.json"
        with open(path, encoding="utf-8") as f:
            return json.load(f)[key]

    return _load_api_response


def test_count_agent_alerts(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("count_agent_alerts_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/wazuh-alerts-.*/_count$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import count_agent_alerts

    response = count_agent_alerts("001", "now-1h", "now")
    assert response["count"] == 2116


def test_agent_alerts(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("agent_alerts_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/wazuh-alerts-.*/_search$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import agent_alerts

    response = agent_alerts("004", x_limit=1, ruleId=5764)
    hits = response.get("hits", {}).get("hits", [])
    assert len(hits) == 1
    assert hits[0]["_source"]["agent"]["id"] == "004"
    assert hits[0]["_source"]["rule"]["id"] == "5764"


def test_agent_alerts_accepts_custom_payload(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("agent_alerts_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:\d+/wazuh-alerts-.*/_search$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import agent_alerts

    payload = {
        "size": 10,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"agent.id": "004"}},
                    {"range": {"rule.level": {"gte": 9}}},
                ]
            }
        },
    }
    agent_alerts("004", payload=payload)

    assert requests_mock.last_request.json() == payload


def test_agent_archives(demo_wazuh_api_response, requests_mock):
    demo_response = demo_wazuh_api_response("agent_archives_response")
    requests_mock.post(
        re.compile(r"^https?://[^/:]+:9200/wazuh-archives-.*/_search$"),
        json=demo_response,
    )
    from wazuh_api.indexer_api import agent_archives

    response = agent_archives("005", keyword="whoami", x_limit=1)
    hits = response.get("hits", {}).get("hits", [])
    assert len(hits) == 1
    assert hits[0]["_source"]["agent"]["id"] == "005"


def test_indexer_requests_are_serialized(monkeypatch):
    from wazuh_api import indexer_api

    active_requests = 0
    max_active_requests = 0
    state_lock = threading.Lock()
    start_barrier = threading.Barrier(3)

    class FakeResponse:
        ok = True
        status_code = 200
        text = ""

        @staticmethod
        def raise_for_status():
            return None

        @staticmethod
        def json():
            return {"hits": {"hits": []}}

    def fake_post(*args, **kwargs):
        nonlocal active_requests, max_active_requests
        with state_lock:
            active_requests += 1
            max_active_requests = max(max_active_requests, active_requests)
        time.sleep(0.03)
        with state_lock:
            active_requests -= 1
        return FakeResponse()

    monkeypatch.setattr(indexer_api.requests, "post", fake_post)

    def query_archives(keyword):
        start_barrier.wait()
        return indexer_api.agent_archives("005", keyword=keyword)

    with ThreadPoolExecutor(max_workers=3) as executor:
        list(executor.map(query_archives, ["one", "two", "three"]))

    assert max_active_requests == 1
