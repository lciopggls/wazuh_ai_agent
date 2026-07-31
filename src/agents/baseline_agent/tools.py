from datetime import UTC, datetime
from typing import Any

from wazuh_api.indexer_api import agent_alerts, agent_archives

DEFAULT_BATCH_SIZE = 5
MAX_BATCH_SIZE = 5
MAX_ALERTS = 10
MIN_ALERT_LEVEL = 9


def _time_query(agent_id: str, start_time: str, end_time: str) -> dict[str, Any]:
    return {
        "bool": {
            "filter": [
                {"term": {"agent.id": agent_id}},
                {
                    "range": {
                        "timestamp": {
                            "gte": start_time,
                            "lte": end_time,
                        }
                    }
                },
            ]
        }
    }


def count_raw_archives_by_time(
    *,
    agent_id: str,
    start_time: str,
    end_time: str,
) -> int:
    """统计指定 Agent 和固定时间范围内的原始归档日志数量。"""
    response = agent_archives(
        agent_id=agent_id,
        payload={
            "size": 0,
            "track_total_hits": True,
            "query": _time_query(agent_id, start_time, end_time),
        },
    )
    total = response.get("hits", {}).get("total", 0)
    if isinstance(total, dict):
        return int(total.get("value", 0))
    return int(total)


def get_raw_archives_by_time(
    *,
    agent_id: str,
    start_time: str,
    end_time: str,
    search_after: list[Any] | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> dict[str, Any]:
    """按时间升序返回一批未经字段精简的 Wazuh Archives 原始日志。"""
    result_size = max(1, min(batch_size, MAX_BATCH_SIZE))
    payload: dict[str, Any] = {
        "size": result_size,
        "track_total_hits": False,
        "query": _time_query(agent_id, start_time, end_time),
        "sort": [
            {"timestamp": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
    }
    if search_after is not None:
        payload["search_after"] = search_after

    response = agent_archives(agent_id=agent_id, payload=payload)
    hits = response.get("hits", {}).get("hits", [])
    next_search_after = hits[-1].get("sort") if hits else None

    return {
        "logs": hits,
        "search_after": next_search_after,
    }


def _alert_time_query(
    agent_id: str,
    start_time: str,
    end_time: str,
    *,
    include_start: bool,
    include_end: bool,
) -> dict[str, Any]:
    time_range = {
        "gte" if include_start else "gt": start_time,
        "lte" if include_end else "lt": end_time,
    }
    return {
        "bool": {
            "filter": [
                {"term": {"agent.id": agent_id}},
                {"range": {"timestamp": time_range}},
                {"range": {"rule.level": {"gte": MIN_ALERT_LEVEL}}},
            ]
        }
    }


def _alert_level(alert: dict[str, Any]) -> int:
    try:
        return int(alert.get("_source", {}).get("rule", {}).get("level", 0))
    except (TypeError, ValueError):
        return 0


def _alert_timestamp(alert: dict[str, Any]) -> datetime:
    value = alert.get("_source", {}).get("timestamp")
    if not isinstance(value, str):
        return datetime.max.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(value)
        if parsed.tzinfo is not None:
            return parsed
    except ValueError:
        pass
    return datetime.max.replace(tzinfo=UTC)


def get_high_level_alerts_near_time(
    *,
    agent_id: str,
    anchor_time: str,
    start_time: str,
    end_time: str,
) -> list[dict[str, Any]]:
    """选择初始时间附近最多十条高等级 Wazuh 告警。"""
    before_payload = {
        "size": MAX_ALERTS,
        "track_total_hits": False,
        "query": _alert_time_query(
            agent_id,
            start_time,
            anchor_time,
            include_start=True,
            include_end=True,
        ),
        "sort": [
            {"rule.level": {"order": "desc"}},
            {"timestamp": {"order": "desc"}},
            {"_id": {"order": "asc"}},
        ],
    }
    after_payload = {
        "size": MAX_ALERTS,
        "track_total_hits": False,
        "query": _alert_time_query(
            agent_id,
            anchor_time,
            end_time,
            include_start=False,
            include_end=True,
        ),
        "sort": [
            {"rule.level": {"order": "desc"}},
            {"timestamp": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
    }

    before_response = agent_alerts(agent_id=agent_id, payload=before_payload)
    after_response = agent_alerts(agent_id=agent_id, payload=after_payload)
    candidates = [
        *before_response.get("hits", {}).get("hits", []),
        *after_response.get("hits", {}).get("hits", []),
    ]
    anchor = datetime.fromisoformat(anchor_time)

    selected = sorted(
        candidates,
        key=lambda alert: (
            -_alert_level(alert),
            abs((_alert_timestamp(alert) - anchor).total_seconds()),
            str(alert.get("_id", "")),
        ),
    )[:MAX_ALERTS]
    return sorted(
        selected,
        key=lambda alert: (
            _alert_timestamp(alert),
            str(alert.get("_id", "")),
        ),
    )
