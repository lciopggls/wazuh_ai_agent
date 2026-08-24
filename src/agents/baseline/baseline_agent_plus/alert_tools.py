from datetime import UTC, datetime
from typing import Any

from wazuh_api.indexer_api import agent_alerts

MAX_ALERTS = 10
MIN_TARGET_ALERTS = 5
HIGH_ALERT_LEVEL = 9
SUPPLEMENT_MAX_LEVEL = 8


def _alert_time_query(
    agent_id: str,
    start_time: str,
    end_time: str,
    *,
    include_start: bool,
    include_end: bool,
    level_range: dict[str, int],
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
                {"range": {"rule.level": level_range}},
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


def _get_alert_candidates(
    *,
    agent_id: str,
    anchor_time: str,
    start_time: str,
    end_time: str,
    level_range: dict[str, int],
    size: int,
) -> list[dict[str, Any]]:
    before_payload = {
        "size": size,
        "track_total_hits": False,
        "query": _alert_time_query(
            agent_id,
            start_time,
            anchor_time,
            include_start=True,
            include_end=True,
            level_range=level_range,
        ),
        "sort": [
            {"rule.level": {"order": "desc"}},
            {"timestamp": {"order": "desc"}},
            {"_id": {"order": "asc"}},
        ],
    }
    after_payload = {
        "size": size,
        "track_total_hits": False,
        "query": _alert_time_query(
            agent_id,
            anchor_time,
            end_time,
            include_start=False,
            include_end=True,
            level_range=level_range,
        ),
        "sort": [
            {"rule.level": {"order": "desc"}},
            {"timestamp": {"order": "asc"}},
            {"_id": {"order": "asc"}},
        ],
    }

    before_response = agent_alerts(agent_id=agent_id, payload=before_payload)
    after_response = agent_alerts(agent_id=agent_id, payload=after_payload)
    return [
        *before_response.get("hits", {}).get("hits", []),
        *after_response.get("hits", {}).get("hits", []),
    ]


def _select_alerts(
    candidates: list[dict[str, Any]],
    *,
    anchor: datetime,
    limit: int,
) -> list[dict[str, Any]]:
    return sorted(
        candidates,
        key=lambda alert: (
            -_alert_level(alert),
            abs((_alert_timestamp(alert) - anchor).total_seconds()),
            str(alert.get("_id", "")),
        ),
    )[:limit]


def _sort_alerts_by_time(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        alerts,
        key=lambda alert: (
            _alert_timestamp(alert),
            str(alert.get("_id", "")),
        ),
    )


def get_nearby_alerts(
    *,
    agent_id: str,
    anchor_time: str,
    start_time: str,
    end_time: str,
) -> tuple[list[dict[str, Any]], str | None]:
    """优先选择高等级告警，不足五条时使用较低等级告警补足。"""
    anchor = datetime.fromisoformat(anchor_time)
    high_level_candidates = _get_alert_candidates(
        agent_id=agent_id,
        anchor_time=anchor_time,
        start_time=start_time,
        end_time=end_time,
        level_range={"gte": HIGH_ALERT_LEVEL},
        size=MAX_ALERTS,
    )
    high_level_alerts = _select_alerts(
        high_level_candidates,
        anchor=anchor,
        limit=MAX_ALERTS,
    )
    if len(high_level_alerts) >= MIN_TARGET_ALERTS:
        return _sort_alerts_by_time(high_level_alerts), None

    try:
        supplemental_candidates = _get_alert_candidates(
            agent_id=agent_id,
            anchor_time=anchor_time,
            start_time=start_time,
            end_time=end_time,
            level_range={"lte": SUPPLEMENT_MAX_LEVEL},
            size=MIN_TARGET_ALERTS,
        )
    except Exception as exc:
        return (
            _sort_alerts_by_time(high_level_alerts),
            f"低等级告警补充失败：{exc}",
        )

    supplemental_alerts = _select_alerts(
        supplemental_candidates,
        anchor=anchor,
        limit=MIN_TARGET_ALERTS - len(high_level_alerts),
    )
    return _sort_alerts_by_time([*high_level_alerts, *supplemental_alerts]), None
