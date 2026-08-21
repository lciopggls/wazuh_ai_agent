import json
import re
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

BEIJING_TZ = timezone(timedelta(hours=8))
_AGENT_BLOCK_PATTERN = re.compile(r'"agent"\s*:\s*\{(?P<body>[^{}]*)\}', re.DOTALL)
_AGENT_ID_PATTERN = re.compile(r'"id"\s*:\s*"(?P<value>[^"]+)"')
_TIMESTAMP_PATTERN = re.compile(r'"timestamp"\s*:\s*"(?P<value>[^"\r\n]+)"')


def remove_rule_mitre_fields(value: Any) -> Any:
    """Return a copy of nested log data with direct ``rule.mitre`` fields removed."""
    if isinstance(value, dict):
        sanitized: dict[Any, Any] = {}
        for key, item in value.items():
            if key == "rule" and isinstance(item, dict):
                sanitized[key] = {
                    rule_key: remove_rule_mitre_fields(rule_value)
                    for rule_key, rule_value in item.items()
                    if rule_key != "mitre"
                }
            else:
                sanitized[key] = remove_rule_mitre_fields(item)
        return sanitized
    if isinstance(value, list):
        return [remove_rule_mitre_fields(item) for item in value]
    return value


def _remove_archive_label_fields(value: Any, *, in_eventdata: bool = False) -> Any:
    if isinstance(value, dict):
        sanitized: dict[Any, Any] = {}
        for key, item in value.items():
            if key == "full_log" or (in_eventdata and key == "ruleName"):
                continue
            sanitized[key] = _remove_archive_label_fields(
                item,
                in_eventdata=key == "eventdata",
            )
        return sanitized
    if isinstance(value, list):
        return [_remove_archive_label_fields(item) for item in value]
    return value


def sanitize_archive_logs(value: Any) -> Any:
    """Return archive logs without direct MITRE and duplicated label fields."""
    return _remove_archive_label_fields(remove_rule_mitre_fields(value))


def _collect_source_agent_ids(obj: Any, agent_ids: list[str]) -> None:
    """递归收集原始 Elasticsearch 日志中的 ``_source.agent.id``。"""
    if isinstance(obj, dict):
        source = obj.get("_source")
        if isinstance(source, dict):
            agent = source.get("agent")
            if isinstance(agent, dict):
                agent_id = agent.get("id")
                if isinstance(agent_id, (str, int)):
                    normalized_id = str(agent_id).strip()
                    if normalized_id:
                        agent_ids.append(normalized_id)

        for value in obj.values():
            _collect_source_agent_ids(value, agent_ids)
    elif isinstance(obj, list):
        for item in obj:
            _collect_source_agent_ids(item, agent_ids)


def _collect_source_timestamps(obj: Any, timestamps: list[datetime]) -> None:
    """递归收集原始 Elasticsearch 日志中的 ``_source.timestamp``。"""
    if isinstance(obj, dict):
        source = obj.get("_source")
        if isinstance(source, dict):
            timestamp = source.get("timestamp")
            if isinstance(timestamp, str):
                try:
                    parsed_timestamp = datetime.fromisoformat(timestamp)
                    if parsed_timestamp.tzinfo is not None:
                        timestamps.append(parsed_timestamp)
                except ValueError:
                    pass

        for value in obj.values():
            _collect_source_timestamps(value, timestamps)
    elif isinstance(obj, list):
        for item in obj:
            _collect_source_timestamps(item, timestamps)


def _iter_json_candidates(text: str) -> Iterator[str]:
    """从带有自然语言前缀的输入中提取大括号平衡的 JSON 片段。"""
    depth = 0
    start = -1
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth > 0:
            depth -= 1
            if depth == 0 and start >= 0:
                yield text[start : index + 1]
                start = -1


def _load_json_objects(text: str) -> list[Any]:
    objects: list[Any] = []
    try:
        objects.append(json.loads(text))
    except json.JSONDecodeError:
        pass

    if objects:
        return objects

    for candidate in _iter_json_candidates(text):
        try:
            objects.append(json.loads(candidate))
        except json.JSONDecodeError:
            continue
    return objects


def _extract_timestamps(text: str) -> list[datetime]:
    timestamps: list[datetime] = []

    for parsed in _load_json_objects(text):
        _collect_source_timestamps(parsed, timestamps)

    if not timestamps:
        for timestamp_match in _TIMESTAMP_PATTERN.finditer(text):
            try:
                parsed_timestamp = datetime.fromisoformat(timestamp_match.group("value"))
                if parsed_timestamp.tzinfo is not None:
                    timestamps.append(parsed_timestamp)
            except ValueError:
                continue

    return timestamps


def extract_agent_ids_from_logs(text: str) -> list[str]:
    """从输入原始日志中提取去重后的 Wazuh Agent ID。"""
    agent_ids: list[str] = []
    for parsed in _load_json_objects(text):
        _collect_source_agent_ids(parsed, agent_ids)

    if not agent_ids:
        for agent_match in _AGENT_BLOCK_PATTERN.finditer(text):
            id_match = _AGENT_ID_PATTERN.search(agent_match.group("body"))
            if id_match:
                agent_ids.append(id_match.group("value").strip())

    return list(dict.fromkeys(agent_ids))


def extract_beijing_time_from_logs(text: str) -> dict[str, str] | None:
    """从输入原始日志提取时间，并生成前后各十分钟的北京时间窗口。"""
    timestamps = _extract_timestamps(text)

    if not timestamps:
        return None

    anchor_time = min(timestamps).astimezone(BEIJING_TZ)
    window_start = (min(timestamps) - timedelta(minutes=10)).astimezone(BEIJING_TZ)
    window_end = (max(timestamps) + timedelta(minutes=10)).astimezone(BEIJING_TZ)
    alert_start = anchor_time - timedelta(minutes=1)
    alert_end = anchor_time + timedelta(minutes=1)

    return {
        "beijing_anchor": anchor_time.isoformat(),
        "beijing_start": window_start.isoformat(),
        "beijing_end": window_end.isoformat(),
        "alert_start": alert_start.isoformat(),
        "alert_end": alert_end.isoformat(),
        "beijing_display": (
            f"{window_start.strftime('%Y-%m-%d %H:%M:%S')} 至 "
            f"{window_end.strftime('%Y-%m-%d %H:%M:%S')}（北京时间）"
        ),
    }
