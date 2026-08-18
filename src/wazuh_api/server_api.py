import ipaddress
import logging
import re
import time
import uuid
from typing import Literal

import requests

from core.config import settings
from wazuh_api.indexer_api import active_response_query_events
from wazuh_api.wazuh_server_token import wazuh_server_token

logger = logging.getLogger(__name__)

protocol = settings.WAZUH_SERVER_API_PROTOCOL
host = settings.WAZUH_SERVER_API_HOST
port = settings.WAZUH_SERVER_API_PORT

requests_headers = {
    "Content-Type": "application/json",
    # Authorization header is set lazily in each function to avoid an import-time
    # network call that would prevent the server from starting when Wazuh is down.
    "Authorization": None,
}


def get_wazuh_server_api_info():
    logger.info("Getting API information")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(f"{protocol}://{host}:{port}", headers=requests_headers, verify=False)
    logger.info("Get API information successfully")
    return response.json()


def get_agents_status_summary():
    logger.info("Getting agents status summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents/summary/status", headers=requests_headers, verify=False
    )
    logger.info("Get agents status summary successfully")
    return response.json()


def get_agents_summary():
    """Get summary of agents."""
    logger.info("Getting agents summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents/summary", headers=requests_headers, verify=False
    )
    logger.info("Get agents summary successfully")
    return response.json()


def list_agents(pretty: bool = False):
    """List all agents."""
    logger.info("Listing all agents")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents?pretty={pretty}",
        headers=requests_headers,
        verify=False,
    )
    logger.info("List all agents successfully")
    return response.json()


def get_agents_os_summary():
    """Get summary of agents operating systems."""
    logger.info("Getting agents OS summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/agents/summary/os",
        headers=requests_headers,
        verify=False,
    )
    logger.info("Get agents OS summary successfully")
    return response.json()


def get_agents_overview():
    """Get overview of agents."""
    logger.info("Getting agents overview")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/overview/agents",
        headers=requests_headers,
        verify=False,
    )
    logger.info("Get agents overview successfully")
    return response.json()


def get_rule_info(rule_id: int):
    """Get information about a specific rule by its ID."""
    logger.info(f"Getting rule information for rule ID: {rule_id}")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/rules?rule_ids={rule_id}",
        headers=requests_headers,
        verify=False,
    )
    logger.info(f"Get rule information for rule ID {rule_id} successfully")
    return response.json()


def _join_api_values(value):
    if value is None:
        return None
    if isinstance(value, (list, tuple, set)):
        values = [str(item) for item in value if item is not None and str(item) != ""]
        return ",".join(values) if values else None
    return value


def _clean_api_params(raw_params: dict):
    return {key: value for key, value in raw_params.items() if value not in (None, "", [])}


def query_rules(
    rule_ids: int | str | list[int | str] | None = None,
    search: str | None = None,
    group: str | None = None,
    level: str | int | None = None,
    filename: str | list[str] | None = None,
    relative_dirname: str | None = None,
    status: str | None = None,
    pci_dss: str | None = None,
    gdpr: str | None = None,
    gpg13: str | None = None,
    hipaa: str | None = None,
    tsc: str | None = None,
    mitre: str | None = None,
    limit: int | None = None,
    offset: int | None = None,
    select: str | None = None,
    sort: str | None = None,
    q: str | None = None,
    pretty: bool | None = None,
    wait_for_complete: bool | None = None,
    distinct: bool | None = None,
):
    """Query Wazuh rules with the filters supported by GET /rules."""
    logger.info("Querying rules")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"

    raw_params = {
        "rule_ids": _join_api_values(rule_ids),
        "search": search,
        "group": group,
        "level": level,
        "filename": _join_api_values(filename),
        "relative_dirname": relative_dirname,
        "status": status,
        "pci_dss": pci_dss,
        "gdpr": gdpr,
        "gpg13": gpg13,
        "hipaa": hipaa,
        "tsc": tsc,
        "mitre": mitre,
        "limit": limit,
        "offset": offset,
        "select": select,
        "sort": sort,
        "q": q,
        "pretty": pretty,
        "wait_for_complete": wait_for_complete,
        "distinct": distinct,
    }
    params = _clean_api_params(raw_params)

    response = requests.get(
        f"{protocol}://{host}:{port}/rules",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    logger.info("Query rules completed")
    return response.json()


def list_rule_files(
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    select: str | None = None,
    sort: str | None = None,
    q: str | None = None,
    pretty: bool | None = None,
    wait_for_complete: bool | None = None,
    distinct: bool | None = None,
):
    """List Wazuh rule files with filters supported by GET /rules/files."""
    logger.info("Listing rule files")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    params = _clean_api_params(
        {
            "limit": limit,
            "offset": offset,
            "search": search,
            "select": select,
            "sort": sort,
            "q": q,
            "pretty": pretty,
            "wait_for_complete": wait_for_complete,
            "distinct": distinct,
        }
    )

    response = requests.get(
        f"{protocol}://{host}:{port}/rules/files",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    logger.info("List rule files completed")
    return response.json()


def get_rule_file(filename: str, raw: bool | None = None, pretty: bool | None = None):
    """Get a Wazuh rule file by filename."""
    logger.info(f"Getting rule file: {filename}")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    params = _clean_api_params({"raw": raw, "pretty": pretty})

    response = requests.get(
        f"{protocol}://{host}:{port}/rules/files/{filename}",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    logger.info(f"Get rule file {filename} completed")
    return response.json()


def list_rule_groups(
    limit: int | None = None,
    offset: int | None = None,
    search: str | None = None,
    select: str | None = None,
    sort: str | None = None,
    q: str | None = None,
    pretty: bool | None = None,
    wait_for_complete: bool | None = None,
    distinct: bool | None = None,
):
    """List Wazuh rule groups with filters supported by GET /rules/groups."""
    logger.info("Listing rule groups")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    params = _clean_api_params(
        {
            "limit": limit,
            "offset": offset,
            "search": search,
            "select": select,
            "sort": sort,
            "q": q,
            "pretty": pretty,
            "wait_for_complete": wait_for_complete,
            "distinct": distinct,
        }
    )

    response = requests.get(
        f"{protocol}://{host}:{port}/rules/groups",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    logger.info("List rule groups completed")
    return response.json()


def get_rules_by_requirement(
    requirement: str,
    limit: int | None = None,
    offset: int | None = None,
    select: str | None = None,
    sort: str | None = None,
    q: str | None = None,
    pretty: bool | None = None,
    wait_for_complete: bool | None = None,
    distinct: bool | None = None,
):
    """Query Wazuh rules by requirement via GET /rules/requirement/{requirement}."""
    logger.info(f"Querying rules by requirement: {requirement}")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    params = _clean_api_params(
        {
            "limit": limit,
            "offset": offset,
            "select": select,
            "sort": sort,
            "q": q,
            "pretty": pretty,
            "wait_for_complete": wait_for_complete,
            "distinct": distinct,
        }
    )

    response = requests.get(
        f"{protocol}://{host}:{port}/rules/requirement/{requirement}",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    logger.info(f"Query rules by requirement {requirement} completed")
    return response.json()


def get_config_agentless():
    """Get agentless configuration."""
    logger.info("Getting agentless configuration")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/manager/configuration?section=agentless",
        headers=requests_headers,
        verify=False,
    )
    logger.info("Get agentless configuration successfully")
    return response.json()


def upload_rule_file(filename: str, content: str, overwrite: bool = False):
    """Upload a rule file to the Wazuh manager."""
    logger.info(f"Uploading rule file: {filename}")
    upload_headers = {
        "Authorization": f"Bearer {wazuh_server_token()}",
        "Content-Type": "application/octet-stream",
    }
    response = requests.put(
        f"{protocol}://{host}:{port}/rules/files/{filename}?overwrite={str(overwrite).lower()}",
        headers=upload_headers,
        data=content,
        verify=False,
    )
    if response.status_code == 200:
        logger.info(f"Upload rule file {filename} successfully")
    else:
        logger.error(f"Failed to upload rule file {filename}: {response.text}")
    return response.json()


def delete_rule_file(filename: str):
    """Delete a rule file from the Wazuh manager."""
    logger.info(f"Deleting rule file: {filename}")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.delete(
        f"{protocol}://{host}:{port}/rules/files/{filename}",
        headers=requests_headers,
        verify=False,
    )
    if response.status_code == 200:
        logger.info(f"Delete rule file {filename} successfully")
    else:
        logger.error(f"Failed to delete rule file {filename}: {response.text}")
    return response.json()


def restart_manager():
    """Restart the Wazuh manager."""
    logger.info("Restarting Wazuh manager")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.put(
        f"{protocol}://{host}:{port}/manager/restart",
        headers=requests_headers,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Restart Wazuh manager successfully")
    else:
        logger.error(f"Failed to restart Wazuh manager: {response.text}")
    return response.json()


def validate_configuration():
    """Validate the Wazuh manager configuration."""
    logger.info("Validating Wazuh manager configuration")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/manager/configuration/validation",
        headers=requests_headers,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Validate configuration successfully")
    else:
        logger.error(f"Failed to validate configuration: {response.text}")
    return response.json()


def get_manager_logs(
    pretty: bool = False,
    limit: int | None = None,
    offset: int | None = None,
    tag: str | None = None,
    level: str | None = None,
):
    """Get Wazuh manager logs from ossec.log."""
    logger.info("Getting manager logs")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"

    params: dict[str, str | int | bool] = {"pretty": pretty}
    if limit is not None:
        params["limit"] = limit
    if offset is not None:
        params["offset"] = offset
    if tag:
        params["tag"] = tag
    if level:
        params["level"] = level

    response = requests.get(
        f"{protocol}://{host}:{port}/manager/logs",
        headers=requests_headers,
        params=params,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Get manager logs successfully")
    else:
        logger.error(f"Failed to get manager logs: {response.text}")
    return response.json()


def get_manager_logs_summary(pretty: bool = False):
    """Get summary of Wazuh manager logs."""
    logger.info("Getting manager logs summary")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"
    response = requests.get(
        f"{protocol}://{host}:{port}/manager/logs/summary",
        headers=requests_headers,
        params={"pretty": pretty},
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Get manager logs summary successfully")
    else:
        logger.error(f"Failed to get manager logs summary: {response.text}")
    return response.json()


def run_logtest(log_event: str, token: str = None, location: str = None, log_format: str = "json"):
    """Run logtest against a log event."""
    logger.info("Running logtest")
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"

    payload = {"event": log_event, "log_format": log_format}
    if token:
        payload["token"] = token
    if location:
        payload["location"] = location

    response = requests.put(
        f"{protocol}://{host}:{port}/logtest",
        headers=requests_headers,
        json=payload,
        verify=False,
    )
    if response.status_code == 200:
        logger.info("Run logtest successfully")
    else:
        logger.error(f"Failed to run logtest: {response.text}")
    return response.json()


def _validate_ip(ip: str) -> None:
    """Validate IP address format, raise ValueError if invalid."""
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValueError(
            f"Invalid IP address format: '{ip}'. Expected a valid IPv4 or IPv6 address."
        ) from exc


def _validate_agent_id(agent_id: str) -> str:
    """Validate and normalize a Wazuh agent ID."""
    normalized = str(agent_id).strip()
    if not re.fullmatch(r"\d{3,}", normalized):
        raise ValueError(
            f"Invalid agent ID: '{agent_id}'. Expected a numeric Wazuh agent ID with at least 3 digits."
        )
    return normalized


def _format_active_response_result(
    response: dict,
    action: str,
    agent_id: str,
    target_ip: str,
    *,
    direction: str | None = None,
    duration: str | None = None,
) -> dict:
    """Format raw Wazuh active-response API response into a human-readable structure."""
    error_code = response.get("error", -1)
    data = response.get("data", {})
    failed = data.get("failed_items", []) if isinstance(data, dict) else []
    affected = data.get("affected_items", []) if isinstance(data, dict) else []
    success = error_code == 0 and not failed
    if isinstance(data, dict) and "affected_items" in data:
        success = success and agent_id in {str(item) for item in affected}

    result: dict = {
        "action": action,
        "success": success,
        "agent_id": agent_id,
        "target_ip": target_ip,
    }
    if direction:
        result["direction"] = direction
    if duration:
        result["duration"] = duration
    if not success:
        result["error_message"] = response.get("message", "Unknown error")
    if isinstance(data, dict):
        if affected:
            result["affected_items"] = affected
        if failed:
            result["failed_items"] = failed
    return result


_BLOCK_COMMAND_ALIASES: dict[str, str] = {
    "block-ip600": "block-ip600",
    "block-ip3600": "block-ip3600",
    "block-ip86400": "block-ip86400",
    "block-ip0": "block-ip0",
    # Backwards compatibility for callers created before the custom script was introduced.
    "netsh600": "block-ip600",
    "netsh3600": "block-ip3600",
    "netsh86400": "block-ip86400",
    "netsh0": "block-ip0",
}

_DURATION_MAP: dict[str, str] = {
    "block-ip600": "10 minutes",
    "block-ip3600": "1 hour",
    "block-ip86400": "1 day",
    "block-ip0": "permanent",
}

BlockCommand = Literal[
    "block-ip600",
    "block-ip3600",
    "block-ip86400",
    "block-ip0",
    "netsh600",
    "netsh3600",
    "netsh86400",
    "netsh0",
]


def _canonical_block_command(command_name: str) -> str:
    try:
        return _BLOCK_COMMAND_ALIASES[command_name]
    except KeyError as exc:
        allowed = ", ".join(sorted(_BLOCK_COMMAND_ALIASES))
        raise ValueError(
            f"Unsupported block command '{command_name}'. Expected one of: {allowed}."
        ) from exc


def _run_active_response(agent_id: str, command: str, alert_data: dict) -> dict:
    """Dispatch an Active Response command and return the Wazuh API response."""
    normalized_agent_id = _validate_agent_id(agent_id)
    requests_headers["Authorization"] = f"Bearer {wazuh_server_token()}"

    try:
        response = requests.put(
            f"{protocol}://{host}:{port}/active-response?agents_list={normalized_agent_id}",
            headers=requests_headers,
            json={
                "command": command,
                "arguments": [],
                "alert": {"data": alert_data},
            },
            verify=False,
            timeout=30,
        )
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        logger.exception(
            "Failed to dispatch Active Response command %s to agent %s",
            command,
            normalized_agent_id,
        )
        return {"error": -1, "message": str(exc), "data": {"affected_items": []}}
    except ValueError as exc:
        logger.exception(
            "Active Response command %s returned invalid JSON for agent %s",
            command,
            normalized_agent_id,
        )
        return {"error": -1, "message": str(exc), "data": {"affected_items": []}}


def block_ip_on_agent(
    agent_id: str,
    target_ip: str,
    direction: Literal["srcip", "dstip", "both"] = "srcip",
    command_name: BlockCommand = "block-ip600",
):
    """Block an IP address on a specified agent via Wazuh Active Response.

    Uses the custom ``block-ip`` stateful Active Response script. The script
    receives the Wazuh JSON protocol on stdin and creates inbound and/or
    outbound Windows Firewall rules according to ``direction``.

    Args:
        agent_id: Wazuh agent ID, e.g. "006".
        target_ip: IP address to block.
        direction:
            "srcip" — block the IP as a source address (inbound attacker).
            "dstip" — block the IP as a destination address (outbound traffic).
            "both"  — block both inbound and outbound traffic.
        command_name: Active Response identifier determining the block duration.
            block-ip600   - 10 minutes (default)
            block-ip3600  - 1 hour
            block-ip86400 - 1 day
            block-ip0     - permanent

            The former netsh values remain accepted as compatibility aliases.
    """
    _validate_ip(target_ip)
    normalized_agent_id = _validate_agent_id(agent_id)
    if direction not in {"srcip", "dstip", "both"}:
        raise ValueError(
            f"Unsupported block direction '{direction}'. Expected srcip, dstip, or both."
        )
    canonical_command = _canonical_block_command(command_name)
    duration = _DURATION_MAP[canonical_command]

    alert_data: dict[str, str] = {"action": "block"}
    if direction in ("srcip", "both"):
        alert_data["srcip"] = target_ip
    if direction in ("dstip", "both"):
        alert_data["dstip"] = target_ip

    logger.info(
        "Blocking IP %s on agent %s (direction=%s, command=%s)",
        target_ip,
        normalized_agent_id,
        direction,
        canonical_command,
    )
    api_result = _run_active_response(normalized_agent_id, canonical_command, alert_data)

    formatted = _format_active_response_result(
        api_result,
        action="block",
        agent_id=normalized_agent_id,
        target_ip=target_ip,
        direction=direction,
        duration=duration,
    )
    all_success = formatted["success"]
    result = {
        "action": "block",
        "success": all_success,
        "status": "dispatched" if all_success else "failed",
        "agent_id": normalized_agent_id,
        "target_ip": target_ip,
        "direction": direction,
        "duration": duration,
        "details": [formatted],
    }
    if not all_success:
        result["error_message"] = formatted.get("error_message", "Unknown error")
    return result


def unblock_ip_on_agent(
    agent_id: str,
    target_ip: str,
):
    """Remove a previously-applied IP block on a specified agent.

    Dispatches ``block-ip0`` with an explicit unblock action. The same custom
    script removes both inbound and outbound rules, so no separate Manager-side
    shell command is required.

    Args:
        agent_id: Wazuh agent ID, e.g. "006".
        target_ip: IP address to unblock.
    """
    _validate_ip(target_ip)
    normalized_agent_id = _validate_agent_id(agent_id)

    logger.info(
        "Unblocking IP %s on agent %s",
        target_ip,
        normalized_agent_id,
    )
    api_result = _run_active_response(
        normalized_agent_id,
        "block-ip0",
        {"action": "unblock", "srcip": target_ip, "dstip": target_ip},
    )
    formatted = _format_active_response_result(
        api_result,
        action="unblock",
        agent_id=normalized_agent_id,
        target_ip=target_ip,
    )
    result = {
        "action": "unblock",
        "success": formatted["success"],
        "status": "dispatched" if formatted["success"] else "failed",
        "agent_id": normalized_agent_id,
        "target_ip": target_ip,
        "details": [formatted],
    }
    if not formatted["success"]:
        result["error_message"] = formatted.get("error_message", "Unknown error")
    return result


_VERIFICATION_TEXT = {
    "verified_blocked": (
        "已验证封禁",
        "要求的防火墙规则均已存在、启用并执行阻断。",
    ),
    "verified_unblocked": (
        "已验证解封",
        "目标 IP 的预期入站和出站防火墙规则均不存在。",
    ),
    "partial": (
        "部分生效",
        "只存在部分预期规则，或规则存在但未启用阻断。",
    ),
    "not_applied": (
        "未生效",
        "命令已经投递，但防火墙仍未达到预期状态。",
    ),
    "unknown": (
        "状态未知",
        "查询超时或暂时无法取得 Windows Firewall 的实际状态。",
    ),
}

_VERIFICATION_RECOMMENDATIONS = {
    "partial": "检查缺失方向的防火墙规则以及 Agent Active Response 脚本日志。",
    "not_applied": "检查 Agent 的 active-responses.log、脚本权限和 Windows Firewall 服务。",
    "unknown": "检查专用查询日志采集、Manager 自定义规则和 Wazuh Indexer 连接。",
}


def _verification_result(
    status: str,
    *,
    agent_id: str,
    target_ip: str | None,
    request_id: str,
    rules: list[dict] | None = None,
    error_message: str | None = None,
) -> dict:
    label, explanation = _VERIFICATION_TEXT[status]
    result = {
        "status": status,
        "status_label": label,
        "status_explanation": explanation,
        "display_status": f"{status}（{label}：{explanation}）",
        "agent_id": agent_id,
        "target_ip": target_ip,
        "request_id": request_id,
        "rules": rules or [],
        "recommendation": _VERIFICATION_RECOMMENDATIONS.get(status),
    }
    if error_message:
        result["error_message"] = error_message
    return result


def _normalize_query_rule(data: dict) -> dict:
    enabled_value = data.get("enabled", False)
    enabled = enabled_value is True or str(enabled_value).lower() in {"true", "yes", "1"}
    return {
        "ip": str(data.get("ip", "")),
        "direction": str(data.get("direction", "")).lower(),
        "enabled": enabled,
        "action": str(data.get("firewall_action", "")).lower(),
        "rule_name": str(data.get("rule_name", "")),
    }


def _parse_query_events(response: dict) -> tuple[list[dict], dict | None]:
    hits = response.get("hits", {}).get("hits", []) if isinstance(response, dict) else []
    rules_by_key: dict[tuple, dict] = {}
    completion = None
    for hit in hits:
        source = hit.get("_source", {}) if isinstance(hit, dict) else {}
        data = source.get("data", {}) if isinstance(source, dict) else {}
        if not isinstance(data, dict):
            continue
        event_type = data.get("event_type")
        if event_type == "wazuh_ai_block_query_rule":
            rule = _normalize_query_rule(data)
            key = (
                rule["rule_name"],
                rule["ip"],
                rule["direction"],
                rule["enabled"],
                rule["action"],
            )
            rules_by_key[key] = rule
        elif event_type == "wazuh_ai_block_query_complete":
            completion = data
    return list(rules_by_key.values()), completion


def _poll_query_result(
    agent_id: str,
    request_id: str,
    *,
    wait_timeout: float,
    poll_interval: float,
) -> tuple[list[dict], str | None]:
    deadline = time.monotonic() + max(wait_timeout, 0)
    last_error = None
    while True:
        try:
            remaining_before_request = max(deadline - time.monotonic(), 0)
            request_timeout = max(1, min(10, remaining_before_request or 1))
            response = active_response_query_events(
                agent_id,
                request_id,
                timeout=request_timeout,
            )
            rules, completion = _parse_query_events(response)
            if completion is not None:
                if completion.get("query_status") == "error":
                    return rules, str(completion.get("error_message", "Agent query failed"))
                try:
                    expected_count = int(completion.get("rule_count", 0))
                except (TypeError, ValueError):
                    expected_count = 0
                if len(rules) >= expected_count:
                    return rules, None
        except (requests.RequestException, ValueError) as exc:
            last_error = str(exc)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], last_error or "Timed out waiting for the Agent firewall query result"
        time.sleep(min(max(poll_interval, 0), remaining))


def _classify_query_rules(
    rules: list[dict],
    *,
    expected_action: Literal["block", "unblock"] | None,
    expected_direction: Literal["srcip", "dstip", "both"],
) -> str:
    expected_directions = {
        "srcip": {"in"},
        "dstip": {"out"},
        "both": {"in", "out"},
    }[expected_direction]
    existing_directions = {
        rule["direction"] for rule in rules if rule["direction"] in expected_directions
    }
    active_directions = {
        rule["direction"]
        for rule in rules
        if rule["direction"] in expected_directions
        and rule["enabled"]
        and rule["action"] == "block"
    }

    if expected_action == "block":
        if expected_directions <= active_directions:
            return "verified_blocked"
        if active_directions:
            return "partial"
        return "not_applied"

    if expected_action == "unblock":
        if not existing_directions:
            return "verified_unblocked"
        if expected_directions <= existing_directions:
            return "not_applied"
        return "partial"

    if not rules:
        return "verified_unblocked"
    active_by_ip: dict[str, set[str]] = {}
    for rule in rules:
        if rule["enabled"] and rule["action"] == "block":
            active_by_ip.setdefault(rule["ip"], set()).add(rule["direction"])
    if active_by_ip and all(directions >= {"in", "out"} for directions in active_by_ip.values()):
        return "verified_blocked"
    return "partial"


def list_blocked_ips_on_agent(
    agent_id: str,
    target_ip: str | None = None,
    *,
    expected_action: Literal["block", "unblock"] | None = None,
    expected_direction: Literal["srcip", "dstip", "both"] = "both",
    wait_timeout: float = 30,
    poll_interval: float = 1,
):
    """Query the endpoint's real Wazuh-managed Windows Firewall rules."""
    normalized_agent_id = _validate_agent_id(agent_id)
    if target_ip:
        _validate_ip(target_ip)
    if expected_direction not in {"srcip", "dstip", "both"}:
        raise ValueError(
            f"Unsupported block direction '{expected_direction}'. Expected srcip, dstip, or both."
        )

    request_id = str(uuid.uuid4())
    alert_data = {"action": "list", "request_id": request_id}
    if target_ip:
        alert_data["target_ip"] = target_ip

    logger.info(
        "Querying managed firewall rules on agent %s (request_id=%s target_ip=%s)",
        normalized_agent_id,
        request_id,
        target_ip,
    )
    api_result = _run_active_response(normalized_agent_id, "block-ip0", alert_data)
    dispatch = _format_active_response_result(
        api_result,
        action="query",
        agent_id=normalized_agent_id,
        target_ip=target_ip or "*",
    )
    if not dispatch["success"]:
        result = _verification_result(
            "unknown",
            agent_id=normalized_agent_id,
            target_ip=target_ip,
            request_id=request_id,
            error_message=dispatch.get("error_message", "Active Response dispatch failed"),
        )
        return {
            "action": "query",
            "success": False,
            "query_completed": False,
            "dispatch_success": False,
            **result,
        }

    rules, query_error = _poll_query_result(
        normalized_agent_id,
        request_id,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )
    if query_error:
        status = "unknown"
    else:
        status = _classify_query_rules(
            rules,
            expected_action=expected_action,
            expected_direction=expected_direction,
        )
    verification = _verification_result(
        status,
        agent_id=normalized_agent_id,
        target_ip=target_ip,
        request_id=request_id,
        rules=rules,
        error_message=query_error,
    )
    return {
        "action": "query",
        "success": status in {"verified_blocked", "verified_unblocked"},
        "query_completed": query_error is None,
        "dispatch_success": True,
        **verification,
    }


def block_ip_and_verify_on_agent(
    agent_id: str,
    target_ip: str,
    direction: Literal["srcip", "dstip", "both"] = "srcip",
    command_name: BlockCommand = "block-ip600",
):
    """Dispatch an IP block, then verify the real Windows Firewall state."""
    result = block_ip_on_agent(agent_id, target_ip, direction, command_name)
    result["dispatch_success"] = result["success"]
    if not result["dispatch_success"]:
        result["verification"] = _verification_result(
            "unknown",
            agent_id=result["agent_id"],
            target_ip=target_ip,
            request_id="not-dispatched",
            error_message="封禁命令投递失败，未执行防火墙验证。",
        )
        return result

    verification = list_blocked_ips_on_agent(
        result["agent_id"],
        target_ip,
        expected_action="block",
        expected_direction=direction,
    )
    result["verification"] = verification
    result["status"] = verification["status"]
    result["success"] = verification["status"] == "verified_blocked"
    return result


def unblock_ip_and_verify_on_agent(agent_id: str, target_ip: str):
    """Dispatch an IP unblock, then verify that both firewall rules are absent."""
    result = unblock_ip_on_agent(agent_id, target_ip)
    result["dispatch_success"] = result["success"]
    if not result["dispatch_success"]:
        result["verification"] = _verification_result(
            "unknown",
            agent_id=result["agent_id"],
            target_ip=target_ip,
            request_id="not-dispatched",
            error_message="解封命令投递失败，未执行防火墙验证。",
        )
        return result

    verification = list_blocked_ips_on_agent(
        result["agent_id"],
        target_ip,
        expected_action="unblock",
        expected_direction="both",
    )
    result["verification"] = verification
    result["status"] = verification["status"]
    result["success"] = verification["status"] == "verified_unblocked"
    return result


# ---------------------------------------------------------------------------
# Agent 001 fixed inbound TCP port demonstration
# ---------------------------------------------------------------------------

_DEMO_PORT_AGENT_ID = "001"
_DEMO_PORT = 54321
_DEMO_PORT_PROTOCOL = "tcp"
_DEMO_PORT_COMMANDS = {
    30: "block-port30",
    60: "block-port60",
    300: "block-port300",
}
_DEMO_PORT_STATUS_TEXT = {
    "blocked": (
        "已封禁",
        "入站 TCP 54321 阻断规则存在、已启用并执行阻断。",
    ),
    "unblocked": (
        "未封禁",
        "未发现入站 TCP 54321 阻断规则。",
    ),
    "unknown": (
        "状态未知",
        "查询超时或暂时无法取得 Windows 防火墙的实际状态。",
    ),
}


def _validate_demo_port_target(agent_id: str, target_port: int) -> tuple[str, int]:
    normalized_agent_id = _validate_agent_id(agent_id)
    if normalized_agent_id != _DEMO_PORT_AGENT_ID:
        raise ValueError(f"无权操作 Agent {normalized_agent_id}；端口演示仅授权 Agent 001。")
    if isinstance(target_port, bool):
        parsed_port = -1
    else:
        try:
            parsed_port = int(target_port)
        except (TypeError, ValueError):
            parsed_port = -1
    if parsed_port != _DEMO_PORT:
        raise ValueError(f"没有权限操作 TCP {target_port}；仅授权入站 TCP {_DEMO_PORT}。")
    return normalized_agent_id, parsed_port


def _validate_demo_port_duration(duration_seconds: int) -> int:
    if isinstance(duration_seconds, bool):
        parsed_duration = -1
    else:
        try:
            parsed_duration = int(duration_seconds)
        except (TypeError, ValueError):
            parsed_duration = -1
    if parsed_duration not in _DEMO_PORT_COMMANDS:
        raise ValueError("端口封禁仅支持 30、60 或 300 秒。")
    return parsed_duration


def _format_port_dispatch_result(
    response: dict,
    *,
    action: str,
    agent_id: str,
    target_port: int,
    duration_seconds: int | None = None,
) -> dict:
    error_code = response.get("error", -1)
    data = response.get("data", {})
    failed = data.get("failed_items", []) if isinstance(data, dict) else []
    affected = data.get("affected_items", []) if isinstance(data, dict) else []
    success = error_code == 0 and not failed
    if isinstance(data, dict) and "affected_items" in data:
        success = success and agent_id in {str(item) for item in affected}

    result = {
        "action": action,
        "success": success,
        "status": "dispatched" if success else "failed",
        "agent_id": agent_id,
        "target_port": target_port,
        "protocol": _DEMO_PORT_PROTOCOL,
        "direction": "in",
        "dispatch_success": success,
    }
    if duration_seconds is not None:
        result["duration_seconds"] = duration_seconds
    if affected:
        result["affected_items"] = affected
    if failed:
        result["failed_items"] = failed
    if not success:
        result["error_message"] = response.get("message", "Unknown error")
    return result


def block_port_on_agent(
    agent_id: str,
    target_port: int,
    duration_seconds: Literal[30, 60, 300] = 30,
) -> dict:
    """Block the fixed inbound TCP demonstration port on Agent 001."""
    normalized_agent_id, parsed_port = _validate_demo_port_target(agent_id, target_port)
    parsed_duration = _validate_demo_port_duration(duration_seconds)
    command = _DEMO_PORT_COMMANDS[parsed_duration]
    alert_data = {
        "action": "block",
        "target_port": str(parsed_port),
        "protocol": _DEMO_PORT_PROTOCOL,
        "direction": "in",
        "duration_seconds": str(parsed_duration),
    }
    logger.info(
        "Blocking inbound TCP port %s on agent %s for %s seconds",
        parsed_port,
        normalized_agent_id,
        parsed_duration,
    )
    response = _run_active_response(normalized_agent_id, command, alert_data)
    return _format_port_dispatch_result(
        response,
        action="block_port",
        agent_id=normalized_agent_id,
        target_port=parsed_port,
        duration_seconds=parsed_duration,
    )


def unblock_port_on_agent(agent_id: str, target_port: int) -> dict:
    """Remove the fixed inbound TCP demonstration rule on Agent 001."""
    normalized_agent_id, parsed_port = _validate_demo_port_target(agent_id, target_port)
    response = _run_active_response(
        normalized_agent_id,
        "block-port0",
        {
            "action": "unblock",
            "target_port": str(parsed_port),
            "protocol": _DEMO_PORT_PROTOCOL,
            "direction": "in",
        },
    )
    return _format_port_dispatch_result(
        response,
        action="unblock_port",
        agent_id=normalized_agent_id,
        target_port=parsed_port,
    )


def _normalize_port_query_rule(data: dict) -> dict:
    enabled_value = data.get("enabled", False)
    enabled = enabled_value is True or str(enabled_value).lower() in {"true", "yes", "1"}
    try:
        target_port = int(data.get("target_port", 0))
    except (TypeError, ValueError):
        target_port = 0
    return {
        "port": target_port,
        "protocol": str(data.get("protocol", "")).lower(),
        "direction": str(data.get("direction", "")).lower(),
        "enabled": enabled,
        "action": str(data.get("firewall_action", "")).lower(),
        "rule_name": str(data.get("rule_name", "")),
    }


def _parse_port_query_events(response: dict) -> tuple[list[dict], dict | None]:
    hits = response.get("hits", {}).get("hits", []) if isinstance(response, dict) else []
    rules_by_key: dict[tuple, dict] = {}
    completion = None
    for hit in hits:
        source = hit.get("_source", {}) if isinstance(hit, dict) else {}
        data = source.get("data", {}) if isinstance(source, dict) else {}
        if not isinstance(data, dict):
            continue
        event_type = data.get("event_type")
        if event_type == "wazuh_ai_port_query_rule":
            rule = _normalize_port_query_rule(data)
            key = (
                rule["rule_name"],
                rule["port"],
                rule["protocol"],
                rule["direction"],
                rule["enabled"],
                rule["action"],
            )
            rules_by_key[key] = rule
        elif event_type == "wazuh_ai_port_query_complete":
            completion = data
    return list(rules_by_key.values()), completion


def _poll_port_query_result(
    agent_id: str,
    request_id: str,
    *,
    wait_timeout: float,
    poll_interval: float,
) -> tuple[list[dict], str | None]:
    deadline = time.monotonic() + max(wait_timeout, 0)
    last_error = None
    while True:
        try:
            remaining_before_request = max(deadline - time.monotonic(), 0)
            request_timeout = max(1, min(10, remaining_before_request or 1))
            response = active_response_query_events(
                agent_id,
                request_id,
                timeout=request_timeout,
            )
            rules, completion = _parse_port_query_events(response)
            if completion is not None:
                if completion.get("query_status") == "error":
                    return rules, str(completion.get("error_message", "Agent query failed"))
                try:
                    expected_count = int(completion.get("rule_count", 0))
                except (TypeError, ValueError):
                    expected_count = 0
                if len(rules) >= expected_count:
                    return rules, None
        except (requests.RequestException, ValueError) as exc:
            last_error = str(exc)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], last_error or "Timed out waiting for the Agent port query result"
        time.sleep(min(max(poll_interval, 0), remaining))


def _port_status_result(
    status: Literal["blocked", "unblocked", "unknown"],
    *,
    agent_id: str,
    target_port: int,
    request_id: str,
    rules: list[dict] | None = None,
    error_message: str | None = None,
) -> dict:
    label, explanation = _DEMO_PORT_STATUS_TEXT[status]
    result = {
        "status": status,
        "status_label": label,
        "status_explanation": explanation,
        "display_status": f"{status}（{label}：{explanation}）",
        "agent_id": agent_id,
        "target_port": target_port,
        "protocol": _DEMO_PORT_PROTOCOL,
        "direction": "in",
        "request_id": request_id,
        "rules": rules or [],
        "recommendation": (
            "检查端口查询日志采集、Manager 自定义规则和 Indexer 连接。"
            if status == "unknown"
            else None
        ),
    }
    if error_message:
        result["error_message"] = error_message
    return result


def query_blocked_port_on_agent(
    agent_id: str,
    target_port: int,
    *,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    """Query the real state of the fixed inbound TCP demonstration rule."""
    normalized_agent_id, parsed_port = _validate_demo_port_target(agent_id, target_port)
    request_id = str(uuid.uuid4())
    response = _run_active_response(
        normalized_agent_id,
        "block-port0",
        {
            "action": "list",
            "target_port": str(parsed_port),
            "request_id": request_id,
        },
    )
    dispatch = _format_port_dispatch_result(
        response,
        action="query_port",
        agent_id=normalized_agent_id,
        target_port=parsed_port,
    )
    if not dispatch["dispatch_success"]:
        verification = _port_status_result(
            "unknown",
            agent_id=normalized_agent_id,
            target_port=parsed_port,
            request_id=request_id,
            error_message=dispatch.get("error_message", "Active Response dispatch failed"),
        )
        return {
            "action": "query_port",
            "success": False,
            "query_completed": False,
            "dispatch_success": False,
            **verification,
        }

    rules, query_error = _poll_port_query_result(
        normalized_agent_id,
        request_id,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )
    if query_error:
        status = "unknown"
    elif not rules:
        status = "unblocked"
    elif any(
        rule["port"] == parsed_port
        and rule["protocol"] == _DEMO_PORT_PROTOCOL
        and rule["direction"] == "in"
        and rule["enabled"]
        and rule["action"] == "block"
        for rule in rules
    ):
        status = "blocked"
    else:
        status = "unknown"

    verification = _port_status_result(
        status,
        agent_id=normalized_agent_id,
        target_port=parsed_port,
        request_id=request_id,
        rules=rules,
        error_message=query_error,
    )
    return {
        "action": "query_port",
        "success": status in {"blocked", "unblocked"},
        "query_completed": query_error is None,
        "dispatch_success": True,
        **verification,
    }


def block_port_and_verify_on_agent(
    agent_id: str,
    target_port: int,
    duration_seconds: Literal[30, 60, 300] = 30,
) -> dict:
    """Dispatch the fixed port block and require verified firewall state."""
    result = block_port_on_agent(agent_id, target_port, duration_seconds)
    if not result["dispatch_success"]:
        result["verification"] = _port_status_result(
            "unknown",
            agent_id=result["agent_id"],
            target_port=result["target_port"],
            request_id="not-dispatched",
            error_message="端口封禁命令投递失败，未执行防火墙验证。",
        )
        result["success"] = False
        return result

    verification = query_blocked_port_on_agent(result["agent_id"], result["target_port"])
    result["verification"] = verification
    result["status"] = verification["status"]
    result["success"] = verification["status"] == "blocked"
    return result


def unblock_port_and_verify_on_agent(agent_id: str, target_port: int) -> dict:
    """Dispatch the fixed port unblock and require verified firewall state."""
    result = unblock_port_on_agent(agent_id, target_port)
    if not result["dispatch_success"]:
        result["verification"] = _port_status_result(
            "unknown",
            agent_id=result["agent_id"],
            target_port=result["target_port"],
            request_id="not-dispatched",
            error_message="端口解封命令投递失败，未执行防火墙验证。",
        )
        result["success"] = False
        return result

    verification = query_blocked_port_on_agent(result["agent_id"], result["target_port"])
    result["verification"] = verification
    result["status"] = verification["status"]
    result["success"] = verification["status"] == "unblocked"
    result["reblock_notice"] = "请等待原封禁时长结束后再发起下一次封禁。"
    return result


# ---------------------------------------------------------------------------
# Agent 001 endpoint demonstration responses
# ---------------------------------------------------------------------------

_ENDPOINT_RESPONSE_AGENT_ID = "001"
_ENDPOINT_RESPONSE_COMMAND = "endpoint-response0"
_ENDPOINT_RESPONSE_ACTIONS = {
    "query_process",
    "terminate_process",
    "query_account",
    "disable_account",
    "enable_account",
}
_ENDPOINT_RESPONSE_STATUS_LABELS = {
    "success": "已验证成功",
    "failed": "执行失败",
    "unknown": "状态未知",
}
_ENDPOINT_RESPONSE_REASON_TEXT = {
    "invalid_agent": "该功能目前只部署在 Agent 001。",
    "invalid_process_id": "PID 必须是大于 0 的整数。",
    "process_not_found": "执行前未找到指定 PID，进程可能已经退出。",
    "process_not_allowed": "指定 PID 对应的进程不在 notepad.exe 演示白名单中。",
    "process_still_running": "已执行终止操作，但指定 PID 仍然存在。",
    "account_not_allowed": "账户功能只允许操作本地账户 demo_user。",
    "account_not_found": "Agent 001 上不存在本地账户 demo_user。",
    "account_state_not_applied": "命令已执行，但 demo_user 没有达到预期状态。",
    "invalid_request": "Agent 收到的端点响应请求不完整或格式无效。",
    "execution_error": "Agent 执行动作时发生错误。",
    "dispatch_failed": "Wazuh 未能将 Active Response 命令投递到 Agent 001。",
    "timeout": "30 秒内未取得 Agent 001 返回的实际状态。",
}


def _as_bool(value) -> bool:
    return value is True or str(value).lower() in {"true", "yes", "1"}


def _endpoint_success_explanation(action: str, evidence: dict) -> str:
    if action == "query_process":
        if evidence.get("exists"):
            return (
                f"PID {evidence.get('process_id')} 对应的进程为 "
                f"{evidence.get('process_name', 'notepad.exe')}。"
            )
        return f"查询完成，PID {evidence.get('process_id')} 当前不存在。"
    if action == "terminate_process":
        return (
            f"PID {evidence.get('process_id')} 的 "
            f"{evidence.get('process_name', 'notepad.exe')} 已经不存在。"
        )
    if action == "query_account":
        state = "启用" if evidence.get("account_enabled") else "禁用"
        return f"本地账户 demo_user 当前处于{state}状态。"
    if action == "disable_account":
        return "本地账户 demo_user 当前已禁用。"
    if action == "enable_account":
        return "本地账户 demo_user 当前已启用。"
    return "Agent 001 的实际状态已达到预期。"


def _endpoint_response_result(
    status: Literal["success", "failed", "unknown"],
    *,
    action: str,
    agent_id: str,
    request_id: str,
    dispatch_success: bool,
    query_completed: bool,
    evidence: dict | None = None,
    reason_code: str | None = None,
    technical_details: str | None = None,
) -> dict:
    evidence = evidence or {}
    if status == "success":
        explanation = _endpoint_success_explanation(action, evidence)
    else:
        explanation = _ENDPOINT_RESPONSE_REASON_TEXT.get(
            reason_code or "execution_error",
            "无法完成端点响应操作。",
        )

    result = {
        "action": action,
        "status": status,
        "status_label": _ENDPOINT_RESPONSE_STATUS_LABELS[status],
        "status_explanation": explanation,
        "display_status": (
            f"{status}（{_ENDPOINT_RESPONSE_STATUS_LABELS[status]}：{explanation}）"
        ),
        "success": status == "success",
        "agent_id": agent_id,
        "request_id": request_id,
        "dispatch_success": dispatch_success,
        "query_completed": query_completed,
        "evidence": evidence,
        "reason_code": reason_code,
    }
    if status != "success":
        result["error_message"] = explanation
    if technical_details:
        result["technical_details"] = technical_details
    return result


def _normalize_endpoint_evidence(data: dict) -> dict:
    evidence = {}
    if "process_id" in data and str(data.get("process_id", "")).strip():
        raw_process_id = data["process_id"]
        try:
            evidence["process_id"] = int(raw_process_id)
        except (TypeError, ValueError):
            evidence["process_id"] = str(raw_process_id)
    if "process_name" in data:
        evidence["process_name"] = str(data.get("process_name", ""))
    if "exists" in data:
        evidence["exists"] = _as_bool(data.get("exists"))
    if "account_name" in data:
        evidence["account_name"] = str(data.get("account_name", ""))
    if "account_enabled" in data:
        evidence["account_enabled"] = _as_bool(data.get("account_enabled"))
    if "account_sid" in data:
        evidence["account_sid"] = str(data.get("account_sid", ""))
    if "changed" in data:
        evidence["changed"] = _as_bool(data.get("changed"))
    return evidence


def _parse_endpoint_response_event(response: dict) -> dict | None:
    hits = response.get("hits", {}).get("hits", []) if isinstance(response, dict) else []
    for hit in reversed(hits):
        source = hit.get("_source", {}) if isinstance(hit, dict) else {}
        data = source.get("data", {}) if isinstance(source, dict) else {}
        if isinstance(data, dict) and data.get("event_type") == "wazuh_ai_endpoint_response_result":
            return data
    return None


def _poll_endpoint_response_result(
    agent_id: str,
    request_id: str,
    *,
    wait_timeout: float,
    poll_interval: float,
) -> tuple[dict | None, str | None]:
    deadline = time.monotonic() + max(wait_timeout, 0)
    last_error = None
    while True:
        try:
            remaining_before_request = max(deadline - time.monotonic(), 0)
            request_timeout = max(1, min(10, remaining_before_request or 1))
            response = active_response_query_events(
                agent_id,
                request_id,
                timeout=request_timeout,
            )
            event = _parse_endpoint_response_event(response)
            if event is not None:
                return event, None
        except (requests.RequestException, ValueError) as exc:
            last_error = str(exc)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None, last_error or "Timed out waiting for the Agent endpoint response result"
        time.sleep(min(max(poll_interval, 0), remaining))


def _run_endpoint_response_action(
    agent_id: str,
    action: str,
    *,
    process_id: int | None = None,
    account_name: str | None = None,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    normalized_agent_id = str(agent_id).strip()
    if normalized_agent_id != _ENDPOINT_RESPONSE_AGENT_ID:
        return _endpoint_response_result(
            "failed",
            action=action,
            agent_id=normalized_agent_id,
            request_id="not-dispatched",
            dispatch_success=False,
            query_completed=False,
            reason_code="invalid_agent",
        )
    if action not in _ENDPOINT_RESPONSE_ACTIONS:
        raise ValueError(f"Unsupported endpoint response action: {action}")
    if action in {"query_process", "terminate_process"} and (
        isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0
    ):
        return _endpoint_response_result(
            "failed",
            action=action,
            agent_id=normalized_agent_id,
            request_id="not-dispatched",
            dispatch_success=False,
            query_completed=False,
            evidence={"process_id": process_id},
            reason_code="invalid_process_id",
        )
    if action in {"query_account", "disable_account", "enable_account"} and (
        account_name != "demo_user"
    ):
        return _endpoint_response_result(
            "failed",
            action=action,
            agent_id=normalized_agent_id,
            request_id="not-dispatched",
            dispatch_success=False,
            query_completed=False,
            evidence={"account_name": account_name or ""},
            reason_code="account_not_allowed",
        )

    request_id = str(uuid.uuid4())
    alert_data: dict[str, str | int] = {
        "action": action,
        "request_id": request_id,
    }
    if process_id is not None:
        alert_data["process_id"] = process_id
    if account_name is not None:
        alert_data["account_name"] = account_name

    logger.info(
        "Dispatching endpoint response action %s to agent %s (request_id=%s)",
        action,
        normalized_agent_id,
        request_id,
    )
    api_result = _run_active_response(
        normalized_agent_id,
        _ENDPOINT_RESPONSE_COMMAND,
        alert_data,
    )
    dispatch = _format_active_response_result(
        api_result,
        action=action,
        agent_id=normalized_agent_id,
        target_ip=str(process_id if process_id is not None else account_name),
    )
    if not dispatch["success"]:
        return _endpoint_response_result(
            "failed",
            action=action,
            agent_id=normalized_agent_id,
            request_id=request_id,
            dispatch_success=False,
            query_completed=False,
            reason_code="dispatch_failed",
            technical_details=dispatch.get("error_message"),
        )

    event, query_error = _poll_endpoint_response_result(
        normalized_agent_id,
        request_id,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )
    if event is None:
        return _endpoint_response_result(
            "unknown",
            action=action,
            agent_id=normalized_agent_id,
            request_id=request_id,
            dispatch_success=True,
            query_completed=False,
            reason_code="timeout",
            technical_details=query_error,
        )

    operation_status = str(event.get("operation_status", "failed")).lower()
    status: Literal["success", "failed"] = "success" if operation_status == "success" else "failed"
    reason_code = str(event.get("reason_code", "")) or None
    return _endpoint_response_result(
        status,
        action=action,
        agent_id=normalized_agent_id,
        request_id=request_id,
        dispatch_success=True,
        query_completed=True,
        evidence=_normalize_endpoint_evidence(event),
        reason_code=reason_code,
        technical_details=str(event.get("error_message", "")) or None,
    )


def query_process_on_agent(
    agent_id: str,
    process_id: int,
    *,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    """Query one PID on Agent 001, restricted by the Agent script whitelist."""
    return _run_endpoint_response_action(
        agent_id,
        "query_process",
        process_id=process_id,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )


def terminate_process_on_agent(
    agent_id: str,
    process_id: int,
    *,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    """Terminate one whitelisted notepad.exe PID on Agent 001 and verify it is absent."""
    return _run_endpoint_response_action(
        agent_id,
        "terminate_process",
        process_id=process_id,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )


def query_local_account_on_agent(
    agent_id: str,
    account_name: str,
    *,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    """Query the fixed demo_user local account on Agent 001."""
    return _run_endpoint_response_action(
        agent_id,
        "query_account",
        account_name=account_name,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )


def disable_local_account_on_agent(
    agent_id: str,
    account_name: str,
    *,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    """Disable the fixed demo_user local account on Agent 001 and verify it."""
    return _run_endpoint_response_action(
        agent_id,
        "disable_account",
        account_name=account_name,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )


def enable_local_account_on_agent(
    agent_id: str,
    account_name: str,
    *,
    wait_timeout: float = 30,
    poll_interval: float = 1,
) -> dict:
    """Enable the fixed demo_user local account on Agent 001 and verify it."""
    return _run_endpoint_response_action(
        agent_id,
        "enable_account",
        account_name=account_name,
        wait_timeout=wait_timeout,
        poll_interval=poll_interval,
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
