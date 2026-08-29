from pathlib import Path
from xml.etree import ElementTree

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESPONSE_CONFIG_ROOT = PROJECT_ROOT / "src" / "documents" / "response_config"
WINDOWS_AGENT_SCRIPTS = RESPONSE_CONFIG_ROOT / "windows_agent" / "scripts"
WINDOWS_AGENT_LOG_COLLECTION = RESPONSE_CONFIG_ROOT / "windows_agent" / "log_collection"
WAZUH_MANAGER_ACTIVE_RESPONSE = RESPONSE_CONFIG_ROOT / "wazuh_manager" / "active_response"
WAZUH_MANAGER_RULES = RESPONSE_CONFIG_ROOT / "wazuh_manager" / "rules"


def test_active_response_fragment_registers_custom_command_for_all_timeouts():
    fragment = (WAZUH_MANAGER_ACTIVE_RESPONSE / "ossec_ar_fix.xml").read_text(encoding="utf-8")
    root = ElementTree.fromstring(f"<root>{fragment}</root>")

    commands = {
        command.findtext("name"): command.findtext("executable")
        for command in root.findall("command")
    }
    assert commands["block-ip"] == "block-ip.bat"

    responses = [
        (response.findtext("command"), response.findtext("timeout"))
        for response in root.findall("active-response")
        if response.findtext("command") == "block-ip"
    ]
    assert responses == [
        ("block-ip", "600"),
        ("block-ip", "3600"),
        ("block-ip", "86400"),
        ("block-ip", None),
    ]
    assert all(
        response.findtext("disabled") == "no" for response in root.findall("active-response")
    )


def test_endpoint_response_config_is_separate_and_restricted_for_demo_actions():
    fragment = (WAZUH_MANAGER_ACTIVE_RESPONSE / "ossec_ar_fix.xml").read_text(encoding="utf-8")
    root = ElementTree.fromstring(f"<root>{fragment}</root>")
    commands = {command.findtext("name"): command for command in root.findall("command")}
    endpoint_command = commands["endpoint-response"]

    assert endpoint_command.findtext("executable") == "endpoint-response.bat"
    assert endpoint_command.findtext("timeout_allowed") == "no"
    endpoint_responses = [
        response
        for response in root.findall("active-response")
        if response.findtext("command") == "endpoint-response"
    ]
    assert len(endpoint_responses) == 1
    assert endpoint_responses[0].findtext("disabled") == "no"
    assert endpoint_responses[0].findtext("rules_id") == "999995"

    batch_script = (WINDOWS_AGENT_SCRIPTS / "endpoint-response.bat").read_text(encoding="utf-8")
    powershell_script = (WINDOWS_AGENT_SCRIPTS / "endpoint-response.ps1").read_text(
        encoding="utf-8"
    )
    assert "%~dp0endpoint-response.ps1" in batch_script
    assert "[Console]::In.ReadLine()" in powershell_script
    assert '$allowedProcessName = "notepad.exe"' in powershell_script
    assert '$allowedAccountName = "demo_user"' in powershell_script
    assert "Stop-Process -Id $processId -Force" in powershell_script
    assert '$processClosedAtUtc = [DateTime]::UtcNow.ToString("o")' in powershell_script
    assert "process_closed_at_utc = $processClosedAtUtc" in powershell_script
    assert '"user" $allowedAccountName "/active:$ActiveValue"' in powershell_script
    assert 'event_type"] = "wazuh_ai_endpoint_response_result"' in powershell_script


def test_endpoint_response_result_log_and_manager_rule_use_json():
    agent_config = ElementTree.parse(
        WINDOWS_AGENT_LOG_COLLECTION / "windows-agent-endpoint-response.xml"
    ).getroot()
    manager_rule = ElementTree.parse(
        WAZUH_MANAGER_RULES / "manager-endpoint-response-rule.xml"
    ).getroot()

    localfile = agent_config.find("localfile")
    assert localfile is not None
    assert localfile.findtext("log_format") == "json"
    assert localfile.findtext("location").endswith("endpoint-response-query.log")

    rule = manager_rule.find("rule")
    assert rule is not None
    assert rule.attrib["id"] == "100211"
    assert rule.findtext("decoded_as") == "json"
    assert rule.findtext("field") == "^wazuh_ai_endpoint_response_result$"


def test_windows_scripts_use_wazuh_json_protocol():
    batch_script = (WINDOWS_AGENT_SCRIPTS / "block-ip.bat").read_text(encoding="utf-8")
    powershell_script = (WINDOWS_AGENT_SCRIPTS / "block-ip.ps1").read_text(encoding="utf-8")

    assert "%~dp0block-ip.ps1" in batch_script
    assert "set ACTION=%1" not in batch_script
    assert "set IP=%3" not in batch_script

    assert "[Console]::In.ReadLine()" in powershell_script
    assert "$message.parameters.alert" in powershell_script
    assert 'command = "check_keys"' in powershell_script
    assert "$LASTEXITCODE" in powershell_script
    assert "Write-Output" not in powershell_script


def test_port_response_config_is_fixed_to_demo_agent_port_and_durations():
    fragment = (WAZUH_MANAGER_ACTIVE_RESPONSE / "ossec_ar_fix.xml").read_text(encoding="utf-8")
    root = ElementTree.fromstring(f"<root>{fragment}</root>")
    commands = {
        command.findtext("name"): command.findtext("executable")
        for command in root.findall("command")
    }
    assert commands["block-port"] == "block-port.bat"

    responses = [
        (response.findtext("rules_id"), response.findtext("timeout"))
        for response in root.findall("active-response")
        if response.findtext("command") == "block-port"
    ]
    assert responses == [
        ("999996", "30"),
        ("999997", "60"),
        ("999998", "300"),
        ("999999", None),
    ]
    assert all(
        response.findtext("disabled") == "no"
        for response in root.findall("active-response")
        if response.findtext("command") == "block-port"
    )

    batch_script = (WINDOWS_AGENT_SCRIPTS / "block-port.bat").read_text(encoding="utf-8")
    powershell_script = (WINDOWS_AGENT_SCRIPTS / "block-port.ps1").read_text(encoding="utf-8")
    assert "%~dp0block-port.ps1" in batch_script
    assert "$allowedPort = 54321" in powershell_script
    assert '$allowedProtocol = "TCP"' in powershell_script
    assert '$ruleName = "Demo_Block_In_TCP_54321"' in powershell_script
    assert '"dir=in"' in powershell_script
    assert '"localport=$allowedPort"' in powershell_script
    assert "Assert-AuthorizedPort -Port $targetPort" in powershell_script
    assert 'command = "check_keys"' in powershell_script


def test_port_query_uses_separate_json_log_and_manager_rule():
    agent_config = ElementTree.parse(
        WINDOWS_AGENT_LOG_COLLECTION / "windows-agent-port-query.xml"
    ).getroot()
    manager_rule = ElementTree.parse(WAZUH_MANAGER_RULES / "manager-port-query-rule.xml").getroot()
    powershell_script = (WINDOWS_AGENT_SCRIPTS / "block-port.ps1").read_text(encoding="utf-8")

    localfile = agent_config.find("localfile")
    assert localfile is not None
    assert localfile.findtext("log_format") == "json"
    assert localfile.findtext("location").endswith("block-port-query.log")

    rule = manager_rule.find("rule")
    assert rule is not None
    assert rule.attrib["id"] == "100212"
    assert rule.findtext("decoded_as") == "json"
    assert "wazuh_ai_port_query_" in (rule.findtext("field") or "")
    assert 'event_type = "wazuh_ai_port_query_rule"' in powershell_script
    assert 'event_type = "wazuh_ai_port_query_complete"' in powershell_script


def test_firewall_query_uses_structured_json_log_and_custom_alert_rule():
    powershell_script = (WINDOWS_AGENT_SCRIPTS / "block-ip.ps1").read_text(encoding="utf-8")
    agent_config = ElementTree.parse(
        WINDOWS_AGENT_LOG_COLLECTION / "windows-agent-query.xml"
    ).getroot()
    manager_rule = ElementTree.parse(WAZUH_MANAGER_RULES / "manager-query-rule.xml").getroot()

    assert 'Get-NetFirewallRule -DisplayName "Wazuh_AI_Block_*"' in powershell_script
    assert 'event_type = "wazuh_ai_block_query_rule"' in powershell_script
    assert 'event_type = "wazuh_ai_block_query_complete"' in powershell_script
    assert "request_id" in powershell_script

    localfile = agent_config.find("localfile")
    assert localfile is not None
    assert localfile.findtext("log_format") == "json"
    assert localfile.findtext("location").endswith("block-ip-query.log")

    rule = manager_rule.find("rule")
    assert rule is not None
    assert 100000 <= int(rule.attrib["id"]) <= 120000
    assert rule.findtext("decoded_as") == "json"
    assert "wazuh_ai_block_query_" in (rule.findtext("field") or "")
