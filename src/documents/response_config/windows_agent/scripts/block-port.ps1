# Active Response script for the fixed inbound TCP 54321 demonstration rule.
# Deploy together with block-port.bat to:
# C:\Program Files (x86)\ossec-agent\active-response\bin\

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$allowedPort = 54321
$allowedProtocol = "TCP"
$ruleName = "Demo_Block_In_TCP_54321"
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$activeResponseRoot = Split-Path -Parent $scriptRoot
$logPath = Join-Path $activeResponseRoot "active-responses.log"
$queryLogPath = Join-Path $activeResponseRoot "block-port-query.log"
$netshPath = Join-Path $env:SystemRoot "System32\netsh.exe"

function Write-ArLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    try {
        Add-Content -LiteralPath $logPath -Value "$timestamp block-port: $Message" -Encoding UTF8
    }
    catch {
        # stdout is reserved for the Active Response control protocol.
    }
}

function Get-AlertField {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Data,
        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    $property = $Data.PSObject.Properties[$Name]
    if ($null -eq $property -or $null -eq $property.Value) {
        return ""
    }
    return [string]$property.Value
}

function Assert-AuthorizedPort {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Port
    )

    $parsedPort = 0
    if (-not [int]::TryParse($Port, [ref]$parsedPort) -or $parsedPort -ne $allowedPort) {
        throw "Unauthorized port: $Port. Only inbound TCP $allowedPort is allowed."
    }
}

function Invoke-Netsh {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [switch]$IgnoreFailure
    )

    $output = & $netshPath @Arguments 2>&1
    $exitCode = $LASTEXITCODE
    $outputText = ($output | Out-String).Trim()
    if ($outputText) {
        Write-ArLog "$Description output: $outputText"
    }
    if ($exitCode -ne 0 -and -not $IgnoreFailure) {
        throw "$Description failed with netsh exit code $exitCode"
    }
    if ($exitCode -ne 0) {
        Write-ArLog "$Description ignored netsh exit code $exitCode"
    }
}

function Remove-BlockRule {
    Invoke-Netsh `
        -Arguments @("advfirewall", "firewall", "delete", "rule", "name=$ruleName") `
        -Description "Delete rule $ruleName" `
        -IgnoreFailure
}

function Add-BlockRule {
    Remove-BlockRule
    Invoke-Netsh `
        -Arguments @(
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=$ruleName",
            "dir=in",
            "action=block",
            "protocol=$allowedProtocol",
            "localport=$allowedPort"
        ) `
        -Description "Add rule $ruleName"
}

function Send-CheckKeys {
    $controlMessage = @{
        version = 1
        origin = @{
            name = "block-port"
            module = "active-response"
        }
        command = "check_keys"
        parameters = @{
            keys = @("block-port:in:tcp:$allowedPort")
        }
    } | ConvertTo-Json -Compress -Depth 5

    [Console]::Out.WriteLine($controlMessage)
    [Console]::Out.Flush()

    $responseLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($responseLine)) {
        throw "The response component did not answer the check_keys request"
    }

    $response = $responseLine | ConvertFrom-Json
    if ($response.command -eq "abort") {
        return $false
    }
    if ($response.command -ne "continue") {
        throw "Unexpected check_keys response: $($response.command)"
    }
    return $true
}

function Write-QueryEvent {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Event
    )

    $jsonLine = $Event | ConvertTo-Json -Compress -Depth 6
    $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::AppendAllText(
        $queryLogPath,
        $jsonLine + [Environment]::NewLine,
        $utf8WithoutBom
    )
}

function Write-ManagedRuleStatus {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequestId
    )

    try {
        $null = Get-Command -Name Get-NetFirewallRule -ErrorAction Stop
        $managedRules = @(Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)
        $ruleCount = 0

        foreach ($rule in $managedRules) {
            $portFilters = @($rule | Get-NetFirewallPortFilter -ErrorAction Stop)
            foreach ($portFilter in $portFilters) {
                $localPorts = @($portFilter.LocalPort)
                if ($localPorts -notcontains [string]$allowedPort) {
                    continue
                }

                Write-QueryEvent -Event @{
                    event_type = "wazuh_ai_port_query_rule"
                    request_id = $RequestId
                    target_port = $allowedPort
                    protocol = $allowedProtocol.ToLowerInvariant()
                    direction = "in"
                    rule_name = [string]$rule.DisplayName
                    enabled = ($rule.Enabled.ToString().ToLowerInvariant() -eq "true")
                    firewall_action = $rule.Action.ToString().ToLowerInvariant()
                }
                $ruleCount++
            }
        }

        Write-QueryEvent -Event @{
            event_type = "wazuh_ai_port_query_complete"
            request_id = $RequestId
            target_port = $allowedPort
            query_status = "ok"
            rule_count = $ruleCount
        }
        Write-ArLog "Managed port query completed. request_id=$RequestId rules=$ruleCount"
    }
    catch {
        Write-QueryEvent -Event @{
            event_type = "wazuh_ai_port_query_complete"
            request_id = $RequestId
            target_port = $allowedPort
            query_status = "error"
            rule_count = 0
            error_message = $_.Exception.Message
        }
        throw
    }
}

try {
    $inputLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($inputLine)) {
        throw "No JSON message received on stdin"
    }

    $message = $inputLine | ConvertFrom-Json
    if ($null -eq $message.parameters -or $null -eq $message.parameters.alert) {
        throw "Missing parameters.alert in the Active Response message"
    }

    $data = $message.parameters.alert.data
    if ($null -eq $data) {
        $data = [PSCustomObject]@{}
    }

    $requestedAction = (Get-AlertField -Data $data -Name "action").ToLowerInvariant()
    $targetPort = Get-AlertField -Data $data -Name "target_port"
    Assert-AuthorizedPort -Port $targetPort

    if ($requestedAction -eq "list") {
        $requestId = Get-AlertField -Data $data -Name "request_id"
        if ($requestId -notmatch "^[0-9A-Za-z-]{8,64}$") {
            throw "Invalid or missing query request_id"
        }
        Write-ManagedRuleStatus -RequestId $requestId
        exit 0
    }

    if ($message.command -eq "delete" -or $requestedAction -eq "unblock") {
        $operation = "unblock"
    }
    elseif ($message.command -eq "add" -and $requestedAction -eq "block") {
        $operation = "block"
    }
    else {
        throw "Unsupported Active Response command/action: $($message.command)/$requestedAction"
    }

    if ($operation -eq "block") {
        if (-not (Send-CheckKeys)) {
            Write-ArLog "Duplicate block request aborted for inbound TCP $allowedPort"
            exit 0
        }
        Add-BlockRule
        Write-ArLog "Block applied. direction=in protocol=tcp local_port=$allowedPort"
    }
    else {
        Remove-BlockRule
        Write-ArLog "Block removed. direction=in protocol=tcp local_port=$allowedPort"
    }

    exit 0
}
catch {
    Write-ArLog "ERROR: $($_.Exception.Message)"
    exit 1
}
