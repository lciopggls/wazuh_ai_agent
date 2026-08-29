# Wazuh Active Response script for directional Windows Firewall IP blocking.
# Deploy together with block-ip.bat to:
# C:\Program Files (x86)\ossec-agent\active-response\bin\

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$activeResponseRoot = Split-Path -Parent $scriptRoot
$logPath = Join-Path $activeResponseRoot "active-responses.log"
$queryLogPath = Join-Path $activeResponseRoot "block-ip-query.log"
$netshPath = Join-Path $env:SystemRoot "System32\netsh.exe"

function Write-ArLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    try {
        Add-Content -LiteralPath $logPath -Value "$timestamp block-ip: $Message" -Encoding UTF8
    }
    catch {
        # Active Response stdout is reserved for the Wazuh control protocol.
        # Do not write fallback diagnostics there because that can deadlock execd.
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

function Assert-ValidIp {
    param(
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )

    $parsedAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($IpAddress, [ref]$parsedAddress)) {
        throw "Invalid IP address: $IpAddress"
    }
}

function Get-RuleName {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("In", "Out")]
        [string]$Direction,
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )

    $safeIp = $IpAddress -replace "[^0-9A-Fa-f.\-]", "_"
    return "Wazuh_AI_Block_${Direction}_${safeIp}"
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
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("In", "Out")]
        [string]$Direction,
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )

    $ruleName = Get-RuleName -Direction $Direction -IpAddress $IpAddress
    Invoke-Netsh `
        -Arguments @("advfirewall", "firewall", "delete", "rule", "name=$ruleName") `
        -Description "Delete rule $ruleName" `
        -IgnoreFailure
}

function Add-BlockRule {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("In", "Out")]
        [string]$Direction,
        [Parameter(Mandatory = $true)]
        [string]$IpAddress
    )

    $ruleName = Get-RuleName -Direction $Direction -IpAddress $IpAddress
    $netshDirection = $Direction.ToLowerInvariant()

    Remove-BlockRule -Direction $Direction -IpAddress $IpAddress
    Invoke-Netsh `
        -Arguments @(
            "advfirewall",
            "firewall",
            "add",
            "rule",
            "name=$ruleName",
            "dir=$netshDirection",
            "action=block",
            "remoteip=$IpAddress",
            "protocol=any"
        ) `
        -Description "Add rule $ruleName"
}

function Send-CheckKeys {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Keys
    )

    $controlMessage = @{
        version = 1
        origin = @{
            name = "block-ip"
            module = "active-response"
        }
        command = "check_keys"
        parameters = @{
            keys = $Keys
        }
    } | ConvertTo-Json -Compress -Depth 5

    [Console]::Out.WriteLine($controlMessage)
    [Console]::Out.Flush()

    $responseLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($responseLine)) {
        throw "Wazuh did not answer the check_keys request"
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

function Write-ManagedRuleList {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequestId,
        [string]$TargetIp = ""
    )

    try {
        $null = Get-Command -Name Get-NetFirewallRule -ErrorAction Stop
        $managedRules = @(
            Get-NetFirewallRule -DisplayName "Wazuh_AI_Block_*" -ErrorAction SilentlyContinue
        )
        $ruleCount = 0

        foreach ($rule in $managedRules) {
            $directionText = $rule.Direction.ToString()
            if ($directionText -match "^In") {
                $direction = "in"
            }
            elseif ($directionText -match "^Out") {
                $direction = "out"
            }
            else {
                continue
            }

            $addressFilters = @($rule | Get-NetFirewallAddressFilter -ErrorAction Stop)
            foreach ($addressFilter in $addressFilters) {
                foreach ($remoteAddress in @($addressFilter.RemoteAddress)) {
                    $ruleIp = [string]$remoteAddress
                    if ([string]::IsNullOrWhiteSpace($ruleIp)) {
                        continue
                    }
                    if ($TargetIp -and $ruleIp -ne $TargetIp) {
                        continue
                    }

                    Write-QueryEvent -Event @{
                        event_type = "wazuh_ai_block_query_rule"
                        request_id = $RequestId
                        target_ip = $TargetIp
                        rule_name = [string]$rule.DisplayName
                        ip = $ruleIp
                        direction = $direction
                        enabled = ($rule.Enabled.ToString().ToLowerInvariant() -eq "true")
                        firewall_action = $rule.Action.ToString().ToLowerInvariant()
                    }
                    $ruleCount++
                }
            }
        }

        Write-QueryEvent -Event @{
            event_type = "wazuh_ai_block_query_complete"
            request_id = $RequestId
            target_ip = $TargetIp
            query_status = "ok"
            rule_count = $ruleCount
        }
        Write-ArLog "Managed firewall query completed. request_id=$RequestId rules=$ruleCount"
    }
    catch {
        Write-QueryEvent -Event @{
            event_type = "wazuh_ai_block_query_complete"
            request_id = $RequestId
            target_ip = $TargetIp
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
        throw "Missing parameters.alert in the Wazuh Active Response message"
    }

    $alert = $message.parameters.alert
    $data = $alert.data
    if ($null -eq $data) {
        $data = [PSCustomObject]@{}
    }

    $srcIp = Get-AlertField -Data $data -Name "srcip"
    $dstIp = Get-AlertField -Data $data -Name "dstip"
    $requestedAction = (Get-AlertField -Data $data -Name "action").ToLowerInvariant()

    if ($requestedAction -eq "list") {
        $requestId = Get-AlertField -Data $data -Name "request_id"
        $targetIp = Get-AlertField -Data $data -Name "target_ip"
        if ($requestId -notmatch "^[0-9A-Za-z-]{8,64}$") {
            throw "Invalid or missing query request_id"
        }
        if ($targetIp) {
            Assert-ValidIp -IpAddress $targetIp
        }
        Write-ManagedRuleList -RequestId $requestId -TargetIp $targetIp
        exit 0
    }

    if ($message.command -eq "delete" -or $requestedAction -eq "unblock") {
        $operation = "unblock"
    }
    elseif ($message.command -eq "add" -and ($requestedAction -eq "" -or $requestedAction -eq "block")) {
        $operation = "block"
    }
    else {
        throw "Unsupported Active Response command/action: $($message.command)/$requestedAction"
    }

    if (-not $srcIp -and -not $dstIp) {
        throw "No srcip or dstip was provided"
    }
    if ($srcIp) {
        Assert-ValidIp -IpAddress $srcIp
    }
    if ($dstIp) {
        Assert-ValidIp -IpAddress $dstIp
    }

    if ($operation -eq "block") {
        $keys = @()
        if ($srcIp) {
            $keys += "block-ip:srcip:$srcIp"
        }
        if ($dstIp) {
            $keys += "block-ip:dstip:$dstIp"
        }

        if (-not (Send-CheckKeys -Keys $keys)) {
            Write-ArLog "Duplicate block request aborted for keys: $($keys -join ', ')"
            exit 0
        }

        if ($srcIp) {
            Add-BlockRule -Direction "In" -IpAddress $srcIp
        }
        if ($dstIp) {
            Add-BlockRule -Direction "Out" -IpAddress $dstIp
        }
        Write-ArLog "Block applied. srcip=$srcIp dstip=$dstIp"
    }
    else {
        if ($srcIp) {
            Remove-BlockRule -Direction "In" -IpAddress $srcIp
        }
        if ($dstIp) {
            Remove-BlockRule -Direction "Out" -IpAddress $dstIp
        }
        Write-ArLog "Block removed. srcip=$srcIp dstip=$dstIp"
    }

    exit 0
}
catch {
    Write-ArLog "ERROR: $($_.Exception.Message)"
    exit 1
}
