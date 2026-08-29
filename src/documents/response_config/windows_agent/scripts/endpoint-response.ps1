# Wazuh Active Response script for demonstration actions on a Windows Agent.
# Deploy together with endpoint-response.bat to:
# C:\Program Files (x86)\ossec-agent\active-response\bin\

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$activeResponseRoot = Split-Path -Parent $scriptRoot
$logPath = Join-Path $activeResponseRoot "active-responses.log"
$resultLogPath = Join-Path $activeResponseRoot "endpoint-response-query.log"
$netPath = Join-Path $env:SystemRoot "System32\net.exe"
$allowedProcessName = "notepad.exe"
$allowedAccountName = "demo_user"

function Write-ArLog {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    $timestamp = Get-Date -Format "yyyy/MM/dd HH:mm:ss"
    try {
        Add-Content -LiteralPath $logPath -Value "$timestamp endpoint-response: $Message" -Encoding UTF8
    }
    catch {
        # Active Response stdout is reserved for the Wazuh protocol.
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

function Write-ResultEvent {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$Event
    )

    $Event["event_type"] = "wazuh_ai_endpoint_response_result"
    $Event["timestamp_utc"] = [DateTime]::UtcNow.ToString("o")
    $jsonLine = $Event | ConvertTo-Json -Compress -Depth 6
    $utf8WithoutBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::AppendAllText(
        $resultLogPath,
        $jsonLine + [Environment]::NewLine,
        $utf8WithoutBom
    )
}

function Get-ProcessSnapshot {
    param(
        [Parameter(Mandatory = $true)]
        [int]$ProcessId
    )

    $process = Get-Process -Id $ProcessId -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $process) {
        return [PSCustomObject]@{
            Exists = $false
            ProcessId = $ProcessId
            ProcessName = ""
        }
    }

    return [PSCustomObject]@{
        Exists = $true
        ProcessId = $ProcessId
        ProcessName = "$($process.ProcessName).exe".ToLowerInvariant()
    }
}

function Get-DemoAccountSnapshot {
    $account = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True AND Name='demo_user'" |
        Select-Object -First 1
    if ($null -eq $account) {
        return [PSCustomObject]@{
            Exists = $false
            AccountName = $allowedAccountName
            Enabled = $false
            Sid = ""
        }
    }

    return [PSCustomObject]@{
        Exists = $true
        AccountName = [string]$account.Name
        Enabled = -not [bool]$account.Disabled
        Sid = [string]$account.SID
    }
}

function Invoke-AccountStateChange {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("yes", "no")]
        [string]$ActiveValue
    )

    $output = & $netPath "user" $allowedAccountName "/active:$ActiveValue" 2>&1
    $exitCode = $LASTEXITCODE
    $outputText = ($output | Out-String).Trim()
    if ($outputText) {
        Write-ArLog "net user output: $outputText"
    }
    if ($exitCode -ne 0) {
        throw "net user failed with exit code $exitCode"
    }
}

$requestId = ""
$action = ""
$processIdText = ""
$accountName = ""
$reasonCode = "execution_error"

try {
    $inputLine = [Console]::In.ReadLine()
    if ([string]::IsNullOrWhiteSpace($inputLine)) {
        throw "No JSON message received on stdin"
    }

    $message = $inputLine | ConvertFrom-Json
    if ($null -eq $message.parameters -or $null -eq $message.parameters.alert) {
        throw "Missing parameters.alert in the Wazuh Active Response message"
    }

    $data = $message.parameters.alert.data
    if ($null -eq $data) {
        $data = [PSCustomObject]@{}
    }

    $requestId = Get-AlertField -Data $data -Name "request_id"
    $action = (Get-AlertField -Data $data -Name "action").ToLowerInvariant()
    $processIdText = Get-AlertField -Data $data -Name "process_id"
    $accountName = Get-AlertField -Data $data -Name "account_name"

    $reasonCode = "invalid_request"
    if ($requestId -notmatch "^[0-9A-Za-z-]{8,64}$") {
        throw "Invalid or missing request_id"
    }

    if ($action -in @("query_process", "terminate_process")) {
        $processId = 0
        if (-not [int]::TryParse($processIdText, [ref]$processId) -or $processId -le 0) {
            throw "Invalid process_id"
        }

        $snapshot = Get-ProcessSnapshot -ProcessId $processId
        if ($action -eq "query_process" -and -not $snapshot.Exists) {
            Write-ResultEvent -Event @{
                request_id = $requestId
                action = $action
                operation_status = "success"
                process_id = $processId
                process_name = ""
                exists = $false
                changed = $false
                reason_code = ""
            }
            Write-ArLog "Process query completed. request_id=$requestId pid=$processId exists=false"
            exit 0
        }

        if (-not $snapshot.Exists) {
            $reasonCode = "process_not_found"
            throw "Process $processId was not found before termination"
        }
        if ($snapshot.ProcessName -ne $allowedProcessName) {
            $reasonCode = "process_not_allowed"
            throw "Process $processId is $($snapshot.ProcessName), not $allowedProcessName"
        }

        if ($action -eq "query_process") {
            Write-ResultEvent -Event @{
                request_id = $requestId
                action = $action
                operation_status = "success"
                process_id = $processId
                process_name = $snapshot.ProcessName
                exists = $true
                changed = $false
                reason_code = ""
            }
            Write-ArLog "Process query completed. request_id=$requestId pid=$processId exists=true"
            exit 0
        }

        $reasonCode = "execution_error"
        Stop-Process -Id $processId -Force -ErrorAction Stop
        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            if (-not (Get-ProcessSnapshot -ProcessId $processId).Exists) {
                break
            }
            Start-Sleep -Milliseconds 100
        }

        $postSnapshot = Get-ProcessSnapshot -ProcessId $processId
        if ($postSnapshot.Exists) {
            $reasonCode = "process_still_running"
            throw "Process $processId still exists after Stop-Process"
        }
        $processClosedAtUtc = [DateTime]::UtcNow.ToString("o")

        Write-ResultEvent -Event @{
            request_id = $requestId
            action = $action
            operation_status = "success"
            process_id = $processId
            process_name = $snapshot.ProcessName
            process_closed_at_utc = $processClosedAtUtc
            exists = $false
            changed = $true
            reason_code = ""
        }
        Write-ArLog "Process terminated and verified. request_id=$requestId pid=$processId"
        exit 0
    }

    if ($action -in @("query_account", "disable_account", "enable_account")) {
        if ($accountName -cne $allowedAccountName) {
            $reasonCode = "account_not_allowed"
            throw "Only the demo_user local account is allowed"
        }

        $snapshot = Get-DemoAccountSnapshot
        if (-not $snapshot.Exists) {
            $reasonCode = "account_not_found"
            throw "The demo_user local account was not found"
        }

        if ($action -eq "query_account") {
            Write-ResultEvent -Event @{
                request_id = $requestId
                action = $action
                operation_status = "success"
                account_name = $snapshot.AccountName
                account_enabled = $snapshot.Enabled
                account_sid = $snapshot.Sid
                changed = $false
                reason_code = ""
            }
            Write-ArLog "Account query completed. request_id=$requestId enabled=$($snapshot.Enabled)"
            exit 0
        }

        $expectedEnabled = $action -eq "enable_account"
        $changed = $snapshot.Enabled -ne $expectedEnabled
        if ($changed) {
            $activeValue = if ($expectedEnabled) { "yes" } else { "no" }
            $reasonCode = "execution_error"
            Invoke-AccountStateChange -ActiveValue $activeValue
        }

        for ($attempt = 0; $attempt -lt 50; $attempt++) {
            $postSnapshot = Get-DemoAccountSnapshot
            if ($postSnapshot.Exists -and $postSnapshot.Enabled -eq $expectedEnabled) {
                break
            }
            Start-Sleep -Milliseconds 100
        }

        $postSnapshot = Get-DemoAccountSnapshot
        if (-not $postSnapshot.Exists) {
            $reasonCode = "account_not_found"
            throw "The demo_user local account disappeared during verification"
        }
        if ($postSnapshot.Enabled -ne $expectedEnabled) {
            $reasonCode = "account_state_not_applied"
            throw "The demo_user account state did not reach the expected value"
        }

        Write-ResultEvent -Event @{
            request_id = $requestId
            action = $action
            operation_status = "success"
            account_name = $postSnapshot.AccountName
            account_enabled = $postSnapshot.Enabled
            account_sid = $postSnapshot.Sid
            changed = $changed
            reason_code = ""
        }
        Write-ArLog "Account action verified. request_id=$requestId action=$action changed=$changed"
        exit 0
    }

    $reasonCode = "invalid_request"
    throw "Unsupported endpoint response action: $action"
}
catch {
    $errorMessage = $_.Exception.Message
    Write-ArLog "ERROR: request_id=$requestId action=$action reason=$reasonCode message=$errorMessage"

    if ($requestId -match "^[0-9A-Za-z-]{8,64}$") {
        try {
            Write-ResultEvent -Event @{
                request_id = $requestId
                action = $action
                operation_status = "failed"
                process_id = $processIdText
                account_name = $accountName
                changed = $false
                reason_code = $reasonCode
                error_message = $errorMessage
            }
        }
        catch {
            Write-ArLog "ERROR: unable to write endpoint result event"
        }
    }
    exit 1
}
