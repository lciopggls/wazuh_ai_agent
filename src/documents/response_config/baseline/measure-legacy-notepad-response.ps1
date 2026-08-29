<#
.SYNOPSIS
模拟传统安全人员检查并终止 VMware Windows 虚拟机中的可疑记事本进程。

.DESCRIPTION
操作人员需要先在虚拟机中手动打开记事本。每轮测试包含三个明确披露的 5 秒模拟阶段：
拉取进程清单、分析进程上下文、检查处置策略。脚本默认只展示 notepad.exe，允许只读
分页查看全部进程，并要求操作人员选择 PID 和二次确认。脚本只终止所选 PID，随后验证
目标进程消失且其他记事本仍然保留。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,

    [ValidateRange(1, 100)]
    [int]$Runs = 3,

    [ValidateRange(0.01, 3600)]
    [double]$OptimizedAverageSeconds = 5,

    [string]$CsvPath = "",

    [string]$VmrunPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$minimumRequiredSpeedup = 2.0
$simulatedStageSeconds = 5
$allProcessPageSize = 20
$allowedProcessName = "notepad.exe"

function Resolve-VmrunExecutable {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        return (Resolve-Path -LiteralPath $RequestedPath -ErrorAction Stop).Path
    }
    $command = Get-Command vmrun.exe -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }

    $candidates = @()
    if (${env:ProgramFiles(x86)}) {
        $candidates += Join-Path ${env:ProgramFiles(x86)} "VMware\VMware Workstation\vmrun.exe"
    }
    if ($env:ProgramFiles) {
        $candidates += Join-Path $env:ProgramFiles "VMware\VMware Workstation\vmrun.exe"
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "未找到 vmrun.exe。请安装 VMware Workstation，或通过 -VmrunPath 指定路径。"
}

function Invoke-Vmrun {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [switch]$IgnoreFailure
    )

    $previousOutputEncoding = [Console]::OutputEncoding
    $output = @()
    $exitCode = -1
    try {
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $output = @(& $script:ResolvedVmrunPath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        [Console]::OutputEncoding = $previousOutputEncoding
    }
    if ($exitCode -ne 0 -and -not $IgnoreFailure) {
        $message = ($output | Out-String).Trim()
        if (-not $message) {
            $message = "vmrun 执行失败，退出代码为 $exitCode。"
        }
        throw $message
    }
    return $output
}

function Normalize-PathForComparison {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
}

function ConvertFrom-VmrunProcessLine {
    param([Parameter(Mandatory = $true)][string]$Line)

    if ($Line -notmatch "^pid=(\d+),\s*owner=(.*?),\s*cmd=(.*)$") {
        return $null
    }
    $processId = [int]$Matches[1]
    $owner = $Matches[2].Trim()
    $commandLine = $Matches[3].Trim()
    if ($commandLine -match '^"([^"]+\.exe)"') {
        $executablePath = $Matches[1]
    }
    elseif ($commandLine -match "^(.*?\.exe)(?:\s|$)") {
        $executablePath = $Matches[1].Trim('"')
    }
    else {
        $executablePath = $commandLine
    }
    $processName = [System.IO.Path]::GetFileName($executablePath)
    if ([string]::IsNullOrWhiteSpace($processName)) {
        $processName = "未知"
    }
    return [PSCustomObject]@{
        Pid = $processId
        Name = $processName
        Owner = $(if ($owner) { $owner } else { "未知" })
        ExecutablePath = $executablePath
        CommandLine = $commandLine
    }
}

function Get-GuestProcesses {
    param([Parameter(Mandatory = $true)][string[]]$GuestArguments)

    $output = Invoke-Vmrun `
        -Arguments ($GuestArguments + @("listProcessesInGuest", $script:ResolvedVmxPath))
    $processes = [System.Collections.Generic.List[object]]::new()
    foreach ($line in $output) {
        $process = ConvertFrom-VmrunProcessLine -Line ([string]$line)
        if ($null -ne $process) {
            $processes.Add($process)
        }
    }
    return @($processes | Sort-Object Name, Pid)
}

function Invoke-SimulatedSecurityStage {
    param([Parameter(Mandatory = $true)][string]$Message)

    Write-Host ""
    Write-Host $Message -ForegroundColor Yellow
    for ($remaining = $simulatedStageSeconds; $remaining -ge 1; $remaining--) {
        Write-Progress -Activity $Message `
            -Status "模拟传统人工处理，剩余 $remaining 秒" `
            -PercentComplete ((($simulatedStageSeconds - $remaining) / $simulatedStageSeconds) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity $Message -Completed
}

function Show-ActionableProcesses {
    param([Parameter(Mandatory = $true)][object[]]$Processes)

    $actionable = @($Processes | Where-Object { $_.Name -ieq $allowedProcessName })
    Write-Host ""
    Write-Host "进程检查摘要" -ForegroundColor Cyan
    Write-Host "- 已扫描进程：$($Processes.Count) 个"
    Write-Host "- 可处置的演示进程：$($actionable.Count) 个"
    if ($actionable.Count -eq 0) {
        Write-Host "未发现 notepad.exe。请在虚拟机中打开记事本后按 R 重新扫描。" `
            -ForegroundColor Yellow
        return $actionable
    }

    $rows = for ($index = 0; $index -lt $actionable.Count; $index++) {
        [PSCustomObject]@{
            序号 = $index + 1
            PID = $actionable[$index].Pid
            进程名称 = $actionable[$index].Name
            所有者 = $actionable[$index].Owner
        }
    }
    $rows | Format-Table -AutoSize | Out-Host
    return $actionable
}

function Show-AllProcessesPaged {
    param([Parameter(Mandatory = $true)][object[]]$Processes)

    if ($Processes.Count -eq 0) {
        Write-Host "当前没有可显示的进程记录。" -ForegroundColor Yellow
        return
    }
    $page = 0
    $pageCount = [int][Math]::Ceiling($Processes.Count / $allProcessPageSize)
    while ($true) {
        $start = $page * $allProcessPageSize
        $end = [Math]::Min($start + $allProcessPageSize - 1, $Processes.Count - 1)
        $rows = for ($index = $start; $index -le $end; $index++) {
            [PSCustomObject]@{
                PID = $Processes[$index].Pid
                进程名称 = $Processes[$index].Name
                所有者 = $Processes[$index].Owner
            }
        }
        Write-Host ""
        Write-Host "全部进程（只读）— 第 $($page + 1)/$pageCount 页" -ForegroundColor Cyan
        $rows | Format-Table -AutoSize | Out-Host
        Write-Host "[N] 下一页  [P] 上一页  [B] 返回"
        $choice = (Read-Host "请选择").Trim().ToUpperInvariant()
        switch ($choice) {
            "N" {
                if ($page + 1 -lt $pageCount) { $page++ }
                else { Write-Host "已经是最后一页。" -ForegroundColor Yellow }
            }
            "P" {
                if ($page -gt 0) { $page-- }
                else { Write-Host "已经是第一页。" -ForegroundColor Yellow }
            }
            "B" { return }
            default { Write-Host "无效选项，请输入 N、P 或 B。" -ForegroundColor Yellow }
        }
    }
}

function Show-TargetDetails {
    param([Parameter(Mandatory = $true)][object]$Target)

    Write-Host ""
    Write-Host "处置对象确认" -ForegroundColor Cyan
    Write-Host "- 虚拟机：$([System.IO.Path]::GetFileNameWithoutExtension($script:ResolvedVmxPath))"
    Write-Host "- PID：$($Target.Pid)"
    Write-Host "- 进程名称：$($Target.Name)"
    Write-Host "- 进程所有者：$($Target.Owner)"
    Write-Host "- 命令路径：$($Target.ExecutablePath)"
    Write-Host "- 执行动作：强制终止单个进程"
    Write-Host "- 影响范围：仅当前 PID，不影响其他同名进程"
}

function Select-ProcessForResponse {
    param(
        [Parameter(Mandatory = $true)][string[]]$GuestArguments,
        [Parameter(Mandatory = $true)][object[]]$InitialProcesses
    )

    $processes = @($InitialProcesses)
    while ($true) {
        $actionable = @(Show-ActionableProcesses -Processes $processes)
        Write-Host "[序号或 PID] 选择目标  [R] 重新扫描  [A] 查看全部进程  [Q] 退出"
        $choice = (Read-Host "请输入操作").Trim()
        $upperChoice = $choice.ToUpperInvariant()
        if ($upperChoice -eq "Q") {
            throw [System.OperationCanceledException]::new("操作人员退出了本轮测试。")
        }
        if ($upperChoice -eq "A") {
            Show-AllProcessesPaged -Processes $processes
            continue
        }
        if ($upperChoice -eq "R") {
            Invoke-SimulatedSecurityStage -Message "正在重新连接终端并拉取当前进程清单……"
            $processes = @(Get-GuestProcesses -GuestArguments $GuestArguments)
            continue
        }

        $numericChoice = 0
        if (-not [int]::TryParse($choice, [ref]$numericChoice) -or $numericChoice -le 0) {
            Write-Host "请输入列表序号、PID、R、A 或 Q。" -ForegroundColor Yellow
            continue
        }
        $target = $null
        if ($numericChoice -le $actionable.Count) {
            $target = $actionable[$numericChoice - 1]
        }
        else {
            $target = $actionable | Where-Object { $_.Pid -eq $numericChoice } | Select-Object -First 1
        }
        if ($null -eq $target) {
            $other = $processes | Where-Object { $_.Pid -eq $numericChoice } | Select-Object -First 1
            if ($null -ne $other) {
                Write-Host "拒绝处置 PID $numericChoice（$($other.Name)）：仅允许处置 notepad.exe。" `
                    -ForegroundColor Red
            }
            else {
                Write-Host "未找到序号或 PID：$numericChoice。" -ForegroundColor Yellow
            }
            continue
        }

        Invoke-SimulatedSecurityStage -Message "正在分析目标进程特征、所有者和运行上下文……"
        $currentProcesses = @(Get-GuestProcesses -GuestArguments $GuestArguments)
        $currentTarget = $currentProcesses | Where-Object { $_.Pid -eq $target.Pid } | Select-Object -First 1
        if ($null -eq $currentTarget -or $currentTarget.Name -ine $allowedProcessName) {
            Write-Host "目标进程已退出或身份发生变化，请重新选择。" -ForegroundColor Yellow
            $processes = $currentProcesses
            continue
        }
        Show-TargetDetails -Target $currentTarget
        Invoke-SimulatedSecurityStage -Message "正在检查处置策略、白名单和影响范围……"

        $latestProcesses = @(Get-GuestProcesses -GuestArguments $GuestArguments)
        $latestTarget = $latestProcesses | Where-Object { $_.Pid -eq $currentTarget.Pid } | Select-Object -First 1
        if ($null -eq $latestTarget -or $latestTarget.Name -ine $allowedProcessName) {
            Write-Host "确认前目标进程已退出或身份发生变化，请重新选择。" -ForegroundColor Yellow
            $processes = $latestProcesses
            continue
        }

        while ($true) {
            $confirmation = (Read-Host "是否确认执行处置？[Y/N/Q]").Trim().ToUpperInvariant()
            if ($confirmation -eq "Y") {
                $candidatePids = @(
                    $latestProcesses |
                        Where-Object { $_.Name -ieq $allowedProcessName } |
                        ForEach-Object { $_.Pid }
                )
                return [PSCustomObject]@{
                    Target = $latestTarget
                    CandidateCount = $candidatePids.Count
                    OtherCandidatePids = @($candidatePids | Where-Object { $_ -ne $latestTarget.Pid })
                    Confirmation = "Y"
                }
            }
            if ($confirmation -eq "N") {
                Write-Host "已取消当前目标，请重新选择。" -ForegroundColor Yellow
                $processes = $latestProcesses
                break
            }
            if ($confirmation -eq "Q") {
                throw [System.OperationCanceledException]::new("操作人员退出了本轮测试。")
            }
            Write-Host "请输入 Y、N 或 Q。" -ForegroundColor Yellow
        }
    }
}

function Wait-ForProcessExit {
    param(
        [Parameter(Mandatory = $true)][string[]]$GuestArguments,
        [Parameter(Mandatory = $true)][int]$ProcessId,
        [int]$TimeoutSeconds = 5
    )

    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    $processes = @()
    do {
        $processes = @(Get-GuestProcesses -GuestArguments $GuestArguments)
        $exists = $null -ne ($processes | Where-Object { $_.Pid -eq $ProcessId } | Select-Object -First 1)
        if ($exists) { Start-Sleep -Milliseconds 250 }
    } while ($exists -and [DateTime]::UtcNow -lt $deadline)
    return [PSCustomObject]@{ Exited = -not $exists; Processes = $processes }
}

function New-ResultRecord {
    param(
        [string]$RecordType, [string]$Timestamp, [string]$Run, [string]$Status,
        [object]$DurationSeconds, [object]$ScannedProcessCount, [object]$CandidateCount,
        [object]$SelectedPid, [string]$SelectedName, [string]$SelectedOwner,
        [string]$Confirmation, [object]$TargetClosed, [object]$OtherNotepadCount,
        [object]$OtherNotepadPreserved, [object]$BaselineAverageSeconds,
        [object]$BaselineMinSeconds, [object]$BaselineMaxSeconds, [object]$Speedup,
        [object]$MetricPassed, [string]$Notes, [string]$ErrorMessage
    )
    return [PSCustomObject]@{
        RecordType = $RecordType; Timestamp = $Timestamp; Run = $Run; Status = $Status
        DurationSeconds = $DurationSeconds; ScannedProcessCount = $ScannedProcessCount
        CandidateCount = $CandidateCount; SelectedPid = $SelectedPid
        SelectedName = $SelectedName; SelectedOwner = $SelectedOwner
        Confirmation = $Confirmation; TargetClosed = $TargetClosed
        OtherNotepadCount = $OtherNotepadCount; OtherNotepadPreserved = $OtherNotepadPreserved
        BaselineAverageSeconds = $BaselineAverageSeconds
        BaselineMinSeconds = $BaselineMinSeconds; BaselineMaxSeconds = $BaselineMaxSeconds
        OptimizedAverageSeconds = $OptimizedAverageSeconds; Speedup = $Speedup
        RequiredSpeedup = $minimumRequiredSpeedup; MetricPassed = $MetricPassed
        Notes = $Notes; ErrorMessage = $ErrorMessage
    }
}

$script:ResolvedVmrunPath = Resolve-VmrunExecutable -RequestedPath $VmrunPath
$script:ResolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
if ([System.IO.Path]::GetExtension($script:ResolvedVmxPath) -ne ".vmx") {
    throw "VmxPath 必须指向 .vmx 文件。"
}
if (-not $CsvPath) {
    $CsvPath = Join-Path $PSScriptRoot "legacy-notepad-interactive-results.csv"
}
$csvParent = Split-Path -Parent ([System.IO.Path]::GetFullPath($CsvPath))
if (-not (Test-Path -LiteralPath $csvParent -PathType Container)) {
    throw "CSV 输出目录不存在：$csvParent"
}

Write-Host "正在检查 VMware 测试环境……" -ForegroundColor Cyan
$runningOutput = Invoke-Vmrun -Arguments @("-T", "ws", "list")
$normalizedTarget = Normalize-PathForComparison -Path $script:ResolvedVmxPath
$runningPaths = @(
    (($runningOutput | Out-String) -split "\r?\n") |
        Where-Object { ([string]$_).Trim() -match "(?i)\.vmx$" } |
        ForEach-Object {
            try { Normalize-PathForComparison -Path ([string]$_).Trim() }
            catch { $null }
        } |
        Where-Object { $_ }
)
if ($normalizedTarget -notin $runningPaths) {
    $detected = if ($runningPaths.Count -gt 0) { $runningPaths -join "; " } else { "无" }
    throw "目标虚拟机未运行或当前 PowerShell 无法看到它。已检测路径：$detected"
}
$toolsState = ((Invoke-Vmrun -Arguments @(
    "-T", "ws", "checkToolsState", $script:ResolvedVmxPath
)) | Out-String).Trim()
if ($toolsState -notmatch "(?i)running") {
    throw "VMware Tools 尚未就绪，当前状态：$toolsState"
}

$guestUserInput = Read-Host "请输入虚拟机桌面当前登录的 Windows 用户名"
if ([string]::IsNullOrWhiteSpace($guestUserInput)) { throw "未提供虚拟机用户名。" }
$secureGuestPassword = Read-Host "请输入虚拟机 Windows 账户密码" -AsSecureString
if ($secureGuestPassword.Length -eq 0) { throw "未提供虚拟机账户密码。" }
$credential = [System.Management.Automation.PSCredential]::new(
    $guestUserInput.Trim(), $secureGuestPassword
)
$networkCredential = $credential.GetNetworkCredential()
$guestPassword = $networkCredential.Password
$guestArguments = @("-T", "ws", "-gu", $credential.UserName, "-gp", $guestPassword)
Write-Host "正在验证凭据并读取进程信息……" -ForegroundColor Cyan
$null = Get-GuestProcesses -GuestArguments $guestArguments
Write-Host "环境和凭据检查通过。" -ForegroundColor Green

$results = [System.Collections.Generic.List[object]]::new()
$stopRequested = $false
$simulationNote = "包含三个各 5 秒的传统安全人员采集、研判和决策模拟阶段。"

try {
    for ($runNumber = 1; $runNumber -le $Runs; $runNumber++) {
        Write-Host ""
        Write-Host "========== 第 $runNumber/$Runs 轮 ==========" -ForegroundColor Cyan
        $ready = (Read-Host "请在虚拟机中手动打开记事本，然后按 Enter 开始；输入 Q 结束").Trim()
        if ($ready.ToUpperInvariant() -eq "Q") { $stopRequested = $true; break }

        $runTimestamp = (Get-Date).ToString("o")
        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $stage = "连接终端并拉取进程清单"
        $scannedCount = 0
        $selection = $null
        try {
            Invoke-SimulatedSecurityStage -Message "正在连接终端并拉取当前进程清单……"
            $processes = @(Get-GuestProcesses -GuestArguments $guestArguments)
            $scannedCount = $processes.Count
            $stage = "人工筛选和确认可疑进程"
            $selection = Select-ProcessForResponse `
                -GuestArguments $guestArguments -InitialProcesses $processes
            $target = $selection.Target

            $stage = "终止所选进程"
            Write-Host "正在终止 PID $($target.Pid) 的 $($target.Name)……" -ForegroundColor Cyan
            $null = Invoke-Vmrun -Arguments ($guestArguments + @(
                "killProcessInGuest", $script:ResolvedVmxPath, [string]$target.Pid
            ))

            $stage = "验证目标进程和其他记事本状态"
            $verification = Wait-ForProcessExit `
                -GuestArguments $guestArguments -ProcessId $target.Pid
            $remainingPids = @($verification.Processes | ForEach-Object { $_.Pid })
            $otherPreserved = @(
                $selection.OtherCandidatePids | Where-Object { $_ -notin $remainingPids }
            ).Count -eq 0
            $stopwatch.Stop()
            $duration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            $success = $verification.Exited -and $otherPreserved
            $status = if ($success) { "success" } else { "failed" }

            $results.Add((New-ResultRecord `
                -RecordType "run" -Timestamp $runTimestamp -Run ([string]$runNumber) `
                -Status $status -DurationSeconds $duration `
                -ScannedProcessCount $scannedCount -CandidateCount $selection.CandidateCount `
                -SelectedPid $target.Pid -SelectedName $target.Name -SelectedOwner $target.Owner `
                -Confirmation "Y" -TargetClosed $verification.Exited `
                -OtherNotepadCount $selection.OtherCandidatePids.Count `
                -OtherNotepadPreserved $otherPreserved -BaselineAverageSeconds "" `
                -BaselineMinSeconds "" -BaselineMaxSeconds "" -Speedup "" `
                -MetricPassed "" -Notes $simulationNote -ErrorMessage ""))

            if ($success) {
                Write-Host "处置成功：PID $($target.Pid) 已经消失。" -ForegroundColor Green
                Write-Host "其他记事本保留验证：通过。"
                Write-Host ("本轮总耗时：{0:N3} 秒" -f $duration) -ForegroundColor Green
            }
            else { Write-Warning "处置验证未通过，请检查进程状态。" }
        }
        catch [System.OperationCanceledException] {
            if ($stopwatch.IsRunning) { $stopwatch.Stop() }
            $duration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            $results.Add((New-ResultRecord `
                -RecordType "run" -Timestamp $runTimestamp -Run ([string]$runNumber) `
                -Status "aborted" -DurationSeconds $duration `
                -ScannedProcessCount $scannedCount -CandidateCount "" -SelectedPid "" `
                -SelectedName "" -SelectedOwner "" -Confirmation "Q" -TargetClosed $false `
                -OtherNotepadCount "" -OtherNotepadPreserved "" `
                -BaselineAverageSeconds "" -BaselineMinSeconds "" -BaselineMaxSeconds "" `
                -Speedup "" -MetricPassed "" -Notes $simulationNote `
                -ErrorMessage $_.Exception.Message))
            Write-Warning $_.Exception.Message
            $stopRequested = $true
            break
        }
        catch {
            if ($stopwatch.IsRunning) { $stopwatch.Stop() }
            $duration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            $results.Add((New-ResultRecord `
                -RecordType "run" -Timestamp $runTimestamp -Run ([string]$runNumber) `
                -Status "failed" -DurationSeconds $duration `
                -ScannedProcessCount $scannedCount `
                -CandidateCount $(if ($selection) { $selection.CandidateCount } else { "" }) `
                -SelectedPid $(if ($selection) { $selection.Target.Pid } else { "" }) `
                -SelectedName $(if ($selection) { $selection.Target.Name } else { "" }) `
                -SelectedOwner $(if ($selection) { $selection.Target.Owner } else { "" }) `
                -Confirmation "" -TargetClosed $false -OtherNotepadCount "" `
                -OtherNotepadPreserved "" -BaselineAverageSeconds "" `
                -BaselineMinSeconds "" -BaselineMaxSeconds "" -Speedup "" `
                -MetricPassed "" -Notes $simulationNote `
                -ErrorMessage "$stage：$($_.Exception.Message)"))
            Write-Warning "第 $runNumber 轮在“$stage”阶段失败：$($_.Exception.Message)"
        }
    }
}
finally {
    $guestPassword = $null
    $networkCredential = $null
    $credential = $null
    $secureGuestPassword = $null
}

$successfulRuns = @($results | Where-Object { $_.Status -eq "success" })
$failedRuns = @($results | Where-Object { $_.Status -ne "success" })
if ($successfulRuns.Count -gt 0) {
    $durations = @($successfulRuns | ForEach-Object { [double]$_.DurationSeconds })
    $average = [Math]::Round(($durations | Measure-Object -Average).Average, 3)
    $minimum = [Math]::Round(($durations | Measure-Object -Minimum).Minimum, 3)
    $maximum = [Math]::Round(($durations | Measure-Object -Maximum).Maximum, 3)
    $speedup = [Math]::Round($average / $OptimizedAverageSeconds, 3)
}
else { $average = 0.0; $minimum = 0.0; $maximum = 0.0; $speedup = 0.0 }

$testComplete = -not $stopRequested -and $failedRuns.Count -eq 0 -and $successfulRuns.Count -eq $Runs
$metricPassed = $testComplete -and $speedup -ge $minimumRequiredSpeedup
$summaryStatus = if ($metricPassed) { "passed" } elseif (-not $testComplete) { "incomplete" } else { "not_met" }
$results.Add((New-ResultRecord `
    -RecordType "summary" -Timestamp ((Get-Date).ToString("o")) -Run "all" `
    -Status $summaryStatus -DurationSeconds "" -ScannedProcessCount "" `
    -CandidateCount "" -SelectedPid "" -SelectedName "" -SelectedOwner "" `
    -Confirmation "" -TargetClosed "" -OtherNotepadCount "" `
    -OtherNotepadPreserved "" -BaselineAverageSeconds $average `
    -BaselineMinSeconds $minimum -BaselineMaxSeconds $maximum -Speedup $speedup `
    -MetricPassed $metricPassed `
    -Notes "交互式传统安全人员处置基线；三个 5 秒模拟阶段已明确披露。" `
    -ErrorMessage ""))

if (Test-Path -LiteralPath $CsvPath) {
    $results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -Append
}
else { $results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 }

Write-Host ""
Write-Host "传统处置基线测试汇总" -ForegroundColor Cyan
Write-Host "- 成功轮次：$($successfulRuns.Count)/$Runs"
Write-Host ("- 基线平均耗时：{0:N3} 秒" -f $average)
Write-Host ("- 最小/最大耗时：{0:N3} 秒 / {1:N3} 秒" -f $minimum, $maximum)
Write-Host ("- 智能响应平均耗时：{0:N3} 秒" -f $OptimizedAverageSeconds)
Write-Host ("- 响应速度提升倍数：{0:N3} 倍" -f $speedup)
Write-Host ("- 指标要求：不低于 {0:N3} 倍" -f $minimumRequiredSpeedup)
Write-Host "- 指标是否通过：$metricPassed"
Write-Host "- CSV 报告：$([System.IO.Path]::GetFullPath($CsvPath))"
Write-Host "- 说明：结果包含三个各 5 秒的传统人工流程模拟阶段。" -ForegroundColor Yellow
if (-not $metricPassed) { Write-Warning "测试未同时满足完整性、精确处置和速度提升要求。" }
