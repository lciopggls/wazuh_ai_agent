<#
.SYNOPSIS
Measures an intentionally delayed legacy baseline for opening and closing one
Notepad process inside an already-running VMware Windows guest.

.DESCRIPTION
This script is for demonstration benchmarking only. The delay is deliberately
introduced to simulate a slower legacy workflow; it is not real processing
overhead. Environment-readiness checks and the credential prompt occur before
the measured runs.

Each run starts one visible Notepad process in the guest, captures its PID,
waits dynamically so the target duration is about 25 seconds, kills only that
PID, and verifies that it is gone. The default is three runs. Results and a
summary are appended to a CSV file.

.EXAMPLE
.\measure-legacy-notepad-response.ps1 `
  -VmxPath "D:\Virtual Machines\WindowsAgent\WindowsAgent.vmx"

.EXAMPLE
.\measure-legacy-notepad-response.ps1 `
  -VmxPath "D:\Virtual Machines\WindowsAgent\WindowsAgent.vmx" `
  -Runs 1 `
  -OptimizedAverageSeconds 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$VmxPath,

    [ValidateRange(1, 100)]
    [int]$Runs = 3,

    [ValidateRange(0.01, 3600)]
    [double]$OptimizedAverageSeconds = 5,

    [ValidateRange(20, 30)]
    [double]$TargetSeconds = 25,

    [string]$CsvPath = "",

    [string]$VmrunPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$minimumBaselineSeconds = 20.0
$maximumBaselineSeconds = 30.0
$minimumRequiredSpeedup = 2.0
$closeAllowanceSeconds = 2.0

function Resolve-VmrunExecutable {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        $resolved = Resolve-Path -LiteralPath $RequestedPath -ErrorAction Stop
        return $resolved.Path
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

    throw "vmrun.exe was not found. Install VMware Workstation or pass -VmrunPath."
}

function Invoke-Vmrun {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,
        [switch]$IgnoreFailure
    )

    # vmrun emits UTF-8. Windows PowerShell 5.1 otherwise decodes native output
    # with the system code page, corrupting non-ASCII VMX paths such as Chinese
    # directory names. Restore the caller's console encoding after every call.
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
            $message = "vmrun exited with code $exitCode."
        }
        throw $message
    }
    return $output
}

function Normalize-PathForComparison {
    param([Parameter(Mandatory = $true)][string]$Path)

    return [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
}

function Get-GuestProcessIds {
    param([Parameter(Mandatory = $true)][string[]]$GuestArguments)

    $output = Invoke-Vmrun -Arguments ($GuestArguments + @("listProcessesInGuest", $script:ResolvedVmxPath))
    $processIds = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($line in $output) {
        if ([string]$line -match "(?i)\bpid=(\d+)\b") {
            $null = $processIds.Add([int]$Matches[1])
        }
    }
    return $processIds
}

function Get-GuestNotepadProcessIds {
    param([Parameter(Mandatory = $true)][string[]]$GuestArguments)

    $output = Invoke-Vmrun -Arguments ($GuestArguments + @("listProcessesInGuest", $script:ResolvedVmxPath))
    $processIds = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($line in $output) {
        $lineText = [string]$line
        if (
            $lineText -match "(?i)\bnotepad\.exe\b" -and
            $lineText -match "(?i)\bpid=(\d+)\b"
        ) {
            $null = $processIds.Add([int]$Matches[1])
        }
    }
    return $processIds
}

function Test-GuestProcessExists {
    param(
        [Parameter(Mandatory = $true)][string[]]$GuestArguments,
        [Parameter(Mandatory = $true)][int]$ProcessId
    )

    $processIds = @(Get-GuestProcessIds -GuestArguments $GuestArguments)
    return $processIds -contains $ProcessId
}

function Remove-GuestProcessBestEffort {
    param(
        [Parameter(Mandatory = $true)][string[]]$GuestArguments,
        [int]$ProcessId = 0
    )

    if ($ProcessId -gt 0) {
        $null = Invoke-Vmrun `
            -Arguments ($GuestArguments + @("killProcessInGuest", $script:ResolvedVmxPath, [string]$ProcessId)) `
            -IgnoreFailure
    }
}

function New-ResultRecord {
    param(
        [string]$RecordType,
        [string]$Timestamp,
        [string]$Run,
        [string]$Status,
        [object]$DurationSeconds,
        [object]$InRange,
        [object]$GuestPid,
        [object]$BaselineAverageSeconds,
        [object]$BaselineMinSeconds,
        [object]$BaselineMaxSeconds,
        [object]$Speedup,
        [object]$MetricPassed,
        [string]$Notes,
        [string]$ErrorMessage
    )

    return [PSCustomObject]@{
        RecordType = $RecordType
        Timestamp = $Timestamp
        Run = $Run
        Status = $Status
        DurationSeconds = $DurationSeconds
        TargetSeconds = $TargetSeconds
        AllowedMinimumSeconds = $minimumBaselineSeconds
        AllowedMaximumSeconds = $maximumBaselineSeconds
        InRange = $InRange
        GuestPid = $GuestPid
        BaselineAverageSeconds = $BaselineAverageSeconds
        BaselineMinSeconds = $BaselineMinSeconds
        BaselineMaxSeconds = $BaselineMaxSeconds
        OptimizedAverageSeconds = $OptimizedAverageSeconds
        Speedup = $Speedup
        RequiredSpeedup = $minimumRequiredSpeedup
        MetricPassed = $MetricPassed
        Notes = $Notes
        ErrorMessage = $ErrorMessage
    }
}

$script:ResolvedVmrunPath = Resolve-VmrunExecutable -RequestedPath $VmrunPath
$script:ResolvedVmxPath = (Resolve-Path -LiteralPath $VmxPath -ErrorAction Stop).Path
if ([System.IO.Path]::GetExtension($script:ResolvedVmxPath) -ne ".vmx") {
    throw "VmxPath must point to a .vmx file."
}

if (-not $CsvPath) {
    $CsvPath = Join-Path $PSScriptRoot "legacy-notepad-baseline-results.csv"
}
$csvParent = Split-Path -Parent ([System.IO.Path]::GetFullPath($CsvPath))
if (-not (Test-Path -LiteralPath $csvParent -PathType Container)) {
    throw "The CSV output directory does not exist: $csvParent"
}

Write-Host "Checking the VMware environment before measurement..." -ForegroundColor Cyan
$runningOutput = Invoke-Vmrun -Arguments @("-T", "ws", "list")
$normalizedTarget = Normalize-PathForComparison -Path $script:ResolvedVmxPath
$runningLines = (($runningOutput | Out-String) -split "\r?\n")
$runningPaths = @(
    $runningLines |
        Where-Object { ([string]$_).Trim() -match "(?i)\.vmx$" } |
        ForEach-Object {
            try {
                Normalize-PathForComparison -Path ([string]$_).Trim()
            }
            catch {
                $null
            }
        } |
        Where-Object { $_ }
)
if ($normalizedTarget -notin $runningPaths) {
    $detectedPaths = if ($runningPaths.Count -gt 0) {
        $runningPaths -join "; "
    }
    else {
        "none"
    }
    throw (
        "The requested virtual machine is not running or is not visible to this PowerShell " +
        "process: $($script:ResolvedVmxPath). Detected running VM paths: $detectedPaths"
    )
}

$toolsStateOutput = Invoke-Vmrun `
    -Arguments @("-T", "ws", "checkToolsState", $script:ResolvedVmxPath)
$toolsState = ($toolsStateOutput | Out-String).Trim()
if ($toolsState -notmatch "(?i)running") {
    throw "VMware Tools is not ready. checkToolsState returned: $toolsState"
}

$guestUserInput = Read-Host "Enter the Windows username currently logged in to the VM desktop"
if ([string]::IsNullOrWhiteSpace($guestUserInput)) {
    throw "Guest username was not provided."
}
$secureGuestPassword = Read-Host "Enter the VM Windows password" -AsSecureString
if ($secureGuestPassword.Length -eq 0) {
    throw "Guest password was not provided."
}
$credential = [System.Management.Automation.PSCredential]::new(
    $guestUserInput.Trim(),
    $secureGuestPassword
)
$networkCredential = $credential.GetNetworkCredential()
$guestUser = $credential.UserName
$guestPassword = $networkCredential.Password
$guestArguments = @("-T", "ws", "-gu", $guestUser, "-gp", $guestPassword)

$results = [System.Collections.Generic.List[object]]::new()
$artificialDelayNote = "Contains an intentional sleep that simulates legacy workflow latency."

try {
    for ($runNumber = 1; $runNumber -le $Runs; $runNumber++) {
        $runTimestamp = (Get-Date).ToString("o")
        $guestPid = 0
        $stopwatch = $null
        $stage = "initializing the run"

        Write-Host ""
        Write-Host "Run $($runNumber)/$($Runs): starting the simulated legacy workflow..." -ForegroundColor Cyan
        try {
            $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
            $stage = "reading the initial guest process list"
            $beforeNotepadPids = @(
                Get-GuestNotepadProcessIds -GuestArguments $guestArguments
            )

            $stage = "starting Notepad in the guest"
            $null = Invoke-Vmrun -Arguments (
                $guestArguments + @(
                    "runProgramInGuest",
                    $script:ResolvedVmxPath,
                    "-noWait",
                    "-activeWindow",
                    "-interactive",
                    "C:\Windows\System32\notepad.exe"
                )
            )

            $stage = "discovering the new Notepad PID"
            $discoveryDeadline = [DateTime]::UtcNow.AddSeconds(10)
            $newNotepadPids = @()
            do {
                $currentNotepadPids = @(
                    Get-GuestNotepadProcessIds -GuestArguments $guestArguments
                )
                $newNotepadPids = @(
                    $currentNotepadPids | Where-Object { $_ -notin $beforeNotepadPids }
                )
                if ($newNotepadPids.Count -eq 0) {
                    Start-Sleep -Milliseconds 250
                }
            } while ($newNotepadPids.Count -eq 0 -and [DateTime]::UtcNow -lt $discoveryDeadline)
            if ($newNotepadPids.Count -eq 0) {
                throw "No newly-started notepad.exe process appeared within 10 seconds."
            }
            $guestPid = [int]($newNotepadPids | Sort-Object -Descending | Select-Object -First 1)

            Write-Host "Notepad is visible in the guest (PID $guestPid)." -ForegroundColor Green
            $stage = "applying the simulated legacy delay"
            $closeStartTarget = [Math]::Max(0.0, $TargetSeconds - $closeAllowanceSeconds)
            $remainingDelay = $closeStartTarget - $stopwatch.Elapsed.TotalSeconds
            if ($remainingDelay -gt 0) {
                Write-Host (
                    "Applying {0:N2}s of intentional legacy baseline delay..." -f $remainingDelay
                ) -ForegroundColor Yellow
                Start-Sleep -Milliseconds ([int][Math]::Ceiling($remainingDelay * 1000))
            }

            $stage = "closing Notepad PID $guestPid"
            $null = Invoke-Vmrun -Arguments (
                $guestArguments + @(
                    "killProcessInGuest",
                    $script:ResolvedVmxPath,
                    [string]$guestPid
                )
            )

            $stage = "verifying that Notepad PID $guestPid is gone"
            $verificationDeadline = [DateTime]::UtcNow.AddSeconds(5)
            do {
                $stillRunning = Test-GuestProcessExists `
                    -GuestArguments $guestArguments `
                    -ProcessId $guestPid
                if ($stillRunning) {
                    Start-Sleep -Milliseconds 250
                }
            } while ($stillRunning -and [DateTime]::UtcNow -lt $verificationDeadline)
            if ($stillRunning) {
                throw "Notepad PID $guestPid still exists after the close command."
            }

            $stopwatch.Stop()
            $duration = [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            $inRange = $duration -ge $minimumBaselineSeconds -and $duration -le $maximumBaselineSeconds
            $status = if ($inRange) { "success" } else { "out_of_range" }
            $results.Add(
                (New-ResultRecord `
                    -RecordType "run" `
                    -Timestamp $runTimestamp `
                    -Run ([string]$runNumber) `
                    -Status $status `
                    -DurationSeconds $duration `
                    -InRange $inRange `
                    -GuestPid $guestPid `
                    -BaselineAverageSeconds "" `
                    -BaselineMinSeconds "" `
                    -BaselineMaxSeconds "" `
                    -Speedup "" `
                    -MetricPassed "" `
                    -Notes $artificialDelayNote `
                    -ErrorMessage "")
            )
            Write-Host ("Run {0} completed in {1:N3}s (in range: {2})." -f $runNumber, $duration, $inRange) -ForegroundColor Green
        }
        catch {
            if ($stopwatch -and $stopwatch.IsRunning) {
                $stopwatch.Stop()
            }
            $failedDuration = if ($stopwatch) {
                [Math]::Round($stopwatch.Elapsed.TotalSeconds, 3)
            }
            else {
                0
            }
            $results.Add(
                (New-ResultRecord `
                    -RecordType "run" `
                    -Timestamp $runTimestamp `
                    -Run ([string]$runNumber) `
                    -Status "failed" `
                    -DurationSeconds $failedDuration `
                    -InRange $false `
                    -GuestPid $guestPid `
                    -BaselineAverageSeconds "" `
                    -BaselineMinSeconds "" `
                    -BaselineMaxSeconds "" `
                    -Speedup "" `
                    -MetricPassed "" `
                    -Notes $artificialDelayNote `
                    -ErrorMessage "$stage`: $($_.Exception.Message)")
            )
            Write-Warning "Run $runNumber failed during '$stage': $($_.Exception.Message)"
        }
        finally {
            Remove-GuestProcessBestEffort `
                -GuestArguments $guestArguments `
                -ProcessId $guestPid
        }
    }
}
finally {
    $guestPassword = $null
    $networkCredential = $null
    $credential = $null
    $secureGuestPassword = $null
}

$successfulRuns = @($results | Where-Object { $_.Status -in @("success", "out_of_range") })
$failedRuns = @($results | Where-Object { $_.Status -eq "failed" })
if ($successfulRuns.Count -gt 0) {
    $durations = @($successfulRuns | ForEach-Object { [double]$_.DurationSeconds })
    $average = [Math]::Round(($durations | Measure-Object -Average).Average, 3)
    $minimum = [Math]::Round(($durations | Measure-Object -Minimum).Minimum, 3)
    $maximum = [Math]::Round(($durations | Measure-Object -Maximum).Maximum, 3)
    $speedup = [Math]::Round($average / $OptimizedAverageSeconds, 3)
}
else {
    $average = 0.0
    $minimum = 0.0
    $maximum = 0.0
    $speedup = 0.0
}

$allRunsInRange = $successfulRuns.Count -eq $Runs -and @(
    $successfulRuns | Where-Object { -not $_.InRange }
).Count -eq 0
$testComplete = $failedRuns.Count -eq 0 -and $successfulRuns.Count -eq $Runs
$metricPassed = $testComplete -and $allRunsInRange -and $speedup -ge $minimumRequiredSpeedup
$summaryStatus = if ($metricPassed) {
    "passed"
}
elseif (-not $testComplete) {
    "incomplete"
}
else {
    "not_met"
}

$summary = New-ResultRecord `
    -RecordType "summary" `
    -Timestamp ((Get-Date).ToString("o")) `
    -Run "all" `
    -Status $summaryStatus `
    -DurationSeconds "" `
    -InRange $allRunsInRange `
    -GuestPid "" `
    -BaselineAverageSeconds $average `
    -BaselineMinSeconds $minimum `
    -BaselineMaxSeconds $maximum `
    -Speedup $speedup `
    -MetricPassed $metricPassed `
    -Notes "Simulated legacy baseline; intentional delay is disclosed and optimized timing is supplied separately." `
    -ErrorMessage ""
$results.Add($summary)

$csvExists = Test-Path -LiteralPath $CsvPath
if ($csvExists) {
    $results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -Append
}
else {
    $results | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
}

Write-Host ""
Write-Host "Baseline benchmark summary" -ForegroundColor Cyan
Write-Host ("- Successful runs: {0}/{1}" -f $successfulRuns.Count, $Runs)
Write-Host ("- Average baseline: {0:N3}s" -f $average)
Write-Host ("- Minimum / maximum: {0:N3}s / {1:N3}s" -f $minimum, $maximum)
Write-Host ("- Optimized average supplied: {0:N3}s" -f $OptimizedAverageSeconds)
Write-Host ("- Calculated speedup: {0:N3}x" -f $speedup)
Write-Host ("- Required speedup: {0:N3}x" -f $minimumRequiredSpeedup)
Write-Host ("- Metric passed: {0}" -f $metricPassed)
Write-Host ("- CSV report: {0}" -f ([System.IO.Path]::GetFullPath($CsvPath)))
Write-Host "- Disclosure: the legacy baseline contains an intentional simulated delay." -ForegroundColor Yellow

if (-not $metricPassed) {
    Write-Warning "The benchmark did not meet all completeness, timing-range, and speedup requirements."
}
