$global:hasRunOnTabCollectMemory = $false

$Global:windowsPlugins = @{
	"dlllist" = "windows.dlllist";
    "pslist" = "windows.pslist";
    "pstree" = "windows.pstree";
	"psscan" = "windows.psscan";
	"cmdline" = "windows.cmdline";
    "filescan" = "windows.filescan";
	"getsids" = "windows.getsids";
	"registry.hivelist" = "windows.registry.hivelist";
#   "handles" = "windows.handles";
	"malfind" = "windows.malfind";
	"sessions" = "windows.sessions";
	"timeliner" = "timeliner"	
}

$Global:linuxPlugins = @{
	"bash" = "linux.bash"
	"lsmod" = "linux.lsmod"
	"lsof" = "linux.lsof"
	"malfind" = "linux.malfind"
	"mountinfo" = "linux.mountinfo"
	"proc" = "linux.proc"
    "psaux" = "linux.psaux"
    "pslist" = "linux.pslist"
    "psscan" = "linux.psscan"
    "pstree" = "linux.pstree"
    "sockstat" = "linux.sockstat"
    "tty_check" = "linux.tty_check"
    "timeliner" = "timeliner"
}

$Global:macPlugins = @{
	"bash" = "mac.bash"
	"check_syscall" = "mac.check_syscall"
	"check_sysctl" = "mac.check_sysctl"
	"check_trap_table" = "mac.check_trap_table"
	"ifconfig" = "mac.ifconfig"
	"kevents" = "mac.kevents"
	"list_files" = "mac.list_files"
	"lsmod" = "mac.lsmod"
	"lsof" = "mac.lsof"
	"malfind" = "mac.malfind"
	"mount" = "mac.mount"
	"netstat" = "mac.netstat"
	"proc_maps" = "mac.proc_maps"
	"psaux" = "mac.psaux"
	"pslist" = "mac.pslist"
	"pstree" = "mac.pstree"
	"socket_filters" = "mac.socket_filters"
	"timeliner" = "timeliner"
}

#Timer for volatility initialization
$volJobTimer = New-Object System.Windows.Forms.Timer
$volJobTimer.Interval = 2000
$volJobTimer.Add_Tick({
    Check-VolJobStatus
})
$Global:volPendingJobs = @()
$Global:volMaxParallel = 2

function Test-VolatilityProcessingActive {
    $runningCount = 0

    foreach ($job in $Global:volJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if ($updatedJob -and ($updatedJob.State -eq "Running" -or $updatedJob.State -eq "NotStarted")) {
            $runningCount++
        }
    }

    return ($runningCount -gt 0 -or $Global:volPendingJobs.Count -gt 0)
}

function Get-VolatilityActivePluginSummary {
    $running = @()
    foreach ($job in $Global:volJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if ($updatedJob -and ($updatedJob.State -eq "Running" -or $updatedJob.State -eq "NotStarted")) {
            $running += $job.PluginName
        }
    }

    $queued = @()
    foreach ($pending in $Global:volPendingJobs) {
        if ($pending -and $pending.PluginName) {
            $queued += $pending.PluginName
        }
    }

    $running = @($running | Select-Object -Unique)
    $queued = @($queued | Select-Object -Unique)

    $runningText = if ($running.Count -gt 0) { $running -join ", " } else { "none" }
    $queuedText = if ($queued.Count -gt 0) { $queued -join ", " } else { "none" }

    return ("Volatility status: running [{0}] | queued [{1}]" -f $runningText, $queuedText)
}

##memoryfunctions start
function OnTabCollectMemory_GotFocus {
    if ($global:hasRunOnTabCollectMemory) {
        Update-MemoryButtonStates -Force
        return
    }    
    $subDirectoryPath = Join-Path $global:currentcasedirectory "MemoryArtifacts"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'MemoryArtifacts' created successfully." "MemoryTextBox"
    }
	
    $resolvedVolPath = Resolve-VolatilityExecutablePath -SelectedPath $VolatilityPathTextBox.Text
    if (-not (Test-MemoryPathPattern $resolvedVolPath "vol.py")) {
        Find-VolExecutable
    } else {
        $VolatilityPathTextBox.Text = $resolvedVolPath
    }
    $resolvedWinpmemPath = Resolve-WinpmemExecutablePath -SelectedPath $WinpmemPathTextBox.Text
    if (-not (Test-MemoryPathPattern $resolvedWinpmemPath "winpmem*.exe")) {
        Find-WinpmemExecutable
    } else {
        $WinpmemPathTextBox.Text = $resolvedWinpmemPath
    }
    Update-MemoryButtonStates -Force
	$global:hasRunOnTabCollectMemory = $true
}

function Normalize-MemoryPath {
    param([string]$PathValue)

    if ([string]::IsNullOrWhiteSpace($PathValue)) {
        return $null
    }

    $normalized = $PathValue.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($normalized)) {
        return $null
    }

    return $normalized
}

function Resolve-WinpmemExecutablePath {
    param([string]$SelectedPath)

    $resolvedPath = Normalize-MemoryPath -PathValue $SelectedPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return $resolvedPath
    }

    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $resolvedPath
    }

    $candidate = Get-ChildItem -Path $resolvedPath -Filter "winpmem*.exe" -File -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($candidate) {
        return $candidate
    }

    return $resolvedPath
}

function Resolve-VolatilityExecutablePath {
    param([string]$SelectedPath)

    $resolvedPath = Normalize-MemoryPath -PathValue $SelectedPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return $resolvedPath
    }

    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $resolvedPath
    }

    $candidate = Join-Path $resolvedPath "vol.py"
    if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
        return $candidate
    }

    return $resolvedPath
}

function Test-MemoryPathPattern {
    param(
        [string]$Path,
        [string]$Pattern
    )

    $normalizedPath = Normalize-MemoryPath -PathValue $Path
    if ([string]::IsNullOrWhiteSpace($normalizedPath)) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $normalizedPath -ErrorAction SilentlyContinue)) {
        return $false
    }

    $leaf = Split-Path -Path $normalizedPath -Leaf

    # If pattern contains '*', treat it as a wildcard pattern.
    if ($pattern.Contains('*')) {
        return ($leaf -like $pattern)
    } else {
        return $leaf.EndsWith($pattern, [System.StringComparison]::OrdinalIgnoreCase)
    }
}

function Update-MemoryButtonStates {
    param(
        [switch]$Force
    )

    if (-not $Force) {
        # Avoid heavy path validation during startup when the Memory tab is not active.
        if ($TabCollectAndProcessMemory -and -not $TabCollectAndProcessMemory.IsSelected) {
            return
        }
    }

    $resolvedWinpmemPath = Resolve-WinpmemExecutablePath -SelectedPath $WinpmemPathTextBox.Text
    $winpmemValid = Test-MemoryPathPattern -Path $resolvedWinpmemPath -Pattern "winpmem*.exe"
    $StartMemoryCaptureButton.IsEnabled = $winpmemValid

    $resolvedVolatilityPath = Resolve-VolatilityExecutablePath -SelectedPath $VolatilityPathTextBox.Text
    $volatilityValid = Test-MemoryPathPattern -Path $resolvedVolatilityPath -Pattern "vol.py"
    $memoryPath = Normalize-MemoryPath -PathValue $MemoryPathTextBox.Text
    $memoryValid = -not [string]::IsNullOrWhiteSpace($memoryPath) -and (Test-Path -LiteralPath $memoryPath -PathType Leaf -ErrorAction SilentlyContinue) -and $memoryPath.EndsWith(".raw", [System.StringComparison]::OrdinalIgnoreCase)
    $osValid = $null -ne $OSSelectionComboBox.SelectedItem
    $pluginValid = $null -ne $PluginsComboBox.SelectedItem

    $ProcessVolatilityButton.IsEnabled = $volatilityValid -and $memoryValid -and $osValid -and $pluginValid
}

function Find-WinpmemExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $wimpmemPath = Get-ChildItem -Path $toolsDirectory -Filter "winpmem*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($wimpmemPath) {
        $WinpmemPathTextBox.Text = $wimpmemPath
    }
}

function Find-VolExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $volPath = Get-ChildItem -Path $toolsDirectory -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($volPath) {
        $VolatilityPathTextBox.Text = $volPath
    }
}

function StartMemoryCaptureButton_Click {
    Update-Log "Collecting Memory..." "MemoryTextBox"
    Capture-Memory
}

function Capture-Memory {
    $winpmemPath = Resolve-WinpmemExecutablePath -SelectedPath $WinpmemPathTextBox.Text
    if (-not (Test-MemoryPathPattern -Path $winpmemPath -Pattern "winpmem*.exe")) {
        Update-Log "Winpmem executable path is not valid." "MemoryTextBox"
        return
    }
    $WinpmemPathTextBox.Text = $winpmemPath

    # Capture memory
    $currentTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $systemName = $env:COMPUTERNAME
    $memoryFileName = "$currentTimestamp`_$systemName`_memdump.raw"
    $memorySubDirectory = Join-Path $global:currentcasedirectory "MemoryArtifacts\$systemName"
    $memoryFilePath = Join-Path $memorySubDirectory $memoryFileName

    if (-not (Test-Path $memorySubDirectory)) {
        New-Item -Path $memorySubDirectory -ItemType Directory -Force
    }

    # Save Windows version and patch level
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $windowsVersion = $osInfo.Caption
    $patchLevel = $osInfo.ServicePackMajorVersion
    $windowsVersionFile = Join-Path $memorySubDirectory "WindowsVersion.txt"
    Set-Content -Path $windowsVersionFile -Value "Windows Version: $windowsVersion`r`nPatch Level: Service Pack $patchLevel"
	Update-Log "Executing command: $winpmemPath `"$memoryFilePath`"" "MemoryTextBox"
	Start-Process -FilePath $winpmemPath -ArgumentList @($memoryFilePath)

    Update-Log "Memory capture started in new window." "MemoryTextBox"
}

function Check-VolJobStatus {
    $remainingJobs = @()
    $logQueueStatus = $false

    foreach ($job in $Global:volJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        $jobOutput = @(Receive-Job -Id $updatedJob.Id -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        foreach ($line in $jobOutput) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                if ($line -like "Finished Volatility plugin:*") {
                    $job.HasDetailedCompletionOutput = $true
                } elseif ($line -like "Failed Volatility plugin:*") {
                    $job.HasDetailedFailureOutput = $true
                }
                Update-Log $line "MemoryTextBox"
            }
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    if (-not $job.HasDetailedCompletionOutput) {
                        Update-Log "Finished Volatility plugin: $($job.PluginName)" "MemoryTextBox"
                    }
                } else {
                    if (-not $job.HasDetailedFailureOutput) {
                        $failureReason = $null
                        if ($updatedJob.ChildJobs -and $updatedJob.ChildJobs.Count -gt 0) {
                            $failureReason = $updatedJob.ChildJobs[0].JobStateInfo.Reason
                        }
                        if ($failureReason) {
                            Update-Log "Volatility plugin failed: $($job.PluginName) - $failureReason" "MemoryTextBox"
                        } else {
                            Update-Log "Volatility plugin failed: $($job.PluginName)" "MemoryTextBox"
                        }
                    }
                }
                $job.DataAdded = $true
            }

            $logQueueStatus = $true
            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:volJobs = $remainingJobs
    Start-NextVolatilityJobs

    if ($logQueueStatus) {
        Update-Log (Get-VolatilityActivePluginSummary) "MemoryTextBox"
    }

    if ($Global:volJobs.Count -eq 0 -and $Global:volPendingJobs.Count -eq 0) {
        Update-Log "All jobs completed." "MemoryTextBox"
        $volJobTimer.Stop() # Stop the timer after all jobs are completed
    }
}

function ProcessVolatilityButton_Click {
    Update-Log "Processing Memory..." "MemoryTextBox"

    if (Test-VolatilityProcessingActive) {
        [System.Windows.MessageBox]::Show("Volatility processing is already running. Please wait until current plugins complete.")
        Update-Log "Volatility processing request ignored because another run is still active." "MemoryTextBox"
        return
    }

    # Validations
    if (-not $MemoryPathTextBox.Text -or -not $OSSelectionComboBox.SelectedItem -or -not $PluginsComboBox.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a memory path, OS type, and a plugin.")
        return
    }

    $pythonCommandInfo = Get-PythonCommand
    if (-not $pythonCommandInfo) {
        [System.Windows.MessageBox]::Show("Python is not installed or not available in PATH. Install Python or ensure python/python3/py is available.")
        return
    }

    # Processing with selected options
	$volatilityPath  = Resolve-VolatilityExecutablePath -SelectedPath $VolatilityPathTextBox.Text
    $memoryFilePath = Normalize-MemoryPath -PathValue $MemoryPathTextBox.Text
    $selectedOs = [string]$OSSelectionComboBox.SelectedItem
    $selectedPlugin = [string]$PluginsComboBox.SelectedItem
	if ([string]::IsNullOrWhiteSpace($memoryFilePath)) {
		Write-Warning "Memory file path is null or empty."
		return
	}
    if (-not (Test-Path -LiteralPath $memoryFilePath -PathType Leaf -ErrorAction SilentlyContinue)) {
        [System.Windows.MessageBox]::Show("Selected memory file path is not valid.")
        return
    }
    if (-not (Test-MemoryPathPattern -Path $volatilityPath -Pattern "vol.py")) {
        [System.Windows.MessageBox]::Show("Volatility path must point to vol.py.")
        return
    }
	
    Update-Log ("Using Python interpreter: {0} {1}" -f $pythonCommandInfo.Command, (($pythonCommandInfo.PrefixArgs -join ' ').Trim())) "MemoryTextBox"
    Process-Volatility -MemoryFilePath $memoryFilePath -OS $selectedOs -Plugin $selectedPlugin -VolatilityPath $volatilityPath -PythonCommand $pythonCommandInfo.Command -PythonPrefixArgs $pythonCommandInfo.PrefixArgs
	$volJobTimer.Start() # Start the timer when processing begins
}

function Process-Volatility {
    param(
        [string]$MemoryFilePath,
        [string]$OS,
        [string]$Plugin,
		[string]$VolatilityPath,
        [string]$PythonCommand,
        [string[]]$PythonPrefixArgs
    )
	
    $Global:volJobs = @()
	
	$memorySubDirectory = Join-Path $global:currentcasedirectory "MemoryArtifacts"
	if ([string]::IsNullOrWhiteSpace($memoryFilePath)) {
		Write-Warning "Memory file path is null or empty."
		return
	}

    # Access global plugin dictionaries
    $selectedPlugins = @{}
    switch ($OS) {
        "Windows" { $selectedPlugins = $Global:windowsPlugins }
        "Linux"   { $selectedPlugins = $Global:linuxPlugins }
        "Mac"     { $selectedPlugins = $Global:macPlugins }
    }

	$pluginToRun = if ($Plugin -eq "All Plugins") { $selectedPlugins } else { @{$Plugin = $selectedPlugins[$Plugin]} }

    # Run the selected plugins
    $memoryFileName = (Split-Path $memoryFilePath -Leaf).TrimEnd('.raw')
    $volOutputDirectory = Join-Path $memorySubDirectory "VolOutput\$memoryFileName"
    if (-not (Test-Path $volOutputDirectory)) {
        $null = New-Item -Path $volOutputDirectory -ItemType Directory -Force
    }

    $maxParallel = [Math]::Max(1, [Math]::Min(4, [Environment]::ProcessorCount / 2))
    $Global:volMaxParallel = [int]$maxParallel
    Update-Log "Volatility parallel workers: $($Global:volMaxParallel)" "MemoryTextBox"

    $Global:volPendingJobs = @()
    foreach ($pluginName in $pluginToRun.Keys) {
        $Global:volPendingJobs += [PSCustomObject]@{
            PluginName = $pluginName
            Plugin = $pluginToRun[$pluginName]
            VolatilityPath = $VolatilityPath
            MemoryFilePath = $MemoryFilePath
            VolOutputDirectory = $volOutputDirectory
            PythonCommand = $PythonCommand
            PythonPrefixArgs = $PythonPrefixArgs
        }
    }

    Start-NextVolatilityJobs
}

function Start-NextVolatilityJobs {
    if (-not $Global:volPendingJobs) {
        return
    }

    $runningCount = 0
    foreach ($existingJob in $Global:volJobs) {
        $updatedJob = Get-Job -Id $existingJob.JobObject.Id -ErrorAction SilentlyContinue
        if ($updatedJob -and ($updatedJob.State -eq "Running" -or $updatedJob.State -eq "NotStarted")) {
            $runningCount++
        }
    }

    while ($runningCount -lt $Global:volMaxParallel -and $Global:volPendingJobs.Count -gt 0) {
        $next = $Global:volPendingJobs[0]
        if ($Global:volPendingJobs.Count -gt 1) {
            $Global:volPendingJobs = @($Global:volPendingJobs[1..($Global:volPendingJobs.Count - 1)])
        } else {
            $Global:volPendingJobs = @()
        }

        $job = Start-Job -ScriptBlock {
            param($pluginName, $plugin, $volatilityPath, $memoryFilePath, $volOutputDirectory, $pythonCommand, $pythonPrefixArgs)
            try {
                Write-Output ("Starting Volatility plugin: {0}" -f $pluginName)

                $pythonArgs = @()
                if ($pythonPrefixArgs -and $pythonPrefixArgs.Count -gt 0) {
                    $pythonArgs += $pythonPrefixArgs
                }
                $pythonArgs += @($volatilityPath, "-f", $memoryFilePath, "-q", "-r", "csv", $plugin)

                $stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) ("vol_{0}_{1}.stderr.log" -f $pluginName, ([guid]::NewGuid().ToString("N")))
                $stdout = (& $pythonCommand @pythonArgs 2> $stderrPath | Out-String)
                if ($LASTEXITCODE -ne 0) {
                    $stderrText = ""
                    if (Test-Path -LiteralPath $stderrPath) {
                        $stderrText = (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue).Trim()
                    }
                    throw "Volatility returned exit code $LASTEXITCODE for plugin $pluginName. $stderrText"
                }

                $memoryFileName = (Split-Path $memoryFilePath -Leaf).TrimEnd('.raw')
                $outputFile = Join-Path $volOutputDirectory "$memoryFileName`_$pluginName.csv"
                if (Test-Path -LiteralPath $outputFile -ErrorAction SilentlyContinue) {
                    $isLocked = $false
                    try {
                        $fs = [System.IO.File]::Open($outputFile, [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
                        $fs.Close()
                    } catch {
                        $isLocked = $true
                    }
                    if ($isLocked) {
                        $stamp = Get-Date -Format "yyyyMMdd_HHmmssfff"
                        $outputFile = Join-Path $volOutputDirectory "$memoryFileName`_$pluginName`_$stamp.csv"
                    }
                }

                $cleanLines = @($stdout -split "`r?`n" | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and ($_ -notmatch "^Volatility 3 Framework") })
                $cleanOutput = ($cleanLines -join [Environment]::NewLine)

                try {
                    $csvRows = $cleanOutput | ConvertFrom-Csv
                    if ($csvRows) {
                        $csvRows | Export-Csv $outputFile -NoTypeInformation
                    } else {
                        Set-Content -Path $outputFile -Value $cleanOutput
                    }
                } catch {
                    Set-Content -Path $outputFile -Value $cleanOutput
                }

                Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue

                Write-Output ("Finished Volatility plugin: {0}. Output: {1}" -f $pluginName, $outputFile)
            } catch {
                Write-Output ("Failed Volatility plugin: {0}. Error: {1}" -f $pluginName, $_.Exception.Message)
                throw
            }
        } -ArgumentList $next.PluginName, $next.Plugin, $next.VolatilityPath, $next.MemoryFilePath, $next.VolOutputDirectory, $next.PythonCommand, $next.PythonPrefixArgs

        $Global:volJobs += [PSCustomObject]@{
            JobObject = $job
            PluginName = $next.PluginName
            DataAdded = $false
            HasDetailedCompletionOutput = $false
            HasDetailedFailureOutput = $false
        }

        $runningCount++
    }
}
