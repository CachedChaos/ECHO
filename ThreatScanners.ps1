####Start of Threat Scanner Functions#####
function OnTabThreatScanners_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "ThreatScanners"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'ThreatScanners' created successfully." "ThreatScannerTextBox"
    }

    # Check and call Find-* functions only if the corresponding path text boxes are empty or invalid
    $resolvedClamScannerPath = Resolve-ClamAVScannerExecutable -SelectedScannerPath $ClamAVPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($resolvedClamScannerPath) -or (-not (Test-Path -LiteralPath $resolvedClamScannerPath -ErrorAction SilentlyContinue))) {
        Find-ClamAVScannerExecutable
    } else {
        $ClamAVPathTextBox.Text = $resolvedClamScannerPath
    }
    $resolvedLokiPath = Resolve-LokiExecutablePath -SelectedPath $LokiPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($resolvedLokiPath) -or (-not (Test-Path -LiteralPath $resolvedLokiPath -ErrorAction SilentlyContinue))) {
        Find-LokiExecutable
    } else {
        $LokiPathTextBox.Text = $resolvedLokiPath
    }
	
    $resolvedLokiUpdaterPath = Resolve-LokiUpdaterExecutablePath -SelectedPath $LokiUpdaterPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($resolvedLokiUpdaterPath) -or (-not (Test-Path -LiteralPath $resolvedLokiUpdaterPath -ErrorAction SilentlyContinue))) {
        Find-LokiUpgraderExecutable
    } else {
        $LokiUpdaterPathTextBox.Text = $resolvedLokiUpdaterPath
    }	
	
    if (-not (IsValidPath $clamAVUpdaterPathTextBox.Text "freshclam.exe")) {
		Find-ClamAVUpgraderExecutable
	}		
}

function Test-ThreatScannerPath {
    param([string]$Path)
    $normalizedPath = Normalize-ThreatScannerPath -PathValue $Path
    if ([string]::IsNullOrWhiteSpace($normalizedPath)) {
        return $false
    }

    try {
        return (Test-Path -LiteralPath $normalizedPath -ErrorAction SilentlyContinue)
    } catch {
        return $false
    }
}

function Normalize-ThreatScannerPath {
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

function Get-JobFailureReasonText {
    param($Job)
    if ($Job -and $Job.ChildJobs -and $Job.ChildJobs.Count -gt 0) {
        $reason = $Job.ChildJobs[0].JobStateInfo.Reason
        if ($reason) {
            return $reason.ToString()
        }
    }
    return $null
}

function Get-ClamDTempDirectory {
    param([string]$ScannerDirectory)
    return (Join-Path $ScannerDirectory "echo_clamd_tmp")
}

function Get-ClamDStateFilePath {
    param([string]$ScannerDirectory)
    return (Join-Path (Get-ClamDTempDirectory -ScannerDirectory $ScannerDirectory) "echo_clamd_state.json")
}

function Stop-SharedClamAVDaemon {
    param([string]$ScannerExecutablePath)

    $resolvedPath = Normalize-ThreatScannerPath -PathValue $ScannerExecutablePath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return
    }

    $scannerDirectory = Split-Path $resolvedPath -Parent
    $stateFilePath = Get-ClamDStateFilePath -ScannerDirectory $scannerDirectory
    if (-not (Test-Path $stateFilePath)) {
        return
    }

    $state = $null
    try {
        $state = Get-Content -Path $stateFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
    } catch {
        Remove-Item -Path $stateFilePath -Force -ErrorAction SilentlyContinue
        return
    }

    if ($state -and $state.Pid) {
        Stop-Process -Id ([int]$state.Pid) -Force -ErrorAction SilentlyContinue
    }

    if ($state -and $state.ConfigPath -and (Test-Path $state.ConfigPath)) {
        Remove-Item -Path $state.ConfigPath -Force -ErrorAction SilentlyContinue
    }

    Remove-Item -Path $stateFilePath -Force -ErrorAction SilentlyContinue
}

function UpdateScanningButtonsStatus() {
    $artifactScanningPathFilled = -not [string]::IsNullOrEmpty($ArtifactScanningPathTextBox.Text)
    $resolvedClamAVPath = Resolve-ClamAVScannerExecutable -SelectedScannerPath $ClamAVPathTextBox.Text
    $resolvedLokiPath = Resolve-LokiExecutablePath -SelectedPath $LokiPathTextBox.Text
    $resolvedLokiUpdaterPath = Resolve-LokiUpdaterExecutablePath -SelectedPath $LokiUpdaterPathTextBox.Text

    # Enable or disable buttons based on conditions
    $ScanClamAVButton.IsEnabled = $artifactScanningPathFilled -and (Test-ThreatScannerPath $resolvedClamAVPath)
    $ScanLokiButton.IsEnabled = $artifactScanningPathFilled -and (Test-ThreatScannerPath $resolvedLokiPath)
    $UpdateLokiButton.IsEnabled = (Test-ThreatScannerPath $resolvedLokiUpdaterPath)
	$UpdateclamAVButton.IsEnabled = (Test-ThreatScannerPath $clamAVUpdaterPathTextBox.Text)
}

#Timer for ClamAV initialization
$Global:clamAVJobs = @()
$clamAVJobTimer = New-Object System.Windows.Forms.Timer
$clamAVJobTimer.Interval = 2000
$clamAVJobTimer.Add_Tick({
    Check-ClamAVJobStatus
})

function Check-ClamAVJobStatus {
    $remainingJobs = @()
    foreach ($job in $Global:clamAVJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    Update-Log "Finished ClamAV Scan for $($job.ArtifactPath)" "ThreatScannerTextBox"
                    Write-Host "$timestamp Finished ClamAV Scan for $($job.ArtifactPath)"
                } else {
                    $failureReason = Get-JobFailureReasonText -Job $updatedJob
                    if ($failureReason) {
                        Update-Log "ClamAV Scan failed for $($job.ArtifactPath): $failureReason" "ThreatScannerTextBox"
                    } else {
                        Update-Log "ClamAV Scan failed for $($job.ArtifactPath)." "ThreatScannerTextBox"
                    }
                }
                $job.DataAdded = $true
            }

            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:clamAVJobs = $remainingJobs

    if ($Global:clamAVJobs.Count -eq 0) {
        $resolvedScannerPath = Resolve-ClamAVScannerExecutable -SelectedScannerPath $ClamAVPathTextBox.Text
        Stop-SharedClamAVDaemon -ScannerExecutablePath $resolvedScannerPath
        Update-Log "All ClamAV Scan jobs completed." "ThreatScannerTextBox"
        $clamAVJobTimer.Stop()
    }
}

function Find-ClamAVScannerExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $clamdscanPath = Get-ChildItem -Path $toolsDirectory -Filter "clamdscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($clamdscanPath) {
        $clamdPath = Join-Path (Split-Path $clamdscanPath -Parent) "clamd.exe"
        if (Test-Path $clamdPath) {
            $ClamAVPathTextBox.Text = $clamdscanPath
            return
        }
    }

    $clamscanPath = Get-ChildItem -Path $toolsDirectory -Filter "clamscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if (-not $clamscanPath) {
        $clamscanPath = $clamdscanPath
    }
    $ClamAVPathTextBox.Text = $clamscanPath
}

# Backward-compatible alias for older references.
function Find-ClamdscanExecutable {
    Find-ClamAVScannerExecutable
}

function Resolve-ClamAVScannerExecutable {
    param([string]$SelectedScannerPath)

    $resolvedPath = Normalize-ThreatScannerPath -PathValue $SelectedScannerPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return $resolvedPath
    }

    $scannerDir = $resolvedPath
    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue) {
        $scannerDir = Split-Path $resolvedPath -Parent
    }

    $clamdscanPath = Join-Path $scannerDir "clamdscan.exe"
    $clamdPath = Join-Path $scannerDir "clamd.exe"
    $clamscanPath = Join-Path $scannerDir "clamscan.exe"
    if ((Test-Path $clamdscanPath) -and (Test-Path $clamdPath)) {
        return $clamdscanPath
    }
    if (Test-Path $clamscanPath) {
        return $clamscanPath
    }

    return $resolvedPath
}

function ScanClamAVButton_Click {
    Update-Log "Starting ClamAV scan..." "ThreatScannerTextBox"
    
    if (-not $ArtifactScanningPathTextBox.Text -or -not $ClamAVPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select a scan path and ClamAV scanner executable.")
        return
    }
		
    $ArtifactPath = $ArtifactScanningPathTextBox.Text.trim().Trim('"')
    $ClamAVPathFilePath = Resolve-ClamAVScannerExecutable -SelectedScannerPath $ClamAVPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($ClamAVPathFilePath)) {
        [System.Windows.MessageBox]::Show("Please select a valid ClamAV scanner executable.")
        return
    }
		
    Scan-ClamAV -ArtifactPath $ArtifactPath -ClamAVFilePath $ClamAVPathFilePath
    
    # Check if the timer is already running
    if (-not $clamAVJobTimer.Enabled) {
        $clamAVJobTimer.Start()
    } 
}

function Scan-ClamAV {
    param (
        [string]$ArtifactPath,
        [string]$ClamAVFilePath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "ClamAV_{0}_{1}.txt" -f $timestamp, [IO.Path]::GetFileNameWithoutExtension($ArtifactPath)
    $logFilePath = Join-Path $global:currentcasedirectory "ThreatScanners\$logFileName"

    # Ensure that the path ends correctly for volumes
    if ($ArtifactPath -match "\\$") {
        $ArtifactPath = $ArtifactPath.TrimEnd('\')
    }

    Start-ClamAVScanJob -ArtifactPath $ArtifactPath -ClamAVFilePath $ClamAVFilePath -LogFilePath $logFilePath
}

function Start-ClamAVScanJob {
    param (
        [string]$ArtifactPath,
        [string]$ClamAVFilePath,
        [string]$LogFilePath
    )
    $job = Start-Job -ScriptBlock {
        param ($ArtifactPath, $ClamAVFilePath, $LogFilePath)
        $scannerPath = $ClamAVFilePath
        $scannerName = [IO.Path]::GetFileName($scannerPath).ToLowerInvariant()
        $scannerDirectory = Split-Path $scannerPath -Parent
        $clamdscanPath = Join-Path $scannerDirectory "clamdscan.exe"
        $clamdPath = Join-Path $scannerDirectory "clamd.exe"
        $preferredClamscan = Join-Path $scannerDirectory "clamscan.exe"
        $databaseDirectory = Join-Path $scannerDirectory "database"
        $clamdTempDir = Join-Path $scannerDirectory "echo_clamd_tmp"
        $stateFilePath = Join-Path $clamdTempDir "echo_clamd_state.json"

        # Prefer clamdscan when both daemon binaries are available.
        if ((Test-Path $clamdscanPath) -and (Test-Path $clamdPath)) {
            $scannerPath = $clamdscanPath
            $scannerName = "clamdscan.exe"
        } elseif ($scannerName -ne "clamscan.exe" -and (Test-Path $preferredClamscan)) {
            $scannerPath = $preferredClamscan
            $scannerName = "clamscan.exe"
        }

        if ($scannerName -eq "clamdscan.exe") {
                if (-not (Test-Path $databaseDirectory)) {
                    throw "ClamAV database directory not found: $databaseDirectory"
                }

                if (-not (Test-Path $clamdTempDir)) {
                    New-Item -Path $clamdTempDir -ItemType Directory -Force | Out-Null
                }

                $mutex = New-Object System.Threading.Mutex($false, "Global\ECHO_ClamAV_DaemonLock")
                $mutexTaken = $false
                $clamdConfigPath = $null

                try {
                    $mutexTaken = $mutex.WaitOne(120000)
                    if (-not $mutexTaken) {
                        throw "Timed out waiting for ClamAV daemon lock."
                    }

                    $testPort = {
                        param([int]$Port)
                        try {
                            $client = New-Object System.Net.Sockets.TcpClient
                            $asyncResult = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
                            $connected = $asyncResult.AsyncWaitHandle.WaitOne(500, $false)
                            if ($connected) {
                                $client.EndConnect($asyncResult) | Out-Null
                                $client.Close()
                                return $true
                            }
                            $client.Close()
                        } catch { }
                        return $false
                    }

                    $existingState = $null
                    if (Test-Path $stateFilePath) {
                        try {
                            $existingState = Get-Content -Path $stateFilePath -Raw -Encoding UTF8 | ConvertFrom-Json
                        } catch {
                            Remove-Item -Path $stateFilePath -Force -ErrorAction SilentlyContinue
                        }
                    }

                    $useExistingDaemon = $false
                    if ($existingState -and $existingState.Pid -and $existingState.Port -and $existingState.ConfigPath) {
                        $existingProc = Get-Process -Id ([int]$existingState.Pid) -ErrorAction SilentlyContinue
                        if ($existingProc -and (Test-Path $existingState.ConfigPath) -and (& $testPort ([int]$existingState.Port))) {
                            $clamdConfigPath = [string]$existingState.ConfigPath
                            $useExistingDaemon = $true
                        }
                    }

                    if (-not $useExistingDaemon) {
                        $listenPort = $null
                        for ($i = 0; $i -lt 25; $i++) {
                            $candidatePort = Get-Random -Minimum 35000 -Maximum 45000
                            try {
                                $portProbe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse("127.0.0.1"), $candidatePort)
                                $portProbe.Start()
                                $portProbe.Stop()
                                $listenPort = $candidatePort
                                break
                            } catch { }
                        }
                        if (-not $listenPort) {
                            throw "Unable to allocate a TCP port for clamd."
                        }

                        $maxThreads = [Environment]::ProcessorCount
                        if ($maxThreads -lt 1) {
                            $maxThreads = 1
                        }

                        $clamdConfigPath = Join-Path $clamdTempDir ("echo_clamd_{0}.conf" -f $listenPort)
                        @(
                            "LogTime yes",
                            "Foreground yes",
                            "TCPSocket $listenPort",
                            "TCPAddr 127.0.0.1",
                            "MaxThreads $maxThreads",
                            "DatabaseDirectory $databaseDirectory",
                            "TemporaryDirectory $clamdTempDir"
                        ) | Set-Content -Path $clamdConfigPath -Encoding ASCII -Force

                        $clamdProcess = Start-Process -FilePath $clamdPath -ArgumentList @("--config-file=$clamdConfigPath", "--foreground=yes") -WorkingDirectory $scannerDirectory -WindowStyle Hidden -PassThru

                        $daemonReady = $false
                        for ($i = 0; $i -lt 240; $i++) {
                            Start-Sleep -Milliseconds 500
                            if ($clamdProcess.HasExited) {
                                throw "clamd exited before becoming ready."
                            }
                            if (& $testPort $listenPort) {
                                $daemonReady = $true
                                break
                            }
                        }

                        if (-not $daemonReady) {
                            throw "Timed out waiting for clamd to start."
                        }

                        [PSCustomObject]@{
                            Pid        = $clamdProcess.Id
                            Port       = $listenPort
                            ConfigPath = $clamdConfigPath
                        } | ConvertTo-Json -Compress | Set-Content -Path $stateFilePath -Encoding UTF8 -Force
                    }
                } finally {
                    if ($mutexTaken) {
                        $mutex.ReleaseMutex() | Out-Null
                    }
                    $mutex.Dispose()
                }

                if (-not $clamdConfigPath -or (-not (Test-Path $clamdConfigPath))) {
                    throw "ClamAV daemon config was not available."
                }

                $clamArgs = @("--config-file=$clamdConfigPath", "--multiscan", "--log=$LogFilePath", $ArtifactPath)
                & $scannerPath @clamArgs
        } elseif ($scannerName -eq "clamscan.exe") {
                Set-Location $scannerDirectory

                $clamArgs = @("--log=$LogFilePath")
                if (Test-Path $databaseDirectory) {
                    $clamArgs += "--database=$databaseDirectory"
                }
                if (Test-Path -LiteralPath $ArtifactPath -PathType Container) {
                    $clamArgs += "--recursive=yes"
                }
                $clamArgs += $ArtifactPath

                & $scannerPath @clamArgs
        } else {
            throw "Unsupported ClamAV scanner executable: $scannerPath"
        }

        # ClamAV returns 1 when malware is found, which is a successful scan completion.
        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne 1) {
            throw "ClamAV scan exited with code $LASTEXITCODE. Scanner: $scannerPath. Log: $LogFilePath"
        }
    } -ArgumentList $ArtifactPath, $ClamAVFilePath, $LogFilePath

    # Store the job in the global job list
    $Global:clamAVJobs += [PSCustomObject]@{
        JobObject = $job
        ArtifactPath = $ArtifactPath
        LogFilePath = $LogFilePath
        DataAdded = $false
    }
}

#Timer for ClamAV update
$Global:clamAVupdateJobs = @()
$ClamAVupdateJobTimer = New-Object System.Windows.Forms.Timer
$ClamAVupdateJobTimer.Interval = 2000
$ClamAVupdateJobTimer.Add_Tick({
    Check-ClamAVUpdateJobStatus
})

function Check-ClamAVUpdateJobStatus {
    $remainingJobs = @()
    foreach ($job in $Global:clamAVupdateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    Update-Log "Finished ClamAV Update" "ThreatScannerTextBox"
                    Write-Host "$timestamp Finished ClamAV Update"
                } else {
                    $failureReason = Get-JobFailureReasonText -Job $updatedJob
                    if ($failureReason) {
                        Update-Log "ClamAV Update failed: $failureReason" "ThreatScannerTextBox"
                    } else {
                        Update-Log "ClamAV Update failed." "ThreatScannerTextBox"
                    }
                }
                $job.DataAdded = $true
            }

            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:clamAVupdateJobs = $remainingJobs
    if ($Global:clamAVupdateJobs.Count -eq 0) {
        $ClamAVupdateJobTimer.Stop()
    }
}

function Find-ClamAVUpgraderExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $clamAVPath = Get-ChildItem -Path $toolsDirectory -Filter "freshclam.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $clamAVUpdaterPathTextBox.Text = $clamAVPath
}

function UpdateclamAVButton_Click {
    Update-Log "Starting ClamAV Upgrader (freshclam)..." "ThreatScannerTextBox"
    
    if (-not $clamAVUpdaterPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select the freshclam executable.")
        return
    }
    $clamAVUpgraderFilePath = $clamAVUpdaterPathTextBox.Text.trim().Trim('"')

    Upgrade-ClamAV -ClamAVUpgraderFilePath $ClamAVUpgraderFilePath
    
    if (-not $ClamAVupdateJobTimer.Enabled) {
        $ClamAVupdateJobTimer.Start()
    } 
}

function Upgrade-ClamAV {
    param (
        [string]$ClamAVUpgraderFilePath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $clamAVUpgraderDirectory = Split-Path $clamAVUpgraderFilePath
    $outputFile = Join-Path $clamAVUpgraderDirectory "clamAV_upgrader_output_$timestamp.txt"

    Update-Log "ClamAV upgrader path is $clamAVUpgraderFilePath. Output will be logged to $outputFile" "ThreatScannerTextBox"

    $job = Start-Job -ScriptBlock {
        param($clamAVUpgraderFilePath, $outputFile, $clamAVUpgraderDirectory)
        Set-Location $clamAVUpgraderDirectory
        & $clamAVUpgraderFilePath *> $outputFile
        if ($LASTEXITCODE -ne 0) {
            throw "freshclam exited with code $LASTEXITCODE. See log file: $outputFile"
        }
    } -ArgumentList $clamAVUpgraderFilePath, $outputFile, $clamAVUpgraderDirectory

    $Global:clamAVupdateJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = "ClamAV Upgrade"
        DataAdded = $false
    }
}

#Timer for Loki initialization
$Global:lokiJobs = @()
$lokiJobTimer = New-Object System.Windows.Forms.Timer
$lokiJobTimer.Interval = 2000
$lokiJobTimer.Add_Tick({
    Check-LokiJobStatus
})

function Check-LokiJobStatus {
    $remainingJobs = @()
    foreach ($job in $Global:lokiJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    if (Test-Path $job.Logfile) {
                        Update-Log "Finished Loki Scan: $($job.PluginName) for $($job.ArtifactPath). `nLog file: $($job.Logfile)" "ThreatScannerTextBox"
                    } else {
                        Update-Log "Finished Loki Scan: $($job.PluginName) for $($job.ArtifactPath). `nNo findings detected." "ThreatScannerTextBox"
                        $noFindingsMsg = "No findings detected in the Loki scan for $($job.ArtifactPath)"
                        Out-File -FilePath $job.Logfile -InputObject $noFindingsMsg -Force
                    }
                    Write-Host "$timestamp Finished Loki Scan: $($job.PluginName) for $($job.ArtifactPath)"
                } else {
                    $failureReason = Get-JobFailureReasonText -Job $updatedJob
                    if ($failureReason) {
                        Update-Log "Loki Scan failed for $($job.ArtifactPath): $failureReason" "ThreatScannerTextBox"
                    } else {
                        Update-Log "Loki Scan failed for $($job.ArtifactPath)." "ThreatScannerTextBox"
                    }
                }
                $job.DataAdded = $true
            }

            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:lokiJobs = $remainingJobs
    if ($Global:lokiJobs.Count -eq 0) {
        Update-Log "All Loki Scan jobs completed." "ThreatScannerTextBox"
        $lokiJobTimer.Stop()
    }
}

function Find-LokiExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $LokiPath = Get-ChildItem -Path $toolsDirectory -Filter "loki.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $LokiPathTextBox.Text = $LokiPath
}

function Resolve-LokiExecutablePath {
    param([string]$SelectedPath)

    $resolvedPath = Normalize-ThreatScannerPath -PathValue $SelectedPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return $resolvedPath
    }

    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $resolvedPath
    }

    $lokiPath = Join-Path $resolvedPath "loki.exe"
    if (Test-Path -LiteralPath $lokiPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $lokiPath
    }

    return $resolvedPath
}

function ScanLokiButton_Click {
    Update-Log "Starting Loki..." "ThreatScannerTextBox"
    
    if (-not $ArtifactScanningPathTextBox.Text -or -not $LokiPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an scan path and Loki executable.")
        return
    }
	
    $ArtifactPath = $ArtifactScanningPathTextBox.Text.trim().Trim('"')
    $LokiPathFilePath = Resolve-LokiExecutablePath -SelectedPath $LokiPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($LokiPathFilePath) -or (-not (Test-Path -LiteralPath $LokiPathFilePath -PathType Leaf -ErrorAction SilentlyContinue))) {
        [System.Windows.MessageBox]::Show("Please select a valid loki.exe path or a folder containing loki.exe.")
        return
    }
    $LokiPathTextBox.Text = $LokiPathFilePath
    $includeProcScan = $ProcscanCheckbox.IsChecked
    $includeIntenseScan = $IntenseScanCheckbox.IsChecked
    $includeVulnChecks = $VulnchecksCheckbox.IsChecked

    Scan-Loki -ArtifactPath $ArtifactPath -LokiFilePath $LokiPathFilePath -IncludeProcScan $includeProcScan -IncludeIntenseScan $includeIntenseScan -IncludeVulnChecks $includeVulnChecks
    
    if (-not $lokiJobTimer.Enabled) {
        $lokiJobTimer.Start()
    } 
}

function Scan-Loki {
    param (
        [string]$ArtifactPath,
        [string]$LokiFilePath,
        [bool]$IncludeProcScan,
        [bool]$IncludeIntenseScan,
        [bool]$IncludeVulnChecks
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $logFileName = "Loki_{0}_{1}.csv" -f $timestamp, [IO.Path]::GetFileNameWithoutExtension($ArtifactPath)
    $logFilePath = Join-Path $global:currentcasedirectory "ThreatScanners\$logFileName"

    if ($ArtifactPath -match "\\$") {
        $ArtifactPath = $ArtifactPath.TrimEnd('\')
    }
    $lokiArgs = @("--onlyrelevant", "--csv", "-l", "`"$logFilePath`"", "-p", "`"$ArtifactPath`"")
    $lokiDirectory = Split-Path $LokiFilePath
    # Adjust arguments based on checkbox states
    if (-not $IncludeProcScan) { $lokiArgs += "--noprocscan" }
    if ($IncludeIntenseScan) { $lokiArgs += "--intense" }
    if ($IncludeVulnChecks) { $lokiArgs += "--vulnchecks" }
    $job = Start-Job -ScriptBlock {
        param ($LokiFilePath, $lokiArgs, $lokiDirectory)
			Set-Location $lokiDirectory
        & $LokiFilePath @lokiArgs
    } -ArgumentList $LokiFilePath, $lokiArgs, $lokiDirectory

    $Global:lokiJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = "Loki Scan"
        ArtifactPath = $ArtifactPath
		Logfile = $logFilePath
        DataAdded = $false
    }
}

#Timer for Loki update
$Global:lokiupdateJobs = @()
$lokiupdateJobTimer = New-Object System.Windows.Forms.Timer
$lokiupdateJobTimer.Interval = 2000
$lokiupdateJobTimer.Add_Tick({
    Check-LokiUpdateJobStatus
})

function Check-LokiUpdateJobStatus {
    $remainingJobs = @()
    foreach ($job in $Global:lokiupdateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                    Update-Log "Finished Loki Update" "ThreatScannerTextBox"
                    Write-Host "$timestamp Finished Loki Update"
                } else {
                    $failureReason = Get-JobFailureReasonText -Job $updatedJob
                    if ($failureReason) {
                        Update-Log "Loki Update failed: $failureReason" "ThreatScannerTextBox"
                    } else {
                        Update-Log "Loki Update failed." "ThreatScannerTextBox"
                    }
                }
                $job.DataAdded = $true
            }

            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:lokiupdateJobs = $remainingJobs
    if ($Global:lokiupdateJobs.Count -eq 0) {
        $lokiupdateJobTimer.Stop()
    }
}

function Find-LokiUpgraderExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $LokiPath = Get-ChildItem -Path $toolsDirectory -Filter "loki-upgrader.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $LokiUpdaterPathTextBox.Text = $LokiPath
}

function Resolve-LokiUpdaterExecutablePath {
    param([string]$SelectedPath)

    $resolvedPath = Normalize-ThreatScannerPath -PathValue $SelectedPath
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return $resolvedPath
    }

    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $resolvedPath
    }

    $updaterPath = Join-Path $resolvedPath "loki-upgrader.exe"
    if (Test-Path -LiteralPath $updaterPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $updaterPath
    }

    return $resolvedPath
}

function UpdateLokiButton_Click {
    Update-Log "Starting Loki Upgrader..." "ThreatScannerTextBox"
    
    if (-not $LokiUpdaterPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select the Loki-Upgrader executable.")
        return
    }
    $LokiUpgraderFilePath = Resolve-LokiUpdaterExecutablePath -SelectedPath $LokiUpdaterPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($LokiUpgraderFilePath) -or (-not (Test-Path -LiteralPath $LokiUpgraderFilePath -PathType Leaf -ErrorAction SilentlyContinue))) {
        [System.Windows.MessageBox]::Show("Please select a valid loki-upgrader.exe path or a folder containing loki-upgrader.exe.")
        return
    }
    $LokiUpdaterPathTextBox.Text = $LokiUpgraderFilePath

    Upgrade-Loki -LokiUpgraderFilePath $LokiUpgraderFilePath
    
    if (-not $lokiupdateJobTimer.Enabled) {
        $lokiupdateJobTimer.Start()
    } 
}

function Upgrade-Loki {
    param (
        [string]$LokiUpgraderFilePath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $lokiUpgraderDirectory = Split-Path $LokiUpgraderFilePath
    $outputFile = Join-Path $lokiUpgraderDirectory "loki_upgrader_output_$timestamp.txt"

    Update-Log "Loki upgrader path is $LokiUpgraderFilePath. Output will be logged to $outputFile" "ThreatScannerTextBox"

    $job = Start-Job -ScriptBlock {
        param($lokiUpgraderFilePath, $outputFile, $lokiUpgraderDirectory)
        Set-Location $lokiUpgraderDirectory
        & $lokiUpgraderFilePath *> $outputFile
        if ($LASTEXITCODE -ne 0) {
            throw "loki-upgrader exited with code $LASTEXITCODE. See log file: $outputFile"
        }
    } -ArgumentList $LokiUpgraderFilePath, $outputFile, $lokiUpgraderDirectory

    $Global:lokiupdateJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = "Loki Upgrade"
        DataAdded = $false
    }
}

####End of Threat Scanner Functions####
