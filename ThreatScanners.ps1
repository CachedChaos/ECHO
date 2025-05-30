####Start of Threat Scanner Functions#####
function OnTabThreatScanners_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "ThreatScanners"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'ThreatScanners' created successfully." "ThreatScannerTextBox"
    }

    # Check and call Find-* functions only if the corresponding path text boxes are empty or invalid
    if (-not (IsValidPath $ClamAVPathTextBox.Text "clamdscan.exe")) {
        Find-ClamdscanExecutable
    }
    if (-not (IsValidPath $LokiPathTextBox.Text "loki.exe")) {
        Find-LokiExecutable
    }
	
    if (-not (IsValidPath $LokiUpdaterPathTextBox.Text "loki-upgrader.exe")) {
        Find-LokiUpgraderExecutable
    }	
	
    if (-not (IsValidPath $clamAVUpdaterPathTextBox.Text "freshclam.exe")) {
        Find-ClamAVUpgraderExecutable
    }		
}

function UpdateScanningButtonsStatus() {
    $artifactScanningPathFilled = -not [string]::IsNullOrEmpty($ArtifactScanningPathTextBox.Text)

    # Function to safely test paths
    function SafeTestPath($path) {
        return -not [string]::IsNullOrEmpty($path) -and (Test-Path $path)
    }

    # Enable or disable buttons based on conditions
    $ScanClamAVButton.IsEnabled = $artifactScanningPathFilled -and (SafeTestPath $ClamAVPathTextBox.Text)
    $ScanLokiButton.IsEnabled = $artifactScanningPathFilled -and (SafeTestPath $LokiPathTextBox.Text)
    $UpdateLokiButton.IsEnabled = (SafeTestPath $LokiUpdaterPathTextBox.Text)
	$UpdateclamAVButton.IsEnabled = (SafeTestPath $clamAVUpdaterPathTextBox.Text)
}

#Timer for ClamAV initialization
$Global:clamAVJobs = @()
$clamAVJobTimer = New-Object System.Windows.Forms.Timer
$clamAVJobTimer.Interval = 2000
$clamAVJobTimer.Add_Tick({
    Check-ClamAVJobStatus
})

function Check-ClamAVJobStatus {
    $completedCount = 0
    foreach ($job in $Global:clamAVJobs) {
        # Refresh the job state
        $updatedJob = Get-Job -Id $job.JobObject.Id
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Finished ClamAV Scan: $($job.PluginName) for $($job.ArtifactPath)" "ThreatScannerTextBox"
				Write-Host "$timestamp Finished ClamAV Scan: $($job.PluginName) for $($job.ArtifactPath)"
                $job.DataAdded = $true
            }
            $completedCount++
        }
    }
    if ($completedCount -eq $Global:clamAVJobs.Count) {
        Update-Log "All ClamAV Scan jobs completed." "ThreatScannerTextBox"
        $clamAVJobTimer.Stop()
		
        # Stop the clamd job
        if ($Global:clamdJob -and ($Global:clamdJob.State -eq 'Running')) {
            Stop-Job -Id $Global:clamdJob.Id
            Remove-Job -Id $Global:clamdJob.Id
            $Global:clamdJob = $null
            Update-Log "Clamd process stopped." "ThreatScannerTextBox"
        }		
    }
}

function Find-ClamdscanExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $clamdscanPath = Get-ChildItem -Path $toolsDirectory -Filter "clamdscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $ClamAVPathTextBox.Text = $clamdscanPath
}

function ScanClamAVButton_Click {
    Update-Log "Starting Clamdscan..." "ThreatScannerTextBox"
    
    if (-not $ArtifactScanningPathTextBox.Text -or -not $ClamAVPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an scan path and Clamdscan executable.")
        return
    }
	
    $ArtifactPath = $ArtifactScanningPathTextBox.Text.trim().Trim('"')
    $ClamAVPathFilePath = $ClamAVPathTextBox.Text.trim().Trim('"')
	
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

    # Start clamd in a background job and track it
    $existingClamdJob = Get-Job | Where-Object { $_.Name -eq 'ClamdJob' -and $_.State -eq 'Running' }
    if ($existingClamdJob) {
        $clamdJob = $existingClamdJob
    } else {
        $clamdJob = Start-ClamdJob -ClamAVFilePath $ClamAVFilePath
        $Global:clamdJob = $clamdJob  # Store the clamd job globally
    }
    # Start clamdscan in a background job
    Start-ClamdscanJob -ArtifactPath $ArtifactPath -ClamAVFilePath $ClamAVFilePath -LogFilePath $logFilePath -ClamdJob $clamdJob
}

function Start-ClamdJob {
    param ([string]$ClamAVFilePath)

    $clamdPath = Join-Path (Split-Path $ClamAVFilePath) 'clamd.exe'
    $job = Start-Job -ScriptBlock {
        param ($clamdPath)
        & $clamdPath
    } -ArgumentList $clamdPath

    return $job
}

function Start-ClamdscanJob {
    param (
        [string]$ArtifactPath,
        [string]$ClamAVFilePath,
        [string]$LogFilePath,
        $ClamdJob
    )
    $job = Start-Job -ScriptBlock {
        param ($ArtifactPath, $ClamAVFilePath, $LogFilePath)
        try {
            # Perform the scan
            & $ClamAVFilePath -m -w --log="`"$LogFilePath`"" "`"$ArtifactPath`""
        } catch {
            Write-Host "Error running ClamAV scan: $_"
        }
    } -ArgumentList $ArtifactPath, $ClamAVFilePath, $LogFilePath

    # Store the job in the global job list
    $Global:clamAVJobs += [PSCustomObject]@{
        JobObject = $job
        ArtifactPath = $ArtifactPath
        LogFilePath = $LogFilePath
        ClamdJob = $ClamdJob
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
    $completedCount = 0
    foreach ($job in $Global:clamAVupdateJobs) {
        # Refresh the job state
        $updatedJob = Get-Job -Id $job.JobObject.Id
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Finished ClamAV Update" "ThreatScannerTextBox"
				Write-Host "$timestamp Finished ClamAV Update"
                $job.DataAdded = $true
            }
            $completedCount++
        }
    }
    if ($completedCount -eq $Global:clamAVupdateJobs.Count) {
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
        [System.Windows.MessageBox]::Show("Please select the clamdscan executable.")
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
    $completedCount = 0
    foreach ($job in $Global:lokiJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                if (Test-Path $job.Logfile) {
                    Update-Log "Finished Loki Scan: $($job.PluginName) for $($job.ArtifactPath). `nLog file: $($job.Logfile)" "ThreatScannerTextBox"
                } else {
                    Update-Log "Finished Loki Scan: $($job.PluginName) for $($job.ArtifactPath). `nNo findings detected." "ThreatScannerTextBox"
                    $noFindingsMsg = "No findings detected in the Loki scan for $($job.ArtifactPath)"
                    Out-File -FilePath $job.Logfile -InputObject $noFindingsMsg -Force
                }
                Write-Host "$timestamp Finished Loki Scan: $($job.PluginName) for $($job.ArtifactPath)"
                $job.DataAdded = $true
            }
            $completedCount++
        }
    }

    if ($completedCount -eq $Global:lokiJobs.Count) {
        Update-Log "All Loki Scan jobs completed." "ThreatScannerTextBox"
        $lokiJobTimer.Stop()
    }
}

function Find-LokiExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $LokiPath = Get-ChildItem -Path $toolsDirectory -Filter "loki.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $LokiPathTextBox.Text = $LokiPath
}

function ScanLokiButton_Click {
    Update-Log "Starting Loki..." "ThreatScannerTextBox"
    
    if (-not $ArtifactScanningPathTextBox.Text -or -not $LokiPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an scan path and Loki executable.")
        return
    }
	
    $ArtifactPath = $ArtifactScanningPathTextBox.Text.trim().Trim('"')
    $LokiPathFilePath = $LokiPathTextBox.Text.trim().Trim('"')
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
	Update-Log "lokiargs: $lokiArgs" "ThreatScannerTextBox"
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
    $completedCount = 0
    foreach ($job in $Global:lokiupdateJobs) {
        # Refresh the job state
        $updatedJob = Get-Job -Id $job.JobObject.Id
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Finished Loki Update" "ThreatScannerTextBox"
				Write-Host "$timestamp Finished Loki Update"
                $job.DataAdded = $true
            }
            $completedCount++
        }
    }
    if ($completedCount -eq $Global:lokiupdateJobs.Count) {
        $lokiupdateJobTimer.Stop()
    }
}

function Find-LokiUpgraderExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $LokiPath = Get-ChildItem -Path $toolsDirectory -Filter "loki-upgrader.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $LokiUpdaterPathTextBox.Text = $LokiPath
}

function UpdateLokiButton_Click {
    Update-Log "Starting Loki Upgrader..." "ThreatScannerTextBox"
    
    if (-not $LokiUpdaterPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select the Loki-Upgrader executable.")
        return
    }
    $LokiUpgraderFilePath = $LokiUpdaterPathTextBox.Text.trim().Trim('"')

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
    } -ArgumentList $LokiUpgraderFilePath, $outputFile, $lokiUpgraderDirectory

    $Global:lokiupdateJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = "Loki Upgrade"
        DataAdded = $false
    }
}

####End of Threat Scanner Functions####