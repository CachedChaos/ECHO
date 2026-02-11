####Starting functions for System Processing####

#Timer for bulk extractor initialization
$Global:bulkJobs = @()
$bulkJobTimer = New-Object System.Windows.Forms.Timer
$bulkJobTimer.Interval = 2000
$bulkJobTimer.Add_Tick({
    Check-BulkJobStatus
})

#Timer for chainsaw initialization
$Global:chainsawjobs = @()
$chainsawJobTimer = New-Object System.Windows.Forms.Timer
$chainsawJobTimer.Interval = 2000
$chainsawJobTimer.Add_Tick({
    Check-chainsawJobStatus
})

#Timer for extractArchivesJobs initialization
$Global:extractArchivesJobs = @()
$extractArchivesTimer = New-Object System.Windows.Forms.Timer
$extractArchivesTimer.Interval = 2000 # 2 seconds
$extractArchivesTimer.Add_Tick({
    Check-ExtractArchivesJobStatus
})

#Timer for geoIP parser initialization
$Global:geolocateJobs = @()
$geolocateProcessingTimer = New-Object System.Windows.Forms.Timer
$geolocateProcessingTimer.Interval = 2000 # 2 seconds
$geolocateProcessingTimer.Add_Tick({
    Check-GeoLocateProcessingStatus
})

#Timer for hayabusa parser initialization
$Global:hayabusalocateJobs = @()
$HyabusaProcessingTimer = New-Object System.Windows.Forms.Timer
$HyabusaProcessingTimer.Interval = 2000 # 2 seconds
$HyabusaProcessingTimer.Add_Tick({
    Check-HyabusaProcessingStatus
})

#Timer for plaso parser initialization
$Global:plasolocateJobs = @()
$plasoProcessingTimer = New-Object System.Windows.Forms.Timer
$plasoProcessingTimer.Interval = 2000 # 2 seconds
$plasoProcessingTimer.Add_Tick({
    Check-PlasoProcessingStatus
})

#Timer for zimmermanProcessingTimer initialization
$Global:zimmermanJobs = @()
$Global:zimmermanPendingJobs = @()
$Global:zimmermanMaxParallel = 4
$Global:zimmermanRequestCounter = 0
$Global:zimmermanRequestTracker = @{}
$zimmermanProcessingTimer = New-Object System.Windows.Forms.Timer
$zimmermanProcessingTimer.Interval = 2000 # 2 seconds
$zimmermanProcessingTimer.Add_Tick({
    Check-ZimmermanProcessingStatus
})

#Timer for Zimmerman Tools update
$Global:zimmermantoolsUpdateJobs = @()
$zimmermantoolsUpdateTimer = New-Object System.Windows.Forms.Timer
$zimmermantoolsUpdateTimer.Interval = 2000 # 2 seconds
$zimmermantoolsUpdateTimer.Add_Tick({
    Check-ZimmermanToolsStatus
})

#Timer for zircolite initialization
$Global:zircoliteJobs = @()
$zircoliteProcessingTimer = New-Object System.Windows.Forms.Timer
$zircoliteProcessingTimer.Interval = 2000 # 2 seconds
$zircoliteProcessingTimer.Add_Tick({
    Check-ZircoliteProcessingStatus
})

#Timer for zircolite update
$Global:zircoliteupdateJobs = @()
$zircoliteUpdateTimer = New-Object System.Windows.Forms.Timer
$zircoliteUpdateTimer.Interval = 2000 # 2 seconds
$zircoliteUpdateTimer.Add_Tick({
    Check-ZircoliteUpdateStatus
})

#Timer for timeline artifacts initialization
$Global:timelineartifactsJobs = @()
$timelineartifactsJobTimer = New-Object System.Windows.Forms.Timer
$timelineartifactsJobTimer.Interval = 2000
$timelineartifactsJobTimer.Add_Tick({
    Check-TimelineArtifactsJobStatus
})

#Timer for timeline export initialization
$Global:timelineexportJobs = @()
$timelineexportJobTimer = New-Object System.Windows.Forms.Timer
$timelineexportJobTimer.Interval = 2000
$timelineexportJobTimer.Add_Tick({
    Check-TimelineExportJobStatus
})

function OnTabProcessArtifacts_GotFocus {
    $currentCaseDirectory = [string]$global:currentcasedirectory
    if ([string]::IsNullOrWhiteSpace($currentCaseDirectory)) {
        return
    }

    $nowUtc = [DateTime]::UtcNow
    if (
        $script:lastProcessArtifactsFocusCase -eq $currentCaseDirectory -and
        $script:lastProcessArtifactsFocusUtc -and
        ($nowUtc - $script:lastProcessArtifactsFocusUtc).TotalMilliseconds -lt 1500
    ) {
        return
    }
    $script:lastProcessArtifactsFocusCase = $currentCaseDirectory
    $script:lastProcessArtifactsFocusUtc = $nowUtc

    $subDirectoryPath = Join-Path $global:currentcasedirectory "SystemArtifacts"
    $global:timelineIOCFilePath = Join-Path $subDirectoryPath "CustomIOCs.txt"
    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'SystemArtifacts' created successfully." "ProcessSystemTextBox"
    }
    foreach ($path in @($timelineIOCFilePath)) {
        if (!(Test-Path $path)) {
            New-Item -ItemType File -Path $path | Out-Null
            Update-Log "File '$(Split-Path $path -Leaf)' created successfully." "ProcessSystemTextBox"
        }
    }
    # Check and call Find-* functions only if the corresponding path text boxes are empty or invalid
    if (-not (IsValidPath $BulkExtractorPathTextBox.Text "bulk_extractor64.exe")) {
        Find-BulkExtractorExecutable
    }
    if (-not (IsValidPath $ZimmermanPathTextBox.Text "Get-ZimmermanTools.ps1")) {
        Find-ZimmermanTools
    }
    if (-not (IsValidPath $SevenzipPathTextBox.Text "7za.exe")) {
        Find-7zipExecutable
    }
    if (-not (IsValidPath $GeoLite2CityDBPathTextBox.Text "GeoLite2-City.mmdb")) {
        Find-GeoLite2CityDB
    }
    if (-not (IsValidPath $PlasoPathTextBox.Text "log2timeline.py")) {
        Find-Plaso
    }
    if (-not (IsValidPath $HayabusaPathTextBox.Text "hayabusa*.exe")) {
        Find-hayabusa
    }	
    if (-not (IsValidPath $ChainsawPathTextBox.Text "chainsaw*.exe")) {
        Find-chainsaw
    }	
    if (-not (IsValidPath $ZircolitePathTextBox.Text "zircolite*.exe")) {
        Find-zircolite
    }	
    if (-not (IsValidPath $sqlitePathTextBox.Text "System.Data.SQLite.dll")) {
        Find-sqlite3
    }		
}

function IsValidPath($path, $fileName) {
    if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($fileName)) {
        return $false
    }

    $resolvedPath = $path.Trim().Trim('"')
    if (-not (Test-Path -LiteralPath $resolvedPath -PathType Leaf)) {
        return $false
    }

    $leafName = Split-Path -Path $resolvedPath -Leaf
    if ($fileName -like "*`**" -or $fileName -like "*`?*") {
        return $leafName -like $fileName
    }

    return $leafName -ieq $fileName
}

function UpdateProcessingButtonsStatus() {
    $artifactPathFilled = -not [string]::IsNullOrEmpty($ArtifactProcessingPathTextBox.Text)

    # Function to safely test paths
    function SafeTestPath($path) {
        return -not [string]::IsNullOrEmpty($path) -and (Test-Path $path)
    }

    # Enable or disable buttons based on conditions
    $ProcessBulkExtractorButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $BulkExtractorPathTextBox.Text)
    $ProcessZimmermanButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $ZimmermanPathTextBox.Text)
    $ProcessPlasoButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $PlasoPathTextBox.Text)
    $GeoLocateButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $GeoLite2CityDBPathTextBox.Text)
    $Process7zipButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $SevenzipPathTextBox.Text)
	$ProcessHayabusaButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $HayabusaPathTextBox.Text)
	$ProcessChainsawButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $ChainsawPathTextBox.Text)
	$ProcessZircoliteButton.IsEnabled = $artifactPathFilled -and (SafeTestPath $ZircolitePathTextBox.Text)
	$UpdateZircoliteButton.IsEnabled = SafeTestPath $ZircolitePathTextBox.Text
	$UpdateZimmermanButton.IsEnabled = SafeTestPath $ZimmermanPathTextBox.Text
	$ProcessTimelineArtifactsButton.IsEnabled = SafeTestPath $sqlitePathTextBox.Text
	$ExportTimelineArtifactsButton.IsEnabled = SafeTestPath $sqlitePathTextBox.Text
}

function Find-7zipExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $SevenzipPathTextBox.Text = $7zipPath
}

function Find-BulkExtractorExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $bulkExtractorPath = Get-ChildItem -Path $toolsDirectory -Filter "bulk_extractor64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $BulkExtractorPathTextBox.Text = $bulkExtractorPath
}

function Find-chainsaw {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $chainsawPath = Get-ChildItem -Path $toolsDirectory -Filter "chainsaw*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $ChainsawPathTextBox.Text = $chainsawPath
}

function Find-GeoLite2CityDB {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $GeoLite2CityDBPath = Get-ChildItem -Path $toolsDirectory -Filter "GeoLite2-City.mmdb" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $GeoLite2CityDBPathTextBox.Text = $GeoLite2CityDBPath
}

function Find-hayabusa {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $HayabusaPath = Get-ChildItem -Path $toolsDirectory -Filter "hayabusa*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $HayabusaPathTextBox.Text = $HayabusaPath
}

function Find-Plaso {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $PlasoPath = Get-ChildItem -Path $toolsDirectory -Filter "log2timeline.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $PlasoPathTextBox.Text = $PlasoPath
}

function Find-ZimmermanTools {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $ZimmermanToolsPath = Get-ChildItem -Path $toolsDirectory -Filter "Get-ZimmermanTools.ps1" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $ZimmermanPathTextBox.Text = $ZimmermanToolsPath
}

function Find-Zircolite {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $ZircolitePath = Get-ChildItem -Path $toolsDirectory -Filter "zircolite*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $ZircolitePathTextBox.Text = $ZircolitePath
}

function Find-sqlite3 {
    function SafeTestPath($path) {
        return -not [string]::IsNullOrEmpty($path) -and (Test-Path $path)
    }	
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $sqlitePath = Get-ChildItem -Path $toolsDirectory -Filter "System.Data.SQLite.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $sqlitePathTextBox.Text = $sqlitePath
	$ProcessTimelineArtifactsButton.IsEnabled = SafeTestPath $sqlitePathTextBox.Text
	$ExportTimelineArtifactsButton.IsEnabled = SafeTestPath $sqlitePathTextBox.Text
}

function Check-BulkJobStatus {
    # Initialize the completed job count
    $completedCount = 0

    foreach ($job in $Global:bulkJobs) {
        # Refresh the job state
        $updatedJob = Get-Job -Id $job.JobObject.Id
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Finished Bulk Extractor: $($job.PluginName) for $($job.ArtifactPath)" "ProcessSystemTextBox"
				Write-Host "$timestamp Finished Bulk Extractor: $($job.PluginName) for $($job.ArtifactPath)"
                $job.DataAdded = $true
            }
            $completedCount++
        }
    }

    if ($completedCount -eq $Global:bulkJobs.Count) {
        Update-Log "All BulkExtractor jobs completed." "ProcessSystemTextBox"
        $bulkJobTimer.Stop()
    }
}

function ProcessBulkExtractorButton_Click {
    Update-Log "Starting BulkExtractor..." "ProcessSystemTextBox"
    
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $BulkExtractorPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and bulk extractor executable.")
        return
    }
	
    $ArtifactPath = $ArtifactProcessingPathTextBox.Text
    $BulkExtractorFilePath = $BulkExtractorPathTextBox.Text
	
    Process-BulkExtractor -ArtifactPath $ArtifactPath -BulkExtractorFilePath $BulkExtractorFilePath
    
    # Check if the timer is already running
    if (-not $bulkJobTimer.Enabled) {
        $bulkJobTimer.Start()
    } 
}

function Process-BulkExtractor {
    param (
        [string]$ArtifactPath,
        [string]$BulkExtractorFilePath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    $systemArtifactsDirectory = Join-Path $global:currentcasedirectory "SystemArtifacts"
    $processedArtifactsDirectory = Join-Path $systemArtifactsDirectory "ProcessedArtifacts"
    
    # Extracting only the folder/base file name without extension
    $inputFolderName = [IO.Path]::GetFileNameWithoutExtension($ArtifactPath)
    $bulkExtractorParentDirectory = Join-Path $processedArtifactsDirectory $inputFolderName


    if (-not (Test-Path $bulkExtractorParentDirectory)) {
        $null = New-Item -Path $bulkExtractorParentDirectory -ItemType Directory -Force
    }

	$bulkExtractorDirectory = Join-Path $bulkExtractorParentDirectory "${timestamp}_BulkExtractor"
    
    if (-not (Test-Path $bulkExtractorDirectory)) {
        $null = New-Item -Path $bulkExtractorDirectory -ItemType Directory -Force
    }

    $bulkExtractorCommand = "`"$BulkExtractorFilePath`" -o `"$bulkExtractorDirectory`" -e all `"$ArtifactPath`""

    Write-Host "$timestamp Starting BulkExtractor with command: $bulkExtractorCommand"
    $uniquePluginName = "BulkExtractor_${timestamp}"
	
    $job = Start-Job -ScriptBlock {
        param($BulkExtractorFilePath, $bulkExtractorDirectory, $ArtifactPath)
		$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $arguments = "-o `"$bulkExtractorDirectory`" -e all `"$ArtifactPath`""
        $outputFile = Join-Path $bulkExtractorDirectory "$($timestamp)_bulk_extractor_output.txt"
        $errorFile = Join-Path $bulkExtractorDirectory "$($timestamp)_bulk_extractor_error.txt"
        try {
            Start-Process -FilePath $BulkExtractorFilePath -ArgumentList $arguments -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile -Wait -PassThru
        } catch {
            Write-Host "Error in Bulk Extractor execution: $_"
        }
    } -ArgumentList $BulkExtractorFilePath, $bulkExtractorDirectory, $ArtifactPath

    $Global:bulkJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = "$uniquePluginName"
		ArtifactPath = $ArtifactPath
        DataAdded = $false
        Command = $bulkExtractorCommand 
    }
}

function Check-chainsawJobStatus {	
    $remainingJobs = @()
    foreach ($job in $Global:chainsawjobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        $jobOutput = @(Receive-Job -Id $updatedJob.Id -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        foreach ($line in $jobOutput) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                Update-Log $line "ProcessSystemTextBox"
            }
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    Update-Log "Chainsaw completed: $($job.JobName) (output: $($job.OutputPath))" "ProcessSystemTextBox"
                } else {
                    $failureReason = $null
                    if ($updatedJob.ChildJobs -and $updatedJob.ChildJobs.Count -gt 0) {
                        $failureReason = $updatedJob.ChildJobs[0].JobStateInfo.Reason
                    }
                    if ($failureReason) {
                        Update-Log "Chainsaw failed: $($job.JobName) - $failureReason" "ProcessSystemTextBox"
                    } else {
                        Update-Log "Chainsaw failed: $($job.JobName)" "ProcessSystemTextBox"
                    }
                }
                $job.DataAdded = $true
            }

            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:chainsawjobs = $remainingJobs
    if ($Global:chainsawjobs.Count -eq 0) {
        Update-Log "All Chainsaw processing completed." "ProcessSystemTextBox"
        $chainsawJobTimer.Stop()
    }
}

function ProcessChainsawButton_Click {
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $ChainsawPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and Chainsaw path.")
        return
    }
    Update-Log "Starting Chainsaw..." "ProcessSystemTextBox"
    $inputPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
    $ChainsawPath = $ChainsawPathTextBox.Text.Trim().Trim('"')
    $artifactName = [System.IO.Path]::GetFileNameWithoutExtension($ArtifactProcessingPathTextBox.Text.Trim().Trim('"'))

    # Check if the user wants to use json output or the regex search
    $useJsonOutput = $ChainsawJson.IsChecked
	
    Process-Chainsaw -InputPath $inputPath -ChainsawPath $ChainsawPath -useJsonOutput $useJsonOutput

    if (-not $chainsawJobTimer.Enabled) {
        $chainsawJobTimer.Start()
    }
}

function Process-Chainsaw {
    param (
        [string]$InputPath,
        [string]$ChainsawPath,
        [bool]$useJsonOutput
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
	$chainsawDirectory = [System.IO.Path]::GetDirectoryName($ChainsawPath)
    if (-not (Test-Path -LiteralPath $InputPath -ErrorAction SilentlyContinue)) {
        Update-Log "Chainsaw input path does not exist: $InputPath" "ProcessSystemTextBox"
        return
    }
    if (-not (Test-Path -LiteralPath $ChainsawPath -PathType Leaf -ErrorAction SilentlyContinue)) {
        Update-Log "Chainsaw executable path does not exist: $ChainsawPath" "ProcessSystemTextBox"
        return
    }
	# Determine artifactName based on whether InputPath is a root directory or a specific file/folder
	if (([System.IO.Path]::GetPathRoot($InputPath)).TrimEnd('\') -eq $InputPath.TrimEnd('\')) {
		# InputPath is a root directory, so use a modified naming convention
		$artifactName = "Root_" + $InputPath.Trim(':\\') + "_Drive"
	} else {
		$artifactName = [System.IO.Path]::GetFileNameWithoutExtension($InputPath)
	}
	
    $outputBaseFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Chainsaw'
    $ChainsawParentFolder = Split-Path $ChainsawPath -Parent	
    if (-not (Test-Path $outputBaseFolder)) {
        $null = New-Item -Path $outputBaseFolder -ItemType Directory -Force
    }
	$outputPath = Join-Path $outputBaseFolder "${timestamp}_$artifactName"
    if (-not (Test-Path -LiteralPath $outputPath)) {
        $null = New-Item -Path $outputPath -ItemType Directory -Force
    }
	$jsonoutputPath = Join-Path $outputPath "${artifactName}.json"
	
    $sigmaPath = Join-Path $ChainsawParentFolder "sigma"
    $mappingPath = Join-Path $ChainsawParentFolder "mappings\sigma-event-logs-all.yml"
    $rulesPath = Join-Path $ChainsawParentFolder "rules"
    $chainsawArguments = @("hunt", $InputPath, "-s", $sigmaPath, "--mapping", $mappingPath, "-r", $rulesPath, "--skip-errors", "-o")
	
		
    if ($useJsonOutput) {
        $chainsawArguments += @($jsonoutputPath, "--json")
    } else {
		$chainsawArguments += @($outputPath, "--csv")
	}
	
    $chainsawCommandPreview = "& `"$ChainsawPath`" " + (($chainsawArguments | ForEach-Object { "`"$_`"" }) -join " ")
    Update-Log "chainsawCommand is $chainsawCommandPreview" "ProcessSystemTextBox"
    $job = Start-Job -ScriptBlock {
        param($chainsawPath, $chainsawArguments, $chainsawDirectory, $outputPath, $useJsonOutput)
        try {
            Write-Output ("Starting Chainsaw job in {0}" -f $chainsawDirectory)
            Set-Location -Path $chainsawDirectory

            $runStamp = Get-Date -Format "yyyyMMdd_HHmmss"
            $stdoutPath = Join-Path $outputPath "${runStamp}_chainsaw_stdout.txt"
            $stderrPath = Join-Path $outputPath "${runStamp}_chainsaw_stderr.txt"

            $proc = Start-Process -FilePath $chainsawPath -ArgumentList $chainsawArguments -NoNewWindow -Wait -PassThru -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath
            if ($proc.ExitCode -ne 0) {
                $stderrText = ""
                if (Test-Path -LiteralPath $stderrPath) {
                    $stderrText = (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue).Trim()
                }
                throw ("Chainsaw exited with code {0}. {1}" -f $proc.ExitCode, $stderrText)
            }

            $producedArtifacts = Get-ChildItem -Path $outputPath -File -ErrorAction SilentlyContinue | Where-Object {
                $_.Name -notlike "*_chainsaw_stdout.txt" -and $_.Name -notlike "*_chainsaw_stderr.txt"
            }
            if (-not $producedArtifacts -or $producedArtifacts.Count -eq 0) {
                Write-Output "Chainsaw finished with no result artifacts produced. Verify input contains supported logs."
            } else {
                Write-Output ("Chainsaw produced {0} artifact file(s) in {1}" -f $producedArtifacts.Count, $outputPath)
            }
        } catch {
            Write-Output ("Chainsaw execution failed: {0}" -f $_.Exception.Message)
            throw
        }
    } -ArgumentList ($ChainsawPath, $chainsawArguments, $chainsawDirectory, $outputPath, $useJsonOutput)

    $Global:chainsawjobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "chainsaw_$timestamp"
        ArtifactPath = $InputPath
        OutputPath = $outputPath
        DataAdded = $false
    }

    Update-Log "Chainsaw job started for $InputPath." "ProcessSystemTextBox"
}

function Check-PlasoProcessingStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:plasolocateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Plaso Timeline completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Plaso Timeline completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:plasolocateJobs.Count) {
        Update-Log "All Plaso processing completed." "ProcessSystemTextBox"
        $plasoProcessingTimer.Stop()
    }
}

function ProcessPlasoButton_Click {
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $PlasoPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and log2timeline.py path.")
        return
    }

    # Check for Python installation
    $pythonCheck = & python --version 2>&1
    if ($pythonCheck -like "*not recognized as*") {
        [System.Windows.MessageBox]::Show("Python is not installed. Please install Python and try again.")
        return
    }

    Update-Log "Starting Plaso..." "ProcessSystemTextBox"
    $inputPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
    $PlasoPath = $PlasoPathTextBox.Text.Trim().Trim('"')
    $artifactName = [System.IO.Path]::GetFileNameWithoutExtension($ArtifactProcessingPathTextBox.Text.Trim().Trim('"'))
    $outputDirectoryName = "${artifactName}_plaso"
    # Check if the user wants to use a custom date range or psort only
    $useCustomDateRange = $PlasoDateRangeCheckBox.IsChecked
    $usePsortOnly = $PsortOnlyCheckBox.IsChecked
    $startDate = $null
    $endDate = $null

    if ($useCustomDateRange -eq $true) {
        $startDate = $PlasoStartDatePicker.SelectedDate
        $endDate = $PlasoEndDatePicker.SelectedDate

        # Validate date range
        if ($startDate -and $endDate -and $startDate -gt $endDate) {
            [System.Windows.MessageBox]::Show("Start Date must be before End Date.")
            return
        }
    }

    # Check if the psort only checkbox is selected and if so, validate the input file
    if ($usePsortOnly -eq $true -and -not ($inputPath -match '\.plaso$')) {
        [System.Windows.MessageBox]::Show("The selected file for Psort processing does not appear to be a Plaso storage file (.plaso).")
        return
    }

    Process-Plaso -InputPath $inputPath -PlasoPath $PlasoPath -OutputDirectoryName $outputDirectoryName -StartDate $startDate -EndDate $endDate -UsePsortOnly $usePsortOnly

    if (-not $plasoProcessingTimer.Enabled) {
        $plasoProcessingTimer.Start()
    }
}

function Process-Plaso {
    param (
        [string]$InputPath,
        [string]$PlasoPath,
        [string]$OutputDirectoryName,
        [Nullable[DateTime]]$StartDate,
        [Nullable[DateTime]]$EndDate,
        [bool]$UsePsortOnly
    )

    $pythonInstalled = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonInstalled) {
        Write-Warning "Python not found. Please install Python and try again."
        return
    }

	#try to find psort.py in the same directory as log2timeline.py
	$psortPath = Get-ChildItem -Path (Split-Path $PlasoPath) -Filter "psort.py" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	if (-not $psortPath) {
		Write-Warning "psort.py not found in the same directory as log2timeline.py. Please ensure both are available."
		return
	}

	Write-Host "psort path is $psortPath"
    # If using psort only, check if the input file is a Plaso storage file
    if ($UsePsortOnly) {
        if (-not ($InputPath -match '\.plaso$')) {
            Write-Warning "The input file does not appear to be a Plaso storage file. Please provide a valid .plaso file."
            return
        }
    }

    # Create output directory
    $systemArtifactsDirectory = Join-Path $global:currentcasedirectory "SystemArtifacts"
    $processedArtifactsDirectory = Join-Path $systemArtifactsDirectory "ProcessedArtifacts"
    $userOutputDirectory = Join-Path $processedArtifactsDirectory $OutputDirectoryName

    if (-not (Test-Path $userOutputDirectory)) {
        $null = New-Item -Path $userOutputDirectory -ItemType Directory -Force
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $outputPlasoFile = Join-Path $userOutputDirectory "${timestamp}_output.plaso"
    $outputXLSXFile = Join-Path $userOutputDirectory "${timestamp}_super_timeline.xlsx"  
    $outputFilePath = Join-Path $userOutputDirectory "${timestamp}_plaso_output.txt"
    $errorFilePath = Join-Path $userOutputDirectory "${timestamp}_plaso_error.txt"


	# For log2timeline, specify the output storage file (.plaso) with the --storage_file argument
	$plasoArguments = @("--storage_file", "`"$outputPlasoFile`"", "`"$InputPath`"")
	
    # Construct the filter string based on provided start and/or end dates
    $filterString = $null
    if ($StartDate -and $EndDate) {
        $filterString = "date >= '" + (Get-Date $StartDate -Format "s") + "' and date <= '" + (Get-Date $EndDate -Format "s") + "'"
    } elseif ($StartDate) {
        $filterString = "date >= '" + (Get-Date $StartDate -Format "s") + "'"
    } elseif ($EndDate) {
        $filterString = "date <= '" + (Get-Date $EndDate -Format "s") + "'"
    }

	# For psort, specify the .plaso file and construct the command with correct arguments
	$psortArguments = @("-o", "xlsx", "-w", "`"$outputXLSXFile`"")
	
	# Add the input path to the psort arguments after potentially adding the filter string
	$psortArguments += "`"$InputPath`""

	# Now pass the correct set of arguments to Start-Job based on the condition
	$argumentsToUse = if ($UsePsortOnly) { $psortArguments } else { $plasoArguments }
	$filePathToUse = if ($UsePsortOnly) { $psortPath } else { $PlasoPath }

	Write-Host "plaso argments are $plasoArguments"
	Write-Host "psort armuments are $psortArguments"
	# Start the Plaso processing job
	$job = Start-Job -ScriptBlock {
		param($UsePsortOnly, $PlasoArguments, $PsortArguments, $outputFilePath, $errorFilePath, $PlasoPath, $psortPath, $outputPlasoFile, $filterString)
		
		if (-not $UsePsortOnly) {
			# Run log2timeline.py
			$log2timelineCommand = "python `"$PlasoPath`" " + ($PlasoArguments -join ' ') + " 2>`"$errorFilePath`" >`"$outputFilePath`""
			Invoke-Expression $log2timelineCommand
		
			# Wait for log2timeline.py to complete
			while (Get-Job -Name $JobName -State "Running") {
				Start-Sleep -Seconds 5
			}
		
			# Set the input path for psort to the output of log2timeline
			$PsortArguments[-1] = "`"$outputPlasoFile`""
		}
		
		# If a filter string is provided, append it to the psort arguments
		if ($filterString) {
			$PsortArguments += "`"$filterString`""
		}
		# Now, run psort.py whether we have just created a Plaso file or are using an existing one
		$psortCommand = "python `"$psortPath`" " + ($PsortArguments -join ' ') + " 2>>`"$errorFilePath`" >>`"$outputFilePath`""
		Write-Host "psort command is $psortCommand"
		Invoke-Expression $psortCommand
		
	} -ArgumentList ($UsePsortOnly, $plasoArguments, $psortArguments, $outputFilePath, $errorFilePath, $PlasoPath, $psortPath, $outputPlasoFile, $filterString)

	

    $Global:plasolocateJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "ProcessPlaso_$timestamp"
        ArtifactPath = $InputPath
        DataAdded = $false
    }

    Update-Log "Plaso parsing job started for $InputPath." "ProcessSystemTextBox"
}

function Check-HyabusaProcessingStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:hayabusalocateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Hayabusa Timeline completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Hayabusa Timeline completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:hayabusalocateJobs.Count) {
        Update-Log "All hayabusa processing completed." "ProcessSystemTextBox"
        $HyabusaProcessingTimer.Stop()
    }
}

function ProcessHayabusaButton_Click {
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $HayabusaPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and Hayabusa path.")
        return
    }
    Update-Log "Starting Hayabusa..." "ProcessSystemTextBox"
    $inputPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
    $HayabusaPath = $HayabusaPathTextBox.Text.Trim().Trim('"')
    $artifactName = [System.IO.Path]::GetFileNameWithoutExtension($ArtifactProcessingPathTextBox.Text.Trim().Trim('"'))

    # Check if the user wants to use a custom date range or psort only
    $useCustomDateRange = $HayabusaDateRangeCheckBox.IsChecked
    $useGeoDB = $HayabusaGeoDBCheckBox.IsChecked
	
    $startDate = $null
    $endDate = $null

    if ($useCustomDateRange -eq $true) {
        $startDate = $HayabusaStartDatePicker.SelectedDate
        $endDate = $HayabusaEndDatePicker.SelectedDate

        # Validate date range
        if ($startDate -and $endDate -and $startDate -gt $endDate) {
            [System.Windows.MessageBox]::Show("Start Date must be before End Date.")
            return
        }
    }

	if ($useGeoDB) {
		$GeoDBPath = Test-GeoLite2DBs
		if (-not $GeoDBPath) {
			Update-Log "All three GeoLite2 databases (City, ASN, Country) were not found in the Tools directory. They are required for the GeoDB option and can be downloaded from the Tool Management tab with a valid key." "ProcessSystemTextBox"
			return
		}
	}
	
    Process-Hyabusa -InputPath $inputPath -HayabusaPath $HayabusaPath -StartDate $startDate -EndDate $endDate -useGeoDB $useGeoDB -GeoDBPath $GeoDBPath

    if (-not $HyabusaProcessingTimer.Enabled) {
        $HyabusaProcessingTimer.Start()
    }
}

function Process-Hyabusa {
    param (
        [string]$InputPath,
        [string]$HayabusaPath,
        [Nullable[DateTime]]$StartDate,
        [Nullable[DateTime]]$EndDate,
        [bool]$useGeoDB,
        [string]$GeoDBPath
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $HayabusaCSVName = "${timestamp}_${artifactName}_hayabusa.csv"
    $outputBaseFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Hayabusa'
    
    if (-not (Test-Path $outputBaseFolder)) {
        $null = New-Item -Path $outputBaseFolder -ItemType Directory -Force
    }
    $outputPath = Join-Path $outputBaseFolder $HayabusaCSVName
    $hyabusaArguments = @("csv-timeline")
    if (Test-Path $InputPath -PathType Container) {
        $hyabusaArguments += ("-d", "`"$InputPath`"", "--RFC-3339", "-o", "`"$OutputPath`"", "-p", "timesketch-verbose", "-U", "-Q", "-w")
    } else {
        $hyabusaArguments += ("-f", "`"$InputPath`"", "--RFC-3339", "-o", "`"$OutputPath`"", "-p", "timesketch-verbose", "-U", "-Q", "-w")
    }

    if ($useGeoDB) {
        $hyabusaArguments += ("-G", "`"$GeoDBPath`"")
    }

    # Construct the filter string based on provided start and/or end dates
    $filterString = $null
    if ($StartDate -and $EndDate) {
        $startDateFormatted = (Get-Date $StartDate -Format "yyyy-MM-dd HH:mm:ss +00:00")
        $endDateFormatted = (Get-Date $EndDate -Format "yyyy-MM-dd HH:mm:ss +00:00")
        $filterString = "--timeline-start `"$startDateFormatted`" --timeline-end `"$endDateFormatted`""
    } elseif ($StartDate) {
        $startDateFormatted = (Get-Date $StartDate -Format "yyyy-MM-dd HH:mm:ss +00:00")
        $filterString = "--timeline-start `"$startDateFormatted`""
    } elseif ($EndDate) {
        $endDateFormatted = (Get-Date $EndDate -Format "yyyy-MM-dd HH:mm:ss +00:00")
        $filterString = "--timeline-end `"$endDateFormatted`""
    }

    if ($filterString) {
        $hyabusaArguments += $filterString
    }

    $hyabusaCommand = "& `"$HayabusaPath`" $hyabusaArguments"
    Update-Log "hyabusaCommand is $hyabusaCommand" "ProcessSystemTextBox"
    $job = Start-Job -ScriptBlock {
        param($hyabusaCommand)
        
        Invoke-Expression $hyabusaCommand
        
    } -ArgumentList ($hyabusaCommand)

    $Global:hayabusalocateJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "hyabusa_$timestamp"
        ArtifactPath = $InputPath
        DataAdded = $false
    }

    Update-Log "Hyabusa parsing job started for $InputPath." "ProcessSystemTextBox"
}

function Check-ExtractArchivesJobStatus {
	# Initialize the completed job count
    $completedCount = 0
    foreach ($job in $Global:extractArchivesJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
			if (-not $job.DataAdded) {
			$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
            Update-Log "Finished extracting archives for job: $($job.JobName) in $($job.TargetDirectory)" "ProcessSystemTextBox"
			Write-Host "$timestamp Finished extracting archives for job: $($job.JobName) in $($job.TargetDirectory)" "ProcessSystemTextBox"
			$job.DataAdded = $true
        }
		$completedCount++
		}
	}

    if ($completedCount -eq $Global:extractArchivesJobs.Count) {
        Update-Log "All 7zip extraction jobs completed." "ProcessSystemTextBox"
        $extractArchivesTimer.Stop()
    }
}

function ExtractArchives_Click {   
    $inputPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
    $PathTo7zExe = $SevenzipPathTextBox.Text.Trim().Trim('"')

    if (-not $inputPath) {
        [System.Windows.MessageBox]::Show("Please select a file or folder path for extraction.")
        return
    }

    if (-not $PathTo7zExe) {
        [System.Windows.MessageBox]::Show("Please select the 7zip executable.")
        return
    }
    Update-Log "Starting 7zip Extraction..." "ProcessSystemTextBox"
    # Directly pass the input path (file or directory) to the Extract-Archives function
    Extract-Archives -InputPath $inputPath -SevenZipPath $PathTo7zExe
	
    # Check if the timer is already running
    if (-not $extractArchivesTimer.Enabled) {
        $extractArchivesTimer.Start()
    }
}

function Extract-Archives {
    param (
        [string]$InputPath,  # Can be either a file or directory
        [string]$SevenZipPath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $uniqueJobName = "7zExtraction_${timestamp}"
    $systemArtifactsDirectory = Join-Path $global:currentcasedirectory "SystemArtifacts\ProcessedArtifacts"

    $job = Start-Job -ScriptBlock {
        param($InputPath, $SevenZipPath, $systemArtifactsDirectory)
        $previousArchives = @{}
		$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
		$outputFile = Join-Path $systemArtifactsDirectory "$($timestamp)_archive_extractor_output.txt"
        $errorFile = Join-Path $systemArtifactsDirectory "$($timestamp)_archive_extractor_error.txt"

        # Determine if the input is a file or directory
        $isFile = Test-Path $InputPath -PathType Leaf

        do {
            # If it's a file, process only that file; otherwise, find archives in the directory
            $archives = if ($isFile) { Get-Item $InputPath } else { Get-ChildItem $InputPath -Recurse | Where-Object { $_.Extension -match "^\.7z$|^\.zip$|^\.rar$|^\.tar$|^\.gz$" } }
            $newArchives = $archives | Where-Object { !$previousArchives.ContainsKey($_.FullName) }

            if ($newArchives) {
                $newArchives | ForEach-Object {
                    try {
                        $containingFolderName = if ($isFile) { [IO.Path]::GetFileNameWithoutExtension($InputPath) } else { Split-Path $_.DirectoryName -Leaf }
                        $archiveOutputDir = Join-Path $systemArtifactsDirectory unarchived_$containingFolderName
                        if (-not (Test-Path $archiveOutputDir)) {
                            New-Item -Path $archiveOutputDir -ItemType Directory | Out-Null
                        }

                        $arguments = "x `"$($_.FullName)`" -o`"$archiveOutputDir`" -aos"
                        Start-Process -FilePath $SevenZipPath -ArgumentList $arguments -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile -Wait -PassThru
                        Write-Output "Extracted archive: $($_.FullName) to $archiveOutputDir"
                        $previousArchives[$_.FullName] = $true
                    } catch {
                        Write-Output "Error extracting archive: $($_.FullName)"
                        Write-Output "Error detail: $($_.Exception.Message)"
                    }
                }
            }

            # If processing a single file, break the loop after the first iteration
            if ($isFile) { break }
        } while ($newArchives)
    } -ArgumentList $InputPath, $SevenZipPath, $systemArtifactsDirectory

    $Global:extractArchivesJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = $uniqueJobName
		DataAdded = $false
        TargetDirectory = if (Test-Path $InputPath -PathType Leaf) { Split-Path $InputPath } else { $InputPath }
    }
}

function Check-GeoLocateProcessingStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:geolocateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Geolocation completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Finished Geolocation completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:geolocateJobs.Count) {
        Update-Log "All GeoLocation processing completed." "ProcessSystemTextBox"
        $geolocateProcessingTimer.Stop()
    }
}

function Test-GeoLite2DBs {
    $toolsDirectory = Join-Path $executableDirectory "Tools"
    $geoDBFiles = @("GeoLite2-City.mmdb", "GeoLite2-ASN.mmdb", "GeoLite2-Country.mmdb")
    $allFilesExist = $true

    foreach ($file in $geoDBFiles) {
        $foundFiles = Get-ChildItem -Path $toolsDirectory -Filter $file -Recurse -ErrorAction SilentlyContinue
        if ($foundFiles.Count -eq 0) {
            $allFilesExist = $false
            break
        }
    }

    if ($allFilesExist) {
        # Return the directory path of the first file, assuming all files are in the same directory
        return Split-Path (Get-ChildItem -Path $toolsDirectory -Filter $geoDBFiles[0] -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1)
    } else {
        return $null
    }
}

function GeoLocateButton_Click {
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $GeoLite2CityDBPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and GeoLite2-City.mmdb.")
        return
    }

    # Check for Python and necessary modules
    $pythonCheck = & python --version 2>&1
    $geoip2Check = & python -c "import geoip2.database" 2>&1
    $requestsCheck = & python -c "import requests" 2>&1

    # Function to prompt for module installation
    function Prompt-For-Module-Installation($moduleName) {
        $message = "Python and the $moduleName module are required for this operation. Do you want to install $moduleName now?"
        $caption = "Dependency Required"
        $buttons = [System.Windows.MessageBoxButton]::YesNo
        $icon = [System.Windows.MessageBoxImage]::Question
        $result = [System.Windows.MessageBox]::Show($message, $caption, $buttons, $icon)
        
        if ($result -eq "Yes") {
            & pip install $moduleName
        } else {
            Update-Log "$moduleName module installation aborted. $moduleName is required for this feature." "ProcessSystemTextBox"
            return $false
        }
        return $true
    }

    if ($geoip2Check -like "*ModuleNotFoundError: No module named 'geoip2'*") {
        if (-not (Prompt-For-Module-Installation 'geoip2')) { return }
    } elseif ($geoip2Check -like "*Error*") {
        Update-Log "An error occurred checking Python dependencies for geoip2." "ProcessSystemTextBox"
        return
    }

    if ($requestsCheck -like "*ModuleNotFoundError: No module named 'requests'*") {
        if (-not (Prompt-For-Module-Installation 'requests')) { return }
    } elseif ($requestsCheck -like "*Error*") {
        Update-Log "An error occurred checking Python dependencies for requests." "ProcessSystemTextBox"
        return
    }

    Update-Log "Starting IP Address Geolocation..." "ProcessSystemTextBox"
    $ArtifactPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
    $GeoLite2CityDBPath = $GeoLite2CityDBPathTextBox.Text.Trim().Trim('"')
	
	write-host "artifact path is $ArtifactPath"
     # Verify if the ArtifactPath points to a text file
    if (-not (Test-Path -Path $ArtifactPath -PathType Leaf)) {
        [System.Windows.MessageBox]::Show("The selected artifact path must be a file containing IP addresses and not a folder.")
        return
    }

    # Check if the VirusTotal checkbox is checked
    if ($CheckVirusTotal.IsChecked -eq $true) {
        # Create a new form for secure API key input
        $apiKeyForm = New-Object System.Windows.Forms.Form
        $apiKeyForm.Text = 'Enter VirusTotal API Key'
        $apiKeyForm.Size = New-Object System.Drawing.Size(500, 200)
        $apiKeyForm.StartPosition = 'CenterScreen'

        # Add note about rate limit
        $noteLabel = New-Object System.Windows.Forms.Label
        $noteLabel.Text = "Public keys are limited to 4 lookups per minute."
        $noteLabel.Location = New-Object System.Drawing.Point(10, 10)
        $noteLabel.Size = New-Object System.Drawing.Size(480, 20)
        $apiKeyForm.Controls.Add($noteLabel)

        # Add password box
        $apiKeyBox = New-Object System.Windows.Forms.TextBox
        $apiKeyBox.UseSystemPasswordChar = $true
        $apiKeyBox.Location = New-Object System.Drawing.Point(10, 50)
        $apiKeyBox.Size = New-Object System.Drawing.Size(400, 20)
        $apiKeyForm.Controls.Add($apiKeyBox)

        # Add OK button
        $okButton = New-Object System.Windows.Forms.Button
        $okButton.Text = 'OK'
        $okButton.Location = New-Object System.Drawing.Point(190, 80)
        $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
        $apiKeyForm.AcceptButton = $okButton
        $apiKeyForm.Controls.Add($okButton)

        # Show API key input form as a dialog
        $result = $apiKeyForm.ShowDialog()

        if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $apiKeyBox.Text) {
            # If the user entered a key and pressed OK, proceed with the GeoLocate function
            GeoLocate-IPs -ArtifactPath $ArtifactPath -GeoLite2CityDBPath $GeoLite2CityDBPath -UseVirusTotal $true -VirusTotalApiKey $apiKeyBox.Text
        } else {
            # If the user canceled or did not enter a key, do not proceed with VirusTotal lookup
            GeoLocate-IPs -ArtifactPath $ArtifactPath -GeoLite2CityDBPath $GeoLite2CityDBPath -UseVirusTotal $false
        }
    } else {
        # If the VirusTotal checkbox is not checked, proceed without VirusTotal lookup
        GeoLocate-IPs -ArtifactPath $ArtifactPath -GeoLite2CityDBPath $GeoLite2CityDBPath -UseVirusTotal $false
    }

    # Start the timer
    if (-not $geolocateProcessingTimer.Enabled) {
        $geolocateProcessingTimer.Start()
    }
}

function GeoLocate-IPs {
		param (
		[string]$ArtifactPath,
        [string]$GeoLite2CityDBPath,
        [bool]$UseVirusTotal,
        [string]$VirusTotalApiKey
    )
	
	$systemArtifactsDirectory = Join-Path $global:currentcasedirectory "SystemArtifacts"
    $processedArtifactsDirectory = Join-Path $systemArtifactsDirectory "ProcessedArtifacts"
    $outputFolderPath = Join-Path $processedArtifactsDirectory "ResolvedIPs"
    
    if (-not (Test-Path $outputFolderPath)) {
        $null = New-Item -Path $outputFolderPath -ItemType Directory -Force
    }

    $outputFilePath = Join-Path $outputFolderPath ((Get-Date -Format "yyyyMMdd_HHmmss") + "_geolocated_ips.csv")

    # Get unique, non-private IP addresses from the file
		
    # Ensure the necessary Python package is installed
    if (!(pip list | Select-String "geoip2")) {
        $confirmation = Read-Host "GeoIP2 Python package is required but not installed. Do you want to install it now? (y/n)"
        if ($confirmation -eq 'y') {
            pip install geoip2
        } else {
            Show-ArtifactMenu
            return
        }
    }
	
	Write-Host "artifact path is $ArtifactPath"

# GeoLocate IPs using GeoIP2 in Python
$pythonScript = @"
import csv
import geoip2.database
import sys
import requests
import time
from datetime import datetime

VT_API_KEY = sys.argv[4] if len(sys.argv) > 4 else None  # Adjust the index based on the arguments
VT_URL = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
RATE_LIMIT_DELAY = 15  # Delay in seconds (4 requests per minute would be a 15-second delay)

def vt_lookup(ip, retries=0, max_retries=5):
    if VT_API_KEY:
        headers = {
            ""x-apikey"": VT_API_KEY
        }
        url = f""https://www.virustotal.com/api/v3/ip_addresses/{ip}""
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            vt_data = response.json()
            attributes = vt_data['data']['attributes']
            last_analysis_stats = attributes['last_analysis_stats']

            # Convert last_analysis_date to human-readable format
            last_analysis_date = attributes.get('last_analysis_date')
            if last_analysis_date:
                formatted_date = datetime.utcfromtimestamp(last_analysis_date).strftime('%Y-%m-%d %H:%M:%S')
            else:
                formatted_date = 'N/A'
				
            # Count the occurrences of each category
            category_counts = {}
            for engine_name, analysis_result in attributes.get('last_analysis_results', {}).items():
                category = analysis_result.get('category')
                if category:
                    category_counts[category] = category_counts.get(category, 0) + 1

            # Format categories with counts
            formatted_categories = [f""{cat} ({count})"" for cat, count in category_counts.items()]

            return {
                'VT Last Analysis Date': formatted_date,
                'VT Categories': ', '.join(formatted_categories),
				'VT ASN': attributes.get('asn', 'Unknown'),
				'VT Country': attributes.get('country', 'Unknown'),
				'AS Owner': attributes.get('as_owner', 'Unknown'),
                'VT Whois': attributes.get('whois', 'Unknown')

            }
        elif response.status_code == 429:
            if retries < max_retries:
                time.sleep(RATE_LIMIT_DELAY)
                return vt_lookup(ip, retries=retries+1, max_retries=max_retries)
            else:
                print(f""Rate limited. Maximum retries reached for IP: {ip}"")
    # If the request fails for any reason, or if rate limit is reached, return default values
    return {
        'VT Last Analysis Date': 'N/A',
        'VT Categories': 'N/A',
        'VT ASN': 'N/A',
		'VT Country': 'N/A',
        'AS Owner': 'N/A',
		'VT Whois': 'N/A'
    }

		
def lookup_ip(ip, reader):
    try:
        response = reader.city(ip)
        return {
            'IP': ip,
            'Continent': response.continent.name,
            'Country': response.country.name,
            'Country ISO Code': response.country.iso_code,
            'Subdivision Name': response.subdivisions.most_specific.name,
            'Subdivision ISO Code': response.subdivisions.most_specific.iso_code,
            'City': response.city.name,
            'Postal Code': response.postal.code,
            'Latitude': response.location.latitude,
            'Longitude': response.location.longitude,
            'Metro Code': response.location.metro_code
        }
    except:
        return {
            'IP': ip,
            'Continent': 'Unknown',
            'Country': 'Unknown',
            'Country ISO Code': 'Unknown',
            'Subdivision Name': 'Unknown',
            'Subdivision ISO Code': 'Unknown',
            'City': 'Unknown',
            'Postal Code': 'Unknown',
            'Latitude': 'Unknown',
            'Longitude': 'Unknown',
            'Metro Code': 'Unknown'
        }

dbPath = sys.argv[1]
ipList = sys.argv[2].split(',')
outputFilePath = sys.argv[3]

with geoip2.database.Reader(dbPath) as reader:
    with open(outputFilePath, 'w', newline='', encoding='utf-8') as f_out:
        # Add VT-related fields only if VT_API_KEY is provided
        fieldnames = [
            'IP', 'Continent', 'Country', 'Country ISO Code', 'Subdivision Name', 
            'Subdivision ISO Code', 'City', 'Postal Code', 'Latitude', 'Longitude', 
            'Metro Code'
        ]
        
        if VT_API_KEY:
            fieldnames.extend([
                'VT Last Analysis Date', 'VT Categories', 'VT ASN', 'VT Country', 'AS Owner', 'VT Whois'
            ])

        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for ip in ipList:
            ip_data = lookup_ip(ip, reader)
            if VT_API_KEY:
                vt_data = vt_lookup(ip)
                ip_data.update(vt_data)
            writer.writerow(ip_data)
"@

	$job = Start-Job -ScriptBlock {
		param($GeoLite2CityDBPath, $outputFilePath, $pythonScript, $ArtifactPath, $outputFolderPath, $VirusTotalApiKey)
		$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
		$outputFile = Join-Path $outputFolderPath "$($timestamp)_GeoIP_parser_output.txt"
		$errorFile = Join-Path $outputFolderPath "$($timestamp)_IP_parser_error.txt"
		$pythonCommand = "python"
		# Load IPs from file inside the job
		$ipv4Pattern = '(?<![\\\/\.\d])\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b(?![\.\d])'
		$ipv6Pattern = '\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}(?::[A-Fa-f0-9]{1,4}){1,7}\b'
		# Private IP ranges for IPv4 and IPv6
		$privateIPRanges = "^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
						"^172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}$",
						"^192\.168\.\d{1,3}\.\d{1,3}$",
						"^169\.254\.\d{1,3}\.\d{1,3}$",
						"^224\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
						"^239\.\d{1,3}\.\d{1,3}\.\d{1,3}$",
						"^fc00:[0-9a-fA-F:]*$",
						"^fd[0-9a-fA-F]{2}:[0-9a-fA-F:]*$",
						"^fe80:[0-9a-fA-F:]*$",
						"^ff00:[0-9a-fA-F:]*$",
						"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})"


		$fileContent = Get-Content -Path $ArtifactPath
	
		# Extract all IP addresses from the file content
		$allIPs = @($fileContent | Select-String -Pattern $ipv4Pattern -AllMatches).Matches.Value + 
				@($fileContent | Select-String -Pattern $ipv6Pattern -AllMatches).Matches.Value
	
		# Unique the IP addresses
		$uniqueIPs = $allIPs | Sort-Object -Unique
	
		# Filter out private IP ranges
		$ipList = $uniqueIPs | Where-Object {
			$ip = $_
			$isPrivate = $false
			foreach ($range in $privateIPRanges) {
				if ($ip -match $range) {
					$isPrivate = $true
					break
				}
			}
			-not $isPrivate
		}

		$ipListString = $ipList -join ','
		$pythonArguments = "-c `"$pythonScript`" `"$GeoLite2CityDBPath`" `"$ipListString`" `"$outputFilePath`""
		if ($VirusTotalApiKey) {
			$pythonArguments += " `"$VirusTotalApiKey`""
		}
	
		try {
			Start-Process -FilePath "python" -ArgumentList $pythonArguments -NoNewWindow -RedirectStandardOutput $outputFile -RedirectStandardError $errorFile -PassThru
		} catch {
			Write-Host "Error in GeoDB execution: $_"
		}
	} -ArgumentList $GeoLite2CityDBPath, $outputFilePath, $pythonScript, $ArtifactPath, $outputFolderPath, $VirusTotalApiKey
		

    $Global:geolocateJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "GeoLocateIPs_$(Get-Date -Format "yyyyMMdd_HHmmss")"
        ArtifactPath = $ArtifactPath
        DataAdded = $false
    }	
	Update-Log "IP Geolocation complete. Results saved to $outputFilePath." "ProcessSystemTextBox"

}

function Get-ZimmermanActiveModuleSummary {
    $running = @()
    foreach ($job in $Global:zimmermanJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if ($updatedJob -and ($updatedJob.State -eq "Running" -or $updatedJob.State -eq "NotStarted")) {
            $running += $job.ModuleName
        }
    }

    $queued = @()
    foreach ($pending in $Global:zimmermanPendingJobs) {
        if ($pending -and $pending.ModuleName) {
            $queued += $pending.ModuleName
        }
    }

    $running = @($running | Select-Object -Unique)
    $queued = @($queued | Select-Object -Unique)

    $runningText = if ($running.Count -gt 0) { $running -join ", " } else { "none" }
    $queuedText = if ($queued.Count -gt 0) { $queued -join ", " } else { "none" }
    return ("Zimmerman status: running [{0}] | queued [{1}]" -f $runningText, $queuedText)
}

function Start-NextZimmermanJobs {
    if (-not $Global:zimmermanPendingJobs) {
        return
    }

    $runningCount = 0
    foreach ($existingJob in $Global:zimmermanJobs) {
        $updatedJob = Get-Job -Id $existingJob.JobObject.Id -ErrorAction SilentlyContinue
        if ($updatedJob -and ($updatedJob.State -eq "Running" -or $updatedJob.State -eq "NotStarted")) {
            $runningCount++
        }
    }

    while ($runningCount -lt $Global:zimmermanMaxParallel -and $Global:zimmermanPendingJobs.Count -gt 0) {
        $next = $Global:zimmermanPendingJobs[0]
        if ($Global:zimmermanPendingJobs.Count -gt 1) {
            $Global:zimmermanPendingJobs = @($Global:zimmermanPendingJobs[1..($Global:zimmermanPendingJobs.Count - 1)])
        } else {
            $Global:zimmermanPendingJobs = @()
        }

        $job = Start-Job -ScriptBlock {
            param($moduleName, $moduleFilePath, $moduleArguments, $outputFolderPath)
            try {
                Write-Output ("Starting Zimmerman module: {0}" -f $moduleName)

                if (-not (Test-Path -LiteralPath $moduleFilePath -ErrorAction SilentlyContinue)) {
                    throw "Executable not found: $moduleFilePath"
                }

                $debugPath = Join-Path $outputFolderPath "debug.txt"
                $outputFile = Join-Path $outputFolderPath "ztools_output.txt"
                $command = "& `"$moduleFilePath`" $moduleArguments"
                Add-Content -Path $debugPath -Value ("Executing command: {0}" -f $command)

                $output = Invoke-Expression $command 2>&1 | Out-String
                if (-not [string]::IsNullOrWhiteSpace($output)) {
                    Add-Content -Path $outputFile -Value ("`r`n--- {0} ---`r`n{1}" -f $moduleName, $output)
                }

                Write-Output ("Finished Zimmerman module: {0}. OutputPath: {1}" -f $moduleName, $outputFolderPath)
            } catch {
                Write-Output ("Failed Zimmerman module: {0}. Error: {1}" -f $moduleName, $_.Exception.Message)
                throw
            }
        } -ArgumentList $next.ModuleName, $next.FilePath, $next.Arguments, $next.OutputPath

        $Global:zimmermanJobs += [PSCustomObject]@{
            JobObject = $job
            RequestId = $next.RequestId
            JobName = $next.JobName
            ModuleName = $next.ModuleName
            OutputPath = $next.OutputPath
            DataAdded = $false
            HasDetailedCompletionOutput = $false
            HasDetailedFailureOutput = $false
        }

        $runningCount++
    }
}

function Check-ZimmermanProcessingStatus {
    $remainingJobs = @()
    $logQueueStatus = $false

    foreach ($job in $Global:zimmermanJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        $jobOutput = @(Receive-Job -Id $updatedJob.Id -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
        foreach ($line in $jobOutput) {
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                if ($line -like "Finished Zimmerman module:*") {
                    $job.HasDetailedCompletionOutput = $true
                } elseif ($line -like "Failed Zimmerman module:*") {
                    $job.HasDetailedFailureOutput = $true
                }
                Update-Log $line "ProcessSystemTextBox"
            }
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                if ($updatedJob.State -eq "Completed") {
                    if (-not $job.HasDetailedCompletionOutput) {
                        Update-Log "Finished Zimmerman module: $($job.ModuleName)" "ProcessSystemTextBox"
                    }
                } else {
                    if (-not $job.HasDetailedFailureOutput) {
                        $failureReason = $null
                        if ($updatedJob.ChildJobs -and $updatedJob.ChildJobs.Count -gt 0) {
                            $failureReason = $updatedJob.ChildJobs[0].JobStateInfo.Reason
                        }
                        if ($failureReason) {
                            Update-Log "Zimmerman module failed: $($job.ModuleName) - $failureReason" "ProcessSystemTextBox"
                        } else {
                            Update-Log "Zimmerman module failed: $($job.ModuleName)" "ProcessSystemTextBox"
                        }
                    }
                }

                if ($job.RequestId -and $Global:zimmermanRequestTracker.ContainsKey($job.RequestId)) {
                    $requestRecord = $Global:zimmermanRequestTracker[$job.RequestId]
                    if ($updatedJob.State -eq "Completed") {
                        $requestRecord.Completed = [int]$requestRecord.Completed + 1
                    } else {
                        $requestRecord.Failed = [int]$requestRecord.Failed + 1
                    }

                    $finishedCount = [int]$requestRecord.Completed + [int]$requestRecord.Failed
                    if (-not $requestRecord.Logged -and $finishedCount -ge [int]$requestRecord.Total) {
                        Update-Log ("Zimmerman request #{0} completed: {1}/{2} succeeded, {3} failed [{4}]" -f $requestRecord.Id, $requestRecord.Completed, $requestRecord.Total, $requestRecord.Failed, $requestRecord.Label) "ProcessSystemTextBox"
                        $requestRecord.Logged = $true
                    }
                    $Global:zimmermanRequestTracker[$job.RequestId] = $requestRecord
                }

                $job.DataAdded = $true
            }

            $logQueueStatus = $true
            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:zimmermanJobs = $remainingJobs
    Start-NextZimmermanJobs

    if ($logQueueStatus) {
        Update-Log (Get-ZimmermanActiveModuleSummary) "ProcessSystemTextBox"
    }

    if ($Global:zimmermanJobs.Count -eq 0 -and $Global:zimmermanPendingJobs.Count -eq 0) {
        Update-Log "All Zimmerman Tools processing completed." "ProcessSystemTextBox"
        $Global:zimmermanRequestTracker = @{}
        $zimmermanProcessingTimer.Stop()
    }
}

function ProcessZimmermanButton_Click {
    try {
        if (-not $ArtifactProcessingPathTextBox.Text -or -not $ZimmermanPathTextBox.Text) {
            [System.Windows.MessageBox]::Show("Please select an artifact path and Zimmerman Tools main directory or Get-ZimmermanTools.ps1.")
            return
        }

        $artifactPathValue = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
        $zimmermanPathValue = $ZimmermanPathTextBox.Text.Trim().Trim('"')
        if (-not (Test-Path -LiteralPath $artifactPathValue -ErrorAction SilentlyContinue)) {
            [System.Windows.MessageBox]::Show("Selected artifact path does not exist.")
            return
        }
        if (-not (Test-Path -LiteralPath $zimmermanPathValue -ErrorAction SilentlyContinue)) {
            [System.Windows.MessageBox]::Show("Selected Zimmerman path does not exist.")
            return
        }

        # Use dotnet CLI to check for installed runtimes
        $validDotNetVersionInstalled = $false
        try {
            $dotnetOutput = & dotnet --list-runtimes 2>$null
            foreach ($line in $dotnetOutput) {
                if ($line -match '^Microsoft\.NETCore\.App\s+(\d+)\.') {
                    $majorVersion = [int]$matches[1]
                    if ($majorVersion -ge 9) {
                        $validDotNetVersionInstalled = $true
                        break
                    }
                }
            }
        } catch {
            Update-Log "Could not detect .NET runtimes. Please ensure .NET is installed and 'dotnet' is on your PATH." "ProcessSystemTextBox"
            return
        }

        # Logic based on whether a valid version is installed
        if ($validDotNetVersionInstalled) {
            Update-Log "Starting Zimmerman Tools..." "ProcessSystemTextBox"
            $selectedModule = $null
            if ($ZtoolsComboBox.SelectedItem -is [string]) {
                $selectedModule = [string]$ZtoolsComboBox.SelectedItem
            } elseif ($ZtoolsComboBox.SelectedItem -and $ZtoolsComboBox.SelectedItem.Content) {
                $selectedModule = [string]$ZtoolsComboBox.SelectedItem.Content
            }
            if ([string]::IsNullOrWhiteSpace($selectedModule)) {
                $selectedModule = "All Modules"
            }

            Process-ZimmermanTools -SelectedModule $selectedModule -ArtifactPath $artifactPathValue -ZimmermanFilePath $zimmermanPathValue

            # Start the timer
            if (-not $zimmermanProcessingTimer.Enabled) {
                $zimmermanProcessingTimer.Start()
            }
        } else {
            Update-Log "Zimmerman Tools used in this program require .NET version 9 or greater. Please install the required .NET version." "ProcessSystemTextBox"
            return
        }
    } catch {
        $errorMessage = $_.Exception.Message
        Update-Log "Zimmerman Tools launch failed: $errorMessage" "ProcessSystemTextBox"
        [System.Windows.MessageBox]::Show("Zimmerman Tools launch failed. Check Process System Artifacts log for details.")
    }
}

function Get-ZimmermanModuleMap {
    param(
        [string]$ArtifactPath,
        [string]$ZimmermanToolsPath,
        [string]$OutputFolderPath,
        [bool]$IsFile,
        [bool]$IsDirectory,
        [string]$ArtifactFullPath
    )

    $modules = @{
        'JLECmd' = @{
            FilePath = "$ZimmermanToolsPath\JLECmd.exe"
            Arguments = "-d `'$ArtifactPath`' --csv `'$OutputFolderPath\FileFolderAccess`' -q --mp"
        }
        'LECmd' = @{
            FilePath = "$ZimmermanToolsPath\LECmd.exe"
            Arguments = "-d `'$ArtifactPath`' --csv `'$OutputFolderPath\FileFolderAccess`' -q --mp"
        }
        'PECmd' = @{
            FilePath = "$ZimmermanToolsPath\PECmd.exe"
            Arguments = "-d `'$ArtifactPath`' --csv `'$OutputFolderPath\ProgramExecution`' --mp -q"
        }
        'RBCmd' = @{
            FilePath = "$ZimmermanToolsPath\RBCmd.exe"
            Arguments = "-d `'$ArtifactPath`' --csv `'$OutputFolderPath\RecycleBin`' -q"
        }
        'RECmd' = @{
            FilePath = "$ZimmermanToolsPath\RECmd\RECmd.exe"
            Arguments = "-d `'$ArtifactPath`' --bn `'$ZimmermanToolsPath\RECmd\BatchExamples\Kroll_Batch.reb`' --csv `'$OutputFolderPath\Registry`' --nl --recover"
        }
        'SBECmd' = @{
            FilePath = "$ZimmermanToolsPath\SBECmd.exe"
            Arguments = "-d `'$ArtifactPath`' --csv `'$OutputFolderPath\FileFolderAccess`' --nl"
        }
        'SQLECmd' = @{
            FilePath = "$ZimmermanToolsPath\SQLECmd\SQLECmd.exe"
            Arguments = "-d `'$ArtifactPath`' --csv `'$OutputFolderPath\SQLDatabases`'"
        }
    }

    $amcacheFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter 'Amcache.hve' -ErrorAction SilentlyContinue | Select-Object -First 1
    $recentFileCacheFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter 'RecentFileCache.bcf' -ErrorAction SilentlyContinue | Select-Object -First 1
    $systemHive = Get-ChildItem -Path $ArtifactPath -Include "SYSTEM" -Recurse -File | Where-Object { $_.FullName -like "*\Windows\System32\config\SYSTEM" } | Select-Object -First 1
    if (-not $systemHive) {
        $systemHive = Get-ChildItem -Path $ArtifactPath -Include "SYSTEM" -Recurse -File | Select-Object -First 1
    }
    $softwareHive = Get-ChildItem -Path $ArtifactPath -Include "SOFTWARE" -Recurse -File | Where-Object { $_.FullName -like "*\Windows\System32\config\SOFTWARE" } | Select-Object -First 1
    if (-not $softwareHive) {
        $softwareHive = Get-ChildItem -Path $ArtifactPath -Include "SOFTWARE" -Recurse -File | Select-Object -First 1
    }

    $eventLogFolderPath = $null
    $eventLogFilePath = $null
    $evtxecmdArguments = $null
    if ($IsDirectory) {
        $eventLogFolder = Get-ChildItem -Path $ArtifactPath -Recurse -Directory | Where-Object { $_.FullName -like "*\Windows\System32\winevt\Logs" } | Select-Object -First 1
        if ($eventLogFolder) {
            $eventLogFolderPath = $eventLogFolder.FullName
        } else {
            $eventLogFolderPath = $ArtifactPath
        }
        $evtxecmdArguments = "-d `'$eventLogFolderPath`' --csv `'$OutputFolderPath\EventLogs`'"
    } elseif ($IsFile) {
        $eventLogFilePath = $ArtifactFullPath
        $evtxecmdArguments = "-f `'$eventLogFilePath`' --csv `'$OutputFolderPath\EventLogs`'"
    }

    $MFTFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter '$MFT' -ErrorAction SilentlyContinue | Select-Object -First 1
    $JFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter '*$J' -ErrorAction SilentlyContinue | Select-Object -First 1
    $sumFolder = Get-ChildItem -Path $ArtifactPath -Recurse -Directory | Where-Object { $_.FullName -like "*\Windows\System32\LogFiles\SUM" } | Select-Object -First 1
    $sumFolderPath = $null
    if ($sumFolder) {
        $sumFolderPath = $sumFolder.FullName
    } else {
        $currentMdbFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter "Current.mdb" | Select-Object -First 1
        if ($currentMdbFile) {
            $sumFolderPath = $currentMdbFile.DirectoryName
        }
    }
    $ActivitiesCacheFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter 'ActivitiesCache.db' -ErrorAction SilentlyContinue | Select-Object -First 1
    $srudbFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter 'SRUDB.dat' -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($amcacheFile) {
        $modules['AmcacheParser'] = @{
            FilePath = "$ZimmermanToolsPath\AmcacheParser.exe"
            Arguments = "-f `'$($amcacheFile.FullName)`' --csv `'$OutputFolderPath\ProgramExecution`' -i --mp --nl"
        }
    }
    if ($systemHive) {
        $modules['AppCompatCacheParser'] = @{
            FilePath = "$ZimmermanToolsPath\AppCompatCacheParser.exe"
            Arguments = "-f `'$($systemHive.FullName)`' --csv `'$OutputFolderPath\ProgramExecution`' --nl"
        }
    }
    if ($eventLogFolderPath -or $eventLogFilePath) {
        $modules['EvtxECmd'] = @{
            FilePath = "$ZimmermanToolsPath\EvtxECmd\EvtxECmd.exe"
            Arguments = $evtxecmdArguments
        }
    }
    if ($sumFolderPath) {
        $modules['SumECmd'] = @{
            FilePath = "$ZimmermanToolsPath\SumECmd.exe"
            Arguments = "-d `'$sumFolderPath`' --csv `'$OutputFolderPath\SUMDatabase`'"
        }
    }
    if ($MFTFile -and $JFile) {
        $modules['MFTECmd'] = @{
            FilePath = "$ZimmermanToolsPath\MFTECmd.exe"
            Arguments = "-f `'$($JFile.FullName)`' -m `'$($MFTFile.FullName)`' --csv `'$OutputFolderPath\FileSystem`'"
        }
    } elseif ($MFTFile) {
        $modules['MFTECmd'] = @{
            FilePath = "$ZimmermanToolsPath\MFTECmd.exe"
            Arguments = "-f `'$($MFTFile.FullName)`' --csv `'$OutputFolderPath\FileSystem`'"
        }
    }
    if ($recentFileCacheFile) {
        $modules['RecentFileCacheParser'] = @{
            FilePath = "$ZimmermanToolsPath\RecentFileCacheParser.exe"
            Arguments = "-f `'$($recentFileCacheFile.FullName)`' --csv `'$OutputFolderPath\ProgramExecution`'"
        }
    }
    if ($ActivitiesCacheFile) {
        $modules['WxTCmd'] = @{
            FilePath = "$ZimmermanToolsPath\WxTCmd.exe"
            Arguments = "-f `'$($ActivitiesCacheFile.FullName)`' --csv `'$OutputFolderPath\FileFolderAccess`'"
        }
    }
    if ($srudbFile -and $softwareHive) {
        $modules['SrumECmd'] = @{
            FilePath = "$ZimmermanToolsPath\SrumECmd.exe"
            Arguments = "-f `'$($srudbFile.FullName)`' -r `'$($softwareHive.FullName)`' --csv `'$OutputFolderPath\SRUMDatabase`'"
        }
    } elseif ($srudbFile) {
        $modules['SrumECmd'] = @{
            FilePath = "$ZimmermanToolsPath\SrumECmd.exe"
            Arguments = "-f `'$($srudbFile.FullName)`' --csv `'$OutputFolderPath\SRUMDatabase`'"
        }
    }

    return $modules
}

function Process-ZimmermanTools {
    param (
        [string]$SelectedModule,
        [string]$ArtifactPath,
        [string]$ZimmermanFilePath
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $uniqueJobName = "ZimmermanJob_${timestamp}"

    $isFile = $false
    $isDirectory = $false
    $ArtifactfullPath = $null
    if (Test-Path -Path $ArtifactPath -PathType Leaf) {
        $isFile = $true
        $ArtifactfullPath = $ArtifactPath
    } elseif (Test-Path -Path $ArtifactPath -PathType Container) {
        $isDirectory = $true
    } else {
        Update-Log "Artifact path is not a valid file or directory for Zimmerman processing." "ProcessSystemTextBox"
        return
    }

    if ($isFile) {
        $ArtifactPath = [System.IO.Path]::GetDirectoryName($ArtifactPath)
    }

    if (([System.IO.Path]::GetPathRoot($ArtifactPath)).TrimEnd('\') -eq $ArtifactPath.TrimEnd('\')) {
        $outputFolderName = "Root_" + $ArtifactPath.Trim(':\\') + "_Drive"
    } else {
        $outputFolderName = [IO.Path]::GetFileNameWithoutExtension($ArtifactPath)
    }

    $outputBaseFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zimmermantools'
    $outputFolderPath = Join-Path $outputBaseFolder $outputFolderName
    if (-not (Test-Path $outputFolderPath)) {
        $null = New-Item -Path $outputFolderPath -ItemType Directory -Force
    }

    $zimmermanItem = Get-Item -LiteralPath $ZimmermanFilePath -ErrorAction Stop
    $ZimmermanToolsPath = if ($zimmermanItem.PSIsContainer) { $zimmermanItem.FullName } else { Split-Path -Path $zimmermanItem.FullName -Parent }
    $net9Path = Join-Path -Path $ZimmermanToolsPath -ChildPath "net9"
    if (-not (Test-Path -Path $net9Path)) {
        Update-Log "This program requires the .NET 9 version of Zimmerman Tools located in a 'net9' directory within $ZimmermanToolsPath." "ProcessSystemTextBox"
        return
    }
    $ZimmermanToolsPath = $net9Path

    Update-Log "Zimmerman Tool: $($ZimmermanToolsPath) SelectedModule: $($SelectedModule) ArtifactPath: $($ArtifactPath) ArtifactfullPath: $($ArtifactfullPath) outputFolderPath: $($outputFolderPath)" "ProcessSystemTextBox"

    $modules = Get-ZimmermanModuleMap -ArtifactPath $ArtifactPath -ZimmermanToolsPath $ZimmermanToolsPath -OutputFolderPath $outputFolderPath -IsFile:$isFile -IsDirectory:$isDirectory -ArtifactFullPath $ArtifactfullPath

    $modulesToQueue = @()
    if ($SelectedModule -eq 'All Modules') {
        foreach ($entry in $modules.GetEnumerator()) {
            if ($entry.Key -and $entry.Value -and $entry.Value.FilePath) {
                $modulesToQueue += [PSCustomObject]@{
                    ModuleName = $entry.Key
                    FilePath = $entry.Value.FilePath
                    Arguments = $entry.Value.Arguments
                }
            }
        }
    } elseif ($modules.ContainsKey($SelectedModule)) {
        $moduleData = $modules[$SelectedModule]
        $modulesToQueue += [PSCustomObject]@{
            ModuleName = $SelectedModule
            FilePath = $moduleData.FilePath
            Arguments = $moduleData.Arguments
        }
    } else {
        Update-Log "Selected module ($SelectedModule) is not recognized for this artifact set." "ProcessSystemTextBox"
        return
    }

    $modulesToQueue = @($modulesToQueue | Where-Object { $_ -and -not [string]::IsNullOrWhiteSpace($_.ModuleName) -and (Test-Path -LiteralPath $_.FilePath -ErrorAction SilentlyContinue) })
    if ($modulesToQueue.Count -eq 0) {
        Update-Log "No runnable Zimmerman modules were identified for this path." "ProcessSystemTextBox"
        return
    }

    $requestId = [int]$Global:zimmermanRequestCounter + 1
    $Global:zimmermanRequestCounter = $requestId
    $requestLabel = "{0} | {1}" -f (Split-Path $ArtifactPath -Leaf), $SelectedModule
    $Global:zimmermanRequestTracker[$requestId] = [PSCustomObject]@{
        Id = $requestId
        Label = $requestLabel
        Total = $modulesToQueue.Count
        Completed = 0
        Failed = 0
        Logged = $false
    }

    foreach ($module in $modulesToQueue) {
        $Global:zimmermanPendingJobs += [PSCustomObject]@{
            RequestId = $requestId
            JobName = $uniqueJobName
            ModuleName = $module.ModuleName
            FilePath = $module.FilePath
            Arguments = $module.Arguments
            OutputPath = $outputFolderPath
        }
    }

    Update-Log ("Queued Zimmerman request #{0}: {1} module(s) [{2}]" -f $requestId, $modulesToQueue.Count, $requestLabel) "ProcessSystemTextBox"
    Update-Log ("Zimmerman parallel workers: {0}" -f $Global:zimmermanMaxParallel) "ProcessSystemTextBox"
    Start-NextZimmermanJobs
    Update-Log (Get-ZimmermanActiveModuleSummary) "ProcessSystemTextBox"
}

function Check-ZimmermanToolsStatus {	
    $completedCount = 0	
    foreach ($job in $Global:zimmermantoolsUpdateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Zimmerman Tools update completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Zimmerman Tools update completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
    if ($completedCount -eq $Global:zimmermantoolsUpdateJobs.Count) {
        Update-Log "Zimmerman Tools update completed." "ProcessSystemTextBox"
        $zimmermantoolsUpdateTimer.Stop()
    }
}

function UpdateZimmermanButton_Click {
    $ZimmermanToolsPath = $ZimmermanPathTextBox.Text.Trim().Trim('"')
    $ZimmermanDirectory = [System.IO.Path]::GetDirectoryName($ZimmermanToolsPath) 
    $ZimmermanCommand = "& `"$ZimmermanToolsPath`" -Dest `"$ZimmermanDirectory`""
    Update-Log "Zimmerman Command is $ZimmermanCommand" "ProcessSystemTextBox"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $job = Start-Job -ScriptBlock {
        param($ZimmermanCommand, $ZimmermanDirectory)
        
        Set-Location -Path $ZimmermanDirectory
        Invoke-Expression $ZimmermanCommand
        
    } -ArgumentList $ZimmermanCommand, $ZimmermanDirectory

    $Global:zimmermantoolsUpdateJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "zimmermantToolsUpdate_$timestamp"
        DataAdded = $false
    }

    Update-Log "Zimmermant Tools update started." "ProcessSystemTextBox" 
    if (-not $zimmermantoolsUpdateTimer.Enabled) {
        $zimmermantoolsUpdateTimer.Start()
    }    
}

function Check-ZircoliteProcessingStatus {	
    $completedCount = 0	
    foreach ($job in $Global:zircoliteJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Zircolite completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Zircolite completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
    if ($completedCount -eq $Global:zircoliteJobs.Count) {
        Update-Log "All Zircolite processing completed." "ProcessSystemTextBox"
        $zircoliteProcessingTimer.Stop()
		Perform-Cleanup
    }
}

function Perform-Cleanup {
	$zircoliteFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zircolite'
	$ZircolitePath = $ZircolitePathTextBox.Text.Trim().Trim('"')	
	$zircoliteDirectory = [System.IO.Path]::GetDirectoryName($ZircolitePath)
    # Remove empty CSV and small JSON files
    Get-ChildItem -Path $zircoliteFolder -Filter "*.csv" | Where-Object { $_.Length -eq 0 } | Remove-Item
    Get-ChildItem -Path $zircoliteFolder -Filter "*.json" | Where-Object { $_.Length -le 1024 } | Remove-Item

    # Move recent zircogui-output-xxxx.zip files
    $cutoffTime = (Get-Date).AddHours(-6)
    Get-ChildItem -Path $zircoliteDirectory -Filter "zircogui-output-*.zip" | 
        Where-Object { $_.CreationTime -gt $cutoffTime } |
        Move-Item -Destination $zircoliteFolder
}

function ProcessZircoliteButton_Click {
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $ZircolitePathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and Zircolite path.")
        return
    }
    Update-Log "Starting Zircolite..." "ProcessSystemTextBox"
    $InputPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
    $ZircolitePath = $ZircolitePathTextBox.Text.Trim().Trim('"')
    $artifactName = [System.IO.Path]::GetFileNameWithoutExtension($ArtifactProcessingPathTextBox.Text.Trim().Trim('"'))

    # Check if the user wants to use a custom date range or psort only
    $useCustomDateRange = $ZircoliteDateRangeCheckBox.IsChecked
    $useJson = $ZircolitejsonCheckBox.IsChecked
    $usePackage = $ZircolitepackageCheckBox.IsChecked
    # Fetch the selected items as strings
    $ZircoliteRules = if ($ZircoliteRulesComboBox.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) { 
                        $ZircoliteRulesComboBox.SelectedItem.Content 
                      } else { 
                        $ZircoliteRulesComboBox.SelectedItem 
                      }

    $ZircoliteTemplates = if ($ZircoliteTemplatesComboBox.SelectedItem -is [System.Windows.Controls.ComboBoxItem]) { 
                            $ZircoliteTemplatesComboBox.SelectedItem.Content 
                          } else { 
                            $ZircoliteTemplatesComboBox.SelectedItem 
                          }
	$Zircolitesysmon = $ZircolitesysmonCheckBox.IsChecked
	
    $startDate = $null
    $endDate = $null
	Write-Host "Zircolite rule is $ZircoliteRules"
	Write-Host "ZircoliteTemplate is $ZircoliteTemplates"
	
    if ($useCustomDateRange -eq $true) {
        $startDate = $ZircoliteStartDatePicker.SelectedDate
        $endDate = $ZircoliteEndDatePicker.SelectedDate

        # Validate date range
        if ($startDate -and $endDate -and $startDate -gt $endDate) {
            [System.Windows.MessageBox]::Show("Start Date must be before End Date.")
            return
        }
    }

    # Check if input path is a directory
    if (Test-Path -Path $InputPath -PathType Container) {
        Start-ZircoliteDirectoryJob -DirectoryPath $InputPath -ZircolitePath $ZircolitePath -StartDate $startDate -EndDate $endDate -useJson $useJson -usePackage $usePackage -ZircoliteRules $ZircoliteRules -ZircoliteTemplates $ZircoliteTemplates -Zircolitesysmon $Zircolitesysmon
        if (-not $zircoliteProcessingTimer.Enabled) {
            $zircoliteProcessingTimer.Start()
        }
    } else {
        Process-Zircolite -logFile $InputPath -ZircolitePath $ZircolitePath -StartDate $startDate -EndDate $endDate -useJson $useJson -usePackage $usePackage -ZircoliteRules $ZircoliteRules -ZircoliteTemplates $ZircoliteTemplates -Zircolitesysmon $Zircolitesysmon
		if (-not $zircoliteProcessingTimer.Enabled) {
			$zircoliteProcessingTimer.Start()
		}		
    }
}

function Start-ZircoliteDirectoryJob {
    param (
        [string]$DirectoryPath,
        [string]$ZircolitePath,
        [Nullable[DateTime]]$StartDate,
        [Nullable[DateTime]]$EndDate,
        [bool]$useJson,
        [bool]$usePackage,
        [string]$ZircoliteRules,
        [string]$ZircoliteTemplates,
        [bool]$Zircolitesysmon
    )

	$outputBaseFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zircolite'

	$job = Start-Job -ScriptBlock {
		param ($DirectoryPath, $ZircolitePath, $StartDate, $EndDate, $useJson, $usePackage, $ZircoliteRules, $ZircoliteTemplates, $Zircolitesysmon, $outputBaseFolder)
		$zircoliteDirectory = [System.IO.Path]::GetDirectoryName($ZircolitePath)	

		$fileFilter = if ($ZircoliteRules -ne "rules_linux.json") { "*.evtx" } else { "*.log" }

		$logFiles = Get-ChildItem -Path $DirectoryPath -Filter $fileFilter -Recurse -File
		foreach ($logFile in $logFiles) {
			$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
			$artifactName = [System.IO.Path]::GetFileNameWithoutExtension($logFile.FullName)	
			$ZircoliteCSVName = "${timestamp}_${artifactName}_zircolite.csv"
			$ZircoliteJsonName = "${timestamp}_${artifactName}_zircolite.json"
			$ZircoliteTemplateName = $ZircoliteTemplates.Replace('.tmpl', '.json')	
			if (-not (Test-Path $outputBaseFolder)) {
				$null = New-Item -Path $outputBaseFolder -ItemType Directory -Force
			}
			$outputPathcsv = Join-Path $outputBaseFolder $ZircoliteCSVName
			$outputPathjson = Join-Path $outputBaseFolder $ZircoliteJsonName	
			$outputPathtemplate = Join-Path $outputBaseFolder $ZircoliteTemplateName	
			$zircoliteArguments = @("--events", "`'$($logFile.FullName)`'", "-r", "rules\$ZircoliteRules")	
			$filterString = $null
			if ($StartDate -and $EndDate) {
				$startDateFormatted = (Get-Date $StartDate -Format "yyyy-MM-ddTHH:mm:ss")
				$endDateFormatted = (Get-Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss +00:00")
				$filterString = "--after `"$startDateFormatted`" --before `"$endDateFormatted`""
			} elseif ($StartDate) {
				$startDateFormatted = (Get-Date $StartDate -Format "yyyy-MM-ddTHH:mm:ss")
				$filterString = "--after `"$startDateFormatted`""
			} elseif ($EndDate) {
				$endDateFormatted = (Get-Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss")
				$filterString = "--before `"$endDateFormatted`""
			}	
			if ($filterString) {
				$zircoliteArguments += $filterString
			}	
			if ($artifactName -eq "auditd.log") {
				$zircoliteArguments += ("--auditd" )
			}	
			if ($Zircolitesysmon ) {
				$zircoliteArguments += ("--sysmon-linux" )
			}		
			if ($useJson -or $ZircoliteTemplates -ne "Default (None)") {
				$zircoliteArguments += ("-o", "`'$outputPathjson`'")
			} else {
				$zircoliteArguments += ("-o", "`'$outputPathcsv`'", "--csv", "--csv-delimiter", "`",`"")
			}
		
			if ($ZircoliteTemplates -ne "Default (None)" ) {
				$zircoliteArguments += ("--template", "templates\$ZircoliteTemplates", "--templateOutput", "`'$outputPathtemplate`'")
			}			
			if ($usePackage) {
				$zircoliteArguments += ("--package")
			}			
			$zircoliteCommand = "& `"$ZircolitePath`" $zircoliteArguments"
			Set-Location -Path $zircoliteDirectory			
            Invoke-Expression $zircoliteCommand
		}
	} -ArgumentList $DirectoryPath, $ZircolitePath, $StartDate, $EndDate, $useJson, $usePackage, $ZircoliteRules, $ZircoliteTemplates, $Zircolitesysmon, $outputBaseFolder

    $Global:zircoliteJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "Zircolite Processing for $DirectoryPath"
        ArtifactPath = $DirectoryPath
        DataAdded = $false
    }
}

function Process-Zircolite {
    param (
        [string]$logFile,
        [string]$ZircolitePath,
        [Nullable[DateTime]]$StartDate,
        [Nullable[DateTime]]$EndDate,
        [bool]$useJson,
        [bool]$usePackage,
        [bool]$Zircolitesysmon,		
        [string]$ZircoliteRules,
        [string]$ZircoliteTemplates
    )

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $zircoliteDirectory = [System.IO.Path]::GetDirectoryName($ZircolitePath)	
	$artifactName = [System.IO.Path]::GetFileNameWithoutExtension($logFile)	
    $ZircoliteCSVName = "${timestamp}_${artifactName}_zircolite.csv"
	$ZircoliteJsonName = "${timestamp}_${artifactName}_zircolite.json"
	$ZircoliteTemplateName = $ZircoliteTemplates.Replace('.tmpl', '.json')
    $outputBaseFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zircolite'
    
    if (-not (Test-Path $outputBaseFolder)) {
        $null = New-Item -Path $outputBaseFolder -ItemType Directory -Force
    }
    $outputPathcsv = Join-Path $outputBaseFolder $ZircoliteCSVName
    $outputPathjson = Join-Path $outputBaseFolder $ZircoliteJsonName	
	$outputPathtemplate = Join-Path $outputBaseFolder $ZircoliteTemplateName	
    $zircoliteArguments = @("--events", "`'$logFile`'", "-r", "rules\$ZircoliteRules")

    # Construct the filter string based on provided start and/or end dates
    $filterString = $null
    if ($StartDate -and $EndDate) {
        $startDateFormatted = (Get-Date $StartDate -Format "yyyy-MM-ddTHH:mm:ss")
        $endDateFormatted = (Get-Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss +00:00")
        $filterString = "--after `"$startDateFormatted`" --before `"$endDateFormatted`""
    } elseif ($StartDate) {
        $startDateFormatted = (Get-Date $StartDate -Format "yyyy-MM-ddTHH:mm:ss")
        $filterString = "--after `"$startDateFormatted`""
    } elseif ($EndDate) {
        $endDateFormatted = (Get-Date $EndDate -Format "yyyy-MM-ddTHH:mm:ss")
        $filterString = "--before `"$endDateFormatted`""
    }

    if ($filterString) {
        $zircoliteArguments += $filterString
    }

    if ($artifactName -eq "auditd.log") {
        $zircoliteArguments += ("--auditd" )
    }

    if ($Zircolitesysmon ) {
        $zircoliteArguments += ("--sysmon-linux" )
    }
	
    if ($useJson -or $ZircoliteTemplates -ne "Default (None)") {
        $zircoliteArguments += ("-o", "`'$outputPathjson`'")
    } else {
		$zircoliteArguments += ("-o", "`'$outputPathcsv`'", "--csv", "--csv-delimiter", "`",`"")
	}

    if ($ZircoliteTemplates -ne "Default (None)" ) {
        $zircoliteArguments += ("--template", "templates\$ZircoliteTemplates", "--templateOutput", "`'$outputPathtemplate`'")
    }
	
    if ($usePackage) {
        $zircoliteArguments += ("--package")
    }
	
    $zircoliteCommand = "& `"$ZircolitePath`" $zircoliteArguments"


    Update-Log "Zircolite Command is $zircoliteCommand" "ProcessSystemTextBox"
    $job = Start-Job -ScriptBlock {
        param($zircoliteCommand, $zircoliteDirectory)
        Set-Location -Path $zircoliteDirectory       
        Invoke-Expression $zircoliteCommand
        
    } -ArgumentList ($zircoliteCommand, $zircoliteDirectory)

    $Global:zircoliteJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "zircolite_$timestamp"
        ArtifactPath = $logFile
        DataAdded = $false
    }

    Update-Log "Zircolite parsing job started for $logFile." "ProcessSystemTextBox"
}

function Check-ZircoliteUpdateStatus {	
    $completedCount = 0	
    foreach ($job in $Global:zircoliteupdateJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Zircolite rules update completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Zircolite rules update completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
    if ($completedCount -eq $Global:zircoliteupdateJobs.Count) {
        Update-Log "Zircolite rules update completed." "ProcessSystemTextBox"
        $zircoliteUpdateTimer.Stop()
    }
}

function UpdateZircoliteButton_Click {
    $ZircolitePath = $ZircolitePathTextBox.Text.Trim().Trim('"')
    $zircoliteDirectory = [System.IO.Path]::GetDirectoryName($ZircolitePath)
    $zircoliteArguments = @("-U")   
    $zircoliteCommand = "& `"$ZircolitePath`" $zircoliteArguments"
    Update-Log "Zircolite Command is $zircoliteCommand" "ProcessSystemTextBox"
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $job = Start-Job -ScriptBlock {
        param($zircoliteCommand, $zircoliteDirectory)
        
        Set-Location -Path $zircoliteDirectory
        Invoke-Expression $zircoliteCommand
        
    } -ArgumentList $zircoliteCommand, $zircoliteDirectory

    $Global:zircoliteupdateJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "zircolite_$timestamp"
        DataAdded = $false
    }

    Update-Log "Zircolite rules update started." "ProcessSystemTextBox" 
    if (-not $zircoliteUpdateTimer.Enabled) {
        $zircoliteUpdateTimer.Start()
    }    
}

function Check-TimelineArtifactsJobStatus {	
    $completedCount = 0	
    foreach ($job in $Global:timelineartifactsJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Timeline Database update completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Timeline Database update completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
    if ($completedCount -eq $Global:timelineartifactsJobs.Count) {
        Update-Log "Timeline Database update completed." "ProcessSystemTextBox"
        $timelineartifactsJobTimer.Stop()
    }
}

function Check-TimelineExportJobStatus {	
    $completedCount = 0	
    foreach ($job in $Global:timelineexportJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Timeline export completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Timeline export completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
    if ($completedCount -eq $Global:timelineexportJobs.Count) {
        Update-Log "Timeline export completed." "ProcessSystemTextBox"
        $timelineexportJobTimer.Stop()
    }
}

function Load-SQLiteDLL {
    $sqliteDllPath = $sqlitePathTextBox.Text.Trim().Trim('"')
    if (Test-Path -Path $sqliteDllPath) {
        try {
            Unblock-File -Path $sqliteDllPath  # Unblock the file if it is blocked
            $alreadyLoaded = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object {
                $_.Location -and ($_.Location -ieq $sqliteDllPath)
            }
            if (-not $alreadyLoaded) {
                Add-Type -Path $sqliteDllPath
            }
            Write-Host "System.Data.SQLite.dll loaded successfully."
            return $true
        } catch {
            Write-Host "Failed to load System.Data.SQLite.dll. Error: $_"
            Update-Log "Failed to load System.Data.SQLite.dll. Error: $_" "ProcessSystemTextBox"
            return $false
        }
    } else {
        Write-Host "System.Data.SQLite.dll not found. Please locate it."
        Update-Log "System.Data.SQLite.dll not found. Please locate it." "ProcessSystemTextBox"
        return $false
    }
}

function ExportTimelineArtifactsButton_Click {
    if (-not $sqlitePathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select the System.Data.SQLite.dll for the processing tool location.")
        return
    }

    # Ensure the SQLite DLL is loaded
    if (-not (Load-SQLiteDLL)) {
        [System.Windows.MessageBox]::Show("Failed to load System.Data.SQLite.dll. Check the selected path and try again.")
        return
    }

    $artifactsTimelineDir = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\ArtifactsTimeline'
    $databasePath = Join-Path $artifactsTimelineDir 'ArtifactsTimeline.db'
    $logFilePath = Join-Path $artifactsTimelineDir 'ArtifactsTimeline.log'

    # Check if the database exists
    if (-not (Test-Path -Path $databasePath)) {
        [System.Windows.MessageBox]::Show("ArtifactsTimeline.db does not exist. Please make sure the database is created.")
        return
    }

    # Check if the user wants to use a custom date range
    $useCustomDateRange = $TimelineDateRangeCheckBox.IsChecked
    $startDate = $null
    $endDate = $null
    $dateFilter = ""

    if ($useCustomDateRange -eq $true) {
        $startDate = $TimelineArtifactsStartDatePicker.SelectedDate
        $endDate = $TimelineArtifactsEndDatePicker.SelectedDate

        # Validate date range
        if ($startDate -and $endDate -and $startDate -gt $endDate) {
            [System.Windows.MessageBox]::Show("Start Date must be before End Date.")
            return
        }

        # Adjust dates to include the entire day
        if ($startDate) {
            $startDate = $startDate.ToString("yyyy-MM-dd 00:00:00")
        }

        if ($endDate) {
            $endDate = $endDate.ToString("yyyy-MM-dd 23:59:59")
        }

        # Create date filter for the SQL query
        if ($startDate -and $endDate) {
            $dateFilter = "AND [@timestamp] BETWEEN '$startDate' AND '$endDate'"
        } elseif ($startDate) {
            $dateFilter = "AND [@timestamp] >= '$startDate'"
        } elseif ($endDate) {
            $dateFilter = "AND [@timestamp] <= '$endDate'"
        }
    }

    # Load System.Data.SQLite assembly in the main script
    $assemblyPath = $sqlitePathTextBox.Text.Trim().Trim('"')

    Update-Log "Starting Timeline Export..." "ProcessSystemTextBox"

    # Read IOCs if the checkbox is checked
    $findIOCs = $TimelineDateIOCCheckBox.IsChecked
    $IOCFilePath = $global:timelineIOCFilePath
    $IOCs = @()

    if ($findIOCs -eq $true) {
        $IOCs = Read-IOCFile -filePath $IOCFilePath
    }

    $job = Start-Job -ScriptBlock {
        param($DatabasePath, $ArtifactsTimelineDir, $DateFilter, $AssemblyPath, $LogFilePath, $IOCs, $findIOCs)

        # Load the assembly inside the job
        Add-Type -Path $AssemblyPath 

        function Write-Log {
            param (
                [string]$Message
            )
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            $logMessage = "$timestamp - $Message"
            Add-Content -Path $LogFilePath -Value $logMessage
        }

        function Process-DataInBatches {
            param(
                [string]$query,
                [string]$filePath,
                [System.Data.SQLite.SQLiteConnection]$connection,
                [System.IO.StreamWriter]$streamWriter,
                [ref]$headersWritten,
                [int]$batchSize = 5000000,
                [bool]$includeIOC = $false
            )

            $command = $connection.CreateCommand()
            $command.CommandText = $query

            $totalRowsProcessed = 0

            do {
                $batchQuery = $query + " LIMIT $batchSize OFFSET $totalRowsProcessed;"
                $command.CommandText = $batchQuery
                $reader = $command.ExecuteReader()

                $rowsProcessed = 0
                while ($reader.Read()) {
                    if (-not $headersWritten.Value) {
                        $columns = @()
                        if ($includeIOC) {
                            $columns += "IOC_Hit"
                        }
                        for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                            $columns += $reader.GetName($i)
                        }
                        $streamWriter.WriteLine(($columns -join ","))
                        $headersWritten.Value = $true
                    }

                    $row = @()
                    if ($includeIOC) {
                        $row += '"' + $reader["IOC_Hit"].ToString().Replace('"', '""') + '"'
                    }
                    for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                        $row += '"' + $reader.GetValue($i).ToString().Replace('"', '""') + '"'
                    }
                    $streamWriter.WriteLine(($row -join ","))
                    $rowsProcessed++
                }

                $totalRowsProcessed += $rowsProcessed
                $reader.Close()
            } while ($rowsProcessed -gt 0)
        }

        function Escape-SQLString {
            param (
                [string]$str
            )
            return $str -replace "'", "''" `
                         -replace '"', '""' `
                         -replace "`n", " " `
                         -replace "`r", " " `
                         -replace "`t", " " `
                         -replace "[^\x20-\x7E]", '' `
                         -replace "\\", "\\\\" ` # Escape backslashes
                         -replace "%", "[%]" `   # Escape percentage signs
                         -replace "_", "[_]" `   # Escape underscores
                         -replace "!", "[!]" `   # Escape exclamation marks
                         -replace "~", "[~]"     # Escape tildes
        }

        try {
            $connectionString = "Data Source=$DatabasePath;Version=3;"
            $sqliteConnection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
            $sqliteConnection.Open()

            $timestamp = Get-Date -Format "yyyy_MM_dd-HH_mm_ss"

            if ($findIOCs) {
                $IOCResultsFilePath = Join-Path $ArtifactsTimelineDir "$timestamp-IOC-hits.csv"

                # Open stream writer for exporting to CSV
                $IOCStreamWriter = [System.IO.StreamWriter]::new($IOCResultsFilePath)

                $headersWritten = $false

                # Build the combined IOC query for each column
                $iocConditions = @()
                $columns = @("event_description", "system_name", "user_name")
                foreach ($column in $columns) {
                    $columnConditions = @()
                    foreach ($IOC in $IOCs) {
                        $lowerIOC = $IOC.ToLower()
                        $escapedIOC = Escape-SQLString $lowerIOC  # Use the Escape-SQLString function to escape the IOC
                        $columnConditions += "LOWER($column) LIKE '%$escapedIOC%'"
                    }
                    $iocConditions += "(" + ($columnConditions -join " OR ") + ")"
                }

                $iocConditionString = $iocConditions -join " OR "
                $IOCQuery = @"
SELECT *, (CASE 
    $(foreach ($IOC in $IOCs) {
        $escapedIOC = Escape-SQLString $IOC.ToLower()
        "WHEN LOWER(event_description) LIKE '%$escapedIOC%' THEN '$escapedIOC'
         WHEN LOWER(system_name) LIKE '%$escapedIOC%' THEN '$escapedIOC'
         WHEN LOWER(user_name) LIKE '%$escapedIOC%' THEN '$escapedIOC'"
    }) ELSE ''
END) AS IOC_Hit FROM Artifacts WHERE 
($iocConditionString) $DateFilter
"@

                # Log the IOC terms and the resulting SQL query for debugging
                Write-Log "Searching for IOCs: $($IOCs -join ', ')"
                #Write-Log "SQL Query: $IOCQuery"

                # Process IOC hits in batches
                Process-DataInBatches -query $IOCQuery -filePath $IOCResultsFilePath -connection $sqliteConnection -streamWriter $IOCStreamWriter -headersWritten ([ref]$headersWritten) -includeIOC $true

                $IOCStreamWriter.Close()

                Write-Host "IOC hits export completed. CSV file saved to: $IOCResultsFilePath"
                Write-Log "IOC hits export completed. CSV file saved to: $IOCResultsFilePath"
            } else {
                $exportFilePath = Join-Path $ArtifactsTimelineDir "$timestamp-timeline.csv"
                
                # Create SQL query to fetch data, sorted by @timestamp in descending order
                $query = "SELECT * FROM Artifacts WHERE 1=1 $DateFilter ORDER BY [@timestamp] DESC"

                # Process data in batches
                $streamWriter = [System.IO.StreamWriter]::new($exportFilePath)
                $headersWritten = $false
                Process-DataInBatches -query $query -filePath $exportFilePath -connection $sqliteConnection -streamWriter $streamWriter -headersWritten ([ref]$headersWritten)

                $streamWriter.Close()

                Write-Host "Timeline export completed. CSV file saved to: $exportFilePath"
                Write-Log "Timeline export completed. CSV file saved to: $exportFilePath"
            }

            $sqliteConnection.Close()
        } catch {
            Write-Log "An unexpected error occurred during export: $_"
            Write-Host "An unexpected error occurred: $_"
        }
    } -ArgumentList $databasePath, $artifactsTimelineDir, $dateFilter, $assemblyPath, $logFilePath, $IOCs, $findIOCs

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Global:timelineexportJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "timelineexport_$timestamp"
        ArtifactPath = $artifactsTimelineDir
        DataAdded = $false
    }

    Update-Log "Timeline export job started." "ProcessSystemTextBox"
    $timelineexportJobTimer.Start()
}

function ProcessTimelineArtifactsButton_Click {
    param (
        [string[]]$SelectedTools
    )

    if (-not $sqlitePathTextBox.Text.Trim().Trim('"')) {
        [System.Windows.MessageBox]::Show("Please select the System.Data.SQLite.dll for the processing tool location.")
        return
    }
	
    if (-not (Load-SQLiteDLL)) {
        [System.Windows.MessageBox]::Show("Failed to load System.Data.SQLite.dll. Check the selected path and try again.")
        return
    }

	# Define paths
	$artifactsTimelineDir = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\ArtifactsTimeline'
	$databasePath = Join-Path $artifactsTimelineDir 'ArtifactsTimeline.db'
	$logFilePath = Join-Path $artifactsTimelineDir 'ArtifactsTimeline.log'
	$hashLogPath = Join-Path $artifactsTimelineDir 'ProcessedFilesHashes.log'
	$zimmermanToolsPath = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zimmermantools'
	$chainsawPath = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Chainsaw'
	$hayabusaPath = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Hayabusa'
	$zircolitePath = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zircolite'


    # Ensure the ArtifactsTimeline directory exists
    if (-not (Test-Path -Path $artifactsTimelineDir)) {
        New-Item -ItemType Directory -Path $artifactsTimelineDir -Force | Out-Null
    }

    # Load System.Data.SQLite assembly in the main script
    $assemblyPath = $sqlitePathTextBox.Text.Trim().Trim('"')

    # Function to convert JSON to Hashtable
    function ConvertTo-Hashtable {
        param (
            [PSCustomObject]$jsonObject
        )

        $hashtable = @{}
        foreach ($entry in $jsonObject) {
            $hashtable[$entry.Key] = $entry.Value
        }
        return $hashtable
    }

    # Start the process as a background job
    $job = Start-Job -ScriptBlock {
        param($SelectedTools, $DatabasePath, $LogFilePath, $HashLogPath, $ZimmermanToolsPath, $AssemblyPath, $chainsawPath, $hayabusaPath, $zircolitePath)

        # Load the assembly inside the job
        Add-Type -Path $AssemblyPath

        # Define the function inside the job
        function Process-TimelineArtifacts {
            param (
                [string[]]$SelectedTools,
                [string]$DatabasePath,
                [string]$LogFilePath,
                [string]$HashLogPath,
                [string]$ZimmermanToolsPath,
                [string]$chainsawPath,
                [string]$hayabusaPath,
                [string]$zircolitePath				
            )

            function Write-Log {
                param (
                    [string]$Message
                )
                $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $logMessage = "$timestamp - $Message"
                Add-Content -Path $LogFilePath -Value $logMessage
            }

            function Get-FileHash {
                param (
                    [string]$FilePath
                )
                $hasher = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $stream = [System.IO.File]::OpenRead($FilePath)
                    $hash = $hasher.ComputeHash($stream)
                    return [BitConverter]::ToString($hash) -replace '-', ''
                } catch {
                    Write-Log "Failed to access file $FilePath. Error: $_"
                    return $null
                } finally {
                    if ($stream) {
                        $stream.Close()
                    }
                    $hasher.Dispose()
                }
            }

            function Format-Timestamp {
                param (
                    [string]$timestamp
                )
                try {
                    $date = [DateTime]::Parse($timestamp)
                    return $date.ToString("yyyy-MM-dd HH:mm:ss.fffffff")
                } catch {
                    return $null
                }
            }

			function Escape-SQLString {
				param (
					[string]$str
				)
				return $str -replace "'", "''" -replace '"', '""' -replace "`n", " " -replace "`r", " " -replace "`t", " " -replace "[^\x20-\x7E]", '' # Escaping single quotes, double quotes, newlines, tabs, and removing non-printable characters
			}


            function ConvertTo-Hashtable {
                param (
                    [PSCustomObject]$jsonObject
                )

                $hashtable = @{}
                foreach ($entry in $jsonObject) {
                    $hashtable[$entry.Key] = $entry.Value
                }
                return $hashtable
            }
			Add-Type -AssemblyName Microsoft.VisualBasic
			
			function Process-CSVFile {
				param (
					[string]$filePath,
					[System.Data.SQLite.SQLiteConnection]$sqliteConnection,
					[string]$systemName,
					[string]$fileType,
					[string]$tool,
					[string[]]$columns,
					[string]$LogFilePath
				)

				$batchSize = 1000
				$batch = New-Object System.Collections.ArrayList
				$lineNumber = 0

				try {
					if ([string]::IsNullOrWhiteSpace($filePath)) {
						Write-Log "The file path is empty or null."
						return
					}
					if ([string]::IsNullOrWhiteSpace($LogFilePath)) {
						Write-Log "The log file path is empty or null."
						return
					}

					$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($filePath)
					$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
					$parser.SetDelimiters(",")

					# Read header
					$headers = $parser.ReadFields()

					while (-not $parser.EndOfData) {
						$values = $parser.ReadFields()
						$row = @{}

						for ($i = 0; $i -lt $headers.Length; $i++) {
							$row[$headers[$i]] = $values[$i]
						}

						# Prepare SQL command for the row
						$timestamp = ""
						$user_name = ""
						$event_description = ""
						$file_name = [System.IO.Path]::GetFileName($filePath)
						$source_file = $filePath

						if ($tool -eq 'Chainsaw') {
							$user_name = $row['User']
							$systemName = $row['Computer']
							$fileType = [System.IO.Path]::GetFileNameWithoutExtension($filePath)							

							$timestamp = $row['timestamp']
							
							# Regular expression to match the timestamp format and timezone offset
							if ($timestamp -match '^(.*)T(.*?)([+-]\d{2}):(\d{2})$') {
								$datePart = $matches[1]
								$timePart = $matches[2]
								$sign = $matches[3][0]
								$hoursOffset = [int]$matches[3].Substring(1, 2)
								$minutesOffset = [int]$matches[4]
								
								# Calculate total offset in minutes
								$totalOffsetMinutes = ($hoursOffset * 60) + $minutesOffset
								if ($sign -eq '-') {
									$totalOffsetMinutes = -$totalOffsetMinutes
								}
								
								# Combine date and time part
								$combinedDateTime = "$datePart $timePart"
								
								# Attempt to parse using multiple formats
								$dateTime = $null
								$formats = @(
									"yyyy-MM-dd HH:mm:ss.ffffff",
									"yyyy-MM-dd HH:mm:ss.fffff",
									"yyyy-MM-dd HH:mm:ss.fff",
									"yyyy-MM-dd HH:mm:ss.ff",
									"yyyy-MM-dd HH:mm:ss.f",
									"yyyy-MM-dd HH:mm:ss"
								)

								foreach ($format in $formats) {
									try {
										$dateTime = [DateTime]::ParseExact($combinedDateTime, $format, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
										break
									} catch {
										continue
									}
								}

								if ($dateTime -eq $null) {
									Write-Log "Failed to parse timestamp: $timestamp"
									continue
								}

								# Adjust the timestamp by the timezone offset
								$timestamp = $dateTime.AddMinutes(-$totalOffsetMinutes).ToString("yyyy-MM-dd HH:mm:ss.fffffff")
							} else {
								# If no timezone offset, just format the timestamp
								$timestamp = $timestamp -replace 'T', ' ' -replace '[+-].*', ''
							}
						if ($file_name -like 'powershell_script.csv') {	
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$Information = if ($row['Information'] -ne '') { Escape-SQLString $row['Information'] } else { '<empty_field>' }						
							$event_description = "Detection of $detections with information of $Information"
							}
						elseif ($file_name -like 'rdp_attacks.csv') {
							$user_name = $row['username']
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$ipaddress = if ($row['ip address'] -ne '') { Escape-SQLString $row['ip address'] } else { '<empty_field>' } 							
							$event_description = "$detections from IP address $ipaddress"
							}
						elseif ($file_name -like 'rdp_events.csv') {
							if ($row['Information'] -match 'User:\s*(.+)') {
								$user_name = $matches[1]
								}
								$event_description = $row['detections']								
							}
						elseif ($file_name -like 'antivirus.csv') {
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$ThreatName = if ($row['Threat Name'] -ne '') { Escape-SQLString $row['Threat Name'] } else { '<empty_field>' }
							$ThreatPath = if ($row['Threat Path'] -ne '') { Escape-SQLString $row['Threat Path'] } else { '<empty_field>' }
							$SHA1 = if ($row['SHA1'] -ne '') { Escape-SQLString $row['SHA1'] } else { '<empty_field>' }
 							$ThreatType = if ($row['Threat Type'] -ne '') { Escape-SQLString $row['Threat Type'] } else { '<empty_field>' }							
							$event_description = "$detections with threat name: $ThreatName threat path: $ThreatPath SHA1: $SHA1 and threat type: $ThreatType"
							}
						elseif ($file_name -like '*_user_profile_disk.csv') {
							if ($row['Information'] -match '\\Users\\([^\\]+)') {
								$user_name = $matches[1]
							}							
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$Information = if ($row['Information'] -ne '') { Escape-SQLString $row['Information'] } else { '<empty_field>' }						
							$event_description = "$detections from registry $Information"
							}
						elseif ($file_name -like 'login_attacks.csv') {
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$count = if ($row['count'] -ne '') { Escape-SQLString $row['count'] } else { '<empty_field>' }						
							$event_description = "$detections with $count failed logins"
							}
						elseif ($file_name -like 'lateral_movement.csv') {
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$IPAddress = if ($row['IP Address'] -ne '') { Escape-SQLString $row['IP Address'] } else { '<empty_field>' }							
							$LogonType = if ($row['Logon Type'] -ne '') { Escape-SQLString $row['Logon Type'] } else { '<empty_field>' }						
							$event_description = "$detections with type $LogonType from IP address $IPAddress"
							}
						elseif ($file_name -like 'sigma.csv') {
							$detections = if ($row['detections'] -ne '') { Escape-SQLString $row['detections'] } else { '<empty_field>' }
							$EventData = if ($row['Event Data'] -ne '') { Escape-SQLString $row['Event Data'] } else { '<empty_field>' }						
							$event_description = "$detections with event data of $EventData"
							}							
						else {
							$event_description = $row['detections']
							}
						}

						if ($tool -eq 'Hayabusa') {
							$systemName = $row['Computer']
							$fileType = $row['MitreTactics']							
							$event_description = $row['message']
							$timestamp = $row['datetime']
							
							# Regular expression to match the timestamp format and timezone offset
							if ($timestamp -match '^(.*) (.*?)([+-]\d{2}):(\d{2})$') {
								$datePart = $matches[1]
								$timePart = $matches[2]
								$sign = $matches[3][0]
								$hoursOffset = [int]$matches[3].Substring(1, 2)
								$minutesOffset = [int]$matches[4]
								
								# Calculate total offset in minutes
								$totalOffsetMinutes = ($hoursOffset * 60) + $minutesOffset
								if ($sign -eq '-') {
									$totalOffsetMinutes = -$totalOffsetMinutes
								}
								
								# Combine date and time part
								$combinedDateTime = "$datePart $timePart"
								
								# Attempt to parse using multiple formats
								$dateTime = $null
								$formats = @(
									"yyyy-MM-dd HH:mm:ss.ffffff",
									"yyyy-MM-dd HH:mm:ss.fffff",
									"yyyy-MM-dd HH:mm:ss.fff",
									"yyyy-MM-dd HH:mm:ss.ff",
									"yyyy-MM-dd HH:mm:ss.f",
									"yyyy-MM-dd HH:mm:ss"
								)

								foreach ($format in $formats) {
									try {
										$dateTime = [DateTime]::ParseExact($combinedDateTime, $format, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
										break
									} catch {
										continue
									}
								}

								if ($dateTime -eq $null) {
									Write-Log "Failed to parse timestamp: $timestamp"
									continue
								}

								# Adjust the timestamp by the timezone offset
								$timestamp = $dateTime.AddMinutes(-$totalOffsetMinutes).ToString("yyyy-MM-dd HH:mm:ss.fffffff")
								} else {
								# If no timezone offset, just format the timestamp
								$timestamp = $timestamp -replace 'T', ' ' -replace '[+-].*', ''
								}
							$Details = if ($row['Details'] -ne '') { Escape-SQLString $row['Details'] } else { '<empty_field>' }							
							$message = if ($row['message'] -ne '') { Escape-SQLString $row['message'] } else { '<empty_field>' }						
							$event_description = "$message with details of $Details"							
							
						}

						if ($tool -eq 'Zircolite') {
						$user_name = $row['User']
						$systemName = $row['Computer']
						$timestamp = $row['SystemTime']
						
						# Regular expression to match the timestamp format with 'Z' indicating UTC time
						if ($timestamp -match '^(.*)T(.*)Z$') {
							$datePart = $matches[1]
							$timePart = $matches[2]
							
							# Combine date and time part
							$combinedDateTime = "$datePart $timePart"
							
							# Attempt to parse using multiple formats
							$dateTime = $null
							$formats = @(
								"yyyy-MM-dd HH:mm:ss.ffffff",
								"yyyy-MM-dd HH:mm:ss.fffff",
								"yyyy-MM-dd HH:mm:ss.fff",
								"yyyy-MM-dd HH:mm:ss.ff",
								"yyyy-MM-dd HH:mm:ss.f",
								"yyyy-MM-dd HH:mm:ss"
							)

							foreach ($format in $formats) {
								try {
									$dateTime = [DateTime]::ParseExact($combinedDateTime, $format, $null, [System.Globalization.DateTimeStyles]::AssumeUniversal)
									break
								} catch {
									continue
								}
							}

							if ($dateTime -eq $null) {
								Write-Log "Failed to parse timestamp: $timestamp"
								continue
							}

							# Format the timestamp in the desired format
							$timestamp = $dateTime.ToString("yyyy-MM-dd HH:mm:ss.fffffff")
						} else {
							# If the format does not match, log an error
							Write-Log "Invalid SystemTime format: $timestamp"
							continue
						}
						if ($file_name -like '*Application_zircolite.csv') {	
							$user_name = $row['UserID']						
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							$Message = if ($row['Message'] -ne '') { Escape-SQLString $row['Message'] } else { '<empty_field>' }						
							$event_description = "$rule_title with message $Message"
							}
						elseif ($file_name -like '*Microsoft-Windows-ServerManager-MgmtProvider*.csv') {
							$user_name = $row['UserID']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							$Guid = if ($row['Guid'] -ne '') { Escape-SQLString $row['Guid'] } else { '<empty_field>' } 							
							$event_description = "$rule_title with Guid of $Guid"
							}
						elseif ($file_name -like '*Microsoft-Windows-TerminalServices-LocalSessionManager*.csv') {
							$user_name = $row['User']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							# Drop the row if rule_title matches "WMI Event Subscription"
							if ($rule_title -eq 'WMI Event Subscription') {
								continue
							}							
							$event_description = "$rule_title"
							}	
						elseif ($file_name -like '*Microsoft-Windows-Windows Firewall With Advanced Security*.csv') {
							$user_name = $row['UserID']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							$ModifyingUser = if ($row['ModifyingUser'] -ne '') { Escape-SQLString $row['ModifyingUser'] } else { '<empty_field>' }
							$RuleName = if ($row['RuleName'] -ne '') { Escape-SQLString $row['RuleName'] } else { '<empty_field>' }
							$ApplicationPath = if ($row['ApplicationPath'] -ne '') { Escape-SQLString $row['ApplicationPath'] } else { '<empty_field>' }
							$ModifyingApplication = if ($row['ModifyingApplication'] -ne '') { Escape-SQLString $row['ModifyingApplication'] } else { '<empty_field>' }
							$event_description = "$rule_title with modifying user: $ModifyingUser Rule Name: $RuleName Application Path: $ApplicationPath Modifying Application: $ModifyingApplication"
							}
						elseif ($file_name -like '*_OpenSSH*.csv') {
							$user_name = $row['UserID']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							$Guid = if ($row['Guid'] -ne '') { Escape-SQLString $row['Guid'] } else { '<empty_field>' } 							
							$event_description = "$rule_title with Guid of $Guid"
							}
						elseif ($file_name -like '*_Security*.csv') {
							$user_name = $row['TargetUserName']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }							
							$event_description = "$rule_title"
							}
						elseif ($file_name -like '*_Symantec Endpoint Protection*.csv') {
							$user_name = $row['UserID']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							$Message = if ($row['Message'] -ne '') { Escape-SQLString $row['Message'] } else { '<empty_field>' } 							
							$event_description = "$rule_title with Message of $Message"
							}
						elseif ($file_name -like '*_System*.csv') {
							$user_name = $row['UserID']	
							$rule_title = if ($row['rule_title'] -ne '') { Escape-SQLString $row['rule_title'] } else { '<empty_field>' }
							if ($rule_title -eq 'WMI Event Subscription') {
								continue
							}							
							$event_description = "$rule_title"
							}							
						else {
							$event_description = $row['rule_title']
							}
						$rule_level = if ($row['rule_level'] -ne '') { Escape-SQLString $row['rule_level'] } else { '<empty_field>' }						$fileType = "Zircolite level of $rule_level"					
						}
					
						# Specific mappings for Zimmermantools
						if ($file_name -like '*EvtxECmd_Output.csv') {
							$timestamp = $row['TimeCreated']
							$user_name = Escape-SQLString -str $row['UserName']
							$MapDescription = if ($row['MapDescription'] -ne '') { Escape-SQLString $row['MapDescription'] } else { '<empty_field>' }
							$RemoteHost = if ($row['RemoteHost'] -ne '') { Escape-SQLString $row['RemoteHost'] } else { '<empty_field>' }
							$PayloadData1 = if ($row['PayloadData1'] -ne '') { Escape-SQLString $row['PayloadData1'] } else { '<empty_field>' }
							$PayloadData2 = if ($row['PayloadData2'] -ne '') { Escape-SQLString $row['PayloadData2'] } else { '<empty_field>' }
							$PayloadData3 = if ($row['PayloadData3'] -ne '') { Escape-SQLString $row['PayloadData3'] } else { '<empty_field>' }
							$PayloadData4 = if ($row['PayloadData4'] -ne '') { Escape-SQLString $row['PayloadData4'] } else { '<empty_field>' }
							$PayloadData5 = if ($row['PayloadData5'] -ne '') { Escape-SQLString $row['PayloadData5'] } else { '<empty_field>' }
							$PayloadData6 = if ($row['PayloadData6'] -ne '') { Escape-SQLString $row['PayloadData6'] } else { '<empty_field>' }
							$ExecutableInfo = if ($row['ExecutableInfo'] -ne '') { Escape-SQLString $row['ExecutableInfo'] } else { '<empty_field>' }
							$event_description = "Map Description $MapDescription with PayloadData1: $PayloadData1 Data2: $PayloadData2 Data3: $PayloadData3 Data4: $PayloadData4 Data5: $PayloadData5 Data6: $PayloadData6 Executable Info: $ExecutableInfo RemoteHost: $RemoteHost"
						}
						elseif ($file_name -like '*_Amcache_*.csv') {
							$timestamp = $row['FileKeyLastWriteTimestamp']
							if (-not $timestamp) {
								$timestamp = $row['KeyLastWriteTimestamp']
							}
							# Create event_description based on columns
							if ($row.ContainsKey('Name') -and $row.ContainsKey('FullPath') -and $row.ContainsKey('SHA1')) {
								$Name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }
								$FullPath = if ($row['FullPath'] -ne '') { Escape-SQLString $row['FullPath'] } else { '<empty_field>' }
								$SHA1 = if ($row['SHA1'] -ne '') { Escape-SQLString $row['SHA1'] } else { '<empty_field>' }
								$event_description = "Program $Name was executed at full path $FullPath with SHA1 of $SHA1"
							}
							elseif ($row.ContainsKey('Categories') -and $row.ContainsKey('IsActive') -and $row.ContainsKey('IsConnected') -and $row.ContainsKey('ModelName')) {
								$categories = if ($row['Categories'] -ne '') { Escape-SQLString $row['Categories'] } else { '<empty_field>' }
								$isActive = if ($row['IsActive'] -ne '') { Escape-SQLString $row['IsActive'] } else { '<empty_field>' }
								$isConnected = if ($row['IsConnected'] -ne '') { Escape-SQLString $row['IsConnected'] } else { '<empty_field>' }
								$modelName = if ($row['ModelName'] -ne '') { Escape-SQLString $row['ModelName'] } else { '<empty_field>' }
								$event_description = "Last write time of $categories with Active as $isActive and connected as $isConnected with a model name of $modelName"
							}
							elseif ($row.ContainsKey('KeyName') -and $row.ContainsKey('Class') -and $row.ContainsKey('Description') -and $row.ContainsKey('Manufacturer')) {
								$keyName = if ($row['KeyName'] -ne '') { Escape-SQLString $row['KeyName'] } else { '<empty_field>' }
								$class = if ($row['Class'] -ne '') { Escape-SQLString $row['Class'] } else { '<empty_field>' }
								$description = if ($row['Description'] -ne '') { Escape-SQLString $row['Description'] } else { '<empty_field>' }
								$manufacturer = if ($row['Manufacturer'] -ne '') { Escape-SQLString $row['Manufacturer'] } else { '<empty_field>' }
								$event_description = "Last write time of KeyName $keyName with Class $class and description $description with a Manufacturer name of $manufacturer"
							}
							elseif ($row.ContainsKey('KeyName') -and $row.ContainsKey('DriverName') -and $row.ContainsKey('DriverCompany') -and $row.ContainsKey('Product') -and $row.ContainsKey('ProductVersion')) {
								$keyName = if ($row['KeyName'] -ne '') { Escape-SQLString $row['KeyName'] } else { '<empty_field>' }
								$driverName = if ($row['DriverName'] -ne '') { Escape-SQLString $row['DriverName'] } else { '<empty_field>' }
								$driverCompany = if ($row['DriverCompany'] -ne '') { Escape-SQLString $row['DriverCompany'] } else { '<empty_field>' }
								$product = if ($row['Product'] -ne '') { Escape-SQLString $row['Product'] } else { '<empty_field>' }
								$productVersion = if ($row['ProductVersion'] -ne '') { Escape-SQLString $row['ProductVersion'] } else { '<empty_field>' }
								$event_description = "Last write time of Driver Binary KeyName $keyName with Driver Name $driverName and DriverCompany $driverCompany, Product name of $product version $productVersion"
							}
							elseif ($row.ContainsKey('Name') -and $row.ContainsKey('Version') -and $row.ContainsKey('InstallDate') -and $row.ContainsKey('RootDirPath') -and $row.ContainsKey('UninstallString')) {
								$name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }
								$version = if ($row['Version'] -ne '') { Escape-SQLString $row['Version'] } else { '<empty_field>' }
								$installDate = if ($row['InstallDate'] -ne '') { Escape-SQLString $row['InstallDate'] } else { '<empty_field>' }
								$rootDirPath = if ($row['RootDirPath'] -ne '') { Escape-SQLString $row['RootDirPath'] } else { '<empty_field>' }
								$uninstallString = if ($row['UninstallString'] -ne '') { Escape-SQLString $row['UninstallString'] } else { '<empty_field>' }
								$event_description = "Last write program entry for $name version $version and Install Date $installDate, with a RootDirPath of $rootDirPath and UninstallString of $uninstallString"
							}
							elseif ($row.ContainsKey('KeyName') -and $row.ContainsKey('Class') -and $row.ContainsKey('Directory') -and $row.ContainsKey('DriverInBox') -and $row.ContainsKey('Hwids') -and $row.ContainsKey('Provider') -and $row.ContainsKey('Version')) {
								$keyName = if ($row['KeyName'] -ne '') { Escape-SQLString $row['KeyName'] } else { '<empty_field>' }
								$directory = if ($row['Directory'] -ne '') { Escape-SQLString $row['Directory'] } else { '<empty_field>' }
								$provider = if ($row['Provider'] -ne '') { Escape-SQLString $row['Provider'] } else { '<empty_field>' }
								$version = if ($row['Version'] -ne '') { Escape-SQLString $row['Version'] } else { '<empty_field>' }
								$event_description = "Last write time of sysfile $keyName within directory $directory and provider $provider version $version"
							}
							elseif ($row.ContainsKey('KeyName') -and $row.ContainsKey('LnkName') -and $row.ContainsKey('KeyLastWriteTimestamp')) {
								$keyName = if ($row['KeyName'] -ne '') { Escape-SQLString $row['KeyName'] } else { '<empty_field>' }
								$lnkName = if ($row['LnkName'] -ne '') { Escape-SQLString $row['LnkName'] } else { '<empty_field>' }
								$event_description = "Last write time of shortcut file $keyName with Lnk name of $lnkName"
							}
						}
						elseif ($file_name -like '*AppCompatCache.csv') {
							$timestamp = $row['LastModifiedTimeUTC']
							$path = if ($row['Path'] -ne '') { Escape-SQLString $row['Path'] } else { '<empty_field>' }
							$executed = if ($row['Executed'] -ne '') { Escape-SQLString $row['Executed'] } else { '<empty_field>' }
							$event_description = "Last modified Program at path $path showing executed flag as $executed"
						}
						elseif ($file_name -like '*_SrumECmd_AppResourceUseInfo*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$userName = if ($row['UserName'] -ne '') { Escape-SQLString $row['UserName'] } else { '<empty_field>' }
							$exeInfo = if ($row['ExeInfo'] -ne '') { Escape-SQLString $row['ExeInfo'] } else { '<empty_field>' }
							$backgroundBytesWritten = if ($row['BackgroundBytesWritten'] -ne '') { Escape-SQLString $row['BackgroundBytesWritten'] } else { '<empty_field>' }
							$foregroundBytesWritten = if ($row['ForegroundBytesWritten'] -ne '') { Escape-SQLString $row['ForegroundBytesWritten'] } else { '<empty_field>' }
							$event_description = "Srum App Resource Usage shows executable $exeInfo having background bytes written of $backgroundBytesWritten and foreground bytes written as $foregroundBytesWritten by user $userName"
						}
						elseif ($file_name -like '*_SrumECmd_AppTimelineProvider*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$userName = if ($row['UserName'] -ne '') { Escape-SQLString $row['UserName'] } else { '<empty_field>' }
							$exeInfo = if ($row['ExeInfo'] -ne '') { Escape-SQLString $row['ExeInfo'] } else { '<empty_field>' }
							$ExeTimestamp = if ($row['ExeTimestamp'] -ne '') { Escape-SQLString $row['ExeTimestamp'] } else { '<empty_field>' }
							$EndTime = if ($row['EndTime'] -ne '') { Escape-SQLString $row['EndTime'] } else { '<empty_field>' }
							$DurationMs = if ($row['DurationMs'] -ne '') { Escape-SQLString $row['DurationMs'] } else { '<empty_field>' }
							$event_description = "Srum App Timeline Provider shows executable $exeInfo having a timestamp of $ExeTimestamp, an Endtime of $EndTime, and duration of $DurationMs Ms by user $userName"
						}
						elseif ($file_name -like '*_SrumECmd_NetworkUsages*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$userName = if ($row['UserName'] -ne '') { Escape-SQLString $row['UserName'] } else { '<empty_field>' }
							$exeInfo = if ($row['ExeInfo'] -ne '') { Escape-SQLString $row['ExeInfo'] } else { '<empty_field>' }
							$bytesReceived = if ($row['BytesReceived'] -ne '') { Escape-SQLString $row['BytesReceived'] } else { '<empty_field>' }
							$bytesSent = if ($row['BytesSent'] -ne '') { Escape-SQLString $row['BytesSent'] } else { '<empty_field>' }
							$event_description = "Srum Network Usage shows executable $exeInfo having bytes received as $bytesReceived and bytes sent as $bytesSent by user $userName"
						}
						elseif ($file_name -like '*_SrumECmd_EnergyUsage*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$event_description = 'Srum Energy Usage'
						}
						elseif ($file_name -like '*_SrumECmd_NetworkConnections*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$event_description = 'Srum Network Connections'
						}
						elseif ($file_name -like '*_SrumECmd_PushNotifications*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$userName = if ($row['UserName'] -ne '') { Escape-SQLString $row['UserName'] } else { '<empty_field>' }
							$exeInfo = if ($row['ExeInfo'] -ne '') { Escape-SQLString $row['ExeInfo'] } else { '<empty_field>' }
							$exeInfoDescription = if ($row['ExeInfoDescription'] -ne '') { Escape-SQLString $row['ExeInfoDescription'] } else { '<empty_field>' }
							$event_description = "Srum Push Notification of $exeInfo with description $exeInfoDescription"
						}
						elseif ($file_name -like '*_SrumECmd_vfuprov*.csv') {
							$timestamp = $row['Timestamp']
							$user_name = $row['UserName']
							$event_description = 'Srum vfuprov information'
						}
						elseif ($file_name -like '*_RBCmd_*.csv') {
							$timestamp = $row['DeletedOn']
							$FileName = if ($row['FileName'] -ne '') { Escape-SQLString $row['FileName'] } else { '<empty_field>' }
							$event_description = "The file $FileName was deleted"
						}
						elseif ($file_name -like '*_AutomaticDestinations.csv') {
							$timestamp = $row['LastModified']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}
							$TargetIDAbsolutePath = if ($row['TargetIDAbsolutePath'] -ne '') { Escape-SQLString $row['TargetIDAbsolutePath'] } else { '<empty_field>' }
							$Arguments = if ($row['Arguments'] -ne '') { Escape-SQLString $row['Arguments'] } else { '<empty_field>' }
							$exeInfoDescription = if ($row['ExeInfoDescription'] -ne '') { Escape-SQLString $row['ExeInfoDescription'] } else { '<empty_field>' }
							$event_description = "Automatic Destinations last modified date of target ID $TargetIDAbsolutePath and arguments $Arguments"
						}
						elseif ($file_name -like '*_CustomDestinations.csv') {
							$timestamp = $row['SourceModified']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}
							$TargetIDAbsolutePath = if ($row['TargetIDAbsolutePath'] -ne '') { Escape-SQLString $row['TargetIDAbsolutePath'] } else { '<empty_field>' }
							$Arguments = if ($row['Arguments'] -ne '') { Escape-SQLString $row['Arguments'] } else { '<empty_field>' }
							$exeInfoDescription = if ($row['ExeInfoDescription'] -ne '') { Escape-SQLString $row['ExeInfoDescription'] } else { '<empty_field>' }
							$event_description = "Custom Destinations source modified date of target ID $TargetIDAbsolutePath and arguments $Arguments"
						}
						elseif ($file_name -like '*_LECmd_Output.csv') {
							$timestamp = $row['SourceModified']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}
							$TargetIDAbsolutePath = if ($row['TargetIDAbsolutePath'] -ne '') { Escape-SQLString $row['TargetIDAbsolutePath'] } else { '<empty_field>' }
							$NetworkPath = if ($row['NetworkPath'] -ne '') { Escape-SQLString $row['NetworkPath'] } else { '<empty_field>' }
							$exeInfoDescription = if ($row['ExeInfoDescription'] -ne '') { Escape-SQLString $row['ExeInfoDescription'] } else { '<empty_field>' }
							$event_description = "LNK file source modified date of target ID $TargetIDAbsolutePath and NetworkPath $NetworkPath"
						}
						elseif ($file_name -like '*_NTUSER.csv') {
							$timestamp = $row['LastWriteTime']
							if ($file_name -match '^(.*)_NTUSER\.csv$') {
								$user_name = $matches[1]
							}
							$AbsolutePath = if ($row['AbsolutePath'] -ne '') { Escape-SQLString $row['AbsolutePath'] } else { '<empty_field>' }
							$ShellType = if ($row['ShellType'] -ne '') { Escape-SQLString $row['ShellType'] } else { '<empty_field>' }
							$FirstInteracted = if ($row['FirstInteracted'] -ne '') { Escape-SQLString $row['FirstInteracted'] } else { '<empty_field>' }
							$LastInteracted = if ($row['LastInteracted'] -ne '') { Escape-SQLString $row['LastInteracted'] } else { '<empty_field>' }
							$event_description = "Shellbag Last Write of $AbsolutePath with type $ShellType First Interactred $FirstInteracted and Last Interacted $LastInteracted"
						}
						elseif ($file_name -like '*_UsrClass.csv') {
							$timestamp = $row['LastWriteTime']
							if ($file_name -match '^(.*)_UsrClass\.csv$') {
								$user_name = $matches[1]
							}
							$AbsolutePath = if ($row['AbsolutePath'] -ne '') { Escape-SQLString $row['AbsolutePath'] } else { '<empty_field>' }
							$ShellType = if ($row['ShellType'] -ne '') { Escape-SQLString $row['ShellType'] } else { '<empty_field>' }
							$FirstInteracted = if ($row['FirstInteracted'] -ne '') { Escape-SQLString $row['FirstInteracted'] } else { '<empty_field>' }
							$LastInteracted = if ($row['LastInteracted'] -ne '') { Escape-SQLString $row['LastInteracted'] } else { '<empty_field>' }
							$event_description = "Shellbag Last Write of $AbsolutePath with type $ShellType First Interactred $FirstInteracted and Last Interacted $LastInteracted"
						}
						elseif ($file_name -like '*_Activity.csv') {
							$timestamp = $row['LastModifiedTime']
							if ($file_name -match '^\d+_(.+)_Activity\.csv$') {
								$user_name = $matches[1]
							}
							$Executable = if ($row['Executable'] -ne '') { Escape-SQLString $row['Executable'] } else { '<empty_field>' }
							$Payload = if ($row['Payload'] -ne '') { Escape-SQLString $row['Payload'] } else { '<empty_field>' }
							$StartTime = if ($row['StartTime'] -ne '') { Escape-SQLString $row['StartTime'] } else { '<empty_field>' }
							$event_description = "Last Modified Time of activity related to executable $Executable with payload $Payload and start time $StartTime"
						}						
						elseif ($file_name -like '*_Activity_PackageIDs.csv') {
							if ($file_name -match '^\d+_(.+)_Activity_PackageIDs\.csv$') {
								$user_name = $matches[1]
							}
							$Id = if ($row['Id'] -ne '') { Escape-SQLString $row['Id'] } else { '<empty_field>' }							
							$Platform = if ($row['Platform'] -ne '') { Escape-SQLString $row['Platform'] } else { '<empty_field>' }
							$Name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }
							$Expires = if ($row['Expires'] -ne '') { Escape-SQLString $row['Expires'] } else { '<empty_field>' }							
							$event_description = "Activity Package ID $Id Platform $Platform  Name $Name Expires $Expires"
						}
						elseif ($file_name -like '*_SumECmd_DETAIL_Clients_Output.csv') {
							$timestamp = $row['LastAccess']
							$user_name = $row['AuthenticatedUserName']
							$InsertDate = if ($row['InsertDate'] -ne '') { Escape-SQLString $row['InsertDate'] } else { '<empty_field>' }
							$IpAddress = if ($row['IpAddress'] -ne '') { Escape-SQLString $row['IpAddress'] } else { '<empty_field>' }
							$TotalAccesses = if ($row['TotalAccesses'] -ne '') { Escape-SQLString $row['TotalAccesses'] } else { '<empty_field>' }
							$event_description = "Last Access date from IP Address $IpAddress with total access $TotalAccesses and Insert Date of $InsertDate"
						}
						elseif ($file_name -like '*_SumECmd_DETAIL_ClientsDetailed_Output.csv') {
							$timestamp = $row['LastAccess']
							$user_name = $row['AuthenticatedUserName']
							$InsertDate = if ($row['InsertDate'] -ne '') { Escape-SQLString $row['InsertDate'] } else { '<empty_field>' }
							$IpAddress = if ($row['IpAddress'] -ne '') { Escape-SQLString $row['IpAddress'] } else { '<empty_field>' }
							$TotalAccesses = if ($row['TotalAccesses'] -ne '') { Escape-SQLString $row['TotalAccesses'] } else { '<empty_field>' }
							$LastAccess = if ($row['LastAccess'] -ne '') { Escape-SQLString $row['LastAccess'] } else { '<empty_field>' }
							$event_description = "Last Access from IP Address $IpAddress with total access $TotalAccesses and Insert Date of $InsertDate"
						}
						elseif ($file_name -like '*_SumECmd_DETAIL_RoleAccesses_Output.csv') {
							$timestamp = $row['LastSeen']
							$RoleDescription = if ($row['RoleDescription'] -ne '') { Escape-SQLString $row['RoleDescription'] } else { '<empty_field>' }
							$FirstSeen = if ($row['FirstSeen'] -ne '') { Escape-SQLString $row['FirstSeen'] } else { '<empty_field>' }
							$event_description = "Last seen role of $RoleDescription with first seen of $FirstSeen"
						}
						elseif ($file_name -like '*_SumECmd_SUMMARY_ChainedDbInfo_Output.csv') {							
							$Year = if ($row['Year'] -ne '') { Escape-SQLString $row['Year'] } else { '<empty_field>' }
							$FileName = if ($row['FileName'] -ne '') { Escape-SQLString $row['FileName'] } else { '<empty_field>' }
							$event_description = "SUM Chained Db info with year $Year and FileName $FileName"
						}
						elseif ($file_name -like '*_SumECmd_SUMMARY_RoleInfos_Output.csv') {
							$RoleName = if ($row['RoleName'] -ne '') { Escape-SQLString $row['RoleName'] } else { '<empty_field>' }
							$RoleGuid = if ($row['RoleGuid'] -ne '') { Escape-SQLString $row['RoleGuid'] } else { '<empty_field>' }
							$event_description = "SUM Role Information with Role Guid $RoleGuid linked to Role Name $RoleName"
						}
						elseif ($file_name -like '*_SumECmd_SUMMARY_SystemIdentInfo_Output.csv') {
							$timestamp = $row['CreationTime']							
							$OsMajor = if ($row['OsMajor'] -ne '') { Escape-SQLString $row['OsMajor'] } else { '<empty_field>' }
							$OsMinor = if ($row['OsMinor'] -ne '') { Escape-SQLString $row['OsMinor'] } else { '<empty_field>' }
							$OsBuild = if ($row['OsBuild'] -ne '') { Escape-SQLString $row['OsBuild'] } else { '<empty_field>' }
							$event_description = "Creation time of SUM System Identification Information with Os Major: $OsMajor Minor: $OsMinor and Build: $OsBuild"
						}
						elseif ($file_name -like '*_MFTECmd_$J_Output.csv') {
							$timestamp = $row['UpdateTimestamp']
							$Name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }
							$ParentPath = if ($row['ParentPath'] -ne '') { Escape-SQLString $row['ParentPath'] } else { '<empty_field>' }
							$UpdateReasons = if ($row['UpdateReasons'] -ne '') { Escape-SQLString $row['UpdateReasons'] } else { '<empty_field>' }
							$event_description = "$($ParentPath)\$($Name) updated with reason $UpdateReasons"
						}
						elseif ($file_name -like '*_MFTECmd_$MFT_Output.csv') {
							$timestamp = $row['Created0x10']
							$FileName = if ($row['FileName'] -ne '') { Escape-SQLString $row['FileName'] } else { '<empty_field>' }
							$ParentPath = if ($row['ParentPath'] -ne '') { Escape-SQLString $row['ParentPath'] } else { '<empty_field>' }
							$InUse = if ($row['InUse'] -ne '') { Escape-SQLString $row['InUse'] } else { '<empty_field>' }							
							$SIFN = if ($row['SI<FN'] -ne '') { Escape-SQLString $row['SI<FN'] } else { '<empty_field>' }
							$event_description = "$($ParentPath)\$($FileName) created with In use: $InUse and SI<FN: $SIFN"
						}
						elseif ($file_name -like '*_Windows_ActivityPackageId_*.csv') {
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$ActivityId = if ($row['ActivityId'] -ne '') { Escape-SQLString $row['ActivityId'] } else { '<empty_field>' }							
							$Platform = if ($row['Platform'] -ne '') { Escape-SQLString $row['Platform'] } else { '<empty_field>' }
							$ExpirationTime = if ($row['ExpirationTime'] -ne '') { Escape-SQLString $row['ExpirationTime'] } else { '<empty_field>' }
							$event_description = "Activity ID $ActivityId with Platform $Platform and expiration time $ExpirationTime"
						}
						elseif ($file_name -like '*_Windows_ActivitiesCacheDB_*.csv') {
							$timestamp = $row['LastModifiedTime']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$Id = if ($row['Id'] -ne '') { Escape-SQLString $row['Id'] } else { '<empty_field>' }
							$StartTime = if ($row['StartTime'] -ne '') { Escape-SQLString $row['StartTime'] } else { '<empty_field>' }
							$EndTime = if ($row['EndTime'] -ne '') { Escape-SQLString $row['EndTime'] } else { '<empty_field>' }							
							$event_description = "Last Modified time of Id $Id with Start Time $StartTime and End Time $EndTime"
						}
						elseif ($file_name -like '*_Windows_ActivityOperation_*.csv') {
							$timestamp = $row['LastModifiedTime']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$AppId = if ($row['AppId'] -ne '') { Escape-SQLString $row['AppId'] } else { '<empty_field>' }
							$CreatedTime = if ($row['CreatedTime'] -ne '') { Escape-SQLString $row['CreatedTime'] } else { '<empty_field>' }
							$EndTime = if ($row['EndTime'] -ne '') { Escape-SQLString $row['EndTime'] } else { '<empty_field>' }							
							$event_description = "Last Modified time of AppId $AppId with Created Time $CreatedTime and End Time $EndTime"
						}						
						elseif ($file_name -like '*_ChromiumBrowser_HistoryVisits_*.csv') {
							$timestamp = $row['VisitTime (Local)']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$URL = if ($row['URL'] -ne '') { Escape-SQLString $row['URL'] } else { '<empty_field>' }
							$URLTitle = if ($row['URLTitle'] -ne '') { Escape-SQLString $row['URLTitle'] } else { '<empty_field>' }
							$VisitCount = if ($row['VisitCount'] -ne '') { Escape-SQLString $row['VisitCount'] } else { '<empty_field>' }							
							$event_description = "Visit time of URL $URL with Title $URLTitle and Visit Count of $VisitCount"
						}
						elseif ($file_name -like '*_ChromiumBrowser_AutofillEntries_*.csv') {
							$timestamp = $row['LastUsed']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$Name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }
							$Value = if ($row['Value'] -ne '') { Escape-SQLString $row['Value'] } else { '<empty_field>' }
							$DateCreated = if ($row['DateCreated'] -ne '') { Escape-SQLString $row['DateCreated'] } else { '<empty_field>' }
							$Count = if ($row['Count'] -ne '') { Escape-SQLString $row['Count'] } else { '<empty_field>' }
							$event_description = "Last Used Autofill Entry of $Name with value $Value created $DateCreated and count $Count"
						}	
						elseif ($file_name -like '*_ChromiumBrowser_Cookies_*.csv') {
							$timestamp = $row['LastAccessUTC']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$CreationUTC = if ($row['CreationUTC'] -ne '') { Escape-SQLString $row['CreationUTC'] } else { '<empty_field>' }
							$HostKey = if ($row['HostKey'] -ne '') { Escape-SQLString $row['HostKey'] } else { '<empty_field>' }
							$Name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }	
							$Path = if ($row['Path'] -ne '') { Escape-SQLString $row['Path'] } else { '<empty_field>' }								
							$event_description = "Last Access of Cookie with Host Key $HostKey and name $Name at Path $Path"
						}	
						elseif ($file_name -like '*_ChromiumBrowser_Downloads_*.csv') {
							$timestamp = $row['StartTime']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$TargetPath = if ($row['TargetPath'] -ne '') { Escape-SQLString $row['TargetPath'] } else { '<empty_field>' }
							$State = if ($row['State'] -ne '') { Escape-SQLString $row['State'] } else { '<empty_field>' }
							$DownloadURL = if ($row['DownloadURL'] -ne '') { Escape-SQLString $row['DownloadURL'] } else { '<empty_field>' }
							$ReferrerURL = if ($row['ReferrerURL'] -ne '') { Escape-SQLString $row['ReferrerURL'] } else { '<empty_field>' }
							$event_description = "Download $State for target file $TargetPath from Download URL $DownloadURL and Referrer URL $ReferrerURL"
						}	
						elseif ($file_name -like '*_ChromiumBrowser_Favicons_*.csv') {
							$timestamp = $row['LastUpdated']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$PageURL = if ($row['PageURL'] -ne '') { Escape-SQLString $row['PageURL'] } else { '<empty_field>' }
							$FaviconURL = if ($row['FaviconURL'] -ne '') { Escape-SQLString $row['FaviconURL'] } else { '<empty_field>' }						
							$event_description = "Last Update for Favicon URL $FaviconURL for Page URL $PageURL Last Updated"
						}
						elseif ($file_name -like '*_ChromiumBrowser_OmniboxShortcuts_*.csv') {
							$timestamp = $row['LastAccessTime']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$TextTyped = if ($row['TextTyped'] -ne '') { Escape-SQLString $row['TextTyped'] } else { '<empty_field>' }
							$FillIntoEdit = if ($row['FillIntoEdit'] -ne '') { Escape-SQLString $row['FillIntoEdit'] } else { '<empty_field>' }
							$URL = if ($row['URL'] -ne '') { Escape-SQLString $row['URL'] } else { '<empty_field>' }
							$Contents = if ($row['Contents'] -ne '') { Escape-SQLString $row['Contents'] } else { '<empty_field>' }							
							$event_description = "Last Access of Text Typed $TextTyped Fill Into Edit $FillIntoEdit with URL $URL and Contents $Contents"
						}
						elseif ($file_name -like '*_ChromiumBrowser_KeywordSearches_*.csv') {
							$timestamp = $row['LastVisitTime']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$KeywordSearchTerm = if ($row['KeywordSearchTerm'] -ne '') { Escape-SQLString $row['KeywordSearchTerm'] } else { '<empty_field>' }
							$Title = if ($row['Title'] -ne '') { Escape-SQLString $row['Title'] } else { '<empty_field>' }
							$URL = if ($row['URL'] -ne '') { Escape-SQLString $row['URL'] } else { '<empty_field>' }						
							$event_description = "Last Visit of Keyword Search Term $KeywordSearchTerm with Title $Title and URL $URL"
						}						
						elseif ($file_name -like '*_ChromiumBrowser_NetworkActionPredictor_*.csv') {
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$UserText = if ($row['UserText'] -ne '') { Escape-SQLString $row['UserText'] } else { '<empty_field>' }
							$URL = if ($row['URL'] -ne '') { Escape-SQLString $row['URL'] } else { '<empty_field>' }						
							$event_description = "Network Action Predictor from User Text of $UserText at URL $URL"
						}
						elseif ($file_name -like '*_Firefox_Bookmarks_*.csv') {
							$timestamp = $row['LastModified']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$DateAdded = if ($row['DateAdded'] -ne '') { Escape-SQLString $row['DateAdded'] } else { '<empty_field>' }
							$Type = if ($row['Type'] -ne '') { Escape-SQLString $row['Type'] } else { '<empty_field>' }
							$Title = if ($row['Title'] -ne '') { Escape-SQLString $row['Title'] } else { '<empty_field>' }
							$URL = if ($row['URL'] -ne '') { Escape-SQLString $row['URL'] } else { '<empty_field>' }							
							$event_description = "Last Modified bookmark type $Type with Title $Title and URL $URL added on $DateAdded"
						}
						elseif ($file_name -like '*_Firefox_Downloads-PlacesDB_*.csv') {
							$timestamp = $row['DateAdded']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$Content = if ($row['Content'] -ne '') { Escape-SQLString $row['Content'] } else { '<empty_field>' }
							$LastModified = if ($row['LastModified'] -ne '') { Escape-SQLString $row['LastModified'] } else { '<empty_field>' }					
							$event_description = "$Content downloaded with last modified date of $LastModified"
						}
						elseif ($file_name -like '*_Firefox_History_*.csv') {
							$timestamp = $row['LastVisitDate']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$Title = if ($row['Title'] -ne '') { Escape-SQLString $row['Title'] } else { '<empty_field>' }
							$Typed = if ($row['Typed'] -ne '') { Escape-SQLString $row['Typed'] } else { '<empty_field>' }
							$URL = if ($row['URL'] -ne '') { Escape-SQLString $row['URL'] } else { '<empty_field>' }
							$VisitCount = if ($row['VisitCount'] -ne '') { Escape-SQLString $row['VisitCount'] } else { '<empty_field>' }							
							$event_description = "Last Vist of URL $URL with title $Title and Typed: $Typed Visit Count: $VisitCount"
						}
						elseif ($file_name -like '*_Firefox_Cookies_*.csv') {
							$timestamp = $row['Last Accessed Time']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$CreationTime = if ($row['Creation Time'] -ne '') { Escape-SQLString $row['Creation Time'] } else { '<empty_field>' }
							$HostName = if ($row['Host'] -ne '') { Escape-SQLString $row['Host'] } else { '<empty_field>' }
							$Name = if ($row['Name'] -ne '') { Escape-SQLString $row['Name'] } else { '<empty_field>' }
							$Value = if ($row['Value'] -ne '') { Escape-SQLString $row['Value'] } else { '<empty_field>' }							
							$event_description = "Last Accessed time of Cookie with Host: $HostName Name: $Name Value: $Value and Creation time of $CreationTime"
						}
						elseif ($file_name -like '*_Firefox_Favicons_*.csv') {
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$PageURL = if ($row['PageURL'] -ne '') { Escape-SQLString $row['PageURL'] } else { '<empty_field>' }
							$FaviconURL = if ($row['FaviconURL'] -ne '') { Escape-SQLString $row['FaviconURL'] } else { '<empty_field>' }
							$Expiration = if ($row['Expiration'] -ne '') { Escape-SQLString $row['Expiration'] } else { '<empty_field>' }							
							$event_description = "Favicon with Page Url $PageURL and Favicon URL $FaviconURL with Expiration of $Expiration"
						}
						elseif ($file_name -like '*_Firefox_FormHistory_*.csv') {
							$timestamp = $row['Last Used']
							if ($row['SourceFile'] -match 'Users\\([^\\]+)\\AppData') {
								$user_name = $matches[1]
							}							
							$FieldName = if ($row['FieldName'] -ne '') { Escape-SQLString $row['FieldName'] } else { '<empty_field>' }
							$FirstUsed = if ($row['First Used'] -ne '') { Escape-SQLString $row['First Used'] } else { '<empty_field>' }
							$Value = if ($row['Value'] -ne '') { Escape-SQLString $row['Value'] } else { '<empty_field>' }
							$TimesUsed = if ($row['TimesUsed'] -ne '') { Escape-SQLString $row['TimesUsed'] } else { '<empty_field>' }						
							$event_description = "Last Use of Form History with Field Name: $FieldName Value: $value Times Used: $TimesUsed First Used: $FirstUsed"
						}
						elseif ($file_name -like '*_RECmd_Batch_*.csv') {
							$timestamp = $row['LastWriteTimestamp']
							if ($row['HivePath'] -match 'Users\\([^\\]+)\\') {
								$user_name = $matches[1]
							}
							# Check for specific strings in the ValueData columns
							if ($row['ValueData'] -match 'Execution time:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							}
							if ($row['ValueData2'] -match 'Execution time:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Executed:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'InstallTime:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Created:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Last Connect LOCAL:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Last Executed:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Last Start:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'LastDectectionTime:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Modified:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Name last write:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Ext last open:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Opened on:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Opened:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							} elseif ($row['ValueData2'] -match 'Timestamp:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{7})') {
								$timestamp = $matches[1]
							}
							$fileType = $row['Category']
							$Description = if ($row['Description'] -ne '') { Escape-SQLString $row['Description'] } else { '<empty_field>' }
							$ValueName = if ($row['ValueName'] -ne '') { Escape-SQLString $row['ValueName'] } else { '<empty_field>' }
							$ValueData = if ($row['ValueData'] -ne '') { Escape-SQLString $row['ValueData'] } else { '<empty_field>' }
							$ValueData2 = if ($row['ValueData2'] -ne '') { Escape-SQLString $row['ValueData2'] } else { '<empty_field>' }
							$ValueData3 = if ($row['ValueData3'] -ne '') { Escape-SQLString $row['ValueData3'] } else { '<empty_field>' }
							$Comment = if ($row['Comment'] -ne '') { Escape-SQLString $row['Comment'] } else { '<empty_field>' }
							if ($row['Description'] -match 'Add/Remove Programs Entries') {
								$event_description = "Install date of $ValueData $ValueData3"
							}
							elseif ($row['Description'] -match 'App Paths') {
								$event_description = "Install date of $ValueData"
							}
							elseif ($row['Description'] -match 'AppCompatCache') {
								$event_description = "Modification of $description file $ValueData Comment: $Comment"
							}
							elseif ($row['Description'] -match 'Background Activity Moderator \(BAM\)') {
								$event_description = "Last execution of $ValueName"
							}
							elseif ($row['Description'] -match 'RecentDocs') {
								$event_description = "Last Opened or Opened on of $ValueData"
							}		
							elseif ($row['Description'] -match 'UserAssist') {
								$event_description = "Execution of $ValueData $ValueData3 Comment: If Last executed is empty, execution date is last write date $ValueData2"
							} 
							else {
								$event_description = "Last Write of $description with Value Name: $ValueName Data1: $ValueData Data2: $ValueData2 Data3: $ValueData3 Comment:  $Comment"
							}
						}						
						# If the timestamp is missing, use the earliest possible date
						if (-not $timestamp) {
							$timestamp = "1970-01-01 00:00:00.0000000"
						} else {
							$timestamp = Format-Timestamp -timestamp $timestamp
						}

						function Escape-SQLString {
							param (
								[string]$str
							)
							return $str -replace "'", "''" -replace '"', '""' -replace "`n", " " -replace "`r", " " -replace "`t", " " -replace "[^\x20-\x7E]", '' # Escaping single quotes, double quotes, newlines, tabs, and removing non-printable characters
						}

						# Build the SQL command for the current row
						$columnsData = @()
						foreach ($column in $columns) {
							$value = $row[$column]
							if ($value -eq $null -or $value -eq '') {
								$columnsData += "NULL"
							} else {
								$value = Escape-SQLString -str $value
								$columnsData += "'$value'"
							}
						}

						# Adjust column names
						$columnsString = ($columns | ForEach-Object { 
							if ($_ -eq 'Group') { 
								'_group' 
							} else { 
								$_ -replace '[^a-zA-Z0-9_]', '_' 
							}
						}) -join ", "						

						$columnsDataString = $columnsData -join ", "

						$sqlCommandText = @"
						INSERT INTO Artifacts ('@timestamp', system_name, user_name, event_description, tool, file_name, source_file, file_type, $columnsString)
						VALUES ('$timestamp', '$systemName', '$user_name', '$event_description', '$tool', '$file_name', '$source_file', '$fileType', $columnsDataString);
"@


						if ([string]::IsNullOrWhiteSpace($sqlCommandText)) {
							Write-Log "Generated SQL command is empty for line number $lineNumber. Skipping."
						} else {
							$batch += $sqlCommandText
							$lineNumber++
						}

						if ($batch.Count -ge $batchSize) {
							try {
								Process-Batch -batch $batch -sqliteConnection $sqliteConnection -filePath $filePath -LogFilePath $LogFilePath
							} catch {
								Write-Log "An error occurred while processing the batch. Error: $_"
							}
							$batch = New-Object System.Collections.ArrayList
						}
					}

					if ($batch.Count -gt 0) {
						Write-Log "Processing final batch of size $($batch.Count)"
						try {
							Process-Batch -batch $batch -sqliteConnection $sqliteConnection -filePath $filePath -LogFilePath $LogFilePath
						} catch {
							Write-Log "An error occurred while processing the final batch. Error: $_"
						}
						$batch.Clear()
					}
				} catch {
					Write-Log "An error occurred while processing the CSV file $filePath. Error: $_"
				} finally {
					$parser.Close()
				}
			}

			function Process-Batch {
				param (
					[System.Collections.ArrayList]$batch,
					[System.Data.SQLite.SQLiteConnection]$sqliteConnection,
					[string]$filePath,
					[string]$LogFilePath
				)

				if ([string]::IsNullOrWhiteSpace($filePath)) {
					Write-Log "The file path is empty or null in Process-Batch."
					return
				}
				if ([string]::IsNullOrWhiteSpace($LogFilePath)) {
					Write-Log "The log file path is empty or null in Process-Batch."
					return
				}

				$transaction = $null
				try {
					$transaction = $sqliteConnection.BeginTransaction()
					foreach ($sqlCommandText in $batch) {
						$insertCommand = $sqliteConnection.CreateCommand()
						$insertCommand.CommandText = $sqlCommandText
						try {
							$insertCommand.ExecuteNonQuery() | Out-Null
						} catch {
							Write-Log "Error executing SQL command: $sqlCommandText. Error: $_"
							throw $_  # rethrow the error to be caught in the outer catch block
						} finally {
							if ($insertCommand) {
								$insertCommand.Dispose()  # Dispose of the command object after use
							}
						}
					}
					$transaction.Commit()
				} catch {
					Write-Log "Failed to insert batch into Artifacts table from file: $filePath. Error: $_"
					if ($transaction) {
						$transaction.Rollback()
					}
					throw $_  # rethrow the error to indicate failure in batch processing
				} finally {
					if ($transaction) {
						$transaction.Dispose()
					}
				}
			}



            try {
                Write-Log "Starting Process-TimelineArtifacts with tools: $SelectedTools"
                Write-Log "Database path: $DatabasePath"
                Write-Log "Log file path: $LogFilePath"

                # Initialize SQLite connection
                $connectionString = "Data Source=$DatabasePath;Version=3;"
                $sqliteConnection = New-Object -TypeName System.Data.SQLite.SQLiteConnection -ArgumentList $connectionString
                $sqliteConnection.Open()
                Write-Log "Opened SQLite connection."

                # Apply PRAGMA settings
				$pragmaCommands = @(
					"PRAGMA synchronous = OFF;",
					"PRAGMA journal_mode = MEMORY;",
					"PRAGMA temp_store = MEMORY;",
					"PRAGMA cache_size = -50000;",  # Approximately 50 MB cache size
					"PRAGMA locking_mode = EXCLUSIVE;",
					"PRAGMA mmap_size = 2147483648;",  # 2 GB memory-mapped I/O
					"PRAGMA page_size = 4096;",  # Ensure this is compatible with your database initialization
					"PRAGMA cache_spill = FALSE;",
					"PRAGMA wal_autocheckpoint = 10000;"
				)

                foreach ($pragmaCommand in $pragmaCommands) {
                    $command = $sqliteConnection.CreateCommand()
                    $command.CommandText = $pragmaCommand
                    $command.ExecuteNonQuery() | Out-Null
                }
                Write-Log "Applied PRAGMA settings."

                # Create a table if it doesn't exist
                $createTableCommand = $sqliteConnection.CreateCommand()
                $createTableCommand.CommandText = @"
                CREATE TABLE IF NOT EXISTS Artifacts (
                    '@timestamp' TEXT,
                    system_name TEXT,
                    user_name TEXT,
                    event_description TEXT,
                    tool TEXT,
                    file_name TEXT,
                    source_file TEXT,
                    file_type TEXT
                );
"@
                $createTableCommand.ExecuteNonQuery()
                Write-Log "Table 'Artifacts' created or already exists."
				
				# Create an index on the @timestamp column if it doesn't exist
				$createIndexCommand = $sqliteConnection.CreateCommand()
				$createIndexCommand.CommandText = "CREATE INDEX IF NOT EXISTS idx_timestamp ON Artifacts([@timestamp]);"
				$createIndexCommand.ExecuteNonQuery()			

                # Load existing file hashes
                $existingHashes = @{}
                if (Test-Path -Path $HashLogPath) {
                    try {
                        $hashLogRaw = Get-Content -Path $HashLogPath -Raw
                        if (-not [string]::IsNullOrWhiteSpace($hashLogRaw)) {
                            $jsonObject = $hashLogRaw | ConvertFrom-Json
                            $existingHashes = ConvertTo-Hashtable -jsonObject $jsonObject
                        }
                    } catch {
                        Write-Log "Hash log could not be parsed. Rebuilding hash cache from scratch. Error: $_"
                        $existingHashes = @{}
                    }
                }

				# Process Tools
				$tools = @{
					Zimmermantools = $ZimmermanToolsPath
					Chainsaw = $chainsawPath
					Hayabusa = $hayabusaPath
					Zircolite = $zircolitePath
				}

				foreach ($tool in $tools.GetEnumerator()) {
					if ($SelectedTools -contains $tool.Key) {
						$toolPath = $tool.Value
                        if ([string]::IsNullOrWhiteSpace($toolPath) -or -not (Test-Path -LiteralPath $toolPath -PathType Container)) {
                            Write-Log "Tool output path does not exist for $($tool.Key): $toolPath"
                            continue
                        }
						# Get all CSV files in the tool's output folder recursively
						$csvFiles = @(Get-ChildItem -Path $toolPath -Filter *.csv -Recurse -ErrorAction SilentlyContinue)
						if ($csvFiles.Count -eq 0) {
							Write-Log "No CSV files found in $toolPath"
						} else {
							foreach ($csvFile in $csvFiles) {
								# Exclude files in the Registry subfolder
								if ($csvFile.FullName -like "*\Zimmermantools*\Registry\*\*") {
									continue
								}

								$fileHash = Get-FileHash -FilePath $csvFile.FullName
								if ($null -eq $fileHash) {
									Write-Log "File $($csvFile.FullName) is inaccessible, skipping."
									continue
								}
								if ($existingHashes.ContainsKey($fileHash)) {
									Write-Log "File $($csvFile.FullName) already processed, skipping."
									continue
								}

								Write-Log "Processing file: $($csvFile.FullName)"

								# Read the CSV file headers to get the column names
								$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($csvFile.FullName)
								$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
								$parser.SetDelimiters(",")
								$headers = $parser.ReadFields()
								$columns = $headers | ForEach-Object { $_.Trim() }
								
								# Ensure all columns exist in the database
								foreach ($column in $columns) {
									$columnSafe = $column -replace '[^a-zA-Z0-9_]', '_'
									if ($columnSafe -eq 'Group') {
										$columnSafe = '_group'
									}
									if ($column -ne 'timestamp' -and $column -ne 'system_name' -and $column -ne 'user_name' -and $column -ne 'file_name' -and $column -ne 'source_file' -and $column -ne 'file_type') {
										$alterTableCommand = $sqliteConnection.CreateCommand()
										$alterTableCommand.CommandText = "ALTER TABLE Artifacts ADD COLUMN '$columnSafe' TEXT;"
										try {
											$alterTableCommand.ExecuteNonQuery()
										} catch {
											# Ignore error if column already exists
										}
									}
								}

								# Add this block to explicitly handle 'Timestamp' column
								if ($columns -contains 'Timestamp') {
									$alterTableCommand = $sqliteConnection.CreateCommand()
									$alterTableCommand.CommandText = "ALTER TABLE Artifacts ADD COLUMN 'Timestamp' TEXT;"
									try {
										$alterTableCommand.ExecuteNonQuery()
									} catch {
										# Ignore error if column already exists
									}
								}

								# Get the file type from the folder name (e.g., EventLogs, FileFolderAccess)
								$fileType = (Split-Path -Parent $csvFile.FullName).Split('\')[-1]

								# Get the system name from the folder name after the tool
								$relativePath = $csvFile.FullName -replace [regex]::Escape("$toolPath\"), ''
								$systemName = $relativePath.Split('\')[0]

								# Process the CSV file
								Process-CSVFile -filePath $csvFile.FullName -sqliteConnection $sqliteConnection -systemName $systemName -fileType $fileType -tool $tool.Key -columns $columns -LogFilePath $LogFilePath

								# Add file hash to the log
								$existingHashes[$fileHash] = $csvFile.FullName
								$existingHashes.GetEnumerator() | ConvertTo-Json | Set-Content -Path $HashLogPath
							}
						}
					}
				}

                # Close the SQLite connection
                $sqliteConnection.Close()
                Write-Log "SQLite connection closed."
            } catch {
                Write-Log "An unexpected error occurred: $_"
            }
        }

        # Call the function inside the job
        Process-TimelineArtifacts -SelectedTools $SelectedTools -DatabasePath $DatabasePath -LogFilePath $LogFilePath -HashLogPath $HashLogPath -ZimmermanToolsPath $ZimmermanToolsPath -chainsawPath $chainsawPath -hayabusaPath $hayabusaPath -zircolitePath $zircolitePath

    } -ArgumentList ($SelectedTools, $databasePath, $logFilePath, $hashLogPath, $zimmermanToolsPath, $assemblyPath, $chainsawPath, $hayabusaPath, $zircolitePath)

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $Global:timelineartifactsJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "timelineartifacts_$timestamp"
        ArtifactPath = $SelectedTools
        DataAdded = $false
    }

    Update-Log "Timeline artifacts processing job started for $SelectedTools." "ProcessSystemTextBox"
    $timelineartifactsJobTimer.Start()
}

function Read-IOCFile {
    param($filePath)
    
    if (Test-Path -Path $filePath) {
        $IOCs = Get-Content -Path $filePath | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        return $IOCs
    } else {
        Write-Host "IOC file not found at: $filePath"
        Update-Log "IOC file not found at: $filePath" "ProcessSystemTextBox"
        return @()
    }
}

####End functions for System Processing####
