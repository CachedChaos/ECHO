
# ---- ArtifactCollection.ps1 ----

$global:hasRunOnTabCollectSystemArtifacts = $false
$Global:velociraptorJob = @()
$velociraptorJobTimer = New-Object System.Windows.Forms.Timer
$velociraptorJobTimer.Interval = 2000
$velociraptorJobTimer.Add_Tick({
    Check-velociraptorJobStatus
})

function Check-velociraptorJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:velociraptorJob) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Velociraptor collection completed: $($job.JobName)`nOutput in $($job.JobOutputPath)" "SystemArtifactsTextBox"
				Write-Host "$timestamp Velociraptor collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:velociraptorJob.Count) {
        Update-Log "All Velociraptor Collections completed." "SystemArtifactsTextBox"
        $velociraptorJobTimer.Stop()
    }
}

# Function to update parameters based on selected items
function Update-Parameters {
    $Global:Parameters = @()
    $CheckBoxListBox = $window.FindName("CheckBoxListBox")
    foreach ($item in $CheckBoxListBox.Items) {
        if ($item.IsChecked) {
            $param = "--args $($item.Content)=Y"
            $Global:Parameters += $param
        }
    }
    Show-Selection1 # Update the display
}

# Event handler for checkbox state change
function CheckBox_StateChanged {
    Update-Parameters
    # Include the Volume Shadow Copy checkbox state explicitly
    if ($volumeShadowCopyCheckbox.IsChecked) {
        $Global:Parameters += "--args VSSAnalysis=Y"
    } else {
        $Global:Parameters = $Global:Parameters.Where({$_ -ne "--args VSSAnalysis=Y"})
    }
    Show-Selection1
}

function OnTabCollectSystemArtifacts_GotFocus {
	if ($global:hasRunOnTabCollectSystemArtifacts) {
        return
    }    	
    $subDirectoryPath = Join-Path $global:currentcasedirectory "SystemArtifacts"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'SystemArtifacts' created successfully." "SystemArtifactsTextBox"
    }

    # Set default selection to _SANS_Triage (if needed)
    $CheckBoxListBox = $window.FindName("CheckBoxListBox")
    if ($CheckBoxListBox.Items.Count -gt 0) {
        $index = $CheckBoxListBox.Items.IndexOf("_SANS_Triage")
        if ($index -ne -1) {
            $CheckBoxListBox.SelectedItem = $CheckBoxListBox.Items[$index]
        }
    }
	
	# Check if velociraptorPathTextBox already has a valid path
    if (-not [string]::IsNullOrEmpty($velociraptorPathTextBox.Text) -and 
        ($velociraptorPathTextBox.Text -match "Velociraptor.*\.exe$") -and 
        (Test-Path $velociraptorPathTextBox.Text)) {
        return
    }
    # Search for the velociraptor.exe executable
    Find-VelociraptorExecutable
	Display-Volumes
	Select-SANSTriageDefault
	$global:hasRunOnTabCollectSystemArtifacts = $true
}

function Find-VelociraptorExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $VelociraptorPath = Get-ChildItem -Path $toolsDirectory -Filter "Velociraptor*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Update the Velociraptor path text box
    $velociraptorPathTextBox.Text = $VelociraptorPath

    # Enable the button only if both Velociraptor path and volume are set
    $collectWithVelociraptorButton.IsEnabled = ($VelociraptorPath -and $VolumeComboBox.SelectedItem)
}

function Display-Volumes {
    $VolumeComboBox.Items.Clear() # Clear existing items
    $Global:volumes = Get-Volume | Where-Object { $_.DriveLetter } | Sort-Object FileSystemLabel, DriveLetter

    foreach ($volume in $Global:volumes) {
        $item = [System.Windows.Controls.ComboBoxItem]::new()
        $item.Content = "$($volume.FileSystemLabel) ($($volume.DriveLetter))"
        $item.Tag = $volume # Store the entire volume object
        $VolumeComboBox.Items.Add($item)
    }

    if ($VolumeComboBox.Items.Count -gt 0) {
        $VolumeComboBox.SelectedIndex = 0 # Select the first volume by default
    }
}

function Show-Selection1 {
    $currentSelectionText.Text = "" # Clear existing text
    $selectedVolume = $null

    if ($VolumeComboBox.SelectedItem -and $VolumeComboBox.SelectedItem.Tag) {
        $selectedVolume = $VolumeComboBox.SelectedItem.Tag
        $currentSelectionText.AppendText("Current Volume Selection: $($selectedVolume.FileSystemLabel) $($selectedVolume.DriveLetter)`r`n")
        $currentSelectionText.AppendText("`nParameters: $($Global:Parameters -join ' ')`r`n")
        $currentSelectionText.AppendText("`nVelociraptor Command: `nvelociraptor.exe artifacts collect Windows.KapeFiles.Targets $($Global:Parameters -join ' ') --args Device=$($selectedVolume.DriveLetter): `r`n")
    } else {
        $currentSelectionText.AppendText("No volume selected for collection.`r`n")
    }
}

function Collect-Velociraptor {
    if ($Global:SelectedVolume) {
        $VelociraptorPath = $velociraptorPathTextBox.Text

        if (-not (Test-Path $VelociraptorPath)) {
            $SystemArtifactsTextBox.Text = "Velociraptor executable path is not valid."
            return
        }

        $folderName = [System.Environment]::MachineName
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $outputPath = "$global:currentcasedirectory\SystemArtifacts\AcquiredArtifacts\$folderName"

        if (-not (Test-Path -Path $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
        }

        $outputFile = "${timestamp}_${folderName}_$($Global:SelectedVolume.DriveLetter).zip"
        $outputPath = Join-Path $outputPath $outputFile

        $globalParametersString = $Global:Parameters -join ' '
        $velociraptorArgs = "artifacts collect Windows.KapeFiles.Targets $globalParametersString --args Device=$($Global:SelectedVolume.DriveLetter): --output `"$outputPath`""
        $velociraptorCommand = "& `"$VelociraptorPath`" $velociraptorArgs"

        $SystemArtifactsTextBox.Text = "Executing Velociraptor, please wait..."

        Start-VelociraptorJob -VelociraptorCommand $velociraptorCommand -OutputPath $outputPath
		# Start the timer
		if (-not $velociraptorJobTimer.Enabled) {
			$velociraptorJobTimer.Start()
		}
    }
}

function Start-VelociraptorJob {
    param (
        [string]$VelociraptorCommand,
        [string]$OutputPath
    )

	Update-Log "Velociraptor collection command = $($VelociraptorCommand)" "SystemArtifactsTextBox"

    try {
        # Start the Velociraptor job
        $job = Start-Job -ScriptBlock {
            param($command)
            Invoke-Expression $command
        } -ArgumentList $VelociraptorCommand

        # Add the job to the global job list
        $Global:velociraptorJob += [PSCustomObject]@{
            JobObject = $job
            JobName = "VelociraptorCollection"
            DataAdded = $false
			JobOutputPath = $OutputPath
        }

        Update-Log "Velociraptor collection job started. Job ID: $($job.Id)" "SystemArtifactsTextBox"
    } catch {
        Update-Log "Error starting velociraptor: $_" "SystemArtifactsTextBox"
    }
}

function Select-SANSTriageDefault {
    $CheckBoxListBox = $window.FindName("CheckBoxListBox")

    # Reset all checkboxes and check only "_SANS_Triage"
    foreach ($item in $CheckBoxListBox.Items) {
        if ($item.Content -eq "_SANS_Triage") {
            $item.IsChecked = $true
        } else {
            $item.IsChecked = $false
        }
    }

    $volumeShadowCopyCheckbox.IsChecked = $false
    Update-Parameters
}

# ---- ArtifactProcessing.ps1 ----

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
    $completedCount = 0
    foreach ($job in $Global:chainsawjobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Chainsaw completed: $($job.JobName)" "ProcessSystemTextBox"
				Write-Host "$timestamp Chainsaw completed: $($job.JobName) for $($job.ArtifactPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
    if ($completedCount -eq $Global:chainsawjobs.Count) {
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
	$artifactFileNameWithJson = "${artifactName}.json"
	$jsonoutputPath = Join-Path $outputBaseFolder "${timestamp}_$artifactFileNameWithJson"
	
    $chainsawArguments = @("hunt", "`'$InputPath`'", "-s", "`'$($ChainsawParentFolder)\sigma`'", "--mapping", "`'$($ChainsawParentFolder)\mappings\sigma-event-logs-all.yml`'", "-r", "`'$($ChainsawParentFolder)\rules`'", "-o")
	
		
    if ($useJsonOutput) {
        $chainsawArguments += ("`'$jsonoutputPath`'", "--json")
    } else {
		$chainsawArguments += ("`'$outputPath`'", "--csv")
	}
	
    $chainsawCommand = "& `"$ChainsawPath`" $chainsawArguments"
    Update-Log "chainsawCommand is $chainsawCommand" "ProcessSystemTextBox"
    $job = Start-Job -ScriptBlock {
        param($chainsawCommand, $chainsawDirectory)
        Set-Location -Path $chainsawDirectory 
        Invoke-Expression $chainsawCommand
        
    } -ArgumentList ($chainsawCommand, $chainsawDirectory)

    $Global:chainsawjobs += [PSCustomObject]@{
        JobObject = $job
        JobName = "chainsaw_$timestamp"
        ArtifactPath = $InputPath
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

function Check-ZimmermanProcessingStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:zimmermanJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Finished Zimmerman Tool: $($job.JobName) at outputpath $($job.OutputPath)" "ProcessSystemTextBox"
				Write-Host "$timestamp Finished Zimmerman Tool: $($job.JobName) at outputpath $($job.OutputPath)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:zimmermanJobs.Count) {
        Update-Log "All Zimmerman Tools processing completed." "ProcessSystemTextBox"
        $zimmermanProcessingTimer.Stop()
    }
}

function ProcessZimmermanButton_Click {
    if (-not $ArtifactProcessingPathTextBox.Text -or -not $ZimmermanPathTextBox.Text) {
        [System.Windows.MessageBox]::Show("Please select an artifact path and Zimmerman Tools main directory or Get-ZimmermanTools.ps1.")
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
        $selectedModule = $ZtoolsComboBox.SelectedItem
        $ArtifactPath = $ArtifactProcessingPathTextBox.Text.Trim().Trim('"')
        $ZimmermanFilePath = $ZimmermanPathTextBox.Text.Trim().Trim('"')
        Process-ZimmermanTools -SelectedModule $selectedModule -ArtifactPath $ArtifactPath -ZimmermanFilePath $ZimmermanFilePath

        # Start the timer
        if (-not $zimmermanProcessingTimer.Enabled) {
            $zimmermanProcessingTimer.Start()
        }
    } else {
        Update-Log "Zimmerman Tools used in this program require .NET version 9 or greater. Please install the required .NET version." "ProcessSystemTextBox"
        return
    }
}

function Process-ZimmermanTools {
	param (
        [string]$SelectedModule,
		[string]$ArtifactPath,
        [string]$ZimmermanFilePath
    )
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $uniqueJobName = "ZimmermanJob_${timestamp}"	

    # Determine if the ArtifactPath is a file or a directory
    $isFile = $false
    $isDirectory = $false
    if (Test-Path -Path $ArtifactPath -PathType Leaf) {
        $isFile = $true
		$ArtifactfullPath = $ArtifactPath
    } elseif (Test-Path -Path $ArtifactPath -PathType Container) {
        $isDirectory = $true
    }
	
	# Check if ArtifactPath is a file, and if so, get the directory
	if (Test-Path -Path $ArtifactPath -PathType Leaf) {
		$ArtifactPath = [System.IO.Path]::GetDirectoryName($ArtifactPath)
	}
	
	
    # Get the name of the folder or file from the ArtifactPath (without extension)
	# Check if ArtifactPath is a root path
	if (([System.IO.Path]::GetPathRoot($ArtifactPath)).TrimEnd('\') -eq $ArtifactPath.TrimEnd('\')) {
		# It's a root path, handle accordingly
		$outputFolderName = "Root_" + $ArtifactPath.Trim(':\\') + "_Drive"
	} else {
		$outputFolderName = [IO.Path]::GetFileNameWithoutExtension($ArtifactPath)
	}

    $outputBaseFolder = Join-Path $global:currentcasedirectory 'SystemArtifacts\ProcessedArtifacts\Zimmermantools'
    $outputFolderPath = Join-Path $outputBaseFolder $outputFolderName
    if (-not (Test-Path $outputFolderPath)) {
        $null = New-Item -Path $outputFolderPath -ItemType Directory -Force
    }

	# Modify ZimmermanToolsPath to point to the directory containing the executables
	$ZimmermanToolsPath = (Get-Item $ZimmermanFilePath).Directory.FullName
	$net9Path = Join-Path -Path $ZimmermanToolsPath -ChildPath "net9"
    if (-not (Test-Path -Path $net9Path)) {
        # Update the GUI with a message and return from the function
        Update-Log "This program requires the .NET 9 version of Zimmerman Tools located in a 'net9' directory within $ZimmermanToolsPath." "ProcessSystemTextBox"
        return
    } else {
        $ZimmermanToolsPath = $net9Path
    }
	Update-Log "Zimmerman Tool: $($ZimmermanToolsPath) SelectedModule: $($SelectedModule) ArtifactPath: $($ArtifactPath) ArtifactfullPath: $($ArtifactfullPath)  outputFolderPath: $($outputFolderPath)" "ProcessSystemTextBox"
    # Start processing job
    $job = Start-Job -ScriptBlock {
        param($SelectedModule, $ArtifactPath, $ZimmermanToolsPath, $outputFolderPath, $isFile, $isDirectory, $ArtifactfullPath)

		# Debugging: Write initial parameters to a file
		$debugOutput = "Zimmerman Tool: $ZimmermanToolsPath SelectedModule: $SelectedModule ArtifactPath: $ArtifactPath outputFolderPath: $outputFolderPath isFile: $isFile isDirectory: $isDirectory"
		Add-Content -Path "$outputFolderPath\debug.txt" -Value $debugOutput
	
		# Add logic to locate specific files
		$amcacheFile = Get-ChildItem -Path $ArtifactPath  -Recurse -Filter 'Amcache.hve' -ErrorAction SilentlyContinue | Select-Object -First 1
		$amcacheFilePath = $amcacheFile.FullName
		$recentFileCacheFile = Get-ChildItem -Path $ArtifactPath  -Recurse -Filter 'RecentFileCache.bcf' -ErrorAction SilentlyContinue | Select-Object -First 1
		$recentFileCacheFolder = $recentFileCacheFile.FullName		
		$systemHive = Get-ChildItem -Path $ArtifactPath -Include "SYSTEM" -Recurse -File | 
					Where-Object { $_.FullName -like "*\Windows\System32\config\SYSTEM" } | 
					Select-Object -First 1
		if (-not $systemHive) {
			$systemHive = Get-ChildItem -Path $ArtifactPath -Include "SYSTEM" -Recurse -File | 
						Select-Object -First 1
		}
		$systemHivePath = $null
		if ($systemHive) {
			$systemHivePath = $systemHive.FullName
		}	
		
		if ($isDirectory) {
			$eventLogFolder = Get-ChildItem -Path $ArtifactPath -Recurse -Directory | 
							Where-Object { $_.FullName -like "*\Windows\System32\winevt\Logs" } | 
							Select-Object -First 1	
			if ($eventLogFolder) {
				$eventLogFolderPath = $eventLogFolder.FullName
				$evtxecmdArguments = "-d `'$eventLogFolderPath`' --csv `'$outputFolderPath\EventLogs`'"
			} else {
				$eventLogFolderPath = $ArtifactPath
				$evtxecmdArguments = "-d `'$eventLogFolderPath`' --csv `'$outputFolderPath\EventLogs`'"
			}		 
		} elseif ($isFile) {
			$eventLogFilePath = $ArtifactfullPath
			$evtxecmdArguments = "-f `'$eventLogFilePath`' --csv `'$outputFolderPath\EventLogs`'"
		}
		$MFTFile = Get-ChildItem -Path $ArtifactPath  -Recurse -Filter '$MFT' -ErrorAction SilentlyContinue | Select-Object -First 1
		$MFTFileFolderPath = $MFTFile.Fullname
		$JFile = Get-ChildItem -Path $ArtifactPath  -Recurse -Filter '*$J' -ErrorAction SilentlyContinue | Select-Object -First 1
		$JFileFolderPath = $Jfile.FullName
		$sumFolder = Get-ChildItem -Path $ArtifactPath -Recurse -Directory | 
					Where-Object { $_.FullName -like "*\Windows\System32\LogFiles\SUM" } | 
					Select-Object -First 1		
		$sumFolderPath = $null	
		if ($sumFolder) {
			$sumFolderPath = $sumFolder.FullName
		} else {
			$currentMdbFile = Get-ChildItem -Path $ArtifactPath -Recurse -Filter "Current.mdb" | 
							Select-Object -First 1
			if ($currentMdbFile) {
				$sumFolderPath = $currentMdbFile.DirectoryName
			}
		}	
		$ActivitiesCacheFile = Get-ChildItem -Path $ArtifactPath  -Recurse -Filter 'ActivitiesCache.db' -ErrorAction SilentlyContinue | Select-Object -First 1
		$ActivitiesCacheFilePath = $ActivitiesCacheFile.FullName
		$srudbFile = Get-ChildItem -Path $ArtifactPath  -Recurse -Filter 'SRUDB.dat' -ErrorAction SilentlyContinue | Select-Object -First 1
		$srudbFilePath = $srudbFile.Fullname
		$softwareHive = Get-ChildItem -Path $ArtifactPath -Include "SOFTWARE" -Recurse -File | 
						Where-Object { $_.FullName -like "*\Windows\System32\config\SOFTWARE" } | 
						Select-Object -First 1
		if (-not $softwareHive) {
			$softwareHive = Get-ChildItem -Path $ArtifactPath -Include "SOFTWARE" -Recurse -File | 
							Select-Object -First 1
		}
		$softwareHivePath = $null
		if ($softwareHive) {
			$softwareHivePath = $softwareHive.FullName
		}
		# Process artifacts using specified modules  
		$modules = @{
			'JLECmd' = @{
				FilePath = "$ZimmermanToolsPath\JLECmd.exe"
				Arguments = "-d `'$ArtifactPath`' --csv `'$outputFolderPath\FileFolderAccess`' -q --mp"
			}
			'LECmd' = @{
				FilePath = "$ZimmermanToolsPath\LECmd.exe"
				Arguments = "-d `'$ArtifactPath`' --csv `'$outputFolderPath\FileFolderAccess`' -q --mp"
			}
			'PECmd' = @{
				FilePath = "$ZimmermanToolsPath\PECmd.exe"
				Arguments = "-d `'$ArtifactPath`' --csv `'$outputFolderPath\ProgramExecution`' --mp -q"
			}
			'RBCmd' = @{
				FilePath = "$ZimmermanToolsPath\RBCmd.exe"
				Arguments = "-d `'$ArtifactPath`' --csv `'$outputFolderPath\RecycleBin`' -q"
			}
			'RECmd' = @{
				FilePath = "$ZimmermanToolsPath\RECmd\RECmd.exe"
				Arguments = "-d `'$ArtifactPath`' --bn `'$ZimmermanToolsPath\RECmd\BatchExamples\Kroll_Batch.reb`' --csv `'$outputFolderPath\Registry`' --nl --recover"
			}
			'SBECmd' = @{
				FilePath = "$ZimmermanToolsPath\SBECmd.exe"
				Arguments = "-d `'$ArtifactPath`' --csv `'$outputFolderPath\FileFolderAccess`' --nl"
			}
			'SQLECmd' = @{
				FilePath = "$ZimmermanToolsPath\SQLECmd\SQLECmd.exe"
				Arguments = "-d `'$ArtifactPath`' --csv `'$outputFolderPath\SQLDatabases`'"
			}
			
		}
		
	
		if ($amcacheFilePath) {
			$modules['AmcacheParser'] = @{
				FilePath = "$ZimmermanToolsPath\AmcacheParser.exe"
				Arguments = "-f `'$amcacheFilePath`' --csv `'$outputFolderPath\ProgramExecution`' -i --mp --nl"
			}
		}
		
		if ($systemHivePath) {
			$modules['AppCompatCacheParser'] = @{
				FilePath =  "$ZimmermanToolsPath\AppCompatCacheParser.exe"
				Arguments = "-f `'$systemHivePath`' --csv `'$outputFolderPath\ProgramExecution`' --nl"
			}
		}
		
		if ($eventLogFolderPath -or $eventLogFilePath) {
            $modules['EvtxECmd'] = @{
                FilePath =  "$ZimmermanToolsPath\EvtxECmd\EvtxECmd.exe"
                Arguments = $evtxecmdArguments
            }
        }
		
		if ($sumFolderPath) {
			$modules['SumECmd'] = @{
				FilePath =  "$ZimmermanToolsPath\SumECmd.exe"
				Arguments = "-d `'$sumFolderPath`' --csv `'$outputFolderPath\SUMDatabase`'"
			}
		}
		
		if ($MFTFileFolderPath -and $JFileFolderPath) {
			$modules['MFTECmd'] = @{
				FilePath =  "$ZimmermanToolsPath\MFTECmd.exe"
				Arguments = "-f `'$JFileFolderPath`' -m `'$MFTFileFolderPath`' --csv `'$outputFolderPath\FileSystem`'"
			}
		} elseif ($MFTFileFolderPath -and -not $JFileFolderPath) {
			$modules['MFTECmd'] = @{
				FilePath =  "$ZimmermanToolsPath\MFTECmd.exe"
				Arguments = "-f `'$MFTFileFolderPath`' --csv `'$outputFolderPath\FileSystem`'"
			}
		}
		
		if ($recentFileCacheFolder) {
			$modules['RecentFileCacheParser'] = @{
				FilePath =  "$ZimmermanToolsPath\RecentFileCacheParser.exe"
				Arguments = "-f `'$recentFileCacheFolder`' --csv `'$outputFolderPath\ProgramExecution`'"
			}
		}
		
		if ($ActivitiesCacheFilePath) {
			$modules['WxTCmd'] = @{
				FilePath =  "$ZimmermanToolsPath\WxTCmd.exe"
				Arguments = "-f `'$ActivitiesCacheFilePath`' --csv `'$outputFolderPath\FileFolderAccess`'"
			}
		}
		
		if ($srudbFilePath -and $softwareHivePath) {
			$modules['SrumECmd'] = @{
				FilePath =  "$ZimmermanToolsPath\SrumECmd.exe"
				Arguments = "-f `'$srudbFilePath`' -r `'$softwareHivePath`' --csv `'$outputFolderPath\SRUMDatabase`'"
			}
		} elseif ($srudbFilePath -and -not $softwareHivePath) {
			$modules['SrumECmd'] = @{
				FilePath =  "$ZimmermanToolsPath\SrumECmd.exe"
				Arguments = "-f `'$srudbFilePath`' --csv `'$outputFolderPath\SRUMDatabase`'"
			}
		}
	
		#Determine the modules to process based on the selection
		$modulesToProcess = @{}
		if ($SelectedModule -eq 'All Modules') {
			$modulesToProcess = $modules.GetEnumerator() | Where-Object { $_.Key }
		} elseif ($modules.ContainsKey($SelectedModule)) {
			$modulesToProcess[$SelectedModule] = $modules[$SelectedModule]
		} else {
			Write-Host "Selected module ($SelectedModule) is not recognized."
			return
		}

		$outputFile = Join-Path $outputFolderPath "ztools_output.txt"

		foreach ($module in $modulesToProcess.GetEnumerator()) {
			$moduleFilePath = $module.Value.FilePath
			$moduleArguments = $module.Value.Arguments
		
			try {
				# Construct the command
				$command = "& `'$moduleFilePath`' $moduleArguments"
				
				# Log the command to debug file for troubleshooting
				Add-Content -Path "$outputFolderPath\debug.txt" -Value "Executing command: $command"
			
				# Run the command and capture output and error
				$output = Invoke-Expression $command 2>&1 | Out-String
			
				# Append output to the files
				Add-Content -Path $outputFile -Value $output
				# Errors are included in $output due to 2>&1 redirection
			} catch {
				# Log error in debug.txt
				Add-Content -Path "$outputFolderPath\debug.txt" -Value "Error with module: $moduleFilePath"
				Add-Content -Path "$outputFolderPath\debug.txt" -Value $_.Exception.Message
			}
		}

		
	} -ArgumentList $SelectedModule, $ArtifactPath, $ZimmermanToolsPath, $outputFolderPath, $isFile, $isDirectory, $ArtifactfullPath

    # Add job details to global job list
    $Global:zimmermanJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = $uniqueJobName
        OutputPath = $outputFolderPath
        DataAdded = $false
    }
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

# ---- DiskImage.ps1 ----

$Global:SelectedDrives = New-Object System.Collections.ArrayList

####starting functions for Image Collection####
function OnTabCollectDiskImage_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "DiskImage"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'DiskImage' created successfully." "FTKImagerTextBox"
    }

	# Search for the FTK executable
    Find-FTKExecutable
}

function Update-FTKParameters {
    $Global:FTKParameters = @()
    $DriveCheckBoxListBox = $window.FindName("DriveCheckBoxListBox")
    foreach ($item in $DriveCheckBoxListBox.Items) {
        if ($item.IsChecked) {
            # Extract only the drive name part from the checkbox content
            $driveName = $item.Content -split " - " | Select-Object -First 1
            $Global:FTKParameters += $driveName
        }
    }
    Show-SelectionFTK # Update the display
}

function Find-FTKExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $ftkImagerPath = Get-ChildItem -Path $toolsDirectory -Filter "ftkimager.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Update the ftk path text box
    $FTKPathTextBox.Text = $ftkImagerPath

}

function Update-CollectDrivesButtonState {
    $FTKPath = $FTKPathTextBox.Text
    $selectedDriveCount = ($DriveCheckBoxListBox.Items | Where-Object { $_.IsChecked }).Count

    # Enable the CollectDrivesButton if both FTKPath is valid and at least one drive is selected
    $CollectDrivesButton.IsEnabled = [string]::IsNullOrWhiteSpace($FTKPath) -eq $false -and $selectedDriveCount -gt 0
}

function Display-Drives {
    $DriveCheckBoxListBox = $window.FindName("DriveCheckBoxListBox")
    $DriveCheckBoxListBox.Items.Clear()

    $connectedDrives = Get-WmiObject -Class Win32_DiskDrive | ForEach-Object {
        $driveName = "\\.$($_.DeviceID.Replace('\\.',''))"
        $sizeInGb = [math]::Round($_.Size / 1GB, 2)
        $driveDescription = "$($_.Caption) [$($sizeInGb)GB $($_.InterfaceType)]"
        "$driveName - $driveDescription"
    }

    foreach ($drive in $connectedDrives) {
        $checkBox = New-Object System.Windows.Controls.CheckBox
        $checkBox.Content = $drive
        $checkBox.Add_Click({ FTKCheckBox_StateChanged }) # Add event handler
        $null = $DriveCheckBoxListBox.Items.Add($checkBox)
    }
}

function FTKCheckBox_StateChanged {
    # Update the selected drives and the command preview
    Update-FTKSelection
	Update-CollectDrivesButtonState
}

function Update-FTKSelection {
    # Clear the existing selection
    $Global:SelectedDrives.Clear()
    $commandPreview = "ftkimager.exe "

    # Iterate over each checkbox
    foreach ($checkBox in $DriveCheckBoxListBox.Items) {
        if ($checkBox.IsChecked) {
            # Extract only the drive name part from the checkbox content
            $drive = ($checkBox.Content -split " - ")[0]
            $null = $Global:SelectedDrives.Add($drive)
            $commandPreview += "`"$drive`" "
        }
    }

    # Update command preview with additional parameters
    $commandPreview += "--e01 --frag 2G --compress 6"

    # Update the CurrentFTKSelectionText box
    if ($Global:SelectedDrives.Count -eq 0) {
        $CurrentFTKSelectionText.Text = "No drives selected."
    } else {
        $selectedDrivesText = $Global:SelectedDrives -join ', '
        $CurrentFTKSelectionText.Text = "Selected Drives: $selectedDrivesText`r`nCommand: $commandPreview"
		
    }
	
}

function Show-SelectionFTK {
    $CurrentFTKSelectionText = $window.FindName("CurrentFTKSelectionText")
    $CurrentFTKSelectionText.Text = ""

    if ($Global:FTKParameters.Count -eq 0) {
        $CurrentFTKSelectionText.AppendText("No drives selected.`n")
    } else {
        $CurrentFTKSelectionText.AppendText("Selected Drives:`n")
        foreach ($drive in $Global:FTKParameters) {
            $CurrentFTKSelectionText.AppendText("$drive`n")
        }
        $ftkImagerPath = $FTKPathTextBox.Text
        if ($ftkImagerPath -and $Global:FTKParameters.Count -gt 0) {
            # Building the command to display
            $command = "$ftkImagerPath `"$($Global:FTKParameters -join '" "')`" --e01 --frag 2G --compress 6"
            $CurrentFTKSelectionText.AppendText("`n`nCommand: $command")
        }
    }
}

function Collect-Drives {
    # Use the FTKImager path from the GUI
    $ftkImagerPath = $FTKPathTextBox.Text

    # Get the hostname of the current computer using the PowerShell 'hostname' command
    $hostname = hostname

    # Check if FTKImager path is valid
    if (-not (Test-Path $ftkImagerPath)) {
        [System.Windows.MessageBox]::Show("FTKImager executable not found. Please specify a valid path.", "Error")
        return
    }

    # Check if there are selected drives
    if ($Global:SelectedDrives.Count -eq 0) {
        [System.Windows.MessageBox]::Show("No drive(s) selected for collection. Please select drives first.", "Error")
        return
    }

    $diskImageFolder = Join-Path -Path $Global:CurrentCaseDirectory -ChildPath "DiskImage"

    # Ensure that the disk image folder exists
    if (-not (Test-Path $diskImageFolder)) {
        New-Item -ItemType Directory -Path $diskImageFolder | Out-Null
    }

    foreach ($drive in $Global:SelectedDrives) {
        # Remove the leading "\\.\"
        $cleanDeviceID = $drive -replace '\\\\.\\', ''

        # Append the hostname to the folder and file names
        $driveFolderName = "${hostname}_$cleanDeviceID"
        $driveFolder = Join-Path -Path $diskImageFolder -ChildPath $driveFolderName
        if (-not (Test-Path $driveFolder)) {
            New-Item -ItemType Directory -Path $driveFolder | Out-Null
        }

        $e01FileName = "${hostname}_$cleanDeviceID.E01"
        $e01Path = Join-Path -Path $driveFolder -ChildPath $e01FileName

        $arguments = "`"$drive`" `"$e01Path`" --e01 --frag 2G --compress 6"
        # Output the command being executed for debugging
        Update-Log "Executing command: $ftkImagerPath $arguments" "FTKImagerTextBox"
        Start-Process -FilePath $ftkImagerPath -ArgumentList $arguments 
		Update-Log "Started imaging drive $drive." "FTKImagerTextBox"
    }

    Update-Log "Drive collection initiated in new window." "FTKImagerTextBox"
}
####End functions for Image Collection####

# ---- ElasticSearch.ps1 ----

####Start Elastic Search Functions####
function OnTabElasticSearch_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "Elastic"
    $global:elasticIOCFilePath = Join-Path $subDirectoryPath "CustomIOCs.txt"
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'Elastic' created successfully." "ElasticSearchTextBox"
    }

    foreach ($path in @($elasticIOCFilePath)) {
        if (!(Test-Path $path)) {
            New-Item -ItemType File -Path $path | Out-Null
            Update-Log "File '$(Split-Path $path -Leaf)' created successfully." "ElasticSearchTextBox"
        }
    }
}

function ElasticSearchButton_Click {
    $baseKibanaUrl = $ElasticURLPathTextBox.Text.Trim().TrimEnd('/')
    # Ensure the URL starts with http:// or https://
    if (-not $baseKibanaUrl.StartsWith("http://") -and -not $baseKibanaUrl.StartsWith("https://")) {
        [System.Windows.MessageBox]::Show("Please enter a valid URL starting with http:// or https://")
        return
    }
	
	$IndexPattern = $ElasticIndexIDTextBox.Text.trim()
    $selectedItem = $ElasticCheckBoxListBox.SelectedItem
    if ($selectedItem -eq $null) {
        [System.Windows.MessageBox]::Show("Please select a query from the list.")
        return
    }

	$selectedQueryKey = $selectedItem.ToString()
	
	$selectedItemDetails = $queryMapping[$selectedQueryKey]
	if ($selectedItemDetails -eq $null) {
		[System.Windows.MessageBox]::Show("Selected query not found in query mapping.")
		return
	}
	
	$selectedQuery = $selectedItemDetails["Query"]
	$selectedColumns = $selectedItemDetails["Columns"] -join ',' 

    # Initialize an array to hold IOCs and custom search strings
    $iocs = @()
    
    # Process the selected IOC item
    $selectedIOCItem = $ElasticCustomIOCComboBox.SelectedItem.Content
    if ($selectedIOCItem -eq "CustomIOCs.txt") {
        try {
            $iocs = Get-Content -Path $global:elasticIOCFilePath -ErrorAction Stop
        } catch {
            [System.Windows.MessageBox]::Show("Error reading CustomIOCs.txt")
            return
        }
    }

    # Add the custom search string to the IOC list
    $customQuery = $ElasticSearchIOCTextBox.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($customQuery)) {
        $iocs += $customQuery
    }

    # Build the IOC query part with wildcards
    $iocQueryPart = ""
	if ($iocs.Count -gt 0) {
		$formattedIOCs = $iocs | ForEach-Object {
			if (ShouldQuote $_) {
				"`"$_`""
			} else {
				$_
			}
		}
		$iocQueryPart = $formattedIOCs -join " or "
		$iocQueryPart = " and ($iocQueryPart)"
	}

    # Combine the selected query with the IOC query part
    $combinedQuery = $selectedQuery + $iocQueryPart

	$discoverAppPath = "/app/kibana#/discover/"
	$encodedQuery = [uri]::EscapeDataString($combinedQuery)
	$appStateColumns = "!($selectedColumns)" 
	$globalState = "(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-1y%2Fd,to:now))"  # Added time filters
	$appState = "(columns:$appStateColumns,filters:!(),index:'$IndexPattern',interval:auto,query:(language:kuery,query:'$encodedQuery'),sort:!(!(timestamp,desc)))"

    if ($combinedQuery.StartsWith("=")) {
        [System.Windows.MessageBox]::Show("Invalid query format.")
        return
    }
	$fullUrl = "$($baseKibanaUrl)$($discoverAppPath)?_g=$($globalState)&_a=$($appState)"

    Write-Host "Elastic URL: $baseKibanaUrl"
	Update-Log "Elastic URL: $baseKibanaUrl" "ElasticSearchTextBox"
	Write-Host "URL: $fullUrl"
	Update-Log "URL: $fullUrl" "ElasticSearchTextBox"
	Start-Process $fullUrl

}

function ShouldQuote($term) {
    # Add more special characters if needed
    $specialChars = ' ', ',', '/', ':', ';'
    foreach ($char in $specialChars) {
        if ($term.Contains($char)) {
            return $true
        }
    }
    return $false
}

function UpdateElasticSearchButtonState {
    $isURLPathValid = -not [string]::IsNullOrWhiteSpace($ElasticURLPathTextBox.Text)
    $isIndexIDValid = -not [string]::IsNullOrWhiteSpace($ElasticIndexIDTextBox.Text)
    $ElasticSearchButton.IsEnabled = $isURLPathValid -and $isIndexIDValid
}
####End Elastic Search Functions####

# ---- EvidenceSync.ps1 ----

####Start SyncTools Functions####
$global:hasRunOnTabSyncTools = $false
$global:TimesketchconnectionSuccessful = $false
$global:quickSyncPaths = @{}
$Global:timesketchJobs = @()
$timesketchJobTimer = New-Object System.Windows.Forms.Timer
$timesketchJobTimer.Interval = 2000
$timesketchJobTimer.Add_Tick({
    Check-TimesketchJobStatus
})

function Check-TimesketchJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:timesketchJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Timesketch synced completed: $($job.JobName)" "EvidenceSyncTextBox"
				Write-Host "$timestamp Timesketch synced completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:timesketchJobs.Count) {
        Update-Log "All Timesketch jobs synced." "EvidenceSyncTextBox"
        $timesketchJobTimer.Stop()
    }
}

$script:usingToken = $true
$script:timesketchUrl = ""
$script:timesketchUsername = ""

function OnTabTabSyncTools_GotFocus {
    if ($global:hasRunOnTabSyncTools) {
        return
    }    		
    $subDirectoryPath = Join-Path $global:currentcasedirectory "SyncToolLogs"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'SyncToolLogs' created successfully." "EvidenceSyncTextBox"
    }
	
	$global:hasRunOnTabSyncTools = $true
}

function Check-TimesketchImportClientInstalled {
    try {
        pip show timesketch-import-client | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Check-openpyxlInstalled {
    try {
        pip show openpyxl | Out-Null
        return $true
    } catch {
        return $false
    }
}

function TestTimesketchButton_Click {
    if (-not (Check-PythonInstalled)) {
        $EvidenceSyncTextBox.Text = "Python is required for this operation."
        return
    }

    if (-not (Check-TimesketchImportClientInstalled)) {
        $message = "Timesketch-Import-Client is not installed. Would you like to install it now?"
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Installs the module."
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does not install the module."
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice("Install Module", $message, $options, 1)
        
        if ($result -eq 0) {
            Start-Process "python" -ArgumentList "-m pip install timesketch-import-client" -Wait
        } else {
            return
        }
    }

    if (-not (Check-openpyxlInstalled)) {
        $message = "openpyxl is not installed and used for parsing xmlx files. Would you like to install it now?"
        $yes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Installs the module."
        $no = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Does not install the module."
        $options = [System.Management.Automation.Host.ChoiceDescription[]]($yes, $no)
        $result = $host.ui.PromptForChoice("Install Module", $message, $options, 1)
        
        if ($result -eq 0) {
            Start-Process "python" -ArgumentList "-m pip install openpyxl" -Wait
        } else {
            return
        }
    }
		
	
	
    $url = $SyncTimesketchURLPathTextBox.Text.Trim()
    $username = $TimesketchUserTextBox.Text.Trim()
	if ($url.EndsWith("/")) {
        $url = $url.Substring(0, $url.Length - 1)
    }
    $connectionSuccessful = Test-TimesketchConnection $url $username
	$global:TimesketchconnectionSuccessful = $connectionSuccessful
    if ($connectionSuccessful) {
        $EvidenceSyncTextBox.Text = "Timesketch connection successful.`n"
        Populate-TimesketchIndexComboBox
        $RefreshTimesketchButton.IsEnabled = $true
    } else {
        $EvidenceSyncTextBox.Text = "Failed to connect to Timesketch.`n"
    }
	UpdateSyncTimesketchButtonState
}

function Check-TokenFileExists {
    param (
        [string]$url,
        [string]$username
    )

    $tokenFilePath = Join-Path $HOME ".timesketch.token"
    $configFilePath = Join-Path $HOME ".timesketchrc"

    # Check if the token file exists
    if (-not (Test-Path $tokenFilePath)) {
        return $false
    }

    # Parse the configuration file into objects
    $configObjects = @()
    $currentObject = $null

    if (Test-Path $configFilePath) {
        $configLines = Get-Content $configFilePath

        foreach ($line in $configLines) {
            if ($line -match "\[(.*)\]") {
                if ($currentObject) {
                    $configObjects += $currentObject
                }
                $currentObject = New-Object PSObject -Property @{
                    SectionName = $matches[1]
                }
            } elseif ($line -match "(.*?)\s*=\s*(.*)") {
                $key = $matches[1].Trim()
                $value = $matches[2].Trim()
                $currentObject | Add-Member -MemberType NoteProperty -Name $key -Value $value
            }
        }

        if ($currentObject) {
            $configObjects += $currentObject
        }
    }

    # Check for the matching 'timesketch' section
    foreach ($obj in $configObjects) {
        if ($obj.SectionName -eq "timesketch" -and $obj.username -eq $username -and $obj.host_uri -eq $url) {
            return $true
        }
    }

    return $false
}

function Test-TimesketchConnection {
    param (
        [string]$url,
        [string]$username
    )

    $script:timesketchUrl = $url
    $script:timesketchUsername = $username

    # Check if the token file exists
    $tokenExists = Check-TokenFileExists -url $script:timesketchUrl -username $script:timesketchUsername

    if (-not $tokenExists) {
        # If the token file does not exist, prompt the user for the Timesketch password
        $password = Get-GraphicalPassword
        [Environment]::SetEnvironmentVariable("TIMESKETCH_PASSWORD", $password, [System.EnvironmentVariableTarget]::Process)
        $script:usingToken = $false

        # Define a Python script to authenticate
        $pythonAuthScript = @"
import os
import sys
from timesketch_api_client import client as timesketch_client

host_uri = '$script:timesketchUrl'
username = '$script:timesketchUsername'
password = os.environ['TIMESKETCH_PASSWORD']

def test_authentication():
    try:
        client = timesketch_client.TimesketchApi(host_uri, username, password)
        sketches = client.list_sketches()
        for sketch in sketches:
            pass  # Just iterating to confirm access
        print('Authenticated successfully')
    except Exception as e:
        print('Authentication failed due to an unexpected error.')

original_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

try:
    test_authentication()
finally:
    sys.stderr.close()
    sys.stderr = original_stderr
"@

        $output = python -c $pythonAuthScript

        # Check for successful authentication
        if ($output -match "Authenticated successfully") {
            Write-Host "Authenticated to Timesketch successfully."
			$script:usingToken = $false
			return $true
        } else {
            $errorMessage = "Failed to connect to Timesketch: $output"
            Write-Host $errorMessage
            $EvidenceSyncTextBox.Text = $errorMessage
			$script:usingToken = $true
            return $false
        }
	}
    # Test the connection if a token exists or authentication was successful
    if ($tokenExists -and $script:usingToken) {
        $pythonScript = @"
import os
import sys
from timesketch_api_client import config

def test_authentication():
    try:
        ts_client = config.get_client()
        sketches = ts_client.list_sketches()
        for sketch in sketches:
            pass  # Just iterating to confirm access
        print('Authenticated successfully')
    except Exception as e:
        print('Authentication failed due to an unexpected error.')

original_stderr = sys.stderr
sys.stderr = open(os.devnull, 'w')

try:
    test_authentication()
finally:
    sys.stderr.close()
    sys.stderr = original_stderr
"@
        $output = python -c $pythonScript

        if ($output -match "Authenticated successfully") {
            Write-Host "Connection to Timesketch successful using token."
			$script:usingToken = $true
            return $true
        } else {
            $errorMessage = "Failed to connect to Timesketch using token: $output"
            Write-Host $errorMessage
            $EvidenceSyncTextBox.Text = $errorMessage
			$script:usingToken = $false
            return $false
        }
    }
}

function Populate-TimesketchIndexComboBox {
    $TimesketchIndexComboBox.Items.Clear()

    # Choose the Python script based on whether the token or the password is used
    if ($script:usingToken) {
        # Token-based script logic
        $pythonScript = @"
from timesketch_api_client import config

ts_client = config.get_client()
sketches = ts_client.list_sketches()

for sketch in sketches:
    print(f""{sketch.name}, ID: {sketch.id}"")
"@
    } else {
        # Password-based script logic
        $pythonScript = @"
import os
from timesketch_api_client import client as timesketch_client

host_uri = '$script:timesketchUrl'
username = '$script:timesketchUsername'
password = os.environ['TIMESKETCH_PASSWORD']

client = timesketch_client.TimesketchApi(host_uri, username, password)
sketches = client.list_sketches()

for sketch in sketches:
	print(f""{sketch.name}, ID: {sketch.id}"")

"@
    }

    # Run the Python script and capture output
    $sketches = python -c $pythonScript
    foreach ($sketch in $sketches) {
        [void]$TimesketchIndexComboBox.Items.Add($sketch)
    }
}

function RefreshTimesketchButton_Click {
    Populate-TimesketchIndexComboBox
}

function UpdateTestConnectionButtonState {
    $url = $SyncTimesketchURLPathTextBox.Text
    $username = $TimesketchUserTextBox.Text

    $TestTimesketchButton.IsEnabled = ($url -ne "" -and $username -ne "")
}

function Get-GraphicalPassword {
    Add-Type -AssemblyName System.Windows.Forms
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Enter Password'
    $form.Size = New-Object System.Drawing.Size(300, 150)
    $form.StartPosition = 'CenterScreen'
    $form.FormBorderStyle = 'FixedDialog'
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true

    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Password:'
    $label.Location = New-Object System.Drawing.Point(10, 20)
    $label.Size = New-Object System.Drawing.Size(280, 20)
    $form.Controls.Add($label)

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = New-Object System.Drawing.Point(10, 40)
    $textBox.Size = New-Object System.Drawing.Size(260, 20)
    $textBox.UseSystemPasswordChar = $true
    $form.Controls.Add($textBox)

    $button = New-Object System.Windows.Forms.Button
    $button.Location = New-Object System.Drawing.Point(10, 70)
    $button.Size = New-Object System.Drawing.Size(260, 23)
    $button.Text = 'OK'
    $button.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $form.Controls.Add($button)
    $form.AcceptButton = $button

    $form.ShowDialog() > $null
    return $textBox.Text
}

function UpdateSyncTimesketchButtonState {
    $enableButton = $false

    # Check if the connection was successful
    if ($global:TimesketchconnectionSuccessful) {
        # Check if either SyncProcessingPathTextBox has data or an item is selected in QuickSyncComboBox
        $pathOrFolderSelected = ($SyncProcessingPathTextBox.Text -ne "") -or ($QuickSyncComboBox.SelectedItem -ne $null)

        # Check if either NewTimesketchCheckBox is checked with a name in NewTimesketchTextBox or an item is selected in TimesketchIndexComboBox
        $newOrExistingSketch = ($NewTimesketchCheckBox.IsChecked -and $NewTimesketchTextBox.Text -ne "") -or ($TimesketchIndexComboBox.SelectedItem -ne $null)

        $enableButton = $pathOrFolderSelected -and $newOrExistingSketch
    }

    $SyncTimesketchButton.IsEnabled = $enableButton
}

function SyncTimesketchButton_Click {
    # Step 1: Check for Necessary Conditions
    if (-not $global:TimesketchconnectionSuccessful) {
        $EvidenceSyncTextBox.Text = "Please establish a connection to Timesketch first."
        return
    }

    # Determine the source of files
    $isQuickSync = $QuickSyncCheckBox.IsChecked
    $quickSyncSelection = $null
    $path = $SyncProcessingPathTextBox.Text.Trim('"')
	$authMethod = if ($script:usingToken) { 'token' } else { 'password' }

    if ($isQuickSync) {
        $quickSyncSelection = $QuickSyncComboBox.SelectedItem
    }
    # Get the list of files to upload
    $filesToUpload = Get-FilesToUpload -path $path -isQuickSync $isQuickSync -quickSyncSelection $quickSyncSelection


	# Step 3: Determine Sketch Details
	$sketchId = $null
	$newSketchName = $null
	if ($NewTimesketchCheckBox.IsChecked) {
		$newSketchName = $NewTimesketchTextBox.Text
	} else {
		# Get the selected item from TimesketchIndexComboBox
		$selectedItem = $TimesketchIndexComboBox.SelectedItem
		if ($selectedItem -ne $null) {
			# Extract the ID from the selected item
			# Assuming the format is "SketchName, ID: SketchID"
			$sketchId = $selectedItem -split ", ID: " | Select-Object -Last 1
		}
	}

	#Update-Log "SketchID selected is: $sketchId" "EvidenceSyncTextBox"
	#Update-Log "New Sketch Name is: $newSketchName" "EvidenceSyncTextBox"

	# Convert the list of files to a format that can be passed to Python
	$fileList = $filesToUpload -join ','
	#Update-Log "Files to upload are: $fileList" "EvidenceSyncTextBox"
	
	$uploadScript = @"

from timesketch_api_client import config as ts_config, client as ts_client
from timesketch_import_client import importer
import sys, os, pandas as pd, json, openpyxl
from datetime import datetime
from pandas._libs.tslibs.np_datetime import OutOfBoundsDatetime
pd.options.mode.chained_assignment = None 
CHUNK_SIZE = 50000

def safe_convert_to_datetime(column):
    placeholder_date = pd.Timestamp('1678-01-01').to_pydatetime()

    def convert_date(date):
        try:
            # Strip nanoseconds if needed
            if isinstance(date, str) and '.' in date:
                date = date.split('.')[0]
            result = pd.to_datetime(date, errors='raise')
            return result
        except (ValueError, OutOfBoundsDatetime):
            return placeholder_date

    return column.apply(convert_date)

def extract_from_nested_array(json_array, key):
	for item in json_array:
		if item.get('Name') == key:
			return item.get('Value')
	return None

def initialize_ts_client(auth_method, host_uri, username, password):
    if auth_method == 'token':
        return ts_config.get_client()
    elif auth_method == 'password':
        return ts_client.TimesketchApi(host_uri, username, password)
    else:
        raise ValueError('Invalid authentication method')

	
def upload_files(file_paths, sketch_id, new_sketch_name, auth_method, host_uri, username, password):
	ts_client = initialize_ts_client(auth_method, host_uri, username, password)
	if sketch_id and sketch_id != 'None':
		my_sketch = ts_client.get_sketch(sketch_id)
	else:
		my_sketch = ts_client.create_sketch(new_sketch_name)
	with importer.ImportStreamer() as streamer:
		streamer.set_sketch(my_sketch)
		for file_path in file_paths:
			try:
				timeline_name = os.path.basename(file_path) # Timeline name based on file name
				streamer.set_timeline_name(timeline_name)
				streamer.set_timestamp_description('File Upload')

				if file_path.endswith('.plaso'):
					streamer.add_file(file_path)
					print(f'Uploaded file: {file_path}\n')
					continue 

				if file_path.endswith('.jsonl'):
					streamer.add_file(file_path)
					print(f'Uploaded file: {file_path}\n')
					continue 

				if file_path.endswith('.json'):
					streamer.add_file(file_path)
					print(f'Uploaded file: {file_path}\n')
					continue 
					
				# Read the file into a DataFrame
				if file_path.endswith('.csv'):
					df = pd.read_csv(file_path, low_memory=False)
				elif file_path.endswith('.xlsx'):
					df = pd.read_excel(file_path)				
	
				# Use SourceModified as datetime if file is LECmd_Output.csv
				if file_path.endswith('LECmd_Output.csv') and 'SourceModified' in df.columns:
					df.rename(columns={'SourceModified': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('SourceModified')
				
				# Use TimeCreated as datetime if file is EvtxECmd_Output.csv
				elif file_path.endswith('EvtxECmd_Output.csv') and 'TimeCreated' in df.columns:
					df.drop(columns=['Payload'], inplace=True)
					df.rename(columns={'TimeCreated': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('TimeCreated')
				
				elif 'LastModified' in df.columns and 'EntryNumber' in df.columns and 'FileBirthDroid' in df.columns:
					df.drop(columns=['EntryNumber'], inplace=True)
					df['LastModified'] = safe_convert_to_datetime(df['LastModified'])
					df.rename(columns={'LastModified': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastModified')

				elif file_path.endswith('CustomDestinations.csv') and 'SourceModified' in df.columns:
					df.rename(columns={'SourceModified': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('SourceModified')
					
				elif file_path.endswith('Activity.csv') and 'LastModifiedTime' in df.columns:
					df.rename(columns={'LastModifiedTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastModifiedTime')
				
				elif file_path.endswith('NTUSER.csv') and 'LastWriteTime' in df.columns:
					df.rename(columns={'LastWriteTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastWriteTime')
				
				elif file_path.endswith('usrClass.csv') and 'LastWriteTime' in df.columns:
					df.rename(columns={'LastWriteTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastWriteTime')
				
				elif file_path.endswith('MFT_Output.csv') and 'Created0x10' in df.columns:
					df.rename(columns={'Created0x10': 'datetime'}, inplace=True)
					df['datetime'] = safe_convert_to_datetime(df['datetime'])					
					streamer.set_timestamp_description('Created0x10')
				
				elif file_path.endswith('J_Output.csv') and 'UpdateTimestamp' in df.columns:
					df.rename(columns={'UpdateTimestamp': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('UpdateTimestamp')
				
				elif file_path.endswith('AppCompatCache.csv') and 'LastModifiedTimeUTC' in df.columns:
					df.rename(columns={'LastModifiedTimeUTC': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastModifiedTimeUTC')
				
				elif file_path.endswith('PECmd_Output_Timeline.csv') and 'RunTime' in df.columns:
					df.rename(columns={'RunTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('RunTime')
				
				elif file_path.endswith('RBCmd_Output.csv') and 'DeletedOn' in df.columns:
					df.rename(columns={'DeletedOn': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('DeletedOn')

				elif 'ChromiumBrowser_OmniboxShortcuts' in file_path and file_path.endswith('.csv'):
					df = pd.read_csv(file_path, low_memory=False)
					if 'ID' in df.columns:
						df.rename(columns={'ID': 'CustomID'}, inplace=True)
					if 'LastAccessTime' in df.columns:
						df.rename(columns={'LastAccessTime': 'datetime'}, inplace=True)
						streamer.set_timestamp_description('LastAccessTime')

				elif 'AuditData' in df.columns and 'ObjectState' in df.columns:
					df['AuditData'] = df['AuditData'].apply(json.loads)
					df['ActorIpAddress'] = df['AuditData'].apply(lambda x: x.get('ActorIpAddress'))
					df['ClientIP'] = df['AuditData'].apply(lambda x: x.get('ClientIP'))
					df['UserAgent'] = df['AuditData'].apply(lambda x: extract_from_nested_array(x.get('ExtendedProperties', []), 'UserAgent'))
					df['BrowserType'] = df['AuditData'].apply(lambda x: extract_from_nested_array(x.get('DeviceProperties', []), 'BrowserType'))
					df['Workload'] = df['AuditData'].apply(lambda x: x.get('Workload'))
					df['datetime'] = pd.to_datetime(df['AuditData'].apply(lambda x: x['CreationTime']))
					streamer.set_timestamp_description('CreationTime')

		
				elif 'FileKeyLastWriteTimestamp' in df.columns:
					df.rename(columns={'FileKeyLastWriteTimestamp': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('FileKeyLastWriteTimestamp')
	
				elif 'LastRun' in df.columns:
					df.rename(columns={'LastRun': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastRun')
	
				elif 'LastModifiedTime' in df.columns:
					df.rename(columns={'LastModifiedTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastModifiedTime')
					
				elif 'VisitTime (Local)' in df.columns:
					df.rename(columns={'VisitTime (Local)': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('VisitTime')
				
				elif 'CreationUTC' in df.columns:
					df.rename(columns={'CreationUTC': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('CreationUTC')

				elif 'LastAccessTime' in df.columns:
					df.rename(columns={'LastAccessTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastAccessTime')
					
				elif 'LastModified' in df.columns:
					df.rename(columns={'LastModified': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastModified')
				
				elif 'KeyLastWriteTimestamp' in df.columns:
					df.rename(columns={'KeyLastWriteTimestamp': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('KeyLastWriteTimestamp')
	
				elif 'LastUpdated' in df.columns:
					df.rename(columns={'LastUpdated': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastUpdated')

				elif 'LastAccessed' in df.columns:
					df.rename(columns={'LastAccessed': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastAccessed')

				elif 'Created Date' in df.columns:
					df.rename(columns={'Created Date': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('CreatedDate')

				elif 'LoadTime' in df.columns:
					df.rename(columns={'LoadTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LoadTime')

				elif 'CreateTime' in df.columns:
					df.rename(columns={'CreateTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('CreateTime')

				elif 'Create Time' in df.columns:
					df.rename(columns={'Create Time': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('CreateTime')

				elif 'RunDate' in df.columns:
					df.rename(columns={'RunDate': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('RunDate')

				elif 'Received' in df.columns:
					df.rename(columns={'Received': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('Received')
					
				elif 'LastPasswordChangeTimestamp' in df.columns:
					df.rename(columns={'LastPasswordChangeTimestamp': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('LastPasswordChangeTimestamp')
					
				elif 'ActivityDateTime' in df.columns:
					df.rename(columns={'ActivityDateTime': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('ActivityDateTime')

					
				elif 'Timestamp' in df.columns:
					df.rename(columns={'Timestamp': 'datetime'}, inplace=True)
					streamer.set_timestamp_description('Timestamp')
										
				num_chunks = len(df) // CHUNK_SIZE + (len(df) % CHUNK_SIZE > 0)
				for i in range(num_chunks):
					chunk = df.iloc[i*CHUNK_SIZE:(i+1)*CHUNK_SIZE]
					streamer.add_data_frame(chunk)
					print(f'Uploaded chunk {i+1} of {num_chunks} for file: {file_path}')

				print(f'Uploaded file: {file_path}')				
			except Exception as e:
				print(f'Error uploading file {file_path}: {e}\n')
				continue

if __name__ == '__main__':
    file_paths = sys.argv[1].split(',')
    sketch_id = int(sys.argv[2]) if sys.argv[2] != 'None' else None
    new_sketch_name = sys.argv[3]
    auth_method = sys.argv[4] 
    host_uri = os.environ.get('TIMESKETCH_URL')
    username = os.environ.get('TIMESKETCH_USERNAME')
    password = os.environ.get('TIMESKETCH_PASSWORD')
    upload_files(file_paths, sketch_id, new_sketch_name, auth_method, host_uri, username, password)
"@

	[Environment]::SetEnvironmentVariable("TIMESKETCH_USERNAME", $script:timesketchUsername, "Process")
	[Environment]::SetEnvironmentVariable("TIMESKETCH_URL", $script:timesketchUrl, "Process")

    $scriptArguments = @{
        fileList = $fileList
        sketchId = if ([string]::IsNullOrEmpty($sketchId)) { 'None' } else { $sketchId }
        newSketchName = if ([string]::IsNullOrEmpty($newSketchName)) { 'None' } else { $newSketchName }
        authMethod = $authMethod
        username = $script:timesketchUsername
        url = $script:timesketchUrl
    }
	
    # Generate a unique timestamp for the job name
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $uniqueJobName = "$($timestamp)_Timesketch Sync"	
	
	Update-Log "Uploading to Timesketch. Job name: $uniqueJobName. Please wait..." "EvidenceSyncTextBox"
    # Start the upload process as a job
    $job = Start-Job -ScriptBlock {
        param($fileList, $sketchId, $newSketchName, $authMethod, $username, $url)
        
        # Set environment variables for the job
        [Environment]::SetEnvironmentVariable("TIMESKETCH_USERNAME", $username, "Process")
        [Environment]::SetEnvironmentVariable("TIMESKETCH_URL", $url, "Process")

        # Run the upload script
        python -c $using:uploadScript $fileList $sketchId $newSketchName $authMethod
    } -ArgumentList @($scriptArguments.fileList, $scriptArguments.sketchId, $scriptArguments.newSketchName, $scriptArguments.authMethod, $scriptArguments.username, $scriptArguments.url)

    # Add the job to the global job list
    $Global:timesketchJobs += @{ JobObject = $job; JobName = $uniqueJobName; DataAdded = $false }

    # Start the timer to check job status
    $timesketchJobTimer.Start()

}

function Get-FilesToUpload {
    param (
        [string]$path,
        [bool]$isQuickSync,
        [string]$quickSyncSelection
    )

    $filesToUpload = @()
    $validExtensions = @(".csv", ".jsonl", ".plaso", ".xlsx")

    if ($isQuickSync) {
        # Retrieve the full path from the global hashtable
        $directory = $global:quickSyncPaths[$quickSyncSelection]
        $filesToUpload = Get-ChildItem -Path $directory -Recurse |
                         Where-Object { $_.Extension -in $validExtensions -and -not $_.PSIsContainer }
    }
    else {
        if (Test-Path $path -PathType Container) {
            # Path is a directory
            $filesToUpload = Get-ChildItem -Path $path -Recurse |
                             Where-Object { $_.Extension -in $validExtensions -and -not $_.PSIsContainer }
        }
        elseif (Test-Path $path -PathType Leaf) {
            # Path is a file
            $file = Get-Item $path
            if ($file.Extension -in $validExtensions) {
                $filesToUpload += $file
            }
        }
    }

    return $filesToUpload | Select-Object -ExpandProperty FullName
}

####End SyncTools Functions####

# ---- M365Collection.ps1 ----

$global:ipAddressesFilePath = $null
$global:usernamesFilePath = $null

# Define a global variable to track the pipe server job
$Global:PipeServerJob = $null

#Timer for collect triage
$Global:m365triageJobs = @()
$m365triageJobTimer = New-Object System.Windows.Forms.Timer
$m365triageJobTimer.Interval = 2000
$m365triageJobTimer.Add_Tick({
    Check-M365TriageJobStatus
})

function Check-M365TriageJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365triageJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Triage Collection completed: $($job.JobName)" "M365TextBox"
				Write-Host "$timestamp Triage Collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365triageJobs.Count) {
        Update-Log "All Triage Collections completed." "M365TextBox"
        $m365triageJobTimer.Stop()
    }
}

#Timer for collect UAL
$Global:m365UALJobs = @()
$m365UALJobTimer = New-Object System.Windows.Forms.Timer
$m365UALJobTimer.Interval = 2000
$m365UALJobTimer.Add_Tick({
    Check-M365UALJobStatus
})

function Check-M365UALJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365UALJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Unified Audit Logs Collection completed: $($job.JobName)" "M365TextBox"
				Write-Host "$timestamp Unified Audit Logs Collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365UALJobs.Count) {
        Update-Log "All Unified Audit Logs Collections completed." "M365TextBox"
        $m365UALJobTimer.Stop()
    }
}

#Timer for collect MAL
$Global:m365MALJobs = @()
$m365MALJobTimer = New-Object System.Windows.Forms.Timer
$m365MALJobTimer.Interval = 2000
$m365MALJobTimer.Add_Tick({
    Check-M365MALJobStatus
})

function Check-M365MALJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365MALJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Mailbox Audit Logs Collection completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\MailboxAuditLogs" "M365TextBox"
				Write-Host "$timestamp Mailbox Audit Logs Collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365MALJobs.Count) {
        Update-Log "All Mailbox Audit Logs Collections completed." "M365TextBox"
        $m365MALJobTimer.Stop()
    }
}

#Timer for collect Admin Logs
$Global:m365AdminLogsJobs = @()
$m365AdminLogsJobTimer = New-Object System.Windows.Forms.Timer
$m365AdminLogsJobTimer.Interval = 2000
$m365AdminLogsJobTimer.Add_Tick({
    Check-M365AdminLogsJobStatus
})

function Check-M365AdminLogsJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365AdminLogsJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Admin Logs Collection completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\AdminAuditLog" "M365TextBox"
				Write-Host "$timestamp Admin Logs Collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365AdminLogsJobs.Count) {
        Update-Log "All Admin Logs Collections completed."
        $m365AdminLogsJobTimer.Stop()
    }
}

#Timer for collect Inbox Rules
$Global:m365InboxRulesJobs = @()
$m365InboxRulesJobTimer = New-Object System.Windows.Forms.Timer
$m365InboxRulesJobTimer.Interval = 2000
$m365InboxRulesJobTimer.Add_Tick({
    Check-M365InboxRulesJobStatus
})

function Check-M365InboxRulesJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365InboxRulesJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Inbox Rules Collection completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\InboxRules" "M365TextBox"
				Write-Host "$timestamp Inbox Rules Collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365InboxRulesJobs.Count) {
        Update-Log "All Inbox Rules Collections completed." "M365TextBox"
        $m365InboxRulesJobTimer.Stop()
    }
}

#Timer for collect Forwarding Rules
$Global:m365ForwardingRulesJobs = @()
$m365ForwardingRulesJobTimer = New-Object System.Windows.Forms.Timer
$m365ForwardingRulesJobTimer.Interval = 2000
$m365ForwardingRulesJobTimer.Add_Tick({
    Check-M365ForwardingRulesJobStatus
})

function Check-M365ForwardingRulesJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365ForwardingRulesJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Forwarding Rules Collection completed: $($job.JobName)"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\ForwardingRules" "M365TextBox"
				Write-Host "$timestamp Forwarding Rules Collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365ForwardingRulesJobs.Count) {
        Update-Log "All Forwarding Rules Collections completed." "M365TextBox"
        $m365ForwardingRulesJobTimer.Stop()
    }
}

#Timer for collect M365 Info
$Global:m365InfoJobs = @()
$m365InfoJobTimer = New-Object System.Windows.Forms.Timer
$m365InfoJobTimer.Interval = 2000
$m365InfoJobTimer.Add_Tick({
    Check-M365InfoJobStatus
})

function Check-M365InfoJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365InfoJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "MS65 Info completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\M365Info" "M365TextBox"
				Write-Host "$timestamp MS65 Info completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365InfoJobs.Count) {
        Update-Log "All MS65 Info Collection completed." "M365TextBox"
        $m365InfoJobTimer.Stop()
    }
}

#Timer for collect Message Trace
$Global:m365MessageTraceJobs = @()
$m365MessageTraceJobTimer = New-Object System.Windows.Forms.Timer
$m365MessageTraceJobTimer.Interval = 2000
$m365MessageTraceJobTimer.Add_Tick({
    Check-M365MessageTraceJobStatus
})

function Check-M365MessageTraceJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365MessageTraceJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Message Trace completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\MessageTrace" "M365TextBox"
				Write-Host "$timestamp Message Trace completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365MessageTraceJobs.Count) {
        Update-Log "All Message Trace Log Collection completed." "M365TextBox"
        $m365MessageTraceJobTimer.Stop()
    }
}

#Timer for collect Azure Logs
$Global:m365AzureLogsJobs = @()
$m365AzureLogsJobTimer = New-Object System.Windows.Forms.Timer
$m365AzureLogsJobTimer.Interval = 2000
$m365AzureLogsJobTimer.Add_Tick({
    Check-M365AzureLogsJobStatus
})

function Check-M365AzureLogsJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365AzureLogsJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Azure log collection completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\AzureLogs" "M365TextBox"
				Write-Host "$timestamp Azure log collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365AzureLogsJobs.Count) {
        Update-Log "All Azure Log Collection completed." "M365TextBox"
        $m365AzureLogsJobTimer.Stop()
    }
}

#Timer for collect Last Password Change
$Global:m365LastPassJobs = @()
$m365LastPassJobTimer = New-Object System.Windows.Forms.Timer
$m365LastPassJobTimer.Interval = 2000
$m365LastPassJobTimer.Add_Tick({
    Check-M365LastPassJobStatus
})

function Check-M365LastPassJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:m365LastPassJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Last Password Change Log collection completed: $($job.JobName)" "M365TextBox"
				Update-Log "Results in $($Global:CurrentCaseDirectory)\M365Evidence\LastPasswordChange" "M365TextBox"
				Write-Host "$timestamp Last Password Change Log collection completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:m365LastPassJobs.Count) {
        Update-Log "All Last Password Change Log Collection completed." "M365TextBox"
        $m365LastPassJobTimer.Stop()
    }
}

function OnTabCollectM365_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "M365Evidence"
    $global:usernamesFilePath = Join-Path $subDirectoryPath "Usernames.txt"
    $global:ipAddressesFilePath = Join-Path $subDirectoryPath "IPAddresses.txt"


    # Create subdirectory if it doesn't exist
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'M365Evidence' created successfully." "M365TextBox"
    }

    # Create necessary files if they don't exist
    foreach ($path in @($usernamesFilePath, $ipAddressesFilePath)) {
        if (!(Test-Path $path)) {
            New-Item -ItemType File -Path $path | Out-Null
            Update-Log "File '$(Split-Path $path -Leaf)' created successfully." "M365TextBox"
        }
    }
}

function Disconnect-MsolService {
    $adalTokenCachePath = Join-Path -Path $env:LOCALAPPDATA -ChildPath "Microsoft\Office\16.0\ADAL"
    if (Test-Path -Path $adalTokenCachePath) {
        $adalTokenCacheFiles = Get-ChildItem -Path $adalTokenCachePath -Filter "AdalCacheStorage*"
        if ($adalTokenCacheFiles.Count -gt 0) {
            foreach ($adalTokenCacheFile in $adalTokenCacheFiles) {
                Remove-Item -Path $adalTokenCacheFile.FullName -Force
            }
            Write-Host "MSOnline Service connection has been cleared."
        } else {
            Write-Host "No token cache found."
        }
    } else {
        Write-Host "No ADAL token cache directory found."
    }
}

function ConnectClientButton_Click {
    $M365TextBox.Text = ""
    $CollectTriageButton.IsEnabled = $true
    $CollectUALButton.IsEnabled = $true
    $CollectMALButton.IsEnabled = $true
    $CollectAdminLogsButton.IsEnabled = $true
    $CollectInboxRulesButton.IsEnabled = $true
    $CollectForwardingRulesButton.IsEnabled = $true
    $CollectM365InfoButton.IsEnabled = $true
    $CollectMessageTraceButton.IsEnabled = $true
    $CollectAzureLogsButton.IsEnabled = $true
    $CollectLastPasswordChangeButton.IsEnabled = $true
    $ConnectClientButton.IsEnabled = $false 
    # Required modules
    $requiredModules = @("AzureADPreview", "ExchangeOnlineManagement", "MSOnline")

    # Check if the required modules are installed and construct the command string
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            # Prompt user to install the module
            $message = "The module '$module' is required but not installed. Do you want to install it now? This is required for the connection."
            $caption = "Module Installation Required"
            $buttons = [System.Windows.MessageBoxButton]::YesNo
            $icon = [System.Windows.MessageBoxImage]::Warning
            $result = [System.Windows.MessageBox]::Show($message, $caption, $buttons, $icon)

            if ($result -eq 'Yes') {
                # Install the module
                Install-Module -Name $module -Scope CurrentUser -Force -ErrorAction Stop
            } else {
                # If the user chooses not to install, log it and return
                Update-Log "Module '$module' installation skipped by user." "M365TextBox"
                return
            }
        }
    }

    # Generate a unique pipe name
    $Global:pipeName = "M365Pipe_$([System.Guid]::NewGuid().ToString())"

    # Start the named pipe server if not already started
    if (-not $Global:PipeServerJob) {
        $Global:PipeServerJob = Start-NamedPipeServer -pipeName $Global:pipeName
    }

    try {
        # Send a request to the server to execute Connect-Client function
        $command = "Connect-Client"
        $response = Send-CommandToProcess -pipeName $Global:pipeName -commandToSend $command
        Update-Log $response "M365TextBox"

    } catch {
        # Log the exception
        Update-Log "Failed to send commands: $_" "M365TextBox"
    }
    $ConnectClientButton.IsEnabled = $true
}

function Start-NamedPipeServer {
    param($pipeName)
    
    Write-Host "Starting Named Pipe Server..."

    $serverScriptBlock = {
        param([string]$pipeName)
		$serverShouldRun = $true
        # Define embedded functions
        function Connect-Client {
            try {
                Connect-MsolService
                AzureADPreview\Connect-AzureAD
                Connect-ExchangeOnline
                return "Connected to all services."
            } catch {
                return "Failed to connect: $($_.Exception.Message)"
            }
        }

		function Test-M365Connection {
			try {
				# Execute commands and collect responses
				$azureADResponse = try { $tenant = Get-AzureADTenantDetail; "Connected to Azure AD tenant: " + $tenant.DisplayName } catch { "Not connected to Azure AD" }
				$exchangeResponse = try { $orgConfig = Get-OrganizationConfig; "Connected to Exchange Online tenant: " + $orgConfig.DisplayName } catch { "Not connected to Exchange Online" }
				$msolResponse = try { $domain = (Get-MsolDomain)[0].Name; "Connected to MsolService: " + $domain } catch { "Not connected to MsolService" }
				$auditLogResponse = try { $auditConfig = Get-AdminAuditLogConfig; if ($auditConfig.UnifiedAuditLogIngestionEnabled) { "Unified Audit Logs are enabled" } else { "Unified Audit Logs are not enabled" } } catch { "Failed to check Unified Audit Logs status" }
				
				# Check current user's permissions in Azure AD
				$currentUser = Get-AzureADCurrentSessionInfo
				$userRoles = Get-AzureADDirectoryRole | Where-Object { (Get-AzureADDirectoryRoleMember -ObjectId $_.ObjectId).ObjectId -contains $currentUser.ObjectId }
				$roleNames = $userRoles.DisplayName -join ", "
				$permissionsResponse = if ($roleNames) { "Current user roles in Azure AD: $roleNames" } else { "Current user has no special roles in Azure AD" }
		
				# Combine all responses into a single string with newline characters
				$fullResponse = ($azureADResponse, $exchangeResponse, $msolResponse, $auditLogResponse, $permissionsResponse) -join "`r`n"
				return $fullResponse
			} catch {
				return "Failed to test connection: $($_.Exception.Message)"
			}
		}

		function Collect-Triage {
			param(
				[string]$currentcasedirectory
			)
		
			# Set the default values for parameters used across multiple functions
			$defaultScope = "Entire Tenant"
			$defaultUsernamesFilePath = "$currentcasedirectory\Usernames.txt"
			$defaultIPsFilePath = "$currentcasedirectory\IPAddresses.txt" 
			$defaultIPScope = "All IPs"
			$defaultOperationsScope = "Limited Operations"
			$defaultStartDate = (Get-Date).AddDays(-90).ToString("yyyy-MM-dd")
		
			# Create a hashtable to hold the response from each function
			$responses = @{}
		

			# Define an array of function calls
			$functionCalls = @(
				{ Collect-InboxRules -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
				{ Collect-ForwardingRules -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
				{ Collect-AdminLogs -currentcasedirectory $currentcasedirectory },
				{ Collect-AzureLogs -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
				{ Collect-M365Info -currentcasedirectory $currentcasedirectory }, 
				{ Collect-LastPasswordChange -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
				{ Collect-UAL -Scope $defaultScope -currentcasedirectory $currentcasedirectory -usernamesFilePath $defaultUsernamesFilePath -IPScope $defaultIPScope -OperationsScope $defaultOperationsScope -ipAddressesFilePath $defaultIPsFilePath -StartDate $defaultStartDate }
			)		
		
			# Call each function and store the responses
			foreach ($functionCall in $functionCalls) {
				try {
					# Get the function name for logging
					$functionName = $functionCall.ToString().Split(' ')[1]
					Write-Output "Starting collection for $functionName"
			
					# Invoke the function call script block
					$responses[$functionName] = & $functionCall
			
					Write-Output "$functionName collection response: $($responses[$functionName])"
				} catch {
					$errorString = "Error in " + $functionName + ": " + $_.Exception.Message
					Write-Output $errorString
				}
			}
			
			# Return all responses
			return $responseses
		}

		function Collect-UAL {
			param(
				[string]$Scope,  # "Entire Tenant" or "Custom Users"
				[string]$currentcasedirectory,
				[string]$usernamesFilePath,  # Path to file containing usernames
				[string]$IPScope,  # "All IPs" or "Custom IPs"
				[string]$OperationsScope,  # "Limited Operations" or "All Operations"
				[string]$ipAddressesFilePath,  # Path to file containing IP addresses
				[string]$StartDate  # Custom start date if selected
			)

			$unifiedAuditLogsPath = Join-Path $currentcasedirectory "M365Evidence\UnifiedAuditLogs"
			if (!(Test-Path $unifiedAuditLogsPath)) {
				New-Item -ItemType Directory -Path $unifiedAuditLogsPath | Out-Null
			}

			# Building the query based on the GUI selections
			$specifiedUsers = $null
			$specifiedIPs = $null
			$allOperations = $false
			$endDate = (Get-Date)

			if ($Scope -eq "Custom Users") {
				$specifiedUsers = Get-Content $usernamesFilePath
			}

			if ($IPScope -eq "Custom IPs") {
				$specifiedIPs = Get-Content $ipAddressesFilePath
			}

			if ($OperationsScope -eq "All Operations") {
				$operations = @("*")
			} else {
				$operations = @("UserLoggedIn", "New-InboxRule", "Set-InboxRule", "Update-InboxRule", "AddOAuth2PermissionGrant")
			}

			function Get-AdjustedInterval {
				param (
					[int]$IntervalMinutes,
					[int]$BatchSize,
					[int]$ResultCount
				)

				if ($ResultCount -ge $BatchSize * 0.8) {
					# If results are close to the batch size limit, reduce the interval increase
					$NewInterval = $IntervalMinutes + 15
				} elseif ($ResultCount -ge $BatchSize * 0.5) {
					# Moderate increase if results are half of the batch size limit
					$NewInterval = $IntervalMinutes + 30
				} else {
					# Otherwise, increase more significantly
					$NewInterval = $IntervalMinutes + 60
				}

				# Check if the new interval exceeds the maximum allowed value (1440 minutes)
				if ($NewInterval -gt 1440) {
					$NewInterval = 1440
				}

				return $NewInterval
			}

			# Search the Unified Audit Logs and save the results
			$intervalMinutes = 30  # Start with a smaller interval
			$maxIntervalMinutes = 1440
			$batchSize = 5000
			$allResults = @()
			$currentStart = [datetime]::ParseExact($startDate, "yyyy-MM-dd", $null)

			while ($currentStart -lt $endDate) {
				$currentEnd = $currentStart.AddMinutes($intervalMinutes)

				Write-Host "Retrieving audit records for activities performed between $($currentStart) and $($currentEnd)"

				$searchParams = @{
					StartDate  = $currentStart
					EndDate    = $currentEnd
					ResultSize = $batchSize
				}

				if (-not $allOperations) {
					$searchParams['Operations'] = $operations
				}

				if ($specifiedUsers) {
					$searchParams['UserIds'] = $specifiedUsers
				}

				if ($specifiedIPs) {
					$searchParams['IPAddress'] = $specifiedIPs
				}

				$results = Search-UnifiedAuditLog @searchParams
				$allResults += $results

				# Adjust the interval based on the returned results
				$intervalMinutes = Get-AdjustedInterval -IntervalMinutes $intervalMinutes -BatchSize $batchSize -ResultCount $results.Count

				if ($results.Count -eq $batchSize) {
					$currentStart = $results[-1].CreationDate.AddSeconds(-10)  # Ensure a slight overlap
				} else {
					$currentStart = $currentEnd
				}
			}

			# Save the results in the appropriate file(s)
			$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
			if ($specifiedUsers) {
				foreach ($user in $specifiedUsers) {
					$userLogs = $allResults | Where-Object { $_.UserIds -eq $user }
					$logFileName = "$($user)_UAL_${startDate}_to_$timestamp.csv"
					$logFilePath = Join-Path $unifiedAuditLogsPath $logFileName
					$userLogs | Export-Csv -Path $logFilePath -NoTypeInformation
				}
			} else {
				$logFileName = "${startDate}_to_${timestamp}_UAL_AllUsers.csv"
				$logFilePath = Join-Path $unifiedAuditLogsPath $logFileName
				$allResults | Export-Csv -Path $logFilePath -NoTypeInformation
			}

			# Returning the path to the output file for logging purposes
			return "Ual Logs collected"
		}

		function Collect-InboxRules {
			param(
				[string]$Scope,
				[string]$currentcasedirectory,
				[string]$usernamesFilePath
			)	
			$inboxRulesPath = Join-Path $currentcasedirectory "M365Evidence\InboxRules"
			if (!(Test-Path $inboxRulesPath)) {
				New-Item -ItemType Directory -Path $inboxRulesPath | Out-Null
			}
		
			switch ($Scope) {
				"Entire Tenant" {
					$allUsers = Get-Mailbox -ResultSize Unlimited
					$results = @()
					foreach ($user in $allUsers) {
						$mailbox = $user.UserPrincipalName
						$inboxRules = Get-InboxRule -Mailbox $mailbox
						$results += $inboxRules
					}
					$outputFilePath = Join-Path $inboxRulesPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_InboxRules_Tenant.csv"
					$results | Export-Csv -Path $outputFilePath -NoTypeInformation
					return "Inbox rules for entire tenant collected."
				}
				"CustomUsers" {
					$mailboxes = Get-Content $usernamesFilePath
					foreach ($mailbox in $mailboxes) {
						$mailboxTrimmed = $mailbox.Trim()
						$user = Get-Mailbox -Identity $mailboxTrimmed
						$outputFileName = $user.Alias + "_InboxRules.csv"
						$outputFilePath = Join-Path $inboxRulesPath $outputFileName
						$inboxRules = Get-InboxRule -Mailbox $mailboxTrimmed
						$inboxRules | Export-Csv -Path $outputFilePath -NoTypeInformation
					}
					return "Inbox rules for custom users collected."
				}
				default {
					throw "Invalid scope: $Scope"
				}
			}
		}

		function Collect-ForwardingRules {
			param(
				[string]$Scope,
				[string]$currentcasedirectory,
				[string]$usernamesFilePath
			)	
			$forwardingRulesPath = Join-Path $currentcasedirectory "M365Evidence\ForwardingRules"
			if (!(Test-Path $forwardingRulesPath)) {
				New-Item -ItemType Directory -Path $forwardingRulesPath | Out-Null
			}
		
			switch ($Scope) {
				"Entire Tenant" {
					$allUsers = Get-Mailbox -ResultSize Unlimited
					$results = @()
					foreach ($user in $allUsers) {
						$forwardingInfo = [PSCustomObject]@{
							UserPrincipalName         = $user.UserPrincipalName
							ForwardingSmtpAddress     = $user.ForwardingSmtpAddress
							DeliverToMailboxAndForward = $user.DeliverToMailboxAndForward
						}
						$results += $forwardingInfo
					}
					$outputFilePath = Join-Path $forwardingRulesPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_ForwardingRules_Tenant.csv"
					$results | Export-Csv -Path $outputFilePath -NoTypeInformation
					return "Forwarding rules for entire tenant collected."
				}
				"CustomUsers" {
					$mailboxes = Get-Content $usernamesFilePath
					foreach ($mailbox in $mailboxes) {
						$mailboxTrimmed = $mailbox.Trim()
						$user = Get-Mailbox -Identity $mailboxTrimmed
						$forwardingInfo = [PSCustomObject]@{
							UserPrincipalName         = $user.UserPrincipalName
							ForwardingSmtpAddress     = $user.ForwardingSmtpAddress
							DeliverToMailboxAndForward = $user.DeliverToMailboxAndForward
						}
						$outputFileName = $user.Alias + "_ForwardingRules.csv"
						$outputFilePath = Join-Path $forwardingRulesPath $outputFileName
						$forwardingInfo | Export-Csv -Path $outputFilePath -NoTypeInformation
					}
					return "Forwarding rules for custom users collected."
				}
				default {
					throw "Invalid scope: $Scope"
				}
			}
		}
			
		function Collect-AdminLogs {
			param(
				[string]$currentcasedirectory
			)
			
			# Create AdminAuditLog subdirectory under M365Evidence folder
			$adminAuditLogPath = Join-Path $currentcasedirectory "M365Evidence\AdminAuditLog"
			if (!(Test-Path $adminAuditLogPath)) {
				New-Item -ItemType Directory -Path $adminAuditLogPath | Out-Null
			}
			
			# Collect admin audit logs for their default retention policy (90 days)
			$startDate = (Get-Date).AddDays(-90)
			$endDate = (Get-Date)
			
			try {
				$adminAuditLogs = Search-AdminAuditLog -StartDate $startDate -EndDate $endDate
				
				# Save the admin audit logs to a CSV file
				$csvFilePath = Join-Path $adminAuditLogPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_AdminAuditLogs.csv"
				$adminAuditLogs | Export-Csv -Path $csvFilePath -NoTypeInformation
				
				return "Admin audit logs have been saved to the CSV file: $csvFilePath"
			} catch {
				return "Failed to collect admin audit logs: $($_.Exception.Message)"
			}
		}

		function Collect-MailboxAuditLogs {
			param(
				[string]$Scope,
				[string]$currentcasedirectory,
				[string]$usernamesFilePath
			)
		
			# Create MailboxAuditLogs subdirectory under M365Evidence folder
			$mailboxAuditLogsPath = Join-Path $currentcasedirectory "M365Evidence\MailboxAuditLogs"
			if (!(Test-Path $mailboxAuditLogsPath)) {
				New-Item -ItemType Directory -Path $mailboxAuditLogsPath | Out-Null
			}
		
			$startDate = (Get-Date).AddDays(-90)
		
			switch ($Scope) {
				"Entire Tenant" {
					$malTenantPath = Join-Path $mailboxAuditLogsPath "MAL_Tenant"
					if (!(Test-Path $malTenantPath)) {
						New-Item -ItemType Directory -Path $malTenantPath | Out-Null
					}
		
					$allUsers = Get-Mailbox -ResultSize Unlimited
					foreach ($user in $allUsers) {
						$identity = $user.UserPrincipalName
						$fileName = "$($user.Alias)_MAL_Tenant.csv"
						$filePath = Join-Path $malTenantPath $fileName
						Search-MailboxAuditLog -Identity $identity -showdetail -StartDate $startDate -EndDate (Get-Date) | Export-Csv -Path $filePath -NoTypeInformation
					}
					return "Mailbox audit logs for entire tenant collected."
				}
		
				"CustomUsers" {
					$malIndividualPath = Join-Path $mailboxAuditLogsPath "MAL_Individual"
					if (!(Test-Path $malIndividualPath)) {
						New-Item -ItemType Directory -Path $malIndividualPath | Out-Null
					}
		
					$identities = if ($usernamesFilePath) {
						Get-Content $usernamesFilePath
					} else {
						throw "Usernames file path is required for collecting specific users' mailbox audit logs."
					}
		
					foreach ($identity in $identities) {
						$user = Get-Mailbox -Identity $identity.Trim()
						$fileName = "$($user.Alias)_MAL_Individual.csv"
						$filePath = Join-Path $malIndividualPath $fileName
						Search-MailboxAuditLog -Identity $identity.Trim() -showdetail -StartDate $startDate -EndDate (Get-Date) | Export-Csv -Path $filePath -NoTypeInformation
					}
					return "Mailbox audit logs for specified users collected."
				}
		
				default {
					throw "Invalid scope: $Scope"
				}
			}
		}
		
		function Collect-MessageTrace {
			param(
				[string]$Scope,
				[string]$currentcasedirectory,
				[string]$usernamesFilePath
			)
		
			# Create MessageTrace subdirectory under M365Evidence folder
			$messageTracePath = Join-Path $currentcasedirectory "M365Evidence\MessageTrace"
			if (!(Test-Path $messageTracePath)) {
				New-Item -ItemType Directory -Path $messageTracePath | Out-Null
			}
		
			$endDate = Get-Date
			$startDate = $endDate.AddDays(-10)
		
			switch ($Scope) {
				"Entire Tenant" {
					$allUsers = Get-Mailbox -ResultSize Unlimited
					$senderResults = @()
					$recipientResults = @()
		
					foreach ($user in $allUsers) {
						$senderMessageTraces = Get-MessageTrace -SenderAddress $user.UserPrincipalName -StartDate $startDate -EndDate $endDate
						$recipientMessageTraces = Get-MessageTrace -RecipientAddress $user.UserPrincipalName -StartDate $startDate -EndDate $endDate
					
						if ($senderMessageTraces) {
							$senderResults += $senderMessageTraces
						}
						if ($recipientMessageTraces) {
							$recipientResults += $recipientMessageTraces
						}
					}
					
					# Export only if there are results
					if ($senderResults) {
						$senderResults | Export-Csv -Path (Join-Path $messageTracePath "MessageTrace_Tenant_Sender.csv") -NoTypeInformation
					}
					
					if ($recipientResults) {
						$recipientResults | Export-Csv -Path (Join-Path $messageTracePath "MessageTrace_Tenant_Recipient.csv") -NoTypeInformation
					}

					return "Message trace for entire tenant collected."
				}
		
				"CustomUsers" {
					$mailboxes = if ($usernamesFilePath) {
						Get-Content $usernamesFilePath
					} else {
						throw "Usernames file path is required for collecting specific users' message traces."
					}
		
					foreach ($mailbox in $mailboxes) {
						$mailbox = $mailbox.Trim()
						$user = Get-Mailbox -Identity $mailbox
		
						$senderMessageTraces = Get-MessageTrace -SenderAddress $user.UserPrincipalName -StartDate $startDate -EndDate $endDate
						$recipientMessageTraces = Get-MessageTrace -RecipientAddress $user.UserPrincipalName -StartDate $startDate -EndDate $endDate
		
						$senderMessageTraces | Export-Csv -Path (Join-Path $messageTracePath "$($user.Alias)_MessageTrace_Sender.csv") -NoTypeInformation
						$recipientMessageTraces | Export-Csv -Path (Join-Path $messageTracePath "$($user.Alias)_MessageTrace_Recipient.csv") -NoTypeInformation
					}
					return "Message trace for specified users collected."
				}
		
				default {
					throw "Invalid scope: $Scope"
				}
			}
		}

		function Collect-AzureLogs {
			param(
				[string]$Scope,  # "Entire Tenant" or "CustomUsers"
				[string]$currentcasedirectory,
				[string]$usernamesFilePath = $null  # Optional parameter for path to usernames file
			)
			
			# Create AzureLogs subdirectory under M365Evidence folder
			$azureLogsPath = Join-Path $currentcasedirectory "M365Evidence\AzureLogs"
			if (!(Test-Path $azureLogsPath)) {
				New-Item -ItemType Directory -Path $azureLogsPath | Out-Null
			}
			$timestampFormat = (Get-Date).ToString("yyyyMMdd_HHmmss")
			
			# Determine if we are filtering by specific users
			$userPrincipalNames = if ($Scope -eq "CustomUsers" -and (Test-Path $usernamesFilePath)) {
				Get-Content $usernamesFilePath
			} else {
				$null
			}
			
			function Extract-PropertiesFromCell {
				param($cellContent)
			
				# Normalize line breaks, remove class definitions and braces
				$cleanContent = $cellContent -replace "`r`n", "`n" -replace "class\s+\w+\s+\{", "" -replace "[\{\}]", ""
			
				# Extract properties using regex
				$properties = @{}
				$cleanContent -split "`n" | ForEach-Object {
					if ($_ -match "Id:\s*(\S+)") { $properties["Id"] = $matches[1].Trim() }
					if ($_ -match "DisplayName:\s*([^\n]*)") { $properties["DisplayName"] = $matches[1].Trim() }
					if ($_ -match "IpAddress:\s*(\S+)") { $properties["IpAddress"] = $matches[1].Trim() }
					if ($_ -match "UserPrincipalName:\s*(\S+)") { $properties["UserPrincipalName"] = $matches[1].Trim() }
					if ($_ -match "ServicePrincipalId:\s*(\S+)") { $properties["ServicePrincipalId"] = $matches[1].Trim() }
					if ($_ -match "DisplayName:\s*([^\n]+)") { $properties["AppDisplayName"] = $matches[1].Trim() }
				}
			
				return $properties
			}
		
			
			# Attempt to collect sign-in logs
			try {
				if ($userPrincipalNames) {
					foreach ($userPrincipalName in $userPrincipalNames) {
						$userPrincipalName = $userPrincipalName.Trim()
						$signInLogs = Get-AzureADAuditSignInLogs -All $true -Filter "userPrincipalName eq '$userPrincipalName'"
						$signInLogs | Export-Csv -Path (Join-Path $azureLogsPath "$($userPrincipalName)_SignInLogs.csv") -NoTypeInformation
					}
				} else {
					$signInLogs = Get-AzureADAuditSignInLogs -All $true
					$signInLogs | Export-Csv -Path (Join-Path $azureLogsPath "$($timestampFormat)_AzureSignInLogs_Tenant.csv") -NoTypeInformation
				}
			} catch {
				if ($_.Exception -match "Authentication_RequestFromNonPremiumTenantOrB2CTenant") {
					$errorMessage = "Error: Tenant does not have a premium license required for sign-in logs."
					Out-File -FilePath (Join-Path $azureLogsPath "$($timestampFormat)_AzureSignInLogs_Error.txt") -InputObject $errorMessage
				} else {
					throw $_
				}
			}
			
			# Attempt to collect audit directory logs
			try {
				$auditLogs = Get-AzureADAuditDirectoryLogs -All $true
				
				# Create a custom object for each log entry to parse the InitiatedBy details
				$customAuditLogs = $auditLogs | ForEach-Object {
					# Extract properties from the InitiatedBy column
					$properties = if ($_.InitiatedBy) {
						Extract-PropertiesFromCell -cellContent $_.InitiatedBy
					} else {
						@{}  # Empty hashtable if there is no InitiatedBy content
					}
				
					# Output the current object with the added properties
					$_ | Select-Object *,
						@{Name="InitiatedById"; Expression={$properties["Id"]}},
						@{Name="InitiatedByDisplayName"; Expression={$properties["DisplayName"]}},
						@{Name="InitiatedByIpAddress"; Expression={$properties["IpAddress"]}},
						@{Name="InitiatedByUserPrincipalName"; Expression={$properties["UserPrincipalName"]}},
						@{Name="InitiatedByAppDisplayName"; Expression={$properties["AppDisplayName"]}}
						# Include other properties from $_ as needed
				}
				
				# Export the custom object array to CSV, including the new dynamic columns
				$auditLogFileName = "${timestampFormat}_AzureAuditLogs_Tenant.csv"
				$auditLogFilePath = Join-Path $azureLogsPath $auditLogFileName
				$customAuditLogs | Export-Csv -Path $auditLogFilePath -NoTypeInformation
		
				
			} catch {
				throw $_
			}
		}

		function Collect-M365Info {
			param(
				[string]$currentcasedirectory
			)
		
			$m365InfoPath = Join-Path $currentcasedirectory "M365Evidence\M365Info"
			
			# Check if the M365Info directory exists, and if not, create it
			if (!(Test-Path $m365InfoPath)) {
				New-Item -ItemType Directory -Path $m365InfoPath | Out-Null
			}
		
			$AdminAuditLogConfig = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_AdminAuditLogConfig.csv"
			$casMailboxFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_CasMailbox.csv"
			$MailboxFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_Mailbox.csv"
			$MailboxPermissionsFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_MailboxPermissions.csv"
			$MsolUsersFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_MsolUsers.csv"
		
			Get-AdminAuditLogConfig | Export-Csv $AdminAuditLogConfig -NoTypeInformation
			Get-CasMailbox -ResultSize unlimited | Export-Csv $casMailboxFile -NoTypeInformation
			Get-Mailbox -ResultSize unlimited | Export-Csv $MailboxFile -NoTypeInformation
		
			$mailboxes = Get-Mailbox -ResultSize unlimited
			$mailboxPermissions = @()
		
			foreach ($mailbox in $mailboxes) {
				$permissions = Get-MailboxPermission -Identity $mailbox.Identity
				$mailboxPermissions += $permissions
			}
		
			$mailboxPermissions | Export-Csv $MailboxPermissionsFile -NoTypeInformation
		
			# Get and export MsolUsers with expanded properties
			$msolUsers = Get-MsolUser -All
			$msolUsers | Select-Object *, 
				@{Name="MFA_MethodTypes";Expression={($_.StrongAuthenticationMethods | ForEach-Object {$_.MethodType}) -join ', '}},
				# Additional expressions as per original function...
				Export-Csv $MsolUsersFile -NoTypeInformation
		
			return "M365 Information collected."
		}
			
		function Collect-LastPasswordChange {
			param(
				[string]$Scope,
				[string]$currentcasedirectory,
				[string]$usernamesFilePath
			)
		
			# Create LastPasswordChange subdirectory under M365Evidence folder
			$lastPasswordChangePath = Join-Path $currentcasedirectory "M365Evidence\LastPasswordChange"
			if (!(Test-Path $lastPasswordChangePath)) {
				New-Item -ItemType Directory -Path $lastPasswordChangePath | Out-Null
			}
		
			switch ($Scope) {
				"Entire Tenant" {
					$allUsers = Get-MsolUser -All
					$allUsers | Select-Object UserPrincipalName, 
						LastPasswordChangeTimestamp, 
						@{Name="MFAStatus";Expression={($_.StrongAuthenticationRequirements.State)}}, 
						@{Name="MFAEnabledDate";Expression={($_.StrongAuthenticationUserDetails.LastUpdated)}},
						@{Name="MFAMethodTypes";Expression={($_.StrongAuthenticationMethods | ForEach-Object {$_.MethodType}) -join ', '}},
						@{Name="MFADefaultMethods";Expression={($_.StrongAuthenticationMethods | Where-Object {$_.IsDefault} | ForEach-Object {$_.MethodType}) -join ', '}} |
						Export-Csv -Path (Join-Path $lastPasswordChangePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_LastPasswordChange_Tenant.csv") -NoTypeInformation
					return "Last password change for entire tenant collected."
				}
		
				"CustomUsers" {
					$userPrincipalNames = if ($usernamesFilePath) {
						Get-Content $usernamesFilePath
					} else {
						throw "Usernames file path is required for collecting specific users' last password change information."
					}
		
					foreach ($userPrincipalName in $userPrincipalNames) {
						$userPrincipalName = $userPrincipalName.Trim()
						$user = Get-MsolUser -UserPrincipalName $userPrincipalName
			
						$user | Select-Object UserPrincipalName, 
							LastPasswordChangeTimestamp, 
							@{Name="MFAStatus";Expression={($_.StrongAuthenticationRequirements.State)}}, 
							@{Name="MFAEnabledDate";Expression={($_.StrongAuthenticationUserDetails.LastUpdated)}},
							@{Name="MFAMethodTypes";Expression={($_.StrongAuthenticationMethods | ForEach-Object {$_.MethodType}) -join ', '}},
							@{Name="MFADefaultMethods";Expression={($_.StrongAuthenticationMethods | Where-Object {$_.IsDefault} | ForEach-Object {$_.MethodType}) -join ', '}} |
							Export-Csv -Path (Join-Path $lastPasswordChangePath "$($user.UserPrincipalName)_LastPasswordChange.csv") -NoTypeInformation
					}
					return "Last password change for specified users collected."
				}
		
				default {
					throw "Invalid scope: $Scope"
				}
			}
		}
	
		function shutdown-server {
			# Set the flag to false to signal the server loop to exit
			$script:serverShouldRun = $false
			Write-Host "Server shutdown signal sent."
		}
	
        while ($serverShouldRun) {
            $pipeServer = New-Object System.IO.Pipes.NamedPipeServerStream(
                $pipeName,
                [System.IO.Pipes.PipeDirection]::InOut,
                1,
                [System.IO.Pipes.PipeTransmissionMode]::Byte,
                [System.IO.Pipes.PipeOptions]::Asynchronous
            )
            Write-Host "Waiting for client connection..."
            $pipeServer.WaitForConnection()
            Write-Host "Client connected."

            $reader = New-Object System.IO.StreamReader($pipeServer)
            $writer = New-Object System.IO.StreamWriter($pipeServer)
            $writer.AutoFlush = $true

            try {
                while ($pipeServer.IsConnected) {
                    $line = $reader.ReadLine()
                    if ($line) {
                        Write-Host "Received request from client: $line"
                        try {
                            $requestParts = $line -split ";"
                            $functionName = $requestParts[0]
                            $params = $requestParts[1..($requestParts.Length - 1)]
        
                            switch ($functionName) {
                                "Connect-Client" {
                                    $response = Connect-Client
                                    $writer.WriteLine(($response | Out-String).Trim())
                                }
                                "Test-M365Connection" {
                                    $response = Test-M365Connection
                                    $writer.WriteLine(($response | Out-String).Trim())
                                }
								"Collect-Triage" {
									$response = Collect-Triage -currentcasedirectory $params[0]
									$writer.WriteLine($response)
								}									
								"Collect-UAL" {
									$response = Collect-UAL -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2] -IPScope $params[3] -OperationsScope $params[4] -ipAddressesFilePath $params[5] -StartDate $params[6]
									$writer.WriteLine($response)
								}							
								"Collect-MailboxAuditLogs" {
									$response = Collect-MailboxAuditLogs -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2]
									$writer.WriteLine($response)
								}
								"Collect-AdminLogs" {
									$response = Collect-AdminLogs -currentcasedirectory $params[0]
									$writer.WriteLine($response)
								}								
								"Collect-InboxRules" {
									$response = Collect-InboxRules -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2]
									$writer.WriteLine($response)
								}								
								"Collect-ForwardingRules" {
									$response = Collect-ForwardingRules -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2]
									$writer.WriteLine($response)
								}
								"Collect-M365Info" {
									$response = Collect-M365Info -currentcasedirectory $params[0]
									$writer.WriteLine($response)
								}									
								"Collect-MessageTrace" {
									$response = Collect-MessageTrace -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2]
									$writer.WriteLine($response)
								}
								"Collect-AzureLogs" {
									$response = Collect-AzureLogs -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2]
									$writer.WriteLine($response)
								}								
								"Collect-LastPasswordChange" {
									$response = Collect-LastPasswordChange -Scope $params[0] -currentcasedirectory $params[1] -usernamesFilePath $params[2]
									$writer.WriteLine($response)
								}					
								"shutdown-server" {
									$response = shutdown-server
									$writer.WriteLine($response)
								}										
                                default {
                                    $errorMsg = "Unknown function: $functionName"
                                    $writer.WriteLine("Error: $errorMsg")
                                }
                            }
                        } catch {
                            $errorMsg = "Error executing request: $($_.Exception.Message)"
                            $writer.WriteLine("Error: $errorMsg")
                        }
                        $writer.WriteLine("END_OF_MESSAGE")
                    }
                }
            } catch {
                Write-Error "Server error: $($_.Exception.Message)"
            } finally {
                try {
                    if ($pipeServer.IsConnected) {
                        $pipeServer.Disconnect()
                    }
                } catch {
                    Write-Host "Error disconnecting pipe: $($_.Exception.Message)"
                }

                if ($reader -ne $null) {
                    try {
                        $reader.Close()
                    } catch {
                        Write-Host "Error closing reader: $($_.Exception.Message)"
                    }
                }

                if ($writer -ne $null) {
                    try {
                        $writer.Close()
                    } catch {
                        Write-Host "Error closing writer: $($_.Exception.Message)"
                    }
                }

                try {
                    $pipeServer.Close()
                } catch {
                    Write-Host "Error closing pipe server: $($_.Exception.Message)"
                }

                Write-Host "Client disconnected."
            }
        }

        Write-Host "Server is closing..."
        $pipeServer.Close()
    }

    # Start the PowerShell script block as a background job
    $job = Start-Job -ScriptBlock $serverScriptBlock -ArgumentList $pipeName

    Write-Host "Named Pipe Server started as a job. Job ID: $($job.Id)"
    return $job
}

function Send-CommandToProcess {
    param(
        [string]$pipeName,		
        [string]$commandToSend
    )
    $maxRetries = 3
    $retryDelay = 2 # seconds
    $retryCount = 0
	
    while ($retryCount -lt $maxRetries) {
        try {
            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
            $pipeClient.Connect(5000)

			if ($pipeClient.IsConnected) {
				Write-Host "Connected to server."
				$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
				$streamWriter.AutoFlush = $true
			
				# Example request to collect forwarding rules for entire tenant
				$request = ($commandToSend)
				$streamWriter.WriteLine($request)
			
				# Read response from server
				$streamReader = New-Object System.IO.StreamReader($pipeClient)
				while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
					if ($line -is [System.Array] -or $line -is [System.Object]) {
						$line = $line -join "`r`n"
					}
					Write-Host "Response from server: $line"
					Update-Log "$line" "M365TextBox"
				}
			
				$streamWriter.Close()
				$streamReader.Close()
				$pipeClient.Close()
				Write-Host "Message sent, client disconnected."
				# Return the response
				return $response
			} else {
				Write-Host "Failed to connect to server. Retrying..."
				Start-Sleep -Seconds $retryDelay
				$retryCount++
			}
		} catch {
			Write-Host "Error: $_. Retrying..."
			Start-Sleep -Seconds $retryDelay
			$retryCount++
		}
    }
    Write-Host "Failed to connect to server after $maxRetries retries."
}

function TestClientConnectionButton_Click {
    $M365TextBox.Text = ""
    $TestClientConnectionButton.IsEnabled = $false
    Update-Log "Testing Tenant Connection..." "M365TextBox"
    
    try {
        # Send a request to the server to execute Test-M365Connection function
        $command = "Test-M365Connection"
        $response = Send-CommandToProcess -pipeName $Global:pipeName -commandToSend $command

        # Split the response into an array using ';' and loop through each part
        $responseParts = $response -split ';'
        foreach ($part in $responseParts) {
            Update-Log $part.Trim() "M365TextBox"
        }

    } catch {
        # Log the exception
        Update-Log "Failed to send commands: $_" "M365TextBox"
    }   
    $TestClientConnectionButton.IsEnabled = $true
}

function CollectTriageButton_Click {
    Update-Log "Collecting Triage data..." "M365TextBox"
	$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "TriageCollection_$timestamp"

    $scriptBlock = {
        param(
			$currentcasedirectory,
			$pipeName
		)

		function Send-CommandToProcess {
			param(
                [string]$pipeName,			
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		# Build the command string with all parameters
		$command = "Collect-Triage;$currentcasedirectory"
		$response = Send-CommandToProcess -pipeName $pipeName -commandToSend $command

    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $global:currentcasedirectory, $Global:pipeName
    $Global:m365triageJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365triageJobTimer.Enabled) {
        $m365triageJobTimer.Start()
    }
    Update-Log "Triage collection job ($jobName) started." "M365TextBox"
}

function CollectUALButton_Click {
    Update-Log "Collecting Unified Audit Logs..." "M365TextBox"
	$selectedUserOption = $CollectUALUsersComboBox.SelectedItem.Content.ToString()
    $selectedIPOption = $CollectUALIPsComboBox.SelectedItem.Content.ToString()
    $selectedDateOption = $CollectUALDateComboBox.SelectedItem.Content.ToString()
    $selectedOperationsOption = $CollectUALOperationsComboBox.SelectedItem.Content.ToString()
    $StartDate = if ($selectedDateOption -eq "Custom Date") { $M365StartDatePicker.SelectedDate } else { (Get-Date).AddDays(-90) }
	$StartDate = $StartDate.ToString("yyyy-MM-dd")
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "UALCollection_$timestamp"

    $scriptBlock = {
        param(
			$selectedUserOption,
			$currentcasedirectory, 
			$usernamesFilePath, 			
			$selectedIPOption,
			$selectedOperationsOption,
			$ipAddressesFilePath,
			$StartDate,
			$pipeName
		)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		# Build the command string with all parameters
		$command = "Collect-UAL;$selectedUserOption;$currentcasedirectory;$usernamesFilePath;$selectedIPOption;$selectedOperationsOption;$ipAddressesFilePath;$StartDate"
		$response = Send-CommandToProcess -pipeName $pipeName -commandToSend $command

    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedUserOption, $global:currentcasedirectory, $global:usernamesFilePath, $selectedIPOption, $selectedOperationsOption, $global:ipAddressesFilePath, $StartDate, $Global:pipeName
    $Global:m365UALJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365UALJobTimer.Enabled) {
        $m365UALJobTimer.Start()
    }
    Update-Log "Unified Audit Log collection job ($jobName) started." "M365TextBox"
}

function CollectMALButton_Click {
    Update-Log "Collecting Mailbox Audit Logs..." "M365TextBox"

	$selectedOption = $CollectMALComboBox.SelectedItem.Content.ToString()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "MALCollection_$timestamp"

    $scriptBlock = {
        param($selectedOption, $currentcasedirectory, $usernamesFilePath, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		if ($selectedOption -eq "Entire Tenant") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-MailboxAuditLogs;Entire Tenant;$global:currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-MailboxAuditLogs;CustomUsers;$global:currentcasedirectory;$global:usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting MAL Logs."
		}
    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365MALJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365MALJobTimer.Enabled) {
        $m365MALJobTimer.Start()
    }
    Update-Log "Mail Audit Log collection job ($jobName) started." "M365TextBox"
}

function CollectAdminLogsButton_Click {
    Update-Log "Collecting Admin Audit Logs..." "M365TextBox"
	
	$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "AdminLogCollection_$timestamp"
	
    $scriptBlock = {
        param($currentcasedirectory, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-AdminLogs;$currentcasedirectory"
		return $response
	}

    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $global:currentcasedirectory, $Global:pipeName
    $Global:m365AdminLogsJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365AdminLogsJobTimer.Enabled) {
        $m365AdminLogsJobTimer.Start()
    }
    Update-Log "Admin Audit Log collection job ($jobName) started." "M365TextBox"
}

function CollectInboxRulesButton_Click {
    Update-Log "Starting Inbox Rules Collection..." "M365TextBox"
    
    $selectedOption = $CollectInboxRulesComboBox.SelectedItem.Content.ToString()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "InboxRulesCollection_$timestamp"

    $scriptBlock = {
        param($selectedOption, $currentcasedirectory, $usernamesFilePath, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		if ($selectedOption -eq "Entire Tenant") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-InboxRules;Entire Tenant;$global:currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-InboxRules;CustomUsers;$global:currentcasedirectory;$global:usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting inbox rules."
		}
    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365InboxRulesJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365InboxRulesJobTimer.Enabled) {
        $m365InboxRulesJobTimer.Start()
    }
    Update-Log "Inbox rules collection job ($jobName) started." "M365TextBox"
}

function CollectForwardingRulesButton_Click {
    Update-Log "Collecting Forwarding Rules..." "M365TextBox"
    
    $selectedOption = $CollectForwardingRulesComboBox.SelectedItem.Content.ToString()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "ForwardingRulesCollection_$timestamp"

    $scriptBlock = {
        param($selectedOption, $currentcasedirectory, $usernamesFilePath, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true					
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}					
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		if ($selectedOption -eq "Entire Tenant") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-ForwardingRules;Entire Tenant;$global:currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-ForwardingRules;CustomUsers;$global:currentcasedirectory;$global:usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting forwarding rules."
		}
    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365ForwardingRulesJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365ForwardingRulesJobTimer.Enabled) {
        $m365ForwardingRulesJobTimer.Start()
    }

    Update-Log "Inbox rules collection job ($jobName) started." "M365TextBox"
}

function CollectM365InfoButton_Click {
    Update-Log "Collecting M365 Tenant Information..." "M365TextBox"
	$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "M365InfoCollection_$timestamp"
	
    $scriptBlock = {
        param($currentcasedirectory, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-M365Info;$currentcasedirectory"
		return $response
	}

    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $global:currentcasedirectory, $Global:pipeName
    $Global:m365InfoJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365InfoJobTimer.Enabled) {
        $m365InfoJobTimer.Start()
    }
    Update-Log "M365 Information collection job ($jobName) started." "M365TextBox"
}

function CollectMessageTraceButton_Click {
    Update-Log "Collecting Message Trace Logs..." "M365TextBox"
    $selectedOption = $CollectMessageTraceComboBox.SelectedItem.Content.ToString()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "MessageTraceCollection_$timestamp"

    $scriptBlock = {
        param($selectedOption, $currentcasedirectory, $usernamesFilePath, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		if ($selectedOption -eq "Entire Tenant") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-MessageTrace;Entire Tenant;$global:currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-MessageTrace;CustomUsers;$global:currentcasedirectory;$global:usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting inbox rules."
		}
    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365MessageTraceJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365MessageTraceJobTimer.Enabled) {
        $m365MessageTraceJobTimer.Start()
    }
    Update-Log "Mesasge Trace collection job ($jobName) started." "M365TextBox"
}

function CollectAzureLogsButton_Click {
    Update-Log "Collecting Azure Logs..." "M365TextBox"
	$selectedUserOption = $CollectAzureLogsComboBox.SelectedItem.Content.ToString()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "AzureCollection_$timestamp"

    $scriptBlock = {
        param(
			$selectedUserOption,
			$currentcasedirectory, 
			$usernamesFilePath,
			$pipeName
		)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		# Build the command string with all parameters
		$command = "Collect-AzureLogs;$selectedUserOption;$currentcasedirectory;$usernamesFilePath"
		$response = Send-CommandToProcess -pipeName $pipeName -commandToSend $command

    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedUserOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365AzureLogsJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365AzureLogsJobTimer.Enabled) {
        $m365AzureLogsJobTimer.Start()
    }
    Update-Log "Azure Log collection job ($jobName) started." "M365TextBox"
}

function CollectLastPasswordChangeButton_Click {
    Update-Log "Collecting Last Password Change Logs..." "M365TextBox"
    $selectedOption = $CollectLastPasswordComboBox.SelectedItem.Content.ToString()
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $jobName = "LastPasswordChangeCollection_$timestamp"

    $scriptBlock = {
        param($selectedOption, $currentcasedirectory, $usernamesFilePath, $pipeName)

		function Send-CommandToProcess {
			param(
				[string]$pipeName,
				[string]$commandToSend
			)
			$maxRetries = 150
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(5000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {					
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
						}				
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return $response
					} else {
						Write-Host "Failed to connect to server. Retrying..."
						Start-Sleep -Seconds $retryDelay
						$retryCount++
					}
				} catch {
					Write-Host "Error: $_. Retrying..."
					Start-Sleep -Seconds $retryDelay
					$retryCount++
				}
			}
			Write-Host "Failed to connect to server after $maxRetries retries."
		}
        # Send command to server and return response
		if ($selectedOption -eq "Entire Tenant") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-LastPasswordChange;Entire Tenant;$global:currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-LastPasswordChange;CustomUsers;$global:currentcasedirectory;$global:usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting inbox rules."
		}
    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365LastPassJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365LastPassJobTimer.Enabled) {
        $m365LastPassJobTimer.Start()
    }
    Update-Log "Last Password Change collection job ($jobName) started." "M365TextBox"
}

####End of m365 functions####

# ---- MemoryCollection.ps1 ----

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

##memoryfunctions start
function OnTabCollectMemory_GotFocus {
    if ($global:hasRunOnTabCollectMemory) {
        return
    }    
    $subDirectoryPath = Join-Path $global:currentcasedirectory "MemoryArtifacts"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'MemoryArtifacts' created successfully." "MemoryTextBox"
    }
	
    if (-not (IsValidPath $VolatilityPathTextBox.Text "vol.py")) {
        Find-VolExecutable
    }
    if (-not (IsValidPath $WinpmemPathTextBox.Text "winpmem*.exe")) {
        Find-WinpmemExecutable
    }
	$global:hasRunOnTabCollectMemory = $true
}

function IsValidPath($path, $pattern) {
    if ([string]::IsNullOrEmpty($path)) {
        return $false
    }

    # If pattern contains '*', treat it as a regex pattern
    if ($pattern -like "*\*") {
        # Convert wildcard pattern to regex pattern
        $regexPattern = "^" + [regex]::Escape($pattern).Replace('\*', '.*') + "$"
        return ($path -match $regexPattern) -and (Test-Path $path)
    } else {
        return $path.EndsWith($pattern) -and (Test-Path $path)
    }
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
    $winpmemPath = $WinpmemPathTextBox.Text
    if (-not $winpmemPath -or -not (Test-Path $winpmemPath)) {
        Update-Log "Winpmem executable path is not valid." "MemoryTextBox"
        return
    }

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
	$captureCommand = "`"$memoryFilePath`""
	Update-Log "Executing command: $winpmemPath $captureCommand" "MemoryTextBox"
	Start-Process -FilePath $winpmemPath -ArgumentList $captureCommand

    Update-Log "Memory capture started in new window." "MemoryTextBox"
}

function Check-VolJobStatus {
    foreach ($job in $Global:volJobs) {
        if ($job.JobObject.JobStateInfo.State -eq "Completed" -or $job.JobObject.JobStateInfo.State -eq "Failed") {
            if (-not $job.DataAdded) {
                Update-Log "Finished Volatility plugin: $($job.PluginName)" "MemoryTextBox"
                $job.DataAdded = $true
                $Global:completedJobs++
            }
        }
    }

    if ($Global:completedJobs -ge $Global:volJobs.Count) {
        Update-Log "All jobs completed." "MemoryTextBox"
        $volJobTimer.Stop() # Stop the timer after all jobs are completed
    }
}

function ProcessVolatilityButton_Click {
    Update-Log "Processing Memory..." "MemoryTextBox"

    # Validations
    if (-not $MemoryPathTextBox.Text -or -not $OSSelectionComboBox.SelectedItem -or -not $PluginsComboBox.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a memory path, OS type, and a plugin.")
        return
    }

    if (-not (Check-PythonInstalled)) {
        [System.Windows.MessageBox]::Show("Python is not installed. Please install Python to continue.")
        return
    }

    # Processing with selected options
	$volatilityPath  = $VolatilityPathTextBox.Text.trim().Trim('"')
    $memoryFilePath = $MemoryPathTextBox.Text.trim().Trim('"')
    $selectedOs = $OSSelectionComboBox.SelectedItem
    $selectedPlugin = $PluginsComboBox.SelectedItem
	if ([string]::IsNullOrWhiteSpace($memoryFilePath)) {
		Write-Warning "Memory file path is null or empty."
		return
	}
	
    Process-Volatility -MemoryFilePath $memoryFilePath -OS $selectedOs -Plugin $selectedPlugin -VolatilityPath $volatilityPath
	$volJobTimer.Start() # Start the timer when processing begins
}

function Process-Volatility {
    param(
        [string]$MemoryFilePath,
        [string]$OS,
        [string]$Plugin,
		[string]$VolatilityPath
    )
	
    $Global:volJobs = @()
    $Global:completedJobs = 0	
	
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
    
    $job = Start-Job -ScriptBlock {
        param($volatilityPath, $memoryFilePath, $pluginsToRun, $volOutputDirectory)
        
        foreach ($pluginName in $pluginsToRun.Keys) {
            $plugin = $pluginsToRun[$pluginName]
            $pluginCommand = "python `"$volatilityPath`" -f `"$memoryFilePath`" -q -r csv $plugin"
            try {
                $output = Invoke-Expression $pluginCommand
                $memoryFileName = (Split-Path $memoryFilePath -Leaf).TrimEnd('.raw')
                $outputFile = Join-Path $volOutputDirectory "$memoryFileName`_$pluginName.csv"
                $output | ConvertFrom-Csv | Export-Csv $outputFile -NoTypeInformation
            } catch {
                Write-Warning "Failed to process plugin $pluginName"
            }
        }
    } -ArgumentList $VolatilityPath, $MemoryFilePath, $pluginToRun, $volOutputDirectory

    $Global:volJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = $Plugin
        DataAdded = $false
    }
}

# ---- PacketCapture.ps1 ----

$global:packetCaptureJob = $null
$global:jobTimer = $null

function OnTabCollectPacketCapture_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "NetworkArtifacts"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'NetworkArtifacts' created successfully." "PacketCaptureTextBox"
    }
	
	    # Check if Etl2PcapngPathTextBox already has a valid path
    if (-not [string]::IsNullOrEmpty($Etl2PcapngPathTextBox.Text) -and 
        $Etl2PcapngPathTextBox.Text.EndsWith("etl2pcapng.exe") -and 
        (Test-Path $Etl2PcapngPathTextBox.Text)) {
        return
    }
	
    # Search for the etl2pcapng.exe executable
    Find-Etl2PcapngExecutable	
}

function ExtractCabFileButton_Click {
    # Your logic for extracting Cab file
    Update-Log "Extracting Cab File..." "PacketCaptureTextBox"
    Extract-CabFile
}

function StartPacketCaptureButton_Click {
    # Disable the button
    $StartPacketCaptureButton.IsEnabled = $false

    # Your existing logic for starting packet capture
    Update-Log "Starting Packet Capture..." "PacketCaptureTextBox"
    Process-PacketCapture -captureTimeInput $CaptureTimeTextBox.Text.Trim()
}

function Process-PacketCapture {
    param (
        [string]$captureTimeInput
    )

    [double]$captureTime = 0
    if ([double]::TryParse($captureTimeInput, [ref]$captureTime)) {
        if ($captureTime -le 0) {
            $captureTime = 5
        }
    } else {
        $captureTime = 5
    }

    Update-Log "Starting network packet capture for $captureTime minutes..." "PacketCaptureTextBox"

    $currentTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $systemName = $env:COMPUTERNAME
    $fileName = "$systemName`_$currentTimestamp"
    $filePath = Join-Path $global:currentcasedirectory "NetworkArtifacts\$fileName.etl"

    $captureTimeInSeconds = $captureTime * 60
    $traceCommand = "netsh trace start capture=yes tracefile=`"$filePath`" report=no maxsize=512 correlation=no overwrite=no; Start-Sleep -Seconds $captureTimeInSeconds; netsh trace stop"
    
    # Print the command to the log
    Update-Log "Executing command: $traceCommand" "PacketCaptureTextBox"

    # Start the job and the timer
    Start-PacketCaptureJob -TraceCommand $traceCommand
}

function Start-PacketCaptureJob {
    param (
        [string]$TraceCommand
    )

    if ($global:packetCaptureJob -ne $null -and (Get-Job -Id $global:packetCaptureJob.Id).State -eq 'Running') {
        Update-Log "A packet capture job is already running." "PacketCaptureTextBox"
        return
    }

    try {
        # Start the packet capture job
        $global:packetCaptureJob = Start-Job -ScriptBlock {
            param($command)
            Invoke-Expression $command
        } -ArgumentList $TraceCommand

        Update-Log "Packet capture job started. Job ID: $($global:packetCaptureJob.Id)" "PacketCaptureTextBox"

        # Create a timer to check the job status periodically
        $global:netTraceJobTimer = New-Object System.Windows.Threading.DispatcherTimer
        $global:netTraceJobTimer.Interval = [TimeSpan]::FromSeconds(10)
        $global:netTraceJobTimer.Add_Tick({
            if ($global:packetCaptureJob -and (Get-Job -Id $global:packetCaptureJob.Id).State -ne 'Running') {
                if ((Get-Job -Id $global:packetCaptureJob.Id).State -eq 'Completed') {
                    Update-Log "Packet capture job has completed." "PacketCaptureTextBox"
                } else {
                    Update-Log "Packet capture job has stopped or failed." "PacketCaptureTextBox"
                }

                $StartPacketCaptureButton.IsEnabled = $true
                Remove-Job -Job $global:packetCaptureJob -Force
                $global:packetCaptureJob = $null
                $global:netTraceJobTimer.Stop()
            }
        })
        $global:netTraceJobTimer.Start()
    } catch {
        Update-Log "Error starting packet capture job: $_" "PacketCaptureTextBox"
    }
}



function Extract-CabFile {
    $cabFiles = Get-ChildItem -Path "$global:currentcasedirectory\NetworkArtifacts" -Filter "*.cab" -File
    foreach ($cabFile in $cabFiles) {
        $extractedDirectory = "$($cabFile.Directory)\$($cabFile.BaseName)_cab"
        if (-not (Test-Path $extractedDirectory)) {
            Update-Log "Extracting $($cabFile.Name)..." "PacketCaptureTextBox"
            $null = New-Item -Path $extractedDirectory -ItemType Directory -Force
            $expandArguments = @(
                "/I",
                "`"$($cabFile.FullName)`"",
                "/F:*",
                "`"$extractedDirectory`""
            )
            Start-Process -FilePath "expand" -ArgumentList $expandArguments -Wait -NoNewWindow
            Update-Log "Extraction completed for $($cabFile.Name)" "PacketCaptureTextBox"
        } else {
            Update-Log "The directory $extractedDirectory already exists. Skipping extraction of $($cabFile.Name)." "PacketCaptureTextBox"
        }
    }
}

function ConvertETL2PCAPButton_Click {
    # Your logic for converting ETL to PCAP
    Update-Log "Converting ETL to PCAP..." "PacketCaptureTextBox"
    Convert-ETL2PCAP
}

function Convert-ETL2PCAP {
    # Try to find etl2pcapng.exe in the default location first
    $etl2PcapngPath = $Etl2PcapngPathTextBox.Text
    if (-not (Test-Path $etl2PcapngPath)) {
        Update-Log "etl2pcapng.exe path is not valid. Please provide the correct path." "PacketCaptureTextBox"
        return
    }
	# Function to validate etl2pcapng.exe path
    function IsValidEtl2PcapngPath($path) {
        return -not [string]::IsNullOrEmpty($path) -and (Test-Path $path) -and $path.EndsWith("etl2pcapng.exe")
    }

    if (-not (IsValidEtl2PcapngPath $etl2PcapngPath)) {
        Update-Log "etl2pcapng.exe path is not valid. Please provide the correct path." "PacketCaptureTextBox"
        return
    }
    # Convert ETL files to PCAP
    $networkArtifactsPath = Join-Path $global:currentcasedirectory "NetworkArtifacts"
	$etlFiles = Get-ChildItem -Path $networkArtifactsPath -Filter "*.etl" -Recurse | Where-Object { $_.Name -ne "report.etl" }

    foreach ($etlFile in $etlFiles) {
        $pcapSubdirectory = "$($etlFile.BaseName)_pcap"
        $pcapSubdirectoryPath = Join-Path $networkArtifactsPath $pcapSubdirectory
        if (-not (Test-Path $pcapSubdirectoryPath)) {
            New-Item -ItemType Directory -Path $pcapSubdirectoryPath | Out-Null
            $pcapFileName = [System.IO.Path]::ChangeExtension($etlFile.Name, "pcap")
            $pcapFilePath = Join-Path $pcapSubdirectoryPath $pcapFileName

            Update-Log "Converting $($etlFile.Name) to PCAP..." "PacketCaptureTextBox"
			
            & $etl2PcapngPath $etlFile.FullName $pcapFilePath
            Update-Log "Conversion completed for $($etlFile.Name)" "PacketCaptureTextBox"
        } else {
            Update-Log "The directory $pcapSubdirectoryPath already exists. Skipping conversion of $($etlFile.Name)." "PacketCaptureTextBox"
        }
    }
}

function Find-Etl2PcapngExecutable {
    $etl2PcapngPath = Get-ChildItem -Path $toolsDirectory -Filter "etl2pcapng.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Check if the path ends with etl2pcapng.exe
    if ($etl2PcapngPath -and $etl2PcapngPath.EndsWith("etl2pcapng.exe")) {
        $etl2PcapngPathTextBox.Text = $etl2PcapngPath
        $convertETL2PCAPButton.IsEnabled = $true
    } else {
        $etl2PcapngPathTextBox.Text = ""
        $convertETL2PCAPButton.IsEnabled = $false
    }
}

# ---- ThreatScanners.ps1 ----

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

# ---- ToolManagement.ps1 ----

$global:hasRunOnTabPageTools = $false

#Timer for downloading tools
$Global:tooldownloadJobs = @()
$Global:activeToolDownloads = @{}
$Global:toolDownloadStatuses = @{}
$script:toolManagementScriptPath = Join-Path $PSScriptRoot "ToolManagement.ps1"
$tooldownloadJobTimer = New-Object System.Windows.Forms.Timer
$tooldownloadJobTimer.Interval = 2000
$tooldownloadJobTimer.Add_Tick({
    Check-tooldownloadJobStatus
})

####Starting functions for Tools Tab####

function Test-ToolDownloadActive {
    return @($Global:tooldownloadJobs | Where-Object {
        $_.JobObject -and
        ($_.JobObject.State -eq 'Running' -or $_.JobObject.State -eq 'NotStarted')
    }).Count -gt 0
}

function Set-ToolDownloadStatus {
    param(
        [string]$ToolName,
        [string]$StatusText
    )

    if ([string]::IsNullOrWhiteSpace($ToolName)) {
        return
    }

    $Global:toolDownloadStatuses[$ToolName] = $StatusText
}

function Update-SelectedToolDownloadStatus {
    if (-not $ToolDownloadStatusTextBlock) {
        return
    }

    $selectedTool = $null
    if ($ToolsSelectionComboBox -and $ToolsSelectionComboBox.SelectedItem -and $ToolsSelectionComboBox.SelectedItem.Content) {
        $selectedTool = [string]$ToolsSelectionComboBox.SelectedItem.Content
    }

    if ([string]::IsNullOrWhiteSpace($selectedTool)) {
        $ToolDownloadStatusTextBlock.Text = "Status: Idle"
        return
    }

    if ($Global:toolDownloadStatuses.ContainsKey($selectedTool)) {
        $ToolDownloadStatusTextBlock.Text = "Status: $($Global:toolDownloadStatuses[$selectedTool])"
    } else {
        $ToolDownloadStatusTextBlock.Text = "Status: Idle"
    }
}

function Update-DownloadToolButtonState {
    if (-not $DownloadToolButton) {
        return
    }

    $hasSelection = $false
    if ($ToolsSelectionComboBox -and $ToolsSelectionComboBox.SelectedItem -and $ToolsSelectionComboBox.SelectedItem.Content) {
        $hasSelection = $true
    }

    $isBusy = Test-ToolDownloadActive
    $DownloadToolButton.IsEnabled = $hasSelection -and (-not $isBusy)
    if ($ToolsSelectionComboBox) {
        $ToolsSelectionComboBox.IsEnabled = -not $isBusy
    }
    Update-SelectedToolDownloadStatus
}

function Invoke-ExternalProcessQuiet {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [AllowEmptyString()]
        [string]$ArgumentList = "",
        [string]$WorkingDirectory,
        [string]$ErrorContext = "external process",
        [int]$TimeoutSeconds = 600,
        [switch]$UseShellExecuteHidden
    )

    $stdoutPath = Join-Path ([System.IO.Path]::GetTempPath()) ("ECHO_stdout_{0}.log" -f ([guid]::NewGuid().ToString("N")))
    $stderrPath = Join-Path ([System.IO.Path]::GetTempPath()) ("ECHO_stderr_{0}.log" -f ([guid]::NewGuid().ToString("N")))

    $process = $null
    try {
        $stdoutText = ""
        $stderrText = ""
        if ($UseShellExecuteHidden) {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $FilePath
            $psi.Arguments = $ArgumentList
            $psi.UseShellExecute = $true
            $psi.CreateNoWindow = $true
            $psi.WindowStyle = [System.Diagnostics.ProcessWindowStyle]::Hidden
            if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
                $psi.WorkingDirectory = $WorkingDirectory
            }

            $process = [System.Diagnostics.Process]::Start($psi)
            if (-not $process) {
                throw ("{0} failed to start: {1}" -f $ErrorContext, $FilePath)
            }
        } else {
            $psi = New-Object System.Diagnostics.ProcessStartInfo
            $psi.FileName = $FilePath
            $psi.Arguments = $ArgumentList
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
                $psi.WorkingDirectory = $WorkingDirectory
            }

            $process = New-Object System.Diagnostics.Process
            $process.StartInfo = $psi
            $started = $process.Start()
            if (-not $started) {
                throw ("{0} failed to start: {1}" -f $ErrorContext, $FilePath)
            }
            $stdoutTask = $process.StandardOutput.ReadToEndAsync()
            $stderrTask = $process.StandardError.ReadToEndAsync()
        }

        $timeoutMs = [Math]::Max(1000, ($TimeoutSeconds * 1000))
        if (-not $process.WaitForExit($timeoutMs)) {
            try { $process.Kill() } catch {}
            throw ("{0} timed out after {1} seconds." -f $ErrorContext, $TimeoutSeconds)
        }
        if (-not $UseShellExecuteHidden) {
            [System.Threading.Tasks.Task]::WaitAll(@($stdoutTask, $stderrTask), 5000) | Out-Null
            $stdoutText = $stdoutTask.Result
            $stderrText = $stderrTask.Result
        }
        if (-not [string]::IsNullOrWhiteSpace($stdoutText)) {
            Set-Content -LiteralPath $stdoutPath -Value $stdoutText -Encoding UTF8 -ErrorAction SilentlyContinue
        }
        if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
            Set-Content -LiteralPath $stderrPath -Value $stderrText -Encoding UTF8 -ErrorAction SilentlyContinue
        }

        if ($process.ExitCode -ne 0) {
            $stderrText = ""
            if (Test-Path -LiteralPath $stderrPath) {
                $stderrText = (Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue).Trim()
            }
            if ([string]::IsNullOrWhiteSpace($stderrText) -and (Test-Path -LiteralPath $stdoutPath)) {
                $stderrText = (Get-Content -LiteralPath $stdoutPath -Raw -ErrorAction SilentlyContinue).Trim()
            }
            throw ("{0} failed with exit code {1}. {2}" -f $ErrorContext, $process.ExitCode, $stderrText)
        }
    } finally {
        if ($process) {
            try { $process.Dispose() } catch {}
        }
        Remove-Item -LiteralPath $stdoutPath -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
}

function Start-ToolDownloadJob {
    param(
        [string]$SelectedOption,
        [string]$GeoLiteLicenseKeyPlain
    )

    $job = Start-Job -ScriptBlock {
        param($selectedTool, $toolsDir, $toolManagementPath, $geoLiteLicense)

        function Update-Log {
            param([string]$message, [string]$callerFunction)
            if (-not [string]::IsNullOrWhiteSpace($message)) {
                Write-Output $message
            }
        }

        try {
            Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
            $ProgressPreference = 'SilentlyContinue'
            $VerbosePreference = 'SilentlyContinue'
            $InformationPreference = 'SilentlyContinue'
            $global:toolsDirectory = $toolsDir
            . $toolManagementPath

            switch ($selectedTool) {
                "7zip" { Download-7zip }
                "BulkExtractor" { Download-BulkExtractor }
                "chainsaw" { Download-chainsaw }
                "ClamAV" { Download-ClamAV }
                "etl2pcapng" { Download-etl2pcapng }
                "Ftkimager" { Download-Ftkimager }
                "GeoLite2Databases" {
                    if ([string]::IsNullOrWhiteSpace($geoLiteLicense)) {
                        Update-Log "GeoLite2 City download cancelled or no license key entered." "tabPageToolsTextBox"
                    } else {
                        $secureLicenseKey = ConvertTo-SecureString $geoLiteLicense -AsPlainText -Force
                        Download-GeoLite2Databases -licenseKey $secureLicenseKey
                    }
                }
                "Hayabusa" { Download-Hayabusa }
                "Loki" { Download-Loki }
                "Plaso" { Download-Plaso }
                "SQLite" { Download-SQLite }
                "Velociraptor" { Download-Velociraptor }
                "Volatility3" { Download-Volatility3 }
                "winpmem" { Download-winpmem }
                "ZimmermanTools" { Download-ZimmermanTools }
                "Zircolite" { Download-Zircolite }
                default { Update-Log "Unknown tool selection: $selectedTool" "tabPageToolsTextBox" }
            }
        } catch {
            Write-Output ("Unhandled tool download error for {0}: {1}" -f $selectedTool, $_.Exception.Message)
            throw
        }
    } -ArgumentList @($SelectedOption, $toolsDirectory, $script:toolManagementScriptPath, $GeoLiteLicenseKeyPlain)

    $Global:tooldownloadJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = $SelectedOption
        DataAdded = $false
    }
    $Global:activeToolDownloads[$SelectedOption] = $true
    Set-ToolDownloadStatus -ToolName $SelectedOption -StatusText ("Running (started {0})" -f (Get-Date -Format "HH:mm:ss"))
    $tooldownloadJobTimer.Start()
    Update-DownloadToolButtonState
}

function Check-tooldownloadJobStatus {
    $remainingJobs = @()

    foreach ($job in $Global:tooldownloadJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $updatedJob) {
            continue
        }

        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed" -or $updatedJob.State -eq "Stopped") {
            if (-not $job.DataAdded) {
                $jobOutput = @()
                try {
                    $jobOutput = @(Receive-Job -Id $updatedJob.Id -ErrorAction Stop | ForEach-Object { [string]$_ })
                } catch {
                    Update-Log ("Failed to read background output for {0}: {1}" -f $job.JobName, $_.Exception.Message) "tabPageToolsTextBox"
                }
                foreach ($line in $jobOutput) {
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        Update-Log $line "tabPageToolsTextBox"
                    }
                }

                if ($updatedJob.State -eq "Completed") {
                    Update-Log "Tool download completed: $($job.JobName)" "tabPageToolsTextBox"
                    Update-Log "Results in $($toolsDirectory)" "tabPageToolsTextBox"
                    Set-ToolDownloadStatus -ToolName $job.JobName -StatusText ("Completed ({0})" -f (Get-Date -Format "HH:mm:ss"))
                } else {
                    $failureReason = $null
                    if ($updatedJob.ChildJobs -and $updatedJob.ChildJobs.Count -gt 0) {
                        $failureReason = $updatedJob.ChildJobs[0].JobStateInfo.Reason
                    }
                    if ($failureReason) {
                        Update-Log "Tool download failed: $($job.JobName) - $failureReason" "tabPageToolsTextBox"
                    } else {
                        Update-Log "Tool download failed: $($job.JobName)" "tabPageToolsTextBox"
                    }
                    Set-ToolDownloadStatus -ToolName $job.JobName -StatusText ("Failed ({0})" -f (Get-Date -Format "HH:mm:ss"))
                }

                $job.DataAdded = $true
                if ($Global:activeToolDownloads.ContainsKey($job.JobName)) {
                    $Global:activeToolDownloads.Remove($job.JobName) | Out-Null
                }
            }

            Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
            continue
        }

        $remainingJobs += $job
    }

    $Global:tooldownloadJobs = $remainingJobs
    if ($Global:tooldownloadJobs.Count -eq 0) {
        $tooldownloadJobTimer.Stop()
    }
    Update-DownloadToolButtonState
}

function OnTabTabPageTools_GotFocus {
    if ($global:hasRunOnTabPageTools) {
        Update-SelectedToolDownloadStatus
        Update-DownloadToolButtonState
        return
    }    		
    # Create subdirectory if it doesn't exist
    if (!(Test-Path $toolsDirectory)) {
        New-Item -ItemType Directory -Path $toolsDirectory | Out-Null
        Update-Log "Subdirectory 'Tools' created successfully." "tabPageToolsTextBox"
    }
		$global:hasRunOnTabPageTools = $true
    Update-SelectedToolDownloadStatus
    Update-DownloadToolButtonState
}

function Add-ToolToCsv {
    param(
        [string]$toolName,
        [string]$filePath
    )
    if ([string]::IsNullOrWhiteSpace($filePath)) {
        $filePath = Get-ChildItem -Path $toolsDirectory -Filter "$toolName" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    }

    if ($null -ne $filePath -and (Test-Path $filePath)) {
        $csvPath = Join-Path $toolsDirectory "tools.csv"
        $hash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash

        # Read existing CSV data if it exists
        $existingData = @()
        if (Test-Path $csvPath) {
            $existingData = Import-Csv -Path $csvPath
        }

        # Check if an entry with the same hash already exists
        $existingEntry = $existingData | Where-Object { $_."SHA256 Hash" -eq $hash }
        if ($existingEntry) {
            return
        }
 
        $fileInfo = Get-Item $filePath
        $creationDate = $fileInfo.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
        $modificationDate = $fileInfo.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")

        $toolInfo = [PSCustomObject]@{
            "Tool Name" = $toolName
            "SHA256 Hash" = $hash
            "Creation Date" = $creationDate
            "Modification Date" = $modificationDate
        }

        # Append to CSV
		try {
			$toolInfo | Export-Csv -Path $csvPath -NoTypeInformation -Append
		} catch {
			Update-Log "Failed to update tools.csv. It might be open in another program: $_" "tabPageToolsTextBox"
		}
    } else {
        Update-Log "Tool not found: $toolName" "tabPageToolsTextBox"
    }
}

function Test-InternetConnection {
    param (
        [string]$TestUri = "http://www.google.com"
    )

    try {
        $request = [System.Net.WebRequest]::Create($TestUri)
        $request.Timeout = 5000
        $response = $request.GetResponse()
        $response.Close()
        return $true
    } catch {
        return $false
    }
}

function DownloadToolButton_Click {
    if (-not $ToolsSelectionComboBox.SelectedItem -or -not $ToolsSelectionComboBox.SelectedItem.Content) {
        Update-Log "Select a tool before starting download/update." "tabPageToolsTextBox"
        return
    }

    if (Test-ToolDownloadActive) {
        Update-Log "A tool download is already running. Wait for it to complete before starting another." "tabPageToolsTextBox"
        Update-DownloadToolButtonState
        return
    }

    $selectedOption = $ToolsSelectionComboBox.SelectedItem.Content.ToString()
    # Check for Internet Connection
    if (-not (Test-InternetConnection)) {
        Update-Log "Internet connection not available, cannot download tool." "tabPageToolsTextBox"
        return
    }

    $geoLiteLicenseKeyPlain = $null
    if ($selectedOption -eq "GeoLite2Databases") {
        # Create a new form for license key input
            $licenseKeyForm = New-Object System.Windows.Forms.Form
            $licenseKeyForm.Text = 'Enter GeoLite2 License Key'
            $licenseKeyForm.Size = New-Object System.Drawing.Size(500, 200)
            $licenseKeyForm.StartPosition = 'CenterScreen'

            # Add license key box
            $licenseKeyBox = New-Object System.Windows.Forms.TextBox
            $licenseKeyBox.UseSystemPasswordChar = $true
            $licenseKeyBox.Location = New-Object System.Drawing.Point(10, 40)
            $licenseKeyBox.Size = New-Object System.Drawing.Size(450, 20)
            $licenseKeyForm.Controls.Add($licenseKeyBox)

            # Add OK button
            $okButton = New-Object System.Windows.Forms.Button
            $okButton.Text = 'OK'
            $okButton.Location = New-Object System.Drawing.Point(200, 70)
            $okButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $licenseKeyForm.AcceptButton = $okButton
            $licenseKeyForm.Controls.Add($okButton)

            # Show license key input form as a dialog
            $result = $licenseKeyForm.ShowDialog()

            if ($result -eq [System.Windows.Forms.DialogResult]::OK -and $licenseKeyBox.Text) {
                $geoLiteLicenseKeyPlain = $licenseKeyBox.Text
            } else {
                Update-Log "GeoLite2 City download cancelled or no license key entered." "tabPageToolsTextBox"
                return
            }
    }

    Update-Log "Downloading $($selectedOption)..." "tabPageToolsTextBox"
    Start-ToolDownloadJob -SelectedOption $selectedOption -GeoLiteLicenseKeyPlain $geoLiteLicenseKeyPlain
    Update-SelectedToolDownloadStatus
}

function Download-7zip {
    # Setup for 7zr.exe
    $7zipFolder = Join-Path $toolsDirectory "7-Zip"
    if (!(Test-Path $7zipFolder)) {
        New-Item -ItemType Directory -Path $7zipFolder | Out-Null
    }	
    $tempFolder = Join-Path $toolsDirectory "Temp7Zip"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Download 7zr.exe
    $7zrPath = Join-Path $tempFolder "7zr.exe"
    $7zrUrl = "https://www.7-zip.org/a/7zr.exe"
   try {
        Invoke-WebRequest -UseBasicParsing -Uri $7zrUrl -OutFile $7zrPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download 7zip: $_" "tabPageToolsTextBox"
        return
    }

    # Download 7z2301-extra.7z
    $extra7zPath = Join-Path $tempFolder "7z2301-extra.7z"
    $extra7zUrl = "https://www.7-zip.org/a/7z2301-extra.7z"
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $extra7zUrl -OutFile $extra7zPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download 7zip: $_" "tabPageToolsTextBox"
        return
    }

    # Extract 7z2301-extra.7z using 7zr.exe
    try {
        Invoke-ExternalProcessQuiet -FilePath $7zrPath -ArgumentList "x `"$extra7zPath`" -o`"$tempFolder`" -y" -WorkingDirectory $tempFolder -ErrorContext "7zr extraction for 7-Zip package"
    } catch {
        Update-Log "Failed to extract 7-Zip package: $_" "tabPageToolsTextBox"
        throw
    }

    # Check hash and update if necessary
    # Assuming you want to update if 7z.exe is not the latest version
    $new7zPath = Join-Path $tempFolder "7za.exe"
    if (Test-Path $new7zPath) {
        $newHash = (Get-FileHash -Path $new7zPath -Algorithm SHA256).Hash
        $existing7zPath = Join-Path $7zipFolder "7za.exe"
        $existingHash = if (Test-Path $existing7zPath) { (Get-FileHash -Path $existing7zPath -Algorithm SHA256).Hash } else { "" }

        if ($newHash -ne $existingHash) {
            Copy-Item -Path (Join-Path $tempFolder "*") -Destination $7zipFolder -Force
            Add-ToolToCsv -toolName "7za.exe" -filePath $existing7zPath
            Update-Log "7-Zip updated." "tabPageToolsTextBox"
        } else {
            Update-Log "7-Zip is already up-to-date." "tabPageToolsTextBox"
        }
    }

    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-BulkExtractor {
    $bulkExtractorFolder = Join-Path $toolsDirectory "BulkExtractor"
    if (!(Test-Path $bulkExtractorFolder)) {
        New-Item -ItemType Directory -Path $bulkExtractorFolder | Out-Null
    }
    
    $tempFolder = Join-Path $toolsDirectory "TempBulkExtractor"
    $downloadUrl = "https://digitalcorpora.s3.amazonaws.com/downloads/bulk_extractor/bulk_extractor-2.0.0-windows.zip"
    $downloadPath = Join-Path $tempFolder "bulk_extractor-download.zip"

    # Ensure the temporary folder exists
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Download to temporary folder
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Bulk Extractor: $_" "tabPageToolsTextBox"
        return
    }
    Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force

    $tempExecutable = Join-Path $tempFolder "win64\bulk_extractor64.exe"

    if (Test-Path $tempExecutable) {
        $bulkExtractorExecutable = Get-ChildItem -Path $bulkExtractorFolder -Filter "bulk_extractor64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

        $existingHash = if ($bulkExtractorExecutable -and (Test-Path $bulkExtractorExecutable)) { (Get-FileHash -Path $bulkExtractorExecutable -Algorithm SHA256).Hash } else { "" }
        $newHash = (Get-FileHash -Path $tempExecutable -Algorithm SHA256).Hash

        if ($newHash -ne $existingHash) {
            # Update the tool as the hash is different
            $destinationPath = Join-Path $bulkExtractorFolder "bulk_extractor64.exe"
            Copy-Item -Path $tempExecutable -Destination $destinationPath -Force
            Add-ToolToCsv -toolName "bulk_extractor64.exe" -filePath $destinationPath
        } else {
            Update-Log "BulkExtractor is already up-to-date." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded BulkExtractor executable not found." "tabPageToolsTextBox"
    }

    # Clean up temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-chainsaw {
	$7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $7zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($7zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		return
	}
    $chainsawFolder = Join-Path $toolsDirectory "chainsaw"
    if (!(Test-Path $chainsawFolder)) {
        New-Item -ItemType Directory -Path $chainsawFolder | Out-Null
    }		
    $chainsawExecutable = Get-ChildItem -Path $chainsawFolder -Filter "chainsaw*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "Tempchainsaw"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/WithSecureLabs/chainsaw/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^chainsaw_all_platforms.rules.zip$' } | Select-Object -ExpandProperty browser_download_url -First 1
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for chainsaw.exe not found." "tabPageToolsTextBox"
		return
	}
	# Decode the URL to get the correct file name
	$decodedUrl = [System.Web.HttpUtility]::UrlDecode($downloadUrl)
	$originalFileName = Split-Path -Leaf $decodedUrl
	$downloadPath = Join-Path $tempFolder $originalFileName

    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download chainsaw: $_" "tabPageToolsTextBox"
        return
    }
	    if (Test-Path $downloadPath) {
	        # Extract the zip file
			try {
				$7zipArgs = "x `"$downloadPath`" -o`"$tempFolder`" -y"
				Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList $7zipArgs -WorkingDirectory $tempFolder -ErrorContext "7-Zip extraction (temp) for chainsaw"
			} catch {
				Update-Log "Failed to extract chainsaw with 7-Zip: $_" "tabPageToolsTextBox"
				throw
			}

        # Identify the executable based on pattern
        $extractedExecutable = Get-ChildItem -Path $tempFolder -Filter "chainsaw*.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

	        if ($extractedExecutable) {
	            # Calculate hash of the downloaded executable
	            $newHash = (Get-FileHash -Path $extractedExecutable -Algorithm SHA256).Hash
	            $existingHash = if ($chainsawExecutable -and (Test-Path $chainsawExecutable)) { (Get-FileHash -Path $chainsawExecutable -Algorithm SHA256).Hash } else { "" }

	            if (-not $chainsawExecutable -or $newHash -ne $existingHash) {
					# Check and clear the chainsaw folder
					if (Test-Path $chainsawFolder) {
						Remove-Item -Path $chainsawFolder\* -Recurse -Force
					}
	                Add-ToolToCsv -toolName (Split-Path -Leaf $extractedExecutable)
	            } else {
	                Update-Log "chainsaw is already up-to-date." "tabPageToolsTextBox"
	            }
	            # Always refresh chainsaw package contents so rules are updated
				$7zipArgs2 = "x `"$downloadPath`" -o`"$chainsawFolder`" -y"
				Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList $7zipArgs2 -WorkingDirectory $chainsawFolder -ErrorContext "7-Zip extraction (final) for chainsaw"
	            if (-not $chainsawExecutable -or $newHash -ne $existingHash) {
	                Update-Log "chainsaw updated." "tabPageToolsTextBox"
	            } else {
	                Update-Log "chainsaw rules package refreshed." "tabPageToolsTextBox"
	            }
	        } else {
	            Update-Log "Downloaded chainsaw executable not found in the extracted files." "tabPageToolsTextBox"
	        }
    } else {
        Update-Log "Downloaded chainsaw executable not found." "tabPageToolsTextBox"
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-ClamAV {
    $ClamAVFolder = Join-Path $toolsDirectory "ClamAV"
    if (!(Test-Path $ClamAVFolder)) {
        New-Item -ItemType Directory -Path $ClamAVFolder | Out-Null
    }
    $ClamdscanExecutable = Get-ChildItem -Path $ClamAVFolder -Filter "clamdscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $existingFreshclam = Get-ChildItem -Path $ClamAVFolder -Filter "freshclam.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Existing install: prefer DB signature update in place and skip binary download.
    if ($ClamdscanExecutable -and (Test-Path $ClamdscanExecutable) -and $existingFreshclam -and (Test-Path $existingFreshclam)) {
        Update-Log "Existing ClamAV installation found. Updating ClamAV database..." "tabPageToolsTextBox"
        try {
            $freshclamDirectory = Split-Path $existingFreshclam
            Invoke-ExternalProcessQuiet -FilePath $existingFreshclam -WorkingDirectory $freshclamDirectory -ArgumentList "" -ErrorContext "ClamAV database update (existing install)" -TimeoutSeconds 300 -UseShellExecuteHidden
            Update-Log "ClamAV database updated." "tabPageToolsTextBox"
        } catch {
            Update-Log "Error updating ClamAV database: $_" "tabPageToolsTextBox"
            throw
        }
        return
    }

    $tempFolder = Join-Path $toolsDirectory "TempClamAV"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Base URL for ClamAV website
    $baseUrl = "https://www.clamav.net"
    
    # Retrieve the latest release page and parse the download URL
    $apiUrl = "$baseUrl/downloads"
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    $latestReleasePage = Invoke-WebRequest -UseBasicParsing -Uri $apiUrl -Headers @{ "User-Agent" = $userAgent }
    $relativePath = $latestReleasePage.Links | Where-Object { $_.href -match 'clamav-\d+\.\d+\.\d+\.win\.x64\.zip$' } | Select-Object -ExpandProperty href -First 1
    
    # Check if a valid download path was retrieved
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        Update-Log "Download URL for ClamAV not found." "tabPageToolsTextBox"
        return
    }

    # Define the path where the downloaded file will be saved
    $originalFileName = Split-Path -Leaf $relativePath
    $downloadPath = Join-Path $tempFolder $originalFileName
    
    # Construct the full download URL
    $downloadUrl = $baseUrl + $relativePath
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download ClamAV: $_" "tabPageToolsTextBox"
        return
    }

    if (Test-Path $downloadPath) {
        Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force
        Remove-Item -Path $downloadPath -Force
        $extractedClamdscan = Get-ChildItem -Path $tempFolder -Filter "clamdscan.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1
        if ($extractedClamdscan) {
            $newHash = (Get-FileHash -Path $extractedClamdscan -Algorithm SHA256).Hash
            $existingHash = if ($ClamdscanExecutable -and (Test-Path $ClamdscanExecutable)) { (Get-FileHash -Path $ClamdscanExecutable -Algorithm SHA256).Hash } else { "" }

            if (-not $ClamdscanExecutable -or $newHash -ne $existingHash) {
                # Rename and configure the sample configuration files
                $clamdscanDirectory = Split-Path $extractedClamdscan
                $confFiles = Get-ChildItem -Path $tempFolder -Filter "*.conf.sample" -Recurse
                foreach ($file in $confFiles) {
                    $newConfPath = Join-Path $clamdscanDirectory ($file.Name -replace "\.sample$", "")
                    Copy-Item -Path $file.FullName -Destination $newConfPath -Force
                    (Get-Content $newConfPath) | Where-Object { $_ -notmatch "^Example" } | Set-Content $newConfPath
                }

                # Copy updated contents to the ClamAV folder
                Remove-Item -Path $ClamAVFolder\* -Recurse -Force
                Copy-Item -Path $tempFolder\* -Destination $ClamAVFolder -Recurse -Force
				Add-ToolToCsv -toolName "clamdscan.exe"
                Update-Log "ClamAV updated." "tabPageToolsTextBox"
            } else {
                Update-Log "ClamAV is already up-to-date." "tabPageToolsTextBox"
            }
        } else {
            Update-Log "Downloaded ClamAV executable not found in the extracted files." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded ClamAV zip file not found." "tabPageToolsTextBox"
    }
		# Run freshclam to update the database
		try {
			$freshclamPath = Get-ChildItem -Path $ClamAVFolder -Filter "freshclam.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
			if (Test-Path $freshclamPath) {
                Update-Log "Updating ClamAV database..." "tabPageToolsTextBox"
				$freshclamDirectory = Split-Path $freshclamPath
				Invoke-ExternalProcessQuiet -FilePath $freshclamPath -WorkingDirectory $freshclamDirectory -ArgumentList "" -ErrorContext "ClamAV database update (post-download)" -TimeoutSeconds 300 -UseShellExecuteHidden
				Update-Log "ClamAV database updated." "tabPageToolsTextBox"
			} else {
				Update-Log "freshclam.exe not found in ClamAV directory." "tabPageToolsTextBox"
			}
		} catch {
			Update-Log "Error updating ClamAV database: $_" "tabPageToolsTextBox"
            throw
		}

    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-etl2pcapng {
    $etl2pcapngFolder = Join-Path $toolsDirectory "etl2pcapng"
    if (!(Test-Path $etl2pcapngFolder)) {
        New-Item -ItemType Directory -Path $etl2pcapngFolder | Out-Null
    }		
    $etl2pcapngExecutable = Join-Path $etl2pcapngFolder "etl2pcapng.exe"
    $tempFolder = Join-Path $toolsDirectory "Tempetl2pcapng"

    # Ensure the temporary and etl2pcapng folders exist
    New-Item -ItemType Directory -Path $tempFolder, $etl2pcapngFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/microsoft/etl2pcapng/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -eq 'etl2pcapng.exe' } | Select-Object -ExpandProperty browser_download_url
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for etl2pcapng.exe not found." "tabPageToolsTextBox"
		return
	}

    $downloadPath = Join-Path $tempFolder "etl2pcapng.exe"

    # Always download to temporary folder
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download et12pcapng: $_" "tabPageToolsTextBox"
        return
    }

    if (Test-Path $downloadPath) {
        # Compare hash of the downloaded file with the existing one
        $newHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
        $existingHash = if (Test-Path $etl2pcapngExecutable) { (Get-FileHash -Path $etl2pcapngExecutable -Algorithm SHA256).Hash } else { "" }

        if ($newHash -ne $existingHash) {
            # Update the tool as the hash is different
            Copy-Item -Path $downloadPath -Destination $etl2pcapngExecutable -Force
            Add-ToolToCsv -toolName "etl2pcapng.exe" -filePath $etl2pcapngExecutable
            Update-Log "etl2pcapng updated." "tabPageToolsTextBox"
        } else {
            Update-Log "etl2pcapng is already up-to-date." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded etl2pcapng executable not found." "tabPageToolsTextBox"
    }

    # Clean up temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Ftkimager {
    $ftkImagerPath = Get-ChildItem -Path $toolsDirectory -Filter "ftkimager.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Check if FTK Imager CLI exists
    if ($ftkImagerPath -and (Test-Path $ftkImagerPath)) {
        Update-Log "FTK Command line version found at $ftkImagerPath. This version is no longer supported by Exterro and cannot be updated." "tabPageToolsTextBox"
    } else {
        Update-Log "FTK Command line version is not present. It is no longer supported by Exterro and cannot be downloaded directly from their site.`nYou can see the details of the tool here <https://www.exterro.com/ftk-product-downloads/windows-32bit-3-1-1>." "tabPageToolsTextBox"
    }
}

function Download-GeoLite2Databases {
    param(
        [string]$zipPath,
        [System.Security.SecureString]$licenseKey
    )

	$zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		return
	}
    # Convert the secure string license key to plain text
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($licenseKey)
    $plainLicenseKey = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Define URLs for the GeoLite2 databases
    $dbUrls = @{
        "City" = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=$plainLicenseKey&suffix=tar.gz";
        "ASN" = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=$plainLicenseKey&suffix=tar.gz";
        "Country" = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=$plainLicenseKey&suffix=tar.gz"
    }

    # Setup for GeoLite2 databases
    $GeoLite2Folder = Join-Path $toolsDirectory "GeoLite2Databases"
    if (!(Test-Path $GeoLite2Folder)) {
        New-Item -ItemType Directory -Path $GeoLite2Folder | Out-Null
    }

    foreach ($db in $dbUrls.Keys) {
        $tempFolder = Join-Path $toolsDirectory ("TempGeoLite2" + $db)
        New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

        # Download database
        $downloadPath = Join-Path $tempFolder ("GeoLite2" + $db + ".tar.gz")
        Invoke-WebRequest -UseBasicParsing -Uri $dbUrls[$db] -OutFile $downloadPath

        # Extract the downloaded database using 7zip
        try {
            Invoke-ExternalProcessQuiet -FilePath $zipPath -ArgumentList "x `"$downloadPath`" -o`"$tempFolder`" -y" -WorkingDirectory $tempFolder -ErrorContext ("7-Zip extraction (.tar.gz) for GeoLite2 {0}" -f $db)
        } catch {
            Update-Log ("Failed to extract GeoLite2 " + $db + " archive (.tar.gz): $_") "tabPageToolsTextBox"
            throw
        }
        $downloadPath = Join-Path $tempFolder ("GeoLite2" + $db + ".tar")
        try {
            Invoke-ExternalProcessQuiet -FilePath $zipPath -ArgumentList "x `"$downloadPath`" -o`"$tempFolder`" -y" -WorkingDirectory $tempFolder -ErrorContext ("7-Zip extraction (.tar) for GeoLite2 {0}" -f $db)
        } catch {
            Update-Log ("Failed to extract GeoLite2 " + $db + " archive (.tar): $_") "tabPageToolsTextBox"
            throw
        }

        # Locate the .mmdb file in the extracted folder
        $mmdbPath = Get-ChildItem -Path $tempFolder -Filter "*.mmdb" -Recurse | Select-Object -ExpandProperty FullName -First 1

        if ($mmdbPath) {
            # Check hash and copy .mmdb file to the GeoLite2 folder
            $destinationPath = Join-Path $GeoLite2Folder (Split-Path -Leaf $mmdbPath)
            $isNewOrUpdated = $false
            if (Test-Path $destinationPath) {
                $existingHash = (Get-FileHash -Path $destinationPath -Algorithm SHA256).Hash
                $newHash = (Get-FileHash -Path $mmdbPath -Algorithm SHA256).Hash
                if ($newHash -ne $existingHash) {
                    Copy-Item -Path $mmdbPath -Destination $destinationPath -Force
                    $isNewOrUpdated = $true
                }
            } else {
                Copy-Item -Path $mmdbPath -Destination $destinationPath -Force
                $isNewOrUpdated = $true
            }

            if ($isNewOrUpdated) {
                # Update the CSV with database information
                Add-ToolToCsv -toolName ("GeoLite2-" + $db + ".mmdb") -filePath $destinationPath
                Update-Log ("GeoLite2" + $db + " database updated.") "tabPageToolsTextBox"
            }
        } else {
            Update-Log ("GeoLite2" + $db + " database file not found after extraction.") "tabPageToolsTextBox"
        }

        # Clean up temporary folder
        Remove-Item -Path $tempFolder -Recurse -Force
    }
}

function Download-Hayabusa {  
    $HayabusaFolder = Join-Path $toolsDirectory "Hayabusa"
    if (!(Test-Path $HayabusaFolder)) {
        New-Item -ItemType Directory -Path $HayabusaFolder | Out-Null
    }		
    $HayabusaExecutable = Get-ChildItem -Path $HayabusaFolder -Filter "hayabusa*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Existing install: prefer rules update in place and skip binary download.
    if ($HayabusaExecutable -and (Test-Path $HayabusaExecutable)) {
        Update-Log "Existing Hayabusa installation found. Updating rules..." "tabPageToolsTextBox"
        try {
            $hayabusaDirectory = Split-Path $HayabusaExecutable
            Invoke-ExternalProcessQuiet -FilePath $HayabusaExecutable -WorkingDirectory $hayabusaDirectory -ArgumentList "update-rules" -ErrorContext "Hayabusa rules update (existing install)" -TimeoutSeconds 300 -UseShellExecuteHidden
            Update-Log "Hayabusa rules updated." "tabPageToolsTextBox"
        } catch {
            Update-Log "Error updating Hayabusa rules: $_" "tabPageToolsTextBox"
            throw
        }
        return
    }

    $tempFolder = Join-Path $toolsDirectory "TempHayabusa"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^hayabusa.*win-x64.zip$' } | Select-Object -ExpandProperty browser_download_url -First 1
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Hayabusa.exe not found." "tabPageToolsTextBox"
		return
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Hayabusa: $_" "tabPageToolsTextBox"
        return
    }
    if (Test-Path $downloadPath) {
        # Extract the zip file
        Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force

        # Delete the zip file after extraction
        Remove-Item -Path $downloadPath -Force

        # Identify the executable based on pattern
        $extractedExecutable = Get-ChildItem -Path $tempFolder -Filter "hayabusa*.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

        if ($extractedExecutable) {
            # Calculate hash of the downloaded executable
            $newHash = (Get-FileHash -Path $extractedExecutable -Algorithm SHA256).Hash
            $existingHash = if ($HayabusaExecutable -and (Test-Path $HayabusaExecutable)) { (Get-FileHash -Path $HayabusaExecutable -Algorithm SHA256).Hash } else { "" }

            if (-not $HayabusaExecutable -or $newHash -ne $existingHash) {
                Remove-Item -Path $HayabusaFolder\* -Recurse -Force
				# Copy all contents from the temp folder to the Hayabusa folder
				Copy-Item -Path $tempFolder\* -Destination $HayabusaFolder -Recurse -Force
                $destinationPath = Join-Path $HayabusaFolder (Split-Path -Leaf $extractedExecutable)
                Add-ToolToCsv -toolName (Split-Path -Leaf $extractedExecutable) -filePath $destinationPath
                Update-Log "Hayabusa updated." "tabPageToolsTextBox"
            } else {
                Update-Log "Hayabusa is already up-to-date." "tabPageToolsTextBox"
            }

            $hayabusaExecutableToRun = Get-ChildItem -Path $HayabusaFolder -Filter "hayabusa*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
            if ($hayabusaExecutableToRun -and (Test-Path $hayabusaExecutableToRun)) {
                Update-Log "Updating Hayabusa rules..." "tabPageToolsTextBox"
                try {
                    $hayabusaDirectory = Split-Path $hayabusaExecutableToRun
                    Invoke-ExternalProcessQuiet -FilePath $hayabusaExecutableToRun -WorkingDirectory $hayabusaDirectory -ArgumentList "update-rules" -ErrorContext "Hayabusa rules update (post-download)" -TimeoutSeconds 300 -UseShellExecuteHidden
                    Update-Log "Hayabusa rules updated." "tabPageToolsTextBox"
                } catch {
                    Update-Log "Error updating Hayabusa rules: $_" "tabPageToolsTextBox"
                    throw
                }
            } else {
                Update-Log "Hayabusa rules update skipped: executable not found after update check." "tabPageToolsTextBox"
            }
        } else {
            Update-Log "Downloaded Hayabusa executable not found in the extracted files." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded Hayabusa executable not found." "tabPageToolsTextBox"
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Loki {
    $LokiFolder = Join-Path $toolsDirectory "Loki"
    if (!(Test-Path $LokiFolder)) {
        New-Item -ItemType Directory -Path $LokiFolder | Out-Null
    }
    $LokiExecutable = Get-ChildItem -Path $LokiFolder -Filter "loki.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $LokiUpgraderExecutable = Get-ChildItem -Path $LokiFolder -Filter "loki-upgrader.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Existing install: prefer signature update in place and skip binary download.
    if ($LokiExecutable -and (Test-Path $LokiExecutable)) {
        Update-Log "Existing Loki installation found. Updating signatures..." "tabPageToolsTextBox"
        try {
            if ($LokiUpgraderExecutable -and (Test-Path $LokiUpgraderExecutable)) {
                $lokiUpgraderDirectory = Split-Path $LokiUpgraderExecutable
                Invoke-ExternalProcessQuiet -FilePath $LokiUpgraderExecutable -WorkingDirectory $lokiUpgraderDirectory -ArgumentList "" -ErrorContext "Loki signatures update (existing install, upgrader)" -TimeoutSeconds 300 -UseShellExecuteHidden
            } else {
                $lokiDirectory = Split-Path $LokiExecutable
                Invoke-ExternalProcessQuiet -FilePath $LokiExecutable -WorkingDirectory $lokiDirectory -ArgumentList "--update" -ErrorContext "Loki signatures update (existing install, loki --update)" -TimeoutSeconds 300 -UseShellExecuteHidden
            }
            Update-Log "Loki signatures updated." "tabPageToolsTextBox"
        } catch {
            Update-Log "Error updating Loki signatures: $_" "tabPageToolsTextBox"
            throw
        }
        return
    }
			
	$tempFolder = Join-Path $toolsDirectory "TempLoki"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Neo23x0/Loki/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^loki_[\d\.]+\.zip$' } | Select-Object -ExpandProperty browser_download_url -First 1

    if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
        Update-Log "Download URL for Loki not found." "tabPageToolsTextBox"
        return
    }

    $originalFileName = Split-Path -Leaf $downloadUrl
    $downloadPath = Join-Path $tempFolder $originalFileName
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Loki: $_" "tabPageToolsTextBox"
        return
    }

    if (Test-Path $downloadPath) {
        Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force
        Remove-Item -Path $downloadPath -Force

        $extractedLoki = Get-ChildItem -Path $tempFolder -Filter "loki.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

        if ($extractedLoki) {
            $newHash = (Get-FileHash -Path $extractedLoki -Algorithm SHA256).Hash
            $existingHash = if ($LokiExecutable -and (Test-Path $LokiExecutable)) { (Get-FileHash -Path $LokiExecutable -Algorithm SHA256).Hash } else { "" }

            if (-not $LokiExecutable -or $newHash -ne $existingHash) {
                Remove-Item -Path $LokiFolder\* -Recurse -Force
                Copy-Item -Path $tempFolder\* -Destination $LokiFolder -Recurse -Force
				Add-ToolToCsv -toolName "loki.exe"
                Update-Log "Loki updated." "tabPageToolsTextBox"
            } else {
                Update-Log "Loki is already up-to-date." "tabPageToolsTextBox"
            }
        } else {
            Update-Log "Downloaded Loki executable not found in the extracted files." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded Loki zip file not found." "tabPageToolsTextBox"
    }

    # Run Loki Upgrader
    try {
        $lokiUpgraderPath = Get-ChildItem -Path $LokiFolder -Filter "loki-upgrader.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1
        if (Test-Path $lokiUpgraderPath) {
            Update-Log "Updating Loki signatures..." "tabPageToolsTextBox"
            $lokiUpgraderDirectory = Split-Path $lokiUpgraderPath
            Invoke-ExternalProcessQuiet -FilePath $lokiUpgraderPath -WorkingDirectory $lokiUpgraderDirectory -ArgumentList "" -ErrorContext "Loki signatures update (post-download)" -TimeoutSeconds 300 -UseShellExecuteHidden
            Update-Log "Loki signatures updated." "tabPageToolsTextBox"
        } elseif ($LokiExecutable -and (Test-Path $LokiExecutable)) {
            Update-Log "loki-upgrader.exe not found. Running loki.exe --update..." "tabPageToolsTextBox"
            $lokiDirectory = Split-Path $LokiExecutable
            Invoke-ExternalProcessQuiet -FilePath $LokiExecutable -WorkingDirectory $lokiDirectory -ArgumentList "--update" -ErrorContext "Loki signatures update (post-download, loki --update)" -TimeoutSeconds 300 -UseShellExecuteHidden
            Update-Log "Loki signatures updated." "tabPageToolsTextBox"
        } else {
            Update-Log "loki-upgrader.exe not found in Loki directory and loki.exe is unavailable for --update." "tabPageToolsTextBox"
        }
    } catch {
        Update-Log "Error updating Loki signatures: $_" "tabPageToolsTextBox"
        throw
    }
	
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Plaso {
	$7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $7zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($7zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		return
	}
	
    $PlasoFolder = Join-Path $toolsDirectory "Plaso"
    if (!(Test-Path $PlasoFolder)) {
        New-Item -ItemType Directory -Path $PlasoFolder | Out-Null
    }		
	$log2timelinePY = Get-ChildItem -Path $PlasoFolder -Filter "log2timeline.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "Tempplaso"

    # Ensure the temporary and Plaso folders exist
    New-Item -ItemType Directory -Path $tempFolder, $PlasoFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/log2timeline/plaso/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^plaso-\d{8}\.tar\.gz$' } | Select-Object -ExpandProperty browser_download_url
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for log2timeline.py not found." "tabPageToolsTextBox"
		return
	}
	# Download the plaso package
    $tarGzPath = Join-Path $tempFolder (Split-Path -Leaf $downloadUrl)
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $tarGzPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Plaso: $_" "tabPageToolsTextBox"
        return
    }
    if (Test-Path $tarGzPath) {
        Update-Log "Extracting Plaso archive..." "tabPageToolsTextBox"
        # Extract .gz
        $tarPath = $tarGzPath -replace '\.gz$', ''
        try {
            Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList "e `"$tarGzPath`" `-o`"$tempFolder`" -y" -WorkingDirectory $tempFolder -ErrorContext "7-Zip extraction (.gz) for Plaso"
            # Extract .tar
            Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList "x `"$tarPath`" `-o`"$tempFolder`" -y" -WorkingDirectory $tempFolder -ErrorContext "7-Zip extraction (.tar) for Plaso"
        } catch {
            Update-Log "Failed to extract Plaso with 7-Zip: $_" "tabPageToolsTextBox"
            throw
        }
			# Remove .tar and .gz files from the temp folder
			Remove-Item -Path $tarGzPath -Force
			Remove-Item -Path $tarPath -Force		
        # Find log2timeline.py in the extracted files
        $log2timelinetempPY = Get-ChildItem -Path $tempFolder -Filter "log2timeline.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
		if ($log2timelinetempPY) {
			$newHash = (Get-FileHash -Path $log2timelinetempPY -Algorithm SHA256).Hash
			$existingHash = if ($log2timelinePY) { (Get-FileHash -Path $log2timelinePY -Algorithm SHA256).Hash } else { "" }
		
			if (-not $log2timelinePY -or $newHash -ne $existingHash) {
				Copy-Item -Path (Join-Path $tempFolder "*") -Destination $PlasoFolder -Recurse -Force
				Add-ToolToCsv -toolName "log2timeline.py" -filePath $PlasoFolder
				Update-Log "Plaso updated." "tabPageToolsTextBox"
			} else {
				Update-Log "Plaso is already up-to-date." "tabPageToolsTextBox"
			}
		} else {
			Update-Log "log2timeline.py not found in extracted Plaso files." "tabPageToolsTextBox"
		}
    }
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-SQLite {

    # Setup paths
    $SQLiteFolder = Join-Path $toolsDirectory "SQLite"
    if (!(Test-Path $SQLiteFolder)) {
        New-Item -ItemType Directory -Path $SQLiteFolder | Out-Null
    }
    $tempFolder = Join-Path $toolsDirectory "TempSQLite"
	    if (!(Test-Path $SQLiteFolder)) {
        New-Item -ItemType Directory -Path $tempFolder | Out-Null
    }
	$downloadPath = Join-Path $tempFolder "sqlite-netFx46-binary-bundle-x64-2015-1.0.118.0.zip"
    $SQLiteUrl = "https://system.data.sqlite.org/downloads/1.0.118.0/sqlite-netFx46-binary-bundle-x64-2015-1.0.118.0.zip"

    # Ensure directories exist
    if (!(Test-Path $SQLiteFolder)) {
        New-Item -ItemType Directory -Path $SQLiteFolder | Out-Null
    }
    if (!(Test-Path $tempFolder)) {
        New-Item -ItemType Directory -Path $tempFolder | Out-Null
    }

    # Open the download URL in the default web browser (Edge)
    Start-Process $SQLiteUrl

    # Wait for the user to manually download the file
    [System.Windows.MessageBox]::Show("Please wait for the download the be available in your browser, then save file to: $tempFolder. Click OK when done.")

    # Check if the file was manually downloaded and placed in the temp folder
    if (Test-Path $downloadPath) {
        try {
            # Extract the zip file
            Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force

            # Identify the executable based on pattern
            $extractedExecutable = Get-ChildItem -Path $tempFolder -Filter "System.Data.SQLite.dll" -Recurse | Select-Object -ExpandProperty FullName -First 1

            if ($extractedExecutable) {
                # Calculate hash of the downloaded executable
                $newHash = (Get-FileHash -Path $extractedExecutable -Algorithm SHA256).Hash
                $SQLiteExecutable = Get-ChildItem -Path $SQLiteFolder -Filter "System.Data.SQLite.dll" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
                $existingHash = if ($SQLiteExecutable -and (Test-Path $SQLiteExecutable)) { (Get-FileHash -Path $SQLiteExecutable -Algorithm SHA256).Hash } else { "" }

                if (-not $SQLiteExecutable -or $newHash -ne $existingHash) {
                    Remove-Item -Path $SQLiteFolder\* -Recurse -Force
                    # Copy all contents from the temp folder to the SQLite folder
                    Copy-Item -Path $tempFolder\* -Destination $SQLiteFolder -Recurse -Force
                    $destinationPath = Join-Path $SQLiteFolder (Split-Path -Leaf $extractedExecutable)
                    Add-ToolToCsv -toolName (Split-Path -Leaf $extractedExecutable) -filePath $destinationPath
                    Update-Log "SQLite updated." "tabPageToolsTextBox"
                } else {
                    Update-Log "SQLite is already up-to-date." "tabPageToolsTextBox"
                }
            } else {
                Update-Log "Downloaded SQLite executable not found in the extracted files." "tabPageToolsTextBox"
            }
        } catch {
            Update-Log "An error occurred during extraction: $_" "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded SQLite executable not found." "tabPageToolsTextBox"
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Velociraptor {  
    $VelociraptorFolder = Join-Path $toolsDirectory "Velociraptor"
    if (!(Test-Path $VelociraptorFolder)) {
        New-Item -ItemType Directory -Path $VelociraptorFolder | Out-Null
    }		
    $VelociraptorExecutable = Get-ChildItem -Path $VelociraptorFolder -Filter "Velociraptor*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "TempVelociraptor"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # ECHO currently depends on Velociraptor behavior that changed in 0.75+.
    # Pin strictly to the newest stable 0.74 release line.
    $allReleases = @()
    for ($page = 1; $page -le 5; $page++) {
        $apiUrl = "https://api.github.com/repos/Velocidex/velociraptor/releases?per_page=100&page=$page"
        try {
            $pageReleases = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
        } catch {
            Update-Log "Failed to fetch Velociraptor releases: $_" "tabPageToolsTextBox"
            return
        }

        if (-not $pageReleases -or $pageReleases.Count -eq 0) {
            break
        }

        $allReleases += $pageReleases
    }

    $compatibleReleases = $allReleases | Where-Object {
        -not $_.draft -and
        -not $_.prerelease -and
        ([string]$_.tag_name -match '^v?0\.74(\.\d+)?$')
    }

    if (-not $compatibleReleases -or $compatibleReleases.Count -eq 0) {
        Update-Log "No compatible Velociraptor 0.74.x release found on GitHub." "tabPageToolsTextBox"
        return
    }

    $selectedRelease = $compatibleReleases | Sort-Object -Descending -Property @{
        Expression = {
            $tag = [string]$_.tag_name
            if ($tag -match '^v?0\.74(?:\.(\d+))?$') {
                if ($matches[1]) { return [int]$matches[1] }
                return 0
            }
            return -1
        }
    } | Select-Object -First 1

    $downloadAsset = $selectedRelease.assets | Where-Object {
        $_.name -match '^velociraptor-v0\.74(\.\d+)?[^\\\/]*amd64\.exe$'
    } | Select-Object -First 1

    if (-not $downloadAsset) {
        $downloadAsset = $selectedRelease.assets | Where-Object {
            $_.name -match 'amd64\.exe$'
        } | Select-Object -First 1
    }

    $downloadUrl = if ($downloadAsset) { $downloadAsset.browser_download_url } else { $null }
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Velociraptor.exe not found in release $($selectedRelease.tag_name)." "tabPageToolsTextBox"
		return
	}
    Update-Log "Downloading Velociraptor $($selectedRelease.tag_name) (pinned to 0.74.x for current ECHO compatibility)." "tabPageToolsTextBox"
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Velociraptor: $_" "tabPageToolsTextBox"
        return
    }
	if (Test-Path $downloadPath) {
		$newHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
		$existingHash = if ($VelociraptorExecutable -and (Test-Path $VelociraptorExecutable)) { (Get-FileHash -Path $VelociraptorExecutable -Algorithm SHA256).Hash } else { "" }
	
		if (-not $VelociraptorExecutable -or $newHash -ne $existingHash) {
			Get-ChildItem -Path $VelociraptorFolder -Filter "Velociraptor*.exe" -Recurse | Remove-Item -Force
			$destinationPath = Join-Path $VelociraptorFolder $originalFileName
			Copy-Item -Path $downloadPath -Destination $destinationPath -Force
			Add-ToolToCsv -toolName $originalFileName -filePath $destinationPath
			Update-Log "Velociraptor updated." "tabPageToolsTextBox"
		} else {
			Update-Log "Velociraptor is already up-to-date." "tabPageToolsTextBox"
		}
	} else {
		Update-Log "Downloaded Velociraptor executable not found." "tabPageToolsTextBox"
	}
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Volatility3 {
    $Volatility3Folder = Join-Path $toolsDirectory "Volatility3"
    if (!(Test-Path $Volatility3Folder)) {
        New-Item -ItemType Directory -Path $Volatility3Folder | Out-Null
    }		
    $Volatility3Executable = Get-ChildItem -Path $Volatility3Folder -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "TempVolatility3"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
	$apiUrl = "https://api.github.com/repos/volatilityfoundation/volatility3/releases/latest"
	$latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
	$tagName = $latestRelease.tag_name
	$downloadUrl = "https://github.com/volatilityfoundation/volatility3/archive/refs/tags/$tagName.zip"
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Volatility3 not found." "tabPageToolsTextBox"
		return
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Volatility: $_" "tabPageToolsTextBox"
        return
    }
	$TempVelociraptorExecutable = Get-ChildItem -Path $tempFolder -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	if (Test-Path $downloadPath) {
		# Extract the downloaded zip file
		Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force
		Remove-Item -Path $downloadPath -Force
		# Find vol.py in the extracted files
		$tempVolatilityExecutable = Get-ChildItem -Path $tempFolder -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
		if ($tempVolatilityExecutable) {
			$newHash = (Get-FileHash -Path $tempVolatilityExecutable -Algorithm SHA256).Hash
			$existingHash = if ($Volatility3Executable) { (Get-FileHash -Path $Volatility3Executable -Algorithm SHA256).Hash } else { "" }
	
			if (-not $Volatility3Executable -or $newHash -ne $existingHash) {
				# Delete all existing contents before copying new files
				Remove-Item -Path "$Volatility3Folder\*" -Recurse -Force				
				Copy-Item -Path (Join-Path $tempFolder "*") -Destination $Volatility3Folder -Recurse -Force
				Add-ToolToCsv -toolName "vol.py"
				Update-Log "Volatility3 updated." "tabPageToolsTextBox"
			} else {
				Update-Log "Volatility3 is already up-to-date." "tabPageToolsTextBox"
			}
		} else {
			Update-Log "vol.py not found in extracted Volatility3 files." "tabPageToolsTextBox"
		}
	} else {
		Update-Log "Downloaded Volatility3 package not found." "tabPageToolsTextBox"
	}
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-winpmem {
    $winpmemFolder = Join-Path $toolsDirectory "winpmem"
    if (!(Test-Path $winpmemFolder)) {
        New-Item -ItemType Directory -Path $winpmemFolder | Out-Null
    }		
    $winpmemExecutable = Get-ChildItem -Path $winpmemFolder -Filter "winpmem*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "Tempwinpmem"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Velocidex/WinPmem/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^winpmem.*x64.*exe$' } | Select-Object -ExpandProperty browser_download_url -First 1
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for winpmem.exe not found." "tabPageToolsTextBox"
		return
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download winpmem: $_" "tabPageToolsTextBox"
        return
    }
	if (Test-Path $downloadPath) {
		$newHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
		$existingHash = if ($winpmemExecutable -and (Test-Path $winpmemExecutable)) { (Get-FileHash -Path $winpmemExecutable -Algorithm SHA256).Hash } else { "" }
	
		if (-not $winpmemExecutable -or $newHash -ne $existingHash) {
			$destinationPath = Join-Path $winpmemFolder $originalFileName
			Copy-Item -Path $downloadPath -Destination $destinationPath -Force
			Add-ToolToCsv -toolName $originalFileName -filePath $destinationPath
			Update-Log "winpmem updated." "tabPageToolsTextBox"
		} else {
			Update-Log "winpmem is already up-to-date." "tabPageToolsTextBox"
		}
	} else {
		Update-Log "Downloaded winpmem executable not found." "tabPageToolsTextBox"
	}
    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-ZimmermanTools {
    $ZimmermanToolsFolder = Join-Path $toolsDirectory "ZimmermanTools"
    if (!(Test-Path $ZimmermanToolsFolder)) {
        New-Item -ItemType Directory -Path $ZimmermanToolsFolder | Out-Null
    }	
    $tempFolder = Join-Path $toolsDirectory "TempZimmermanTools"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null


    $downloadUrl = "https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip"
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download ZimmermanTools: $_" "tabPageToolsTextBox"
        return
    }
	
    $ZimmermanToolsPath = Join-Path $tempFolder "Get-ZimmermanTools.zip"
    if (Test-Path $ZimmermanToolsPath) {
        Expand-Archive -Path $ZimmermanToolsPath -DestinationPath $tempFolder -Force
        Remove-Item -Path $ZimmermanToolsPath -Force

        $scriptInTemp = Get-ChildItem -Path $tempFolder -Filter "Get-ZimmermanTools.ps1" -Recurse | Select-Object -ExpandProperty FullName -First 1		
        $newHash = (Get-FileHash -Path $scriptInTemp -Algorithm SHA256).Hash
        $existingZimmermanToolsPath = Join-Path $ZimmermanToolsFolder "Get-ZimmermanTools.ps1"
        $existingHash = if (Test-Path $existingZimmermanToolsPath) { (Get-FileHash -Path $existingZimmermanToolsPath -Algorithm SHA256).Hash } else { "" }

        if ($newHash -ne $existingHash) {
            Copy-Item -Path $scriptInTemp -Destination $ZimmermanToolsFolder -Force
            Add-ToolToCsv -toolName "Get-ZimmermanTools.ps1"
        }

        # Run the Zimmerman Tools script regardless of hash change
        $scriptPath = Join-Path $ZimmermanToolsFolder "Get-ZimmermanTools.ps1"
        if (Test-Path $scriptPath) {
            Start-Process "powershell.exe" -ArgumentList "-NoExit", "-File `"$scriptPath`" -Dest `"$ZimmermanToolsFolder`"" -WorkingDirectory $ZimmermanToolsFolder -NoNewWindow
            Update-Log "ZimmermanTools script executed." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded ZimmermanTools package not found." "tabPageToolsTextBox"
    }

    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Zircolite {
	$7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $7zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($7zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		return
	}
    $ZircoliteFolder = Join-Path $toolsDirectory "Zircolite"
    if (!(Test-Path $ZircoliteFolder)) {
        New-Item -ItemType Directory -Path $ZircoliteFolder | Out-Null
    }		
    $ZircoliteExecutable = Get-ChildItem -Path $ZircoliteFolder -Filter "Zircolite*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "TempZircolite"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/wagga40/Zircolite/releases"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^zircolite_win.*7z$' } | Select-Object -ExpandProperty browser_download_url -First 1
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Zircolite.exe not found." "tabPageToolsTextBox"
		return
	}
	# Decode the URL to get the correct file name
	$decodedUrl = [System.Web.HttpUtility]::UrlDecode($downloadUrl)
	$originalFileName = Split-Path -Leaf $decodedUrl
	$downloadPath = Join-Path $tempFolder $originalFileName

    try {
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Zircolite: $_" "tabPageToolsTextBox"
        return
    }
    if (Test-Path $downloadPath) {
        # Extract the zip file
			try {
				$7zipArgs = "x `"$downloadPath`" -o`"$tempFolder`" -y"
				Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList $7zipArgs -WorkingDirectory $tempFolder -ErrorContext "7-Zip extraction (temp) for Zircolite"
			} catch {
				Update-Log "Failed to extract Zircolite with 7-Zip: $_" "tabPageToolsTextBox"
				throw
			}

        # Identify the executable based on pattern
        $extractedExecutable = Get-ChildItem -Path $tempFolder -Filter "Zircolite*.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

	        if ($extractedExecutable) {
                $zircoliteExecutableToRun = $null
	            # Calculate hash of the downloaded executable
	            $newHash = (Get-FileHash -Path $extractedExecutable -Algorithm SHA256).Hash
	            $existingHash = if ($ZircoliteExecutable -and (Test-Path $ZircoliteExecutable)) { (Get-FileHash -Path $ZircoliteExecutable -Algorithm SHA256).Hash } else { "" }

	            if (-not $ZircoliteExecutable -or $newHash -ne $existingHash) {
				# Check and clear the Zircolite folder
				if (Test-Path $ZircoliteFolder) {
					Remove-Item -Path $ZircoliteFolder\* -Recurse -Force
					}
					# Use 7-Zip to extract the ZIP file directly into the Zircolite folder
					$7zipArgs2 = "x `"$downloadPath`" -o`"$ZircoliteFolder`" -y"
					Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList $7zipArgs2 -WorkingDirectory $ZircoliteFolder -ErrorContext "7-Zip extraction (final) for Zircolite"
                    $zircoliteExecutableToRun = Get-ChildItem -Path $ZircoliteFolder -Filter "Zircolite*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
                    if ([string]::IsNullOrWhiteSpace($zircoliteExecutableToRun)) {
                        $zircoliteExecutableToRun = $extractedExecutable
                    }
	                Add-ToolToCsv -toolName (Split-Path -Leaf $zircoliteExecutableToRun)
	                Update-Log "Zircolite updated." "tabPageToolsTextBox"
	            } else {
                    $zircoliteExecutableToRun = $ZircoliteExecutable
	                Update-Log "Zircolite is already up-to-date." "tabPageToolsTextBox"
	            }

                if (-not [string]::IsNullOrWhiteSpace($zircoliteExecutableToRun) -and (Test-Path -LiteralPath $zircoliteExecutableToRun)) {
                    $rulesUpdated = $false
                    Update-Log "Updating Zircolite rules..." "tabPageToolsTextBox"
                    try {
                        Invoke-ExternalProcessQuiet -FilePath $zircoliteExecutableToRun -ArgumentList "-U" -WorkingDirectory $ZircoliteFolder -ErrorContext "Zircolite rules update (-U)" -TimeoutSeconds 300 -UseShellExecuteHidden
                        $rulesUpdated = $true
                    } catch {
                        try {
                            Invoke-ExternalProcessQuiet -FilePath $zircoliteExecutableToRun -ArgumentList "--update-rules" -WorkingDirectory $ZircoliteFolder -ErrorContext "Zircolite rules update (--update-rules)" -TimeoutSeconds 300 -UseShellExecuteHidden
                            $rulesUpdated = $true
                        } catch {
                            Update-Log "Zircolite rules update failed: $_" "tabPageToolsTextBox"
                        }
                    }

                    if ($rulesUpdated) {
                        Update-Log "Zircolite rules updated." "tabPageToolsTextBox"
                    }
                } else {
                    Update-Log "Zircolite rules update skipped: executable not found after update check." "tabPageToolsTextBox"
                }
	        } else {
	            Update-Log "Downloaded Zircolite executable not found in the extracted files." "tabPageToolsTextBox"
	        }
    } else {
        Update-Log "Downloaded Zircolite executable not found." "tabPageToolsTextBox"
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
}

####End functions for Tools Tab####


# ---- _EchoMain.ps1 ----

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework


$executableDirectory = [System.AppDomain]::CurrentDomain.BaseDirectory
#$executableDirectory = Split-Path -Parent $PSCommandPath
$toolsDirectory = Join-Path -Path $executableDirectory -ChildPath "Tools"

function Test-AdminRights {
	$currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
	return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Restart script with administrator rights if not already running as admin
if (-not (Test-AdminRights)) {
	$scriptPath = $MyInvocation.MyCommand.Definition
	Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Verb RunAs
	exit
}

# Check if cases.csv exists, and create it if it doesn't
$casesCsvPath = Join-Path $executableDirectory 'cases.csv'
if (-not (Test-Path $casesCsvPath)) {
    New-Item -ItemType File -Path $casesCsvPath | Out-Null
}

function Check-PythonInstalled {
    try {
        $pythonVersion = python --version 2>&1
        return $true
    } catch {
        return $false
    }
}

function Get-CaseMetadataPath {
    param(
        [string]$CaseDirectory,
        [string]$CaseName
    )
    return (Join-Path -Path $CaseDirectory -ChildPath ("_ECHO.{0}.json" -f $CaseName))
}

function Get-CaseLogPath {
    param(
        [string]$CaseDirectory,
        [string]$CaseName
    )
    return (Join-Path -Path $CaseDirectory -ChildPath ("{0}.log" -f $CaseName))
}

function Get-CaseLegacyTextPath {
    param(
        [string]$CaseDirectory,
        [string]$CaseName
    )
    return (Join-Path -Path $CaseDirectory -ChildPath ("{0}.txt" -f $CaseName))
}

function Ensure-CaseFiles {
    param(
        [string]$CaseDirectory,
        [string]$CaseName,
        [Nullable[DateTime]]$CreatedDate
    )

    if ([string]::IsNullOrWhiteSpace($CaseDirectory) -or [string]::IsNullOrWhiteSpace($CaseName)) {
        return $false
    }

    if (-not (Test-Path -LiteralPath $CaseDirectory -PathType Container)) {
        return $false
    }

    $metadataPath = Get-CaseMetadataPath -CaseDirectory $CaseDirectory -CaseName $CaseName
    $logPath = Get-CaseLogPath -CaseDirectory $CaseDirectory -CaseName $CaseName
    $legacyTextPath = Get-CaseLegacyTextPath -CaseDirectory $CaseDirectory -CaseName $CaseName
    $migratedFromLegacy = $false

    if (-not (Test-Path -LiteralPath $logPath -PathType Leaf)) {
        if (Test-Path -LiteralPath $legacyTextPath -PathType Leaf) {
            try {
                Move-Item -LiteralPath $legacyTextPath -Destination $logPath -Force
                $migratedFromLegacy = $true
            } catch {
                try {
                    Copy-Item -LiteralPath $legacyTextPath -Destination $logPath -Force
                    Remove-Item -LiteralPath $legacyTextPath -Force
                    $migratedFromLegacy = $true
                } catch {
                    return $false
                }
            }
        } else {
            New-Item -ItemType File -Path $logPath | Out-Null
        }
    }

    if (-not (Test-Path -LiteralPath $metadataPath -PathType Leaf)) {
        $resolvedCreatedDate = if ($CreatedDate.HasValue) { $CreatedDate.Value } else { Get-Date }
        $metadata = [ordered]@{
            schema = "ECHO.CaseMetadata"
            schemaVersion = 1
            caseName = $CaseName
            caseDirectory = $CaseDirectory
            createdLocal = $resolvedCreatedDate.ToString("o")
            createdUtc = $resolvedCreatedDate.ToUniversalTime().ToString("o")
            createdBy = [Environment]::UserName
            machineName = [Environment]::MachineName
            logFile = [System.IO.Path]::GetFileName($logPath)
            metadataFile = [System.IO.Path]::GetFileName($metadataPath)
            migratedFromLegacyText = $migratedFromLegacy
            tool = "ECHO"
            entryPoint = [System.IO.Path]::GetFileName($PSCommandPath)
        }
        $metadata | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $metadataPath -Encoding UTF8
    }

    return $true
}

function Get-CurrentCaseLogPath {
    param()

    if ([string]::IsNullOrWhiteSpace($Global:CurrentCaseDirectory)) {
        return $null
    }

    try {
        $caseDirectory = $Global:CurrentCaseDirectory.Trim()
        if (-not (Test-Path -LiteralPath $caseDirectory -PathType Container)) {
            return $null
        }

        $caseName = (Get-Item -LiteralPath $caseDirectory).Name
        $metadataFile = Get-ChildItem -LiteralPath $caseDirectory -Filter "_ECHO.*.json" -File -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($metadataFile) {
            try {
                $metadata = Get-Content -LiteralPath $metadataFile.FullName -Raw | ConvertFrom-Json
                if ($metadata -and -not [string]::IsNullOrWhiteSpace([string]$metadata.caseName)) {
                    $caseName = [string]$metadata.caseName
                }
            } catch {
                # Fall back to directory name if metadata parsing fails.
            }
        }

        $caseLogPath = Get-CaseLogPath -CaseDirectory $caseDirectory -CaseName $caseName
        if (Test-Path -LiteralPath $caseLogPath -PathType Leaf) {
            return $caseLogPath
        }

        $legacyTextPath = Get-CaseLegacyTextPath -CaseDirectory $caseDirectory -CaseName $caseName
        if (Test-Path -LiteralPath $legacyTextPath -PathType Leaf) {
            return $legacyTextPath
        }

        return $caseLogPath
    } catch {
        return $null
    }
}

function Write-CaseLogLine {
    param(
        [string]$LogLine
    )

    if ([string]::IsNullOrWhiteSpace($LogLine)) {
        return
    }

    $caseLogPath = Get-CurrentCaseLogPath
    if ([string]::IsNullOrWhiteSpace($caseLogPath)) {
        return
    }

    for ($attempt = 0; $attempt -lt 3; $attempt++) {
        try {
            $stream = [System.IO.File]::Open($caseLogPath, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            $writer = $null
            try {
                $writer = New-Object System.IO.StreamWriter($stream)
                $writer.WriteLine($LogLine)
                $writer.Flush()
            } finally {
                if ($writer -ne $null) {
                    $writer.Dispose()
                }
                if ($stream -ne $null) {
                    $stream.Dispose()
                }
            }
            return
        } catch {
            if ($attempt -eq 2) {
                Write-Host "Failed to write case log line: $_"
            } else {
                Start-Sleep -Milliseconds 100
            }
        }
    }
}

function Exit-Program {
    param()

    [System.Windows.MessageBox]::Show("Exiting Evidence Processing...")

    # Send shutdown command to the server
    if ($Global:PipeServerJob) {
		Send-CommandToProcess -pipeName $Global:pipeName -commandToSend "shutdown-server" 
        Stop-Job -Job $Global:PipeServerJob -Force
        Remove-Job -Job $Global:PipeServerJob
        $Global:PipeServerJob = $null
    }

    if ($Global:CurrentCaseDirectory -ne $null) {
        $caseName = (Get-Item $Global:CurrentCaseDirectory).Name
        $date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $newFileName = "{0}_{1}.log" -f $date, $caseName

        $transcriptLogsPath = Join-Path $Global:CurrentCaseDirectory "Transcript_Logs"
        if (!(Test-Path $transcriptLogsPath)) {
            New-Item -ItemType Directory -Path $transcriptLogsPath | Out-Null
        }

        $caseLogFile = Get-CurrentCaseLogPath
        if (Test-Path -LiteralPath $caseLogFile -PathType Leaf) {
            # Prepare the new file path with timestamp
            $newFilePath = Join-Path $transcriptLogsPath $newFileName
            Copy-Item -Path $caseLogFile -Destination $newFilePath

            # Archive file name
            $archiveFileName = "$caseName.zip"
            $archivePath = Join-Path $transcriptLogsPath $archiveFileName

            # If archive exists, update it. Otherwise, create new archive.
            if (Test-Path $archivePath) {
                $tempFolder = [System.IO.Path]::GetTempPath()
                $extractedFolderPath = Join-Path $tempFolder ([System.IO.Path]::GetRandomFileName())
                New-Item -ItemType Directory -Path $extractedFolderPath | Out-Null

                Expand-Archive -Path $archivePath -DestinationPath $extractedFolderPath | Out-Null
                Copy-Item -Path $newFilePath -Destination $extractedFolderPath
                Compress-Archive -Path $extractedFolderPath\* -DestinationPath $archivePath -Update | Out-Null

                Remove-Item -Path $extractedFolderPath -Recurse
            } else {
                Compress-Archive -Path $newFilePath -DestinationPath $archivePath | Out-Null
            }
			Remove-Item -Path $newFilePath -Force
            Clear-Content -Path $caseLogFile -Force
        }
    }

    # Clear global variables
    Set-Variable -Name "Global:CurrentCaseDirectory" -Value $null > $null
    [void]$window.Close()
}

function New-Case {
    param(
		[string]$CaseName
	)

    $CaseLocation = Get-Folder -Description "Select the folder to create the new case in"
    if (-not $CaseLocation) { return }

    $CaseDirectory = Join-Path $CaseLocation $CaseName
    if (-not (Test-Path $CaseDirectory)) {
        New-Item -ItemType Directory -Path $CaseDirectory | Out-Null
        $CaseInfo = [PSCustomObject] @{
            Name = $CaseName
            Path = $CaseDirectory
			Created = (Get-Date)
        }
        $CaseInfo | Export-Csv -Path "$executableDirectory\cases.csv" -NoTypeInformation -Append
        Update-Log "Case '$CaseName' created successfully in '$CaseDirectory'." "caseCreationLogTextBox"

        if (Ensure-CaseFiles -CaseDirectory $CaseDirectory -CaseName $CaseName -CreatedDate ([Nullable[DateTime]](Get-Date))) {
            Update-Log "Case files created: '_ECHO.$CaseName.json' and '$CaseName.log'." "caseCreationLogTextBox"
        } else {
            Update-Log "Failed to initialize case files for '$CaseName'." "caseCreationLogTextBox"
        }
    }
    else {
        Update-Log "A case with the name '$CaseName' already exists in '$CaseLocation'." "caseCreationLogTextBox"
    }
	return
}

function Get-Folder {
    [CmdletBinding()]
    Param(
        [string]$Description = "Select a folder",
        [string]$DefaultLocation = "Desktop"
    )
    $folderBrowser = New-Object -ComObject Shell.Application
    $folder = $folderBrowser.BrowseForFolder(0, $Description, 0, $DefaultLocation)
    if ($folder) {
        $selectedFolder = $folder.Self.Path
        return $selectedFolder
    }
}

function Get-Cases {
    param()

    # Safeguard in case the CSV file does not exist
    if (-not (Test-Path "$executableDirectory\cases.csv")) {
        return @()
    }

    # Import cases from CSV and clean up whitespace safely.
    $Cases = Import-Csv -Path "$executableDirectory\cases.csv" | ForEach-Object {
        [PSCustomObject]@{
            Name    = if ($null -eq $_.Name) { "" } else { "$($_.Name)".Trim() }
            Path    = if ($null -eq $_.Path) { "" } else { "$($_.Path)".Trim() }
            Created = $_.Created
        }
    }

    return $Cases
}

function Test-CaseRecordIsUsable {
    param(
        [string]$CaseName,
        [string]$CasePath
    )

    if ([string]::IsNullOrWhiteSpace($CaseName) -or [string]::IsNullOrWhiteSpace($CasePath)) {
        return $false
    }

    try {
        $normalizedPath = $CasePath.Trim()
        if (-not (Test-Path -LiteralPath $normalizedPath -PathType Container)) {
            return $false
        }

        $metadataPath = Get-CaseMetadataPath -CaseDirectory $normalizedPath -CaseName $CaseName
        $logPath = Get-CaseLogPath -CaseDirectory $normalizedPath -CaseName $CaseName
        $legacyTextPath = Get-CaseLegacyTextPath -CaseDirectory $normalizedPath -CaseName $CaseName

        if ((Test-Path -LiteralPath $metadataPath -PathType Leaf) -and (Test-Path -LiteralPath $logPath -PathType Leaf)) {
            return $true
        }

        if (Test-Path -LiteralPath $legacyTextPath -PathType Leaf) {
            return $true
        }

        if (Test-Path -LiteralPath $logPath -PathType Leaf) {
            return $true
        }

        return $false
    } catch {
        return $false
    }
}

function Open-Case {
    param(
        [string]$CaseName,
        [string]$CasePath
    )

    # If a case is already open, close and archive its transcript
    if ($Global:CurrentCaseDirectory) {
        # Archive transcript file
        try {
            $currentCaseName = (Get-Item $Global:CurrentCaseDirectory).Name
            $date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $transcriptLogsPath = Join-Path $Global:CurrentCaseDirectory "Transcript_Logs"
            if (!(Test-Path $transcriptLogsPath)) {
                New-Item -ItemType Directory -Path $transcriptLogsPath | Out-Null
            }

            $caseLogFile = Get-CurrentCaseLogPath
            if (Test-Path -LiteralPath $caseLogFile -PathType Leaf) {
                # Prepare the new file path with timestamp
                $newFileName = "{0}_{1}.log" -f $date, $currentCaseName
                $newFilePath = Join-Path $transcriptLogsPath $newFileName
                Copy-Item -Path $caseLogFile -Destination $newFilePath

                # Archive file name
                $archiveFileName = "$currentCaseName.zip"
                $archivePath = Join-Path $transcriptLogsPath $archiveFileName

                # Archive the transcript file
                if (Test-Path $archivePath) {
                    $tempFolder = [System.IO.Path]::GetTempPath()
                    $extractedFolderPath = Join-Path $tempFolder ([System.IO.Path]::GetRandomFileName())
                    New-Item -ItemType Directory -Path $extractedFolderPath | Out-Null
                    Expand-Archive -Path $archivePath -DestinationPath $extractedFolderPath -Force | Out-Null
                    Move-Item -Path $newFilePath -Destination $extractedFolderPath
                    Compress-Archive -Path $extractedFolderPath\* -DestinationPath $archivePath -Force | Out-Null
                    Remove-Item -Path $extractedFolderPath -Recurse
                } else {
                    Compress-Archive -Path $newFilePath -DestinationPath $archivePath -Force | Out-Null
                }
                Clear-Content -Path $caseLogFile -Force
            }
        } catch {
            [System.Windows.MessageBox]::Show("An error occurred during transcript archiving: $_")
        }
    }
	
    # If no case name is provided, exit the function
    if (-not $CaseName) {
        Update-Log "Case name not provided." "caseCreationLogTextBox"
        return
    }

    # Get the case details from the CSV file
    $Cases = @(Get-Cases)
    $MatchingCases = @($Cases | Where-Object { $_.Name -eq $CaseName })

    if (-not [string]::IsNullOrWhiteSpace($CasePath)) {
        $normalizedRequestedPath = $CasePath.Trim()
        $MatchingCases = @(
            $MatchingCases | Where-Object {
                -not [string]::IsNullOrWhiteSpace($_.Path) -and $_.Path.Trim().ToLowerInvariant() -eq $normalizedRequestedPath.ToLowerInvariant()
            }
        )
    }

    # Check if the selected case exists
    if ($MatchingCases.Count -eq 0) {
        Update-Log "Case '$CaseName' not found in CSV file." "caseCreationLogTextBox"
        return
    }

    # Handle duplicate case names by preferring the single usable record.
    $SelectedCase = $null
    if ($MatchingCases.Count -gt 1) {
        $usableCases = @(
            $MatchingCases | Where-Object {
                Test-CaseRecordIsUsable -CaseName $_.Name -CasePath $_.Path
            }
        )

        if ($usableCases.Count -eq 1) {
            $SelectedCase = $usableCases[0]
        } elseif ($usableCases.Count -gt 1) {
            Update-Log "Multiple usable cases named '$CaseName' were found. Open from the case grid row instead." "caseCreationLogTextBox"
            [System.Windows.MessageBox]::Show("Multiple cases named '$CaseName' are usable. Double-click the exact row in the case grid to open the correct one.", "Ambiguous Case", 'OK', 'Warning')
            return
        } else {
            # Fall back to first match for a clear validation error below.
            $SelectedCase = $MatchingCases[0]
        }
    } else {
        $SelectedCase = $MatchingCases[0]
    }

    # Construct case directory path and validate case structure before opening
    $CaseDirectory = $SelectedCase.Path
    if (-not (Test-CaseRecordIsUsable -CaseName $SelectedCase.Name -CasePath $CaseDirectory)) {
        Update-Log "Case '$($SelectedCase.Name)' is missing required files or has an invalid path." "caseCreationLogTextBox"
        [System.Windows.MessageBox]::Show("Case '$($SelectedCase.Name)' is missing required files (`"_ECHO.$($SelectedCase.Name).json`" and/or `"$($SelectedCase.Name).log`") or has an invalid path.", "Case Invalid", 'OK', 'Error')
        return
    }

    if (Test-Path -LiteralPath $CaseDirectory -PathType Container) {
        $caseFilesReady = $false
        if ($SelectedCase.Created) {
            $createdDateValue = $null
            try {
                $createdDateValue = [DateTime]$SelectedCase.Created
            } catch {
                $createdDateValue = $null
            }

            if ($null -ne $createdDateValue) {
                $caseFilesReady = Ensure-CaseFiles -CaseDirectory $CaseDirectory -CaseName $SelectedCase.Name -CreatedDate ([Nullable[DateTime]]$createdDateValue)
            } else {
                $caseFilesReady = Ensure-CaseFiles -CaseDirectory $CaseDirectory -CaseName $SelectedCase.Name -CreatedDate $null
            }
        } else {
            $caseFilesReady = Ensure-CaseFiles -CaseDirectory $CaseDirectory -CaseName $SelectedCase.Name -CreatedDate $null
        }
        if (-not $caseFilesReady) {
            Update-Log "Failed to initialize case files for '$($SelectedCase.Name)'." "caseCreationLogTextBox"
            [System.Windows.MessageBox]::Show("Failed to initialize case files for '$($SelectedCase.Name)'.", "Case Initialization Error", 'OK', 'Error')
            return
        }
        Set-Variable -Name "Global:CurrentCaseDirectory" -Value $CaseDirectory
		
        # Enable new tabs
        $window.FindName("TabCollectPacketCapture").IsEnabled = $true
 		$window.FindName("TabCollectSystemArtifacts").IsEnabled = $true
		$window.FindName("TabCollectAndProcessMemory").IsEnabled = $true
 		$window.FindName("TabCollectDiskImagewithFTK").IsEnabled = $true
		$window.FindName("TabCollectM365").IsEnabled = $true
#		$window.FindName("TabCollectGoogleWorkspaceLogs").IsEnabled = $true
		$window.FindName("TabProcessSystemArtifacts").IsEnabled = $true
		$window.FindName("TabUseThreatScanners").IsEnabled = $true
        $window.FindName("TabPageTools").IsEnabled = $true
		$window.FindName("TabEvidenceSync").IsEnabled = $true
		$window.FindName("TabElasticSearch").IsEnabled = $true		
        $window.Title = "ECHO - Evidence Collection & Handling Orchestrator - $($SelectedCase.Name)"
		$global:hasRunOnTabCollectMemory = $false
		$global:hasRunOnTabCollectSystemArtifacts = $false
		$global:hasRunOnTabPageTools = $false
		$global:hasRunOnTabSyncTools = $false
        Update-Log "Case '$($SelectedCase.Name)' opened successfully." "caseCreationLogTextBox"

    }
    else {
        Update-Log "Case directory for '$($SelectedCase.Name)' not found." "caseCreationLogTextBox"
    }
}

function Import-Case {
    param()

    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Title = "Select case metadata (_ECHO.<casename>.json) or legacy case file (<casename>.txt) to import"
    $openFileDialog.Filter = "ECHO Case Metadata (_ECHO.*.json)|_ECHO.*.json|Legacy Case File (*.txt)|*.txt|All Files (*.*)|*.*"

    if ($openFileDialog.ShowDialog() -eq "OK") {
        $selectedFile = $openFileDialog.FileName
        $fileInfo = Get-Item $selectedFile

        if ($fileInfo) {
            $caseName = $null
            $casePath = [System.IO.Path]::GetDirectoryName($selectedFile)
            $caseCreated = [DateTime]$fileInfo.CreationTime

            if ($fileInfo.Extension -ieq ".json") {
                try {
                    $metadata = Get-Content -LiteralPath $selectedFile -Raw | ConvertFrom-Json
                    if ($metadata -and -not [string]::IsNullOrWhiteSpace([string]$metadata.caseName)) {
                        $caseName = [string]$metadata.caseName
                    }
                    if ($metadata -and $metadata.createdLocal) {
                        try {
                            $caseCreated = [DateTime]$metadata.createdLocal
                        } catch {
                            # Keep the default creation date if metadata value cannot be parsed.
                        }
                    }
                } catch {
                    Update-Log "Invalid case metadata file: $_" "caseCreationLogTextBox"
                    return
                }
            } else {
                $caseName = [System.IO.Path]::GetFileNameWithoutExtension($selectedFile)
            }

            if ([string]::IsNullOrWhiteSpace($caseName)) {
                $caseName = (Get-Item -LiteralPath $casePath).Name
            }

            if (-not (Ensure-CaseFiles -CaseDirectory $casePath -CaseName $caseName -CreatedDate ([Nullable[DateTime]]$caseCreated))) {
                Update-Log "Failed to initialize case files for imported case '$caseName'." "caseCreationLogTextBox"
                return
            }

            $caseInfo = [PSCustomObject]@{
                Name    = $caseName
                Path    = $casePath
                Created = $caseCreated
            }

            $caseInfo | Export-Csv -Path "$executableDirectory\cases.csv" -NoTypeInformation -Append
            Update-Log "Case '$caseName' imported successfully." "caseCreationLogTextBox"
        } else {
            Update-Log "Invalid case file." "caseCreationLogTextBox"
        }
    }

    # Refresh the GUI controls
    PopulateCaseControls
}

function Remove-Case {
    param(
        [string]$CaseName
    )

    # If no case name is provided, exit the function
    if (-not $CaseName) {
        Update-Log "Case name not provided." "caseCreationLogTextBox"
        return
    }

    $casesFile = "$executableDirectory\cases.csv"
    $cases = Import-Csv $casesFile

    # Find the case to remove
    $caseToRemove = $cases | Where-Object { $_.Name -eq $CaseName }

    if ($caseToRemove) {
        # Remove the case from the CSV file
        $cases = $cases | Where-Object { $_.Name -ne $CaseName }
        $cases | Export-Csv $casesFile -NoTypeInformation -Force
        Update-Log "Case '$CaseName' removed successfully." "caseCreationLogTextBox"
    }
    else {
        Update-Log "Case '$CaseName' not found." "caseCreationLogTextBox"
    }
}

function CreateCaseButton_Click {
    # Get the case name from the CaseNameTextBox
    $CaseName = $caseNameTextBox.Text
    if (-not $CaseName) {
        [System.Windows.MessageBox]::Show("Please enter a case name.", "Error", "OK", "Error")
        return
    }
    New-Case -CaseName $CaseName
    # Refresh the list of cases in the GUI
    PopulateCaseControls
}

function OpenCaseButton_Click {
    # Get the selected case name from the ExistingCasesComboBox
    $selectedItem = [string]$existingCasesComboBox.SelectedItem
    if (-not $selectedItem) {
        [System.Windows.MessageBox]::Show("Please select a case from the dropdown.", "Error", "OK", "Error")
        return
    }

    $selectedItem = $selectedItem -replace '\s+\(Missing\)$', ''
    $selectionParts = $selectedItem -split '\s+\|\s+', 2
    $CaseName = $selectionParts[0].Trim()
    $CasePath = if ($selectionParts.Count -gt 1) { $selectionParts[1].Trim() } else { $null }

    if (-not [string]::IsNullOrWhiteSpace($CasePath)) {
        Open-Case -CaseName $CaseName -CasePath $CasePath
    } else {
        Open-Case -CaseName $CaseName
    }
}

function RemoveCaseButton_Click {
    # Get the selected case from the ComboBox
    $selectedItem = $existingCasesComboBox.SelectedItem

    if (-not [string]::IsNullOrWhiteSpace($selectedItem)) {
        # Remove "(Missing)" from the case name if present
        $selectedItem = $selectedItem -replace '\s+\(Missing\)$', ''
        $selectionParts = $selectedItem -split '\s+\|\s+', 2
        $selectedCaseName = $selectionParts[0].Trim()
        $selectedCasePath = if ($selectionParts.Count -gt 1) { $selectionParts[1].Trim() } else { $null }

        # Get cases from CSV
        $cases = Get-Cases
        if (-not [string]::IsNullOrWhiteSpace($selectedCasePath)) {
            $remainingCases = $cases | Where-Object {
                -not ($_.Name -eq $selectedCaseName -and $_.Path -eq $selectedCasePath)
            }
        } else {
            $remainingCases = $cases | Where-Object { $_.Name -ne $selectedCaseName }
        }

        # Update the cases.csv file
        $remainingCases | Export-Csv -Path "$executableDirectory\cases.csv" -NoTypeInformation -Force

        # Refresh the DataGrid and ComboBox
        PopulateCaseControls
        [System.Windows.MessageBox]::Show("Case '$selectedCaseName' removed successfully.", "Case Removed", 'OK', 'Information')
    } else {
        [System.Windows.MessageBox]::Show("Please select a case to remove.", "Error", 'OK', 'Error')
    }
}

function ImportCaseButton_Click {
    # Call the Import-Case function
    Import-Case
}

function PopulateCaseControls {
	$cases = @(Get-Cases | ForEach-Object {
		[PSCustomObject]@{
			Name    = $_.Name
			Path    = $_.Path
			Created = $_.Created
			Status  = if (Test-CaseRecordIsUsable -CaseName $_.Name -CasePath $_.Path) { "Exists" } else { "Missing" }
		}
	})

    # Bind the DataGrid to the cases
    $casesDataGrid.ItemsSource = $cases

    # Populate the combo box with all cases (both "Exists" and "Missing")
    $existingCasesComboBox.Items.Clear()
    foreach ($case in $cases) {
        $statusText = if ($case.Status -eq "Exists") { "" } else { " (Missing)" }
        $displayText = "$($case.Name) | $($case.Path)$statusText"
        [void]$existingCasesComboBox.Items.Add($displayText)
    }
}

function Update-Log {
    param(
        [string]$message,
        [string]$callerFunction
    )
    
    # Determine the target text box based on the caller function
    $targetLog = $null
    switch ($callerFunction) {
        "caseCreationLogTextBox" { $targetLog = $window.FindName("caseCreationLogTextBox") }
        "PacketCaptureTextBox"     { $targetLog = $window.FindName("PacketCaptureTextBox") }
        "SystemArtifactsTextBox"    { $targetLog = $window.FindName("SystemArtifactsTextBox") }
		"MemoryTextBox"    { $targetLog = $window.FindName("MemoryTextBox") }
		"FTKImagerTextBox"    { $targetLog = $window.FindName("FTKImagerTextBox") }
		"M365TextBox"    { $targetLog = $window.FindName("M365TextBox") }
		"GoogleWorkspaceTextBox"    { $targetLog = $window.FindName("GoogleWorkspaceTextBox") }
		"ProcessSystemTextBox"    { $targetLog = $window.FindName("ProcessSystemTextBox") }
		"ThreatScannerTextBox"    { $targetLog = $window.FindName("ThreatScannerTextBox") }
        "tabPageToolsTextBox"    { $targetLog = $window.FindName("tabPageToolsTextBox") }
		"EvidenceSyncTextBox"    { $targetLog = $window.FindName("EvidenceSyncTextBox") }
		"ElasticSearchTextBox"    { $targetLog = $window.FindName("ElasticSearchTextBox") }			
        default { $targetLog = $window.FindName("caseCreationLogTextBox") } # Default log box
    }

    $rawMessage = if ($null -eq $message) { "" } else { [string]$message }
    $messageLines = [System.Text.RegularExpressions.Regex]::Split($rawMessage, "\r\n|\n|\r")
    $formattedLines = @()

    foreach ($line in $messageLines) {
        if ([string]::IsNullOrWhiteSpace($line)) {
            continue
        }

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $formattedLines += "[$timestamp] $line"
    }

    if ($formattedLines.Count -eq 0) {
        return
    }

    if ($targetLog -ne $null) {
        foreach ($formattedLine in $formattedLines) {
            $targetLog.AppendText("$formattedLine`r`n")
        }
        # Set the caret position to the end and scroll to it
        $targetLog.CaretIndex = $targetLog.Text.Length
        $targetLog.ScrollToEnd()
    }

    foreach ($formattedLine in $formattedLines) {
        Write-CaseLogLine -LogLine $formattedLine
    }
}

# Load the XAML layout
[xml]$xaml = @"

<Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="MainWindow" Title="ECHO - Evidence Collection &amp; Handling Orchestrator" Height="600" Width="800" MinHeight="540" MinWidth="760" WindowStartupLocation="CenterScreen">
    <Grid>
    <Viewbox x:Name="MainViewbox" Stretch="Uniform" StretchDirection="Both">
    <Grid Width="800" Height="600">
    <TabControl x:Name="MainTabControl">
        <!-- Home Tab -->
        <TabItem Header="Home">
            <Grid>
				<TextBlock Text="Welcome to the Evidence Collection &amp; Handling Orchestrator Tool. Start by either proceeding to the Case Management tab or selecting a tab name in the dropdown below to learn more about the individual tab." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap"/>
				<TextBlock Text="Select a tabname below for details on the tab." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,45,0,0" TextWrapping="Wrap"/>
				<ComboBox x:Name="TabsSelectionComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,65,0,0" Width="200">
					<ComboBoxItem Content="Home" />
					<ComboBoxItem Content="Case Management" />
					<ComboBoxItem Content="Collect and Process Memory" />					
					<ComboBoxItem Content="Collect Disk Image" />					
					<ComboBoxItem Content="Collect M365 Logs" />						
					<ComboBoxItem Content="Collect Packet Capture" />
					<ComboBoxItem Content="Collect System Artifacts" />
					<ComboBoxItem Content="Elastic Search" />					
					<ComboBoxItem Content="Evidence Sync" />
					<ComboBoxItem Content="Process System Artifacts" />
					<ComboBoxItem Content="Threat Scanners" />					
					<ComboBoxItem Content="Tool Management" />
				</ComboBox>	
				<TextBox x:Name="TabsDescriptionTextBox" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="10,100" Width="740" Height="300" TextWrapping="Wrap" IsReadOnly="True"/>		
            </Grid>
        </TabItem>

        <!-- Case Management Tab -->
		<TabItem Header="Case Management">
			<Grid>
				<!-- Define rows for layout -->
				<Grid.RowDefinitions>
					<RowDefinition Height="Auto" /> <!-- Top: Instructions and input -->
					<RowDefinition Height="*" />    <!-- Middle: DataGrid -->
					<RowDefinition Height="Auto" /> <!-- Bottom: Log box -->
				</Grid.RowDefinitions>

				<!-- Top Section: Instructions, TextBox, Buttons, and ComboBox -->
				<StackPanel Orientation="Vertical" Grid.Row="0" Margin="10">
					<TextBlock Text="Welcome to the Case Management Tab. Start by either entering a Case Name followed by Create Case, or choose from an Existing Case in the drop Down to Open." TextWrapping="Wrap" Margin="0,0,0,10" Width="720" />
					<TextBlock Text="After you have created a case, select the case from the Existing Cases dropdown and then select Open" TextWrapping="Wrap" Margin="0,0,0,10" />
					<StackPanel Orientation="Horizontal" Margin="0,0,0,10">
						<TextBlock Text="Case Name:" VerticalAlignment="Center" Margin="0,0,10,0" />
						<TextBox x:Name="CaseNameTextBox" Width="200" Margin="0,0,10,0" />
						<Button x:Name="CreateCaseButton" Content="Create Case" Width="100" Margin="0,0,10,0" />
					</StackPanel>
					<StackPanel Orientation="Horizontal" Margin="0,0,0,10">
						<TextBlock Text="Existing Cases:" VerticalAlignment="Center" Margin="0,0,10,0" />
						<ComboBox x:Name="ExistingCasesComboBox" Width="200" Margin="0,0,10,0" />
						<Button x:Name="OpenCaseButton" Content="Open" Width="50" Margin="0,0,10,0" />
						<Button x:Name="RemoveCaseButton" Content="Remove" Width="70" Margin="0,0,10,0" />
					</StackPanel>
					<StackPanel Orientation="Horizontal" Margin="0,0,0,10">
						<Button x:Name="ImportCaseButton" Content="Import Case" Width="100" Margin="0,0,10,0" />
						<TextBlock Text="You can select _ECHO.&lt;casename&gt;.json (or legacy &lt;casename&gt;.txt) from the root of a case directory to import it into cases.csv" TextWrapping="Wrap" VerticalAlignment="Center" />
					</StackPanel>
				</StackPanel>

				<!-- Middle Section: DataGrid -->
				<DataGrid x:Name="CasesDataGrid" AutoGenerateColumns="False" Grid.Row="1" Margin="10" HeadersVisibility="Column" CanUserAddRows="False" IsReadOnly="True" SelectionMode="Single">
					<DataGrid.Columns>
						<DataGridTextColumn Header="Name" Binding="{Binding Name}" Width="*" />
						<DataGridTextColumn Header="Path" Binding="{Binding Path}" Width="2*" />
						<DataGridTextColumn Header="Created" Binding="{Binding Created}" Width="*" />
						<DataGridTextColumn Header="Status" Binding="{Binding Status}" Width="*" />
					</DataGrid.Columns>
				</DataGrid>

				<!-- Bottom Section: Log Box -->
				<TextBox x:Name="caseCreationLogTextBox" Text="" Grid.Row="2" Margin="10" TextWrapping="Wrap" IsReadOnly="True" VerticalScrollBarVisibility="Visible" />
			</Grid>
		</TabItem>
		
		<!-- Packet Capture Tab -->
		<TabItem Header="Collect Packet Capture" IsEnabled="False" x:Name="TabCollectPacketCapture">
			<Grid>
				<TextBlock Text="This process uses Windows built-in netsh trace to capture packets. It does not capture packets in promiscuous mode (e.g., Wireshark)." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap" Width="740"/>
				<Button x:Name="StartPacketCaptureButton" Content="Start Packet Capture" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,50,0,0" Width="150"/>
				<TextBox x:Name="CaptureTimeTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,50,0,0" Width="50"/>
				<Button x:Name="ExtractCabFileButton" Content="Extract Cab File" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,90,0,0" Width="150"/>
				<Button x:Name="ConvertETL2PCAPButton" Content="Convert ETL to PCAP" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,130,0,0" Width="150"/>
				<TextBlock Text="Select Path to Etl2Pcapng.exe" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,130,0,0"/>
				<TextBox x:Name="Etl2PcapngPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,130,0,0" Width="300"/>
				<Button x:Name="BrowseEtl2PcapngPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,130,0,0" Width="25"/>
				<TextBlock Text="Minutes. Default time is 5 minutes if empty" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="225,50,0,0"/>
				<TextBlock Text="The 'Extract Cab File' button extracts all cab files within the Case\NetworkArtifacts folder" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,160,0,0"/>
				<TextBlock Text="The 'Convert ETL to PCAP' button converts all ETL files to PCAP within the Case\NetworkArtifacts folder" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,180,0,0"/>
				<!-- Log Display -->
				<TextBox x:Name="PacketCaptureTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>		

		<!-- System Artifacts Tab -->
		<TabItem Header="Collect System Artifacts" IsEnabled="False" x:Name="TabCollectSystemArtifacts">
			<Grid>
				<!-- Log Display -->
				<TextBox x:Name="SystemArtifactsTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
				<Button x:Name="DisplayVolumesButton" Content="Refresh Volumes" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="10,10,0,0"/>
				<ComboBox x:Name="VolumeComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Width="100" Margin="140,10,0,0"/>
				<TextBlock Text="Start by selecting a volume to collect, then one or more targets, and lastly 'Collect with Velociraptor'." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="250,10,0,0" TextWrapping="Wrap" Width="580"/>
				<CheckBox x:Name="VolumeShadowCopyCheckbox" Content="Include Volume Shadow Copy" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="450,80,0,0"/>
				<Label Content="Select Target(s) to collect below" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,30,0,0"/>
				<ListBox x:Name="CheckBoxListBox" HorizontalAlignment="Left" VerticalAlignment="Top" Height="100" Width="400" Margin="10,50,0,0"/>				
				<Button x:Name="ResetDefaultsButton" Content="Reset to Defaults" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="450,50,0,0"/>
				<TextBlock Text="Default is SANS_Triage and No VSC." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="580,50,0,0"/>
				<TextBox x:Name="CurrentSelectionText" HorizontalAlignment="Center" VerticalAlignment="Top" Width="740" Height="120" Margin="10,170,0,0" TextWrapping="Wrap" IsReadOnly="True"/>
				<Button x:Name="CollectWithVelociraptorButton" Content="Collect with Velociraptor" HorizontalAlignment="Left" VerticalAlignment="Top" Width="180" Margin="10,310,0,0" IsEnabled="False"/>
				<TextBox x:Name="velociraptorPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,340,0,0" Width="310"/>
				<Button x:Name="BrowseVelociraptorPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="320,340,0,0" Width="25"/>
				<Label Content="Select a Velociraptor Executable to execute if not found above" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,355,0,0"/>
			</Grid>
		</TabItem>

		<!-- Collect Disk Image Tab -->
		<TabItem Header="Collect Disk Image" IsEnabled="False" x:Name="TabCollectDiskImagewithFTK">
			<Grid>
				<TextBox x:Name="FTKImagerTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
				<Button x:Name="DisplayDrivesButton" Content="Display Drive(s) List" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="10,10,0,0"/>
				<Label Content="Select Drive(s) to collect below. If multiple drives are selected, imaging will start at the same time." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,30,0,0"/>
				<ListBox x:Name="DriveCheckBoxListBox" HorizontalAlignment="Left" VerticalAlignment="Top" Height="100" Width="600" Margin="10,50,0,0"/>	
				<Button x:Name="CollectDrivesButton" Content="Collect Selected Drives" HorizontalAlignment="Left" VerticalAlignment="Top" Width="180" Margin="10,310,0,0" IsEnabled="False"/>
				<TextBox x:Name="CurrentFTKSelectionText" HorizontalAlignment="Center" VerticalAlignment="Top" Width="740" Height="120" Margin="10,170,0,0" TextWrapping="Wrap" IsReadOnly="True"/>
				<TextBox x:Name="FTKPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,340,0,0" Width="310"/>
				<Button x:Name="BrowseFTKPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="320,340,0,0" Width="25"/>
				<Label Content="Select a FTK Executable to execute if not found above" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,355,0,0"/>
			</Grid>
		</TabItem>
		
		<!-- Memory Capture Tab -->
		<TabItem Header="Collect and Process Memory" IsEnabled="False" x:Name="TabCollectAndProcessMemory">
			<Grid>
				<TextBlock x:Name="MemoryCaptureTextBox" Text="This process uses winpmem to capture memory. Optionally available is the use of Volatility version 3 to parse the memory using a variety of plugins." HorizontalAlignment="Center" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap" Width="740"/>
				<Button x:Name="StartMemoryCaptureButton" Content="Start Memory Capture" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,50,0,0" Width="150" IsEnabled="False"/>
				<TextBox x:Name="WinpmemPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,50,0,0" Width="300"/>
				<Button x:Name="BrowseWimpmemPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,50,0,0" Width="25"/>
				<TextBlock Text="Select Path to Wimpmem" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,50,0,0"/>
				<TextBlock Text="Select a RAW memory collection, OS type, and Plugin to parse with Volatility" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,125,0,0"/>
				<TextBox x:Name="MemoryPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,145,0,0" Width="300"/>
				<Button x:Name="BrowseMemoryPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="310,145,0,0" Width="25"/>
				<ComboBox x:Name="OSSelectionComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,170,0,0" Width="80"/>
				<TextBlock Text="Plugin to process (Default 'All Plugins')" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="100,170,0,0"/>
				<ComboBox x:Name="PluginsComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="310,170,0,0" Width="150"/>
				<TextBlock Text="If a Plugin fails from `All Plugins`, re-run individual plugin" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="470,170,0,0"/>
				<Button x:Name="ProcessVolatilityButton" Content="Process with Volatility" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,220,0,0" Width="150" IsEnabled="False"/>
				<TextBox x:Name="VolatilityPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,220,0,0" Width="300"/>
				<Button x:Name="BrowseVolatilityPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,220,0,0" Width="25"/>
				<TextBlock Text="Select Path to Vol.py" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,220,0,0"/>
				<TextBox x:Name="MemoryTextBox" Text="" HorizontalAlignment="Center" Width="700" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>				
		
		<!-- Process System Artifacts -->
		<TabItem Header="Process System Artifacts" IsEnabled="False" x:Name="TabProcessSystemArtifacts">
			<Grid>
				<TextBlock x:Name="ArtifactProcessingInfoTextBlock" Text="Choose from a variety of forensic tools to process a selected file or folder with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBlock x:Name="ArtifactProcessingPathTextBlock" Text="Select a file or folder for processing, then select a tool to process with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,50,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBox x:Name="ArtifactProcessingPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,65,0,0" Width="400"/>
				<Button x:Name="ArtifactProcessingPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="420,65,0,0" Width="25"/>
				<TextBlock Text="Select a tool to process with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,110,0,0" TextWrapping="Wrap" Width="740"/>
				<!-- Tool Selection ComboBox -->
				<ComboBox x:Name="ProcessingToolComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,130,0,0" Width="150">
					<ComboBoxItem Content="BulkExtractor"/>
					<ComboBoxItem Content="Chainsaw"/>					
					<ComboBoxItem Content="Extract Archives"/>
					<ComboBoxItem Content="Geolocate IPs"/>
					<ComboBoxItem Content="Hayabusa"/>
					<ComboBoxItem Content="Plaso Timeline"/>					
					<ComboBoxItem Content="Zimmerman Tools"/>	
					<ComboBoxItem Content="Zircolite"/>
					<ComboBoxItem Content="Timeline Artifacts"/>					
				</ComboBox>			
				<TextBlock x:Name="ProcessToolLocation" Text="Processing Tool Location" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,155,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBlock x:Name="ProcessToolExtraArguments" Text="Extra Arguments (If any)" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,155,0,0" TextWrapping="Wrap" Width="740"/>
				
				<!-- Timeline Artifacts -->
				<Button x:Name="ProcessTimelineArtifactsButton" Content="Create|Update Database" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>
				<TextBox x:Name="sqlitePathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowsesqlitePathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>				
				<CheckBox x:Name="IncludeChainsaw" Content="Include Chainsaw" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="200,200,0,0"/>
				<CheckBox x:Name="IncludeHayabusa" Content="Include Hayabusa" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="350,200,0,0"/>
				<CheckBox x:Name="IncludeZimmerman" Content="Include Zimmerman" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="200,225,0,0"/>
				<CheckBox x:Name="IncludeZircolite" Content="Include Zircolite" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="350,225,0,0"/>
				<Button x:Name="ExportTimelineArtifactsButton" Content="Export CSV from DB" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" Width="150" IsEnabled="False"/>	
				<Label x:Name="TimelineArtifactsStartDate" Content="Start Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="175,250,0,0"/>
				<DatePicker x:Name="TimelineArtifactsStartDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="245,250,0,0" Width="120" IsEnabled="False"/>
				<Label x:Name="TimelineArtifactsEndDate" Content="End Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="375,250,0,0"/>
				<DatePicker x:Name="TimelineArtifactsEndDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="445,250,0,0" Width="120" IsEnabled="False"/>
				<CheckBox x:Name="TimelineDateRangeCheckBox" Content="Use Custom Date Range" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="570,250,0,0"/>
				<CheckBox x:Name="TimelineDateIOCCheckBox" Content="Find IOCS" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="570,275,0,0"/>
				<Button x:Name="OpenCustomTimelineIOCsButton" Content="Open CustomIOCs" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="570,175,0,0"/>
				<TextBlock x:Name="TimelineArtifactTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,300,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="This process will combine the processed csv output from the selected output folders into a database for searching and future processes."/>
					<LineBreak/>
					<Run Text="Note: When selecting to include Zimmerman, the system name is recorded in the database as the folder after SystemArtifacts\ProcessedArtifacts\Zimmermantools\&lt;system name here&gt;. Change the root folder after Zimmermantools that contains the processed system artifacts for best results."/>
					<LineBreak/>
					<Run Text="Running this process subsequently will update the database with any new files"/>
					<LineBreak/>
					<Run Text="Export a csv from the database with or without a custom data range by clicking on Export CSV from DB"/>
					<LineBreak/>				
					<Run Text="Select Find IOCS to export matching terms from the CustomIOCS file against the columns event_description, system_name, and user_name"/>
				</TextBlock>
				
				<!-- Bulk Extractor -->
				<Button x:Name="ProcessBulkExtractorButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="BulkExtractorPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseBulkExtractorPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<TextBlock x:Name="BulkTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="BulkExtractor is a program that extracts features such as email addresses, credit card numbers, URLs, and other types of information from digital evidence sources. The tool can be downloaded/updated from the Tools Management Tab."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will run Bulk Extractor against the selected file or folder and place the output into the ProcessedArtifacts folder"/>
				</TextBlock>						

				<!-- Chainsaw -->
				<Button x:Name="ProcessChainsawButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="ChainsawPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseChainsawPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>		
				<CheckBox x:Name="ChainsawJson" Content="Json output" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,175,0,0"/>			
				<TextBlock x:Name="ChawnsawTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="Chainsaw provides capability to quickly identify threats within Windows forensic artifacts such as Event Logs and the MFT file using built-in support for Sigma detection rules, and via custom Chainsaw detection rules."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will take in a directory and hunt accross the event logs within using the --mapping set to mappings\sigma-event-logs-all.yml and the -s sigma\ options. Default output will be saved to the ProcessArtifacts\Chainsaw\&lt;processingfolder&gt; name in csv format"/>
					<LineBreak/>
					<Run Text="Select the Json checkbox option to save the output to json format instead of csv"/>				
				</TextBlock>	
				
				<!-- Zimmerman -->
				<Button x:Name="ProcessZimmermanButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>	
				<ComboBox x:Name="ZtoolsComboBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,175,0,0" Width="180"/>				
				<TextBox x:Name="ZimmermanPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseZimmermanPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<Button x:Name="UpdateZimmermanButton" Content="Update Zimmerman Tools" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,220,0,0" Width="200" IsEnabled="False"/>					
				<TextBlock x:Name="ZimmermanTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="Zimmerman Tools, created by Eric Zimmerman, are a collection of digital forensics tools that include utilities for file system analysis, registry examination, and other forensic artifacts analysis. The tools can be downloaded from the Tools Management Tab, or updated via Update Zimmerman Tools button."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will take in a file or directory and use the selected Zimmerman Tools module(s) for parsing. The data will be saved to the PrcessedArtifacts folder under a subdirectory named Zimmermantools"/>
				</TextBlock>		
				
				<!-- Geolocate Extractor -->
				<Button x:Name="GeoLocateButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="GeoLite2CityDBPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseGeoLite2CityDBPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>	
				<CheckBox x:Name="CheckVirusTotal" Content="Check with VirusTotal" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,175,0,0"/>
				<TextBlock x:Name="GeolocateTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="GeoLite2 City is a geolocation database that offers IP address to city-level location mapping, widely utilized in network traffic analysis, cybersecurity, and location-based services. This database is required for this process and can be downloaded\updated from the Tools Management Tab if you have a License Key."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will take in a file and grep out any IPv4 or IPv6 files excluding private IP addresses and resolve them against the GeoLite2 City database parsing out location informatoin. The parsed data will be saved into the ProcessedArtifacts folder within a ResolvedIPs folder as a csv file."/>
					<LineBreak/>
					<Run Text="Select the Check with VirusTotal option to run the IPs against Virustotal for more detailed information. A VirusTotal credential key is required for this process. Note that free public VT keys are subject to 4 lookups a minutes which will drastically slow this process down when resolving multiple IPs."/>
				</TextBlock>				
				
				<!-- 7zip Extractor -->
				<Button x:Name="Process7zipButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>	
				<TextBox x:Name="SevenzipPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="Browse7zipPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<TextBlock x:Name="sevenzipTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="7-Zip is a file archiver with a high compression ratio. The tool can be downloaded/updated from the Tools Management Tab."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will extract contents of an archive using 7zip and place them into the ProcessedArtifacts folder"/>
				</TextBlock>				
				
				<!-- Plaso -->
				<Button x:Name="ProcessPlasoButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="PlasoPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowsePlasoPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<!-- Plaso Date Range -->
				<CheckBox x:Name="PlasoDateRangeCheckBox" Content="Use Custom Date Range" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,200,0,0"/>
				<Label x:Name="PlasoStartDate" Content="Start Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,200,0,0"/>
				<DatePicker x:Name="PlasoStartDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="80,200,0,0" Width="120" IsEnabled="False"/>
				<Label x:Name="PlasoEndDate" Content="End Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="210,200,0,0"/>
				<DatePicker x:Name="PlasoEndDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,200,0,0" Width="120" IsEnabled="False"/>
				<CheckBox x:Name="PsortOnlyCheckBox" Content="Use Psort only" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,175,0,0"/>
				<TextBlock x:Name="PlasoTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="Plaso (Python-based automatic event log analysis) is a Python-based backend engine used by tools such as log2timeline for automatic timeline creation and analysis of various digital forensic artifacts. The tool can be downloaded/updated from the Tools Management Tab."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will create a plaso file using log2timeline along with a super_timeline.xlsx file from plaso"/>
					<LineBreak/>
					<Run Text="Select the Use Psort only option to process an already created plaso file with psort"/>
				</TextBlock>
				
				<!-- Hayabusa -->
				<Button x:Name="ProcessHayabusaButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="HayabusaPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseHayabusaPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<!-- Hayabusa Date Range -->
				<CheckBox x:Name="HayabusaDateRangeCheckBox" Content="Use Custom Date Range" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,200,0,0"/>
				<Label x:Name="HayabusaStartDate" Content="Start Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,200,0,0"/>
				<DatePicker x:Name="HayabusaStartDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="80,200,0,0" Width="120" IsEnabled="False"/>
				<Label x:Name="HayabusaEndDate" Content="End Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="210,200,0,0"/>
				<DatePicker x:Name="HayabusaEndDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,200,0,0" Width="120" IsEnabled="False"/>			
				<CheckBox x:Name="HayabusaGeoDBCheckBox" Content="Use GeoIP" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,175,0,0"/>
				<TextBlock x:Name="HayabusaTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="Hayabusa is an open-source security tool developed by Yamato Security. The tool can be downloaded/updated from the Tools Management Tab."/>
					<LineBreak/>
					<Run Text="It's designed for fast scanning of Windows event logs, which can be crucial for incident response and digital forensics in cybersecurity."/>
					<LineBreak/>
					<Run Text="The tool can quickly parse through large volumes of log data to identify potential security incidents, helping IT professionals and security analysts in efficiently detecting and responding to security threats."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="Select the Use GeoIP option to add GeopIP (ASN, city, ccountry) info to the IPs. This does require the three GeoLite2 DBs which can be downloaded from the Tools Management Tab if you have a License Key."/>
				</TextBlock>


				<!-- Zircolite -->
				<Button x:Name="ProcessZircoliteButton" Content="Launch Process" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>
				<TextBox x:Name="ZircolitePathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseZircolitePathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<CheckBox x:Name="ZircolitejsonCheckBox" Content="Output json" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="570,175,0,0"/>
				<CheckBox x:Name="ZircolitepackageCheckBox" Content="Create Package" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="570,200,0,0"/>				
				<Label x:Name="ZircoliteRules" Content="Rules" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,200,0,0"/>	
				<ComboBox x:Name="ZircoliteRulesComboBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="80,200,0,0" Width="180">
						<ComboBoxItem Content="rules_windows_generic_full.json"/>					
				</ComboBox>						
				<Label x:Name="ZircoliteTemplates" Content="Template" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="265,200,0,0"/>			

				
				<ComboBox x:Name="ZircoliteTemplatesComboBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="340,200,0,0" Width="180">
						<ComboBoxItem Content="Default (None)"/>					
				</ComboBox>		
				<CheckBox x:Name="ZircolitesysmonCheckBox" Content="Sysmon for Linux" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="570,225,0,0"/>					
				<!-- Zircolite Date Range -->
				<CheckBox x:Name="ZircoliteDateRangeCheckBox" Content="Use Custom Date Range" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="570,250,0,0"/>
				<Label x:Name="ZircoliteStartDate" Content="Start Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,230,0,0"/>
				<DatePicker x:Name="ZircoliteStartDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="80,230,0,0" Width="120" IsEnabled="False"/>
				<Label x:Name="ZircoliteEndDate" Content="End Date:" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="210,230,0,0"/>
				<DatePicker x:Name="ZircoliteEndDatePicker" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,230,0,0" Width="120" IsEnabled="False"/>
				<Button x:Name="UpdateZircoliteButton" Content="Update Rules" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,260,0,0" Width="150" IsEnabled="False"/>			
				<TextBlock x:Name="ZircoliteTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,300,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="Zircolite allows to use SIGMA rules on MS Windows EVTX (EVTX, XML and JSONL format), Auditd logs, Sysmon for Linux and EVTXtract logs"/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will run Zircolite against the file\folder using the selected ruleset"/>
					<LineBreak/>
					<Run Text="Additional options include output to Json, selecting a template output, package option, custom date range, and update rules"/>
				</TextBlock>
				
				<TextBox x:Name="ProcessSystemTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>
		
		<!-- M365 Collection Tab -->
		<TabItem Header="Collect M365 Logs" IsEnabled="False" x:Name="TabCollectM365">
			<Grid>
				<Button x:Name="ConnectClientButton" Content="Connect to Client" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="10,10,0,0"/>
				<Button x:Name="TestClientConnectionButton" Content="Test Connection" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="140,10,0,0"/>
				<TextBlock x:Name="M365CustomIPsTextBox" Text="In the Custom IPs or Users files lists, please enter each full IP address or username on a separate line." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="300,10,0,0" Width="500" TextWrapping="Wrap"/>
				<Button x:Name="OpenCustomIPListButton" Content="Open IP List" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="450,50,0,0"/>
				<Button x:Name="OpenCustomUserListButton" Content="Open User List" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="580,50,0,0"/>	
				<TextBlock Text="Collect Triage attempts to collect all collections below except for MAL and Message Trace using their default arguments" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,75,0,0" TextWrapping="Wrap" Width="740"/>							
				<Button x:Name="CollectTriageButton" Content="Collect Triage" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,50,0,0" Width="150" IsEnabled="False"/>				
				<TextBlock x:Name="M365CollectionName" Text="M365 Collection Type" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,105,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBlock x:Name="M365ExtraArguments" Text="Extra Arguments (If any)" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,105,0,0" TextWrapping="Wrap" Width="740"/>
				<Button x:Name="CollectUALButton" Content="Unified Audit Logs" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,125,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectUALUsersComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,125,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>	
				<ComboBox x:Name="CollectUALIPsComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,125,0,0" Width="105">
					<ComboBoxItem Content="All IPs" />
					<ComboBoxItem Content="Custom IPs" />
				</ComboBox>
				<ComboBox x:Name="CollectUALOperationsComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="390,125,0,0" Width="130">
					<ComboBoxItem Content="Limited Operations" />
					<ComboBoxItem Content="All Operations" />
				</ComboBox>				
				<ComboBox x:Name="CollectUALDateComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="525,125,0,0" Width="105">
					<ComboBoxItem Content="Past 90 Days" />
					<ComboBoxItem Content="Custom Date" />
				</ComboBox>				
				<DatePicker x:Name="M365StartDatePicker" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="635,125,0,0" Width="120" IsEnabled="False"/>				
				<Button x:Name="CollectMALButton" Content="Mailbox Audit Logs" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,150,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectMALComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,150,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>				
				<Button x:Name="CollectAdminLogsButton" Content="Admin Logs" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>
				<Button x:Name="CollectInboxRulesButton" Content="InboxRules" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,200,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectInboxRulesComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,200,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>
				<Button x:Name="CollectForwardingRulesButton" Content="Forwarding Rules" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,225,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectForwardingRulesComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,225,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>				
				<Button x:Name="CollectM365InfoButton" Content="M365 Info" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" Width="150" IsEnabled="False"/>
				<Button x:Name="CollectMessageTraceButton" Content="Message Trace" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,275,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectMessageTraceComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,275,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>					
				<Button x:Name="CollectAzureLogsButton" Content="Azure Logs" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,300,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectAzureLogsComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,300,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>					
				<Button x:Name="CollectLastPasswordChangeButton" Content="Last Password Change" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,325,0,0" Width="150" IsEnabled="False"/>
				<ComboBox x:Name="CollectLastPasswordComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,325,0,0" Width="105">
					<ComboBoxItem Content="Entire Tenant" />
					<ComboBoxItem Content="Custom Users" />
				</ComboBox>						
				<TextBox x:Name="M365TextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>		
				<!-- Add your controls here -->
			</Grid>
		</TabItem>	

		<!-- Evidence Sync Tab  -->
		<TabItem Header="Evidence Sync" IsEnabled="False" x:Name="TabEvidenceSync">
			<Grid>
				<TextBlock Text="Welcome to the Evidence Sync Tab. Upload folders or files to various platforms" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap" Width="720"/>
				<CheckBox x:Name="QuickSyncCheckBox" Content="Check to Sync a predifined folder within the Case directory" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,30,0,0"/>
				<ComboBox x:Name="QuickSyncComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="350,30,0,0" Width="180" IsEnabled="False"/>			
				<TextBlock Text="Select a file or folder, then select a tool to sync the data with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,60,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBox x:Name="SyncProcessingPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,75,0,0" Width="400"/>
				<Button x:Name="SyncProcessingPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="420,75,0,0" Width="25"/>
				<TextBlock Text="Sync Tool Name" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,110,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBlock Text="Sync Tool Parameters" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="350,130,0,0" TextWrapping="Wrap" Width="740"/>
				<!-- Tool Selection ComboBox -->
				<ComboBox x:Name="SyncToolComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,130,0,0" Width="150">
					<ComboBoxItem Content="Timesketch"/>
					<ComboBoxItem Content="Splunk"/>
					<ComboBoxItem Content="Elastic"/>
				</ComboBox>
				
				<!-- Coming Soon TextBlocks -->
				<TextBlock x:Name="ComingSoonSplunk" Text="Splunk integration coming soon..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,160,0,0" TextWrapping="Wrap"/>
				<TextBlock x:Name="ComingSoonElastic" Text="Elastic integration coming soon..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,160,0,0" TextWrapping="Wrap"/>
								
				<!-- Time Sketch Start -->	
				<Button x:Name="TestTimesketchButton" Content="Test Connection" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,180,0,0" Width="150" IsEnabled="False"/>
				<TextBlock x:Name="timesketchurltext" Text="URL" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="380,180,0,0" TextWrapping="Wrap" Width="740"/>			
				<TextBox x:Name="SyncTimesketchURLPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,180,0,0" Width="200"/>
				<TextBox x:Name="TimesketchUserTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="450,180,0,0" Width="200"/>
				<TextBlock x:Name="TimesketchUserText" Text="User Name" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="660,180,0,0" TextWrapping="Wrap" Width="740"/>		

				<TextBox x:Name="NewTimesketchTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="450,205,0,0" Width="200"/>
				<TextBlock x:Name="NewTimesketchText" Text="Sketch Name" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="660,205,0,0" TextWrapping="Wrap" Width="740"/>			
				<Button x:Name="RefreshTimesketchButton" Content="Refresh Indexes" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,205,0,0" Width="150" IsEnabled="False"/>	
				<TextBlock x:Name="SketchIndexText" Text="Sketch ID" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="380,205,0,0" TextWrapping="Wrap" Width="740"/>
				<ComboBox x:Name="TimesketchIndexComboBox" HorizontalAlignment="Left" Visibility="Collapsed" VerticalAlignment="Top" Margin="170,205,0,0" Width="200"/>
				<CheckBox x:Name="NewTimesketchCheckBox" Visibility="Collapsed" Content="Check to enter a new Sketch name above" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="430,230,0,0"/>				
				<Button x:Name="SyncTimesketchButton" Content="Sync Timesketch" HorizontalAlignment="Left" Visibility="Collapsed" VerticalAlignment="Top" Margin="10,230,0,0" Width="150" IsEnabled="False"/>
				<TextBlock x:Name="Timesketchdescription" Text="To sync a folder with a Timesketch server, first enter the URL to Timesketch and User Name followed by Test Connection, then either choose an existing index or create a new sketch by checking the box to enter a name. Lastly after a file/folder has been selected, push the Sync Timesketch button. The data will be synced and the timeline names will be named after the file that was synced." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,255,0,0" TextWrapping="Wrap" Width="720"/>				
				<!-- Time Sketch End -->
				<TextBox x:Name="EvidenceSyncTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>	

		<!-- Threat Scanners -->
		<TabItem Header="Threat Scanners" IsEnabled="False" x:Name="TabUseThreatScanners">
			<Grid>
				<TextBlock Text="Choose from a variety of Threat Scanners to scan a selected file or folder with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBlock Text="Select a file or folder for scanning, then select a tool to Scan with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,50,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBox x:Name="ArtifactScanningPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,65,0,0" Width="400"/>
				<Button x:Name="ArtifactScanningPathButton" Content="..." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="420,65,0,0" Width="25"/>
				<TextBlock Text="Select a tool to scan with" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,110,0,0" TextWrapping="Wrap" Width="740"/>
				<!-- Tool Selection ComboBox -->
				<ComboBox x:Name="ThreatScanToolComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,130,0,0" Width="150">
					<ComboBoxItem Content="ClamAV"/>
					<ComboBoxItem Content="Loki"/>				
				</ComboBox>			
				<TextBlock x:Name="ScanToolLocation" Text="Scanning Tool Location" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,155,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBlock x:Name="ScanningToolExtraArguments" Text="Extra Arguments (If any)" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,155,0,0" TextWrapping="Wrap" Width="740"/>
				
				<!-- ClamAV -->
				<Button x:Name="ScanClamAVButton" Content="Launch Scan" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="ClamAVPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseClamAVPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<TextBlock x:Name="ClamAVTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="ClamAV is a free and open-source antivirus software toolkit. It is primarily used for detecting trojans, viruses, malware, and other malicious threats. The tool can be downloaded/updated from the Tools Management Tab."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will run ClamAV against the selected file or folder and place the output into the ProcessedArtifacts folder"/>
					<LineBreak/>					
					<Run Text="Update ClamAV databases directly from here by selecting 'Update ClamAV' after the path to freshclam.exe has been selected"/>						
				</TextBlock>


				<TextBlock x:Name="FreshclamLocation" Text="Path to freshclam.exe Location" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,205,0,0" TextWrapping="Wrap" Width="740"/>
				<Button x:Name="UpdateclamAVButton" Content="Update ClamAV" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,225,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="clamAVUpdaterPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,225,0,0" Width="300"/>
				<Button x:Name="BrowseclamAVUpdatePathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,225,0,0" Width="25"/>					
				
				<!-- Loki -->
				<Button x:Name="ScanLokiButton" Content="Launch Scan" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,175,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="LokiPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,175,0,0" Width="300"/>
				<Button x:Name="BrowseLokiPathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,175,0,0" Width="25"/>
				<TextBlock x:Name="LokiUpgraderLocation" Text="Path to Loki-Upgrader.exe Location" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,205,0,0" TextWrapping="Wrap" Width="740"/>				
				<Button x:Name="UpdateLokiButton" Content="Update Loki" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,225,0,0" Width="150" IsEnabled="False"/>			
				<TextBox x:Name="LokiUpdaterPathTextBox" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="170,225,0,0" Width="300"/>
				<Button x:Name="BrowseLokiUpdatePathButton" Content="..." Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="475,225,0,0" Width="25"/>				
				
				<TextBlock x:Name="LokiTextBlock" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,250,0,0" TextWrapping="Wrap" Width="740">
					<Run Text="Loki is a free and open-source scanner for simple indicators of compromise (IoCs). Unlike ClamAV, Loki is not an antivirus program but rather focuses on various forms of malware and hacker tools based on pattern matching. The tool can be downloaded/updated from the Tools Management Tab."/>
					<LineBreak/>
					<LineBreak/>					
					<Run Text="This Process will run Loki against the selected file or folder and place the output into the ProcessedArtifacts folder"/>
					<LineBreak/>					
					<Run Text="Select the Include Process Scan checkbox to include scanning the running processes on the current system"/>
					<LineBreak/>					
					<Run Text="Select the Include Intense Scan checkbox to also scan unknown file types and all extensions"/>
					<LineBreak/>					
					<Run Text="Select the Include Vulnerability Checks checkbox to check for common vulnerabilities that may be present on the system."/>
					<LineBreak/>					
					<Run Text="Update Loki directly from here by selecting 'Update Loki' after the path to loki-upgrader.exe has been selected"/>						
				</TextBlock>					
				<CheckBox x:Name="ProcscanCheckbox" Content="Include Process scan" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,175,0,0"/>
				<CheckBox x:Name="IntenseScanCheckbox" Content="Include Intense scan" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,200,0,0"/>
				<CheckBox x:Name="VulnchecksCheckbox" Content="Include Vulnerability Check" Visibility="Collapsed" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="510,225,0,0"/>
				
				<TextBox x:Name="ThreatScannerTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>	

		<!-- Elastic Search Tab -->
		<TabItem Header="Elastic Search" IsEnabled="False" x:Name="TabElasticSearch">
			<Grid>
				<TextBlock Text="Welcome to the Elastic Search Tab. This tab contains a list of search queries to use against artifacts acquired from Velociraptor or Zimmerman Tools and ingested into an elastic instance. Input the Kibana URL, Index, and Search Selection along with any options then select Launch Search. Searches with the suffix _V are velociraptor specific." HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" TextWrapping="Wrap" Width="720"/>

				<TextBlock Text="Elasticsearch Kibana URL" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,60,0,0" TextWrapping="Wrap" Width="740"/>
				<TextBox x:Name="ElasticURLPathTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,75,0,0" Width="250"/>
				
				<TextBlock Text="Index Name or ID (Kibana Version Dependent)" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,60,0,0" TextWrapping="Wrap" Width="740"/>				
				<TextBox x:Name="ElasticIndexIDTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,75,0,0" Width="250"/>				
				
				<Button x:Name="ElasticSearchButton" Content="Launch Search" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="650,75,0,0" Width="100" IsEnabled="False"/>

				<!-- Elastic Date Range -->
				<CheckBox x:Name="ElasticDateRangeCheckBox" Content="Use Custom Date Range" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="430,80,0,0" IsEnabled="False" Visibility="Collapsed"/>
				<Label Content="Start Date:" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,80,0,0" Visibility="Collapsed"/>
				<DatePicker x:Name="ElasticStartDatePicker" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="80,80,0,0" Width="120" IsEnabled="False" Visibility="Collapsed"/>
				<Label Content="End Date:" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="210,80,0,0" Visibility="Collapsed"/>
				<DatePicker x:Name="ElasticEndDatePicker" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="280,80,0,0" Width="120" IsEnabled="False" Visibility="Collapsed"/>

				
				<TextBlock Text="Search Selection" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,110,0,0" TextWrapping="Wrap" Width="740"/>
				<!-- Search Selection ComboBox -->
				<ComboBox x:Name="ElasticSearchComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,130,0,0" Width="150">
					<ComboBoxItem Content="All"/>				
					<ComboBoxItem Content="Initial Access"/>
					<ComboBoxItem Content="Execution"/>
					<ComboBoxItem Content="Persistence"/>
					<ComboBoxItem Content="Privilege Escalation"/>
					<ComboBoxItem Content="Defense Evasion"/>
					<ComboBoxItem Content="Credential Access"/>
					<ComboBoxItem Content="Discovery"/>
					<ComboBoxItem Content="Lateral Movement"/>
					<ComboBoxItem Content="Collection"/>
					<ComboBoxItem Content="Command and Control"/>
					<ComboBoxItem Content="Exfiltration"/>
					<ComboBoxItem Content="Impact"/>
					<ComboBoxItem Content="Custom IOCs"/>
				</ComboBox>
	
				<TextBlock Text="Select Custom IOCs (Optional)" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="200,115,0,0" TextWrapping="Wrap" Width="740"/>
				<ComboBox x:Name="ElasticCustomIOCComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="200,130,0,0" Width="175" SelectedIndex="0">
					<ComboBoxItem Content="None"/>
					<ComboBoxItem Content="CustomIOCs.txt"/>				
				</ComboBox>				

				<TextBlock Text="Open CustomIOCs.txt" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="385,115,0,0" TextWrapping="Wrap" Width="740"/>
				<Button x:Name="OpenCustomElasticIOCsButton" Content="Open CustomIOCs" HorizontalAlignment="Left" VerticalAlignment="Top" Width="120" Margin="385,130,0,0"/>
				
				
				<TextBlock Text="Enter Custom Search String (Optional)" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="520,115,0,0" TextWrapping="Wrap" Width="740"/>				
				<TextBox x:Name="ElasticSearchIOCTextBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="520,130,0,0" Width="200"/>

				
				<ListBox x:Name="ElasticCheckBoxListBox" HorizontalAlignment="Left" VerticalAlignment="Top" Height="270" Width="200" Margin="10,150,0,0"/>		

				<TextBox x:Name="ElasticSearchDescriptionTextBox" Text="" HorizontalAlignment="Left" VerticalAlignment="Top" Width="570" Height="270" TextWrapping="Wrap" IsReadOnly="True" Margin="200,150,0,0"/>
				
				<TextBox x:Name="ElasticSearchTextBox" Text="" HorizontalAlignment="Left" Width="760" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>
		
		<!-- Tool Page Tab -->
		<TabItem Header="Tool Management" IsEnabled="False" x:Name="TabPageTools">
			<Grid>
					<TextBlock HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,10,0,0" Width="740">
						<Run Text="This page gives details on the various tools used in this program and allows for their download/update."/>
						<LineBreak/>
						<Run Text="Downloads run in the background. Use the status field to track the selected tool while a download/update is running."/>
					</TextBlock>
				<TextBlock Text="Select a tool for details and to download or update" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,45,0,0" TextWrapping="Wrap"/>
					<ComboBox x:Name="ToolsSelectionComboBox" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="10,65,0,0" Width="200">
					<ComboBoxItem Content="7zip" />
					<ComboBoxItem Content="BulkExtractor" />
					<ComboBoxItem Content="chainsaw" />						
					<ComboBoxItem Content="ClamAV" />			
					<ComboBoxItem Content="etl2pcapng" />
					<ComboBoxItem Content="Ftkimager" />
					<ComboBoxItem Content="GeoLite2Databases" />
					<ComboBoxItem Content="Hayabusa" />
					<ComboBoxItem Content="Loki" />					
					<ComboBoxItem Content="Plaso" />
					<ComboBoxItem Content="SQLite" />					
					<ComboBoxItem Content="Velociraptor" />
					<ComboBoxItem Content="Volatility3" />
					<ComboBoxItem Content="winpmem" />					
					<ComboBoxItem Content="ZimmermanTools" />
					<ComboBoxItem Content="Zircolite" />					
					</ComboBox>
					<TextBlock x:Name="ToolDownloadStatusTextBlock" Text="Status: Idle" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="350,70,0,0" TextWrapping="Wrap" Width="390"/>
					<TextBox x:Name="ToolDescriptionTextBox" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="10,100" Width="740" Height="300" TextWrapping="Wrap" IsReadOnly="True"/>		
					<Button x:Name="DownloadToolButton" Content="Download\Update" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="215,65,0,0" Width="125" IsEnabled="False"/>				
				<!-- Log Display -->
				<TextBox x:Name="tabPageToolsTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>
		
    </TabControl>
    </Grid>
    </Viewbox>
    </Grid>
</Window>

"@
$reader = [System.Xml.XmlNodeReader]::new($xaml)
$window = [System.Windows.Markup.XamlReader]::Load($reader)

#Text boxes
$caseCreationLogTextBox = $window.FindName("CaseCreationLogTextBox")
$PacketCaptureTextBox = $window.FindName("PacketCaptureTextBox")
$SystemArtifactsTextBox = $window.FindName("SystemArtifactsTextBox")
$MemoryTextBox = $window.FindName("MemoryTextBox")
$FTKImagerTextBox = $window.FindName("FTKImagerTextBox")
$M365TextBox = $window.FindName("M365TextBox")
#$GoogleWorkspaceTextBox = $window.FindName("GoogleWorkspaceTextBox")
$ProcessSystemTextBox = $window.FindName("ProcessSystemTextBox")
$ThreatScannerTextBox = $window.FindName("ThreatScannerTextBox")
$tabPageToolsTextBox = $window.FindName("tabPageToolsTextBox")

####Home tab Event handlers####
$TabsSelectionComboBox = $window.FindName("TabsSelectionComboBox")
$TabsDescriptionTextBox = $window.FindName("TabsDescriptionTextBox")
$tabDescriptions = @{
    "Home" = @"
Welcome to the Evidence Collection & Handling Orchestrator Tool, a comprehensive PowerShell-based solution designed for Digital Forensics Analysts. This tool streamlines various evidence collection and processing tasks, offering:

INTEGRATION WITH OPEN-SOURCE TOOLS:
- Leverage a suite of renowned DFIR tools directly within the program. All tools are accessible from a "Tools" folder, co-located with the program's executable.

EASE OF TOOL MANAGEMENT:
- Easily download and update essential open-source tools via the "Tool Management" tab. Note: Some tools require Python as a prerequisite.

ORGANIZED CASE MANAGEMENT:
- Upon launch, the program generates a "cases.csv" file in the same directory, keeping track of case folders and logging data.

KEY FEATURES

USER-FRIENDLY INTERFACE:
- Designed with user experience in mind, ensuring ease of navigation and operation.

COMPREHENSIVE CASE TRACKING:
- All activities and evidence processed are meticulously saved within each case folder for seamless case management.

FLEXIBILITY AND CONTROL:
- Open, create, import, or delete cases with ease, giving you complete control over your case data.
"@
    "Case Management" = @"
The 'Case Management' tab is designed to streamline your digital forensic investigation workflow. Key functionalities include:

CREATE NEW CASE:
- Enter a case name and select a storage directory. The program will create a dedicated folder for your case, complete with metadata ('_ECHO.<casename>.json') and a case log file ('<casename>.log').

MANAGE EXISTING CASES:
- Access and manage your ongoing investigations. The 'Existing Cases' dropdown lets you open or delete cases. Deleting a case removes it from the program's records but doesn't delete the actual case folder.

IMPORT CASE:
- Easily integrate external cases into the program by importing '_ECHO.<casename>.json' (or legacy '<casename>.txt'). This feature allows for seamless collaboration and case transfer.

Note: Cases are tracked in the 'cases.csv' file, located in the same directory as the program, ensuring organized and accessible case data.
"@
    "Collect Packet Capture" = @"
The 'Collect Packet Capture' tab facilitates network packet capture using Windows' native netsh trace command. Key features include:

NETSH TRACE FOR PACKET CAPTURE:
- Utilize the powerful, built-in netsh trace tool to capture network packets. This method is efficient and doesn't require third-party software installation.

CAPTURE DURATION CONTROL:
- Specify the duration for packet capture in minutes. If left blank, the default capture time is set to 5 minutes.

CONVERT ETL TO PCAP:
- After capturing packets, use the 'Convert ETL to PCAP' button to transform the ETL file format to the widely used PCAP format. This conversion makes the captured data compatible with various network analysis tools.
- This will go through any ETL files within the directory the Packet Capture was collected in and convert them.

ETL2PCAPNG PATH:
- Easily set the path to the Etl2Pcapng.exe tool, required for the ETL to PCAP conversion process. Use the 'Browse' button to navigate and select the executable file.
- If you do not have this tool, proceed to the Tool Management Tab where it can be downloaded.

EXTRACT CAB FILE:
- Extract the contents of the captured CAB file for detailed analysis and review. This will go through any CAB files within the directory the Packet Capture was collected in and extract them.

Note: This tab doesn't support promiscuous mode packet capturing (e.g., as done in Wireshark), but is tailored for straightforward and quick network traffic analysis.
"@
    "Collect Disk Image" = @"
The 'Collect Disk Image' tab is designed for creating forensic images of disks using FTK Imager. This tab streamlines the disk imaging process, offering the following features:

DISPLAY AND SELECT DRIVES:
- View a list of all connected drives by clicking on 'Display Drive(s) List'.
- Select one or more drives from the list for imaging. Multiple selections enable simultaneous imaging of multiple drives.

FTK IMAGER INTEGRATION:
- Utilize FTK Imager, a leading forensic imaging tool, for reliable and accurate disk imaging.
- The tab shows the current FTK Imager configuration and allows for easy selection of the FTK executable if not automatically detected.

CREATE DISK IMAGES:
- After selecting the desired drives, use the 'Collect Selected Drives' button to start the imaging process.
- The disk images will be created in a forensically sound manner, preserving the integrity of the data.

Note: This tab requires FTK Imager to be installed on the system or accessible through the provided path. Ensure FTK Imager is correctly configured for optimal functionality of this feature.
"@
    "Process System Artifacts" = @"
The 'Process System Artifacts' tab provides a versatile interface for processing various system artifacts using a range of forensic tools. This tab is designed to facilitate easy selection and processing of files or folders with the chosen tool. Key features include:

TOOL SELECTION AND PATH CONFIGURATION:
- Select from a range of tools like BulkExtractor, Zimmerman Tools, Geolocate IPs, Extract Archives, and Plaso Timeline.
- Conveniently set the path for the tool executable and the artifact to be processed.

VERSATILE PROCESSING OPTIONS:
- Process artifacts with tools like BulkExtractor for comprehensive data extraction or Zimmerman Tools for detailed forensic analysis.
- Use Geolocate IPs on a file to automatically go through and parse IPv4 and Ipv6 IPs for geographical IP analysis.
- Use 7zip for extracting various archive formats.

ADVANCED FEATURES:
- Check VirusTotal for threat analysis during the Geolocate IPs process.
- Customize Plaso timeline generation with options for using custom date ranges or sorting only on pre-processed Plaso storage files.

USER INTERFACE AND LOGGING:
- A straightforward and user-friendly interface for selecting and configuring tools.
- Real-time feedback and detailed logging in a dedicated display area, keeping you informed of the ongoing process and results.

This tab is crucial for forensic analysts who need to process system artifacts efficiently. It streamlines the use of multiple tools, enhancing the capability to extract, analyze, and report forensic data effectively.
"@
    "Collect M365 Logs" = @"
The 'Collect M365 Logs' tab facilitates the gathering of Microsoft 365 logs for digital forensic investigations. This tab includes multiple features to customize and streamline the log collection process:

CONNECT AND TEST CLIENT CONNECTION:
- 'Connect to Client' to establish a connection with the Microsoft 365 tenant.
- Use 'Test Connection' to verify the connectivity and readiness of the client for log collection.

CUSTOMIZE LOG COLLECTION:
- Open lists of 'Custom IPs' and 'Custom Users' to specify targeted log collection using speicif IPs or User names.
- 'Collect Triage' attempts to gather a comprehensive set of logs using default arguments, excluding Mailbox Audit Logs (MAL) and Message Trace for efficiency.

SELECTIVE LOG COLLECTION:
- Choose specific types of logs like 'Unified Audit Logs', 'Mailbox Audit Logs', 'Admin Logs', 'Inbox Rules', 'Forwarding Rules', 'M365 Info', 'Message Trace', 'Azure Logs', and 'Last Password Change'.
- Configure each log type with specific parameters like user scope (entire tenant or custom users), IP addresses, operations, and date ranges.

USER AND IP FILTERING:
- Selectively collect logs for specific users or IP addresses, providing focused and relevant data for analysis.
- Customize collection parameters like operations and date ranges for Unified Audit Logs, enhancing the granularity of the collected data.

Note: Ensure proper configurations and permissions are set up in the Microsoft 365 tenant to allow seamless log collection. This feature is essential for investigations involving Microsoft 365 environments, providing crucial insights and evidence.
"@
    "Tool Management" = @"
The 'Tool Management' tab is a pivotal feature of the Evidence Collection & Handling Orchestrator Tool, focusing on the management and updating of various digital forensics tools. It provides a user-friendly interface for these key functions:

SELECTION AND MANAGEMENT:
- Centralized management of a broad range of essential digital forensics tools.
- Streamlined selection process, with an easy-to-use drop-down menu featuring tools like 7zip, BulkExtractor, etl2pcapng, Ftkimager, and more.

DOWNLOAD AND UPDATE TOOLS:
- Facilitates the easy download and updating of selected tools.
- Ensures users have access to the latest versions of each tool for optimal performance.

SUPPORTED TOOLS:
- Supports a diverse range of tools necessary for different aspects of digital forensic analysis, including data extraction, in-depth analysis, and more.
- Regular updates to include new tools and features as they become available in the digital forensics community.

USER INTERFACE AND FEEDBACK:
- Descriptive text box provides detailed information about each selected tool.
- 'Download/Update' button conveniently located for quick access.
- Real-time feedback and logging displayed at the bottom, monitoring the progress of downloads or updates.

Please Note: The GUI may temporarily freeze during tool downloads or updates, as background operations are not implemented for simplicity. Users are advised to be patient during these processes.
"@
    "Collect and Process Memory" = @"
The 'Collect and Process Memory' tab is designed for capturing and analyzing memory data, a crucial aspect of digital forensics. This tab integrates powerful tools like WinPmem for memory capture and Volatility 3 for in-depth memory analysis. Key functionalities include:

MEMORY CAPTURE WITH WINPMEM:
- Initiate memory capture using WinPmem, known for its reliability and speed in acquiring memory images.
- Set the path to the WinPmem executable and start the memory capture process with ease.

CONFIGURE AND PROCESS WITH VOLATILITY 3:
- Select a captured memory file and specify the operating system type for accurate parsing.
- Choose from a wide range of Volatility plugins for targeted analysis, or opt for 'All Plugins' for a comprehensive examination.
- Define the path to the Volatility executable, enabling the tool to process the memory image.

USER INTERFACE AND FEEDBACK:
- The user-friendly interface guides you through the process of memory capture and analysis.

This tab is an essential resource for forensic analysts, providing the necessary tools to capture and analyze memory data effectively. It simplifies the complexities of memory forensics, making it accessible for in-depth investigations and rapid incident response.
"@
    "Collect System Artifacts" = @"
The 'Collect System Artifacts' tab offers a streamlined approach for gathering crucial system data, essential for forensic analysis. This tab incorporates Velociraptor, a powerful tool for rapid artifact collection:

INITIAL SETUP AND VOLUME SELECTION:
- Start by selecting a volume from the 'Volumes' dropdown list.
- The interface guides you to select one or more targets for data collection.

TARGET SELECTION AND CUSTOMIZATION:
- Choose from a comprehensive list of targets, each representing specific system artifacts or data sets.
- 'Reset to Defaults' option quickly reverts your selection to the program's default settings, focusing on key artifacts with BasicCollection.

ADVANCED OPTIONS AND SHADOW COPIES:
- Opt to include Volume Shadow Copies in the collection, expanding the range of recoverable data.
- Customize your collection process by selecting specific artifacts or areas of interest.

VELOCIRAPTOR INTEGRATION:
- Utilize Velociraptor for efficient and precise artifact collection.
- Specify the path to the Velociraptor executable, ensuring seamless integration with the tool.
- 'Collect with Velociraptor' initiates the collection process, leveraging Velociraptor's capabilities for thorough and rapid artifact gathering.

This tab is an invaluable resource for forensic analysts, enabling efficient and targeted collection of system artifacts. It simplifies the collection process, making it accessible and effective for in-depth forensic investigations.
"@
    "Evidence Sync" = @"
The 'Evidence Sync' tab is designed to facilitate the seamless uploading of folders or files to various data analysis and visualization platforms, enhancing forensic investigations and cybersecurity analytics. This tab integrates with advanced tools like Timesketch, Splunk, and Elastic, offering:

FILE AND FOLDER SYNC
- Choose specific files or folders for upload directly from the case directory. The interface allows for both manual selection and quick sync of predefined folders.

PLATFORM INTEGRATION:
- Start by selecting tool to sync with from the 'Sync Tool Name' dropdown list.

CONFIGURABLE PARAMETERS:
- Customize sync parameters for each platform, tailoring the upload process to the specific requirements of your investigation.

CONNECTION TESTING AND INDEX MANAGEMENT:
- Test connectivity to the chosen platform and manage index settings, ensuring efficient data synchronization and organization.

TIMESKETCH SPECIFICS:
- For Timesketch integration, configure server URLs, user credentials, and sketch details to synchronize data effectively, creating comprehensive timelines for investigative analysis.
"@
    "Threat Scanners" = @"
The "Threat Scanners" tab is an integral part of the GUI application, designed to offer robust and versatile scanning capabilities for detecting various types of malware and vulnerabilities. This tab caters to both basic and advanced users, providing tools like ClamAV and Loki for comprehensive scanning:

FLEXIBLE FILE AND FOLDER SCANNING:
- Users can select any file or folder for scanning, making it highly adaptable to different scenarios.
- The intuitive interface simplifies the selection process, ensuring a user-friendly experience.

INTEGRATION WITH CLAMAV AND LOKI:
- ClamAV: A widely-used open-source antivirus toolkit, effective for detecting viruses, trojans, and other malicious entities.
- Loki: A specialized scanner for indicators of compromise (IoCs), focusing on pattern matching to identify malware and hacker tools.

CUSTOMIZABLE SCANNING OPTIONS:
- ClamAV and Loki offer different strengths, with ClamAV providing traditional antivirus scanning and Loki offering targeted IoC scanning.
- Users can tailor scans according to their needs, choosing from options like process scanning, intense scanning, and vulnerability checks.

SEAMLESS TOOL MANAGEMENT:
- Both tools can be easily downloaded or updated directly from the "Tools Management" tab, ensuring users always have access to the latest versions.
- The application handles all aspects of setup and configuration, streamlining the scanning process.

OUTPUT AND REPORTING:
- Scan results are conveniently stored in the "ProcessedArtifacts" folder within the case directory.
- Users are informed of the scanning progress and outcomes through real-time logging in the interface.
"@
}
$TabsSelectionComboBox.Add_SelectionChanged({
    param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
    $selectedItem = $sender.SelectedItem.Content
    # Update the TabsDescriptionTextBox based on the selected item
    $TabsDescriptionTextBox.Text = $tabDescriptions[$selectedItem]
})
$window.Add_Loaded({
    $TabsSelectionComboBox = $window.FindName("TabsSelectionComboBox")
    $TabsSelectionComboBox.SelectedItem = $TabsSelectionComboBox.Items | Where-Object { $_.Content -eq "Home" }
})
####End Home tab Event Handlers####

####Case Management event handlers####
$caseNameTextBox = $window.FindName("CaseNameTextBox")
$createCaseButton = $window.FindName("CreateCaseButton")
$existingCasesComboBox = $window.FindName("ExistingCasesComboBox")
$openCaseButton = $window.FindName("OpenCaseButton")
$removeCaseButton = $window.FindName("RemoveCaseButton")
$importCaseButton = $window.FindName("ImportCaseButton")
$CasesDataGrid = $window.FindName("CasesDataGrid")
$createCaseButton.Add_Click({ CreateCaseButton_Click })
$openCaseButton.Add_Click({ OpenCaseButton_Click })
$removeCaseButton.Add_Click({ RemoveCaseButton_Click })
$importCaseButton.Add_Click({ ImportCaseButton_Click })
$casesDataGrid.Add_MouseDoubleClick({
    # Get the selected row
    $selectedCase = $casesDataGrid.SelectedItem

    if ($selectedCase -ne $null) {
        # Retrieve case details
        $selectedCaseName = $selectedCase.Name
        $CaseDirectory = $selectedCase.Path.Trim()

        if (Test-CaseRecordIsUsable -CaseName $selectedCaseName -CasePath $CaseDirectory) {
            # Call Open-Case with the case name
            Open-Case -CaseName $selectedCaseName -CasePath $CaseDirectory
        } else {
            # Show an error message if the case is incomplete or path is invalid
            [System.Windows.MessageBox]::Show("Case '$selectedCaseName' is missing required files (`"_ECHO.$selectedCaseName.json`" and/or `"$selectedCaseName.log`") or has an invalid path.", "Error", 'OK', 'Error')
        }
    } else {
        # Show a warning if no case is selected
        [System.Windows.MessageBox]::Show("Please select a case from the list.", "Warning", 'OK', 'Warning')
    }
})
####End Case Management event handlers####

####Packet Capture event handlers####
$startPacketCaptureButton = $window.FindName("StartPacketCaptureButton")
$extractCabFileButton = $window.FindName("ExtractCabFileButton")
$convertETL2PCAPButton = $window.FindName("ConvertETL2PCAPButton")
$startPacketCaptureButton.Add_Click({ StartPacketCaptureButton_Click })
$extractCabFileButton.Add_Click({ ExtractCabFileButton_Click })
$convertETL2PCAPButton.Add_Click({ ConvertETL2PCAPButton_Click })
$tabCollectPacketCapture = $window.FindName("TabCollectPacketCapture")
$tabCollectPacketCapture.Add_GotFocus({ OnTabCollectPacketCapture_GotFocus })
$CaptureTimeTextBox = $window.FindName("CaptureTimeTextBox")
$CaptureTimeTextBox.Text = "5"  
$etl2PcapngPathTextBox = $window.FindName("Etl2PcapngPathTextBox")
$browseEtl2PcapngPathButton = $window.FindName("BrowseEtl2PcapngPathButton")
$convertETL2PCAPButton = $window.FindName("ConvertETL2PCAPButton")
$convertETL2PCAPButton.IsEnabled = $false
$browseEtl2PcapngPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Executable files (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $etl2PcapngPathTextBox.Text = $dialog.FileName
    }
})
$etl2PcapngPathTextBox.Add_TextChanged({
    # Validate the path before enabling the Convert button
    $isValidPath = -not [string]::IsNullOrEmpty($etl2PcapngPathTextBox.Text) -and 
                   $etl2PcapngPathTextBox.Text.EndsWith("etl2pcapng.exe") -and 
                   (Test-Path $etl2PcapngPathTextBox.Text)
    $convertETL2PCAPButton.IsEnabled = $isValidPath
})
####END Packet Capture event handlers####

####System Artifacts Collection event handlers####
$TabCollectSystemArtifacts = $window.FindName("TabCollectSystemArtifacts")
$TabCollectSystemArtifacts.Add_GotFocus({ OnTabCollectSystemArtifacts_GotFocus })
$DisplayVolumesButton = $window.FindName("DisplayVolumesButton")
$VolumeComboBox = $window.FindName("VolumeComboBox")
$volumeShadowCopyCheckbox = $window.FindName("VolumeShadowCopyCheckbox")
$CheckBoxListBox = $window.FindName("CheckBoxListBox")
$resetDefaultsButton = $window.FindName("ResetDefaultsButton")
$collectWithVelociraptorButton = $window.FindName("CollectWithVelociraptorButton")
$velociraptorPathTextBox = $window.FindName("velociraptorPathTextBox")
$BrowseVelociraptorPathButton = $window.FindName("BrowseVelociraptorPathButton")
$BrowseVelociraptorPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Velociraptor files (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $velociraptorPathTextBox.Text = $dialog.FileName
    }
})
$velociraptorPathTextBox.Add_TextChanged({
    $isValidPath = -not [string]::IsNullOrEmpty($velociraptorPathTextBox.Text) -and 
                   ($velociraptorPathTextBox.Text -match "Velociraptor.*\.exe$") -and 
                   (Test-Path $velociraptorPathTextBox.Text)
    $collectWithVelociraptorButton.IsEnabled = $isValidPath
})
$DisplayVolumesButton.Add_Click({
	Display-Volumes
	Show-Selection1
})
$volumeShadowCopyCheckbox.Add_Checked({
    if ("--args VSSAnalysis=Y" -notin $Global:Parameters) {
        $Global:Parameters += "--args VSSAnalysis=Y"
    }
    Show-Selection1
})
$volumeShadowCopyCheckbox.Add_Unchecked({
    $Global:Parameters = $Global:Parameters.Where({$_ -ne "--args VSSAnalysis=Y"})
    Show-Selection1
})
$resetDefaultsButton.Add_Click({
    Select-SANSTriageDefault
})
$collectWithVelociraptorButton.IsEnabled = $false
$CurrentSelectionText = $window.FindName("CurrentSelectionText")
$volumeComboBox.Add_SelectionChanged({
    $Global:SelectedVolume = $VolumeComboBox.SelectedItem.Tag
    $isValidPath = -not [string]::IsNullOrEmpty($velociraptorPathTextBox.Text) -and (Test-Path $velociraptorPathTextBox.Text)
    $collectWithVelociraptorButton.IsEnabled = ($Global:SelectedVolume -and $isValidPath)
    Show-Selection1
})
$collectWithVelociraptorButton.Add_Click({
    Collect-Velociraptor
})
$items = @("_BasicCollection", "_KapeTriage", "_SANS_Triage", "_Boot", "_J", "_LogFile", "_MFT", "_MFTMirr", "_SDS", "_T", "1Password", "4KVideoDownloader", "AVG", "AceText", "AcronisTrueImage", "ActiveDirectoryNTDS", "ActiveDirectorySysvol", "AgentRansack", "Amcache", "Ammyy", "Antivirus", "AnyDesk", "ApacheAccessLog", "AppCompatPCA", "AppData", "AppXPackages", "ApplicationEvents", "AsperaConnect", "AssetAdvisorLog", "AteraAgent", "Avast", "AviraAVLogs", "BCD", "BITS", "BitTorrent", "Bitdefender", "BoxDrive_Metadata", "BoxDrive_UserFiles", "BraveBrowser", "BrowserCache", "CertUtil", "Chrome", "ChromeExtensions", "ChromeFileSystem", "CiscoJabber", "ClipboardMaster", "CloudStorage_All", "CloudStorage_Metadata", "CloudStorage_OneDriveExplorer", "CombinedLogs", "Combofix", "ConfluenceLogs", "Cybereason", "Cylance", "DC__", "DWAgent", "Debian", "DirectoryOpus", "DirectoryTraversal_AudioFiles", "DirectoryTraversal_ExcelDocuments", "DirectoryTraversal_PDFDocuments", "DirectoryTraversal_PictureFiles", "DirectoryTraversal_SQLiteDatabases", "DirectoryTraversal_VideoFiles", "DirectoryTraversal_WildCardExample", "DirectoryTraversal_WordDocuments", "Discord", "DoubleCommander", "Drivers", "Dropbox_Metadata", "Dropbox_UserFiles", "EFCommander", "ESET", "Edge", "EdgeChromium", "Emsisoft", "EncapsulationLogging", "EventLogs_RDP", "EventLogs", "EventTraceLogs", "EventTranscriptDB", "Evernote", "Everything__VoidTools_", "EvidenceOfExecution", "Exchange", "ExchangeClientAccess", "ExchangeCve_2021_26855", "ExchangeTransport", "FSecure", "FTPClients", "Fences", "FileExplorerReplacements", "FileSystem", "FileZillaClient", "FileZillaServer", "Firefox", "FreeCommander", "FreeDownloadManager", "FreeFileSync", "Freenet", "FrostWire", "Gigatribe", "GoogleDriveBackupSync_UserFiles", "GoogleDrive_Metadata", "GoogleEarth", "GroupPolicy", "HeidiSQL", "HexChat", "HitmanPro", "IISConfiguration", "IISLogFiles", "IRCClients", "IceChat", "InternetExplorer", "IrfanView", "JDownloader2", "JavaWebCache", "Kali", "Kaseya", "Keepass", "KeepassXC", "LNKFilesAndJumpLists", "LinuxOnWindowsProfileFiles", "LiveUserFiles", "LogFiles", "LogMeIn", "MOF", "MSSQLErrorLog", "MacriumReflect", "Malwarebytes", "ManageEngineLogs", "Mattermost", "McAfee", "McAfee_ePO", "MediaMonkey", "MemoryFiles", "MessagingClients", "MicrosoftOfficeBackstage", "MicrosoftOneNote", "MicrosoftStickyNotes", "MicrosoftTeams", "MicrosoftToDo", "MidnightCommander", "MiniTimelineCollection", "MultiCommander", "NETCLRUsageLogs", "NGINXLogs", "NZBGet", "Nessus", "NewsbinPro", "Newsleecher", "Nicotine__", "Notepad__", "OfficeAutosave", "OfficeDiagnostics", "OfficeDocumentCache", "OneCommander", "OneDrive_Metadata", "OneDrive_UserFiles", "OpenSSHClient", "OpenSSHServer", "OpenVPNClient", "Opera", "OutlookPSTOST", "P2PClients", "PeaZip", "PowerShell7Config", "PowerShellConsole", "PowerShellTranscripts", "Prefetch", "ProtonVPN", "PuffinSecureBrowser", "PushNotification", "Q_Dir", "QFinderPro__QNAP_", "RDPCache", "RDPLogs", "Radmin", "RecentFileCache", "RecycleBin", "RecycleBin_DataFiles", "RecycleBin_InfoFiles", "RegistryHives", "RegistryHivesOther", "RegistryHivesSystem", "RegistryHivesUser", "RemoteAdmin", "RemoteUtilities_app", "RoamingProfile", "RogueKiller", "RustDesk", "SABnbzd", "SDB", "SOFELK", "SQLiteDatabases", "SRUM", "SUM", "SUPERAntiSpyware", "SUSELinuxEnterpriseServer", "ScheduledTasks", "ScreenConnect", "SecureAge", "SentinelOne", "ServerTriage", "ShareX", "Shareaza", "SiemensTIA", "Signal", "SignatureCatalog", "Skype", "Slack", "Snagit", "SnipAndSketch", "Sophos", "Soulseek", "SpeedCommander", "Splashtop", "StartupFolders", "StartupInfo", "Steam", "SublimeText", "SugarSync", "SumatraPDF", "SupremoRemoteDesktop", "Symantec_AV_Logs", "Syscache", "TablacusExplorer", "TeamViewerLogs", "Telegram", "TeraCopy", "ThumbCache", "Thunderbird", "TorrentClients", "Torrents", "TotalAV", "TotalCommander", "TreeSize", "TrendMicro", "USBDetective", "USBDevicesLogs", "Ubuntu", "Ultraviewer", "Usenet", "UsenetClients", "VIPRE", "VLC_Media_Player", "VMware", "VMwareInventory", "VMwareMemory", "VNCLogs", "Viber", "VirtualBox", "VirtualBoxConfig", "VirtualBoxLogs", "VirtualBoxMemory", "VirtualDisks", "WBEM", "WER", "WSL", "WebBrowsers", "WebServers", "Webroot", "WhatsApp", "WinDefendDetectionHist", "WinSCP", "WindowsDefender", "WindowsFirewall", "WindowsHello", "WindowsIndexSearch", "WindowsNetwork", "WindowsNotificationsDB", "WindowsOSUpgradeArtifacts", "WindowsPowerDiagnostics", "WindowsServerDNSAndDHCP", "WindowsSubsystemforAndroid", "WindowsTelemetryDiagnosticsLegacy", "WindowsTimeline", "WindowsYourPhone", "XPRestorePoints", "XYplorer", "ZohoAssist", "Zoom", "iTunesBackup", "mIRC", "mRemoteNG", "openSUSE", "pCloudDatabase", "qBittorrent", "uTorrent")
foreach ($item in $items) {
    $checkBox = New-Object System.Windows.Controls.CheckBox
    $checkBox.Content = $item
    $checkBox.Add_Click({ CheckBox_StateChanged }) # Add event handler
	$null = $CheckBoxListBox.Items.Add($checkBox)

    # Set default selection
    if ($item -eq "_SANS_Triage") {
        $checkBox.IsChecked = $true
    }
}
Update-Parameters
####END System Artifacts Collection event handlers####

#####Disk Imaging event handlers####
$TabCollectDiskImagewithFTK = $window.FindName("TabCollectDiskImagewithFTK")
$TabCollectDiskImagewithFTK.Add_GotFocus({ OnTabCollectDiskImage_GotFocus })
$DisplayDrivesButton = $window.FindName("DisplayDrivesButton")
$CurrentFTKSelectionText = $window.FindName("CurrentFTKSelectionText")
$FTKPathTextBox = $window.FindName("FTKPathTextBox")
$BrowseFTKPathButton = $window.FindName("BrowseFTKPathButton")
$CollectDrivesButton = $window.FindName("CollectDrivesButton")
$DriveCheckBoxListBox = $window.FindName("DriveCheckBoxListBox")
$BrowseFTKPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Executable files (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $FTKPathTextBox.Text = $dialog.FileName
        $CollectDrivesButton.IsEnabled = Test-Path $dialog.FileName
    }
	Update-CollectDrivesButtonState
})
$DisplayDrivesButton.Add_Click({
    Display-Drives
})
$CollectDrivesButton.Add_Click({
    Collect-Drives
})
foreach ($drive in $connectedDrives) {
    $checkBox = New-Object System.Windows.Controls.CheckBox
    $checkBox.Content = $drive
    $checkBox.Add_Click({ FTKCheckBox_StateChanged })
    $null = $DriveCheckBoxListBox.Items.Add($checkBox)
}
####End Disk Imaging event handlers####

####Memory Capture event handlers####
$TabCollectAndProcessMemory = $window.FindName("TabCollectAndProcessMemory")
$TabCollectAndProcessMemory.Add_GotFocus({ OnTabCollectMemory_GotFocus })
$MemoryCaptureTextBox = $window.FindName("MemoryCaptureTextBox")
$StartMemoryCaptureButton = $window.FindName("StartMemoryCaptureButton")
$StartMemoryCaptureButton.Add_Click({ StartMemoryCaptureButton_Click })
$WinpmemPathTextBox = $window.FindName("WinpmemPathTextBox")
$BrowseWimpmemPathButton = $window.FindName("BrowseWimpmemPathButton")
$MemoryPathTextBox = $window.FindName("MemoryPathTextBox")
$BrowseMemoryPathButton = $window.FindName("BrowseMemoryPathButton")
$ProcessVolatilityButton = $window.FindName("ProcessVolatilityButton")
$ProcessVolatilityButton.Add_Click({ ProcessVolatilityButton_Click })
$BrowseVolatilityPathButton = $window.FindName("BrowseVolatilityPathButton")
$VolatilityPathTextBox = $window.FindName("VolatilityPathTextBox")
$OSSelectionComboBox = $window.FindName("OSSelectionComboBox")
$PluginsComboBox = $window.FindName("PluginsComboBox")
$BrowseWimpmemPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Winpmem files (*.exe)|*.exe" 
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $WinpmemPathTextBox.Text = $dialog.FileName
    }
})

$WinpmemPathTextBox.Add_TextChanged({
    $isValidPath = -not [string]::IsNullOrEmpty($WinpmemPathTextBox.Text) -and 
                   ($WinpmemPathTextBox.Text -match "winpmem.*\.exe$") -and 
                   (Test-Path $WinpmemPathTextBox.Text)
    $StartMemoryCaptureButton.IsEnabled = $isValidPath
})

$BrowseMemoryPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Raw memory file (*.raw)|*.raw"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $MemoryPathTextBox.Text = $dialog.FileName
		$ProcessVolatilityButton.IsEnabled = Test-Path $dialog.FileName
    }
})

$BrowseVolatilityPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "vol.py file (*.py)|*.py"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $VolatilityPathTextBox.Text = $dialog.FileName
        $ProcessVolatilityButton.IsEnabled = Test-Path $dialog.FileName
    }
})

$VolatilityPathTextBox.Add_TextChanged({
    # Validate the path before enabling the Convert button
    $isValidPath = -not [string]::IsNullOrEmpty($VolatilityPathTextBox.Text) -and 
                   $VolatilityPathTextBox.Text.EndsWith("vol.py") -and 
                   (Test-Path $VolatilityPathTextBox.Text)
    $ProcessVolatilityButton.IsEnabled = $isValidPath
})
$osselections = @("Windows", "Linux", "Mac")
foreach	($osselection in $osselections) {
	$null = $OSSelectionComboBox.Items.Add($osselection)
}
$OSSelectionComboBox.Add_SelectionChanged({
    $PluginsComboBox.Items.Clear()
    $PluginsComboBox.Items.Add("All Plugins") # Default option

    $selectedOs = $OSSelectionComboBox.SelectedItem
    $plugins = switch ($selectedOs) {
        "Windows" { $Global:windowsPlugins.Keys }
        "Linux"   { $Global:linuxPlugins.Keys }
        "Mac"     { $Global:macPlugins.Keys }
    }

    foreach ($plugin in $plugins) {
        $PluginsComboBox.Items.Add($plugin)
    }

    $PluginsComboBox.SelectedIndex = 0
})
####END Memory Capture event handlers####

####System processing event handlers####
$TabProcessSystemArtifacts = $window.FindName("TabProcessSystemArtifacts")
$TabProcessSystemArtifacts.AddHandler(
    [System.Windows.Controls.Primitives.Selector]::SelectedEvent,
    [System.Windows.RoutedEventHandler]{
        param($sender, $e)
        if (($e.OriginalSource -eq $TabProcessSystemArtifacts) -and $TabProcessSystemArtifacts.IsSelected) {
            OnTabProcessArtifacts_GotFocus
        }
    }
)
$ArtifactProcessingPathTextBox = $window.FindName("ArtifactProcessingPathTextBox")
$ArtifactProcessingPathButton = $window.FindName("ArtifactProcessingPathButton")
$ProcessBulkExtractorButton = $window.FindName("ProcessBulkExtractorButton")
$ProcessBulkExtractorButton.Add_Click({ ProcessBulkExtractorButton_Click })
$BulkExtractorPathTextBox = $window.FindName("BulkExtractorPathTextBox")
$BrowseBulkExtractorPathButton = $window.FindName("BrowseBulkExtractorPathButton")
$ProcessZimmermanButton = $window.FindName("ProcessZimmermanButton")
$ProcessZimmermanButton.Add_Click({ ProcessZimmermanButton_Click })
$ZtoolsComboBox = $window.FindName("ZtoolsComboBox")
$ZimmermanPathTextBox = $window.FindName("ZimmermanPathTextBox")
$BrowseZimmermanPathButton = $window.FindName("BrowseZimmermanPathButton")
$ProcessPlasoButton = $window.FindName("ProcessPlasoButton")
$ProcessPlasoButton.Add_Click({ ProcessPlasoButton_Click })
$PlasoPathTextBox = $window.FindName("PlasoPathTextBox")
$BrowsePlasoPathButton = $window.FindName("BrowsePlasoPathButton")
$PlasoDateRangeCheckBox = $window.FindName("PlasoDateRangeCheckBox")
$PlasoStartDatePicker = $window.FindName("PlasoStartDatePicker")
$PlasoEndDatePicker = $window.FindName("PlasoEndDatePicker")
$PsortOnlyCheckBox = $window.FindName("PsortOnlyCheckBox")
$Process7zipButton = $window.FindName("Process7zipButton")
$Process7zipButton.Add_Click({ ExtractArchives_Click })
$SevenzipPathTextBox = $window.FindName("SevenzipPathTextBox")
$Browse7zipPathButton = $window.FindName("Browse7zipPathButton")
$GeoLocateButton = $window.FindName("GeoLocateButton")
$GeoLocateButton.Add_Click({ GeoLocateButton_Click })
$GeoLite2CityDBPathTextBox = $window.FindName("GeoLite2CityDBPathTextBox")
$BrowseGeoLite2CityDBPathButton = $window.FindName("BrowseGeoLite2CityDBPathButton")
$CheckVirusTotal = $window.FindName("CheckVirusTotal")
$ArtifactProcessingPathTextBox.Add_TextChanged({ UpdateProcessingButtonsStatus })
$BulkExtractorPathTextBox.Add_TextChanged({ UpdateProcessingButtonsStatus })
$ZimmermanPathTextBox.Add_TextChanged({ UpdateProcessingButtonsStatus })
$UpdateZimmermanButton = $window.FindName("UpdateZimmermanButton")
$UpdateZimmermanButton.Add_Click({UpdateZimmermanButton_Click })

$PlasoPathTextBox.Add_TextChanged({ UpdateProcessingButtonsStatus })
$GeoLite2CityDBPathTextBox.Add_TextChanged({ UpdateProcessingButtonsStatus })
$SevenzipPathTextBox.Add_TextChanged({ UpdateProcessingButtonsStatus })

$ProcessChainsawButton = $window.FindName("ProcessChainsawButton")
$ChainsawPathTextBox = $window.FindName("ChainsawPathTextBox")
$BrowseChainsawPathButton = $window.FindName("BrowseChainsawPathButton")
$ChainsawJson = $window.FindName("ChainsawJson")
$ChawnsawTextBlock = $window.FindName("ChawnsawTextBlock")
$ProcessChainsawButton.Add_Click({ ProcessChainsawButton_Click })


$ArtifactProcessingPathButton.Add_Click({
    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Input Type'
    $form.Size = New-Object System.Drawing.Size(400, 200)
    $form.StartPosition = 'CenterScreen'
    # Add label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Choose a File or Folder to process'
    $label.Location = New-Object System.Drawing.Point(50, 20)
    $label.Size = New-Object System.Drawing.Size(300, 30)
    $form.Controls.Add($label)
    # Add File button
    $fileButton = New-Object System.Windows.Forms.Button
    $fileButton.Text = 'File'
    $fileButton.Location = New-Object System.Drawing.Point(100, 70)
    $fileButton.Size = New-Object System.Drawing.Size(75, 23)
    $fileButton.Add_Click({
        $form.Tag = 'File'
        $form.Close()
    })
    $form.Controls.Add($fileButton)
    # Add Folder button
    $folderButton = New-Object System.Windows.Forms.Button
    $folderButton.Text = 'Folder'
    $folderButton.Location = New-Object System.Drawing.Point(200, 70)
    $folderButton.Size = New-Object System.Drawing.Size(75, 23)
    $folderButton.Add_Click({
        $form.Tag = 'Folder'
        $form.Close()
    })
    $form.Controls.Add($folderButton)
    # Show form
    $form.ShowDialog() | Out-Null
    # Process the selection
    if ($form.Tag -eq 'File') {
        $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $fileDialog.Multiselect = $false
        if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $ArtifactProcessingPathTextBox.Text = $fileDialog.FileName
        }
    } elseif ($form.Tag -eq 'Folder') {
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $ArtifactProcessingPathTextBox.Text = $folderDialog.SelectedPath
        }
    }
})
$BrowseBulkExtractorPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "bulk_extractor64.exe file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $BulkExtractorPathTextBox.Text = $dialog.FileName
    }
})
$BrowseZimmermanPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Get-ZimmermanTools.ps1 file (*.ps1)|*.ps1"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $ZimmermanPathTextBox.Text = $dialog.FileName
    }
})
$BrowsePlasoPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "log2timeline.py file (*.py)|*.py"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $PlasoPathTextBox.Text = $dialog.FileName
    }
})
$Browse7zipPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "7za.exe file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $SevenzipPathTextBox.Text = $dialog.FileName
    }
})
$BrowseGeoLite2CityDBPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "GeoLite2-City.mmdb file (*.mmdb)|*.mmdb"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $GeoLite2CityDBPathTextBox.Text = $dialog.FileName
    }
})
$BrowseChainsawPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "chainsaw file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $ChainsawPathTextBox.Text = $dialog.FileName
    }
})


$modulesList = @('All Modules', 'AmcacheParser', 'AppCompatCacheParser', 'EvtxECmd', 'JLECmd', 'LECmd', 'MFTECmd', 'PECmd', 'RBCmd', 'RecentFileCacheParser', 'RECmd', 'SBECmd', 'SQLECmd', 'SrumECmd', 'SumECmd', 'WxTCmd')
$ZtoolsComboBox.ItemsSource = $modulesList
$ZtoolsComboBox.SelectedItem = 'All Modules'
$PlasoDateRangeCheckBox.Add_Checked({
    $PlasoStartDatePicker.IsEnabled = $true
    $PlasoEndDatePicker.IsEnabled = $true
})
$PlasoDateRangeCheckBox.Add_Unchecked({
    $PlasoStartDatePicker.IsEnabled = $false
    $PlasoEndDatePicker.IsEnabled = $false
})

$PlasoStartDate = $window.FindName("PlasoStartDate")
$PlasoEndDate = $window.FindName("PlasoEndDate")
$ProcessToolLocation = $window.FindName("ProcessToolLocation")
$ProcessToolExtraArguments = $window.FindName("ProcessToolExtraArguments")
$ProcessingToolComboBox = $window.FindName("ProcessingToolComboBox")

##Hayabusa
$ProcessHayabusaButton = $window.FindName("ProcessHayabusaButton")
$ProcessHayabusaButton.Add_Click({ProcessHayabusaButton_Click })
$HayabusaPathTextBox = $window.FindName("HayabusaPathTextBox")
$BrowseHayabusaPathButton = $window.FindName("BrowseHayabusaPathButton")
$HayabusaDateRangeCheckBox = $window.FindName("HayabusaDateRangeCheckBox")
$HayabusaStartDate = $window.FindName("HayabusaStartDate")
$HayabusaStartDatePicker = $window.FindName("HayabusaStartDatePicker")
$HayabusaEndDate = $window.FindName("HayabusaEndDate")
$HayabusaEndDatePicker = $window.FindName("HayabusaEndDatePicker")
$HayabusaGeoDBCheckBox = $window.FindName("HayabusaGeoDBCheckBox")
$HayabusaTextBlock = $window.FindName("HayabusaTextBlock")
$PlasoTextBlock = $window.FindName("PlasoTextBlock")
$sevenzipTextBlock = $window.FindName("sevenzipTextBlock")
$GeolocateTextBlock = $window.FindName("GeolocateTextBlock")
$ZimmermanTextBlock = $window.FindName("ZimmermanTextBlock")
$BulkTextBlock = $window.FindName("BulkTextBlock")

$HayabusaDateRangeCheckBox.Add_Checked({
    $HayabusaStartDatePicker.IsEnabled = $true
    $HayabusaEndDatePicker.IsEnabled = $true
})
$HayabusaDateRangeCheckBox.Add_Unchecked({
    $HayabusaStartDatePicker.IsEnabled = $false
    $HayabusaEndDatePicker.IsEnabled = $false
})
$BrowseHayabusaPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "hyabusa file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $PlasoPathTextBox.Text = $dialog.FileName
    }
})

##Zircolite
$ProcessZircoliteButton = $window.FindName("ProcessZircoliteButton")
$ProcessZircoliteButton.Add_Click({ProcessZircoliteButton_Click })
$ZircolitePathTextBox = $window.FindName("ZircolitePathTextBox")
$BrowseZircolitePathButton = $window.FindName("BrowseZircolitePathButton")
$ZircolitejsonCheckBox = $window.FindName("ZircolitejsonCheckBox")
$ZircoliteRules = $window.FindName("ZircoliteRules")
$ZircoliteRulesComboBox = $window.FindName("ZircoliteRulesComboBox")
$ZircoliteTemplates = $window.FindName("ZircoliteTemplates")
$ZircoliteTemplatesComboBox = $window.FindName("ZircoliteTemplatesComboBox")
$ZircoliteDateRangeCheckBox = $window.FindName("ZircoliteDateRangeCheckBox")
$ZircoliteStartDate = $window.FindName("ZircoliteStartDate")
$ZircoliteStartDatePicker = $window.FindName("ZircoliteStartDatePicker")
$ZircoliteEndDate = $window.FindName("ZircoliteEndDate")
$ZircoliteEndDatePicker = $window.FindName("ZircoliteEndDatePicker")
$ZircoliteTextBlock = $window.FindName("ZircoliteTextBlock")
$UpdateZircoliteButton = $window.FindName("UpdateZircoliteButton")
$UpdateZircoliteButton.Add_Click({UpdateZircoliteButton_Click })
$ZircolitepackageCheckBox = $window.FindName("ZircolitepackageCheckBox")
$ZircolitesysmonCheckBox = $window.FindName("ZircolitesysmonCheckBox")


$ZircoliteDateRangeCheckBox.Add_Checked({
    $ZircoliteStartDatePicker.IsEnabled = $true
    $ZircoliteEndDatePicker.IsEnabled = $true
})
$ZircoliteDateRangeCheckBox.Add_Unchecked({
    $ZircoliteStartDatePicker.IsEnabled = $false
    $ZircoliteEndDatePicker.IsEnabled = $false
})
$BrowseZircolitePathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "Zircolite file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $ZircolitePathTextBox.Text = $dialog.FileName
    }
})

$global:zirTemplatePaths = @{}
$ZircoliteTemplatesComboBox.Add_DropDownOpened({
    $ZircoliteTemplatesComboBox.Items.Clear()
    $defaultItem = "Default (None)"
    $ZircoliteTemplatesComboBox.Items.Add($defaultItem)
    $zircoliteDirectory = [System.IO.Path]::GetDirectoryName($ZircolitePathTextBox.Text)
    $templateDirectory = Join-Path -Path $zircoliteDirectory -ChildPath "templates"
    if (Test-Path -Path $templateDirectory) {
        $templateFiles = Get-ChildItem -Path $templateDirectory -Filter "*.tmpl" -File
        foreach ($templateFile in $templateFiles) {
            $templateName = $templateFile.Name
            $ZircoliteTemplatesComboBox.Items.Add($templateName)
            $global:zirTemplatePaths[$templateName] = $templateFile.FullName
        }
    }
    $ZircoliteTemplatesComboBox.SelectedItem = $defaultItem
})

$global:zirRulesPaths = @{}
$ZircoliteRulesComboBox.Add_DropDownOpened({
    $ZircoliteRulesComboBox.Items.Clear()
    $zircoliteDirectory = [System.IO.Path]::GetDirectoryName($ZircolitePathTextBox.Text)
    $ruleDirectory = Join-Path -Path $zircoliteDirectory -ChildPath "rules"
    if (Test-Path -Path $ruleDirectory) {
        $ruleFiles = Get-ChildItem -Path $ruleDirectory -Filter "*.json" -File
        foreach ($ruleFile in $ruleFiles) {
            $ruleName = $ruleFile.Name
            $ZircoliteRulesComboBox.Items.Add($ruleName)
            $global:zirRulesPaths[$ruleName] = $ruleFile.FullName
        }
    }
    $ZircoliteRulesComboBox.SelectedIndex = 0
})

$ZircoliteTemplatesComboBox.SelectedIndex = 0
$ZircoliteRulesComboBox.SelectedIndex = 0
$ZircolitePathTextBox.Add_TextChanged({
    UpdateProcessingButtonsStatus
})


##timeline
$ProcessTimelineArtifactsButton = $window.FindName("ProcessTimelineArtifactsButton")
$ProcessTimelineArtifactsButton.Add_Click({
    $selectedTools = @()
    if ($IncludeChainsaw.IsChecked) { $selectedTools += "Chainsaw" }
    if ($IncludeHayabusa.IsChecked) { $selectedTools += "Hayabusa" }
    if ($IncludeZimmerman.IsChecked) { $selectedTools += "Zimmermantools" }
    if ($IncludeZircolite.IsChecked) { $selectedTools += "Zircolite" }

    ProcessTimelineArtifactsButton_Click -SelectedTools $selectedTools
})


$IncludeChainsaw = $window.FindName("IncludeChainsaw")
$IncludeHayabusa = $window.FindName("IncludeHayabusa")
$IncludeZimmerman = $window.FindName("IncludeZimmerman")
$IncludeZircolite = $window.FindName("IncludeZircolite")
$TimelineDateIOCCheckBox = $window.FindName("TimelineDateIOCCheckBox")
$ExportTimelineArtifactsButton = $window.FindName("ExportTimelineArtifactsButton")
$ExportTimelineArtifactsButton.Add_Click({ ExportTimelineArtifactsButton_Click })

$TimelineDateRangeCheckBox = $window.FindName("TimelineDateRangeCheckBox")
$TimelineArtifactsStartDate = $window.FindName("TimelineArtifactsStartDate")
$TimelineArtifactsStartDatePicker = $window.FindName("TimelineArtifactsStartDatePicker")
$TimelineArtifactsEndDate = $window.FindName("TimelineArtifactsEndDate")
$TimelineArtifactsEndDatePicker = $window.FindName("TimelineArtifactsEndDatePicker")
$TimelineArtifactTextBlock = $window.FindName("TimelineArtifactTextBlock")
$sqlitePathTextBox = $window.FindName("sqlitePathTextBox")
$ArtifactProcessingInfoTextBlock = $window.FindName("ArtifactProcessingInfoTextBlock")
$ArtifactProcessingPathTextBlock = $window.FindName("ArtifactProcessingPathTextBlock")
$OpenCustomTimelineIOCsButton = $window.FindName("OpenCustomTimelineIOCsButton")
$OpenCustomTimelineIOCsButton.Add_Click({
    Start-Process $global:timelineIOCFilePath
})
$BrowsesqlitePathButton = $window.FindName("BrowsesqlitePathButton")

$BrowsesqlitePathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "System.Data.SQLite.dll file (System.Data.SQLite.dll)|System.Data.SQLite.dll"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $sqlitePathTextBox.Text = $dialog.FileName
    }
})

$TimelineDateRangeCheckBox.Add_Checked({
    $TimelineArtifactsEndDatePicker.IsEnabled = $true
    $TimelineArtifactsStartDatePicker.IsEnabled = $true
})
$TimelineDateRangeCheckBox.Add_Unchecked({
    $TimelineArtifactsEndDatePicker.IsEnabled = $false
    $TimelineArtifactsStartDatePicker.IsEnabled = $false
})

function Set-ProcessArtifactsStretchTextBoxWithBrowse {
    param(
        [object]$TextBoxControl,
        [object]$BrowseButtonControl,
        [double]$Left,
        [double]$Top,
        [double]$Right = 45
    )

    if ($TextBoxControl) {
        $TextBoxControl.HorizontalAlignment = 'Stretch'
        $TextBoxControl.Width = [double]::NaN
        $TextBoxControl.Margin = New-Object System.Windows.Thickness($Left, $Top, $Right, 0)
    }
    if ($BrowseButtonControl) {
        $BrowseButtonControl.HorizontalAlignment = 'Right'
        $BrowseButtonControl.Margin = New-Object System.Windows.Thickness(0, $Top, 10, 0)
    }
}

function Set-ProcessArtifactsFixedTextBoxWithBrowse {
    param(
        [object]$TextBoxControl,
        [object]$BrowseButtonControl,
        [double]$TextLeft,
        [double]$Top,
        [double]$TextWidth = 300,
        [double]$ButtonLeft = 475
    )

    if ($TextBoxControl) {
        $TextBoxControl.HorizontalAlignment = 'Left'
        $TextBoxControl.Width = $TextWidth
        $TextBoxControl.Margin = New-Object System.Windows.Thickness($TextLeft, $Top, 0, 0)
    }
    if ($BrowseButtonControl) {
        $BrowseButtonControl.HorizontalAlignment = 'Left'
        $BrowseButtonControl.Margin = New-Object System.Windows.Thickness($ButtonLeft, $Top, 0, 0)
    }
}

function Set-ProcessArtifactsResponsiveLayout {
    $sizeKey = "$($TabProcessSystemArtifacts.ActualWidth)x$($TabProcessSystemArtifacts.ActualHeight)"
    if ($script:lastProcessArtifactsLayoutSizeKey -eq $sizeKey) {
        return
    }
    $script:lastProcessArtifactsLayoutSizeKey = $sizeKey

    foreach ($headerBlock in @($ArtifactProcessingInfoTextBlock, $ArtifactProcessingPathTextBlock)) {
        if ($headerBlock) {
            $headerBlock.HorizontalAlignment = 'Stretch'
            $headerBlock.Width = [double]::NaN
            $headerBlock.Margin = New-Object System.Windows.Thickness($headerBlock.Margin.Left, $headerBlock.Margin.Top, 10, 0)
        }
    }
    if ($ProcessToolLocation) {
        $ProcessToolLocation.HorizontalAlignment = 'Left'
        $ProcessToolLocation.Width = 330
        $ProcessToolLocation.Margin = New-Object System.Windows.Thickness(170, 155, 0, 0)
    }
    if ($ProcessToolExtraArguments) {
        $ProcessToolExtraArguments.HorizontalAlignment = 'Left'
        $ProcessToolExtraArguments.Width = 220
        $ProcessToolExtraArguments.Margin = New-Object System.Windows.Thickness(510, 155, 0, 0)
    }

    Set-ProcessArtifactsStretchTextBoxWithBrowse -TextBoxControl $ArtifactProcessingPathTextBox -BrowseButtonControl $ArtifactProcessingPathButton -Left 10 -Top 65
    foreach ($toolPathControlPair in @(
        @($BulkExtractorPathTextBox, $BrowseBulkExtractorPathButton),
        @($ZimmermanPathTextBox, $BrowseZimmermanPathButton),
        @($PlasoPathTextBox, $BrowsePlasoPathButton),
        @($SevenzipPathTextBox, $Browse7zipPathButton),
        @($GeoLite2CityDBPathTextBox, $BrowseGeoLite2CityDBPathButton),
        @($ChainsawPathTextBox, $BrowseChainsawPathButton),
        @($HayabusaPathTextBox, $BrowseHayabusaPathButton),
        @($ZircolitePathTextBox, $BrowseZircolitePathButton),
        @($sqlitePathTextBox, $BrowsesqlitePathButton)
    )) {
        Set-ProcessArtifactsFixedTextBoxWithBrowse -TextBoxControl $toolPathControlPair[0] -BrowseButtonControl $toolPathControlPair[1] -TextLeft 170 -Top 175
    }

    if ($ProcessSystemTextBox) {
        $ProcessSystemTextBox.HorizontalAlignment = 'Stretch'
        $ProcessSystemTextBox.Width = [double]::NaN
        $ProcessSystemTextBox.Margin = New-Object System.Windows.Thickness(10, 0, 10, 10)
    }
}

Set-ProcessArtifactsResponsiveLayout
$TabProcessSystemArtifacts.Add_SizeChanged({ Set-ProcessArtifactsResponsiveLayout })

# processingtools controls
function Set-ProcessingControlVisibility {
    param(
        [object[]]$Controls,
        [string]$Visibility
    )

    foreach ($control in $Controls) {
        if ($null -ne $control) {
            $control.Visibility = $Visibility
        }
    }
}

$processingToolControlSets = @{
    "BulkExtractor" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $ProcessBulkExtractorButton, $BulkExtractorPathTextBox, $BrowseBulkExtractorPathButton, $BulkTextBlock
    )
    "Chainsaw" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $ProcessChainsawButton, $ChainsawPathTextBox, $BrowseChainsawPathButton, $ChainsawJson, $ChawnsawTextBlock
    )
    "Zimmerman Tools" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $ProcessZimmermanButton, $ZtoolsComboBox, $ZimmermanPathTextBox, $BrowseZimmermanPathButton, $UpdateZimmermanButton, $ZimmermanTextBlock
    )
    "Extract Archives" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $Process7zipButton, $SevenzipPathTextBox, $Browse7zipPathButton, $sevenzipTextBlock
    )
    "Geolocate IPs" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $GeoLocateButton, $GeoLite2CityDBPathTextBox, $BrowseGeoLite2CityDBPathButton, $CheckVirusTotal, $GeolocateTextBlock
    )
    "Hayabusa" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $ProcessHayabusaButton, $HayabusaPathTextBox, $BrowseHayabusaPathButton,
        $HayabusaDateRangeCheckBox, $HayabusaStartDate, $HayabusaStartDatePicker, $HayabusaEndDate, $HayabusaEndDatePicker,
        $HayabusaGeoDBCheckBox, $HayabusaTextBlock
    )
    "Plaso Timeline" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $ProcessPlasoButton, $PlasoPathTextBox, $BrowsePlasoPathButton,
        $PlasoDateRangeCheckBox, $PlasoStartDate, $PlasoStartDatePicker, $PlasoEndDate, $PlasoEndDatePicker,
        $PsortOnlyCheckBox, $PlasoTextBlock
    )
    "Zircolite" = @(
        $ProcessToolLocation, $ProcessToolExtraArguments,
        $ProcessZircoliteButton, $ZircolitePathTextBox, $BrowseZircolitePathButton,
        $ZircolitejsonCheckBox, $ZircoliteRules, $ZircoliteRulesComboBox, $ZircoliteTemplates, $ZircoliteTemplatesComboBox,
        $ZircoliteDateRangeCheckBox, $ZircoliteStartDate, $ZircoliteStartDatePicker, $ZircoliteEndDate, $ZircoliteEndDatePicker,
        $UpdateZircoliteButton, $ZircolitepackageCheckBox, $ZircolitesysmonCheckBox, $ZircoliteTextBlock
    )
    "Timeline Artifacts" = @(
        $ProcessToolLocation,
        $ProcessTimelineArtifactsButton, $IncludeChainsaw, $IncludeHayabusa, $IncludeZimmerman, $IncludeZircolite,
        $ExportTimelineArtifactsButton,
        $TimelineArtifactsStartDate, $TimelineArtifactsStartDatePicker, $TimelineArtifactsEndDate, $TimelineArtifactsEndDatePicker,
        $TimelineDateRangeCheckBox, $TimelineDateIOCCheckBox,
        $sqlitePathTextBox, $BrowsesqlitePathButton, $OpenCustomTimelineIOCsButton,
        $TimelineArtifactTextBlock
    )
}

# Track currently visible controls so we only update what changed per selection.
$script:currentProcessingVisibleControls = @()

$ProcessingToolComboBox.Add_SelectionChanged({
    $selectedTool = $null
    if ($ProcessingToolComboBox.SelectedItem -and $ProcessingToolComboBox.SelectedItem.Content) {
        $selectedTool = [string]$ProcessingToolComboBox.SelectedItem.Content
    }

    $newVisibleControls = @()
    if (-not [string]::IsNullOrWhiteSpace($selectedTool) -and $processingToolControlSets.ContainsKey($selectedTool)) {
        $newVisibleControls = @($processingToolControlSets[$selectedTool])
    }

    $controlsToHide = @(
        $script:currentProcessingVisibleControls | Where-Object { $newVisibleControls -notcontains $_ }
    )
    $controlsToShow = @(
        $newVisibleControls | Where-Object { $script:currentProcessingVisibleControls -notcontains $_ }
    )

    if ($controlsToHide.Count -gt 0) {
        Set-ProcessingControlVisibility -Controls $controlsToHide -Visibility 'Collapsed'
    }
    if ($controlsToShow.Count -gt 0) {
        Set-ProcessingControlVisibility -Controls $controlsToShow -Visibility 'Visible'
    }

    $script:currentProcessingVisibleControls = $newVisibleControls
})
####End System processing event handlers####

####M365 Event handlers####
$TabCollectM365 = $window.FindName("TabCollectM365")
$TabCollectM365.Add_GotFocus({ OnTabCollectM365_GotFocus })
$ConnectClientButton = $window.FindName("ConnectClientButton")
$ConnectClientButton.Add_Click({ ConnectClientButton_Click })
$TestClientConnectionButton = $window.FindName("TestClientConnectionButton")
$TestClientConnectionButton.Add_Click({ TestClientConnectionButton_Click })
$OpenCustomIPListButton = $window.FindName("OpenCustomIPListButton")
$OpenCustomUserListButton = $window.FindName("OpenCustomUserListButton")
$M365StartDatePicker = $window.FindName("M365StartDatePicker")
$CollectTriageButton = $window.FindName("CollectTriageButton")
$CollectTriageButton.Add_Click({ CollectTriageButton_Click })
$CollectUALButton = $window.FindName("CollectUALButton")
$CollectUALButton.Add_Click({ CollectUALButton_Click })
$CollectUALUsersComboBox = $window.FindName("CollectUALUsersComboBox")
if ($CollectUALUsersComboBox -ne $null) {
    $CollectUALUsersComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectUALIPsComboBox = $window.FindName("CollectUALIPsComboBox")
if ($CollectUALIPsComboBox -ne $null) {
    $CollectUALIPsComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectUALDateComboBox = $window.FindName("CollectUALDateComboBox")
if ($CollectUALDateComboBox -ne $null) {
    $CollectUALDateComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectUALOperationsComboBox = $window.FindName("CollectUALOperationsComboBox")
if ($CollectUALOperationsComboBox -ne $null) {
    $CollectUALOperationsComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$OnCollectUALDateComboBoxSelectionChanged = {
    param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)
    
    # Get the currently selected ComboBox item
    $selectedItem = $sender.SelectedItem.Content
    
    # Enable or disable the DatePicker based on the selection
    if ($selectedItem -eq "Custom Date") {
        $M365StartDatePicker.IsEnabled = $true
    } else {
        $M365StartDatePicker.IsEnabled = $false
        $M365StartDatePicker.SelectedDate = $null # Clear the selected date if not custom
    }
}
$CollectUALDateComboBox.Add_SelectionChanged($OnCollectUALDateComboBoxSelectionChanged)
$CollectMALButton = $window.FindName("CollectMALButton")
$CollectMALButton.Add_Click({ CollectMALButton_Click })
$CollectMALComboBox = $window.FindName("CollectMALComboBox")
if ($CollectMALComboBox -ne $null) {
    $CollectMALComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectAdminLogsButton = $window.FindName("CollectAdminLogsButton")
$CollectAdminLogsButton.Add_Click({ CollectAdminLogsButton_Click })
$CollectInboxRulesButton = $window.FindName("CollectInboxRulesButton")
$CollectInboxRulesButton.Add_Click({ CollectInboxRulesButton_Click })
$CollectInboxRulesComboBox = $window.FindName("CollectInboxRulesComboBox")
if ($CollectInboxRulesComboBox -ne $null) {
    $CollectInboxRulesComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectForwardingRulesButton = $window.FindName("CollectForwardingRulesButton")
$CollectForwardingRulesButton.Add_Click({ CollectForwardingRulesButton_Click })
$CollectForwardingRulesComboBox = $window.FindName("CollectForwardingRulesComboBox")
if ($CollectForwardingRulesComboBox -ne $null) {
    $CollectForwardingRulesComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectM365InfoButton = $window.FindName("CollectM365InfoButton")
$CollectM365InfoButton.Add_Click({ CollectM365InfoButton_Click })
$CollectMessageTraceButton = $window.FindName("CollectMessageTraceButton")
$CollectMessageTraceButton.Add_Click({ CollectMessageTraceButton_Click })
$CollectMessageTraceComboBox = $window.FindName("CollectMessageTraceComboBox")
if ($CollectMessageTraceComboBox -ne $null) {
    $CollectMessageTraceComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectAzureLogsButton = $window.FindName("CollectAzureLogsButton")
$CollectAzureLogsButton.Add_Click({ CollectAzureLogsButton_Click })
$CollectAzureLogsComboBox = $window.FindName("CollectAzureLogsComboBox")
if ($CollectAzureLogsComboBox -ne $null) {
    $CollectAzureLogsComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$CollectLastPasswordChangeButton = $window.FindName("CollectLastPasswordChangeButton")
$CollectLastPasswordChangeButton.Add_Click({ CollectLastPasswordChangeButton_Click })
$CollectLastPasswordComboBox = $window.FindName("CollectLastPasswordComboBox")
if ($CollectLastPasswordComboBox -ne $null) {
    $CollectLastPasswordComboBox.SelectedIndex = 0
} else {
    Write-Host "ComboBox not found."
}
$OpenCustomIPListButton.Add_Click({
    Start-Process $global:ipAddressesFilePath
})
$OpenCustomUserListButton.Add_Click({
    Start-Process $global:usernamesFilePath
})
####End M365 event handlers####

####Start of tools tab event handlers####
$TabPageTools = $window.FindName("TabPageTools")
$DownloadToolButton = $window.FindName("DownloadToolButton")
$DownloadToolButton.Add_Click({ DownloadToolButton_Click })
$TabPageTools.Add_GotFocus({ OnTabTabPageTools_GotFocus })
$ToolsSelectionComboBox = $window.FindName("ToolsSelectionComboBox")
$ToolDescriptionTextBox = $window.FindName("ToolDescriptionTextBox")
$ToolDownloadStatusTextBlock = $window.FindName("ToolDownloadStatusTextBlock")

# Define a hashtable for tool descriptions
$toolDescriptions = @{
    "7zip" = @"
7-Zip is a file archiver with a high compression ratio.

https://www.7-zip.org
"@
    "BulkExtractor" = @"
BulkExtractor is a program that extracts features such as email addresses, credit card numbers, URLs, and other types of information from digital evidence sources.

https://github.com/simsong/bulk_extractor
"@
    "chainsaw" = @"
Chainsaw provides capability to quickly identify threats within Windows forensic artifacts such as Event Logs and the MFT file using built-in support for Sigma detection rules, and via custom Chainsaw detection rules.

https://github.com/WithSecureLabs/chainsaw
"@	
    "ClamAV" = @"
ClamAV is a free and open-source antivirus software toolkit. It is primarily used for detecting trojans, viruses, malware, and other malicious threats. ClamAV is especially popular in the context of email scanning, web scanning, and endpoint security. 

ClamAV provides a number of utilities including a flexible and scalable multi-threaded daemon, a command-line scanner, and an advanced tool for automatic database updates. Known for its versatility and ability to integrate with mail servers, ClamAV supports various file formats and signature languages, making it a robust tool for virus scanning on various systems.

https://www.clamav.net
"@
    "etl2pcapng" = @"
etl2pcapng is a tool for converting ETL (Event Trace Log) files to the PCAPNG (Packet Capture Next Generation) format, enabling network analysis using standard tools like Wireshark.

https://github.com/microsoft/etl2pcapng
"@
    "Ftkimager" = @"
FTK Imager CLI is a command-line interface version of AccessData's FTK Imager. It allows for efficient acquisition of disk images, memory dumps, and specific files, suitable for forensic analysis. With scripting capabilities, it facilitates automated processing in digital forensic investigations and integrates seamlessly into forensic workflows.

https://www.exterro.com/ftk-product-downloads/windows-32bit-3-1-1
"@
    "GeoLite2Databases" = @"
GeoLite2 City is a geolocation database that offers IP address to city-level location mapping, widely utilized in network traffic analysis, cybersecurity, and location-based services. `nThe GeoLite2 ASN (Autonomous System Number) database provides information linking IP addresses to their respective autonomous systems, essential for network analysis and security. `nGeoLite2 Country is a database associating IP addresses with countries, key for geo-restrictions, region-specific marketing, and global user trend analysis.

https://dev.maxmind.com/geoip/geolite2-free-geolocation-data
"@
    "Hayabusa" = @"
Hayabusa is an open-source security tool developed by Yamato Security. It's designed for fast scanning of Windows event logs, which can be crucial for incident response and digital forensics in cybersecurity. The tool can quickly parse through large volumes of log data to identify potential security incidents, helping IT professionals and security analysts in efficiently detecting and responding to security threats.

https://github.com/Yamato-Security/hayabusa
"@
    "Loki" = @"
Loki is a free and open-source scanner for simple indicators of compromise (IoCs). Unlike ClamAV, Loki is not an antivirus program but rather focuses on various forms of malware and hacker tools based on pattern matching. It's designed to scan endpoints for traces of known hacking tools, web shells, suspicious processes, and other IoCs that are often missed by traditional antivirus solutions. 

Loki is commonly used in incident response scenarios to quickly assess whether a system has been compromised. It's known for its simplicity, ease of use, and the ability to integrate IoCs from various sources, making it a valuable tool for initial assessments in cybersecurity incidents.

https://github.com/Neo23x0/Loki

"@	
    "Plaso" = @"
Plaso (Python-based automatic event log analysis) is a Python-based backend engine used by tools such as log2timeline for automatic timeline creation and analysis of various digital forensic artifacts.

The use of Plaso timeline requires more setup than the program can provide. See the following link for setup instructions.
https://plaso.readthedocs.io/en/latest

https://github.com/log2timeline/plaso
"@
    "SQLite" = @"
SQLite is a C-language library that implements a small, fast, self-contained, high-reliability, full-featured, SQL database engine.

Echo uses the SQLite database for storing parsed artifacts within the Timeline Artifacts option in the Process System Artifacts tab.
WHen using Echo to download SQLite, the browser will open up where you must wait 10 seconds to save the file. Save the file to the temporary tools directory and then click the OK prompt in Echo. The name of the file should be saved as the default name of 'sqlite-netFx46-binary-bundle-x64-2015-1.0.118.0.zip'.
https://sqlite.org/
"@
    "Velociraptor" = @"
Velociraptor is a versatile tool for collecting host-based state information for digital forensics and incident response purposes, including file system enumeration, registry inspection, and log analysis.

https://github.com/Velocidex/velociraptor
"@
    "Volatility3" = @"
Volatility3 is an advanced memory forensics framework for analyzing volatile memory (RAM) snapshots, helping forensic investigators extract artifacts such as running processes, network connections, and more.

https://github.com/volatilityfoundation/volatility3
"@
    "winpmem" = @"
winpmem is a tool designed for live memory capture on Windows systems, enabling the acquisition of physical memory data for forensic analysis, including analysis of running processes, open files, and network connections.

https://github.com/Velocidex/WinPmem
"@
    "ZimmermanTools" = @"
Zimmerman Tools, created by Eric Zimmerman, are a collection of digital forensics tools that include utilities for file system analysis, registry examination, and other forensic artifacts analysis.

https://ericzimmerman.github.io
"@
    "Zircolite" = @"
Zircolite is a standalone tool written in Python 3. It allows to use SIGMA rules on : MS Windows EVTX (EVTX, XML and JSONL format), Auditd logs, Sysmon for Linux and EVTXtract logs

https://github.com/wagga40/Zircolite
"@
}

# Add SelectionChanged event handler for ToolsSelectionComboBox
$ToolsSelectionComboBox.Add_SelectionChanged({
    param([System.Object]$sender, [System.Windows.Controls.SelectionChangedEventArgs]$e)

    # Get the selected item
    $selectedItem = $null
    if ($sender.SelectedItem -and $sender.SelectedItem.Content) {
        $selectedItem = [string]$sender.SelectedItem.Content
    }

    # Update the ToolDescriptionTextBox based on the selected item
    if ($selectedItem -and $toolDescriptions.ContainsKey($selectedItem)) {
        $ToolDescriptionTextBox.Text = $toolDescriptions[$selectedItem]
    } else {
        $ToolDescriptionTextBox.Clear()
    }
    Update-SelectedToolDownloadStatus
    Update-DownloadToolButtonState
})

# Add Tool to CSV right after GUI setup
Add-ToolToCsv -toolName "7za.exe"
Add-ToolToCsv -toolName "bulk_extractor64.exe"
Add-ToolToCsv -toolName "chainsaw*.exe"
Add-ToolToCsv -toolName "clamdscan.exe"
Add-ToolToCsv -toolName "etl2pcapng.exe"
Add-ToolToCsv -toolName "ftkimager.exe"
Add-ToolToCsv -toolName "GeoLite2-City.mmdb"
Add-ToolToCsv -toolName "GeoLite2-ASN.mmdb"
Add-ToolToCsv -toolName "GeoLite2-Country.mmdb"
Add-ToolToCsv -toolName "Get-ZimmermanTools.ps1"
Add-ToolToCsv -toolName "hayabusa*.exe"
Add-ToolToCsv -toolName "log2timeline.py"
Add-ToolToCsv -toolName "loki.exe"
Add-ToolToCsv -toolName "Velociraptor*.exe"
Add-ToolToCsv -toolName "vol.py"
Add-ToolToCsv -toolName "winpmem*.exe"
Add-ToolToCsv -toolName "zircolite*.exe"
####End of tools tab event handlers####

####Evidence Sync event handlers####
$EvidenceSyncTextBox = $window.FindName("EvidenceSyncTextBox")
$QuickSyncCheckBox = $window.FindName("QuickSyncCheckBox")
$QuickSyncComboBox = $window.FindName("QuickSyncComboBox")
#Timesketch controls
$SyncProcessingPathTextBox = $window.FindName("SyncProcessingPathTextBox")
$SyncProcessingPathButton = $window.FindName("SyncProcessingPathButton")
$SyncTimesketchURLPathTextBox = $window.FindName("SyncTimesketchURLPathTextBox")
$TimesketchIndexComboBox = $window.FindName("TimesketchIndexComboBox")
$NewTimesketchCheckBox = $window.FindName("NewTimesketchCheckBox")
$NewTimesketchTextBox = $window.FindName("NewTimesketchTextBox")
$SyncTimesketchButton = $window.FindName("SyncTimesketchButton")
$TestTimesketchButton = $window.FindName("TestTimesketchButton")
$timesketchurltext = $window.FindName("timesketchurltext")
$TimesketchUserTextBox = $window.FindName("TimesketchUserTextBox")
$TimesketchUserText = $window.FindName("TimesketchUserText")
$NewTimesketchText = $window.FindName("NewTimesketchText")
$RefreshTimesketchButton = $window.FindName("RefreshTimesketchButton")
$SketchIndexText = $window.FindName("SketchIndexText")
$Timesketchdescription = $window.FindName("Timesketchdescription")

$SyncProcessingPathButton.Add_Click({
    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Input Type'
    $form.Size = New-Object System.Drawing.Size(400, 200)
    $form.StartPosition = 'CenterScreen'
    # Add label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Choose a File or Folder to process'
    $label.Location = New-Object System.Drawing.Point(50, 20)
    $label.Size = New-Object System.Drawing.Size(300, 30)
    $form.Controls.Add($label)
    # Add File button
    $fileButton = New-Object System.Windows.Forms.Button
    $fileButton.Text = 'File'
    $fileButton.Location = New-Object System.Drawing.Point(100, 70)
    $fileButton.Size = New-Object System.Drawing.Size(75, 23)
    $fileButton.Add_Click({
        $form.Tag = 'File'
        $form.Close()
    })
    $form.Controls.Add($fileButton)
    # Add Folder button
    $folderButton = New-Object System.Windows.Forms.Button
    $folderButton.Text = 'Folder'
    $folderButton.Location = New-Object System.Drawing.Point(200, 70)
    $folderButton.Size = New-Object System.Drawing.Size(75, 23)
    $folderButton.Add_Click({
        $form.Tag = 'Folder'
        $form.Close()
    })
    $form.Controls.Add($folderButton)
    # Show form
    $form.ShowDialog() | Out-Null
    # Process the selection
    if ($form.Tag -eq 'File') {
        $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $fileDialog.Multiselect = $false
        if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $SyncProcessingPathTextBox.Text = $fileDialog.FileName
        }
    } elseif ($form.Tag -eq 'Folder') {
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $SyncProcessingPathTextBox.Text = $folderDialog.SelectedPath
        }
    }
})

$QuickSyncCheckBox.Add_Checked({
    $QuickSyncComboBox.IsEnabled = $true
	$SyncProcessingPathTextBox.IsEnabled = $false
	$SyncProcessingPathButton.IsEnabled = $false
    UpdateSyncTimesketchButtonState
})
$QuickSyncCheckBox.Add_Unchecked({
    $QuickSyncComboBox.IsEnabled = $false
	$SyncProcessingPathTextBox.IsEnabled = $true
	$SyncProcessingPathButton.IsEnabled = $true
    UpdateSyncTimesketchButtonState
})

$NewTimesketchCheckBox.Add_Checked({
    $NewTimesketchTextBox.IsEnabled = $true
	$TimesketchIndexComboBox.IsEnabled = $false
})
$NewTimesketchCheckBox.Add_Unchecked({
    $NewTimesketchTextBox.IsEnabled = $false
	$TimesketchIndexComboBox.IsEnabled = $true	
})

$QuickSyncComboBox.Add_DropDownOpened({
    $QuickSyncComboBox.Items.Clear()
    $global:quickSyncPaths = @{}
    $baseDirectories = @(
        "$($CurrentCaseDirectory)\M365Evidence",
        "$($CurrentCaseDirectory)\MemoryArtifacts\VolOutput",
        "$($CurrentCaseDirectory)\SystemArtifacts\ProcessedArtifacts\Zimmermantools",
		"$($CurrentCaseDirectory)\SystemArtifacts\ProcessedArtifacts\Hayabusa"		
    )

    # Prepare an empty array for all directories including _plaso directories
    $directories = @()
    $directories += $baseDirectories
    $processedArtifactsRoot = Join-Path $CurrentCaseDirectory "SystemArtifacts\ProcessedArtifacts"
    $plasoDirectories = @()
    if (Test-Path -LiteralPath $processedArtifactsRoot -PathType Container) {
        $plasoDirectories = @(Get-ChildItem -Path $processedArtifactsRoot -Directory -ErrorAction SilentlyContinue |
                              Where-Object { $_.Name -like "*_plaso" })
    }

    foreach ($dir in $plasoDirectories) {
        $directories += $dir.FullName
    }

    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            $dirName = Split-Path $dir -Leaf
            $displayName = $dirName
            if ($global:quickSyncPaths.ContainsKey($displayName)) {
                $suffix = 2
                while ($global:quickSyncPaths.ContainsKey("$dirName ($suffix)")) {
                    $suffix++
                }
                $displayName = "$dirName ($suffix)"
            }
            $QuickSyncComboBox.Items.Add($displayName)
            $global:quickSyncPaths[$displayName] = $dir
        }
    }
    UpdateSyncTimesketchButtonState
})


$SyncTimesketchButton.Add_Click({SyncTimesketchButton_Click})

# Timesync button Event Handlers
$SyncProcessingPathTextBox.Add_TextChanged({ UpdateSyncTimesketchButtonState })
$QuickSyncComboBox.Add_SelectionChanged({ UpdateSyncTimesketchButtonState })
$NewTimesketchCheckBox.Add_Checked({ UpdateSyncTimesketchButtonState })
$NewTimesketchCheckBox.Add_Unchecked({ UpdateSyncTimesketchButtonState })
$NewTimesketchTextBox.Add_TextChanged({ UpdateSyncTimesketchButtonState })
$TimesketchIndexComboBox.Add_SelectionChanged({ UpdateSyncTimesketchButtonState })
$TestTimesketchButton.Add_Click({
    TestTimesketchButton_Click
    UpdateSyncTimesketchButtonState
})
$RefreshTimesketchButton.Add_Click({
    RefreshTimesketchButton_Click
    UpdateSyncTimesketchButtonState
})

$SyncToolComboBox = $window.FindName("SyncToolComboBox")
$ComingSoonSplunk = $window.FindName("ComingSoonSplunk")
$ComingSoonElastic = $window.FindName("ComingSoonElastic")

# Timesketch controls
$SyncToolComboBox.Add_SelectionChanged({
    switch ($SyncToolComboBox.SelectedItem.Content) {
        "Timesketch" {
            # Show Timesketch controls
            $TestTimesketchButton.Visibility = 'Visible'
			$SyncTimesketchURLPathTextBox.Visibility = 'Visible'
			$TimesketchIndexComboBox.Visibility = 'Visible'
			$NewTimesketchCheckBox.Visibility = 'Visible'
			$NewTimesketchTextBox.Visibility = 'Visible'
			$SyncTimesketchButton.Visibility = 'Visible'			
			$TimesketchUserTextBox.Visibility = 'Visible'
			$TimesketchUserText.Visibility = 'Visible'
			$timesketchurltext.Visibility = 'Visible'
			$NewTimesketchText.Visibility = 'Visible'
			$RefreshTimesketchButton.Visibility = 'Visible'
			$SketchIndexText.Visibility = 'Visible'
			$Timesketchdescription.Visibility = 'Visible'
			
            # Hide other controls
            $ComingSoonSplunk.Visibility = 'Collapsed'
            $ComingSoonElastic.Visibility = 'Collapsed'
        }
        "Splunk" {

            # Show Splunk Controls			
            $ComingSoonSplunk.Visibility = 'Visible'

            # Hide other controls
            $TestTimesketchButton.Visibility = 'Collapsed'
			$SyncTimesketchURLPathTextBox.Visibility = 'Collapsed'
			$TimesketchIndexComboBox.Visibility = 'Collapsed'
			$NewTimesketchCheckBox.Visibility = 'Collapsed'
			$NewTimesketchTextBox.Visibility = 'Collapsed'
			$SyncTimesketchButton.Visibility = 'Collapsed'
			$TestTimesketchButton.Visibility = 'Collapsed'			
			$TimesketchUserTextBox.Visibility = 'Collapsed'
			$TimesketchUserText.Visibility = 'Collapsed'
			$timesketchurltext.Visibility = 'Collapsed'
			$NewTimesketchText.Visibility = 'Collapsed'
			$RefreshTimesketchButton.Visibility = 'Collapsed'
			$SketchIndexText.Visibility = 'Collapsed'
			$Timesketchdescription.Visibility = 'Collapsed'			
        }
        "Elastic" {
            # Show Elastic Controls
            $ComingSoonElastic.Visibility = 'Visible'
            # Hide other controls
            $ComingSoonSplunk.Visibility = 'Collapsed'
            $TestTimesketchButton.Visibility = 'Collapsed'
			$SyncTimesketchURLPathTextBox.Visibility = 'Collapsed'
			$TimesketchIndexComboBox.Visibility = 'Collapsed'
			$NewTimesketchCheckBox.Visibility = 'Collapsed'
			$NewTimesketchTextBox.Visibility = 'Collapsed'
			$SyncTimesketchButton.Visibility = 'Collapsed'
			$TestTimesketchButton.Visibility = 'Collapsed'	
			$TimesketchUserTextBox.Visibility = 'Collapsed'
			$TimesketchUserText.Visibility = 'Collapsed'
			$timesketchurltext.Visibility = 'Collapsed'
			$NewTimesketchText.Visibility = 'Collapsed'
			$RefreshTimesketchButton.Visibility = 'Collapsed'
			$SketchIndexText.Visibility = 'Collapsed'
			$Timesketchdescription.Visibility = 'Collapsed'	

        }
    }
})

$SyncTimesketchURLPathTextBox.Add_TextChanged({
    UpdateTestConnectionButtonState
})

$TimesketchUserTextBox.Add_TextChanged({
    UpdateTestConnectionButtonState
})
####End Evidence Sync event handlers####

####Threat Scanner Event handlers####
$TabUseThreatScanners = $window.FindName("TabUseThreatScanners")
$TabUseThreatScanners.AddHandler(
    [System.Windows.Controls.Primitives.Selector]::SelectedEvent,
    [System.Windows.RoutedEventHandler]{
        param($sender, $e)
        if (($e.OriginalSource -eq $TabUseThreatScanners) -and $TabUseThreatScanners.IsSelected) {
            OnTabThreatScanners_GotFocus
        }
    }
)
$ArtifactScanningPathTextBox = $window.FindName("ArtifactScanningPathTextBox")
$ArtifactScanningPathButton = $window.FindName("ArtifactScanningPathButton")
$ScanToolLocation = $window.FindName("ScanToolLocation")
$ScanningToolExtraArguments = $window.FindName("ScanningToolExtraArguments")
$ScanClamAVButton = $window.FindName("ScanClamAVButton")
$ClamAVPathTextBox = $window.FindName("ClamAVPathTextBox")
$BrowseClamAVPathButton = $window.FindName("BrowseClamAVPathButton")
$ClamAVTextBlock = $window.FindName("ClamAVTextBlock")
$ScanLokiButton = $window.FindName("ScanLokiButton")
$LokiPathTextBox = $window.FindName("LokiPathTextBox")
$BrowseLokiPathButton = $window.FindName("BrowseLokiPathButton")
$LokiTextBlock = $window.FindName("LokiTextBlock")
$ProcscanCheckbox = $window.FindName("ProcscanCheckbox")
$IntenseScanCheckbox = $window.FindName("IntenseScanCheckbox")
$VulnchecksCheckbox = $window.FindName("VulnchecksCheckbox")
$ThreatScanToolComboBox = $window.FindName("ThreatScanToolComboBox")

$UpdateLokiButton = $window.FindName("UpdateLokiButton")
$LokiUpdaterPathTextBox = $window.FindName("LokiUpdaterPathTextBox")
$BrowseLokiUpdatePathButton = $window.FindName("BrowseLokiUpdatePathButton")
$UpdateclamAVButton = $window.FindName("UpdateclamAVButton")
$clamAVUpdaterPathTextBox = $window.FindName("clamAVUpdaterPathTextBox")
$BrowseclamAVUpdatePathButton = $window.FindName("BrowseclamAVUpdatePathButton")
$FreshclamLocation = $window.FindName("FreshclamLocation")
$LokiUpgraderLocation = $window.FindName("LokiUpgraderLocation")
$ArtifactScanningPathTextBox.Add_TextChanged({ UpdateScanningButtonsStatus })
$LokiUpdaterPathTextBox.Add_TextChanged({ UpdateScanningButtonsStatus })
$clamAVUpdaterPathTextBox.Add_TextChanged({ UpdateScanningButtonsStatus })
$ArtifactScanningPathButton.Add_Click({
    # Create a new form
    $form = New-Object System.Windows.Forms.Form
    $form.Text = 'Input Type'
    $form.Size = New-Object System.Drawing.Size(400, 200)
    $form.StartPosition = 'CenterScreen'
    # Add label
    $label = New-Object System.Windows.Forms.Label
    $label.Text = 'Choose a File or Folder to process'
    $label.Location = New-Object System.Drawing.Point(50, 20)
    $label.Size = New-Object System.Drawing.Size(300, 30)
    $form.Controls.Add($label)
    # Add File button
    $fileButton = New-Object System.Windows.Forms.Button
    $fileButton.Text = 'File'
    $fileButton.Location = New-Object System.Drawing.Point(100, 70)
    $fileButton.Size = New-Object System.Drawing.Size(75, 23)
    $fileButton.Add_Click({
        $form.Tag = 'File'
        $form.Close()
    })
    $form.Controls.Add($fileButton)
    # Add Folder button
    $folderButton = New-Object System.Windows.Forms.Button
    $folderButton.Text = 'Folder'
    $folderButton.Location = New-Object System.Drawing.Point(200, 70)
    $folderButton.Size = New-Object System.Drawing.Size(75, 23)
    $folderButton.Add_Click({
        $form.Tag = 'Folder'
        $form.Close()
    })
    $form.Controls.Add($folderButton)
    # Show form
    $form.ShowDialog() | Out-Null
    # Process the selection
    if ($form.Tag -eq 'File') {
        $fileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $fileDialog.Multiselect = $false
        if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $ArtifactScanningPathTextBox.Text = $fileDialog.FileName
        }
    } elseif ($form.Tag -eq 'Folder') {
        $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
        if ($folderDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
            $ArtifactScanningPathTextBox.Text = $folderDialog.SelectedPath
        }
    }
})

$BrowseClamAVPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "clamdscan.exe file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $ClamAVPathTextBox.Text = $dialog.FileName
    }
})

$BrowseLokiPathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "loki.exe file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $LokiPathTextBox.Text = $dialog.FileName
    }
})

$BrowseLokiUpdatePathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "loki-upgrader.exe file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $LokiUpdaterPathTextBox.Text = $dialog.FileName
    }
})

$BrowseclamAVUpdatePathButton.Add_Click({
    $dialog = New-Object System.Windows.Forms.OpenFileDialog
    $dialog.Filter = "freshclam.exe file (*.exe)|*.exe"
    $result = $dialog.ShowDialog()
    if ($result -eq [System.Windows.Forms.DialogResult]::OK) {
        $clamAVUpdaterPathTextBox.Text = $dialog.FileName
    }
})

$threatScannerControlSets = @{
    "ClamAV" = @(
        $ScanToolLocation, $ScanningToolExtraArguments,
        $ScanClamAVButton, $ClamAVPathTextBox, $BrowseClamAVPathButton, $ClamAVTextBlock,
        $UpdateclamAVButton, $clamAVUpdaterPathTextBox, $BrowseclamAVUpdatePathButton, $FreshclamLocation
    )
    "Loki" = @(
        $ScanToolLocation, $ScanningToolExtraArguments,
        $ScanLokiButton, $LokiPathTextBox, $BrowseLokiPathButton, $LokiTextBlock,
        $ProcscanCheckbox, $IntenseScanCheckbox, $VulnchecksCheckbox,
        $UpdateLokiButton, $LokiUpdaterPathTextBox, $BrowseLokiUpdatePathButton, $LokiUpgraderLocation
    )
}

$script:currentThreatScannerVisibleControls = @()

$ThreatScanToolComboBox.Add_SelectionChanged({
    $selectedTool = $null
    if ($ThreatScanToolComboBox.SelectedItem -and $ThreatScanToolComboBox.SelectedItem.Content) {
        $selectedTool = [string]$ThreatScanToolComboBox.SelectedItem.Content
    }

    $newVisibleControls = @()
    if (-not [string]::IsNullOrWhiteSpace($selectedTool) -and $threatScannerControlSets.ContainsKey($selectedTool)) {
        $newVisibleControls = @($threatScannerControlSets[$selectedTool])
    }

    $controlsToHide = @(
        $script:currentThreatScannerVisibleControls | Where-Object { $newVisibleControls -notcontains $_ }
    )
    $controlsToShow = @(
        $newVisibleControls | Where-Object { $script:currentThreatScannerVisibleControls -notcontains $_ }
    )

    if ($controlsToHide.Count -gt 0) {
        Set-ProcessingControlVisibility -Controls $controlsToHide -Visibility 'Collapsed'
    }
    if ($controlsToShow.Count -gt 0) {
        Set-ProcessingControlVisibility -Controls $controlsToShow -Visibility 'Visible'
    }

    $script:currentThreatScannerVisibleControls = $newVisibleControls
})
$ScanClamAVButton.Add_Click({ScanClamAVButton_Click })
$ScanLokiButton.Add_Click({ScanLokiButton_Click })
$UpdateLokiButton.Add_Click({UpdateLokiButton_Click })
$UpdateclamAVButton.Add_Click({UpdateclamAVButton_Click })
####End Threat Scanner Event Hanlders####

####Elastic Search event handlers####
$TabElasticSearch = $window.FindName("TabElasticSearch")
$TabElasticSearch.Add_GotFocus({ OnTabElasticSearch_GotFocus })
$ElasticURLPathTextBox = $window.FindName("ElasticURLPathTextBox")
$ElasticDateRangeCheckBox = $window.FindName("ElasticDateRangeCheckBox")
$ElasticSearchIOCTextBox = $window.FindName("ElasticSearchIOCTextBox")
$ElasticStartDatePicker = $window.FindName("ElasticStartDatePicker")
$ElasticEndDatePicker = $window.FindName("ElasticEndDatePicker")
$ElasticSearchButton = $window.FindName("ElasticSearchButton")
$ElasticIndexIDTextBox = $window.FindName("ElasticIndexIDTextBox")
$OpenCustomElasticIOCsButton = $window.FindName("OpenCustomElasticIOCsButton")
$ElasticSearchComboBox = $window.FindName("ElasticSearchComboBox")
$ElasticSearchTextBox = $window.FindName("ElasticSearchTextBox")
$ElasticCheckBoxListBox = $window.FindName("ElasticCheckBoxListBox")
$ElasticCustomIOCComboBox = $window.FindName("ElasticCustomIOCComboBox")
$ElasticSearchDescriptionTextBox = $window.FindName("ElasticSearchDescriptionTextBox")
$OpenCustomElasticIOCsButton.Add_Click({
    Start-Process $global:elasticIOCFilePath
})

$ElasticDateRangeCheckBox.Add_Checked({
    $ElasticStartDatePicker.IsEnabled = $true
    $ElasticEndDatePicker.IsEnabled = $true
})
$ElasticDateRangeCheckBox.Add_Unchecked({
    $ElasticStartDatePicker.IsEnabled = $false
    $ElasticEndDatePicker.IsEnabled = $false
})

$ElasticURLPathTextBox.Add_TextChanged({ UpdateElasticSearchButtonState })
$ElasticIndexIDTextBox.Add_TextChanged({ UpdateElasticSearchButtonState })
UpdateElasticSearchButtonState

$ElasticSearchButton.Add_Click({ElasticSearchButton_Click })

$ElasticSearchComboBox.Add_SelectionChanged({
    $selectedItem = $ElasticSearchComboBox.SelectedItem.Content
    $ElasticCheckBoxListBox.Items.Clear() 
    if ($selectedItem -eq "All") {
        $ElasticCheckBoxListBox.Items.Add("Amcache")
		$ElasticCheckBoxListBox.Items.Add("Event Logs")
        $ElasticCheckBoxListBox.Items.Add("Event Logs Cleared")
		$ElasticCheckBoxListBox.Items.Add("Failed Logins")
		$ElasticCheckBoxListBox.Items.Add("JumpList")
		$ElasticCheckBoxListBox.Items.Add("Lateral Movement_V")
		$ElasticCheckBoxListBox.Items.Add("LNK")	
        $ElasticCheckBoxListBox.Items.Add("Logins RDP")
        $ElasticCheckBoxListBox.Items.Add("Logins RDP External IP")
        $ElasticCheckBoxListBox.Items.Add("Logins Security")
		$ElasticCheckBoxListBox.Items.Add("Persistence_V")
		$ElasticCheckBoxListBox.Items.Add("Prefetch")
		$ElasticCheckBoxListBox.Items.Add("PSlist_V")
		$ElasticCheckBoxListBox.Items.Add("RecycleBin")
		$ElasticCheckBoxListBox.Items.Add("RDPAuth_V")				
		$ElasticCheckBoxListBox.Items.Add("Scheduled Task")
        $ElasticCheckBoxListBox.Items.Add("Service Creation")
        $ElasticCheckBoxListBox.Items.Add("Shimcache")
        $ElasticCheckBoxListBox.Items.Add("UntrustedBinaries_V")
        $ElasticCheckBoxListBox.Items.Add("Windows Defender")
    }
	elseif ($selectedItem -eq "Initial Access") {
		$ElasticCheckBoxListBox.Items.Add("Failed Logins")
        $ElasticCheckBoxListBox.Items.Add("Logins RDP")
        $ElasticCheckBoxListBox.Items.Add("Logins RDP External IP")
        $ElasticCheckBoxListBox.Items.Add("Logins Security")
		$ElasticCheckBoxListBox.Items.Add("RDPAuth_V")				
	}
	elseif ($selectedItem -eq "Execution") {
        $ElasticCheckBoxListBox.Items.Add("Amcache")
		$ElasticCheckBoxListBox.Items.Add("JumpList")
		$ElasticCheckBoxListBox.Items.Add("LNK")
		$ElasticCheckBoxListBox.Items.Add("Prefetch")
		$ElasticCheckBoxListBox.Items.Add("PSlist_V")
		$ElasticCheckBoxListBox.Items.Add("RecycleBin")
        $ElasticCheckBoxListBox.Items.Add("Shimcache")
        $ElasticCheckBoxListBox.Items.Add("Shimcache")
        $ElasticCheckBoxListBox.Items.Add("Pslist_UntrustedBinaries_V")		
        $ElasticCheckBoxListBox.Items.Add("Windows Defender")
	}	
	elseif ($selectedItem -eq "Persistence") {
		$ElasticCheckBoxListBox.Items.Add("Persistence_V")
		$ElasticCheckBoxListBox.Items.Add("Scheduled Task")
		$ElasticCheckBoxListBox.Items.Add("Service Creation")
        $ElasticCheckBoxListBox.Items.Add("Shimcache")
		$ElasticCheckBoxListBox.Items.Add("PSlist_V")
        $ElasticCheckBoxListBox.Items.Add("UntrustedBinaries_V")
	}
	elseif ($selectedItem -eq "Privilage Escalation") {
	}
	elseif ($selectedItem -eq "Defense Evasion") {
        $ElasticCheckBoxListBox.Items.Add("Event Logs Cleared")
        $ElasticCheckBoxListBox.Items.Add("Windows Defender")
	}
	elseif ($selectedItem -eq "Credential Access") {
	}
	elseif ($selectedItem -eq "Discovery") {
	}	
	elseif ($selectedItem -eq "Lateral Movement") {
		$ElasticCheckBoxListBox.Items.Add("Event Logs")
		$ElasticCheckBoxListBox.Items.Add("Lateral Movement_V")
        $ElasticCheckBoxListBox.Items.Add("Logins RDP")
        $ElasticCheckBoxListBox.Items.Add("Logins Security")
		$ElasticCheckBoxListBox.Items.Add("RDPAuth_V")				
	}		
	elseif ($selectedItem -eq "Collection") {
		$ElasticCheckBoxListBox.Items.Add("JumpList")
		$ElasticCheckBoxListBox.Items.Add("LNK")
	}	
	elseif ($selectedItem -eq "Command and Control") {
	}	
	elseif ($selectedItem -eq "Exfiltration") {
	}	
	elseif ($selectedItem -eq "Impact") {
	}	
	elseif ($selectedItem -eq "Custom IOCs") {
		$ElasticCheckBoxListBox.Items.Add("CustomIOCs.txt")
	}	
})

$ElasticCheckBoxListBox.Add_SelectionChanged({
    $selectedItem = $ElasticCheckBoxListBox.SelectedItem
    if ($selectedItem -and $itemDescriptions.ContainsKey($selectedItem)) {
        $ElasticSearchDescriptionTextBox.Text = $itemDescriptions[$selectedItem]
    } else {
        $ElasticSearchDescriptionTextBox.Text = ""
    }
})

$itemDescriptions = @{
    "Amcache" = @"
This search filters on events related to Windows Amcache artifacts.

Amcache.hve is an artifact located in the Windows operating system which is a registry file created by the Application Experience and Compatibility feature. It was introduced with Windows 8 and exists in all later versions including Windows 8.1 and Windows 10.

Amcache.hve is typically located at
- C:\Windows\AppCompat\Programs\Amcache.hve

It contains information about executed programs including:
- File path information
- Created and modified times
- SHA-1 hash of the file
- PE (Portable Executable) metadata (when available)
- The volume information (like serial number and creation time) of the volume where the file was run from
- The last modification time of the file

When it comes to digital forensics, Amcache.hve can provide the following valuable insights:
- 1. User Activity: The Amcache.hve can help an investigator identify what programs were run on the system and when they were run. This is extremely useful in user activity investigations, such as identifying unauthorized software or malware.
- 2. Timeline Analysis: The created and modified times, along with last execution time can provide valuable information for timeline analysis. This can help investigators determine the sequence of events, which can be crucial in investigations.
- 3. File Identification: The SHA-1 hash can be used to identify the exact version of the executed file, which can be especially useful in malware investigations. It can be compared with known hashes in threat intelligence databases for malware identification.
- 4. Artifact Correlation: The information from Amcache.hve can be correlated with other artifacts for a more complete picture. For example, correlating the last modified times in the Amcache with Windows event logs might give more context about the user actions surrounding an event.

It's important to remember that the existence of a file entry in the Amcache.hve is not a 100`% guarantee that the file was executed. Other actions, like right-clicking a file and viewing its properties, can cause an entry to be created. So, any conclusions drawn from Amcache.hve should be cross-verified with other artifacts.
"@
    "CustomIOCs.txt" = @"
Add in your own list of IOC's and they will be added to the search. 

Use the CustomIOCs.txt text file located in the `<casedirectory`>\Elastic location. You may also open this file by selecting the Open CustomIOCs button.

Each search term should be entered on it's own line

Example:
IOC1
IOC2
IOC3

NOTE: Too many terms can cause a search to be incomplete due to too_many_nested_clauses error.
"@
    "Event Logs" = @"
This is a generic search against all Windows Event logs and populates generic columns.
"@
    "Event Logs Cleared" = @"
This search filters on Log Clearing events from Security and System event Logs.

Specific Event IDs searched for along with a short description:
Event ID 104: Event log cleared
Event ID 1102: Event log cleared
"@
    "Failed Logins" = @"
This search filters on failed logon events from Security event Logs.

Specific Event IDs searched for along with a short description:
Event ID 4625: User Logon Failed
"@
	"JumpList" = @"
This search filters on events related to Windows Jump Lists artifacts.

Jump Lists are a feature introduced in Windows 7 that provide quick access to recently used files, folders, and websites. For digital forensics, they can be a valuable source of information about a user's recent activities.

The Jump List files are located in the user profile directory, specifically:
- C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\ 
- C:\Users\[Username]\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\

Jump Lists are stored as .automaticDestinations-ms and .customDestinations-ms files. The file names are hashed, which makes it difficult to directly associate a Jump List with a specific application, but mappings for many common applications have been documented.

Each .automaticDestinations-ms and .customDestinations-ms file contains multiple entries, each of which represents a file, folder, or URL that was recently accessed by the associated application. Each entry includes:
- The file, folder, or URL that was accessed.
- The number of times it was accessed.
- The dates and times of the most recent accesses.
In addition, each .automaticDestinations-ms file contains a count of the number of items that have been pinned and unpinned from the Jump List.

Relevance in Digital Forensics: 
- Recent Activity: Jump Lists record the files, folders, and websites that were recently accessed by each application, providing a snapshot of a user's recent activity.
- User Behavior: The pinned and unpinned counts can give insights into a user's habits and preferences.
- Application Usage: The association between each Jump List and a specific application can help determine which applications a user has been using.
"@

	"Lateral Movement_V" = @"
This search filters on events related to Velociraptor Windows Lateral Movement Pack.

name: Windows.Packs.LateralMovement
description: |
- Detect evidence of lateral movement.

precondition: SELECT OS From info() where OS = 'windows'

reference:
  - https://digital-forensics.sans.org/media/SANS_Poster_2018_Hunt_Evil_FINAL.pdf

sources:
- name: AlternateLogon
    query: |
      SELECT * FROM Artifact.Windows.EventLogs.AlternateLogon()

- name: WMIC
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Prefetch()
      WHERE Executable =~ "wmic.exe"
- name: ShimCache
    query: |
      SELECT * FROM Artifact.Windows.Registry.AppCompatCache()
      WHERE Name =~ "wmic.exe"
- name: BAM
    query: |
      SELECT * FROM Artifact.Windows.Forensics.Bam()
      WHERE Binary =~ "wmic.exe"
- name: AmCache
    query: |
      SELECT * FROM Artifact.Windows.System.Amcache()
      WHERE Binary =~ "wmic.exe"
"@

	"LNK" = @"
This search filters on events related to Windows LNK artifacts.

LNK files, or Link files, are shortcut files in Windows that provide a reference to an executable file, document, or directory. They are widely used across Windows systems for a variety of tasks.
Location: LNK files can be found almost anywhere on a Windows file system, including on the Desktop, in the Start Menu, and in various other directories. Notable locations for LNK files from a forensic perspective include:
- C:\Users\[username]\Desktop\
- C:\Users\[username]\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\
- C:\Users\[username]\AppData\Roaming\Microsoft\Windows\Recent\
- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\

Structure and Content: LNK files contain a variety of metadata, including:
- The path and name of the file to which the shortcut refers.
- The creation, access, and modification timestamps of the LNK file itself.
- The creation, access, and modification timestamps of the target file at the time the LNK file was created.
- The volume serial number and volume label of the volume where the target file is located.
- The drive type (e.g., fixed drive, network drive, removable drive) where the target file is located.
- The network share details (if the target file is on a network share).
- The file size of the target file at the time the LNK file was created.
- The icon of the file.
	
Relevance in Digital Forensics: 
- User Activity: The existence of a LNK file and its metadata can provide evidence of user activity, including files that were accessed, programs that were run, and directories that were browsed.
- File Existence: The metadata in a LNK file can prove the existence of a file at a particular point in time, even if the file itself has been deleted.
- External Devices: LNK files can provide evidence of external devices that were connected to the system, particularly if the LNK file refers to a file that was on the external device.
"@
	"Logins RDP" = @"
This search filters on RDP events from Security events with type 10 logons, as well as RDP logins within Terminal Service and RdpCoreTS.

Specific Event IDs searched for along with short a description:
Event ID 21: RDP Logon succeeded
Event ID 23: RDP Logoff
Event ID 24: RDP Disconnect
Event ID 25: RDP Reconnect
Event ID 1149: RDP network connection established
Event ID 1024: RDP client is attempting to connect to a remote machine or server
Event ID 68: Log containing Connection Name and Prompt For Credentials fields
Event ID 98: A TCP connection has been successfully established
Event ID 131: The server accepted a new TCP connection from client <ipAddress>
Event ID 4624: User Logon (filterd on Logon Type: 10)
"@
	"Logins RDP External IP" = @"
This search filters on RDP events from Security events with type 10 logons, as well as RDP logins within Terminal Service and RdpCoreTS that contain non Private IPs.

Specific Event IDs searched for along with short a description:
Event ID 21: RDP Logon succeeded
Event ID 24: RDP Disconnect
Event ID 25: RDP Reconnect
Event ID 1149: RDP network connection established
Event ID 131: The server accepted a new TCP connection from client <ipAddress>
Event ID 4624: User Logon (filterd on Logon Type: 10)
"@
	"Logins Security" = @"
This search filters on Logon events from Security event Logs.

Specific Event IDs searched for along with a short description:
Event ID 4624: User Logon
Event ID 4648: User Logon attempted using explicit credentials
Event ID 4778: A session was reconnected to a Window Station
Event ID 4779: A session was disconnected from a Window Station
"@
	"Persistence_V" = @"
This search filters on events related to Velociraptor Windows Persistence Pack.

name: Windows.Packs.Persistence
description: |
-This artifact pack collects various persistence mechanisms in Windows.

Source WMI Event Filters
- SELECT * FROM Artifact.Windows.Persistence.PermanentWMIEvents()

Source Startup Items
- ELECT * FROM Artifact.Windows.Sys.StartupItems()

Source Debug Bootstraping
- SELECT * FROM Artifact.Windows.Persistence.Debug()
"@
	"PSlist_V" = @"
This search filters on events related to Velociraptor Windows System Pslist.

name: Windows.System.Pslist
description: |
-List processes and their running binaries.
"@
	"Prefetch" = @"
This search filters on events related to Windows Prefetch artifacts.

Prefetch files have a .pf extension and are named after the executable that they relate to, followed by a hyphen and a hash value (e.g., NOTEPAD.EXE-3FBE5FBE.pf). Each .pf file contains:
- The name of the application.
- The number of times the application has been run.
- A timestamp indicating the last time the application was run.
- The files and directories accessed during the first 10 seconds of the application's startup process.

Relevance in Digital Forensics: Application Usage: 
- Frequency of Use: The run count stored in each prefetch file can give you an idea of how often each application was used.
- Activity Timeline: The timestamp in each prefetch file can help build a timeline of application usage.
- File Access: The list of files and directories accessed during the application startup can provide additional information about the system's configuration and the user's activities.
"@
	"RDPAuth_V" = @"
This velociraptor artifact will contain extracted Event Logs related to Remote Desktop sessions, logon and logoff.

Security channel 
- EventID in 4624,4634 AND LogonType 3, 7, or 10. Security channel 
- EventID in 4778,4625,4779, or 4647. 
System channel 
- EventID 9009. 
Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational 
- EventID 1149. 
Microsoft-Windows-TerminalServices-LocalSessionManager/Operational 
- EventID 23,22,21,24,25,39, or 40.

Best use of this artifact is to collect RDP and Authentication events around a timeframe of interest and order by EventTime to scope RDP activity.
"@

	"RecycleBin" = @"
This search filters on events related to Windows RecycleBin artifacts.

The Recycle Bin in Windows is a special folder that holds deleted files. When a file is deleted, the file data and some metadata are stored in the Recycle Bin until it's manually emptied or automatically purged when the allocated space is exceeded.

Recycle Bin Artifacts:
- Location: The Recycle Bin is located on the desktop by default, but the actual data associated with the Recycle Bin resides in hidden directories on each volume with a name in the format: `$Recycle.Bin\SID, where SID is the security identifier associated with a specific user.

Relevance in Digital Forensics and Incident Response (DFIR):
- File Recovery: The primary use of the Recycle Bin in a forensics context is to recover deleted files. Until the Recycle Bin is emptied, the deleted files are still available and can be recovered.
- User Activity: Recycle Bin can be used to trace user activity. This includes the files a user deleted and when they were deleted.

When a file is deleted and moved to the Recycle Bin, two files are created: one with a `$R prefix and another with a `$I prefix, followed by a random string.
- `$R file: This file is a copy of the deleted file and contains the actual contents of the file.
- `$I file: This is a small file that contains metadata about the deleted file, such as the original name and location, the file size, and the date and time the file was deleted.
"@
	"Scheduled Task" = @"
This search filters on Scheduled Task events from Security and Task Scheduler event Logs.

Specific Event IDs searched for along with a short description:
Event ID 4698: A scheduled task was created
Event ID 4699: A scheduled task was deleted
Event ID 4702: A scheduled task was updated
Event ID 100: A scheduled task started
Event ID 102: A scheduled task was successfully finished
Event ID 106: A scheduled task was created
Event ID 110: A scheduled task was launched
Event ID 129: Task scheduler launched task
Event ID 140: A scheduled task was updated
Event ID 141: A scheduled task was deleted
Event ID 142: A scheduled task was disabled
Event ID 200: A scheduled task launched action <action>
Event ID 201: A scheduled task completed
"@
	"Service Creation" = @"
This search filters on Service Creation and related events from Security and System event Logs.

Specific Event IDs searched for along with a short description:
Event ID 4697: A service was installed in the system
Event ID 7000: The service failed to start due to the following error
Event ID 7009: A timeout was reached while waiting for the service to connect
Event ID 7045: A new service was installed in the system
"@
	"Shimcache" = @"
This search filters on events related to Windows ShimCache artifacts, also known as the Application Compatibility Cache.

The Shim Cache contains a list of recently executed applications along with some associated metadata. The exact data recorded can vary between different versions of Windows, but typically it includes:
- Full file paths of executed applications
- The size of the executable
- The last modified date of the executable

The Shim Cache doesn't record the exact time of execution, nor does it track the number of times a program has been run. It also doesn't keep entries indefinitely. When the cache reaches its limit, older entries are discarded to make space for newer ones. The size of the cache, and therefore the number of entries it can hold, varies between Windows versions, but it can range from 512 entries on older versions of Windows up to thousands of entries on newer versions.

The Shim Cache data can be accessed via the Windows Registry. On Windows 7 systems, it's typically found in the "SYSTEM" hive under the key:
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility\AppCompatCache
On Windows 8 and later, it's found in the "SYSTEM" hive under the key:
- HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache\AppCompatCache
"@
	"UntrustedBinaries_V" = @"
This search filters on events related to Velociraptor Windows Persistence Pack.

name: Windows.Packs.Persistence
description: |
-Windows runs a number of services and binaries as part of the operating system. 
 Sometimes malware pretends to run as those well known names in order to hide itself in plain sight.
 For example, a malware service might call itself svchost.exe so it shows up in the process listing as a benign service.

 This artifact checks that the common systems binaries are signed. If a malware replaces these files or names itself in this way their signature might not be correct.

 Note that unfortunately Microsoft does not sign all their common binaries so many will not be signed (e.g. conhost.exe).

processNamesRegex	regex	
lsass|svchost|conhost|taskmgr|winlogon|wmiprv|dwm|csrss|velociraptor
A regex to select running processes which we consider should be trusted.

"@
	"Windows Defender" = @"
This search filters on Windows Defender events from Windows Defender Operational event Logs.

Specific Event IDs searched for along with a short description:
Event ID 1000: An antimalware scan finished
Event ID 1006: The antimalware engine found malware or other potentially unwanted software
Event ID 1007: The antimalware platform performed an action to protect your system from malware or other potentially unwanted software
Event ID 1008: The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed
Event ID 1009: The antimalware platform restored an item from quarantine
Event ID 1011: Microsoft Defender Antivirus has deleted an item from quarantine
Event ID 1012: The antimalware platform couldn't delete an item from quarantine
Event ID 1013: The antimalware platform deleted history of malware and other potentially unwanted software
Event ID 1015: Microsoft Defender Antivirus has detected a suspicious behavio
Event ID 1116: Microsoft Defender Antivirus has detected malware or other potentially unwanted software
Event ID 1117: Microsoft Defender Antivirus has taken action to protect this machine from malware or other potentially unwanted software
Event ID 1118: The antimalware platform attempted to perform an action to protect your system from malware or other potentially unwanted software, but the action failed
Event ID 1119: The antimalware platform encountered a critical error when trying to take action on malware or other potentially unwanted software
Event ID 1120: Microsoft Defender Antivirus has deduced the hashes for a threat resource
Event ID 3002: Real-time protection encountered an error and failed
Event ID 3007: Real-time protection recovered from a failure
Event ID 5000: Microsoft Defender Antivirus real-time protection scanning for malware and other potentially unwanted software was enabled
Event ID 5001: Real-time protection is disabled
Event ID 5004: The real-time protection configuration changed
Event ID 5007: Microsoft Defender Antivirus Configuration has changed
Event ID 5008: The antimalware engine encountered an error and failed
Event ID 5010: Scanning for malware and other potentially unwanted software is disabled
Event ID 5011: Scanning for viruses is enabled
Event ID 5012: Scanning for viruses is disabled
Event ID 5013: Tamper protection blocked a change to Microsoft Defender Antivirus.
"@
    # ... Add more mappings for other items ...
}
$queryMapping = @{
    "Amcache" = @{
        "Query" = "((FullPath:* and FileKeyLastWriteTimestamp:*) or (Binary:* and LastModified:*) or (EntryKey:* and KeyMTime:*))"
        "Columns" = @("'@timestamp'", "FileKeyLastWriteTimestamp", "LastModified", "KeyMTime", "Hostname", "Binary", "FullPath", "EntryKey", "EntryPath", "SHA1")
    }
    "Event Logs" = @{
        "Query" = "(Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx)"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "System.Computer", "EventId", "EventID", "Provider", "Channel", "UserId", "Username", "MapDescription", "Message", "RemoteHost", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "PayloadData6", "ExecutableInfo")  
    }
    "Event Logs Cleared" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and (Channel:(Security or System)) and (EventID:(1102 or 104) or EventId:(1102 or 104)))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "UserId", "System.Security.UserID", "Username", "EventData.SubjectUserName", "MapDescription", "Message", "PayloadData1")  
    }	
    "Failed Logins" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and (Channel:Security) and (EventID:4625 or EventId:4625))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "MapDescription", "Message", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "ExecutableInfo", "LogonType", "EventData.LogonType")  
    }
    "JumpList" = @{
        "Query" = "((SourceFile: *customDestinations-ms) or (SourceFile: *automaticDestinations-ms))"
        "Columns" = @("LastModified", "SourceModified", "Hostname", "MachineID", "LocalPath", "Arguments", "Path", "TargetIDAbsolutePath", "AppIdDescription")  
    }
    "Lateral Movement_V" = @{
        "Query" = "(Artifact:Windows.Packs.LateralMovement or collectionName:Windows.Packs.LateralMovement)"
        "Columns" = @("EventTime", "host.name", "IpAddress", "Port", "ProcessName", "SubjectUserName", "SubjectUserSid", "TargetServerName", "TargetUserName")  
    }
    "LNK" = @{
        "Query" = "(Artifact:Windows.Forensics.Lnk or collectionName:Windows.Forensics.Lnk or SourceFile:*.lnk)"
        "Columns" = @("SourceFile.Mtime", "SourceModified", "Hostname", "SourceFile.OSPath", "StringData.Arguments", "StringData.Name", "StringData.RelativePath", "StringData.TargetPath", "StringData.IconLocation", "LocalPath", "RelativePath", "TargetIDAbsolutePath")  
    }
    "Logins RDP" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and (Channel:(*TerminalServices* or *RdpCoreTS* or Security)) and (EventID:(21 or 23 or 24 or 25 or 1149 or 1024 or 68 or 98 or 131) or EventId:(21 or 23 or 24 or 25 or 1149 or 1024 or 68 or 98 or 131) or (EventID:4624 and (EventData.LogonType:10 or LogonType:10)) or (EventId:4624 and (PayloadData2.keyword : LogonType 10))))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "UserName", "UserData.EventXML.User",  "Message", "RemoteHost", "SourceIP", "UserData.EventXML.Address", "MapDescription", "PayloadData1", "UserData.EventXML.SessionID")  
    }
    "Logins RDP External IP" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and (Channel:(*TerminalServices* or *RdpCoreTS* or Security)) and (EventID:(21 or 24 or 25 or 1149 or 131) or EventId:(21 or 24 or 25 or 1149 or 131) or (EventID:4624 and (EventData.LogonType:10 or LogonType:10)) or (EventId:4624 and (PayloadData2.keyword : LogonType 10))) and (Not RemoteHost:(10.* or 127.* or 169.254.* or 172.16.* or 172.17.* or 172.18.* or 172.19.* or 172.20.* or 172.21.* or 172.22.* or 172.23.* or 172.24.* or 172.25.* or 172.26.* or 172.27.* or 172.28.* or 172.29.* or 172.30.* or 172.31.* or 192.168.* or LOCAL or fe80\:\: or fc00\:\: or fd00\:\: or \:\:1)) and (Not SourceIP:(10.* or 127.* or 169.254.* or 172.16.* or 172.17.* or 172.18.* or 172.19.* or 172.20.* or 172.21.* or 172.22.* or 172.23.* or 172.24.* or 172.25.* or 172.26.* or 172.27.* or 172.28.* or 172.29.* or 172.30.* or 172.31.* or 192.168.* or LOCAL or fe80\:\: or fc00\:\: or fd00\:\: or \:\:1)) and (Not UserData.EventXML.Address:(10.* or 127.* or 169.254.* or 172.16.* or 172.17.* or 172.18.* or 172.19.* or 172.20.* or 172.21.* or 172.22.* or 172.23.* or 172.24.* or 172.25.* or 172.26.* or 172.27.* or 172.28.* or 172.29.* or 172.30.* or 172.31.* or 192.168.* or LOCAL or fe80\:\: or fc00\:\: or fd00\:\: or \:\:1)))" 
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "UserName", "UserData.EventXML.User",  "Message", "RemoteHost", "SourceIP", "UserData.EventXML.Address", "MapDescription", "PayloadData1", "UserData.EventXML.SessionID")  
    }
    "Persistence_V" = @{
        "Query" = "(Artifact:Windows.Packs.Persistence or collectionName:Windows.Packs.Persistence)"
        "Columns" = @("EventTime", "host.name", "Name", "OSPath", "Enabled", "Program", "Debugger", "ConsumerDetails.Name", "ConsumerDetails.Category", "ConsumerDetails.CreatorSID", "ConsumerDetails.EventID", "ConsumerDetails.EventType", "ConsumerDetails.InsertionStringTemplates", "ConsumerDetails.NameOfUserSIDProperty")  
    }
    "PSlist_V" = @{
        "Query" = "(Artifact:Windows.System.Pslist or collectionName:Windows.System.Pslist)"
        "Columns" = @("host.name", "Username", "Name", "Exe", "CommandLine", "Authenticode.Trusted", "Hash.MD5", "Hash.SHA1", "Authenticode.ProgramName")  
    }	
    "Scheduled Task" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and ((Channel:Security and (EventID:(4698 or 4699 or 4702) or EventId:(4698 or 4699 or 4702))) or (Channel:*TaskScheduler* and (EventID:(100 or 102 or 106 or 110 or 129 or 140 or 141 or 142 or 200 or 201) or EventId:(100 or 102 or 106 or 110 or 129 or 140 or 141 or 142 or 200 or 201)))))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "UserId", "Username", "EventData.SubjectUserName", "MapDescription", "Message", "PayloadData1", "PayloadData2", "ExecutableInfo") 
	}		
    "Logins Security" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and (Channel:Security) and (EventID:(4624 or 4648 or 4778 or 4779) or EventId:(4624 or 4648 or 4778 or 4779)))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "Description", "UserName", "EventData.SubjectUserName", "MapDescription", "Message", "RemoteHost", "SourceIP",  "EventData.IpAddress", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "ExecutableInfo", "EventData.LogonType", "LogonType", "EventData.TargetServerName", "EventData.TargetUserName", "EventData.ProcessName")  
    }		
    "Prefetch" = @{
        "Query" = "((Artifact:Windows.Attack.Prefetch) or (Artifact:Windows.Timeline.Prefetch) or (ExecutableName:* and RunTime:*))"
        "Columns" = @("ModTime", "prefetch_mtime", "RunTime", "LastRun", "Hostname", "Name", "file_name", "ExecutableName", "RunCount", "message", "SourceFilename")  
    }
    "RecycleBin" = @{
        "Query" = "((Artifact:Windows.Forensics.RecycleBin or collectionName:Windows.Forensics.RecycleBin) or (DeletedOn:* and FileName:* and FileType:* and SourceName:*))"
        "Columns" = @("DeletedTimestamp", "DeletedOn", "Hostname", "OriginalFilePath", "OSPath", "RecyclePath", "FileName", "SourceName")  
    }
    "RDPAuth_V" = @{
        "Query" = "(Artifact:Windows.EventLogs.RDPAuth or collectionName:Windows.EventLogs.RDPAuth)"
        "Columns" = @("EventTime", "Computer", "UserName", "Description", "SourceIP", "LogonType")  
    }	
    "Service Creation" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and (Channel:(System or Security)) and (EventID:(4697 or 7000 or 7009 or 7045) or EventId:(4697 or 7000 or 7009 or 7045)))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "Username", "UserId", "MapDescription", "Message", "PayloadData1", "PayloadData2", "PayloadData3", "ExecutableInfo")  
    }	
    "Shimcache" = @{
        "Query" = "((Artifact:Windows.Registry.AppCompatCache or collectionName:Windows.Registry.AppCompatCache) or (LastModifiedTimeUTC:* and Duplicate:* and Path:* and SourceFile:*SYSTEM and ControlSet:*))"
        "Columns" = @("ModificationTime", "LastModifiedTimeUTC", "host.name", "Hostname", "Path", "Executed", "SourceFile")  
    }
    "UntrustedBinaries_V" = @{
        "Query" = "(Artifact:Windows.System.UntrustedBinaries or collectionName:Windows.System.UntrustedBinaries)"
        "Columns" = @("host.name", "Filename", "Trusted", "Issuer")  
    }	
    "Windows Defender" = @{
        "Query" = "((Artifact:Windows.EventLogs.Evtx or collectionName:Windows.EventLogs.Evtx or OSPath:*.evtx or SourceFile:*.evtx) and Channel:*Defender* and (EventID:(1000 or 1006 or 1007 or 1008 or 1009 or 1011 or 1012 or 1013 or 1015 or 1116 or 1117 or 1118 or 1119 or 1120 or 3002 or 3007 or 5000 or 5001 or 5004 or 5007 or 5008 or 5010 or 5011 or 5012 or 5013) or EventId:(1000 or 1006 or 1007 or 1008 or 1009 or 1011 or 1012 or 1013 or 1015 or 1116 or 1117 or 1118 or 1119 or 1120 or 3002 or 3007 or 5000 or 5001 or 5004 or 5007 or 5008 or 5010 or 5011 or 5012 or 5013)))"
        "Columns" = @("TimeCreated", "EventTime", "Computer", "EventId", "EventID", "UserName", "Username", "MapDescription", "Message", "PayloadData1", "PayloadData2", "PayloadData3", "PayloadData4", "PayloadData5", "ExecutableInfo")  
    }		
}

####End Elastic Search event handlers####

# Populate the controls with existing cases
PopulateCaseControls

$window.Add_Closed({
    Exit-Program
})

# Show the window
try {
    $window.ShowDialog()
} catch {
    Write-Host "Error showing dialog: $_"
}
