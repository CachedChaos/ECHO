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
    if (Get-Command -Name Initialize-SystemArtifactsTargetList -ErrorAction SilentlyContinue) {
        Initialize-SystemArtifactsTargetList
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
