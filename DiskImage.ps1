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