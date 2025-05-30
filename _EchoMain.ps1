Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName PresentationFramework

. "$PSScriptRoot\ArtifactCollection.ps1"
. "$PSScriptRoot\ArtifactProcessing.ps1"
. "$PSScriptRoot\DiskImage.ps1"
. "$PSScriptRoot\ElasticSearch.ps1"
. "$PSScriptRoot\EvidenceSync.ps1"
. "$PSScriptRoot\M365Collection.ps1"
. "$PSScriptRoot\MemoryCollection.ps1"
. "$PSScriptRoot\PacketCapture.ps1"
. "$PSScriptRoot\ThreatScanners.ps1"
. "$PSScriptRoot\ToolManagement.ps1"

#$executableDirectory = [System.AppDomain]::CurrentDomain.BaseDirectory
$executableDirectory = Split-Path -Parent $PSCommandPath
$toolsDirectory = Join-Path -Path $executableDirectory -ChildPath "Tools"

function Is-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Restart script with administrator rights if not already running as admin
if (-not (Is-Admin)) {
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

    # Attempt to stop transcription
    try {
        Stop-Transcript
        # Wait for the transcript to fully stop
        Start-Sleep -Seconds 2
    } catch {
        [System.Windows.MessageBox]::Show("Transcription already stopped or not started.")
    }
    
    if ($Global:CurrentCaseDirectory -ne $null) {
        $caseName = (Get-Item $Global:CurrentCaseDirectory).Name
        $date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
        $newFileName = "{0}_{1}.txt" -f $date, $caseName

        $transcriptLogsPath = Join-Path $Global:CurrentCaseDirectory "Transcript_Logs"
        if (!(Test-Path $transcriptLogsPath)) {
            New-Item -ItemType Directory -Path $transcriptLogsPath | Out-Null
        }

        $transcriptFile = "$Global:CurrentCaseDirectory\$caseName.txt"
        if (Test-Path $transcriptFile) {
            # Prepare the new file path with timestamp
            $newFilePath = Join-Path $transcriptLogsPath $newFileName
            Copy-Item -Path $transcriptFile -Destination $newFilePath

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
            Clear-Content -Path $transcriptFile -Force
        }
    }

    # Clear global variables
    Set-Variable -Name "Global:CurrentCaseName" -Value $null > $null
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
    }
    else {
        Update-Log "A case with the name '$CaseName' already exists in '$CaseLocation'." "caseCreationLogTextBox"
    }
	# Create text file in case directory
    $TextFilePath = Join-Path $CaseDirectory "$CaseName.txt"
    New-Item -ItemType File -Path $TextFilePath | Out-Null
    Update-Log "Text file '$CaseName.txt' created in case directory." "caseCreationLogTextBox"
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

    # Import cases from CSV and clean up whitespace
    $Cases = Import-Csv -Path "$executableDirectory\cases.csv" | ForEach-Object {
        [PSCustomObject]@{
            Name    = $_.Name.Trim()
            Path    = $_.Path.Trim()
            Created = $_.Created
        }
    }

    return $Cases
}

function Open-Case {
    param(
        [string]$CaseName
    )

    # If a case is already open, close and archive its transcript
    if ($Global:CurrentCaseDirectory) {
        try {
            Stop-Transcript
        } catch {
            [System.Windows.MessageBox]::Show("Error stopping current transcript. It may have been already stopped.")
        }

        # Archive transcript file
        try {
            $currentCaseName = (Get-Item $Global:CurrentCaseDirectory).Name
            $date = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
            $transcriptLogsPath = Join-Path $Global:CurrentCaseDirectory "Transcript_Logs"
            if (!(Test-Path $transcriptLogsPath)) {
                New-Item -ItemType Directory -Path $transcriptLogsPath | Out-Null
            }

            $transcriptFile = Join-Path $Global:CurrentCaseDirectory "$currentCaseName.txt"
            if (Test-Path $transcriptFile) {
                # Prepare the new file path with timestamp
                $newFileName = "{0}_{1}.txt" -f $date, $currentCaseName
                $newFilePath = Join-Path $transcriptLogsPath $newFileName
                Copy-Item -Path $transcriptFile -Destination $newFilePath

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
                Clear-Content -Path $transcriptFile -Force
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
    $SelectedCase = $Cases | Where-Object { $_.Name -eq $CaseName }

    # Check if the selected case exists
    if (-not $SelectedCase) {
        Update-Log "Case '$CaseName' not found in CSV file." "caseCreationLogTextBox"
        return
    }

    # Construct case directory path and set global variable
    $CaseDirectory = $SelectedCase.Path

    if (Test-Path $CaseDirectory) {
        Set-Variable -Name "Global:CurrentCaseName" -Value $SelectedCase.Name
        if (-not (Test-Path "$CaseDirectory\$($SelectedCase.Name).txt")) {
            New-Item -ItemType File -Path "$CaseDirectory\$($SelectedCase.Name).txt"
        }
        $TranscriptFile = Join-Path $CaseDirectory "$CaseName.txt"
        Start-Transcript -Path $TranscriptFile -Append
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
		$global:hasRunOnTabProcessArtifacts = $false
		$global:hasRunCollectPacketCaptur = $false
		$global:hasRunOnTabCollectSystemArtifacts = $false
		$global:hasRunOnTabCollectDiskImage = $false
		$global:hasRunOnTabCollectM365 = $false
		$global:hasRunOnTabCollectMemory = $false
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
    $openFileDialog.Title = "Select the case.txt file to import"
    $openFileDialog.Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"

    if ($openFileDialog.ShowDialog() -eq "OK") {
        $selectedFile = $openFileDialog.FileName
        $fileInfo = Get-Item $selectedFile

        if ($fileInfo) {
            $caseName = [System.IO.Path]::GetFileNameWithoutExtension($selectedFile)
            $casePath = [System.IO.Path]::GetDirectoryName($selectedFile)
            $caseCreated = $fileInfo.CreationTime

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
    $CaseName = $existingCasesComboBox.SelectedItem
    if (-not $CaseName) {
        [System.Windows.MessageBox]::Show("Please select a case from the dropdown.", "Error", "OK", "Error")
        return
    }
    Open-Case -CaseName $CaseName
}

function RemoveCaseButton_Click {
    # Get the selected case from the ComboBox
    $selectedItem = $existingCasesComboBox.SelectedItem

    if (-not [string]::IsNullOrWhiteSpace($selectedItem)) {
        # Remove "(Missing)" from the case name if present
        $selectedCaseName = $selectedItem -replace '\s+\(Missing\)$', ''

        # Get cases from CSV
        $cases = Get-Cases
        $remainingCases = $cases | Where-Object { $_.Name -ne $selectedCaseName }

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
			Status  = if (Test-Path $_.Path.Trim()) { "Exists" } else { "Missing" }
		}
	})

    # Bind the DataGrid to the cases
    $casesDataGrid.ItemsSource = $cases

    # Populate the combo box with all cases (both "Exists" and "Missing")
    $existingCasesComboBox.Items.Clear()
    foreach ($case in $cases) {
        $statusText = if ($case.Status -eq "Exists") { "" } else { " (Missing)" }
        $displayText = "$($case.Name)$statusText" # Add "(Missing)" for cases that don't exist
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

    if ($targetLog -ne $null) {
        $targetLog.AppendText("$message`r`n")
        # Set the caret position to the end and scroll to it
        $targetLog.CaretIndex = $targetLog.Text.Length
        $targetLog.ScrollToEnd()
    }
}

# Load the XAML layout
[xml]$xaml = @"

<Window 
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    x:Name="MainWindow" Title="ECHO - Evidence Collection &amp; Handling Orchestrator" Height="600" Width="800">
    <TabControl>
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
						<TextBlock Text="You can select a &lt;casename&gt;.txt file from the root of a case directory to import it into cases.csv" TextWrapping="Wrap" VerticalAlignment="Center" />
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
					<Run Text="The GUI may temporarily freeze during tool downloads or updates. Users are advised to be patient during these processes."/>
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
				<TextBox x:Name="ToolDescriptionTextBox" HorizontalAlignment="Center" VerticalAlignment="Top" Margin="10,100" Width="740" Height="300" TextWrapping="Wrap" IsReadOnly="True"/>		
				<Button x:Name="DownloadToolButton" Content="Download\Update" HorizontalAlignment="Left" VerticalAlignment="Top" Margin="215,65,0,0" Width="125" IsEnabled="False"/>				
				<!-- Log Display -->
				<TextBox x:Name="tabPageToolsTextBox" Text="" HorizontalAlignment="Center" Width="740" VerticalAlignment="Bottom" Height="100" Margin="10" TextWrapping="Wrap" IsReadOnly="True"/>
			</Grid>
		</TabItem>
		
    </TabControl>
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
- Enter a case name and select a storage directory. The program will create a dedicated folder for your case, complete with a tracking file ('<casename>.txt') for logging activities.

MANAGE EXISTING CASES:
- Access and manage your ongoing investigations. The 'Existing Cases' dropdown lets you open or delete cases. Deleting a case removes it from the program's records but doesn't delete the actual case folder.

IMPORT CASE:
- Easily integrate external cases into the program by importing a '<casename>.txt' file. This feature allows for seamless collaboration and case transfer.

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

        if (Test-Path $CaseDirectory) {
            # Call Open-Case with the case name
            Open-Case -CaseName $selectedCaseName
        } else {
            # Show an error message if the directory doesn't exist
            [System.Windows.MessageBox]::Show("The directory for case '$selectedCaseName' does not exist on disk.", "Error", 'OK', 'Error')
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
$TabProcessSystemArtifacts.Add_GotFocus({ OnTabProcessArtifacts_GotFocus })
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

# processingtools controls
$ProcessingToolComboBox.Add_SelectionChanged({
    switch ($ProcessingToolComboBox.SelectedItem.Content) {
        "BulkExtractor" {
            # Show BulkExtractor controls
            $ProcessBulkExtractorButton.Visibility = 'Visible'
			$BulkExtractorPathTextBox.Visibility = 'Visible'
			$BrowseBulkExtractorPathButton.Visibility = 'Visible'
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$BulkTextBlock.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Chainsaw" {
            # Show Chainsaw controls
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$ProcessChainsawButton.Visibility = 'Visible'
			$ChainsawPathTextBox.Visibility = 'Visible'
			$BrowseChainsawPathButton.Visibility = 'Visible'
			$ChainsawJson.Visibility = 'Visible'
			$ChawnsawTextBlock.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Zimmerman Tools" {
            # Show Zimmerman Tools Controls
            $ProcessZimmermanButton.Visibility = 'Visible'
            $ZtoolsComboBox.Visibility = 'Visible'
			$ZimmermanPathTextBox.Visibility = 'Visible'
			$BrowseZimmermanPathButton.Visibility = 'Visible'
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
            $ZimmermanTextBlock.Visibility = 'Visible'
			$UpdateZimmermanButton.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Extract Archives" {
            # Show Elastic Controls
			$Process7zipButton.Visibility = 'Visible'
			$SevenzipPathTextBox.Visibility = 'Visible'
			$Browse7zipPathButton.Visibility = 'Visible'
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$sevenzipTextBlock.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Geolocate IPs" {
            # Show Geolocate Controls
			$GeoLocateButton.Visibility = 'Visible'
			$GeoLite2CityDBPathTextBox.Visibility = 'Visible'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Visible'
			$CheckVirusTotal.Visibility = 'Visible'
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$GeolocateTextBlock.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Plaso Timeline" {
            # Show Plaso Controls
			$ProcessPlasoButton.Visibility = 'Visible'
			$PlasoPathTextBox.Visibility = 'Visible'
			$BrowsePlasoPathButton.Visibility = 'Visible'
			$PlasoDateRangeCheckBox.Visibility = 'Visible'
			$PlasoStartDate.Visibility = 'Visible'
			$PlasoStartDatePicker.Visibility = 'Visible'
			$PlasoEndDate.Visibility = 'Visible'
			$PlasoEndDatePicker.Visibility = 'Visible'
			$PsortOnlyCheckBox.Visibility = 'Visible'
			$PlasoTextBlock.Visibility = 'Visible'
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$sqlitePathTextBox.Visibility = 'Visible'

            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Hayabusa" {
            # Show Hayabusa Controls
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$ProcessHayabusaButton.Visibility = 'Visible'
			$HayabusaPathTextBox.Visibility = 'Visible'
			$BrowseHayabusaPathButton.Visibility = 'Visible'
			$HayabusaDateRangeCheckBox.Visibility = 'Visible'
			$HayabusaStartDate.Visibility = 'Visible'
			$HayabusaStartDatePicker.Visibility = 'Visible'
			$HayabusaEndDate.Visibility = 'Visible'
			$HayabusaEndDatePicker.Visibility = 'Visible'
			$HayabusaGeoDBCheckBox.Visibility = 'Visible'
			$HayabusaTextBlock.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Zircolite" {
            # Show Zircolite Controls
			$ProcessToolLocation.Visibility = 'Visible'
			$ProcessToolExtraArguments.Visibility = 'Visible'
			$ProcessZircoliteButton.Visibility = 'Visible'
			$ZircolitePathTextBox.Visibility = 'Visible'
			$BrowseZircolitePathButton.Visibility = 'Visible'
			$ZircolitejsonCheckBox.Visibility = 'Visible'
			$ZircoliteRules.Visibility = 'Visible'
			$ZircoliteRulesComboBox.Visibility = 'Visible'
			$ZircoliteTemplates.Visibility = 'Visible'
			$ZircoliteTemplatesComboBox.Visibility = 'Visible'
			$ZircoliteDateRangeCheckBox.Visibility = 'Visible'
			$ZircoliteStartDate.Visibility = 'Visible'
			$ZircoliteStartDatePicker.Visibility = 'Visible'
			$ZircoliteEndDate.Visibility = 'Visible'
			$ZircoliteEndDatePicker.Visibility = 'Visible'
			$ZircoliteTextBlock.Visibility = 'Visible'
			$UpdateZircoliteButton.Visibility = 'Visible'
			$ZircolitepackageCheckBox.Visibility = 'Visible'
			$ZircolitesysmonCheckBox.Visibility = 'Visible'

            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
			$ProcessTimelineArtifactsButton.Visibility = 'Collapsed'
			$IncludeChainsaw.Visibility = 'Collapsed'
			$IncludeHayabusa.Visibility = 'Collapsed'
			$IncludeZimmerman.Visibility = 'Collapsed'
			$IncludeZircolite.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$ExportTimelineArtifactsButton.Visibility = 'Collapsed'
			$TimelineArtifactsStartDate.Visibility = 'Collapsed'
			$TimelineArtifactsStartDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactsEndDate.Visibility = 'Collapsed'
			$TimelineArtifactsEndDatePicker.Visibility = 'Collapsed'
			$TimelineArtifactTextBlock.Visibility = 'Collapsed'
			$sqlitePathTextBox.Visibility = 'Collapsed'
			$BrowsesqlitePathButton.Visibility = 'Collapsed'
			$TimelineDateRangeCheckBox.Visibility = 'Collapsed'
			$TimelineDateIOCCheckBox.Visibility = 'Collapsed'
			$OpenCustomTimelineIOCsButton.Visibility = 'Collapsed'
        }
        "Timeline Artifacts" {
            # Show Timeline Artifacts controls
			$ProcessTimelineArtifactsButton.Visibility = 'Visible'
			$IncludeChainsaw.Visibility = 'Visible'
			$IncludeHayabusa.Visibility = 'Visible'
			$IncludeZimmerman.Visibility = 'Visible'
			$IncludeZircolite.Visibility = 'Visible'
			$TimelineArtifactTextBlock.Visibility = 'Visible'
			$ExportTimelineArtifactsButton.Visibility = 'Visible'
			$TimelineArtifactsStartDate.Visibility = 'Visible'
			$TimelineArtifactsStartDatePicker.Visibility = 'Visible'
			$TimelineArtifactsEndDate.Visibility = 'Visible'
			$TimelineArtifactsEndDatePicker.Visibility = 'Visible'
			$TimelineArtifactTextBlock.Visibility = 'Visible'
			$sqlitePathTextBox.Visibility = 'Visible'
			$BrowsesqlitePathButton.Visibility = 'Visible'
			$ProcessToolLocation.Visibility = 'Visible'
			$TimelineDateRangeCheckBox.Visibility = 'Visible'
			$TimelineDateIOCCheckBox.Visibility = 'Visible'
			$OpenCustomTimelineIOCsButton.Visibility = 'Visible'
			
            # Hide other controls
            $ProcessBulkExtractorButton.Visibility = 'Collapsed'
			$BulkExtractorPathTextBox.Visibility = 'Collapsed'
			$BrowseBulkExtractorPathButton.Visibility = 'Collapsed'
			$ProcessToolExtraArguments.Visibility = 'Collapsed'
			$BulkTextBlock.Visibility = 'Collapsed'
            $ProcessZimmermanButton.Visibility = 'Collapsed'
            $ZimmermanTextBlock.Visibility = 'Collapsed'
			$UpdateZimmermanButton.Visibility = 'Collapsed'
            $ZtoolsComboBox.Visibility = 'Collapsed'
			$ZimmermanPathTextBox.Visibility = 'Collapsed'
			$BrowseZimmermanPathButton.Visibility = 'Collapsed'
			$GeoLocateButton.Visibility = 'Collapsed'
			$GeoLite2CityDBPathTextBox.Visibility = 'Collapsed'
			$BrowseGeoLite2CityDBPathButton.Visibility = 'Collapsed'
			$GeolocateTextBlock.Visibility = 'Collapsed'
			$CheckVirusTotal.Visibility = 'Collapsed'
			$Process7zipButton.Visibility = 'Collapsed'
			$SevenzipPathTextBox.Visibility = 'Collapsed'
			$Browse7zipPathButton.Visibility = 'Collapsed'
			$sevenzipTextBlock.Visibility = 'Collapsed'
			$ProcessPlasoButton.Visibility = 'Collapsed'
			$PlasoPathTextBox.Visibility = 'Collapsed'
			$BrowsePlasoPathButton.Visibility = 'Collapsed'
			$PlasoDateRangeCheckBox.Visibility = 'Collapsed'
			$PlasoStartDate.Visibility = 'Collapsed'
			$PlasoStartDatePicker.Visibility = 'Collapsed'
			$PlasoEndDate.Visibility = 'Collapsed'
			$PlasoEndDatePicker.Visibility = 'Collapsed'
			$PsortOnlyCheckBox.Visibility = 'Collapsed'
			$PlasoTextBlock.Visibility = 'Collapsed'
			$ProcessHayabusaButton.Visibility = 'Collapsed'
			$HayabusaPathTextBox.Visibility = 'Collapsed'
			$BrowseHayabusaPathButton.Visibility = 'Collapsed'
			$HayabusaDateRangeCheckBox.Visibility = 'Collapsed'
			$HayabusaStartDate.Visibility = 'Collapsed'
			$HayabusaStartDatePicker.Visibility = 'Collapsed'
			$HayabusaEndDate.Visibility = 'Collapsed'
			$HayabusaEndDatePicker.Visibility = 'Collapsed'
			$HayabusaGeoDBCheckBox.Visibility = 'Collapsed'
			$HayabusaTextBlock.Visibility = 'Collapsed'
			$ProcessChainsawButton.Visibility = 'Collapsed'
			$ChainsawPathTextBox.Visibility = 'Collapsed'
			$BrowseChainsawPathButton.Visibility = 'Collapsed'
			$ChainsawJson.Visibility = 'Collapsed'
			$ChawnsawTextBlock.Visibility = 'Collapsed'
			$ProcessZircoliteButton.Visibility = 'Collapsed'
			$ZircolitePathTextBox.Visibility = 'Collapsed'
			$BrowseZircolitePathButton.Visibility = 'Collapsed'
			$ZircolitejsonCheckBox.Visibility = 'Collapsed'
			$ZircoliteRules.Visibility = 'Collapsed'
			$ZircoliteRulesComboBox.Visibility = 'Collapsed'
			$ZircoliteTemplates.Visibility = 'Collapsed'
			$ZircoliteTemplatesComboBox.Visibility = 'Collapsed'
			$ZircoliteDateRangeCheckBox.Visibility = 'Collapsed'
			$ZircoliteStartDate.Visibility = 'Collapsed'
			$ZircoliteStartDatePicker.Visibility = 'Collapsed'
			$ZircoliteEndDate.Visibility = 'Collapsed'
			$ZircoliteEndDatePicker.Visibility = 'Collapsed'
			$ZircoliteTextBlock.Visibility = 'Collapsed'
			$UpdateZircoliteButton.Visibility = 'Collapsed'
			$ZircolitepackageCheckBox.Visibility = 'Collapsed'
			$ZircolitesysmonCheckBox.Visibility = 'Collapsed'
        }
    }
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
    $selectedItem = $sender.SelectedItem.Content

    # Update the ToolDescriptionTextBox based on the selected item
    $ToolDescriptionTextBox.Text = $toolDescriptions[$selectedItem]
	$DownloadToolButton.IsEnabled = $selectedItem -ne $null
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
})
$QuickSyncCheckBox.Add_Unchecked({
    $QuickSyncComboBox.IsEnabled = $false
	$SyncProcessingPathTextBox.IsEnabled = $true
	$SyncProcessingPathButton.IsEnabled = $true
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
    $baseDirectories = @(
        "$($CurrentCaseDirectory)\M365Evidence",
        "$($CurrentCaseDirectory)\MemoryArtifacts\VolOutput",
        "$($CurrentCaseDirectory)\SystemArtifacts\ProcessedArtifacts\Zimmermantools",
		"$($CurrentCaseDirectory)\SystemArtifacts\ProcessedArtifacts\Hayabusa"		
    )

    # Prepare an empty array for all directories including _plaso directories
    $directories = @()
    $directories += $baseDirectories
    $plasoDirectories = Get-ChildItem -Path "$($CurrentCaseDirectory)\SystemArtifacts\ProcessedArtifacts" -Directory |
                        Where-Object { $_.Name -like "*_plaso" }

    foreach ($dir in $plasoDirectories) {
        $directories += $dir.FullName
    }

    foreach ($dir in $directories) {
        if (Test-Path $dir) {
            $dirName = Split-Path $dir -Leaf
            $QuickSyncComboBox.Items.Add($dirName)
            $global:quickSyncPaths[$dirName] = $dir
        }
    }
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
$TabUseThreatScanners.Add_GotFocus({ OnTabThreatScanners_GotFocus })
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

$ThreatScanToolComboBox.Add_SelectionChanged({
    switch ($ThreatScanToolComboBox.SelectedItem.Content) {
        "ClamAV" {
            # Show ClamAV controls
            $ScanToolLocation.Visibility = 'Visible'
			$ScanningToolExtraArguments.Visibility = 'Visible'
			$ScanClamAVButton.Visibility = 'Visible'
			$ClamAVPathTextBox.Visibility = 'Visible'
			$BrowseClamAVPathButton.Visibility = 'Visible'
			$ClamAVTextBlock.Visibility = 'Visible'
			$UpdateclamAVButton.Visibility = 'Visible'
			$clamAVUpdaterPathTextBox.Visibility = 'Visible'
			$BrowseclamAVUpdatePathButton.Visibility = 'Visible'
			$FreshclamLocation.Visibility = 'Visible'			
            # Hide other controls
			$LokiPathTextBox.Visibility = 'Collapsed'
			$BrowseLokiPathButton.Visibility = 'Collapsed'
			$LokiTextBlock.Visibility = 'Collapsed'
			$ScanLokiButton.Visibility = 'Collapsed'
			$ProcscanCheckbox.Visibility = 'Collapsed'
			$IntenseScanCheckbox.Visibility = 'Collapsed'
			$VulnchecksCheckbox.Visibility = 'Collapsed'	
			$UpdateLokiButton.Visibility = 'Collapsed'
			$LokiUpdaterPathTextBox.Visibility = 'Collapsed'
			$BrowseLokiUpdatePathButton.Visibility = 'Collapsed'	
			$LokiUpgraderLocation.Visibility = 'Collapsed'			
        }
        "Loki" {

            # Show Loki Controls			
            $ScanToolLocation.Visibility = 'Visible'
			$ScanningToolExtraArguments.Visibility = 'Visible'
			$ScanLokiButton.Visibility = 'Visible'			
			$LokiPathTextBox.Visibility = 'Visible'
			$BrowseLokiPathButton.Visibility = 'Visible'
			$LokiTextBlock.Visibility = 'Visible'
			$ProcscanCheckbox.Visibility = 'Visible'
			$IntenseScanCheckbox.Visibility = 'Visible'
			$VulnchecksCheckbox.Visibility = 'Visible'
			$UpdateLokiButton.Visibility = 'Visible'
			$LokiUpdaterPathTextBox.Visibility = 'Visible'
			$BrowseLokiUpdatePathButton.Visibility = 'Visible'			
			$LokiUpgraderLocation.Visibility = 'Visible'	
            # Hide other controls
			$ClamAVPathTextBox.Visibility = 'Collapsed'
			$BrowseClamAVPathButton.Visibility = 'Collapsed'
			$ClamAVTextBlock.Visibility = 'Collapsed'	
			$ScanClamAVButton.Visibility = 'Collapsed'	
			$UpdateclamAVButton.Visibility = 'Collapsed'
			$clamAVUpdaterPathTextBox.Visibility = 'Collapsed'
			$BrowseclamAVUpdatePathButton.Visibility = 'Collapsed'
			$FreshclamLocation.Visibility = 'Collapsed'				
        }
    }
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