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