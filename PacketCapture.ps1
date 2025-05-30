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