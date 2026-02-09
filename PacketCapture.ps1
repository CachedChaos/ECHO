$global:packetCaptureJob = $null
$global:jobTimer = $null

function Resolve-Etl2PcapngExecutablePath {
    param([string]$SelectedPath)

    if ([string]::IsNullOrWhiteSpace($SelectedPath)) {
        return $null
    }

    $resolvedPath = $SelectedPath.Trim().Trim('"')
    if ([string]::IsNullOrWhiteSpace($resolvedPath)) {
        return $null
    }

    if (-not (Test-Path -LiteralPath $resolvedPath -ErrorAction SilentlyContinue)) {
        return $resolvedPath
    }

    if (Test-Path -LiteralPath $resolvedPath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $resolvedPath
    }

    $candidatePath = Join-Path $resolvedPath "etl2pcapng.exe"
    if (Test-Path -LiteralPath $candidatePath -PathType Leaf -ErrorAction SilentlyContinue) {
        return $candidatePath
    }

    return $resolvedPath
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
    Update-Log "Trace output: $filePath" "PacketCaptureTextBox"

    # Start the job and the timer
    Start-PacketCaptureJob -TraceFilePath $filePath -CaptureTimeInSeconds $captureTimeInSeconds
}

function Start-PacketCaptureJob {
    param (
        [string]$TraceFilePath,
        [double]$CaptureTimeInSeconds
    )

    $existingJob = $null
    if ($global:packetCaptureJob) {
        $existingJob = Get-Job -Id $global:packetCaptureJob.Id -ErrorAction SilentlyContinue
    }

    if ($existingJob -and $existingJob.State -eq 'Running') {
        Update-Log "A packet capture job is already running." "PacketCaptureTextBox"
        $StartPacketCaptureButton.IsEnabled = $false
        return
    }

    try {
        $StartPacketCaptureButton.IsEnabled = $false

        # Start the packet capture job
        $global:packetCaptureJob = Start-Job -ScriptBlock {
            param($traceFilePath, $captureSeconds)
            $expectedCabPath = [System.IO.Path]::ChangeExtension($traceFilePath, "cab")

            Write-Output ("netsh trace start: {0}" -f $traceFilePath)
            $netshStartArgs = @(
                "trace", "start",
                "capture=yes",
                ("tracefile=`"{0}`"" -f $traceFilePath),
                "report=no",
                "maxsize=512",
                "correlation=no",
                "overwrite=no"
            )

            $null = & netsh @netshStartArgs
            $startExit = $LASTEXITCODE
            if ($startExit -ne 0) {
                throw "netsh trace start failed with exit code $startExit."
            }

            try {
                Start-Sleep -Seconds ([int][Math]::Round($captureSeconds, 0))
                Write-Output "Capture window ended. Finalizing trace (netsh trace stop)..."
            } finally {
                $stopProcess = Start-Process -FilePath "netsh.exe" -ArgumentList @("trace", "stop") -WindowStyle Hidden -PassThru
                $stopTimeoutSeconds = 300
                $stopCompleted = $stopProcess.WaitForExit($stopTimeoutSeconds * 1000)

                if (-not $stopCompleted) {
                    $cabReady = Test-Path -LiteralPath $expectedCabPath -PathType Leaf -ErrorAction SilentlyContinue
                    $etlReady = Test-Path -LiteralPath $traceFilePath -PathType Leaf -ErrorAction SilentlyContinue

                    if ($cabReady -and $etlReady) {
                        Write-Output "netsh trace stop timed out, but ETL/CAB are present. Marking capture as complete."
                        try { $stopProcess.Kill() } catch { }
                    } else {
                        try { $stopProcess.Kill() } catch { }
                        throw "netsh trace stop timed out after $stopTimeoutSeconds seconds and trace artifacts are incomplete."
                    }
                } else {
                    if ($stopProcess.ExitCode -ne 0) {
                        throw "netsh trace stop failed with exit code $($stopProcess.ExitCode)."
                    }
                }
                Write-Output "Trace finalization complete."
            }
        } -ArgumentList $TraceFilePath, $CaptureTimeInSeconds

        Update-Log "Packet capture job started. Job ID: $($global:packetCaptureJob.Id)" "PacketCaptureTextBox"

        # Create a timer to check the job status periodically
        if ($global:netTraceJobTimer) {
            $global:netTraceJobTimer.Stop()
            $global:netTraceJobTimer = $null
        }
        $global:netTraceJobTimer = New-Object System.Windows.Forms.Timer
        $global:netTraceJobTimer.Interval = 2000
        $global:netTraceJobTimer.Add_Tick({
            if (-not $global:packetCaptureJob) {
                $StartPacketCaptureButton.IsEnabled = $true
                $global:netTraceJobTimer.Stop()
                return
            }

            $updatedJob = Get-Job -Id $global:packetCaptureJob.Id -ErrorAction SilentlyContinue
            if (-not $updatedJob) {
                $StartPacketCaptureButton.IsEnabled = $true
                $global:packetCaptureJob = $null
                $global:netTraceJobTimer.Stop()
                return
            }

            $jobOutput = @(Receive-Job -Id $updatedJob.Id -ErrorAction SilentlyContinue | ForEach-Object { [string]$_ })
            foreach ($line in $jobOutput) {
                if (-not [string]::IsNullOrWhiteSpace($line)) {
                    Update-Log $line "PacketCaptureTextBox"
                }
            }

            if ($updatedJob.State -ne 'Running') {
                if ($updatedJob.State -eq 'Completed') {
                    Update-Log "Packet capture job has completed." "PacketCaptureTextBox"
                } else {
                    $failureReason = Get-JobFailureReasonText -Job $updatedJob
                    if ($failureReason) {
                        Update-Log "Packet capture job has stopped or failed: $failureReason" "PacketCaptureTextBox"
                    } else {
                        Update-Log "Packet capture job has stopped or failed." "PacketCaptureTextBox"
                    }
                }

                $StartPacketCaptureButton.IsEnabled = $true
                Remove-Job -Id $updatedJob.Id -Force -ErrorAction SilentlyContinue
                $global:packetCaptureJob = $null
                $global:netTraceJobTimer.Stop()
            }
        })
        $global:netTraceJobTimer.Start()
    } catch {
        $StartPacketCaptureButton.IsEnabled = $true
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
            $expandProcess = Start-Process -FilePath "expand.exe" -ArgumentList $expandArguments -Wait -NoNewWindow -PassThru
            if ($expandProcess.ExitCode -eq 0) {
                Update-Log "Extraction completed for $($cabFile.Name)" "PacketCaptureTextBox"
            } else {
                Update-Log "Extraction failed for $($cabFile.Name). expand.exe exit code: $($expandProcess.ExitCode)" "PacketCaptureTextBox"
            }
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
    $etl2PcapngPath = Resolve-Etl2PcapngExecutablePath -SelectedPath $Etl2PcapngPathTextBox.Text
    if ([string]::IsNullOrWhiteSpace($etl2PcapngPath) -or (-not (Test-Path -LiteralPath $etl2PcapngPath -PathType Leaf -ErrorAction SilentlyContinue)) -or (-not $etl2PcapngPath.EndsWith("etl2pcapng.exe"))) {
        Update-Log "etl2pcapng.exe path is not valid. Please provide the correct path." "PacketCaptureTextBox"
        return
    }
    $Etl2PcapngPathTextBox.Text = $etl2PcapngPath
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
            if ($LASTEXITCODE -eq 0) {
                Update-Log "Conversion completed for $($etlFile.Name)" "PacketCaptureTextBox"
            } else {
                Update-Log "Conversion failed for $($etlFile.Name). etl2pcapng exit code: $LASTEXITCODE" "PacketCaptureTextBox"
            }
        } else {
            Update-Log "The directory $pcapSubdirectoryPath already exists. Skipping conversion of $($etlFile.Name)." "PacketCaptureTextBox"
        }
    }
}

function Find-Etl2PcapngExecutable {
    $etl2PcapngPath = Get-ChildItem -Path $toolsDirectory -Filter "etl2pcapng.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

    # Check if the path ends with etl2pcapng.exe
    if ($etl2PcapngPath -and $etl2PcapngPath.EndsWith("etl2pcapng.exe")) {
        $Etl2PcapngPathTextBox.Text = $etl2PcapngPath
        $ConvertETL2PCAPButton.IsEnabled = $true
    } else {
        $Etl2PcapngPathTextBox.Text = ""
        $ConvertETL2PCAPButton.IsEnabled = $false
    }
}
