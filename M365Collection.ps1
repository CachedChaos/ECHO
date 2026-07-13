$global:ipAddressesFilePath = $null
$global:usernamesFilePath = $null

# Define a global variable to track the pipe server job
$Global:PipeServerJob = $null
$Global:M365ExchangeConnected = $false
$Global:M365GraphConnected = $false

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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Triage collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Unified Audit Logs collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Admin Logs collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Inbox Rules collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Forwarding Rules collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "M365 Info collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Message Trace collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Azure log collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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
            Write-M365JobOutput -JobInfo $job -LogTarget "M365TextBox"
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Last Password Change collection finished: $($job.JobName) (status: $($updatedJob.State))" "M365TextBox"
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

function Write-M365JobOutput {
    param(
        [hashtable]$JobInfo,
        [string]$LogTarget = "M365TextBox"
    )

    if (-not $JobInfo -or $JobInfo.OutputLogged) {
        return
    }

    try {
        $currentJob = Get-Job -Id $JobInfo.JobObject.Id -ErrorAction SilentlyContinue
        if ($currentJob -and $currentJob.State -eq 'Failed') {
            $JobInfo.Failed = $true
            $reason = $currentJob.ChildJobs[0].JobStateInfo.Reason
            Update-Log "FAILED: $($JobInfo.JobName)$(if ($reason) { ": $($reason.Message)" })" $LogTarget
        } else {
            $JobInfo.Failed = $false
        }
        $jobOutput = Receive-Job -Id $JobInfo.JobObject.Id -Keep -ErrorAction SilentlyContinue
        if ($jobOutput) {
            foreach ($entry in @($jobOutput)) {
                if (-not [string]::IsNullOrWhiteSpace([string]$entry)) {
                    if ([string]$entry -match 'Microsoft Graph authentication expired or is unavailable') {
                        $Global:M365GraphConnected = $false
                        Set-M365GraphButtonStates -Enabled $false
                    }
                    foreach ($line in ([string]$entry -split "(`r`n|`n|`r)")) {
                        if (-not [string]::IsNullOrWhiteSpace($line)) {
                            Update-Log $line $LogTarget
                        }
                    }
                }
            }
        } elseif ($JobInfo.JobObject.ChildJobs -and $JobInfo.JobObject.ChildJobs[0].JobStateInfo.Reason) {
            Update-Log "Job failure details for $($JobInfo.JobName): $($JobInfo.JobObject.ChildJobs[0].JobStateInfo.Reason.Message)" $LogTarget
        }
    } catch {
        Update-Log "Failed to read output for $($JobInfo.JobName): $($_.Exception.Message)" $LogTarget
    }

    $JobInfo.OutputLogged = $true
}

function Get-M365PendingClientJobs {
    # Prune completed jobs that were already logged so long-running GUI sessions
    # do not accumulate PowerShell job objects indefinitely.
    foreach ($collectionName in @(
        'm365triageJobs','m365UALJobs','m365AdminLogsJobs','m365InboxRulesJobs',
        'm365ForwardingRulesJobs','m365InfoJobs','m365MessageTraceJobs',
        'm365AzureLogsJobs','m365LastPassJobs','m365GraphConnectionJobs','m365UALParseJobs'
    )) {
        $collection = @((Get-Variable -Name $collectionName -Scope Global -ValueOnly -ErrorAction SilentlyContinue))
        $retained = @()
        foreach ($jobInfo in $collection) {
            if (-not $jobInfo -or -not $jobInfo.JobObject) { continue }
            $job = Get-Job -Id $jobInfo.JobObject.Id -ErrorAction SilentlyContinue
            $processed = $jobInfo.DataAdded -or $jobInfo.Processed
            if ($job -and $processed -and $job.State -in @('Completed','Failed','Stopped')) {
                Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
            } else {
                $retained += $jobInfo
            }
        }
        Set-Variable -Name $collectionName -Scope Global -Value $retained
    }

    $jobCollections = @(
        $Global:m365triageJobs,
        $Global:m365UALJobs,
        $Global:m365AdminLogsJobs,
        $Global:m365InboxRulesJobs,
        $Global:m365ForwardingRulesJobs,
        $Global:m365InfoJobs,
        $Global:m365MessageTraceJobs,
        $Global:m365AzureLogsJobs,
        $Global:m365LastPassJobs,
        $Global:m365GraphConnectionJobs,
        $Global:m365UALParseJobs
    )

    $pendingJobs = @()
    foreach ($jobCollection in $jobCollections) {
        foreach ($jobInfo in @($jobCollection)) {
            if (-not $jobInfo -or -not $jobInfo.JobObject) {
                continue
            }

            $updatedJob = Get-Job -Id $jobInfo.JobObject.Id -ErrorAction SilentlyContinue
            if (-not $updatedJob) {
                continue
            }

            if ($updatedJob.State -notin @('Completed', 'Failed', 'Stopped')) {
                $pendingJobs += [PSCustomObject]@{
                    Id    = $updatedJob.Id
                    Name  = $jobInfo.JobName
                    State = $updatedJob.State
                }
            }
        }
    }

    return $pendingJobs
}

function Test-M365CanStartRequest {
    param(
        [Parameter(Mandatory = $true)]
        [string]$RequestedAction
    )

    foreach ($pipeValue in @($Global:CurrentCaseDirectory, $Global:usernamesFilePath, $Global:ipAddressesFilePath)) {
        if ($pipeValue -and [string]$pipeValue -match ';') {
            Update-Log "Microsoft 365 paths cannot contain semicolons because they are reserved by the worker protocol: $pipeValue" "M365TextBox"
            return $false
        }
    }

    $pendingJobs = @(Get-M365PendingClientJobs)
    if ($pendingJobs.Count -eq 0) {
        return $true
    }

    $pendingSummary = ($pendingJobs | Select-Object -ExpandProperty Name) -join ', '
    Update-Log "Another Microsoft 365 collection is still running: $pendingSummary. Please let it finish before starting $RequestedAction." "M365TextBox"
    return $false
}

# Graph authentication runs through the same backend process that performs the
# collections. The GUI only monitors this client job, so WPF remains responsive.
$Global:m365GraphConnectionJobs = @()
$m365GraphConnectionJobTimer = New-Object System.Windows.Forms.Timer
$m365GraphConnectionJobTimer.Interval = 1000
$m365GraphConnectionJobTimer.Add_Tick({
    foreach ($jobInfo in @($Global:m365GraphConnectionJobs)) {
        if (-not $jobInfo -or $jobInfo.Processed) { continue }
        $job = Get-Job -Id $jobInfo.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $job) { continue }

        $newOutput = @(Receive-Job -Id $job.Id -ErrorAction SilentlyContinue)
        foreach ($entry in $newOutput) {
            $message = [string]$entry
            $jobInfo.Output += $message
            if ($message -match '^GRAPH_AUTH_INFO\|(.*)$') {
                $authMessage = $matches[1]
                Update-Log $authMessage "M365TextBox"
                if ($authMessage -match 'https://[^\s]+') {
                    Open-M365DefaultBrowserUrl -Url $matches[0] | Out-Null
                }
            }
        }

        if ($job.State -notin @('Completed', 'Failed', 'Stopped')) { continue }

        $response = @($jobInfo.Output) -join "`r`n"
        if ($job.State -eq 'Completed' -and $response -match 'GRAPH_AUTH_SUCCESS\|(.+)') {
            $Global:M365GraphConnected = $true
            Update-Log "Connected to Microsoft Graph as $($matches[1])." "M365TextBox"
            Update-Log "Graph-backed collections are ready." "M365TextBox"
        } else {
            $Global:M365GraphConnected = $false
            if ([string]::IsNullOrWhiteSpace($response)) {
                $jobReason = $job.ChildJobs[0].JobStateInfo.Reason
                $response = if ($jobReason) {
                    $jobReason.Message
                } else {
                    'The Graph connection job failed without returning details.'
                }
            }
            Update-Log "Failed to connect to Microsoft Graph: $response" "M365TextBox"
        }
        Set-M365GraphButtonStates -Enabled $Global:M365GraphConnected
        $ConnectGraphButton.IsEnabled = $Global:M365ExchangeConnected
        $jobInfo.Processed = $true
    }

    if (@($Global:m365GraphConnectionJobs | Where-Object { -not $_.Processed }).Count -eq 0) {
        $m365GraphConnectionJobTimer.Stop()
    }
})

$Global:m365UALParseJobs = @()
$m365UALParseJobTimer = New-Object System.Windows.Forms.Timer
$m365UALParseJobTimer.Interval = 1000
$m365UALParseJobTimer.Add_Tick({
    $remaining = 0
    foreach ($jobInfo in @($Global:m365UALParseJobs)) {
        if (-not $jobInfo -or $jobInfo.Processed) { continue }
        $job = Get-Job -Id $jobInfo.JobObject.Id -ErrorAction SilentlyContinue
        if (-not $job -or $job.State -notin @('Completed','Failed','Stopped')) {
            $remaining++
            continue
        }
        $output = @(Receive-Job -Id $job.Id -ErrorAction SilentlyContinue)
        foreach ($line in $output) {
            if (-not [string]::IsNullOrWhiteSpace([string]$line)) {
                Update-Log ([string]$line) 'M365TextBox'
            }
        }
        if ($job.State -eq 'Failed') {
            $reason = $job.ChildJobs[0].JobStateInfo.Reason
            Update-Log "UAL parsing failed$(if ($reason) { ": $($reason.Message)" })." 'M365TextBox'
        } else {
            Update-Log "UAL parsing finished. Results are in $($jobInfo.OutputPath)" 'M365TextBox'
        }
        $jobInfo.Processed = $true
        Remove-Job -Id $job.Id -Force -ErrorAction SilentlyContinue
    }
    if ($remaining -eq 0) {
        $m365UALParseJobTimer.Stop()
        $Global:m365UALParseJobs = @($Global:m365UALParseJobs | Where-Object { -not $_.Processed })
        if ($ParseUALButton) { $ParseUALButton.IsEnabled = $true }
    }
})

function ParseUALButton_Click {
    if (-not (Test-M365CanStartRequest -RequestedAction 'UAL parsing')) { return }

    $ualPath = Join-Path $Global:CurrentCaseDirectory 'M365Evidence\UnifiedAuditLogs'
    if (-not (Test-Path -LiteralPath $ualPath -PathType Container)) {
        Update-Log "Unified Audit Logs folder was not found: $ualPath" 'M365TextBox'
        return
    }
    $inputFiles = @(Get-ChildItem -LiteralPath $ualPath -Filter '*.csv' -File -ErrorAction SilentlyContinue)
    if ($inputFiles.Count -eq 0) {
        Update-Log "No CSV files were found in $ualPath" 'M365TextBox'
        return
    }

    $useGeoLite = [bool]$ParseUALGeoLiteCheckBox.IsChecked
    $overwriteParsed = [bool]$ParseUALOverwriteCheckBox.IsChecked
    $cityDatabase = $null
    if ($useGeoLite) {
        $cityDatabase = Get-ChildItem -LiteralPath $toolsDirectory -Filter 'GeoLite2-City.mmdb' -File -Recurse -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty FullName -First 1
        if (-not $cityDatabase) {
            Update-Log "Use GeoLite was selected, but GeoLite2-City.mmdb was not found under $toolsDirectory. Download it from Tool Management or clear the option." 'M365TextBox'
            return
        }
        if (-not (Get-Command -Name python -ErrorAction SilentlyContinue)) {
            Update-Log "Use GeoLite requires Python with the geoip2 package, but python was not found in PATH." 'M365TextBox'
            return
        }
    }

    $outputPath = Join-Path $ualPath 'Parsed_UAL'
    if (-not $overwriteParsed) {
        $inputFiles = @($inputFiles | Where-Object {
            $expectedOutput = Join-Path $outputPath ("{0}_Parsed.csv" -f $_.BaseName)
            -not (Test-Path -LiteralPath $expectedOutput -PathType Leaf)
        })
        if ($inputFiles.Count -eq 0) {
            Update-Log "All Unified Audit Log CSV files have already been parsed. Select 'Overwrite parsed files' to rebuild them." 'M365TextBox'
            return
        }
    }
    $ParseUALButton.IsEnabled = $false
    Update-Log "Parsing $($inputFiles.Count) new Unified Audit Log CSV file(s) into $outputPath$(if ($useGeoLite) { ' with GeoLite enrichment' })$(if ($overwriteParsed) { ' (overwrite enabled)' })." 'M365TextBox'

    $job = Start-Job -ScriptBlock {
        param($ualPath, $outputPath, $useGeoLite, $cityDatabase, $overwriteParsed)

        function Add-FlattenedValue {
            param($Value, [string]$Prefix, [System.Collections.IDictionary]$Target)
            if ($null -eq $Value) {
                $Target[$Prefix] = $null
                return
            }
            if ($Value -is [System.Collections.IDictionary]) {
                foreach ($key in $Value.Keys) {
                    Add-FlattenedValue -Value $Value[$key] -Prefix "$Prefix.$key" -Target $Target
                }
                return
            }
            if ($Value -isnot [string] -and $Value -is [System.Collections.IEnumerable]) {
                $index = 0
                foreach ($item in $Value) {
                    Add-FlattenedValue -Value $item -Prefix "$Prefix[$index]" -Target $Target
                    $index++
                }
                if ($index -eq 0) { $Target[$Prefix] = '' }
                return
            }
            $properties = @($Value.PSObject.Properties | Where-Object { $_.MemberType -in @('NoteProperty','Property') })
            if ($properties.Count -gt 0 -and $Value -isnot [string] -and $Value -isnot [datetime]) {
                foreach ($property in $properties) {
                    Add-FlattenedValue -Value $property.Value -Prefix "$Prefix.$($property.Name)" -Target $Target
                }
                return
            }
            $Target[$Prefix] = $Value
        }

        function Get-NormalizedClientIP {
            param([System.Collections.IDictionary]$Values)
            foreach ($name in @('AuditData.ClientIP','AuditData.ClientIPAddress','AuditData.ActorIpAddress','ClientIP')) {
                if (-not $Values.Contains($name) -or [string]::IsNullOrWhiteSpace([string]$Values[$name])) { continue }
                $candidate = ([string]$Values[$name]).Trim()
                if ($candidate -match '^\[([^\]]+)\](?::\d+)?$') { return $matches[1] }
                if ($candidate -match '^(\d{1,3}(?:\.\d{1,3}){3}):\d+$') { return $matches[1] }
                return $candidate
            }
            return $null
        }

        if (-not (Test-Path -LiteralPath $outputPath)) {
            New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
        }

        $geoMap = @{}
        if ($useGeoLite) {
            & python -c 'import geoip2.database' 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw "Python package 'geoip2' is required for GeoLite enrichment. Install it with: python -m pip install geoip2"
            }
            $allIPs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($file in Get-ChildItem -LiteralPath $ualPath -Filter '*.csv' -File) {
                $expectedOutput = Join-Path $outputPath ("{0}_Parsed.csv" -f $file.BaseName)
                if (-not $overwriteParsed -and (Test-Path -LiteralPath $expectedOutput -PathType Leaf)) { continue }
                foreach ($row in Import-Csv -LiteralPath $file.FullName) {
                    try {
                        $audit = $row.AuditData | ConvertFrom-Json -ErrorAction Stop
                        $values = @{}
                        Add-FlattenedValue -Value $audit -Prefix 'AuditData' -Target $values
                        $ip = Get-NormalizedClientIP -Values $values
                        if ($ip) { $null = $allIPs.Add($ip) }
                    } catch {}
                }
            }
            $ipInput = Join-Path $env:TEMP ("echo_ual_ips_{0}.txt" -f [guid]::NewGuid())
            $geoOutput = Join-Path $env:TEMP ("echo_ual_geo_{0}.csv" -f [guid]::NewGuid())
            try {
                $allIPs | Set-Content -LiteralPath $ipInput -Encoding UTF8
                $python = @'
import csv, ipaddress, sys
import geoip2.database
db_path, input_path, output_path = sys.argv[1:4]
with geoip2.database.Reader(db_path) as reader, open(input_path, encoding='utf-8-sig') as src, open(output_path, 'w', newline='', encoding='utf-8') as dst:
    fields = ['IP','City','State','Country','CountryCode','Latitude','Longitude']
    writer = csv.DictWriter(dst, fieldnames=fields)
    writer.writeheader()
    for raw in src:
        ip = raw.strip()
        if not ip:
            continue
        row = dict.fromkeys(fields, '')
        row['IP'] = ip
        try:
            address = ipaddress.ip_address(ip)
            if address.is_private or address.is_loopback or address.is_link_local or address.is_multicast:
                writer.writerow(row)
                continue
            result = reader.city(ip)
            row.update(City=result.city.name or '', State=result.subdivisions.most_specific.name or '', Country=result.country.name or '', CountryCode=result.country.iso_code or '', Latitude=result.location.latitude or '', Longitude=result.location.longitude or '')
        except Exception:
            pass
        writer.writerow(row)
'@
                & python -c $python $cityDatabase $ipInput $geoOutput
                if ($LASTEXITCODE -ne 0) { throw 'GeoLite lookup process failed.' }
                foreach ($geo in Import-Csv -LiteralPath $geoOutput) { $geoMap[$geo.IP] = $geo }
            } finally {
                Remove-Item -LiteralPath $ipInput,$geoOutput -Force -ErrorAction SilentlyContinue
            }
        }

        foreach ($file in Get-ChildItem -LiteralPath $ualPath -Filter '*.csv' -File) {
            $outputFile = Join-Path $outputPath ("{0}_Parsed.csv" -f $file.BaseName)
            if (-not $overwriteParsed -and (Test-Path -LiteralPath $outputFile -PathType Leaf)) {
                Write-Output "Skipped already parsed file: $($file.Name)"
                continue
            }
            $flattenedRows = [System.Collections.Generic.List[object]]::new()
            $columnSet = [ordered]@{}
            foreach ($row in Import-Csv -LiteralPath $file.FullName) {
                $flat = [ordered]@{}
                foreach ($property in $row.PSObject.Properties) {
                    if ($property.Name -ne 'AuditData') {
                        $flat[$property.Name] = $property.Value
                        $columnSet[$property.Name] = $true
                    }
                }
                try {
                    $audit = $row.AuditData | ConvertFrom-Json -ErrorAction Stop
                    Add-FlattenedValue -Value $audit -Prefix 'AuditData' -Target $flat
                } catch {
                    $flat['AuditData.ParseError'] = $_.Exception.Message
                    $flat['AuditData.Raw'] = $row.AuditData
                }
                $flat['ParsedClientIP'] = Get-NormalizedClientIP -Values $flat
                foreach ($geoColumn in @('GeoCity','GeoState','GeoCountry','GeoCountryCode','GeoLatitude','GeoLongitude')) { $flat[$geoColumn] = '' }
                if ($useGeoLite -and $flat['ParsedClientIP'] -and $geoMap.ContainsKey([string]$flat['ParsedClientIP'])) {
                    $geo = $geoMap[[string]$flat['ParsedClientIP']]
                    $flat['GeoCity'] = $geo.City; $flat['GeoState'] = $geo.State; $flat['GeoCountry'] = $geo.Country
                    $flat['GeoCountryCode'] = $geo.CountryCode; $flat['GeoLatitude'] = $geo.Latitude; $flat['GeoLongitude'] = $geo.Longitude
                }
                foreach ($key in $flat.Keys) { $columnSet[$key] = $true }
                $flattenedRows.Add($flat)
            }

            $priority = @('ParsedClientIP','GeoCity','GeoState','GeoCountry','GeoCountryCode','GeoLatitude','GeoLongitude')
            $columns = @($columnSet.Keys | Where-Object { $_ -notin $priority })
            $insertAfter = [array]::IndexOf($columns, 'AuditData.ClientIP')
            if ($insertAfter -lt 0) { $insertAfter = [array]::IndexOf($columns, 'AuditData.ClientIPAddress') }
            if ($insertAfter -lt 0) { $insertAfter = [Math]::Min($columns.Count - 1, 4) }
            $beforeColumns = if ($insertAfter -ge 0) { @($columns[0..$insertAfter]) } else { @() }
            $afterColumns = if (($insertAfter + 1) -lt $columns.Count) { @($columns[($insertAfter + 1)..($columns.Count - 1)]) } else { @() }
            $columns = @($beforeColumns + $priority + $afterColumns | Select-Object -Unique)
            $flattenedRows | ForEach-Object {
                $record = [ordered]@{}
                foreach ($column in $columns) { $record[$column] = $_[$column] }
                [PSCustomObject]$record
            } | Export-Csv -LiteralPath $outputFile -NoTypeInformation -Encoding UTF8
            Write-Output "Parsed $($flattenedRows.Count) row(s): $outputFile"
        }
    } -ArgumentList $ualPath, $outputPath, $useGeoLite, $cityDatabase, $overwriteParsed

    $Global:m365UALParseJobs += @{ JobObject = $job; JobName = "UALParser_$(Get-Date -Format 'yyyyMMdd_HHmmss')"; OutputPath = $outputPath; Processed = $false }
    $m365UALParseJobTimer.Start()
}

function Set-M365ExchangeButtonStates {
    param(
        [bool]$Enabled
    )

    foreach ($control in @(
        $CollectTriageButton,
        $CollectUALButton,
        $CollectAdminLogsButton,
        $CollectInboxRulesButton,
        $CollectForwardingRulesButton,
        $CollectM365InfoButton,
        $CollectMessageTraceButton,
        $TestClientConnectionButton
    )) {
        if ($control) {
            $control.IsEnabled = $Enabled
        }
    }

    if ($ConnectGraphButton) {
        $ConnectGraphButton.IsEnabled = $Enabled
    }
}

function Set-M365GraphButtonStates {
    param(
        [bool]$Enabled
    )

    foreach ($control in @(
        $CollectAzureLogsButton,
        $CollectLastPasswordChangeButton
    )) {
        if ($control) {
            # The click handlers can initiate or retry Graph authentication.
            # Keep these controls available once the Exchange pipe is ready.
            $control.IsEnabled = $Global:M365ExchangeConnected
        }
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

    Set-M365ExchangeButtonStates -Enabled $Global:M365ExchangeConnected
    Set-M365GraphButtonStates -Enabled $Global:M365GraphConnected
}

function Open-M365DefaultBrowserUrl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Url,
        [string]$LogTarget = "M365TextBox"
    )

    try {
        Update-Log "Opening $Url in your default browser..." $LogTarget
        Start-Process $Url | Out-Null
        return $true
    } catch {
        Update-Log "Failed to open $Url in the default browser: $($_.Exception.Message)" $LogTarget
        return $false
    }
}

function Open-M365SecurityInfoButton_Click {
    Open-M365DefaultBrowserUrl -Url "https://aka.ms/mysecurityinfo" | Out-Null
}

function ConnectClientButton_Click {
    $M365TextBox.Text = ""
    if (-not (Test-M365CanStartRequest -RequestedAction "a new Microsoft 365 connection")) {
        return
    }
    $Global:M365GraphConnected = $false
    Set-M365GraphButtonStates -Enabled $false
    $disconnectGraphCommand = Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue
    if ($disconnectGraphCommand) {
        try {
            Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
        } catch {
        }
    }
    $ConnectClientButton.IsEnabled = $false 
    # Required modules
    $requiredModules = @("ExchangeOnlineManagement")
    Update-Log "Preparing Exchange Online connection..." "M365TextBox"

    # Check if the required modules are installed and construct the command string
    foreach ($module in $requiredModules) {
        if (!(Get-Module -ListAvailable -Name $module)) {
            Update-Log "Required module '$module' is not installed." "M365TextBox"
            # Prompt user to install the module
            $message = "The module '$module' is required but not installed. Do you want to install it now? This is required for the connection."
            $caption = "Module Installation Required"
            $buttons = [System.Windows.MessageBoxButton]::YesNo
            $icon = [System.Windows.MessageBoxImage]::Warning
            $result = [System.Windows.MessageBox]::Show($message, $caption, $buttons, $icon)

            if ($result -eq 'Yes') {
                # Install the module
                Update-Log "Installing module '$module'. This can take a little while and may appear idle during download/install." "M365TextBox"
                Install-Module -Name $module -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Update-Log "Module '$module' installed." "M365TextBox"
            } else {
                # If the user chooses not to install, log it and return
                Update-Log "Module '$module' installation skipped by user." "M365TextBox"
                return
            }
        } else {
            Update-Log "Module '$module' is available." "M365TextBox"
        }
    }

    # Generate a unique pipe name
    $Global:pipeName = "M365Pipe_$([System.Guid]::NewGuid().ToString())"

    try {
        # Start the named pipe server if not already started
        if (-not $Global:PipeServerJob) {
            $Global:PipeServerJob = Start-NamedPipeServer -pipeName $Global:pipeName
        }

        Update-Log "Starting Exchange Online sign-in..." "M365TextBox"
        # Send a request to the server to execute Connect-Client function
        $command = "Connect-Client"
        $response = Send-CommandToProcess -pipeName $Global:pipeName -commandToSend $command
        Update-Log $response "M365TextBox"
        if ($response -match "aka\.ms/mysecurityinfo" -or $response -match "Unsupported browser" -or $response -match "not supported in this sign-in window") {
            Open-M365DefaultBrowserUrl -Url "https://aka.ms/mysecurityinfo" | Out-Null
        }
        if ($response -match "^Connected to Exchange Online") {
            $Global:M365ExchangeConnected = $true
            Set-M365ExchangeButtonStates -Enabled $true
            Set-M365GraphButtonStates -Enabled $Global:M365GraphConnected
            Update-Log "Exchange-backed collections are ready. Graph-backed collections stay separate and will prompt only when needed." "M365TextBox"
        } else {
            $Global:M365ExchangeConnected = $false
            Set-M365ExchangeButtonStates -Enabled $false
        }

    } catch {
        # Log the exception
        $Global:M365ExchangeConnected = $false
        Set-M365ExchangeButtonStates -Enabled $false
        Update-Log "Failed to send commands: $_" "M365TextBox"
    }
    $ConnectClientButton.IsEnabled = $true
}

function ConnectGraphButton_Click {
    if (-not $Global:M365ExchangeConnected) {
        Update-Log "Connect Exchange first. Graph-backed collections can be connected separately after Exchange is ready." "M365TextBox"
        return
    }

    if (-not (Test-M365CanStartRequest -RequestedAction "a Microsoft Graph connection")) {
        return
    }

    $ConnectGraphButton.IsEnabled = $false

    try {
        if (-not (Get-Module -ListAvailable -Name 'Microsoft.Graph.Authentication')) {
            $message = "Microsoft Graph PowerShell is not installed for this Windows user. Install Microsoft.Graph now?"
            $caption = "Module Installation Required"
            $buttons = [System.Windows.MessageBoxButton]::YesNo
            $icon = [System.Windows.MessageBoxImage]::Warning
            $result = [System.Windows.MessageBox]::Show($message, $caption, $buttons, $icon)

            if ($result -eq 'Yes') {
                Update-Log "Installing or repairing 'Microsoft.Graph'. This can take a little while and may appear idle during download/install." "M365TextBox"
                Install-Module -Name "Microsoft.Graph" -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Update-Log "Microsoft.Graph installation completed." "M365TextBox"
            } else {
                Update-Log "Module 'Microsoft.Graph' installation skipped by user." "M365TextBox"
                return
            }
        }

        Update-Log "Starting Microsoft Graph device-code sign-in..." "M365TextBox"
        Update-Log "ECHO will display the Microsoft sign-in code below and open the device-login page." "M365TextBox"
        $pipeName = $Global:pipeName
        $job = Start-Job -ScriptBlock {
            param($pipeName)
            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
            try {
                $pipeClient.Connect(30000)
                $writer = New-Object System.IO.StreamWriter($pipeClient)
                $writer.AutoFlush = $true
                $reader = New-Object System.IO.StreamReader($pipeClient)
                $writer.WriteLine('Connect-Graph')
                while (($line = $reader.ReadLine()) -ne 'END_OF_MESSAGE') {
                    if ($null -eq $line) { break }
                    if (-not [string]::IsNullOrWhiteSpace($line)) {
                        Write-Output $line
                    }
                }
            } finally {
                $pipeClient.Dispose()
            }
        } -ArgumentList $pipeName
        $Global:m365GraphConnectionJobs += @{
            JobObject = $job
            JobName = "GraphConnection_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
            Processed = $false
            Output = @()
        }
        $m365GraphConnectionJobTimer.Start()
        return
    } catch {
        $Global:M365GraphConnected = $false
        Set-M365GraphButtonStates -Enabled $false
        Update-Log $_.Exception.Message "M365TextBox"
    }

    $ConnectGraphButton.IsEnabled = $Global:M365ExchangeConnected
}

function Start-NamedPipeServer {
    param($pipeName)
    
    Write-Host "Starting Named Pipe Server..."

    $serverScriptBlock = {
        param([string]$pipeName)
		$serverShouldRun = $true
		$script:graphConnected = $false
		$graphScopes = @(
			"AuditLog.Read.All",
			"Directory.Read.All",
			"Organization.Read.All",
			"User.Read.All",
			"UserAuthenticationMethod.Read.All"
		)

		function Write-M365CollectionNotice {
			param(
				[Parameter(Mandatory = $true)]
				[string]$Path,
				[Parameter(Mandatory = $true)]
				[string]$Message
			)

			$directory = Split-Path -Path $Path -Parent
			if ($directory -and -not (Test-Path $directory)) {
				New-Item -ItemType Directory -Path $directory | Out-Null
			}

			Set-Content -Path $Path -Value $Message
		}

		function Export-M365CollectionData {
			param(
				[Parameter(Mandatory = $true)]
				[AllowNull()]
				[object]$Data,
				[Parameter(Mandatory = $true)]
				[string]$CsvPath,
				[Parameter(Mandatory = $true)]
				[string]$EmptyMessage
			)

			$items = @($Data | Where-Object { $null -ne $_ })
			if ($items.Count -gt 0) {
				$items | Export-Csv -Path $CsvPath -NoTypeInformation
				return "Saved $($items.Count) record(s) to $CsvPath"
			}

			$noticePath = [System.IO.Path]::ChangeExtension($CsvPath, ".txt")
			Write-M365CollectionNotice -Path $noticePath -Message $EmptyMessage
			return $EmptyMessage
		}

		function Convert-M365UnifiedAuditRecord {
			param(
				[Parameter(Mandatory = $true)]
				$Record
			)

			$auditData = $null
			try {
				if ($Record.AuditData) {
					$auditData = $Record.AuditData | ConvertFrom-Json -ErrorAction Stop
				}
			} catch {
				$auditData = $null
			}

			[PSCustomObject]@{
				RecordType          = $Record.RecordType
				CreationDate        = $Record.CreationDate
				UserIds             = $Record.UserIds
				Operations          = $Record.Operations
				Identity            = $Record.Identity
				ResultIndex         = $Record.ResultIndex
				ResultCount         = $Record.ResultCount
				Workload            = if ($auditData) { $auditData.Workload } else { $null }
				Operation           = if ($auditData) { $auditData.Operation } else { $null }
				UserId              = if ($auditData) { $auditData.UserId } else { $null }
				ClientIP            = if ($auditData) { $auditData.ClientIP } else { $null }
				ObjectId            = if ($auditData) { $auditData.ObjectId } else { $null }
				MailboxOwnerUPN     = if ($auditData) { $auditData.MailboxOwnerUPN } else { $null }
				DestMailboxOwnerUPN = if ($auditData) { $auditData.DestMailboxOwnerUPN } else { $null }
				FolderPathName      = if ($auditData) { $auditData.FolderPathName } else { $null }
				ItemSubject         = if ($auditData) { $auditData.ItemSubject } else { $null }
				LogonType           = if ($auditData) { $auditData.LogonType } else { $null }
				ExternalAccess      = if ($auditData) { $auditData.ExternalAccess } else { $null }
				AuditData           = $Record.AuditData
			}
		}

		function Invoke-UnifiedAuditLogPagedSearch {
			param(
				[Parameter(Mandatory = $true)]
				[datetime]$StartDate,
				[Parameter(Mandatory = $true)]
				[datetime]$EndDate,
				[string]$RecordType,
				[string[]]$Operations,
				[string[]]$UserIds,
				[string[]]$ObjectIds,
				[string[]]$IPAddresses,
				[string]$SessionPrefix = "ECHOUAL",
				[int]$ResultSize = 5000
			)

			$sessionId = "{0}_{1}" -f $SessionPrefix, ([guid]::NewGuid().ToString())
			$results = @()

			do {
				$searchParams = @{
					StartDate      = $StartDate
					EndDate        = $EndDate
					SessionId      = $sessionId
					SessionCommand = "ReturnLargeSet"
					ResultSize     = $ResultSize
				}

				if (-not [string]::IsNullOrWhiteSpace($RecordType)) {
					$searchParams.RecordType = $RecordType
				}
				if ($Operations -and $Operations.Count -gt 0) {
					$searchParams.Operations = $Operations
				}
				if ($UserIds -and $UserIds.Count -gt 0) {
					$searchParams.UserIds = $UserIds
				}
				if ($ObjectIds -and $ObjectIds.Count -gt 0) {
					$searchParams.ObjectIds = $ObjectIds
				}
				if ($IPAddresses -and $IPAddresses.Count -gt 0) {
					$searchParams.IPAddresses = $IPAddresses
				}

				$batch = @(Search-UnifiedAuditLog @searchParams)
				if (-not $batch -or $batch.Count -eq 0) {
					break
				}

				$results += $batch
			} while ($batch.Count -ge $ResultSize -and $results.Count -lt 50000)

			if ($results.Count -ge 50000) {
				throw "Unified Audit Log query reached the 50,000-record session limit for $StartDate through $EndDate. Use a narrower date range before treating the collection as complete."
			}

			return $results
		}

		function Invoke-AdaptiveUnifiedAuditLogSearch {
			param(
				[Parameter(Mandatory = $true)]
				[datetime]$StartDate,
				[Parameter(Mandatory = $true)]
				[datetime]$EndDate,
				[string]$RecordType,
				[string[]]$Operations,
				[string[]]$UserIds,
				[string[]]$ObjectIds,
				[string[]]$IPAddresses,
				[int]$InitialWindowDays = 7,
				[int]$MinimumWindowSeconds = 1,
				[string]$SessionPrefix = 'ECHOAdaptiveUAL'
			)

			function Invoke-AdaptiveWindow {
				param([datetime]$WindowStart, [datetime]$WindowEnd)

				$queryParams = @{
					StartDate     = $WindowStart
					EndDate       = $WindowEnd
					SessionPrefix = $SessionPrefix
					ResultSize    = 5000
				}
				if ($RecordType) { $queryParams.RecordType = $RecordType }
				if ($Operations) { $queryParams.Operations = $Operations }
				if ($UserIds) { $queryParams.UserIds = $UserIds }
				if ($ObjectIds) { $queryParams.ObjectIds = $ObjectIds }
				if ($IPAddresses) { $queryParams.IPAddresses = $IPAddresses }

				try {
					return @(Invoke-UnifiedAuditLogPagedSearch @queryParams)
				} catch {
					if ($_.Exception.Message -notmatch '50,000-record session limit') { throw }
					$durationSeconds = ($WindowEnd - $WindowStart).TotalSeconds
					if ($durationSeconds -le $MinimumWindowSeconds) {
						throw "Unified Audit Log volume exceeds 50,000 records between $WindowStart and $WindowEnd. ECHO stopped rather than return incomplete evidence. Use the Microsoft 365 Management Activity API for this extreme interval."
					}

					$midpoint = $WindowStart.AddTicks([long](($WindowEnd.Ticks - $WindowStart.Ticks) / 2))
					Write-Host "UAL window saturated; splitting $WindowStart through $WindowEnd at $midpoint"
					$left = @(Invoke-AdaptiveWindow -WindowStart $WindowStart -WindowEnd $midpoint)
					$right = @(Invoke-AdaptiveWindow -WindowStart $midpoint -WindowEnd $WindowEnd)
					return @($left + $right)
				}
			}

			$allResults = @()
			$windowStart = $StartDate
			while ($windowStart -lt $EndDate) {
				$windowEnd = $windowStart.AddDays($InitialWindowDays)
				if ($windowEnd -gt $EndDate) { $windowEnd = $EndDate }
				$allResults += @(Invoke-AdaptiveWindow -WindowStart $windowStart -WindowEnd $windowEnd)
				$windowStart = $windowEnd
			}

			# Split windows overlap at the midpoint by design so boundary events cannot
			# fall through a gap. Remove only records with the same stable identity.
			return @($allResults | Sort-Object Identity, CreationDate, RecordType, Operations -Unique)
		}

		function Get-GraphAuthenticationMethodSummary {
			param(
				[string]$UserId
			)

			$methodTypes = @()
			try {
				$methods = Get-MgUserAuthenticationMethod -UserId $UserId -ErrorAction Stop
				foreach ($method in $methods) {
					if ($method.AdditionalProperties -and $method.AdditionalProperties.ContainsKey('@odata.type')) {
						$typeName = [string]$method.AdditionalProperties['@odata.type']
						$typeName = $typeName -replace '^#microsoft\.graph\.', ''
						if (-not [string]::IsNullOrWhiteSpace($typeName)) {
							$methodTypes += $typeName
						}
					}
				}
			} catch {
				return @{
					MFAMethodTypes = ''
					MFAStatus = 'Unknown'
					Error = $_.Exception.Message
				}
			}

			$uniqueTypes = $methodTypes | Sort-Object -Unique
			return @{
				MFAMethodTypes = ($uniqueTypes -join ', ')
				MFAStatus = if ($uniqueTypes.Count -gt 0) { 'Registered' } else { 'NotRegistered' }
				Error = ''
			}
		}

		function Ensure-GraphConnection {
			$enableAutosaveCommand = Get-Command -Name Enable-MgContextAutosave -ErrorAction SilentlyContinue
			if ($enableAutosaveCommand) {
				try {
					Enable-MgContextAutosave -Scope CurrentUser | Out-Null
				} catch {
				}
			}

			if ($script:graphConnected) {
				try {
					Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null
					return $true
				} catch {
					$script:graphConnected = $false
				}
			}

			$graphContext = $null
			try {
				$graphContext = Get-MgContext
				if ($graphContext -and $graphContext.Account -and $graphContext.Scopes) {
					try {
						Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null
						$script:graphConnected = $true
						return $true
					} catch {
						if ($_.Exception.Message -notmatch "Authentication needed|Please call Connect-MgGraph|not authenticated") {
							throw
						}
					}
				}
			} catch {
			}

			throw 'Microsoft Graph authentication expired or is unavailable. Use Connect Graph and complete device-code sign-in again.'
		}

		function Connect-Graph {
			param($Writer)
			try {
				$disconnectGraphCommand = Get-Command -Name Disconnect-MgGraph -ErrorAction SilentlyContinue
				if ($disconnectGraphCommand) {
					Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
				}

				Connect-MgGraph -Scopes $graphScopes -NoWelcome -ContextScope CurrentUser -UseDeviceCode -ErrorAction Stop 6>&1 |
					ForEach-Object {
						$message = [string]$_
						foreach ($messageLine in ($message -split "(`r`n|`n|`r)")) {
							if (-not [string]::IsNullOrWhiteSpace($messageLine)) {
								$Writer.WriteLine("GRAPH_AUTH_INFO|$messageLine")
							}
						}
					}
				Get-MgOrganization -Top 1 -ErrorAction Stop | Out-Null
				$script:graphConnected = $true
				$context = Get-MgContext
				return "GRAPH_AUTH_SUCCESS|$($context.Account)"
			} catch {
				$script:graphConnected = $false
				return "GRAPH_AUTH_FAILED|$($_.Exception.Message)"
			}
		}

		function Convert-GraphSignInLog {
			param($LogEntry)

			[PSCustomObject]@{
				CreatedDateTime        = $LogEntry.CreatedDateTime
				UserDisplayName        = $LogEntry.UserDisplayName
				UserPrincipalName      = $LogEntry.UserPrincipalName
				AppDisplayName         = $LogEntry.AppDisplayName
				IpAddress              = $LogEntry.IpAddress
				ClientAppUsed          = $LogEntry.ClientAppUsed
				ConditionalAccessStatus = $LogEntry.ConditionalAccessStatus
				RiskDetail             = $LogEntry.RiskDetail
				RiskLevelAggregated    = $LogEntry.RiskLevelAggregated
				RiskState              = $LogEntry.RiskState
				CorrelationId          = $LogEntry.CorrelationId
				StatusErrorCode        = if ($LogEntry.Status) { $LogEntry.Status.ErrorCode } else { $null }
				StatusFailureReason    = if ($LogEntry.Status) { $LogEntry.Status.FailureReason } else { $null }
				DeviceOperatingSystem  = if ($LogEntry.DeviceDetail) { $LogEntry.DeviceDetail.OperatingSystem } else { $null }
				DeviceBrowser          = if ($LogEntry.DeviceDetail) { $LogEntry.DeviceDetail.Browser } else { $null }
				LocationCity           = if ($LogEntry.Location) { $LogEntry.Location.City } else { $null }
				LocationState          = if ($LogEntry.Location) { $LogEntry.Location.State } else { $null }
				LocationCountry        = if ($LogEntry.Location) { $LogEntry.Location.CountryOrRegion } else { $null }
			}
		}

		function Convert-GraphDirectoryAuditLog {
			param($LogEntry)

			$initiatedByUser = $null
			$initiatedByApp = $null
			if ($LogEntry.InitiatedBy) {
				$initiatedByUser = $LogEntry.InitiatedBy.User.UserPrincipalName
				$initiatedByApp = $LogEntry.InitiatedBy.App.DisplayName
			}

			[PSCustomObject]@{
				ActivityDateTime          = $LogEntry.ActivityDateTime
				ActivityDisplayName       = $LogEntry.ActivityDisplayName
				Category                  = $LogEntry.Category
				LoggedByService           = $LogEntry.LoggedByService
				OperationType             = $LogEntry.OperationType
				Result                    = $LogEntry.Result
				ResultReason              = $LogEntry.ResultReason
				CorrelationId             = $LogEntry.CorrelationId
				InitiatedByUserPrincipalName = $initiatedByUser
				InitiatedByAppDisplayName = $initiatedByApp
				TargetResources           = (($LogEntry.TargetResources | ForEach-Object { $_.DisplayName }) -join '; ')
			}
		}

        # Define embedded functions
        function Connect-Client {
            try {
                Connect-ExchangeOnline -ShowBanner:$false | Out-Null
                return "Connected to Exchange Online. Microsoft Graph will be used from the signed-in user session."
            } catch {
                $message = $_.Exception.Message
                if ($message -match "Unsupported browser" -or $message -match "not supported or up-to-date") {
                    return "Failed to connect: Microsoft requested an authentication method setup flow that is not supported in this sign-in window. Complete the setup in your default browser at https://aka.ms/mysecurityinfo, then retry."
                }
                return "Failed to connect: $message"
            }
        }

		function Test-M365Connection {
			try {
				# Execute commands and collect responses
				$graphResponse = try {
					$graphContext = Get-MgContext
					if ($graphContext -and $graphContext.Account) {
						$tenant = Get-MgOrganization | Select-Object -First 1
						"Connected to Microsoft Graph tenant: " + $tenant.DisplayName
					} else {
						"Microsoft Graph is not connected in the current user session"
					}
				} catch {
					"Microsoft Graph is not connected in the current user session"
				}
				$exchangeResponse = try { $orgConfig = Get-OrganizationConfig; "Connected to Exchange Online tenant: " + $orgConfig.DisplayName } catch { "Not connected to Exchange Online" }
				$auditLogResponse = try { $auditConfig = Get-AdminAuditLogConfig; if ($auditConfig.UnifiedAuditLogIngestionEnabled) { "Unified Audit Logs are enabled" } else { "Unified Audit Logs are not enabled" } } catch { "Failed to check Unified Audit Logs status" }
				$graphContext = Get-MgContext
				$permissionsResponse = if ($graphContext -and $graphContext.Scopes) {
					"Granted Microsoft Graph scopes: " + (($graphContext.Scopes | Sort-Object -Unique) -join ", ")
				} else {
					"Microsoft Graph scopes could not be determined"
				}
		
				# Combine all responses into a single string with newline characters
				$fullResponse = ($graphResponse, $exchangeResponse, $auditLogResponse, $permissionsResponse) -join "`r`n"
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
			$graphAvailableForTriage = $false
			try {
				$graphAvailableForTriage = Ensure-GraphConnection
			} catch {
				Write-Output "Microsoft Graph is not connected for triage. Graph-only collections will be skipped. Details: $($_.Exception.Message)"
			}
		

			# Define an array of function calls
			$functionCalls = @(
				{ Collect-InboxRules -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
				{ Collect-ForwardingRules -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
				{ Collect-AdminLogs -currentcasedirectory $currentcasedirectory },
				{ Collect-M365Info -currentcasedirectory $currentcasedirectory }, 
				{ Collect-UAL -Scope $defaultScope -currentcasedirectory $currentcasedirectory -usernamesFilePath $defaultUsernamesFilePath -IPScope $defaultIPScope -OperationsScope $defaultOperationsScope -ipAddressesFilePath $defaultIPsFilePath -StartDate $defaultStartDate }
			)

			if ($graphAvailableForTriage) {
				$functionCalls += @(
					{ Collect-AzureLogs -Scope $defaultScope -currentcasedirectory $currentcasedirectory },
					{ Collect-LastPasswordChange -Scope $defaultScope -currentcasedirectory $currentcasedirectory }
				)
			}
		
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
			return $responses
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
				$specifiedUsers = @(Get-Content $usernamesFilePath | ForEach-Object { $_.Trim() } | Where-Object { $_ })
				if ($specifiedUsers.Count -eq 0) { throw 'Custom Users was selected, but the user list is empty.' }
			}

			if ($IPScope -eq "Custom IPs") {
				$specifiedIPs = @(Get-Content $ipAddressesFilePath | ForEach-Object { $_.Trim() } | Where-Object { $_ })
				if ($specifiedIPs.Count -eq 0) { throw 'Custom IPs was selected, but the IP address list is empty.' }
			}

			if ($OperationsScope -eq "All Operations") {
				$operations = @("*")
				$allOperations = $true
			} elseif ($OperationsScope -eq "Mailbox Activities") {
				$operations = @(
					"MailItemsAccessed", "FolderBind", "MailboxLogin", "Send", "SendAs", "SendOnBehalf",
					"Create", "Update", "Move", "MoveToDeletedItems", "SoftDelete", "HardDelete",
					"New-InboxRule", "Set-InboxRule", "UpdateInboxRules"
				)
			} else {
				$operations = @("UserLoggedIn", "New-InboxRule", "Set-InboxRule", "Update-InboxRule", "AddOAuth2PermissionGrant")
			}

			$queryParams = @{
				StartDate         = [datetime]::ParseExact($startDate, "yyyy-MM-dd", $null)
				EndDate           = $endDate
				InitialWindowDays = if ($specifiedUsers) { 30 } else { 7 }
				SessionPrefix     = 'ECHOUAL'
			}
			if (-not $allOperations) { $queryParams.Operations = $operations }
			if ($specifiedUsers) { $queryParams.UserIds = $specifiedUsers }
			if ($specifiedIPs) { $queryParams.IPAddresses = $specifiedIPs }
			$allResults = @(Invoke-AdaptiveUnifiedAuditLogSearch @queryParams)

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
						$outputFileName = "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($user.Alias)_InboxRules.csv"
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
						$outputFileName = "$(Get-Date -Format 'yyyyMMdd_HHmmss')_$($user.Alias)_ForwardingRules.csv"
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
			
			$startDate = (Get-Date).AddDays(-90)
			$endDate = (Get-Date)
			
			try {
				$csvFilePath = Join-Path $adminAuditLogPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_AdminAuditLogs.csv"
				$adminAuditLogs = Invoke-AdaptiveUnifiedAuditLogSearch -StartDate $startDate -EndDate $endDate -RecordType "ExchangeAdmin" -InitialWindowDays 30 -SessionPrefix "ECHOAdminAudit"
				$normalizedAdminLogs = $adminAuditLogs | ForEach-Object { Convert-M365UnifiedAuditRecord -Record $_ }
				return (Export-M365CollectionData -Data $normalizedAdminLogs -CsvPath $csvFilePath -EmptyMessage "No Exchange admin audit events were returned from the unified audit log for the last 90 days. If you expected results, confirm unified audit ingestion and Purview audit permissions.")
			} catch {
				return "Failed to collect admin audit logs from the unified audit log: $($_.Exception.Message)"
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
			$timestampFormat = $endDate.ToString('yyyyMMdd_HHmmss')
			$useMessageTraceV2 = $null -ne (Get-Command Get-MessageTraceV2 -ErrorAction SilentlyContinue)
			$startDate = if ($useMessageTraceV2) { $endDate.AddDays(-90) } else { $endDate.AddDays(-10) }

			function Invoke-ECHOMessageTraceQuery {
				param(
					[string]$SenderAddress,
					[string]$RecipientAddress
				)

				$results = @()
				$windowStart = $startDate
				do {
					$windowEnd = if ($useMessageTraceV2 -and $windowStart.AddDays(10) -lt $endDate) {
						$windowStart.AddDays(10)
					} else {
						$endDate
					}

					$params = @{
						StartDate   = $windowStart
						EndDate     = $windowEnd
						ErrorAction = 'Stop'
					}
					if ($SenderAddress) { $params.SenderAddress = $SenderAddress }
					if ($RecipientAddress) { $params.RecipientAddress = $RecipientAddress }

					if ($useMessageTraceV2) {
						$params.ResultSize = 5000
						$batch = @(Get-MessageTraceV2 @params)
						if ($batch.Count -ge 5000) {
							throw "Message trace reached the 5,000-record limit for $windowStart through $windowEnd. Reduce the date window before treating this collection as complete."
						}
						$results += $batch
					} else {
						$results += @(Get-MessageTrace @params)
					}
					$windowStart = $windowEnd
				} while ($windowStart -lt $endDate)

				return @($results | Sort-Object MessageTraceId, RecipientAddress, Received -Unique)
			}
		
			switch ($Scope) {
				"Entire Tenant" {
					$allTraces = @(Invoke-ECHOMessageTraceQuery)
					$tenantAddresses = @{}
					Get-Mailbox -ResultSize Unlimited | ForEach-Object {
						$tenantAddresses[[string]$_.PrimarySmtpAddress] = $true
						if ($_.UserPrincipalName) { $tenantAddresses[[string]$_.UserPrincipalName] = $true }
					}
					$senderResults = @($allTraces | Where-Object { $tenantAddresses.ContainsKey([string]$_.SenderAddress) })
					$recipientResults = @($allTraces | Where-Object { $tenantAddresses.ContainsKey([string]$_.RecipientAddress) })
					
					$traceWindowDescription = if ($useMessageTraceV2) { "last 90 days" } else { "last 10 days because Get-MessageTraceV2 is not available in the current Exchange module" }
					$senderMessage = Export-M365CollectionData -Data $senderResults -CsvPath (Join-Path $messageTracePath "${timestampFormat}_MessageTrace_Tenant_Sender.csv") -EmptyMessage "No sender-side message trace results were returned for the $traceWindowDescription."
					$recipientMessage = Export-M365CollectionData -Data $recipientResults -CsvPath (Join-Path $messageTracePath "${timestampFormat}_MessageTrace_Tenant_Recipient.csv") -EmptyMessage "No recipient-side message trace results were returned for the $traceWindowDescription."

					return ("Message trace command used: " + ($(if ($useMessageTraceV2) { "Get-MessageTraceV2" } else { "Get-MessageTrace" })) + "`r`n" + $senderMessage + "`r`n" + $recipientMessage)
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
		
						$senderMessageTraces = @(Invoke-ECHOMessageTraceQuery -SenderAddress $user.UserPrincipalName)
						$recipientMessageTraces = @(Invoke-ECHOMessageTraceQuery -RecipientAddress $user.UserPrincipalName)
		
						Export-M365CollectionData -Data $senderMessageTraces -CsvPath (Join-Path $messageTracePath "${timestampFormat}_$($user.Alias)_MessageTrace_Sender.csv") -EmptyMessage "No sender-side message trace results were returned for $($user.UserPrincipalName) in the last 90 days." | Out-Null
						Export-M365CollectionData -Data $recipientMessageTraces -CsvPath (Join-Path $messageTracePath "${timestampFormat}_$($user.Alias)_MessageTrace_Recipient.csv") -EmptyMessage "No recipient-side message trace results were returned for $($user.UserPrincipalName) in the last 90 days." | Out-Null
					}
					return "Message trace for specified users collected using $(if ($useMessageTraceV2) { 'Get-MessageTraceV2' } else { 'Get-MessageTrace' })."
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
			# Microsoft Entra activity reports retain at most 30 days for P1/P2
			# tenants (and commonly 7 days for Free). Query only the supported
			# activity window; this is separate from Purview UAL retention.
			$entraActivityStart = (Get-Date).ToUniversalTime().AddDays(-30)
			$entraActivityStartFilter = $entraActivityStart.ToString('yyyy-MM-ddTHH:mm:ssZ')
			try {
				Ensure-GraphConnection | Out-Null
			} catch {
				$errorMessage = "Microsoft Graph is not connected for Azure log collection: $($_.Exception.Message)"
				Write-M365CollectionNotice -Path (Join-Path $azureLogsPath "$($timestampFormat)_AzureLogs_Error.txt") -Message $errorMessage
				return $errorMessage
			}
			
			# Determine if we are filtering by specific users
			$userPrincipalNames = if ($Scope -eq "CustomUsers" -and (Test-Path $usernamesFilePath)) {
				Get-Content $usernamesFilePath
			} else {
				$null
			}
			
			$messages = @("Requested Microsoft Entra activity logs from $($entraActivityStart.ToString('u')) through $((Get-Date).ToUniversalTime().ToString('u')).")

			# Attempt to collect sign-in logs
			try {
				if ($userPrincipalNames) {
					foreach ($userPrincipalName in $userPrincipalNames) {
						$userPrincipalName = $userPrincipalName.Trim()
						$escapedUserPrincipalName = $userPrincipalName -replace "'", "''"
						$signInLogs = @(Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $entraActivityStartFilter and userPrincipalName eq '$escapedUserPrincipalName'" -ErrorAction Stop)
						$messages += Export-M365CollectionData -Data ($signInLogs | ForEach-Object { Convert-GraphSignInLog -LogEntry $_ }) -CsvPath (Join-Path $azureLogsPath "${timestampFormat}_$($userPrincipalName)_SignInLogs.csv") -EmptyMessage "No Entra sign-in logs were returned for $userPrincipalName. Sign-in logs require supported Entra roles and Microsoft Entra ID P1/P2 licensing."
					}
				} else {
					$signInLogs = @(Get-MgAuditLogSignIn -All -Filter "createdDateTime ge $entraActivityStartFilter" -ErrorAction Stop)
					$messages += Export-M365CollectionData -Data ($signInLogs | ForEach-Object { Convert-GraphSignInLog -LogEntry $_ }) -CsvPath (Join-Path $azureLogsPath "$($timestampFormat)_AzureSignInLogs_Tenant.csv") -EmptyMessage "No Entra sign-in logs were returned for the tenant. Sign-in logs require Microsoft Entra ID P1/P2 and supported roles such as Reports Reader or Security Reader."
				}
			} catch {
				if ($_.Exception.Message -match "premium" -or $_.Exception.Message -match "license") {
					$errorMessage = "Error: Tenant does not have a premium license required for sign-in logs."
					Write-M365CollectionNotice -Path (Join-Path $azureLogsPath "$($timestampFormat)_AzureSignInLogs_Error.txt") -Message $errorMessage
					$messages += $errorMessage
				} elseif ($_.Exception.Message -match "Insufficient privileges" -or $_.Exception.Message -match "Authorization_RequestDenied") {
					$errorMessage = "Error: Current account doesn't have the required Microsoft Entra role for sign-in logs. Reports Reader, Global Reader, Security Reader, Security Operator, or Security Administrator are typically required."
					Write-M365CollectionNotice -Path (Join-Path $azureLogsPath "$($timestampFormat)_AzureSignInLogs_Error.txt") -Message $errorMessage
					$messages += $errorMessage
				} else {
					$errorMessage = "Failed to collect Entra sign-in logs: $($_.Exception.Message)"
					Write-M365CollectionNotice -Path (Join-Path $azureLogsPath "$($timestampFormat)_AzureSignInLogs_Error.txt") -Message $errorMessage
					$messages += $errorMessage
				}
			}
			
			# Attempt to collect audit directory logs
			try {
				$auditLogs = @(Get-MgAuditLogDirectoryAudit -All -Filter "activityDateTime ge $entraActivityStartFilter" -ErrorAction Stop)
				$auditLogFileName = "${timestampFormat}_AzureAuditLogs_Tenant.csv"
				$auditLogFilePath = Join-Path $azureLogsPath $auditLogFileName
				$messages += Export-M365CollectionData -Data ($auditLogs | ForEach-Object { Convert-GraphDirectoryAuditLog -LogEntry $_ }) -CsvPath $auditLogFilePath -EmptyMessage "No Entra directory audit logs were returned. Directory audit logs require AuditLog.Read.All and a supported Entra role such as Reports Reader or Security Reader."
			} catch {
				$errorMessage = "Failed to collect Entra directory audit logs: $($_.Exception.Message)"
				Write-M365CollectionNotice -Path (Join-Path $azureLogsPath "$($timestampFormat)_AzureAuditLogs_Error.txt") -Message $errorMessage
				$messages += $errorMessage
			}

			return ($messages -join "`r`n")
		}

		function Collect-M365Info {
			param(
				[string]$currentcasedirectory
			)
		
			$m365InfoPath = Join-Path $currentcasedirectory "M365Evidence\M365Info"
			$graphAvailable = $true
			$graphConnectionError = $null
			try {
				Ensure-GraphConnection | Out-Null
			} catch {
				$graphAvailable = $false
				$graphConnectionError = $_.Exception.Message
			}
			
			# Check if the M365Info directory exists, and if not, create it
			if (!(Test-Path $m365InfoPath)) {
				New-Item -ItemType Directory -Path $m365InfoPath | Out-Null
			}
		
			$AdminAuditLogConfig = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_AdminAuditLogConfig.csv"
			$casMailboxFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_CasMailbox.csv"
			$MailboxFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_Mailbox.csv"
			$MailboxPermissionsFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_MailboxPermissions.csv"
			$GraphUsersFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_GraphUsers.csv"
			$OrganizationFile = Join-Path $m365InfoPath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_Organization.csv"
		
			$messages = @()
			$mailboxes = @(Get-Mailbox -ResultSize Unlimited)
			if (-not $graphAvailable) {
				$messages += "Microsoft Graph is not connected for M365 info collection: $graphConnectionError"
			}
			Get-AdminAuditLogConfig | Export-Csv $AdminAuditLogConfig -NoTypeInformation
			$messages += "Saved admin audit configuration to $AdminAuditLogConfig"
			Get-CasMailbox -ResultSize unlimited | Export-Csv $casMailboxFile -NoTypeInformation
			$messages += "Saved CAS mailbox inventory to $casMailboxFile"
			$mailboxes | Export-Csv $MailboxFile -NoTypeInformation
			$messages += "Saved mailbox inventory to $MailboxFile"
			if ($graphAvailable) {
				try {
					$organization = @(Get-MgOrganization -ErrorAction Stop)
					$messages += Export-M365CollectionData -Data $organization -CsvPath $OrganizationFile -EmptyMessage "No Microsoft Graph organization data was returned. Verify Graph consent and Entra directory read access."
				} catch {
					$errorMessage = "Failed to collect organization data from Microsoft Graph: $($_.Exception.Message)"
					Write-M365CollectionNotice -Path ([System.IO.Path]::ChangeExtension($OrganizationFile, ".txt")) -Message $errorMessage
					$messages += $errorMessage
				}
			} else {
				Write-M365CollectionNotice -Path ([System.IO.Path]::ChangeExtension($OrganizationFile, ".txt")) -Message "Skipped Microsoft Graph organization export because Graph was not connected. $graphConnectionError"
			}
		
			$mailboxPermissions = @()
		
			foreach ($mailbox in $mailboxes) {
				$permissions = Get-MailboxPermission -Identity $mailbox.Identity
				$mailboxPermissions += $permissions
			}
		
			$mailboxPermissions | Export-Csv $MailboxPermissionsFile -NoTypeInformation
			$messages += "Saved mailbox permissions to $MailboxPermissionsFile"
		
			# Export Graph user inventory instead of legacy MSOnline users.
			if ($graphAvailable) {
				try {
					$graphUsers = @(Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,Mail,JobTitle,Department,CompanyName,AccountEnabled,CreatedDateTime,LastPasswordChangeDateTime,UserType" -ErrorAction Stop)
					$messages += Export-M365CollectionData -Data ($graphUsers | Select-Object Id, DisplayName, UserPrincipalName, Mail, JobTitle, Department, CompanyName, AccountEnabled, CreatedDateTime, LastPasswordChangeDateTime, UserType) -CsvPath $GraphUsersFile -EmptyMessage "No Microsoft Graph user records were returned. Verify Graph consent for User.Read.All and the signed-in account's directory access."
				} catch {
					$errorMessage = "Failed to collect Microsoft Graph users: $($_.Exception.Message)"
					Write-M365CollectionNotice -Path ([System.IO.Path]::ChangeExtension($GraphUsersFile, ".txt")) -Message $errorMessage
					$messages += $errorMessage
				}
			} else {
				Write-M365CollectionNotice -Path ([System.IO.Path]::ChangeExtension($GraphUsersFile, ".txt")) -Message "Skipped Microsoft Graph user export because Graph was not connected. $graphConnectionError"
			}
		
			return ($messages -join "`r`n")
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
			try {
				Ensure-GraphConnection | Out-Null
			} catch {
				$errorMessage = "Microsoft Graph is not connected for last password change collection: $($_.Exception.Message)"
				Write-M365CollectionNotice -Path (Join-Path $lastPasswordChangePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_LastPasswordChange_Error.txt") -Message $errorMessage
				return $errorMessage
			}
		
			switch ($Scope) {
				"Entire Tenant" {
					try {
						$allUsers = @(Get-MgUser -All -Property "Id,UserPrincipalName,LastPasswordChangeDateTime" -ErrorAction Stop)
						$exportData = $allUsers | ForEach-Object {
							$methodSummary = Get-GraphAuthenticationMethodSummary -UserId $_.Id
							[PSCustomObject]@{
								UserPrincipalName = $_.UserPrincipalName
								LastPasswordChangeTimestamp = $_.LastPasswordChangeDateTime
								MFAStatus = $methodSummary.MFAStatus
								MFAMethodTypes = $methodSummary.MFAMethodTypes
								Error = $methodSummary.Error
							}
						}
						return (Export-M365CollectionData -Data $exportData -CsvPath (Join-Path $lastPasswordChangePath "$(Get-Date -Format 'yyyyMMdd_HHmmss')_LastPasswordChange_Tenant.csv") -EmptyMessage "No last-password-change records were returned. Verify Graph permissions, directory visibility, and UserAuthenticationMethod.Read.All consent.")
					} catch {
						return "Failed to collect last password change data for the tenant: $($_.Exception.Message)"
					}
				}
		
				"CustomUsers" {
					$userPrincipalNames = if ($usernamesFilePath) {
						Get-Content $usernamesFilePath
					} else {
						throw "Usernames file path is required for collecting specific users' last password change information."
					}
		
					$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
					foreach ($userPrincipalName in $userPrincipalNames) {
						$userPrincipalName = $userPrincipalName.Trim()
						try {
							$user = Get-MgUser -UserId $userPrincipalName -Property "Id,UserPrincipalName,LastPasswordChangeDateTime" -ErrorAction Stop
							$methodSummary = Get-GraphAuthenticationMethodSummary -UserId $user.Id
							$row = [PSCustomObject]@{
								UserPrincipalName = $user.UserPrincipalName
								LastPasswordChangeTimestamp = $user.LastPasswordChangeDateTime
								MFAStatus = $methodSummary.MFAStatus
								MFAMethodTypes = $methodSummary.MFAMethodTypes
								Error = $methodSummary.Error
							}
						} catch {
							$row = [PSCustomObject]@{
								UserPrincipalName = $userPrincipalName
								LastPasswordChangeTimestamp = $null
								MFAStatus = 'Unknown'
								MFAMethodTypes = ''
								Error = $_.Exception.Message
							}
						}
						$row | Export-Csv -Path (Join-Path $lastPasswordChangePath "${timestamp}_$($userPrincipalName)_LastPasswordChange.csv") -NoTypeInformation
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
								"Connect-Graph" {
									$response = Connect-Graph -Writer $writer
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
    $connectTimeoutMs = 30000
    $busyWaitLogged = $false
	
    while ($retryCount -lt $maxRetries) {
        try {
            $pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
            $pipeClient.Connect($connectTimeoutMs)

			if ($pipeClient.IsConnected) {
				Write-Host "Connected to server."
				$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
				$streamWriter.AutoFlush = $true
			
				# Example request to collect forwarding rules for entire tenant
				$request = ($commandToSend)
				$streamWriter.WriteLine($request)
			
				# Read response from server
				$streamReader = New-Object System.IO.StreamReader($pipeClient)
				$responseLines = @()
				while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
					if ($line -is [System.Array] -or $line -is [System.Object]) {
						$line = $line -join "`r`n"
					}
					Write-Host "Response from server: $line"
					Update-Log "$line" "M365TextBox"
					if (-not [string]::IsNullOrWhiteSpace($line)) {
						$responseLines += $line
					}
				}

				$streamWriter.Close()
				$streamReader.Close()
				$pipeClient.Close()
				Write-Host "Message sent, client disconnected."
				# Return the response
				return ($responseLines -join "`r`n")
			} else {
				Write-Host "Failed to connect to server. Retrying..."
				Start-Sleep -Seconds $retryDelay
				$retryCount++
			}
		} catch {
			$errorMessage = $_.Exception.Message
			if ($errorMessage -match "semaphore timeout period has expired|Timed out waiting|The operation has timed out") {
				if (-not $busyWaitLogged) {
					$busyWaitLogged = $true
					Write-Host "M365 worker is busy with another request. Waiting for it to finish..."
					Update-Log "The Microsoft 365 worker is busy with another request. Waiting for it to finish..." "M365TextBox"
				}
			} else {
				Write-Host "Error: $_. Retrying..."
			}
			Start-Sleep -Seconds $retryDelay
			$retryCount++
		}
    }
    $failureMessage = "Failed to connect to the Microsoft 365 worker after waiting. If another Microsoft 365 collection is still running, let it finish and then retry."
    Write-Host $failureMessage
    Update-Log $failureMessage "M365TextBox"
}

function TestClientConnectionButton_Click {
    $M365TextBox.Text = ""
    if (-not (Test-M365CanStartRequest -RequestedAction "a Microsoft 365 connection test")) {
        return
    }
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
    if (-not (Test-M365CanStartRequest -RequestedAction "triage collection")) {
        return
    }
    if (-not $Global:M365GraphConnected) {
        Update-Log "Collect Triage will run Exchange-backed collections only. Graph-backed collections are skipped until Connect Graph is completed." "M365TextBox"
    } else {
        Update-Log "Collect Triage will include both Exchange-backed and Graph-backed collections." "M365TextBox"
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
		return $response
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
    if (-not (Test-M365CanStartRequest -RequestedAction "Unified Audit Log collection")) {
        return
    }
    Update-Log "Collecting Unified Audit Logs..." "M365TextBox"
	$selectedUserOption = $CollectUALUsersComboBox.SelectedItem.Content.ToString()
    $selectedIPOption = $CollectUALIPsComboBox.SelectedItem.Content.ToString()
    $selectedDateOption = $CollectUALDateComboBox.SelectedItem.Content.ToString()
    $selectedOperationsOption = $CollectUALOperationsComboBox.SelectedItem.Content.ToString()
    if ($selectedDateOption -eq "Custom Date" -and -not $M365StartDatePicker.SelectedDate) {
        Update-Log "Select a valid start date before collecting Unified Audit Logs." "M365TextBox"
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
		return $response
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

function CollectAdminLogsButton_Click {
    if (-not (Test-M365CanStartRequest -RequestedAction "admin audit log collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
    if (-not (Test-M365CanStartRequest -RequestedAction "inbox rules collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-InboxRules;Entire Tenant;$currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-InboxRules;CustomUsers;$currentcasedirectory;$usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting inbox rules."
		}
		return $response
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
    if (-not (Test-M365CanStartRequest -RequestedAction "forwarding rules collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true					
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-ForwardingRules;Entire Tenant;$currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-ForwardingRules;CustomUsers;$currentcasedirectory;$usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting forwarding rules."
		}
		return $response
    }
    # Start the job and add it to the global job list
    $job = Start-Job -ScriptBlock $scriptBlock -ArgumentList $selectedOption, $global:currentcasedirectory, $global:usernamesFilePath, $Global:pipeName
    $Global:m365ForwardingRulesJobs += @{JobObject = $job; JobName = $jobName; DataAdded = $false}
    
    # Start the timer if not already running
    if (-not $m365ForwardingRulesJobTimer.Enabled) {
        $m365ForwardingRulesJobTimer.Start()
    }

    Update-Log "Forwarding rules collection job ($jobName) started." "M365TextBox"
}

function CollectM365InfoButton_Click {
    if (-not (Test-M365CanStartRequest -RequestedAction "Microsoft 365 information collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
    if (-not (Test-M365CanStartRequest -RequestedAction "message trace collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-MessageTrace;Entire Tenant;$currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-MessageTrace;CustomUsers;$currentcasedirectory;$usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting inbox rules."
		}
		return $response
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
    if (-not $Global:M365GraphConnected) {
        Update-Log "Azure Logs requires Microsoft Graph. Starting the Graph connection; retry the collection after it completes." "M365TextBox"
        ConnectGraphButton_Click
        return
    }
    if (-not (Test-M365CanStartRequest -RequestedAction "Entra log collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
		return $response
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
    if (-not $Global:M365GraphConnected) {
        Update-Log "Last Password Change requires Microsoft Graph. Starting the Graph connection; retry the collection after it completes." "M365TextBox"
        ConnectGraphButton_Click
        return
    }
    if (-not (Test-M365CanStartRequest -RequestedAction "last password change collection")) {
        return
    }
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
			$maxRetries = 10
			$retryDelay = 2 # seconds
			$retryCount = 0		
			
			while ($retryCount -lt $maxRetries) {
				try {
					$pipeClient = New-Object System.IO.Pipes.NamedPipeClientStream('.', $pipeName, [System.IO.Pipes.PipeDirection]::InOut)
					$pipeClient.Connect(30000)
		
					if ($pipeClient.IsConnected) {
						Write-Host "Connected to server."
						$streamWriter = New-Object System.IO.StreamWriter($pipeClient)
						$streamWriter.AutoFlush = $true			
						$request = ($commandToSend)
						$streamWriter.WriteLine($request)
						$streamReader = New-Object System.IO.StreamReader($pipeClient)
						$responseLines = @()
						while (($line = $streamReader.ReadLine()) -ne "END_OF_MESSAGE") {
							if ($line -is [System.Array] -or $line -is [System.Object]) {
								$line = $line -join "`r`n"
							}
							Write-Host "Response from server: $line"
							if (-not [string]::IsNullOrWhiteSpace($line)) {
								$responseLines += $line
							}
						}
						$streamWriter.Close()
						$streamReader.Close()
						$pipeClient.Close()
						Write-Host "Message sent, client disconnected."
						return ($responseLines -join "`r`n")
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
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-LastPasswordChange;Entire Tenant;$currentcasedirectory"
		} elseif ($selectedOption -eq "Custom Users") {
			$response = Send-CommandToProcess -pipeName $pipeName -commandToSend "Collect-LastPasswordChange;CustomUsers;$currentcasedirectory;$usernamesFilePath"
		} else {
			Write-Host "No option selected for collecting inbox rules."
		}
		return $response
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
