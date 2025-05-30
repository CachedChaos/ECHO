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