$global:hasRunOnTabPageTools = $false
$script:hasSyncedToolsInventory = $false

#Timer for downloading tools
$Global:tooldownloadJobs = @()
$Global:toolDownloadStatuses = @{}

function Resolve-ToolManagementScriptPath {
    $candidateRoots = @()
    if (-not [string]::IsNullOrWhiteSpace($PSScriptRoot)) {
        $candidateRoots += $PSScriptRoot
    }
    if (-not [string]::IsNullOrWhiteSpace($PSCommandPath)) {
        try {
            $candidateRoots += (Split-Path -Parent $PSCommandPath)
        } catch { }
    }
    $baseDirectory = [System.AppDomain]::CurrentDomain.BaseDirectory
    if (-not [string]::IsNullOrWhiteSpace($baseDirectory)) {
        $candidateRoots += $baseDirectory
    }

    foreach ($root in $candidateRoots) {
        try {
            if (-not (Test-Path -LiteralPath $root -PathType Container -ErrorAction SilentlyContinue)) {
                continue
            }

            $candidate = Join-Path -Path $root -ChildPath "ToolManagement.ps1"
            if (Test-Path -LiteralPath $candidate -PathType Leaf -ErrorAction SilentlyContinue) {
                return $candidate
            }
        } catch {
            continue
        }
    }

    return $null
}

$script:toolManagementScriptPath = Resolve-ToolManagementScriptPath
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

    $requiredFunctionNames = @(
        "Invoke-ExternalProcessQuiet",
        "Get-EchoLatestRelease",
        "Get-EchoReleaseAsset",
        "Clear-EchoToolDirectory",
        "Add-ToolToCsv",
        "Test-InternetConnection"
    )
    $downloadFunctionNames = @(Get-Command -Name "Download-*" -CommandType Function -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    if ($downloadFunctionNames.Count -gt 0) {
        $requiredFunctionNames += $downloadFunctionNames
    }
    $requiredFunctionNames = @($requiredFunctionNames | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)

    $embeddedFunctionDefinitions = @{}
    foreach ($functionName in $requiredFunctionNames) {
        $functionCommand = Get-Command -Name $functionName -CommandType Function -ErrorAction SilentlyContinue
        if ($functionCommand -and $functionCommand.Definition) {
            $embeddedFunctionDefinitions[$functionName] = $functionCommand.Definition
        }
    }

    $job = Start-Job -ScriptBlock {
        param($selectedTool, $toolsDir, $toolManagementPath, $geoLiteLicense, $functionDefinitions)

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

            $loadedFromScriptPath = $false
            if (-not [string]::IsNullOrWhiteSpace($toolManagementPath) -and (Test-Path -LiteralPath $toolManagementPath -PathType Leaf -ErrorAction SilentlyContinue)) {
                . $toolManagementPath
                $loadedFromScriptPath = $true
            }

            if (-not $loadedFromScriptPath) {
                if ($functionDefinitions -and $functionDefinitions.Count -gt 0) {
                    foreach ($entry in $functionDefinitions.GetEnumerator()) {
                        Set-Item -Path ("Function:\{0}" -f $entry.Key) -Value $entry.Value
                    }
                } else {
                    throw "Tool download functions are unavailable in this runtime. Rebuild ECHO so download functions are embedded."
                }
            }

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
    } -ArgumentList @($SelectedOption, $toolsDirectory, $script:toolManagementScriptPath, $GeoLiteLicenseKeyPlain, $embeddedFunctionDefinitions)

    $Global:tooldownloadJobs += [PSCustomObject]@{
        JobObject = $job
        JobName = $SelectedOption
        DataAdded = $false
    }
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
        if (-not $script:hasSyncedToolsInventory) {
            Sync-ToolsInventoryCsv
            $script:hasSyncedToolsInventory = $true
        }
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
    if (-not $script:hasSyncedToolsInventory) {
        Sync-ToolsInventoryCsv
        $script:hasSyncedToolsInventory = $true
    }
    Update-SelectedToolDownloadStatus
    Update-DownloadToolButtonState
}

function Sync-ToolsInventoryCsv {
    $toolPatterns = @(
        "7za.exe",
        "bulk_extractor64.exe",
        "chainsaw*.exe",
        "clamdscan.exe",
        "etl2pcapng.exe",
        "ftkimager.exe",
        "GeoLite2-City.mmdb",
        "GeoLite2-ASN.mmdb",
        "GeoLite2-Country.mmdb",
        "Get-ZimmermanTools.ps1",
        "hayabusa*.exe",
        "log2timeline.py",
        "System.Data.SQLite.dll",
        "loki.exe",
        "Velociraptor*.exe",
        "vol.py",
        "winpmem*.exe",
        "zircolite*.exe"
    )

    foreach ($pattern in $toolPatterns) {
        Add-ToolToCsv -toolName $pattern
    }
}

function Add-ToolToCsv {
    param([string]$toolName, [string]$filePath, [string]$PackageVersion, [string]$SourceUrl)
    $explicitPath = -not [string]::IsNullOrWhiteSpace($filePath)
    if (-not $explicitPath) {
        $filePath = Get-ChildItem -LiteralPath $toolsDirectory -Filter $toolName -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/]Temp[^\\/]*[\\/]' } |
            Select-Object -ExpandProperty FullName -First 1
    }
    if (-not $filePath -or -not (Test-Path -LiteralPath $filePath -PathType Leaf)) {
        if ($explicitPath) { throw "Cannot inventory missing tool: $filePath" }
        Update-Log "Tool not found: $toolName" 'tabPageToolsTextBox'
        return
    }
    $file = Get-Item -LiteralPath $filePath -ErrorAction Stop
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
    $version = $file.VersionInfo.FileVersion
    if ([string]::IsNullOrWhiteSpace($version)) { $version = $file.VersionInfo.ProductVersion }
    $versionSource = 'File metadata'
    if ([string]::IsNullOrWhiteSpace($version)) {
        $version = $PackageVersion
        $versionSource = 'Release/package'
    }
    if ([string]::IsNullOrWhiteSpace($version)) { $version = 'Unknown'; $versionSource = 'Unknown' }
    # Never persist a credential-bearing URL in the inventory.
    if ($SourceUrl -match '(?i)(license_key|token|password|api_key)=') { $SourceUrl = '' }
    $columns = @('Tool Name','SHA256 Hash','Creation Date','Modification Date','Version','Version Source','Package Version','Source URL','File Path')
    $csvPath = Join-Path $toolsDirectory 'tools.csv'
    $rows = @()
    if (Test-Path -LiteralPath $csvPath) {
        $rows = @(Import-Csv -LiteralPath $csvPath -ErrorAction Stop | Select-Object -Property $columns)
    }
    $match = @($rows | Where-Object { $_.'SHA256 Hash' -eq $hash -and
        ($_.'File Path' -eq $file.FullName -or [string]::IsNullOrWhiteSpace($_.'File Path')) })
    # Preserve download provenance during later inventory-only scans.
    if ($match.Count -gt 0) {
        if (-not $PackageVersion) { $PackageVersion = $match[-1].'Package Version' }
        if (-not $SourceUrl) { $SourceUrl = $match[-1].'Source URL' }
        if ($version -eq 'Unknown' -and $PackageVersion) { $version = $PackageVersion; $versionSource = 'Release/package' }
    }
    $rows = @($rows | Where-Object { $match -notcontains $_ })
    foreach ($row in $rows) {
        if (-not $row.Version) { $row.Version = 'Unknown'; $row.'Version Source' = 'Unknown' }
    }
    $rows += [pscustomobject][ordered]@{
        'Tool Name' = $file.Name
        'SHA256 Hash' = $hash
        'Creation Date' = $file.CreationTime.ToString('yyyy-MM-dd HH:mm:ss')
        'Modification Date' = $file.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
        'Version' = $version
        'Version Source' = $versionSource
        'Package Version' = $PackageVersion
        'Source URL' = $SourceUrl
        'File Path' = $file.FullName
    }
    $tempCsv = Join-Path $toolsDirectory ('tools.{0}.tmp' -f [guid]::NewGuid().ToString('N'))
    try {
        $rows | Export-Csv -LiteralPath $tempCsv -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
        Move-Item -LiteralPath $tempCsv -Destination $csvPath -Force -ErrorAction Stop
    } finally {
        if (Test-Path -LiteralPath $tempCsv) { Remove-Item -LiteralPath $tempCsv -Force -ErrorAction SilentlyContinue }
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


function Get-EchoLatestRelease {
    param([Parameter(Mandatory = $true)][string]$Uri)
    $release = Invoke-RestMethod -Uri $Uri -Headers @{ 'User-Agent' = 'ECHO'; 'Accept' = 'application/vnd.github+json' } -ErrorAction Stop
    if (-not $release.tag_name -or $release.draft -or $release.prerelease) {
        throw "No published stable release returned by $Uri."
    }
    return $release
}

function Get-EchoReleaseAsset {
    param($Release, [string]$Pattern)
    $assets = @($Release.assets | Where-Object { $_.name -match $Pattern })
    if ($assets.Count -ne 1 -or -not $assets[0].browser_download_url) {
        throw "Expected one asset matching '$Pattern' in release $($Release.tag_name); found $($assets.Count). No older release will be substituted."
    }
    return $assets[0].browser_download_url
}

function Clear-EchoToolDirectory {
    param([Parameter(Mandatory = $true)][string]$Path)
    # Only clear a direct child of the configured Tools directory.
    $root = [IO.Path]::GetFullPath($toolsDirectory).TrimEnd('\', '/')
    $target = [IO.Path]::GetFullPath($Path).TrimEnd('\', '/')
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($target), $root, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clear a directory outside the tool root: $target"
    }
    if (Test-Path -LiteralPath $target) {
        $item = Get-Item -LiteralPath $target -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Refusing to clear a linked tool directory: $target" }
        Get-ChildItem -LiteralPath $target -Force | Remove-Item -Recurse -Force -ErrorAction Stop
    }
}

function Download-7zip {
    # Setup for 7zr.exe
    $7zipFolder = Join-Path $toolsDirectory "7-Zip"
    if (!(Test-Path $7zipFolder)) {
        New-Item -ItemType Directory -Path $7zipFolder | Out-Null
    }	
    $tempFolder = Join-Path $toolsDirectory "Temp7Zip"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    $latestRelease = Get-EchoLatestRelease -Uri "https://api.github.com/repos/ip7z/7zip/releases/latest"
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    # Use bootstrap and Extra package from the same release.
    $7zrPath = Join-Path $tempFolder "7zr.exe"
    $7zrUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^7zr\.exe$'
   try {
        Invoke-WebRequest -UseBasicParsing -Uri $7zrUrl -OutFile $7zrPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download 7zip: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    $extra7zUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^7z[0-9]+-extra\.7z$'
    $extra7zPath = Join-Path $tempFolder (Split-Path -Leaf $extra7zUrl)
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $extra7zUrl -OutFile $extra7zPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download 7zip: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    # Extract the selected Extra archive using its matching 7zr.exe
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
            Copy-Item -Path (Join-Path $tempFolder "*") -Destination $7zipFolder -Recurse -Force -ErrorAction Stop

            Update-Log "7-Zip updated." "tabPageToolsTextBox"
        } else {
            Update-Log "7-Zip is already up-to-date." "tabPageToolsTextBox"
        }
    }

    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $7zipFolder -Filter '7za.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed 7zip file missing; download is incomplete.' }
    Add-ToolToCsv -toolName '7za.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $extra7zUrl
}

function Download-BulkExtractor {
    $bulkExtractorFolder = Join-Path $toolsDirectory "BulkExtractor"
    if (!(Test-Path $bulkExtractorFolder)) {
        New-Item -ItemType Directory -Path $bulkExtractorFolder | Out-Null
    }
    
    $tempFolder = Join-Path $toolsDirectory "TempBulkExtractor"
    $latestRelease = Get-EchoLatestRelease -Uri "https://api.github.com/repos/simsong/bulk_extractor/releases/latest"
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^bulk_extractor64\.exe$'
    $downloadPath = Join-Path $tempFolder "bulk_extractor64.exe"

    # Ensure the temporary folder exists
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Download to temporary folder
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Bulk Extractor: $_" "tabPageToolsTextBox"
        throw
    }
    $tempExecutable = $downloadPath

    if (Test-Path $tempExecutable) {
        $bulkExtractorExecutable = Get-ChildItem -Path $bulkExtractorFolder -Filter "bulk_extractor64.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

        $existingHash = if ($bulkExtractorExecutable -and (Test-Path $bulkExtractorExecutable)) { (Get-FileHash -Path $bulkExtractorExecutable -Algorithm SHA256).Hash } else { "" }
        $newHash = (Get-FileHash -Path $tempExecutable -Algorithm SHA256).Hash

        if ($newHash -ne $existingHash) {
            # Update the tool as the hash is different
            $destinationPath = Join-Path $bulkExtractorFolder "bulk_extractor64.exe"
            Copy-Item -Path $tempExecutable -Destination $destinationPath -Force -ErrorAction Stop

        } else {
            Update-Log "BulkExtractor is already up-to-date." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded BulkExtractor executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."

    }

    # Clean up temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $bulkExtractorFolder -Filter 'bulk_extractor64.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed BulkExtractor file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'bulk_extractor64.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-chainsaw {
	$7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $7zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($7zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		throw "7-Zip (7za.exe) is required but was not found in the tools directory."
	}
    $chainsawFolder = Join-Path $toolsDirectory "chainsaw"
    if (!(Test-Path $chainsawFolder)) {
        New-Item -ItemType Directory -Path $chainsawFolder | Out-Null
    }		
    $chainsawExecutable = Get-ChildItem -Path $chainsawFolder -Filter "chainsaw*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "Tempchainsaw"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/WithSecureOpenSource/chainsaw/releases/latest"
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^chainsaw_all_platforms.rules.zip$'
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for chainsaw.exe not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
	# Decode the URL to get the correct file name
	$decodedUrl = [System.Web.HttpUtility]::UrlDecode($downloadUrl)
	$originalFileName = Split-Path -Leaf $decodedUrl
	$downloadPath = Join-Path $tempFolder $originalFileName

    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download chainsaw: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
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
						Clear-EchoToolDirectory -Path $chainsawFolder
					}
		            } else {
	                Update-Log "chainsaw is already up-to-date." "tabPageToolsTextBox"
	            }
	            # Always refresh chainsaw package contents so rules are updated
				$7zipArgs2 = "x `"$downloadPath`" -o`"$chainsawFolder`" -y"
				Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList $7zipArgs2 -WorkingDirectory $chainsawFolder -ErrorContext "7-Zip extraction (final) for chainsaw"
                $installedChainsaw = Get-ChildItem -LiteralPath $chainsawFolder -Filter "chainsaw*.exe" -Recurse -File | Select-Object -ExpandProperty FullName -First 1
                if (-not $installedChainsaw) { throw "Chainsaw executable missing after installation." }

	            if (-not $chainsawExecutable -or $newHash -ne $existingHash) {
	                Update-Log "chainsaw updated." "tabPageToolsTextBox"
	            } else {
	                Update-Log "chainsaw rules package refreshed." "tabPageToolsTextBox"
	            }
	        } else {
	            Update-Log "Downloaded chainsaw executable not found in the extracted files." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
	        }
    } else {
        Update-Log "Downloaded chainsaw executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $chainsawFolder -Filter 'chainsaw*.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed chainsaw file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'chainsaw*.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-ClamAV {
    $ClamAVFolder = Join-Path $toolsDirectory "ClamAV"
    if (!(Test-Path $ClamAVFolder)) {
        New-Item -ItemType Directory -Path $ClamAVFolder | Out-Null
    }
    $ClamdscanExecutable = Get-ChildItem -Path $ClamAVFolder -Filter "clamdscan.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $existingFreshclam = Get-ChildItem -Path $ClamAVFolder -Filter "freshclam.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1


    $tempFolder = Join-Path $toolsDirectory "TempClamAV"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Base URL for ClamAV website
    $baseUrl = "https://www.clamav.net"
    
    # Retrieve the latest release page and parse the download URL
    $apiUrl = "$baseUrl/downloads"
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    $latestReleasePage = Invoke-WebRequest -UseBasicParsing -Uri $apiUrl -Headers @{ "User-Agent" = $userAgent }
    $relativePath = $latestReleasePage.Links | Where-Object { $_.href -match 'clamav-(\d+\.\d+\.\d+)\.win\.x64\.zip$' } | Sort-Object -Descending -Property @{
        Expression = { if ($_.href -match 'clamav-(\d+\.\d+\.\d+)\.win\.x64\.zip$') { [version]$matches[1] } }
    } | Select-Object -ExpandProperty href -First 1
    
    $packageVersion = if ($relativePath -match 'clamav-(\d+\.\d+\.\d+)') { $matches[1] }
    # Check if a valid download path was retrieved
    if ([string]::IsNullOrWhiteSpace($relativePath)) {
        Update-Log "Download URL for ClamAV not found." "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    # Define the path where the downloaded file will be saved
    $originalFileName = Split-Path -Leaf $relativePath
    $downloadPath = Join-Path $tempFolder $originalFileName
    
    # Construct the full download URL
    $downloadUrl = ([uri]::new([uri]$baseUrl, [string]$relativePath)).AbsoluteUri
    Update-Log "Selected ClamAV package: $downloadUrl" "tabPageToolsTextBox"
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download ClamAV: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    if (Test-Path $downloadPath) {
        Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force -ErrorAction Stop
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
                    Copy-Item -Path $file.FullName -Destination $newConfPath -Force -ErrorAction Stop
                    (Get-Content $newConfPath) | Where-Object { $_ -notmatch "^Example" } | Set-Content $newConfPath
                }

                # Copy updated contents to the ClamAV folder
                Clear-EchoToolDirectory -Path $ClamAVFolder
                Copy-Item -Path $tempFolder\* -Destination $ClamAVFolder -Recurse -Force -ErrorAction Stop

                Update-Log "ClamAV updated." "tabPageToolsTextBox"
            } else {
                Update-Log "ClamAV is already up-to-date." "tabPageToolsTextBox"
            }
        } else {
            Update-Log "Downloaded ClamAV executable not found in the extracted files." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
        }
    } else {
        Update-Log "Downloaded ClamAV zip file not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
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
            throw "Expected tool file is missing after download/extraction."
			}
		} catch {
			Update-Log "Error updating ClamAV database: $_" "tabPageToolsTextBox"
            throw
		}

    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $ClamAVFolder -Filter 'clamdscan.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed ClamAV file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'clamdscan.exe' -filePath $inventoryFile -PackageVersion $packageVersion -SourceUrl $downloadUrl
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
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^etl2pcapng\.exe$'
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for etl2pcapng.exe not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}

    $downloadPath = Join-Path $tempFolder "etl2pcapng.exe"

    # Always download to temporary folder
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download et12pcapng: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    if (Test-Path $downloadPath) {
        # Compare hash of the downloaded file with the existing one
        $newHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
        $existingHash = if (Test-Path $etl2pcapngExecutable) { (Get-FileHash -Path $etl2pcapngExecutable -Algorithm SHA256).Hash } else { "" }

        if ($newHash -ne $existingHash) {
            # Update the tool as the hash is different
            Copy-Item -Path $downloadPath -Destination $etl2pcapngExecutable -Force -ErrorAction Stop

            Update-Log "etl2pcapng updated." "tabPageToolsTextBox"
        } else {
            Update-Log "etl2pcapng is already up-to-date." "tabPageToolsTextBox"
        }
    } else {
        Update-Log "Downloaded etl2pcapng executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
    }

    # Clean up temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $etl2pcapngFolder -Filter 'etl2pcapng.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed etl2pcapng file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'etl2pcapng.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
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
        [System.Security.SecureString]$licenseKey
    )

	$zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		throw "7-Zip (7za.exe) is required but was not found in the tools directory."
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
        Clear-EchoToolDirectory -Path $tempFolder
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
                    Copy-Item -Path $mmdbPath -Destination $destinationPath -Force -ErrorAction Stop
                    $isNewOrUpdated = $true
                }
            } else {
                Copy-Item -Path $mmdbPath -Destination $destinationPath -Force -ErrorAction Stop
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


    $tempFolder = Join-Path $toolsDirectory "TempHayabusa"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Yamato-Security/hayabusa/releases/latest"
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^hayabusa.*win-x64.zip$'
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Hayabusa.exe not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Hayabusa: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }
    if (Test-Path $downloadPath) {
        # Extract the zip file
        Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force -ErrorAction Stop

        # Delete the zip file after extraction
        Remove-Item -Path $downloadPath -Force

        # Identify the executable based on pattern
        $extractedExecutable = Get-ChildItem -Path $tempFolder -Filter "hayabusa*.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

        if ($extractedExecutable) {
            # Calculate hash of the downloaded executable
            $newHash = (Get-FileHash -Path $extractedExecutable -Algorithm SHA256).Hash
            $existingHash = if ($HayabusaExecutable -and (Test-Path $HayabusaExecutable)) { (Get-FileHash -Path $HayabusaExecutable -Algorithm SHA256).Hash } else { "" }

            if (-not $HayabusaExecutable -or $newHash -ne $existingHash) {
                Clear-EchoToolDirectory -Path $HayabusaFolder
				# Copy all contents from the temp folder to the Hayabusa folder
				Copy-Item -Path $tempFolder\* -Destination $HayabusaFolder -Recurse -Force -ErrorAction Stop
                $destinationPath = Get-ChildItem -LiteralPath $HayabusaFolder -Filter "hayabusa*.exe" -Recurse -File | Select-Object -ExpandProperty FullName -First 1

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
            throw "Expected tool file is missing after download/extraction."
        }
    } else {
        Update-Log "Downloaded Hayabusa executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $HayabusaFolder -Filter 'hayabusa*.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed Hayabusa file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'hayabusa*.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-Loki {
    $LokiFolder = Join-Path $toolsDirectory "Loki"
    if (!(Test-Path $LokiFolder)) {
        New-Item -ItemType Directory -Path $LokiFolder | Out-Null
    }
    $LokiExecutable = Get-ChildItem -Path $LokiFolder -Filter "loki.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $LokiUpgraderExecutable = Get-ChildItem -Path $LokiFolder -Filter "loki-upgrader.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

			
	$tempFolder = Join-Path $toolsDirectory "TempLoki"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Neo23x0/Loki/releases/latest"
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^loki_[\d\.]+\.zip$'

    if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
        Update-Log "Download URL for Loki not found." "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    $originalFileName = Split-Path -Leaf $downloadUrl
    $downloadPath = Join-Path $tempFolder $originalFileName
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Loki: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }

    if (Test-Path $downloadPath) {
        Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force -ErrorAction Stop
        Remove-Item -Path $downloadPath -Force

        $extractedLoki = Get-ChildItem -Path $tempFolder -Filter "loki.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

        if ($extractedLoki) {
            $newHash = (Get-FileHash -Path $extractedLoki -Algorithm SHA256).Hash
            $existingHash = if ($LokiExecutable -and (Test-Path $LokiExecutable)) { (Get-FileHash -Path $LokiExecutable -Algorithm SHA256).Hash } else { "" }

            if (-not $LokiExecutable -or $newHash -ne $existingHash) {
                Clear-EchoToolDirectory -Path $LokiFolder
                Copy-Item -Path $tempFolder\* -Destination $LokiFolder -Recurse -Force -ErrorAction Stop

                Update-Log "Loki updated." "tabPageToolsTextBox"
            } else {
                Update-Log "Loki is already up-to-date." "tabPageToolsTextBox"
            }
        } else {
            Update-Log "Downloaded Loki executable not found in the extracted files." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
        }
    } else {
        Update-Log "Downloaded Loki zip file not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
    }

    $LokiExecutable = Get-ChildItem -LiteralPath $LokiFolder -Filter "loki.exe" -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    # Run Loki Upgrader
    try {
        $lokiUpgraderPath = Get-ChildItem -Path $LokiFolder -Filter "loki-upgrader.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1
        if ($lokiUpgraderPath -and (Test-Path $lokiUpgraderPath)) {
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
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $LokiFolder -Filter 'loki.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed Loki file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'loki.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-Plaso {
	$7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $7zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($7zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		throw "7-Zip (7za.exe) is required but was not found in the tools directory."
	}
	
    $PlasoFolder = Join-Path $toolsDirectory "Plaso"
    if (!(Test-Path $PlasoFolder)) {
        New-Item -ItemType Directory -Path $PlasoFolder | Out-Null
    }		
	$log2timelinePY = Get-ChildItem -Path $PlasoFolder -Filter "log2timeline.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "Tempplaso"

    # Ensure the temporary and Plaso folders exist
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/log2timeline/plaso/releases/latest"
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^plaso-\d{8}\.tar\.gz$'
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for log2timeline.py not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
	# Download the plaso package
    $tarGzPath = Join-Path $tempFolder (Split-Path -Leaf $downloadUrl)
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $tarGzPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Plaso: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
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
            # Refresh the complete release even when the launcher is unchanged.
                    Clear-EchoToolDirectory -Path $PlasoFolder
					Copy-Item -Path (Join-Path $tempFolder "*") -Destination $PlasoFolder -Recurse -Force -ErrorAction Stop
                    $copiedLog2timelinePath = Get-ChildItem -LiteralPath $PlasoFolder -Filter "log2timeline.py" -Recurse -File | Select-Object -ExpandProperty FullName -First 1
                    if (-not $copiedLog2timelinePath) { throw "Plaso script missing from final destination." }

					Update-Log "Plaso updated." "tabPageToolsTextBox"
		} else {
			Update-Log "log2timeline.py not found in extracted Plaso files." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
		}
    } else {
        throw "Downloaded Plaso archive is missing."
    }
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $PlasoFolder -Filter 'log2timeline.py' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed Plaso file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'log2timeline.py' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-SQLite {
    $SQLiteFolder = Join-Path $toolsDirectory 'SQLite'
    $tempFolder = Join-Path $toolsDirectory 'TempSQLite'
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder, $SQLiteFolder -Force | Out-Null
    try {
        $index = Invoke-RestMethod -Uri 'https://api.nuget.org/v3-flatcontainer/system.data.sqlite/index.json' -ErrorAction Stop
        $version = $index.versions | Where-Object { $_ -match '^\d+\.\d+\.\d+(?:\.\d+)?$' } | Sort-Object { [version]$_ } -Descending | Select-Object -First 1
        if (-not $version) { throw 'No stable System.Data.SQLite package found.' }
        $url = "https://api.nuget.org/v3-flatcontainer/system.data.sqlite/$version/system.data.sqlite.$version.nupkg"
        Update-Log "Selected System.Data.SQLite $version : $url" 'tabPageToolsTextBox'
        $archive = Join-Path $tempFolder 'sqlite.zip'
        Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $archive -ErrorAction Stop
        Expand-Archive -LiteralPath $archive -DestinationPath $tempFolder -Force -ErrorAction Stop
        $frameworkDirectory = Join-Path $tempFolder 'lib\net471'
        $dll = Join-Path $frameworkDirectory 'System.Data.SQLite.dll'
        if (-not (Test-Path -LiteralPath $dll)) { throw 'Latest SQLite package lacks the required .NET Framework 4.7.1 assembly; no older version was substituted.' }
        $nativeIndex = Invoke-RestMethod -Uri 'https://api.nuget.org/v3-flatcontainer/sqlitepclraw.lib.e_sqlite3/index.json' -ErrorAction Stop
        $nativeVersion = $nativeIndex.versions | Where-Object { $_ -match '^\d+\.\d+\.\d+(?:\.\d+)?$' } | Sort-Object { [version]$_ } -Descending | Select-Object -First 1
        if (-not $nativeVersion) { throw 'No stable native SQLite package found.' }
        $nativeUrl = "https://api.nuget.org/v3-flatcontainer/sqlitepclraw.lib.e_sqlite3/$nativeVersion/sqlitepclraw.lib.e_sqlite3.$nativeVersion.nupkg"
        Update-Log "Selected SQLite native library $nativeVersion : $nativeUrl" 'tabPageToolsTextBox'
        $nativeArchive = Join-Path $tempFolder 'native.zip'
        $nativeFolder = Join-Path $tempFolder 'native'
        Invoke-WebRequest -UseBasicParsing -Uri $nativeUrl -OutFile $nativeArchive -ErrorAction Stop
        Expand-Archive -LiteralPath $nativeArchive -DestinationPath $nativeFolder -Force -ErrorAction Stop
        $architecture = if ([Environment]::Is64BitProcess) { 'win-x64' } else { 'win-x86' }
        $nativeDll = Join-Path $nativeFolder "runtimes\$architecture\native\e_sqlite3.dll"
        if (-not (Test-Path -LiteralPath $nativeDll)) { throw "Latest native SQLite package lacks $architecture/e_sqlite3.dll." }
        Clear-EchoToolDirectory -Path $SQLiteFolder
        Copy-Item -Path (Join-Path $frameworkDirectory '*') -Destination $SQLiteFolder -Force -ErrorAction Stop
        Copy-Item -LiteralPath $nativeDll -Destination $SQLiteFolder -Force -ErrorAction Stop
        Add-ToolToCsv -toolName 'System.Data.SQLite.dll' -filePath (Join-Path $SQLiteFolder 'System.Data.SQLite.dll') -PackageVersion $version -SourceUrl $url
        Add-ToolToCsv -toolName 'e_sqlite3.dll' -filePath (Join-Path $SQLiteFolder 'e_sqlite3.dll') -PackageVersion $nativeVersion -SourceUrl $nativeUrl
        Update-Log "System.Data.SQLite $version installed (.NET Framework 4.7.1+)." 'tabPageToolsTextBox'
    } finally {
        Clear-EchoToolDirectory -Path $tempFolder
        # The clear helper preserves its target directory; remove the empty staging folder too.
        if (Test-Path -LiteralPath $tempFolder) {
            [System.IO.Directory]::Delete($tempFolder, $false)
        }
    }
}

function Download-Velociraptor {  
    $VelociraptorFolder = Join-Path $toolsDirectory "Velociraptor"
    if (!(Test-Path $VelociraptorFolder)) {
        New-Item -ItemType Directory -Path $VelociraptorFolder | Out-Null
    }		
    $VelociraptorExecutable = Get-ChildItem -Path $VelociraptorFolder -Filter "Velociraptor*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "TempVelociraptor"
    Clear-EchoToolDirectory -Path $tempFolder
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
            throw "Tool download did not complete. See the preceding log entry."
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
        throw "Tool download did not complete. See the preceding log entry."
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
        $_.name -match '^velociraptor-v0\.74(?:\.\d+)?-windows-amd64\.exe$'
    } | Sort-Object -Descending -Property @{
        Expression = { if ($_.name -match '^velociraptor-v(0\.74(?:\.\d+)?)-') { [version]$matches[1] } }
    } | Select-Object -First 1

    $downloadUrl = if ($downloadAsset) { $downloadAsset.browser_download_url } else { $null }
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Velociraptor.exe not found in release $($selectedRelease.tag_name)." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
    Update-Log "Downloading Velociraptor $($selectedRelease.tag_name) (pinned to 0.74.x for current ECHO compatibility)." "tabPageToolsTextBox"
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Velociraptor: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }
	if (Test-Path $downloadPath) {
		$newHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
		$existingHash = if ($VelociraptorExecutable -and (Test-Path $VelociraptorExecutable)) { (Get-FileHash -Path $VelociraptorExecutable -Algorithm SHA256).Hash } else { "" }
	
		if (-not $VelociraptorExecutable -or $newHash -ne $existingHash) {
			Get-ChildItem -Path $VelociraptorFolder -Filter "Velociraptor*.exe" -Recurse | Remove-Item -Force
			$destinationPath = Join-Path $VelociraptorFolder $originalFileName
			Copy-Item -Path $downloadPath -Destination $destinationPath -Force -ErrorAction Stop

			Update-Log "Velociraptor updated." "tabPageToolsTextBox"
		} else {
			Update-Log "Velociraptor is already up-to-date." "tabPageToolsTextBox"
		}
	} else {
		Update-Log "Downloaded Velociraptor executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
	}
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $VelociraptorFolder -Filter 'velociraptor*.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed Velociraptor file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'velociraptor*.exe' -filePath $inventoryFile -PackageVersion $selectedRelease.tag_name -SourceUrl $downloadUrl
}

function Download-Volatility3 {
    $Volatility3Folder = Join-Path $toolsDirectory "Volatility3"
    if (!(Test-Path $Volatility3Folder)) {
        New-Item -ItemType Directory -Path $Volatility3Folder | Out-Null
    }		
    $Volatility3Executable = Get-ChildItem -Path $Volatility3Folder -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "TempVolatility3"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
	$apiUrl = "https://api.github.com/repos/volatilityfoundation/volatility3/releases/latest"
	$latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
	$tagName = $latestRelease.tag_name
	$downloadUrl = "https://github.com/volatilityfoundation/volatility3/archive/refs/tags/$tagName.zip"
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Volatility3 not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Volatility: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }
	if (Test-Path $downloadPath) {
		# Extract the downloaded zip file
		Expand-Archive -Path $downloadPath -DestinationPath $tempFolder -Force -ErrorAction Stop
		Remove-Item -Path $downloadPath -Force
		# Find vol.py in the extracted files
		$tempVolatilityExecutable = Get-ChildItem -Path $tempFolder -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
		if ($tempVolatilityExecutable) {
            # Refresh the complete release even when the launcher is unchanged.
				# Delete all existing contents before copying new files
				Clear-EchoToolDirectory -Path $Volatility3Folder
				Copy-Item -Path (Join-Path $tempFolder "*") -Destination $Volatility3Folder -Recurse -Force -ErrorAction Stop

				Update-Log "Volatility3 updated." "tabPageToolsTextBox"
		} else {
			Update-Log "vol.py not found in extracted Volatility3 files." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
		}
	} else {
		Update-Log "Downloaded Volatility3 package not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
	}
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $Volatility3Folder -Filter 'vol.py' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed Volatility3 file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'vol.py' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-winpmem {
    $winpmemFolder = Join-Path $toolsDirectory "winpmem"
    if (!(Test-Path $winpmemFolder)) {
        New-Item -ItemType Directory -Path $winpmemFolder | Out-Null
    }		
    $winpmemExecutable = Get-ChildItem -Path $winpmemFolder -Filter "winpmem*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "Tempwinpmem"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Velocidex/WinPmem/releases/latest"
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^winpmem.*x64.*exe$'
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for winpmem.exe not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download winpmem: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }
	if (Test-Path $downloadPath) {
		$newHash = (Get-FileHash -Path $downloadPath -Algorithm SHA256).Hash
		$existingHash = if ($winpmemExecutable -and (Test-Path $winpmemExecutable)) { (Get-FileHash -Path $winpmemExecutable -Algorithm SHA256).Hash } else { "" }
	
		if (-not $winpmemExecutable -or $newHash -ne $existingHash) {
			$destinationPath = Join-Path $winpmemFolder $originalFileName
			Copy-Item -Path $downloadPath -Destination $destinationPath -Force -ErrorAction Stop

			Update-Log "winpmem updated." "tabPageToolsTextBox"
		} else {
			Update-Log "winpmem is already up-to-date." "tabPageToolsTextBox"
		}
	} else {
		Update-Log "Downloaded winpmem executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
	}
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $winpmemFolder -Filter 'winpmem*.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed winpmem file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'winpmem*.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

function Download-ZimmermanTools {
    $ZimmermanToolsFolder = Join-Path $toolsDirectory "ZimmermanTools"
    if (!(Test-Path $ZimmermanToolsFolder)) {
        New-Item -ItemType Directory -Path $ZimmermanToolsFolder | Out-Null
    }	
    $tempFolder = Join-Path $toolsDirectory "TempZimmermanTools"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null


    $downloadUrl = "https://download.ericzimmermanstools.com/Get-ZimmermanTools.zip"
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download ZimmermanTools: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
    }
	
    $ZimmermanToolsPath = Join-Path $tempFolder "Get-ZimmermanTools.zip"
    if (Test-Path $ZimmermanToolsPath) {
        Expand-Archive -Path $ZimmermanToolsPath -DestinationPath $tempFolder -Force -ErrorAction Stop
        Remove-Item -Path $ZimmermanToolsPath -Force

        $scriptInTemp = Get-ChildItem -Path $tempFolder -Filter "Get-ZimmermanTools.ps1" -Recurse | Select-Object -ExpandProperty FullName -First 1		
        $newHash = (Get-FileHash -Path $scriptInTemp -Algorithm SHA256).Hash
        $existingZimmermanToolsPath = Join-Path $ZimmermanToolsFolder "Get-ZimmermanTools.ps1"
        $existingHash = if (Test-Path $existingZimmermanToolsPath) { (Get-FileHash -Path $existingZimmermanToolsPath -Algorithm SHA256).Hash } else { "" }

        if ($newHash -ne $existingHash) {
            Copy-Item -Path $scriptInTemp -Destination $ZimmermanToolsFolder -Force -ErrorAction Stop
            Add-ToolToCsv -toolName "Get-ZimmermanTools.ps1"
        }

	        # Run the Zimmerman Tools script regardless of hash change
	        $scriptPath = Join-Path $ZimmermanToolsFolder "Get-ZimmermanTools.ps1"
	        if (Test-Path $scriptPath) {
                $zimmermanArgs = "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" -Dest `"$ZimmermanToolsFolder`""
                Invoke-ExternalProcessQuiet -FilePath "powershell.exe" -ArgumentList $zimmermanArgs -WorkingDirectory $ZimmermanToolsFolder -ErrorContext "ZimmermanTools script execution" -TimeoutSeconds 1800
	            Get-ChildItem -LiteralPath $ZimmermanToolsFolder -Filter '*.exe' -Recurse -File | ForEach-Object {
                    Add-ToolToCsv -toolName $_.Name -filePath $_.FullName
                }
                Update-Log "ZimmermanTools script executed." "tabPageToolsTextBox"
	        }
    } else {
        Update-Log "Downloaded ZimmermanTools package not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
    }

    Remove-Item -Path $tempFolder -Recurse -Force
}

function Download-Zircolite {
	$7zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
	
	# Check if $7zipPath is null or an empty string
	if ([string]::IsNullOrWhiteSpace($7zipPath)) {
		Update-Log "7-Zip is required to download this tool for the extraction piece, but is not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
		throw "7-Zip (7za.exe) is required but was not found in the tools directory."
	}
    $ZircoliteFolder = Join-Path $toolsDirectory "Zircolite"
    if (!(Test-Path $ZircoliteFolder)) {
        New-Item -ItemType Directory -Path $ZircoliteFolder | Out-Null
    }		
    $ZircoliteExecutable = Get-ChildItem -Path $ZircoliteFolder -Filter "Zircolite*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    $tempFolder = Join-Path $toolsDirectory "TempZircolite"
    Clear-EchoToolDirectory -Path $tempFolder
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/wagga40/Zircolite/releases/latest"
    $latestRelease = Get-EchoLatestRelease -Uri $apiUrl
    Update-Log "Selected release: $($latestRelease.tag_name)" "tabPageToolsTextBox"
    $downloadUrl = Get-EchoReleaseAsset -Release $latestRelease -Pattern '^(?:Zircolite-[0-9.]+-windows-x64\.zip|zircolite_win.*\.7z)$'
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Zircolite.exe not found." "tabPageToolsTextBox"
		throw "Tool download did not complete. See the preceding log entry."
	}
	# Decode the URL to get the correct file name
	$decodedUrl = [System.Web.HttpUtility]::UrlDecode($downloadUrl)
	$originalFileName = Split-Path -Leaf $decodedUrl
	$downloadPath = Join-Path $tempFolder $originalFileName

    try {
        Update-Log "Downloading package: $downloadUrl" "tabPageToolsTextBox"
        Invoke-WebRequest -UseBasicParsing -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Zircolite: $_" "tabPageToolsTextBox"
        throw "Tool download did not complete. See the preceding log entry."
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
					Clear-EchoToolDirectory -Path $ZircoliteFolder
					}
					# Use 7-Zip to extract the ZIP file directly into the Zircolite folder
					$7zipArgs2 = "x `"$downloadPath`" -o`"$ZircoliteFolder`" -y"
					Invoke-ExternalProcessQuiet -FilePath $7zipPath -ArgumentList $7zipArgs2 -WorkingDirectory $ZircoliteFolder -ErrorContext "7-Zip extraction (final) for Zircolite"
                    $zircoliteExecutableToRun = Get-ChildItem -Path $ZircoliteFolder -Filter "Zircolite*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
                    if ([string]::IsNullOrWhiteSpace($zircoliteExecutableToRun)) {
                        throw "Zircolite executable missing from final installation."
                    }

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
                            throw
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
            throw "Expected tool file is missing after download/extraction."
	        }
    } else {
        Update-Log "Downloaded Zircolite executable not found." "tabPageToolsTextBox"
            throw "Expected tool file is missing after download/extraction."
    }

    # Cleanup: Delete the temporary folder
    Remove-Item -Path $tempFolder -Recurse -Force
    # Record provenance even when the selected binary hash is unchanged.
    $inventoryFile = Get-ChildItem -LiteralPath $ZircoliteFolder -Filter 'zircolite*.exe' -Recurse -File | Select-Object -ExpandProperty FullName -First 1
    if (-not $inventoryFile) { throw 'Installed Zircolite file missing; download is incomplete.' }
    Add-ToolToCsv -toolName 'zircolite*.exe' -filePath $inventoryFile -PackageVersion $latestRelease.tag_name -SourceUrl $downloadUrl
}

####End functions for Tools Tab####
