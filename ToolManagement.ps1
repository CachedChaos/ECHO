$global:hasRunOnTabPageTools = $false

#Timer for downloading tools
$Global:tooldownloadJobs = @()
$tooldownloadJobTimer = New-Object System.Windows.Forms.Timer
$tooldownloadJobTimer.Interval = 2000
$tooldownloadJobTimer.Add_Tick({
    Check-tooldownloadJobStatus
})

####Starting functions for Tools Tab####

function Check-tooldownloadJobStatus {	
    # Initialize the completed job count
    $completedCount = 0
	
    foreach ($job in $Global:tooldownloadJobs) {
        $updatedJob = Get-Job -Id $job.JobObject.Id		
        if ($updatedJob.State -eq "Completed" -or $updatedJob.State -eq "Failed") {
            if (-not $job.DataAdded) {
				$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                Update-Log "Tool download completed: $($job.JobName)" "tabPageToolsTextBox"
				Update-Log "Results in $($toolsDirectory)" "tabPageToolsTextBox"
				Write-Host "$timestamp Tool download completed: $($job.JobName)"
				$job.DataAdded = $true		
            }
			$completedCount++
        }
	}
	
    if ($completedCount -eq $Global:tooldownloadJobs.Count) {
        Update-Log "All Tool download completed." "tabPageToolsTextBox"
        $tooldownloadJobTimer.Stop()
    }
}

function OnTabTabPageTools_GotFocus {
    if ($global:hasRunOnTabPageTools) {
        return
    }    		
    # Create subdirectory if it doesn't exist
    if (!(Test-Path $toolsDirectory)) {
        New-Item -ItemType Directory -Path $toolsDirectory | Out-Null
        Update-Log "Subdirectory 'Tools' created successfully." "tabPageToolsTextBox"
    }
	$global:hasRunOnTabPageTools = $true
}

function Add-ToolToCsv {
    param(
        [string]$toolName
    )
    $filePath = Get-ChildItem -Path $toolsDirectory -Filter "$toolName" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1

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
    $selectedOption = $ToolsSelectionComboBox.SelectedItem.Content.ToString()
    # Check for Internet Connection
    if (-not (Test-InternetConnection)) {
        Update-Log "Internet connection not available, cannot download tool." "tabPageToolsTextBox"
        return
    }

    Update-Log "Downloading $($selectedOption)..." "tabPageToolsTextBox"

    switch ($selectedOption) {
        "7zip" { Download-7zip }
        "BulkExtractor" { Download-BulkExtractor }
		"chainsaw" { Download-chainsaw }		
		"ClamAV" { Download-ClamAV }		
        "etl2pcapng" { Download-etl2pcapng }
        "Ftkimager" { Download-Ftkimager }
        "GeoLite2Databases" {
            # Check if 7zip is available
            $zipPath = Get-ChildItem -Path $toolsDirectory -Filter "7za.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
            if (-not $zipPath) {
                Update-Log "7-Zip is required but not found in the tools directory. Please download it first using the Tools Management page." "tabPageToolsTextBox"
                return
            }

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
                $secureLicenseKey = ConvertTo-SecureString $licenseKeyBox.Text -AsPlainText -Force
                Download-GeoLite2Databases -zipPath $zipPath -licenseKey $secureLicenseKey
            } else {
                Update-Log "GeoLite2 City download cancelled or no license key entered." "tabPageToolsTextBox"
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
        # Add other cases for different tools
    }
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
        Invoke-WebRequest -Uri $7zrUrl -OutFile $7zrPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download 7zip: $_" "tabPageToolsTextBox"
        return
    }

    # Download 7z2301-extra.7z
    $extra7zPath = Join-Path $tempFolder "7z2301-extra.7z"
    $extra7zUrl = "https://www.7-zip.org/a/7z2301-extra.7z"
    try {
        Invoke-WebRequest -Uri $extra7zUrl -OutFile $extra7zPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download 7zip: $_" "tabPageToolsTextBox"
        return
    }

    # Extract 7z2301-extra.7z using 7zr.exe
    Start-Process $7zrPath -ArgumentList "x `"$extra7zPath`" -o`"$tempFolder`" -y" -NoNewWindow -Wait

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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download chainsaw: $_" "tabPageToolsTextBox"
        return
    }
    if (Test-Path $downloadPath) {
        # Extract the zip file
		try {
			# Use 7-Zip to extract the ZIP file
			$7zipArgs = "x `"$downloadPath`" -o`"$tempFolder`" -y"
			Start-Process $7zipPath -ArgumentList $7zipArgs -NoNewWindow -Wait -ErrorAction Stop
		} catch {
			Update-Log "Failed to extract chainsaw with 7-Zip: $_" "tabPageToolsTextBox"
			return
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
				# Use 7-Zip to extract the ZIP file directly into the chainsaw folder
				$7zipArgs2 = "x `"$downloadPath`" -o`"$chainsawFolder`" -y"
				Start-Process $7zipPath -ArgumentList $7zipArgs2 -NoNewWindow -Wait -ErrorAction Stop
                Add-ToolToCsv -toolName (Split-Path -Leaf $extractedExecutable)
                Update-Log "chainsaw updated." "tabPageToolsTextBox"
            } else {
                Update-Log "chainsaw is already up-to-date." "tabPageToolsTextBox"
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
    $tempFolder = Join-Path $toolsDirectory "TempClamAV"
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null

    # Base URL for ClamAV website
    $baseUrl = "https://www.clamav.net"
    
    # Retrieve the latest release page and parse the download URL
    $apiUrl = "$baseUrl/downloads"
    $userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
    $latestReleasePage = Invoke-WebRequest -Uri $apiUrl -Headers @{ "User-Agent" = $userAgent }
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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
			$freshclamDirectory = Split-Path $freshclamPath
			Start-Process -FilePath $freshclamPath -WorkingDirectory $freshclamDirectory -Wait -NoNewWindow
			Update-Log "ClamAV database updated." "tabPageToolsTextBox"
		} else {
			Update-Log "freshclam.exe not found in ClamAV directory." "tabPageToolsTextBox"
		}
	} catch {
		Update-Log "Error updating ClamAV database: $_" "tabPageToolsTextBox"
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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

    # Clear the log screen
    $targetLog = $window.FindName("tabPageToolsTextBox")
    if ($targetLog -ne $null) {
        $targetLog.Clear()
    }

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
        Invoke-WebRequest -Uri $dbUrls[$db] -OutFile $downloadPath

        # Extract the downloaded database using 7zip
        Start-Process $zipPath -ArgumentList "x `"$downloadPath`" -o`"$tempFolder`" -y" -NoNewWindow -Wait
        $downloadPath = Join-Path $tempFolder ("GeoLite2" + $db + ".tar")
        Start-Process $zipPath -ArgumentList "x `"$downloadPath`" -o`"$tempFolder`" -y" -NoNewWindow -Wait

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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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

    # Check if both loki.exe and loki-upgrader.exe exist
    if ($LokiExecutable -and $LokiUpgraderExecutable -and (Test-Path $LokiExecutable) -and (Test-Path $LokiUpgraderExecutable)) {
        # Only run loki-upgrader.exe
        try {
            $lokiUpgraderDirectory = Split-Path $LokiUpgraderExecutable
            Start-Process -FilePath $LokiUpgraderExecutable -WorkingDirectory $lokiUpgraderDirectory -Wait -NoNewWindow
            Update-Log "Loki signatures updated." "tabPageToolsTextBox"
        } catch {
            Update-Log "Error updating Loki signatures: $_" "tabPageToolsTextBox"
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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
            $lokiUpgraderDirectory = Split-Path $lokiUpgraderPath
            Start-Process -FilePath $lokiUpgraderPath -WorkingDirectory $lokiUpgraderDirectory -Wait -NoNewWindow
            Update-Log "Loki signatures updated." "tabPageToolsTextBox"
        } else {
            Update-Log "loki-upgrader.exe not found in Loki directory." "tabPageToolsTextBox"
        }
    } catch {
        Update-Log "Error updating Loki signatures: $_" "tabPageToolsTextBox"
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $tarGzPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Plaso: $_" "tabPageToolsTextBox"
        return
    }
    if (Test-Path $tarGzPath) {
        # Extract .gz
        $tarPath = $tarGzPath -replace '\.gz$', ''
        Start-Process $7zipPath -ArgumentList "e `"$tarGzPath`" `-o`"$tempFolder`" -y" -NoNewWindow -Wait
        # Extract .tar
        Start-Process $7zipPath -ArgumentList "x `"$tarPath`" `-o`"$tempFolder`" -y" -NoNewWindow -Wait
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

    # Get the latest release URL from GitHub API
    $apiUrl = "https://api.github.com/repos/Velocidex/velociraptor/releases/latest"
    $latestRelease = Invoke-RestMethod -Uri $apiUrl -Headers @{ "User-Agent" = "PowerShell" }
    $downloadUrl = $latestRelease.assets | Where-Object { $_.name -match '^velociraptor-v.*amd64.exe$' } | Select-Object -ExpandProperty browser_download_url -First 1
	if ([string]::IsNullOrWhiteSpace($downloadUrl)) {
		Update-Log "Download URL for Velociraptor.exe not found." "tabPageToolsTextBox"
		return
	}
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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


    $downloadUrl = "https://f001.backblazeb2.com/file/EricZimmermanTools/Get-ZimmermanTools.zip"
	$originalFileName = Split-Path -Leaf $downloadUrl
	$downloadPath = Join-Path $tempFolder $originalFileName	
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
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
            Start-Process "powershell.exe" -ArgumentList "-NoExit", "-File `"$scriptPath`"" -WorkingDirectory $ZimmermanToolsFolder -NoNewWindow
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
        Invoke-WebRequest -Uri $downloadUrl -OutFile $downloadPath -ErrorAction Stop
    } catch {
        Update-Log "Failed to download Zircolite: $_" "tabPageToolsTextBox"
        return
    }
    if (Test-Path $downloadPath) {
        # Extract the zip file
		try {
			# Use 7-Zip to extract the ZIP file
			$7zipArgs = "x `"$downloadPath`" -o`"$tempFolder`" -y"
			Start-Process $7zipPath -ArgumentList $7zipArgs -NoNewWindow -Wait -ErrorAction Stop
		} catch {
			Update-Log "Failed to extract Zircolite with 7-Zip: $_" "tabPageToolsTextBox"
			return
		}

        # Identify the executable based on pattern
        $extractedExecutable = Get-ChildItem -Path $tempFolder -Filter "Zircolite*.exe" -Recurse | Select-Object -ExpandProperty FullName -First 1

        if ($extractedExecutable) {
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
				Start-Process $7zipPath -ArgumentList $7zipArgs2 -NoNewWindow -Wait -ErrorAction Stop
                Add-ToolToCsv -toolName (Split-Path -Leaf $extractedExecutable)
                Update-Log "Zircolite updated." "tabPageToolsTextBox"
            } else {
                Update-Log "Zircolite is already up-to-date." "tabPageToolsTextBox"
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