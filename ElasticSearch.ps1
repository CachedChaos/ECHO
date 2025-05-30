####Start Elastic Search Functions####
function OnTabElasticSearch_GotFocus {
    $subDirectoryPath = Join-Path $global:currentcasedirectory "Elastic"
    $global:elasticIOCFilePath = Join-Path $subDirectoryPath "CustomIOCs.txt"
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'Elastic' created successfully." "ElasticSearchTextBox"
    }

    foreach ($path in @($elasticIOCFilePath)) {
        if (!(Test-Path $path)) {
            New-Item -ItemType File -Path $path | Out-Null
            Update-Log "File '$(Split-Path $path -Leaf)' created successfully." "ElasticSearchTextBox"
        }
    }
}

function ElasticSearchButton_Click {
    $baseKibanaUrl = $ElasticURLPathTextBox.Text.Trim().TrimEnd('/')
    # Ensure the URL starts with http:// or https://
    if (-not $baseKibanaUrl.StartsWith("http://") -and -not $baseKibanaUrl.StartsWith("https://")) {
        [System.Windows.MessageBox]::Show("Please enter a valid URL starting with http:// or https://")
        return
    }
	
	$IndexPattern = $ElasticIndexIDTextBox.Text.trim()
    $selectedItem = $ElasticCheckBoxListBox.SelectedItem
    if ($selectedItem -eq $null) {
        [System.Windows.MessageBox]::Show("Please select a query from the list.")
        return
    }

	$selectedQueryKey = $selectedItem.ToString()
	
	$selectedItemDetails = $queryMapping[$selectedQueryKey]
	if ($selectedItemDetails -eq $null) {
		[System.Windows.MessageBox]::Show("Selected query not found in query mapping.")
		return
	}
	
	$selectedQuery = $selectedItemDetails["Query"]
	$selectedColumns = $selectedItemDetails["Columns"] -join ',' 

    # Initialize an array to hold IOCs and custom search strings
    $iocs = @()
    
    # Process the selected IOC item
    $selectedIOCItem = $ElasticCustomIOCComboBox.SelectedItem.Content
    if ($selectedIOCItem -eq "CustomIOCs.txt") {
        try {
            $iocs = Get-Content -Path $global:elasticIOCFilePath -ErrorAction Stop
        } catch {
            [System.Windows.MessageBox]::Show("Error reading CustomIOCs.txt")
            return
        }
    }

    # Add the custom search string to the IOC list
    $customQuery = $ElasticSearchIOCTextBox.Text.Trim()
    if (-not [string]::IsNullOrWhiteSpace($customQuery)) {
        $iocs += $customQuery
    }

    # Build the IOC query part with wildcards
    $iocQueryPart = ""
	if ($iocs.Count -gt 0) {
		$formattedIOCs = $iocs | ForEach-Object {
			if (ShouldQuote $_) {
				"`"$_`""
			} else {
				$_
			}
		}
		$iocQueryPart = $formattedIOCs -join " or "
		$iocQueryPart = " and ($iocQueryPart)"
	}

    # Combine the selected query with the IOC query part
    $combinedQuery = $selectedQuery + $iocQueryPart

	$discoverAppPath = "/app/kibana#/discover/"
	$encodedQuery = [uri]::EscapeDataString($combinedQuery)
	$appStateColumns = "!($selectedColumns)" 
	$globalState = "(filters:!(),refreshInterval:(pause:!t,value:60000),time:(from:now-1y%2Fd,to:now))"  # Added time filters
	$appState = "(columns:$appStateColumns,filters:!(),index:'$IndexPattern',interval:auto,query:(language:kuery,query:'$encodedQuery'),sort:!(!(timestamp,desc)))"

    if ($combinedQuery.StartsWith("=")) {
        [System.Windows.MessageBox]::Show("Invalid query format.")
        return
    }
	$fullUrl = "$($baseKibanaUrl)$($discoverAppPath)?_g=$($globalState)&_a=$($appState)"

    Write-Host "Elastic URL: $baseKibanaUrl"
	Update-Log "Elastic URL: $baseKibanaUrl" "ElasticSearchTextBox"
	Write-Host "URL: $fullUrl"
	Update-Log "URL: $fullUrl" "ElasticSearchTextBox"
	Start-Process $fullUrl

}

function ShouldQuote($term) {
    # Add more special characters if needed
    $specialChars = ' ', ',', '/', ':', ';'
    foreach ($char in $specialChars) {
        if ($term.Contains($char)) {
            return $true
        }
    }
    return $false
}

function UpdateElasticSearchButtonState {
    $isURLPathValid = -not [string]::IsNullOrWhiteSpace($ElasticURLPathTextBox.Text)
    $isIndexIDValid = -not [string]::IsNullOrWhiteSpace($ElasticIndexIDTextBox.Text)
    $ElasticSearchButton.IsEnabled = $isURLPathValid -and $isIndexIDValid
}
####End Elastic Search Functions####