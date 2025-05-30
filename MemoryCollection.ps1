$global:hasRunOnTabCollectMemory = $false

$Global:windowsPlugins = @{
	"dlllist" = "windows.dlllist";
    "pslist" = "windows.pslist";
    "pstree" = "windows.pstree";
	"psscan" = "windows.psscan";
	"cmdline" = "windows.cmdline";
    "filescan" = "windows.filescan";
	"getsids" = "windows.getsids";
	"registry.hivelist" = "windows.registry.hivelist";
#   "handles" = "windows.handles";
	"malfind" = "windows.malfind";
	"sessions" = "windows.sessions";
	"timeliner" = "timeliner"	
}

$Global:linuxPlugins = @{
	"bash" = "linux.bash"
	"lsmod" = "linux.lsmod"
	"lsof" = "linux.lsof"
	"malfind" = "linux.malfind"
	"mountinfo" = "linux.mountinfo"
	"proc" = "linux.proc"
    "psaux" = "linux.psaux"
    "pslist" = "linux.pslist"
    "psscan" = "linux.psscan"
    "pstree" = "linux.pstree"
    "sockstat" = "linux.sockstat"
    "tty_check" = "linux.tty_check"
    "timeliner" = "timeliner"
}

$Global:macPlugins = @{
	"bash" = "mac.bash"
	"check_syscall" = "mac.check_syscall"
	"check_sysctl" = "mac.check_sysctl"
	"check_trap_table" = "mac.check_trap_table"
	"ifconfig" = "mac.ifconfig"
	"kevents" = "mac.kevents"
	"list_files" = "mac.list_files"
	"lsmod" = "mac.lsmod"
	"lsof" = "mac.lsof"
	"malfind" = "mac.malfind"
	"mount" = "mac.mount"
	"netstat" = "mac.netstat"
	"proc_maps" = "mac.proc_maps"
	"psaux" = "mac.psaux"
	"pslist" = "mac.pslist"
	"pstree" = "mac.pstree"
	"socket_filters" = "mac.socket_filters"
	"timeliner" = "timeliner"
}

#Timer for volatility initialization
$volJobTimer = New-Object System.Windows.Forms.Timer
$volJobTimer.Interval = 2000
$volJobTimer.Add_Tick({
    Check-VolJobStatus
})

##memoryfunctions start
function OnTabCollectMemory_GotFocus {
    if ($global:hasRunOnTabCollectMemory) {
        return
    }    
    $subDirectoryPath = Join-Path $global:currentcasedirectory "MemoryArtifacts"

    # Check if the subdirectory exists, if not, create it
    if (!(Test-Path $subDirectoryPath)) {
        New-Item -ItemType Directory -Path $subDirectoryPath | Out-Null
        Update-Log "Subdirectory 'MemoryArtifacts' created successfully." "MemoryTextBox"
    }
	
    if (-not (IsValidPath $VolatilityPathTextBox.Text "vol.py")) {
        Find-VolExecutable
    }
    if (-not (IsValidPath $WinpmemPathTextBox.Text "winpmem*.exe")) {
        Find-WinpmemExecutable
    }
	$global:hasRunOnTabCollectMemory = $true
}

function IsValidPath($path, $pattern) {
    if ([string]::IsNullOrEmpty($path)) {
        return $false
    }

    # If pattern contains '*', treat it as a regex pattern
    if ($pattern -like "*\*") {
        # Convert wildcard pattern to regex pattern
        $regexPattern = "^" + [regex]::Escape($pattern).Replace('\*', '.*') + "$"
        return ($path -match $regexPattern) -and (Test-Path $path)
    } else {
        return $path.EndsWith($pattern) -and (Test-Path $path)
    }
}

function Find-WinpmemExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $wimpmemPath = Get-ChildItem -Path $toolsDirectory -Filter "winpmem*.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($wimpmemPath) {
        $WinpmemPathTextBox.Text = $wimpmemPath
    }
}

function Find-VolExecutable {
    $toolsDirectory = Join-Path $executableDirectory "Tools" 
    $volPath = Get-ChildItem -Path $toolsDirectory -Filter "vol.py" -Recurse -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FullName -First 1
    if ($volPath) {
        $VolatilityPathTextBox.Text = $volPath
    }
}

function StartMemoryCaptureButton_Click {
    Update-Log "Collecting Memory..." "MemoryTextBox"
    Capture-Memory
}

function Capture-Memory {
    $winpmemPath = $WinpmemPathTextBox.Text
    if (-not $winpmemPath -or -not (Test-Path $winpmemPath)) {
        Update-Log "Winpmem executable path is not valid." "MemoryTextBox"
        return
    }

    # Capture memory
    $currentTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $systemName = $env:COMPUTERNAME
    $memoryFileName = "$currentTimestamp`_$systemName`_memdump.raw"
    $memorySubDirectory = Join-Path $global:currentcasedirectory "MemoryArtifacts\$systemName"
    $memoryFilePath = Join-Path $memorySubDirectory $memoryFileName

    if (-not (Test-Path $memorySubDirectory)) {
        New-Item -Path $memorySubDirectory -ItemType Directory -Force
    }

    # Save Windows version and patch level
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $windowsVersion = $osInfo.Caption
    $patchLevel = $osInfo.ServicePackMajorVersion
    $windowsVersionFile = Join-Path $memorySubDirectory "WindowsVersion.txt"
    Set-Content -Path $windowsVersionFile -Value "Windows Version: $windowsVersion`r`nPatch Level: Service Pack $patchLevel"
	$captureCommand = "`"$memoryFilePath`""
	Update-Log "Executing command: $winpmemPath $captureCommand" "MemoryTextBox"
	Start-Process -FilePath $winpmemPath -ArgumentList $captureCommand

    Update-Log "Memory capture started in new window." "MemoryTextBox"
}

function Check-VolJobStatus {
    foreach ($job in $Global:volJobs) {
        if ($job.JobObject.JobStateInfo.State -eq "Completed" -or $job.JobObject.JobStateInfo.State -eq "Failed") {
            if (-not $job.DataAdded) {
                Update-Log "Finished Volatility plugin: $($job.PluginName)" "MemoryTextBox"
                $job.DataAdded = $true
                $Global:completedJobs++
            }
        }
    }

    if ($Global:completedJobs -ge $Global:volJobs.Count) {
        Update-Log "All jobs completed." "MemoryTextBox"
        $volJobTimer.Stop() # Stop the timer after all jobs are completed
    }
}

function ProcessVolatilityButton_Click {
    Update-Log "Processing Memory..." "MemoryTextBox"

    # Validations
    if (-not $MemoryPathTextBox.Text -or -not $OSSelectionComboBox.SelectedItem -or -not $PluginsComboBox.SelectedItem) {
        [System.Windows.MessageBox]::Show("Please select a memory path, OS type, and a plugin.")
        return
    }

    if (-not (Check-PythonInstalled)) {
        [System.Windows.MessageBox]::Show("Python is not installed. Please install Python to continue.")
        return
    }

    # Processing with selected options
	$volatilityPath  = $VolatilityPathTextBox.Text.trim().Trim('"')
    $memoryFilePath = $MemoryPathTextBox.Text.trim().Trim('"')
    $selectedOs = $OSSelectionComboBox.SelectedItem
    $selectedPlugin = $PluginsComboBox.SelectedItem
	if ([string]::IsNullOrWhiteSpace($memoryFilePath)) {
		Write-Warning "Memory file path is null or empty."
		return
	}
	
    Process-Volatility -MemoryFilePath $memoryFilePath -OS $selectedOs -Plugin $selectedPlugin -VolatilityPath $volatilityPath
	$volJobTimer.Start() # Start the timer when processing begins
}

function Process-Volatility {
    param(
        [string]$MemoryFilePath,
        [string]$OS,
        [string]$Plugin,
		[string]$VolatilityPath
    )
	
    $Global:volJobs = @()
    $Global:completedJobs = 0	
	
	$memorySubDirectory = Join-Path $global:currentcasedirectory "MemoryArtifacts"
	if ([string]::IsNullOrWhiteSpace($memoryFilePath)) {
		Write-Warning "Memory file path is null or empty."
		return
	}

    # Access global plugin dictionaries
    $selectedPlugins = @{}
    switch ($OS) {
        "Windows" { $selectedPlugins = $Global:windowsPlugins }
        "Linux"   { $selectedPlugins = $Global:linuxPlugins }
        "Mac"     { $selectedPlugins = $Global:macPlugins }
    }

	$pluginToRun = if ($Plugin -eq "All Plugins") { $selectedPlugins } else { @{$Plugin = $selectedPlugins[$Plugin]} }

    # Run the selected plugins
    $memoryFileName = (Split-Path $memoryFilePath -Leaf).TrimEnd('.raw')
    $volOutputDirectory = Join-Path $memorySubDirectory "VolOutput\$memoryFileName"
    if (-not (Test-Path $volOutputDirectory)) {
        $null = New-Item -Path $volOutputDirectory -ItemType Directory -Force
    }
    
    $job = Start-Job -ScriptBlock {
        param($volatilityPath, $memoryFilePath, $pluginsToRun, $volOutputDirectory)
        
        foreach ($pluginName in $pluginsToRun.Keys) {
            $plugin = $pluginsToRun[$pluginName]
            $pluginCommand = "python `"$volatilityPath`" -f `"$memoryFilePath`" -q -r csv $plugin"
            try {
                $output = Invoke-Expression $pluginCommand
                $memoryFileName = (Split-Path $memoryFilePath -Leaf).TrimEnd('.raw')
                $outputFile = Join-Path $volOutputDirectory "$memoryFileName`_$pluginName.csv"
                $output | ConvertFrom-Csv | Export-Csv $outputFile -NoTypeInformation
            } catch {
                Write-Warning "Failed to process plugin $pluginName"
            }
        }
    } -ArgumentList $VolatilityPath, $MemoryFilePath, $pluginToRun, $volOutputDirectory

    $Global:volJobs += [PSCustomObject]@{
        JobObject = $job
        PluginName = $Plugin
        DataAdded = $false
    }
}