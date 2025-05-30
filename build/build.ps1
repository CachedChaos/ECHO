# build/build.ps1

# The parent directory of the current script (the main project folder)
$sourceDir = Split-Path $PSScriptRoot -Parent

$files = @(
    "ArtifactCollection.ps1",
    "ArtifactProcessing.ps1",
    "DiskImage.ps1",
    "ElasticSearch.ps1",
    "EvidenceSync.ps1",
    "M365Collection.ps1",
    "MemoryCollection.ps1",
    "PacketCapture.ps1",
    "ThreatScanners.ps1",
    "ToolManagement.ps1",
    "_EchoMain.ps1"
)

# Prefix each filename with the parent folder path
$files = $files | ForEach-Object { Join-Path $sourceDir $_ }

# Where to put the combined file (in build/)
$output = Join-Path $PSScriptRoot "ECHO_combined.ps1"
Remove-Item $output -ErrorAction SilentlyContinue

foreach ($file in $files) {
    $filename = Split-Path $file -Leaf
    if ($filename -eq "_EchoMain.ps1") {
        $content = Get-Content $file
        $content = $content | Where-Object { $_ -notmatch '^\.\s*"\$PSScriptRoot\\.*\.ps1"' }
        $content = $content -replace '^\s*#\$executableDirectory = \[System\.AppDomain\]::CurrentDomain\.BaseDirectory', '$executableDirectory = [System.AppDomain]::CurrentDomain.BaseDirectory'
        $content = $content -replace '^\s*\$executableDirectory = Split-Path -Parent \$PSCommandPath', '#$executableDirectory = Split-Path -Parent $PSCommandPath'

        Add-Content -Path $output -Value "`n# ---- $filename ----`n"
        $content | Add-Content -Path $output
    } else {
        Add-Content -Path $output -Value "`n# ---- $filename ----`n"
        Get-Content $file | Add-Content -Path $output
    }
}

# Call PS2EXE (adjust icon path if needed)
Invoke-PS2EXE $output (Join-Path $PSScriptRoot "ECHO.exe") -noConsole -noOutput -requireAdmin -icon (Join-Path $sourceDir "ECHOicon.ico") -title 'ECHO' -version '0.2.4' -product 'Evidence Handling & Processing Orchestrator'
