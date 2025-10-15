#Ryan Naylor
#Requires -Version 7.5.2
$WarningPreference = "Stop";
$ErrorActionPreference = "Stop";
$StartTime = $((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))
Function ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}
$scriptDir = ScriptDirectory
# Define the file share path and output CSV
function SafeExtract {
    param (
        [string[]]$Content,
        [string]$Pattern
    )
    $match = $Content | Select-String -Pattern $Pattern
    if ($match) {
        return $match.Matches.Groups[1].Value.Trim()
    } else {
        Write-Output "Field N/A"
        return "N/A"
    }
}

function Convert-DateFormat {
    param (
        [string]$DateString
    )
    try {
        $dt = [datetime]::ParseExact($DateString, "MM-dd-yyyy_HH-mm-ss", $null)
        return $dt.ToString("yyyyMMdd_HH-mm-ss")
    } catch {
        try {
            $dt = [datetime]::ParseExact($DateString, "yyyy-MM-dd_HH-mm-ss", $null)
            return $dt.ToString("yyyyMMdd_HH-mm-ss")
        } catch {
            return $DateString
        }
    }
}

# Define the file share path and output CSV
if (Test-Path -Path "$scriptDir\reports"){
    Write-Output "$scriptDir\reports already exists"
} else {
    Write-Output "Creating $scriptDir\reports directory"
    mkdir "$scriptDir\reports"
}

# Ensure logs directory exists
if (Test-Path "$scriptDir\logs")
{
    Write-Output "Successfully found $scriptDir\logs"
} else {
    Write-Output "Could not find $scriptDir\logs"
    exit 1
}

# Initialize an array to hold parsed data
$results = @()

# Get all log files in the share
$logFiles = Get-ChildItem -Path "$scriptDir\logs" -Filter "*.log" | Sort-Object creationtime -Descending

foreach ($logFile in $logFiles) {
    Write-Output "Working on $logFile..."
    $content = Get-Content $logFile.FullName
    $hostName      = SafeExtract -Content $content -Pattern "Host Name:\s*(.+)"
    $osName        = SafeExtract -Content $content -Pattern "OS Name:\s*(.+)"
    $systemModel   = SafeExtract -Content $content -Pattern "System Model:\s*(.+)"
    $uptime        = SafeExtract -Content $content -Pattern "System Uptime in Days:\s*(\d+)"
    $scriptVer     = SafeExtract -Content $content -Pattern "Script Version:\s*(\d+)"
    $biosVer       = SafeExtract -Content $content -Pattern "BIOS Version:\s*(.+)"
    $dateRaw       = SafeExtract -Content $content -Pattern "Date:\s*(.+)"
    $dateFormatted = Convert-DateFormat -DateString $dateRaw
    $logFile       = Split-Path $logFile -Leaf

    $results += [PSCustomObject]@{
        "Host Name"             = $hostName
        "OS Name"               = $osName
        "System Model"          = $systemModel
        "BIOS Version"          = $biosVer
        "System Uptime In Days" = $uptime
        "Script Version"        = $scriptVer
        "Run Date"              = $dateFormatted
        "Log_File"              = $logFile
    }
}

# Deduplicate by Host Name and Date
$deduplicated = $results | Sort-Object -Property "Host Name" -Unique | Select-Object "Host Name", "OS Name", "System Model", "BIOS Version", "System Uptime In Days", "Script Version", "Run Date", "Log_File"
# Export to CSV
$deduplicated | Export-Csv -Path "$scriptDir\reports\$StartTime-Windows_Workstation_Updater_Report.csv" -NoTypeInformation -Encoding UTF8

Write-Output "Deduplicated log parsing complete."
Write-Output "Output saved to $scriptDir\reports\$StartTime-Windows_Workstation_Updater_Report.csv"


# Ensure logs directory exists
if (Test-Path "$scriptDir\logs\old")
{
    Write-Output "Successfully found $scriptDir\logs\old"
} else {
    Write-Output "Creating $scriptDir\logs\old directory"
    mkdir "$scriptDir\logs\old"
}

Write-Output "Moving older log files to old, keeping the latest per Host Name"
# Move files not in the keep list
foreach ($logFile in $logFiles) {
    $LogFileLeaf = Split-Path $logFile.Name -Leaf
    Write-Output "Processing $LogFileLeaf..."
    if ($deduplicated.Log_File -notcontains $LogFileLeaf) {
        Write-Output "Moving $LogFileLeaf to $scriptDir\logs\old"
        Move-Item -Path $logFile.FullName -Destination "$scriptDir\logs\old"
    } else {
        Write-Output "$LogFileLeaf is the current log file."
    }
}

Write-Output "Done"