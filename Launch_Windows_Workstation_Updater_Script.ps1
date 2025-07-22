#Requires -Version 7.5.1
$WarningPreference = "Stop";
$ErrorActionPreference = "Stop";
$StartTime = $((Get-Date).ToString('MM-dd-yyyy_HH-mm-ss') )
Function ScriptDirectory {
    $Invocation = (Get-Variable MyInvocation -Scope 1).Value
    Split-Path $Invocation.MyCommand.Path
}
$scriptDir = ScriptDirectory

if (Test-Path -Path "$scriptDir/logs"){
    Write-Output "$scriptDir/logs already exists"
} else {
    Write-Output "Creating $scriptDir/logs directory"
    mkdir "$scriptDir/logs"
}

& .\Script_Functions.ps1 2>&1 | tee-object -Append "$scriptDir/logs/$StartTime-Windows_Workstation_Updater-$Env:ComputerName.log"
