$ScriptVersion = '20250711'
$Author = 'Ryan Naylor'
$WarningPreference = "Stop";
$ErrorActionPreference = "Stop";

Function Application_Exists
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $application
    )

    return [bool](Get-Command -Name $application -ErrorAction SilentlyContinue)
}

Function Confirm_Administator
{
    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {
        Write-Warning "Powershell is not running with Administrator rights"
        exit 1
    }
    else
    {
        Write-Output "Powershell is running with Administrator rights"
    }
}

Function Confirm_OS
{
    $CurrentComputerOS = Get-ComputerInfo | Select-Object WindowsProductName
    Write-Output "Operating System: $CurrentComputerOS"
    if ($CurrentComputerOS -like '*2016*')
    {
        Write-Output "ERROR: Windows Server 2016 found."
        exit 1
    }
    elseif ($CurrentComputerOS -like '*2012*')
    {
        Write-Output "ERROR: Windows Server 2012 found."
        exit 1
    }
}

Function Environment_Details
{
    Write-Output "Windows_Workstation_Updater by $Author"
    Write-Output "Script Version: $ScriptVersion"
    Write-Output "Date: $((Get-Date).ToString('MM-dd-yyyy_HH-mm-ss') )"
    Write-Output "Script Directory: $scriptDir"
    Write-output "User: $env:username"
    Write-output "Domain: $Env:UserDomain"
    Write-output "Computer: $Env:ComputerName"
    Confirm_Administator
    UptimeInDays
    Write-Output "SystemInfo ----------------------------------"
    systeminfo
    Write-Output "END SystemInfo ------------------------------"
}

Function Launch_Application
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $application,
        [Parameter(Mandatory = $true)] [string] $proc
    )
    Do
    {
        $Answer = Read-Host -Prompt "Launch $application GUI? (y/n)"
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to Launch $application GUI"
    }
    else
    {
        Write-Output "Launching $application GUI"
        Start-Process $proc
        Start-Sleep 3
        Do
        {
            $Answer = Read-Host -Prompt "Are you done with $application GUI? (y)"
        }
        Until ($Answer -eq 'y')
    }
}

Function Launch_Dell_Support_Assist_GUI
{
    if (systeminfo | findstr /l Dell)
    {
        $application = "Dell Support Assist"
        Do
        {
            $Answer = Read-Host -Prompt "Launch $application GUI? (y/n)"
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
            Write-Output "User chose not to Launch $application GUI"
        }
        else
        {
            Write-Output "Launching $application GUI"
            $ErrorActionPreference = 'Continue'
            Start-Process "shell:AppsFolder\$(Get-StartApps "SupportAssist" | Select-Object -ExpandProperty AppId)" -PassThru
            $ErrorActionPreference = 'Stop'
            Start-Sleep 5
            Write-Output "Done: Launching $application GUI"
            Do
            {
                $Answer = Read-Host -Prompt "Are you done with $application GUI? (y)"
            }
            Until ($Answer -eq 'y')
        }
    }
    else
    {
        Write-Output "Did not find Dell in the systeminfo.  This is not a Dell Computer.  Not Launching Dell Support Assist."
    }
}

Function Launch_Office_Updater_GUI
{
    if ( Test-Path "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" -PathType Leaf)
    {
        $application = 'Microsoft Office Updater'
        Do
        {
        $Answer = Read-Host -Prompt "Launch $application GUI? (y/n)"
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
        Write-Output "User chose not to Launch $application GUI"
        }
        else
        {
        Write-Output "Launching $application GUI"
        Start-Process "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" "/update user"
        Start-Sleep 3
        Do
        {
        $Answer = Read-Host -Prompt "Are you done with $application GUI? (y)"
        }
        Until ($Answer -eq 'y')
        }
        Write-Output "Done: Launching $application GUI"
    } else {
        Write-Output "Did not find Office Installed."
    }
}

Function Launch_Visual_Studio_Installer_GUI
{
    if ( Test-Path 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe' -PathType Leaf)
    {
    Launch_Application 'Visual Studio Installer' 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe'
    } else {
        Write-Output "Did not find Visual Studio Installed."
    }
}

Function Powershell_Module_Install_Update
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $Module
    )
    if (Get-Module -ListAvailable -Name $Module) {
        Write-Output "Updating Powershell Module: $Module..."
        Update-Module -Name $Module
    }
    else {
        Write-Output "Installing Powershell Module: $Module..."
        Install-Module $Module -Force
    }
    Write-Output "Importing Powershell Module: $Module..."
    Import-Module $Module
}

Function Prompt_Reboot
{
    Do
    {
        $Answer = Read-Host -Prompt 'Reboot Computer? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to reboot computer."
    }
    else
    {
        Write-Output "User chose to reboot computer.  Reboot in 15 seconds."
        Restart-Computer
    }
}

Function Prompt_Windows_Active_Users
{
    query user
    if ((@(query user).Count - 1) -eq 1)
    {
        Write-Host "Your the only user logged into this computer"
    }
    else
    {
        Write-Host "Your not the only user logged in"
        Do
        {
            $Answer = Read-Host -Prompt 'Your not the only user logged into this computer.  Continue? (y/n)'
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
            Write-Output "User chose to not continue."
            exit 0
        }
        else
        {
            Write-Output "User chose to continue despite other users logged into this computer."
        }

    }
}

Function Sleeper
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $totalDuration,
        [Parameter(Mandatory = $true)] [string] $sleepInterval
    )
    # Define the total duration in seconds
    # Define the sleep interval in seconds
    # Loop until the remaining time is greater than zero
    while ($totalDuration -gt 0)
    {
        # Print the remaining time
        Write-Host "Remaining time: $totalDuration seconds..."

        # Sleep for the specified interval
        Start-Sleep -Seconds $sleepInterval

        # Decrease the remaining time by the sleep interval
        $totalDuration -= $sleepInterval
    }

    # Print a triumphant message when the loop is done
    Write-Host "Done Sleeping for $totalDuration seconds"

}

Function UptimeInDays
{
    $LastBootupTime = invoke-command -ScriptBlock { Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object LastBootUpTime }
    $LastBootupTime = $LastBootupTime.LastBootupTime
    $CurrentDate = Get-Date
    $Uptime = $CurrentDate - $LastBootupTime
    $UptimeInDays = $uptime.days
    Write-Output "System Uptime in Days: $UptimeInDays"
}

Function Windows_Update_Microsoft_Update
{
    #https://woshub.com/pswindowsupdate-module/

    Do
    {
        $Answer = Read-Host -Prompt 'Run Windows Update including Microsoft Products update? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to run Windows Update including Microsoft Products update."
    }
    else
    {
        Write-Output "User chose run Windows Update including Microsoft Products update."
        Powershell_Module_Install_Update 'PSWindowsUpdate'
        Write-Output "Scanning and Downloading for available updates..."
        Get-WindowsUpdate -MicrosoftUpdate -Download -AcceptAll
        Write-Output "Installing available updates..."
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
        Write-Output "Done: Windows Update including Microsoft Products update."
    }
}

#Function Windows_Workstation_Create_Scheduled_Task
#{
#    if (Get-ScheduledTask -TaskName 'Windows_Workstation_Updater')
#    {
#        Write-Output "Windows_Workstation_Updater already exists."
#    }
#    else
#    {
#        Write-Output "Creating Windows Workstation Scheduled Task"
#        # Specify the trigger settings
#        $triggers = @(
#            New-ScheduledTaskTrigger -Daily -At 11:30
#            New-ScheduledTaskTrigger -AtLogon
#        )
#
#        $actions = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "$InstallDir\Launch_Windows_Workstation_Updater_Script.ps1"
#
#        #https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/new-scheduledtasksettingsset?view=windowsserver2022-ps
#        $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -RunOnlyIfIdle -IdleDuration 00:02:00 -IdleWaitTimeout 02:00:00 -DontStopOnIdleEnd -ExecutionTimeLimit (New-TimeSpan -Hours 1)
#
#        $principals = New-ScheduledTaskPrincipal -UserID "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
#
#        Register-ScheduledTask -TaskName "Windows_Workstation_Updater" -Description "Windows_Workstation_Updater" -TaskPath "Windows_Workstation_Updater" -Action $actions -Trigger $triggers -Settings $settings -Principal $principals
#
#        Write-Output "DONE: Createing Windows Workstation Scheduled Task"
#    }
#}

Function Winget_Error_IF_Major_Version_Found #TODO Make this faster by winget list as an input
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $application,
        [Parameter(Mandatory = $true)] [string] $MajorVersion
    )
    
    $applicationList = winget list | findstr $application
    
    if ((Write-Output $applicationList | findstr /l (" " + "$MajorVersion" + ".")) -And (Write-Output $applicationList | findstr /l ("." + "$MajorVersion")))
    {
        Write-Output $applicationList
        Write-Output "ERROR: Found $application Major Version: $MajorVersion"
        exit 1
    }
    else
    {
        Write-Output "Did not find $application Major Version: $MajorVersion"
        Return $false
    }
}

Function Winget_Error_IF_Major_Version_Found_DotNet
{
    Do
    {
        $Answer = Read-Host -Prompt 'Winget Check for Old DotNet? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to Winget Check for Old DotNet"
    }
    elseif ($Answer -eq "y")
    {
        Winget_Error_IF_Major_Version_Found "Microsoft.DotNet" 1
        Winget_Error_IF_Major_Version_Found "Microsoft.DotNet" 2
        Winget_Error_IF_Major_Version_Found "Microsoft.DotNet" 3
        Winget_Error_IF_Major_Version_Found "Microsoft.DotNet" 5
        Winget_Error_IF_Major_Version_Found "Microsoft.DotNet" 7
    }
}

Function Winget_Functions
{
    Do
    {
        $Answer = Read-Host -Prompt 'Run Winget Functions? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to run Winget Functions"
    }
    elseif ($Answer -eq "y")
    {
        Write-Output "User chose to run Winget Functions"
        Winget_list
        Winget_Update_all
        Winget_list
    }
}

Function Winget_Install
{
    Do
    {
        $Answer = Read-Host -Prompt 'Do you want to install Winget? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to install Winget"
    }
    elseif ($Answer -eq "y")
    {
        Install-Script -Name winget-install -force
        winget-install
    }
    Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
}

Function Winget_Install_Or_Update
{
    if ((Application_Exists winget) -eq $true)
    {
        Write-Output "Found winget"
        Winget_Update
    }
    elseif((Application_Exists winget) -eq $false)
    {
        Write-Output "Did not find winget"
        Winget_Install
    }
}

Function Winget_list
{
    winget list
    Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
}

Function Winget_list_Upgrade_Available_By_ID
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $ID
    )

    if (winget list --id $ID --upgrade-available | findstr "No installed package found matching input criteria.")
    {
        Write-Output "Did not find an update for $ID"
        Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
        return $false;

    }
    else
    {
        Write-Output "Found an Update for $ID"
        Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
        return $true;
    }
}

Function Winget_Update
{
    Write-Output "Winget Update --accept-source-agreements --accept-package-agreements"
    winget update --accept-source-agreements --accept-package-agreements
    Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
}

Function Winget_Update_all
{
    Do
    {
        $Answer = Read-Host -Prompt 'Winget Update All Application(s)? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to winget update all application(s)"
    }
    elseif ($Answer -eq "y")
    {
        Write-Output "User chose to winget update all application(s)"
        Write-Output "Performing Winget Update all applications (winget update --all)"
        winget update --all --accept-source-agreements --accept-package-agreements
        Write-Output "Done performing Winget Update all applications"
        Write-output "---------------------------------------------------"
    }
}

Function Winget_Update_Application_By_ID()
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $ID
    )
    Write-Output "Updating $ID (Winget Update $ID)"
    Winget Update $ID --accept-source-agreements --accept-package-agreements
    Write-Output "DONE: Updating $ID (Winget Update $ID)"
    Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
}

Function Winget_Version
{
    $winget_version = winget --version
    Write-Output "Winget Version: $winget_version"
    Write-output "---------------------------------------------------------------------------------------------------------------------------------------------"
}

#Startup -----------------------------------------
Prompt_Windows_Active_Users
Environment_Details
Launch_Office_Updater_GUI
Launch_Visual_Studio_Installer_GUI
Launch_Dell_Support_Assist_GUI
Launch_Application Edge msedge
Launch_Application Chrome Chrome

#Windows Updates
Windows_Update_Microsoft_Update

#Winget Functions -----------------------------------------
if (Confirm_OS)
{
    Winget_Install_Or_Update
    Winget_Functions
    #Winget_Error_IF_Major_Version_Found_DotNet
}

#Reboot
Prompt_Reboot