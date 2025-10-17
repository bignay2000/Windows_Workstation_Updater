$ScriptVersion = '20251017'
$Author = 'Ryan Naylor'
$WarningPreference = "Stop";
$ErrorActionPreference = "Stop";

Function Display
{
    Write-Output "
 _       ___           __                      _       __           __        __        __  _                __  __          __      __
| |     / (_)___  ____/ /___ _      _______   | |     / /___  _____/ /_______/ /_____ _/ /_(_)___  ____     / / / /___  ____/ /___ _/ /____  _____
| | /| / / / __ \/ __  / __ \ | /| / / ___/   | | /| / / __ \/ ___/ //_/ ___/ __/ __ `/ __/ / __ \/ __ \   / / / / __ \/ __  / __ `/ __/ _ \/ ___/
| |/ |/ / / / / / /_/ / /_/ / |/ |/ (__  )    | |/ |/ / /_/ / /  / ,< (__  ) /_/ /_/ / /_/ / /_/ / / / /  / /_/ / /_/ / /_/ / /_/ / /_/  __/ /
|__/|__/_/_/ /_/\__,_/\____/|__/|__/____/     |__/|__/\____/_/  /_/|_/____/\__/\__,_/\__/_/\____/_/ /_/   \____/ .___/\__,_/\__,_/\__/\___/_/
                                                                                                              /_/

    "
}

Function Application_Exists
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $application
    )

    return [bool](Get-Command -Name $application -ErrorAction SilentlyContinue)
}

Function Script_Version_Age_Check
{
    $ParsedDate = [datetime]::ParseExact($ScriptVersion, 'yyyyMMdd', $null)
    $CurrentDate = Get-Date
    $ThresholdDate = $CurrentDate.AddDays(-365)

    if($ParsedDate -lt $ThresholdDate)
    {
        Do
        {
            $Answer = Read-Host -Prompt "ScriptVersion: $ScriptVersion This script verison is older than 1 year.  Continue (y/n)"
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
            Write-Output "User chose not to continue."
            exit 1
        }
        else
        {
            Write-Output "User chose to continue."
        }
    }
}

Function Confirm_Administator
{
    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator"))
    {
        Write-Output "Powershell is not running with Administrator rights"
        exit 1
    }
    else
    {
        Write-Output "Powershell is running with Administrator rights"
    }
}

Function Environment_Details
{
    Write-Output "Windows_Workstation_Updater by $Author"
    Write-Output "Script Version: $ScriptVersion"
    Write-Output "Date: $((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss') )"
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
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$proc.exe")
    {
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
    } else {
        Write-Output "Did not find $application Installed."
    }
}

Function Launch_Dell_Support_Assist_GUI
{
    if (systeminfo | findstr /l Dell)
    {
        Do
        {
            $Answer = Read-Host -Prompt "Launch Dell Support Assist GUI? (y/n)"
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
            Write-Output "User chose not to Launch Dell Support Assist GUI"
        }
        else
        {
            Write-Output "Launching Dell Support Assist GUI"
            $ErrorActionPreference = 'Continue'
            Start-Process "shell:AppsFolder\$(Get-StartApps "SupportAssist" | Select-Object -ExpandProperty AppId)" -PassThru
            $ErrorActionPreference = 'Stop'
            Start-Sleep 5
            Write-Output "Done: Launching Dell Support Assist GUI"
            Do
            {
                $Answer = Read-Host -Prompt "Are you done with Dell Support Assist GUI? (y)"
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
        Do
        {
        $Answer = Read-Host -Prompt "Launch Microsoft Office Updater GUI? (y/n)"
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
        Write-Output "User chose not to Launch Microsoft Office Updater GUI"
        }
        else
        {
        Write-Output "Launching Microsoft Office Updater GUI"
        Start-Process "C:\Program Files\Common Files\microsoft shared\ClickToRun\OfficeC2RClient.exe" "/update user"
        Start-Sleep 3
        Do
        {
        $Answer = Read-Host -Prompt "Are you done with Microsoft Office Updater GUI? (y)"
        }
        Until ($Answer -eq 'y')
        }
    } else {
        Write-Output "Did not find Office Installed."
    }
}

Function Launch_Visual_Studio_Installer_GUI
{
    if (Test-Path -Path 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe' -PathType Leaf)
    {
        Do
        {
            $Answer = Read-Host -Prompt "Launch Microsoft Visual Studio Installer GUI? (y/n)"
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
            Write-Output "User chose not to Launch Microsoft Visual Studio Installer GUI"
        }
        else
        {
            Write-Output "Launching Microsoft Visual Studio Installer GUI"
            Start-Process 'C:\Program Files (x86)\Microsoft Visual Studio\Installer\setup.exe'
            Start-Sleep 3
            Do
            {
                $Answer = Read-Host -Prompt "Are you done with Microsoft Visual Studio Installer GUI? (y)"
            }
            Until ($Answer -eq 'y')
        }
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
        Write-Output "Your the only user logged into this computer"
    }
    else
    {
        Write-Output "Your not the only user logged in"
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
        $Answer = Read-Host -Prompt 'Download Windows Update including Microsoft Products? (y/n)'
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to run Windows Update including Microsoft Products."
    }
    else
    {
        Write-Output "User chose run Windows Update including Microsoft Products."
        Powershell_Module_Install_Update 'PSWindowsUpdate'
        Write-Output "Scanning and Downloading for available updates..."
        Get-WindowsUpdate -MicrosoftUpdate -Download -AcceptAll
        Do
        {
            $Answer = Read-Host -Prompt 'Install Windows Update including Microsoft Products? (y/n)'
        }
        Until ($Answer -eq 'y' -or $Answer -eq 'n')
        If ($Answer -eq "n")
        {
            Write-Output "User chose not to install Windows Update including Microsoft Products."
            exit 0
        }
        else
        {
            Write-Output "User chose to install updates."
        }
        Write-Output "Installing available updates..."
        Install-WindowsUpdate -MicrosoftUpdate -AcceptAll
        Write-Output "Done: Windows Update including Microsoft Products update."
    }
}

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
        Winget_Install_Or_Update
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

Function Winget_Update_Application_By_ID
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

Function Launch_Winget
{
    $CurrentComputerOS = Get-ComputerInfo | Select-Object WindowsProductName
    if ($CurrentComputerOS -like '*2016*')
    {
        Write-Output "Windows Server 2016 found."
        Write-Output "Winget not supported on this OS."
    }
    elseif ($CurrentComputerOS -like '*2012*')
    {
        Write-Output "Windows Server 2012 found."
        Write-Output "Winget not supported on this OS."
    }
    elseif ($CurrentComputerOS -like '*2008*')
    {
        Write-Output "Windows Server 2008 found."
        Write-Output "Winget not supported on this OS."
    }
    else
    {
        Winget_Functions
        #Winget_Error_IF_Major_Version_Found_DotNet
    }
}

Function Winget_Install_By_ID
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $ID
    )
    Do
    {
        $Answer = Read-Host -Prompt "Winget install $ID? (y/n)"
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to winget install $ID"
    }
    elseif ($Answer -eq "y")
    {
        Write-Output "-----------------------------------------"
        Write-Output "Winget Install $ID"

        winget install --accept-source-agreements --accept-package-agreements --silent --id $ID --log "$StartTime-Configure-Windows-$Env:ComputerName_Winget_$ID.log" --source winget

        if ($ID -eq 'vim.vim')
        {
            Write-Output "Adding vim environment variable"
            [System.Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';C:\Program Files\Vim\vim91\', [System.EnvironmentVariableTarget]::Machine)
        }

        if ($ID -eq 'Git.Git')
        {
            Write-Output "Adding Git environment variable"
            [System.Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';C:\Program Files\Git\bin\', [System.EnvironmentVariableTarget]::Machine)
            Write-Output "Update Git to use Default Webbrowser for authentication instead of embedded Internet Explorer"
            git config --global credential.msauthFlow system
        }
    }
}

Function Winget_Install_By_Name
{
    Param
    (
        [Parameter(Mandatory = $true)] [string] $Name
    )
    Do
    {
        $Answer = Read-Host -Prompt "Winget install $Name? (y/n)"
    }
    Until ($Answer -eq 'y' -or $Answer -eq 'n')
    If ($Answer -eq "n")
    {
        Write-Output "User chose not to winget install $Name"
    }
    elseif ($Answer -eq "y")
    {
        Write-Output "-----------------------------------------"
        Write-Output "Winget Install $Name"

        winget install --accept-source-agreements --accept-package-agreements --silent --id $Name --log "$StartTime-Configure-Windows-$Env:ComputerName_Winget_$Name.log" --source winget

        if ($Name -eq 'vim.vim')
        {
            Write-Output "Adding vim environment variable"
            [System.Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';C:\Program Files\Vim\vim91\', [System.EnvironmentVariableTarget]::Machine)
        }

        if ($Name -eq 'Git.Git')
        {
            Write-Output "Adding Git environment variable"
            [System.Environment]::SetEnvironmentVariable('PATH', $env:PATH + ';C:\Program Files\Git\bin\', [System.EnvironmentVariableTarget]::Machine)
            Write-Output "Update Git to use Default Webbrowser for authentication instead of embedded Internet Explorer"
            git config --global credential.msauthFlow system
        }
    }
}

function BatteryReport {
    param (
        [string]$ReportPath = "$scriptDir/logs/$StartTime-Windows_Workstation_Updater-$Env:ComputerName-battery-report.html"
    )

    # Check for battery presence using Win32_Battery
    $battery = Get-CimInstance -ClassName Win32_Battery

    if ($battery) {
        Write-Output "Battery detected. Generating report..."
        try {
            powercfg /batteryreport /output $ReportPath /xml
            Write-Output "Battery report generated at: $ReportPath"
        } catch {
            Write-Error "Failed to generate battery report: $_"
        }
    } else {
        Write-Output "No battery found on this system."
    }
}

Function CheckForIISLogSizeGreaterThan100MB
{
    Write-Output "Checking if Microsoft IIS Web Server is installed."
    $feature = Get-WindowsOptionalFeature -Online | Where-Object { $_.FeatureName -eq "IIS-WebServerRole" }

    if ($feature.State -eq "Enabled")
    {
        Write-Output "Found Microsoft IIS Web Server is installed."
        # Get all fixed drives
        $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -gt 0 }
        foreach ($drive in $drives)
        {
            $root = $drive.Root
            Write-Output "Searching for 'Websites' directories in $root..."
            try
            {
                # Find all directories named "Websites"
                $websitesDirs = Get-ChildItem -Depth 3 -Path $root -Recurse -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -eq "Websites" }

                foreach ($dir in $websitesDirs)
                {
                    Write-Output "Found Websites directory: $( $dir.FullName )"

                    # Search for *.log files larger than 100MB
                    $largeLogs = Get-ChildItem -Path $dir.FullName -Recurse -Filter *.log -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 100MB }
                    if ($largeLogs.Count -gt 0) {
                        foreach ($log in $largeLogs)
                        {
                            Write-Output "Found log file greater than 100 MB: $( $log.FullName ) Size: $([math]::Round($log.Length / 1MB, 0) ) MB"
                            Read-Host -Prompt "Hit Enter key to continue..."
                        }
                    } else {
                        Write-Output "Did not find log files greater than 100 MB in directory."
                    }
                }
            }
            catch
            {
                Write-Error "Error searching in $root : $_"
            }
        }
        Write-Output "Finished checking for log files greater than 100 MB from Microsoft IIS Websites directories."
    } else {
        Write-Output "Did not find Microsoft IIS Installed."
    }
}

#Startup -----------------------------------------
Display
Prompt_Windows_Active_Users
Environment_Details
CheckForIISLogSizeGreaterThan100MB
BatteryReport
Script_Version_Age_Check
Launch_Dell_Support_Assist_GUI
Launch_Office_Updater_GUI
Launch_Visual_Studio_Installer_GUI
Launch_Application Edge msedge
Launch_Application Chrome Chrome
Launch_Application Firefox firefox
Windows_Update_Microsoft_Update
Launch_Winget

#Winget_Install_By_ID -ID '7zip.7zip'
#Winget_Install_By_ID -ID 'Adobe.Acrobat.Reader.64-bit'
#Winget_Install_By_ID -ID 'CoreyButler.NVMforWindows'
#Winget_Install_By_ID -ID 'CrystalDewWorld.CrystalDiskInfo'
#Winget_Install_By_ID -ID 'CrystalDewWorld.CrystalDiskMark'
#Winget_Install_By_ID -ID 'Git.Git'
#Winget_Install_By_ID -ID 'Google.Chrome'
#winget_install_By_Name -Name 'Microsoft 365 Copilot'
#Winget_Install_By_ID -ID 'Microsoft.Azure.StorageExplorer'
#Winget_Install_By_ID -ID 'Microsoft.AzureDataStudio'
#Winget_Install_By_ID -ID 'Microsoft.PowerShell'
#Winget_Install_By_ID -ID 'Microsoft.SQLServerManagementStudio'
#Winget_Install_By_ID -ID 'Microsoft.Sqlcmd'
#Winget_Install_By_ID -ID 'Microsoft.VisualStudio.2022.Enterprise'
#Winget_Install_By_ID -ID 'Microsoft.WindowsTerminal'
#Winget_Install_By_ID -ID 'Notepad++.Notepad++'
#Winget_Install_By_ID -ID 'Omnissa.HorizonClient'
#Winget_Install_By_ID -ID 'ScooterSoftware.BeyondCompare.4'
#Winget_Install_By_ID -ID 'Unity.UnityHub'
#Winget_Install_By_ID -ID 'WinDirStat.WinDirStat'
#Winget_Install_By_ID -ID 'vim.vim'

Prompt_Reboot
