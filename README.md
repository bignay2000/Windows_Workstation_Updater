# PowerShell Script to update Windows, Microsoft products via Windows Update, Applications via Winget
1. Windows 10 or Windows Server 2019 or newer required for Winget update
2. Intended to be launched as administrator and human user to answer y/n questions.  
3. Skips software if not installed.
4. Some software is hard to automate the update, so instead this script will launch the application and then your expected to manually check for update.

## Dell
1. Dell Support Assist requires an Administrator login, so Log into your on your laptop as admin.  Otherwise skip the Dell Support Assist when prompted.
2. Download "SupportAssist for Home PCs" (https://www.dell.com/support/contents/en-us/Category/product-support/self-support-knowledgebase/software-and-downloads/support-assist/) then home -> updates.  Install all dell updates
3. reboot
## Launch
1. Launch powershell 7 (if not installed, launch powershell as administrator and install via "winget install Microsoft.PowerShell"
2. Download and unzip the Windows Updater to Downloads
3. Launch Powershell 7 as administrator
4. Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
5. cd ~\downloads\Windows_Workstation_Updater
6. .\Launch_Windows_Workstation_Updater_Script.ps1
7. follow the y/n prompts.  

## Known Issues
1. Has to be ran directly on the Windows Desktop as some installers may require interactive user.
2. Winget may find Adobe Reader and/or Adobe Acrobat updates, download an updater, but the adobe updater will fail to update. Need an alternative way to update Adobe Products.
3. Winget may fail to install due to a dependancy with appx and powershell 7 cannot import-module appx.  "Import-Module Appx -usewindowspowershell" works to resolve this dependency.
4. Google has removed any easy cli update for Google Chrome, so the script launches Chrome and user expected to go to manually go to help update.
