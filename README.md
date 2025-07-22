Windows 10 or Windows Server 2019 or newer required for Winget Functions

1. Dell Support Assist requires an Administrator login, so Log into your on your laptop as admin.  Otherwise skip the Dell Support Assist when prompted.
2. Download "SupportAssist for Home PCs" (https://www.dell.com/support/contents/en-us/Category/product-support/self-support-knowledgebase/software-and-downloads/support-assist/) then home -> updates.  Install all dell updates
3. reboot
4. Launch powershell 7 (if not installed, launch powershell as administrator and install via "winget install Microsoft.PowerShell"
5. Download and unzip the Windows Updater to Downloads
6. Launch Powershell 7 as administrator
7. Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
8. cd ~\downloads\Windows_Workstation_Updater
9. .\Launch_Windows_Workstation_Updater_Script.ps1
10. follow the y/n prompts.  

## Known Issues
Winget may find Adobe Reader and/or Adobe Acrobat updates, download an updater, but the adobe updater will fail to update. Need an alternative way to update Adobe Products.
Winget may fail to install due to a dependancy with appx and powershell 7 cannot import-module appx.  "Import-Module Appx -usewindowspowershell" works to resolve this dependency.
