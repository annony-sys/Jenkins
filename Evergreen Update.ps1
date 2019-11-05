function Get-RandomCharacters($length, $characters) {
    $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length }
    $private:ofs=""
    return [String]$characters[$random]
}

Clear-Host
Write-Verbose "Settings Arugments"
$StartDTM = (Get-Date)

Write-Verbose "Getting Global Settings from XML" -Verbose
$MyConfigFileloc = ("$env:Settings\Applications\Settings.xml")
[xml]$MyConfigFile = (Get-Content $MyConfigFileLoc)

$LogPS = "${env:SystemRoot}" + "\Temp\PSWindowsUpdate.log"
$From = $MyConfigFile.Settings.Mail.From
$To = $MyConfigFile.Settings.Mail.To
$SMTP = $MyConfigFile.Settings.Mail.SMTP
$PasswordFile = $MyConfigFile.Settings.Mail.PasswordFile
$KeyFile = $MyConfigFile.Settings.Mail.KeyFile
$API = $MyConfigFile.Settings.Mail.API
$Attachment = "C:\PSWindowsUpdate.log"

Write-Verbose "Getting Encrypted Password from KeyFile" -Verbose
$SecurePassword = ((Get-Content $PasswordFile) | ConvertTo-SecureString -Key (Get-Content $KeyFile))
$creds = $(New-Object System.Management.Automation.PSCredential ($API, $SecurePassword))

if (!(Test-Path -Path "C:\Program Files\PackageManagement\ProviderAssemblies\nuget")) {Find-PackageProvider -Name 'Nuget' -ForceBootstrap -IncludeDependencies}
if (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {Install-Module PSWindowsUpdate -Force | Import-Module PSWindowsUpdate}
if (!(Get-Module -ListAvailable -Name Evergreen)) {Install-Module Evergreen -Force | Import-Module Evergreen}

Update-Module -Name Evergreen -Force

Write-Verbose "Downloading Sysinternals" -Verbose
if( -Not (Test-Path -Path "C:\Windows\System32\autologon.exe" ) )
{
    $url = "https://live.sysinternals.com/Files/SysinternalsSuite.zip"
    [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
    Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile "${env:Temp}\$Product.$InstallerType"
    Expand-Archive -Path "${env:Temp}\$Product.$InstallerType" -DestinationPath "${env:SystemRoot}\System32"
}

Write-Verbose "Checking if the Windows Update Service is Running" -Verbose
$ServiceName = 'wuauserv'
Set-Service -Name $ServiceName -Startup Automatic
Start-Service -Name $ServiceName

Write-Verbose "Gettings Available Updates from Microsoft" -Verbos
Get-WindowsUpdate -NotCategory "Drivers" -MicrosoftUpdate -ComputerName localhost | Out-File C:\PSWindowsUpdate.log -Append

Write-Verbose "Installing Available Updates from Microsoft" -Verbose
Get-WindowsUpdate -NotCategory "Drivers" -MicrosoftUpdate -ComputerName localhost -Install -AcceptAll -IgnoreReboot | Out-File C:\PSWindowsUpdate.log -Append

Write-Verbose "Updating Antivirus Signatures" -Verbose
if( (Test-Path -Path "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection" ) )
{
    Start-Process -FilePath "C:\Program Files (x86)\Symantec\Symantec Endpoint Protection\SepLiveUpdate.exe" -PassThru -Wait -RedirectStandardOutput SEP.txt
    $SEP = Get-Content .\SEP.txt
    Write-Verbose "$SEP" -Verbose
}

if( (Get-Service WinDefend| Where-Object {$_.Status -eq "Running"}) )
{
    CD "C:\Program Files\Windows Defender\"
    .\MpCmdRun.exe -signatureupdate
}

Write-Verbose "Updating Evergreen Applications" -Verbose

if( (Test-Path -Path "C:\Program Files\Google\Chrome" ) )
{
    CD "$env:Settings\Applications\Google\Chrome Enterprise"
    Invoke-Expression -Command ".\Install.ps1"
}

if( (Test-Path -Path "C:\Program Files (x86)\Adobe\Acrobat Reader DC" ) )
{
    CD "$env:Settings\Applications\Adobe\Reader DC"
    Invoke-Expression -Command ".\Install.ps1"
}

if( (Test-Path -Path "C:\Program Files\Smart-X\ControlUpAgent" ) )
{
    CD "$env:Settings\Applications\Misc\ControlUp"
    Invoke-Expression -Command ".\Install.ps1"
}

if( (Test-Path -Path "C:\Program Files (x86)\Base Image Script Framework (BIS-F)" ) )
{
    CD "$env:Settings\Applications\Misc\BISF"
    Invoke-Expression -Command ".\Install.ps1"
}

if( (Test-Path -Path "C:\Program Files (x86)\App-V Scheduler" ) )
{
    CD "$env:Settings\Applications\Misc\App-V Scheduler"
    Invoke-Expression -Command ".\Install.ps1"
}

Write-Verbose "Checking if Base Image Script Framework is Installed" -Verbose
if( (Test-Path -Path "C:\Program Files (x86)\Base Image Script Framework (BIS-F)" ) )
{
    Write-Verbose "Creating Random Password for AutoLogon" -Verbose
    $password = Get-RandomCharacters -length 10 -characters 'abcdefghiklmnoprstuvwxyz'
    $password += Get-RandomCharacters -length 3 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
    $password += Get-RandomCharacters -length 2 -characters '1234567890'
    $password += Get-RandomCharacters -length 5 -characters '!§$%&/()=?}][{@#*+'
    $secpassword = $password | ConvertTo-SecureString -asPlainText -Force
    Remove-LocalUser -Name Autologon
    New-LocalUser -Name AutoLogon -Password $secpassword
    Add-LocalGroupMember -Group "Administrators" -Member "AutoLogon"

    Write-Verbose "Creating AutoLogon with Encrypted Passowrd"
    Start-Process "C:\Windows\System32\autologon.exe" -ArgumentList "/accepteula",AutoLogon,$env:COMPUTERNAME,$password
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption /t REG_SZ /d " " /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeTest /t REG_SZ /d " " /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoLogonCount /t REG_SZ /d 1 /f
    reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v BISF /t REG_SZ /d "C:\Program Files (x86)\Base Image Script Framework (BIS-F)\PrepareBaseImage.cmd" /f
    reg add "HKLM\SOFTWARE\Policies\Login Consultants\BISF" /v LIC_BISF_CLI_LS /t REG_SZ /d \\dc-01\BISF /f
    reg add "HKLM\SOFTWARE\Policies\Login Consultants\BISF" /v LIC_BISF_CLI_SB /t REG_SZ /d NO /f
    shutdown /r /t 30
    }
    Else {
    }


Write-Verbose "Stop logging" -Verbose
$EndDTM = (Get-Date)
Write-Verbose "Elapsed Time: $(($EndDTM-$StartDTM).TotalSeconds) Seconds" -Verbose
Write-Verbose "Elapsed Time: $(($EndDTM-$StartDTM).TotalMinutes) Minutes" -Verbose

Write-Verbose "Sending Email Report" -Verbose

$props = @{
    From = "Citrix Automation <$From>"
    To = $To 
    Subject = "Evergreen Update executed successfully on $env:ComputerName in $(($EndDTM-$StartDTM).TotalMinutes) Minutes"
    SmtpServer = $SMTP
    Attachments = $Attachment
    #Body = Get-Content "C:\PSWindowsUpdate.log" | Out-String
    Credential = $creds
}

Send-MailMessage @props -UseSsl

Write-Verbose "Restarting VM" -Verbose
shutdown /r /t 30
