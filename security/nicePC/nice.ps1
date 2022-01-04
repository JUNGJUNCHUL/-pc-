try{ 
stop-process (get-process mshta).id 
} 
catch{ 
}
function replay{ 
secedit /export /cfg c:\security\secpol.cfg 
(Get-content -Path c:\security\secpol.cfg) | Foreach-Object {
    $_ -replace 'MinimumPasswordAge = \w*', 'MinimumPasswordAge = 1' `
       -replace 'MaximumPasswordAge = \w*', 'MaximumPasswordAge = 90' `
       -replace 'MinimumPasswordLength = \w*', 'MinimumPasswordLength = 8' `
       -replace 'PasswordComplexity = \w*', 'PasswordComplexity = 1' `
       -replace 'PasswordHistorySize = \w*', 'PasswordHistorySize = 3' `
       -replace 'LockoutBadCount = \w*', 'LockoutBadCount = 5' `
       -replace 'ResetLockoutCount = \w*', 'ResetLockoutCount = 5' `
       -replace 'LockoutDuration = \w*', 'LockoutDuration = 5' `
       -replace 'PasswordExpiryWarning=\w*,\w*' , 'PasswordExpiryWarning=4,15' `
       -replace 'MaximumPasswordAge=\w*,\w*' , 'MaximumPasswordAge=4,90'
} | Out-file c:\security\secpol.cfg  
secedit /configure /db c:\security\secpol.sdb /cfg c:\security\secpol.cfg /areas SECURITYPOLICY  
echo "" 
$file = 'c:\security\secpol.jfm'  
if(-not (Test-Path $file)){echo ""} else{rm -force $file -confirm:$false}  
rm -force c:\security\secpol.cfg -confirm:$false  
rm -force c:\security\secpol.sdb -confirm:$false  
gpupdate /force 
cls 
}
function update{
$CheckPath = set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ -name NoAutoUpdate -value 0  
if($CheckPath -eq $null){ 
new-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate 
new-Item -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU 
} 
set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ -name NoAutoUpdate -value 0  
set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ -name NoAutoRebootWithLoggedOnUsers -value 1  
#windows ������Ʈ ����  
}
function screen{
reg add 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop' /v ScreenSaverIsSecure /t REG_SZ /d 1
reg add 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop' /v ScreenSaveTimeOut /t REG_SZ /d 600
reg delete 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop' /f
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop' -name screensaverissecure -value 1  
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop' -name ScreenSaveTimeOut -value 600  
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop' -name ScreenSaveActive -value 1 -type 1
#ȭ�麸ȣ�� ����   
}
function IE{
(New-Object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/7/2/D/72DDACC9-7CBF-440B-9E65-3DA44C3B2E33/EIE11_KO-KR_MCM_WIN764.EXE','C:\security\EIE11_KO-KR_MCM_WIN764.EXE')  
C:\security\EIE11_KO-KR_MCM_WIN764.EXE  
#explorer 11���� ��ġ ���� �ٲܽ� �����ؾߴ�  
}

function audit{
secedit /export /cfg c:\security\secpol.cfg 
(Get-content -Path c:\security\secpol.cfg) | Foreach-Object {  
    $_ -replace 'AuditSystemEvents = \w*', 'AuditSystemEvents = 3' `
       -replace 'AuditObjectAccess = \w*', 'AuditObjectAccess = 0' `
       -replace 'AuditPrivilegeUse = \w*', 'AuditPrivilegeUse = 3' `
       -replace 'AuditPolicyChange = \w*', 'AuditPolicyChange = 3' `
       -replace 'AuditAccountManage = \w*', 'AuditAccountManage = 6' `
       -replace 'AuditAccountLogon = \w*', 'AuditAccountLogon = 6' `
       -replace 'AuditLogonEvents = \w*', 'AuditLogonEvents = 3'
  } | Out-file c:\security\secpol.cfg  
secedit /configure /db c:\security\secpol.sdb /cfg c:\security\secpol.cfg /areas SECURITYPOLICY  
echo "" 
$file = 'c:\security\secpol.jfm'  
if(-not (Test-Path $file)){echo ""} else{rm -force $file -confirm:$false}  
rm -force c:\security\secpol.cfg -confirm:$false  
rm -force c:\security\secpol.sdb -confirm:$false  
gpupdate /force  
cls
#eventrule ����� �ʿ� 
}

function share{
set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -name AutoShareServer  -value 0 -type 4 
set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -name AutoShareWks  -value 0 -type 4 
$share = wmic share get name  
For($i=1;$i -le $share.length ;$i=$i+1)   
 {   
  if(($share[$i] -replace " ","") -eq "IPC$" -OR ($share[$i] -replace " ","") -eq "print$"){  
  echo "IPC$ PRINT$ �������� ����"  
  }  
  elseif(($share[$i] -replace " ","").length -eq 0){  
  }  
  else  
  {  
  net share /delete ($share[$i].trim())  
  }  
}   
#���� ���� ���� ���� �ٽ��ۼ��Ұ�
}
function firewall{
set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' -name EnableFirewall -value 1  
set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -name EnableFirewall -value 1  
netsh advfirewall set allprofiles state off
netsh advfirewall set allprofiles state on
#firewall
}
function remote{
set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server' -name fDenyTSConnections -value 1  
set-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance' -name fAllowToGetHelp -value 0  
}
function proxy{
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -name proxyenable -value 0  
}
function message{
Get-AppxPackage *skypeapp* | Remove-AppxPackage 
Set-ItemProperty -path 'HKLM:\SOFTWARE\Policies\Microsoft\Messanger\Client' -name PreventRun -value 1 
}
function passch{
$u_name=($env:USERNAME)
wmic useraccount where name="'$u_name'" set PasswordExpires=true
net user $u_name /logonpasswordchg:yes
}

###############################function ����###############################################
if($args -eq "1��")
{ 
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
passch
}
elseif($args -eq "2��")  
{ 
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
update
}
elseif($args -eq "3��")  
{  
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
screen
}  
elseif($args -eq "4��")  
{
(New-Object -ComObject Wscript.Shell).Popup("""Internet EXPLORER ��ġ â�� �߸� ��ġ�� ������ �ּ���.""",5,"""������ȣ�� �޼���""",0x0)
IE
}  
elseif($args -eq "6��")  
{  
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
audit 
}  
elseif($args -eq "7��")  
{  
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
share
}  
elseif($args -eq "8��"){
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
firewall
}  
elseif($args -eq "9��"){  
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
remote
#���� ���� ��� �� ���� ���� ��Ȱ��ȭ  
}  
elseif($args -eq "10��"){  
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
proxy
#proxy ���ͳ�â ������ؾߵ�  
}  
elseif($args -eq "11��"){  
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
replay 
#passrule  
} 
elseif($args -eq "12��"){ 
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
message
}
elseif($args -eq "100��"){
(New-Object -ComObject Wscript.Shell).Popup("""��ġ �� �Դϴ�. ��ġ�� �Ϸ�Ǹ� �ڵ����� â�� �߻��˴ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
replay
message
proxy
remote
firewall
share
audit
IE
screen
update
passch
}
else{ 
(New-Object -ComObject Wscript.Shell).Popup("""���� �߻� ������ȣ������ ������Ź�帳�ϴ�.""",5,"""������ȣ�� �޼���""",0x0)
}  
