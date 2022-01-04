try{ 
Set-ItemProperty -path 'Registry::HKLM\SYSTEM\CurrentControlSet\services\eventlog\Security\' -name MaxSize 1073741824
schtasks.exe /create /F /tn "Security Daily Check" /tr "c:\security\JCcheck.bat" /sc daily /st 11:59 /RL HIGHEST > NUL
} 
catch{ 
} 
try{ 
stop-process (get-process mshta).id 
} 
catch{ 
}
try{ 
Remove-Item -recurse C:\security2
} 
catch{ 
}
$realtime_v3 = New-Object -TypeName PSObject -Property @{
    sysmonuse="null"
   
}
$auto_v3 = New-Object -TypeName PSObject -Property @{
   autoupdateuse = "null"
    autoupdateperiod ="null"
}
###################################조치 스크립트#############################################################
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
#windows 업데이트 설정  
}
function screen{
reg add 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop' /v ScreenSaverIsSecure /t REG_SZ /d 1
reg add 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop' /v ScreenSaveTimeOut /t REG_SZ /d 600
reg delete 'HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop' /f
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop' -name screensaverissecure -value 1  
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop' -name ScreenSaveTimeOut -value 600  
set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop' -name ScreenSaveActive -value 1 -type 1
#화면보호기 설정   
}
function IE{
(New-Object System.Net.WebClient).DownloadFile('https://download.microsoft.com/download/7/2/D/72DDACC9-7CBF-440B-9E65-3DA44C3B2E33/EIE11_KO-KR_MCM_WIN764.EXE','C:\security\EIE11_KO-KR_MCM_WIN764.EXE')  
C:\security\EIE11_KO-KR_MCM_WIN764.EXE  
#explorer 11버전 설치 추후 바꿀시 수정해야댐  
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
#eventrule 재부팅 필요 
}

function share{
set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -name AutoShareServer  -value 0 -type 4 
set-Itemproperty -Path Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters -name AutoShareWks  -value 0 -type 4 
$share = wmic share get name  
For($i=1;$i -le $share.length ;$i=$i+1)   
 {   
  if(($share[$i] -replace " ","") -eq "IPC$" -OR ($share[$i] -replace " ","") -eq "print$"){  
  echo "IPC$ PRINT$ 제거하지 않음"  
  }  
  elseif(($share[$i] -replace " ","").length -eq 0){  
  }  
  else  
  {  
  net share /delete ($share[$i].trim())  
  }  
}   
#공유 폴더 제거 설정 다시작성할것
}
function firewall{
set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile' -name EnableFirewall -value 1  
set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile' -name EnableFirewall -value 1 
netsh advfirewall firewall delete rule name="allow RemoteDesktop"
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
#########################################################################################################
$CheckFilePath = "C:\security\JCpowershell.ps1"    
$md5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider    
$hash = [System.BitConverter]::ToString($md5.ComputeHash([System.IO.File]::ReadAllBytes($CheckFilePath)))    
$ss_secure= (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop').screensaverissecure
$ss_active= (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop').ScreenSaveActive
$ss_time= (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Control Panel\Desktop').ScreenSaveTimeOut
$v3_check=(get-process ASDSvc).ProcessName
$ie_v=$(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Internet Explorer').svcVersion     
$Critical = 0 
$weakcount = 0 
###########패스워드 정책########################   
secedit /export /cfg c:\security\secpol.cfg >$null   
$MinimumPasswordAge = ((Get-content -Path c:\security\secpol.cfg | select-string "MinimumPasswordAge" ) -split " = ")[1]#1   
$MaximumPasswordAge = ((Get-content -Path c:\security\secpol.cfg | select-string "MaximumPasswordAge" ) -split " = ")[1]#90   
$MinimumPasswordLength = ((Get-content -Path c:\security\secpol.cfg | select-string "MinimumPasswordLength" ) -split " = ")[1]#8   
$PasswordComplexity = ((Get-content -Path c:\security\secpol.cfg | select-string "PasswordComplexity" ) -split " = ")[1]#1   
$PasswordHistorySize = ((Get-content -Path c:\security\secpol.cfg | select-string "PasswordHistorySize" ) -split " = ")[1]#3   
$LockoutBadCount = ((Get-content -Path c:\security\secpol.cfg | select-string "LockoutBadCount" ) -split " = ")[1]#5   
$ResetLockoutCount = ((Get-content -Path c:\security\secpol.cfg | select-string "ResetLockoutCount" ) -split " = ")[1]#5   
$LockoutDuration = ((Get-content -Path c:\security\secpol.cfg | select-string "LockoutDuration" ) -split " = ")[1]#5   
 ######################계정관리 감사####################   
$AuditSystemEvents = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditSystemEvents" ) -split " = ")[1] #3   
$AuditObjectAccess = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditObjectAccess" ) -split " = ")[1]#3   
$AuditPrivilegeUse = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditPrivilegeUse" ) -split " = ")[1]#3   
$AuditPolicyChange = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditPolicyChange" ) -split " = ")[1]#3   
$AuditAccountManage = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditAccountManage" ) -split " = ")[1] #6   
$AuditAccountLogon = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditAccountLogon" ) -split " = ")[1] #6   
$AuditLogonEvents = ((Get-content -Path c:\security\secpol.cfg | select-string "AuditLogonEvents" ) -split " = ")[1] #3   
 ##################################################
#$UpdateSession = New-Object -com Microsoft.Update.Session    
#$UpdateSearcher = $UpdateSession.CreateupdateSearcher()    
#$SearchResult = $UpdateSearcher.Search("Type='Software' and IsHidden=0 and IsInstalled=0")    
 $Critical = 0    
# For($i=0;$i -lt $SearchResult.Updates.Count;$i++)   
# {   
#            $cate=$SearchResult.updates.item($i) | select -expand AutoSelectOnWebSites       
#         if ($cate -eq "True"){   
#                 $Critical++ }   
# }   
$Critical_count = $Critical
$share = wmic share get name","caption","path  
for($i=0;$i -lt $share.Length;$i=$i+1){  
if($share[$i].length -eq 0 ){  
$share[$i]= $null  
}  
}  
$u_name=($env:USERNAME) 
$realtime_v3=$(get-itemproperty -path HKLM:\SOFTWARE\AhnLab\ASPack\9.0\Option\AVMON\)    
$auto_v3=$(get-itemproperty -path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\AhnLab\ASPack\9.0\Option\UPDATE\)    
$proxyEnable =(Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyenable   
$ProxyServer = (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings').proxyserver   
if($proxyEnable -eq $null){   
$proxyEnable = 0   
}   
$fDenyTSConnections = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections   
$fAllowUnsolicited = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Remote Assistance').fAllowToGetHelp   
if($fAllowUnsolicited -eq $null){   
$fAllowUnsolicited = 0   
}   
$v = wmic useraccount where name="'$u_name'" get passwordexpires    
if($v[2].split(" ") -eq "FALSE"){    
wmic useraccount where name="'$u_name'" set PasswordExpires=true    
$pw_expire1 = "notset"    
}
$pw_pol1=$(net user $u_name | select-string -pattern "마지막으로 암호 설정한 날짜") 
$pw_pol1 = $pw_pol1 -match "((\d\d\d\d)(\?||\s*)(\?||\s*))-(\?||\s*)(\?||\s*)((\d\d)(\?||\s*)(\?||\s*))-(\?||\s*)(\?||\s*)(\d\d)"
$pw_pol1 = $Matches[0]
$pw_pol1 = $pw_pol1 -replace " ", ""
$pw_pol1 = $pw_pol1 -replace "\t", ""
$pw_pol1 = $pw_pol1 -replace "\?", ""
$pw_expire1=$(net user $u_name | select-string -pattern "암호 만료 날짜") 
$pw_expire1 = $pw_expire1 -match "((\d\d\d\d)(\?||\s*)(\?||\s*))-(\?||\s*)(\?||\s*)((\d\d)(\?||\s*)(\?||\s*))-(\?||\s*)(\?||\s*)(\d\d)"
$pw_expire1 = $Matches[0]
$pw_expire1 = $pw_expire1 -replace " ", ""
$pw_expire1 = $pw_expire1 -replace "\t", ""
$pw_expire1 = $pw_expire1 -replace "\?", ""
$pw_pol2=$pw_pol1    
$pw_warn = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon').PasswordExpiryWarning    
if($pw_expire1 -eq ""){    
$pw_expire1 = "notset"
net user $u_name /logonpasswordchg:yes
}
$firewallcheck =$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile').EnableFirewall   
$firewallcheckk =$(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile').EnableFirewall 
$updateactive = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU').NoAutoUpdate#0   
if($updateactive -eq $null){   
$updateactive = "null" 
}   
$sysdate = get-date   
$sysdate2 = Get-Date -format "yyyy년 MM월 dd일 HH시 mm분"   
$pwdchg = ($sysdate - ($pw_pol1 -as [Datetime])).Days 
$messanger = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Messanger\Client').PreventRun 
$skype = (Get-AppxPackage *skype* | select name) 
#######################################nullIF############################################### 
if($skype -eq $null){$skype = "notinstall"} 
else{$skype = "install"}
if($messanger -eq $null){$messanger = 1} 
if($hostname -eq $null){ $hostname = "null"} 
if($realtime_v3.sysmonuse -eq $null){ $realtime_v3 = New-Object -TypeName PSObject -Property @{ 
sysmonuse="null"
}} 
if($auto_v3.autoupdateuse -eq $null){ $auto_v3 = New-Object -TypeName PSObject -Property @{ 
autoupdateuse="null"
autoupdateperiod="null"
}} 
if($auto_v3.autoupdateperiod -eq $null){ $auto_v3 = New-Object -TypeName PSObject -Property @{ 
autoupdateuse="null"
autoupdateperiod="null"
}} 
if($ss_active -eq $null){ $ss_active = "null"}
if($ss_secure -eq $null){ $ss_secure = "null"} 
if($ss_time -eq $null){ $ss_time = "null"} 
if($ie_v  -eq $null){ $ie_v = "null"} 
if($u_name -eq $null){ $u_name = "null"} 
if($Critical_count -eq $null){ $Critical_count = "null"} 
if($pw_pol2 -eq $null){ $pw_pol2 = "null"} 
if($hash -eq $null){ $hash = "null"} 
if($pw_expire1 -eq $null){ $pw_expire1 = "null"} 
if($pw_warn -eq $null){ $pw_warn = "null"} 
if($updateactive -eq $null){ $updateactive = "null"} 
if($MinimumPasswordAge -eq $null){ $MinimumPasswordAge = "null"} 
if($MaximumPasswordAge -eq $null){ $MaximumPasswordAge = "null"} 
if($MinimumPasswordLength -eq $null){ $MinimumPasswordLength = "null"} 
if($PasswordComplexity -eq $null){ $PasswordComplexity = "null"} 
if($PasswordHistorySize -eq $null){ $PasswordHistorySize = "null"} 
if($LockoutBadCount -eq $null){ $LockoutBadCount = "null"} 
if($ResetLockoutCount -eq $null){ $ResetLockoutCount = "null"} 
if($LockoutDuration -eq $null){ $LockoutDuration = "null"} 
if($AuditSystemEvents -eq $null){ $AuditSystemEvents = "null"} 
if($AuditObjectAccess -eq $null){ $AuditObjectAccess = "null"} 
if($AuditPrivilegeUse -eq $null){ $AuditPrivilegeUse = "null"} 
if($AuditPolicyChange  -eq $null){ $AuditPolicyChange = "null"} 
if($AuditAccountManage -eq $null){ $AuditAccountManage = "null"} 
if($AuditAccountLogon -eq $null){ $AuditAccountLogon = "null"} 
if($AuditLogonEvents -eq $null){ $AuditLogonEvents = "null"} 
if($firewallcheck -eq $null){ $firewallcheck = "null"} 
if($firewallcheckk -eq $null){ $firewallcheckk = "null"} 
if($proxyEnable  -eq $null){ $proxyEnable = "null"} 
if($ProxyServer -eq $null){ $ProxyServer = "null"} 
if($fDenyTSConnections -eq $null){ $fDenyTSConnections = "null"} 
if($fAllowUnsolicited -eq $null){ $fAllowUnsolicited = "null"} 
if($share_count -eq $null){ $share_count = "null"} 
if($weakcount -eq $null){ $weakcount = "null"}  
#######################################function############################################   
function checkOK([ref]$filepath){   
$filepath.value = $filepath.value + [string]"        ..........점검완료"   
}   
function checkNO([ref]$filepath){   
$filepath.value = $filepath.value + [string]"        ..........취약" 
} 
#######################################string#################################################  
$ss_active_p=[string]"화면잠금 설정 여부                                   :       "+$ss_active #O  
$ss_secure_p=[string]"화면잠금 보호 설정 여부                                   :       "+$ss_secure #O
$ss_time_p=[string]"화면잠금 설정 시간(초)                               :       "+$ss_time #O 
$ie_v_p=[string]"인터넷 익스플로러 버전                               :       "+$ie_v  #O   
$Critical_p = [string]"중요 Windows Update 잔여 수량                        :       "+$Critical_count #O  
$updateactive1 = [string]"자동 Windows Update 사용                             :       "+$updateactive #V 
$u_name_display_p=[string]"계정 이름                                            :       "+$u_name #O 
$realtime_v3_p=[string]"V3 실시간 설정여부(설정 : 1, 미설정 : 0)             :       "+ $realtime_v3.sysmonuse #O 
$auto_v3_active_p=[string]"V3 자동 업데이트 설정여부(설정 : 1, 미설정 : 0)      :       " + $auto_v3.autoupdateuse #O  
$auto_v3_period_p=[string]"V3 자동 업데이트 주기(시간)                          :       " + $auto_v3.autoupdateperiod #O  
$v3_check_p=[string]"V3 프로세스 실행 여부                                :       " + $v3_check #O  
$pw_pol2_p=[string]"마지막으로 암호 변경한 날짜는                        :       "+$pw_pol2  #O   
$pw_expire2 =[string]"비밀번호 암호 만료 날짜는                            :       "+$pw_expire1  #O   
$pw_warn1=[string]"패스워드 경고 설정 일자                              :       "+$pw_warn  #O  
$MinimumPasswordAge1 = [string]"최소 비밀번호 사용기간                              :       "+$MinimumPasswordAge  #V 
$MaximumPasswordAge1 = [string]"최대 비밀번호 사용기간                              :       "+$MaximumPasswordAge  #V 
$MinimumPasswordLength1 = [string]"최소 비밀번호 사용길이                              :       "+$MinimumPasswordLength  #V 
$PasswordComplexity1 = [string]"비밀번호 복잡성 설정여부                            :       "+$PasswordComplexity #V 
$PasswordHistorySize1 = [string]"비밀번호 최근 암호 기억                             :       "+$PasswordHistorySize  #V  
$LockoutBadCount1 = [string]"계정 잠금 임계값 횟수                               :       "+$LockoutBadCount #V  
$ResetLockoutCount1 = [string]"계정 잠금 임계값 초기화 시간                        :       "+$ResetLockoutCount #V    
$LockoutDuration1 = [string]"계정 잠금 기간                                      :       "+$LockoutDuration  #V  
$AuditSystemEvents1 = [string]"시스템 이벤트 감사                              :       "+$AuditSystemEvents #V   
$AuditObjectAccess1 = [string]"개체 엑세스 감사                                :       "+$AuditObjectAccess #V   
$AuditPrivilegeUse1 = [string]"권한 사용 감사                                  :       "+$AuditPrivilegeUse #V 
$AuditPolicyChange1 = [string]"정책 변경 감사                                  :       "+$AuditPolicyChange  #V 
$AuditAccountManage1 = [string]"계정 관리 감사                                  :       "+$AuditAccountManage  #V 
$AuditAccountLogon1 = [string]"계정 로그온 감사                                :       "+$AuditAccountLogon #V  
$AuditLogonEvents1 = [string]"로그온 이벤트 감사                              :       "+$AuditLogonEvents  #V 
$firewallcheck1 = [string]"Windows 방화벽 설정                           :       "+$firewallcheck #V  
$firewallcheckk1 = [string]"Windows 공용 방화벽 설정                      :       "+$firewallcheckk #V  
$proxyEnable1 = [string]"프록시 기능 활성화 여부                           :       "+$proxyEnable #V 
$ProxyServer1 = [string]"프록시 설정 서버                                  :       "+$ProxyServer #V  
$fDenyTSConnections1 = [string]"원격 기능 활성화 여부 점검                           :       "+$fDenyTSConnections #V   
$fAllowUnsolicited1 = [string]"원격 지원 기능 활성화 여부 점검                      :       "+$fAllowUnsolicited #V 
$messanger1 = [string]"Windows 메신져 활성화 여부 점검                      :       "+$messanger 
$skype1 = [string]"스카이프 설치 여부 점검                              :       "+$skype 
###############################FUNCTION USE################################################### 
IF($messanger -eq 1){ 
checkOK([ref]$messanger1) 
} 
else{ 
checkNO([ref]$messanger1) 
$weakcount = $weakcount +1
message
} 
IF($skype -eq "notinstall"){ 
checkOK([ref]$skype1) 
} 
else{ 
checkNO([ref]$skype1) 
$weakcount = $weakcount +1
message
} 
IF($ss_active -eq 1){   
checkOK([ref]$SS_ACTIVE_P)}   
else   
{   
checkNO([ref]$SS_ACTIVE_P) 
$weakcount = $weakcount +1
screen
}
IF($ss_secure -eq 1){   
checkOK([ref]$ss_secure_p)}   
else   
{   
checkNO([ref]$ss_secure_P) 
$weakcount = $weakcount +1
screen
}  
IF([int]$ss_time -le 650){   
checkOK([ref]$ss_time_p)}   
else   
{   
checkNO([ref]$ss_time_p) 
$weakcount = $weakcount +1 
screen
}   
IF($ie_v -gt 11){   
checkOK([ref]$ie_v_p)}   
else   
{   
checkNO([ref]$ie_v_p)   
$weakcount = $weakcount +1 
IE
}   
IF($Critical_count -le 10){   
checkOK([ref]$Critical_p)   
}   
else   
{   
checkNO([ref]$Critical_p)   
$weakcount = $weakcount +1
update
}   
IF($updateactive -eq 0){   
checkOK([ref]$updateactive1)   
}   
else   
{   
checkNO([ref]$updateactive1)   
$weakcount = $weakcount +1 
update
}   
IF($realtime_v3.sysmonuse -eq 1){   
checkOK([ref]$realtime_v3_p)   
} 
else   
{   
checkNO([ref]$realtime_v3_p)   
$weakcount = $weakcount +1 
}
IF($v3_check -eq "ASDSvc"){   
checkOK([ref]$v3_check_p)   
}   
else   
{   
checkNO([ref]$v3_check_p)   
$weakcount = $weakcount +1 
}   

IF($auto_v3.autoupdateuse -eq 1){   
checkOK([ref]$auto_v3_active_p)   
}   
else   
{   
checkNO([ref]$auto_v3_active_p)  
$weakcount = $weakcount +1  
}   
IF($auto_v3.autoupdateperiod -eq 3){   
checkOK([ref]$auto_v3_period_p)   
}   
else   
{   
checkNO([ref]$auto_v3_period_p)   
$weakcount = $weakcount +1 
}   
IF($pwdchg -lt 90){   
checkOK([ref]$pw_pol2_p)   
if($pw_expire1 -eq "notset"){    
checkNO([ref]$pw_expire2)   
$weakcount = $weakcount +1 
passch
}   
else{   
checkOK([ref]$pw_expire2)   
}   
checkOK([ref]$pw_warn1)   
}   
else   
{  
checkNO([ref]$pw_pol2_p)   
$weakcount = $weakcount +1 
checkNO([ref]$pw_warn1)
passch
}   
##########패스워드 rule   
IF($MinimumPasswordAge -eq 1){   
checkOK([ref]$MinimumPasswordAge1)   
}   
else   
{   
checkNO([ref]$MinimumPasswordAge1)   
$weakcount = $weakcount +1
replay
}   
IF($MaximumPasswordAge -eq 90){   
checkOK([ref]$MaximumPasswordAge1)   
}   
else   
{   
checkNO([ref]$MaximumPasswordAge1)   
$weakcount = $weakcount +1 
replay
}   
IF($MinimumPasswordLength -eq 8){   
checkOK([ref]$MinimumPasswordLength1)   
}   
else   
{   
checkNO([ref]$MinimumPasswordLength1)   
$weakcount = $weakcount +1 
replay
}   
IF($PasswordComplexity -eq 1){   
checkOK([ref]$PasswordComplexity1)   
}   
else   
{   
checkNO([ref]$PasswordComplexity1)   
$weakcount = $weakcount +1 
replay
}   
IF($PasswordHistorySize -eq 3){   
checkOK([ref]$PasswordHistorySize1)   
}   
else   
{   
checkNO([ref]$PasswordHistorySize1)   
$weakcount = $weakcount +1 
replay
}   
IF($LockoutBadCount -eq 5){   
checkOK([ref]$LockoutBadCount1)   
}   
else   
{   
checkNO([ref]$LockoutBadCount1)   
$weakcount = $weakcount +1 
replay
}   
IF($ResetLockoutCount -eq 5){   
checkOK([ref]$ResetLockoutCount1)   
}   
else   
{   
checkNO([ref]$ResetLockoutCount1)   
$weakcount = $weakcount +1 
replay
}   
IF($LockoutDuration -eq 5){   
checkOK([ref]$LockoutDuration1)   
}   
else   
{   
checkNO([ref]$LockoutDuration1)  
$weakcount = $weakcount +1  
replay
}   
IF($AuditSystemEvents -eq 3){   
checkOK([ref]$AuditSystemEvents1)   
}   
else   
{   
checkNO([ref]$AuditSystemEvents1)   
$weakcount = $weakcount +1 
audit
}   
IF($AuditObjectAccess -ge 0){   
checkOK([ref]$AuditObjectAccess1)   
}   
else   
{   
checkNO([ref]$AuditObjectAccess1)   
$weakcount = $weakcount +1 
audit
}   
IF($AuditPrivilegeUse -eq 3){   
checkOK([ref]$AuditPrivilegeUse1)   
}   
else   
{   
checkNO([ref]$AuditPrivilegeUse1)   
$weakcount = $weakcount +1 
audit
}   
IF($AuditPolicyChange -eq 3){   
checkOK([ref]$AuditPolicyChange1)   
}   
else   
{   
checkNO([ref]$AuditPolicyChange1)   
$weakcount = $weakcount +1 
audit
}   
IF($AuditAccountManage -eq 2){   
checkOK([ref]$AuditAccountManage1)   
}   
else   
{   
checkNO([ref]$AuditAccountManage1)   
$weakcount = $weakcount +1 
audit
}   
IF($AuditAccountLogon -ge 2){   
checkOK([ref]$AuditAccountLogon1)   
}   
else   
{   
checkNO([ref]$AuditAccountLogon1)   
$weakcount = $weakcount +1 
audit
}   
IF($AuditLogonEvents -ge 2){   
checkOK([ref]$AuditLogonEvents1)   
}   
else   
{   
checkNO([ref]$AuditLogonEvents1)   
$weakcount = $weakcount +1 
audit
}   
IF($firewallcheck -eq 1){   
checkOK([ref]$firewallcheck1)   
}   
else   
{   
checkNO([ref]$firewallcheck1)   
$weakcount = $weakcount +1 
firewall
}   
IF($firewallcheckk -eq 1){   
checkOK([ref]$firewallcheckk1)   
}   
else   
{   
checkNO([ref]$firewallcheckk1)   
$weakcount = $weakcount +1 
firewall
}   
IF($proxyEnable -eq 0){   
checkOK([ref]$proxyEnable1)   
checkOK([ref]$ProxyServer1)   
}   
else   
{   
checkNO([ref]$proxyEnable1)   
$weakcount = $weakcount +1 
checkNO([ref]$ProxyServer1)   
proxy
}   
IF($fDenyTSConnections -eq 1){   
checkOK([ref]$fDenyTSConnections1)   
}   
else   
{   
checkNO([ref]$fDenyTSConnections1)   
$weakcount = $weakcount +1 
}   
IF($fAllowUnsolicited -eq 0){   
checkOK([ref]$fAllowUnsolicited1)   
}   
else   
{   
checkNO([ref]$fAllowUnsolicited1)   
$weakcount = $weakcount +1 
}
if($v3_check -eq $null) {$v3_check = "notrun"}
##############################################################################################   
$share2 = wmic share get name  
$share_count = 0  
For($i=2;$i -le $share2.length ;$i=$i+1)   
 {   
  if(($share2[$i] -replace " ","") -eq "IPC$" -OR ($share2[$i] -replace " ","") -eq "print$"){  
  $share[$i] = $share[$i] + [string]"        ..........점검완료"  
  }  
  elseif(($share2[$i] -match "meaningless") -eq "True"){  
  }
  elseif(($share2[$i] -match "canon") -eq "True"){ 
  $share[$i] = $share[$i] + [string]"        ..........점검완료"
  }
  elseif(($share2[$i] -match "print") -eq "True"){
	$share[$i] = $share[$i] + [string]"        ..........점검완료"  
  }
  elseif(($share2[$i] -match "driver") -eq "True"){
	$share[$i] = $share[$i] + [string]"        ..........점검완료"  
  }
  elseif(($share2[$i] -replace " ","").length -eq 0){  
  }  
  else  
  {  
  $share[$i] = $share[$i] + [string]"        ..........취약"  
  $share_count=$share_count +1 
  $weakcount = $weakcount +1
  share
  }  
}  
###############################text 출력###################################################  
echo $realtime_v3_p > "C:\security\log\v3.txt"   
echo $auto_v3_active_p >> "C:\security\log\v3.txt"   
echo $auto_v3_period_p >> "C:\security\log\v3.txt"
echo $v3_check_p >> "C:\security\log\v3.txt"   
echo $Critical_p > "C:\security\log\windowsupdate.txt"   
echo $updateactive1 >> "C:\security\log\windowsupdate.txt"   
echo $ss_active_p > "C:\security\log\screen.txt"
echo $ss_secure_p > "C:\security\log\screen.txt"   
echo $ss_time_p >> "C:\security\log\screen.txt"   
echo $ie_v_p > "C:\security\log\iever.txt"   
echo $u_name  > "C:\security\log\name.txt"   
echo $pw_pol2_p > "C:\security\log\pw_chg.txt"   
echo $pw_expire2 >> "C:\security\log\pw_chg.txt"   
echo $pw_warn1 >> "C:\security\log\pw_chg.txt"   
echo $MinimumPasswordAge1 > "C:\security\log\pwdrule.txt"   
echo $MaximumPasswordAge1 >> "C:\security\log\pwdrule.txt"   
echo $MinimumPasswordLength1 >> "C:\security\log\pwdrule.txt"   
echo $PasswordComplexity1 >> "C:\security\log\pwdrule.txt"   
echo $PasswordHistorySize1 >> "C:\security\log\pwdrule.txt"   
echo $LockoutBadCount1 >> "C:\security\log\pwdrule.txt"   
echo $ResetLockoutCount1 >> "C:\security\log\pwdrule.txt"   
echo $LockoutDuration1 >> "C:\security\log\pwdrule.txt"   
echo $AuditSystemEvents1 > "C:\security\log\eventrule.txt"   
echo $AuditObjectAccess1 >> "C:\security\log\eventrule.txt"   
echo $AuditPrivilegeUse1 >> "C:\security\log\eventrule.txt"   
echo $AuditPolicyChange1 >> "C:\security\log\eventrule.txt"   
echo $AuditAccountManage1 >> "C:\security\log\eventrule.txt"   
echo $AuditAccountLogon1 >> "C:\security\log\eventrule.txt"   
echo $AuditLogonEvents1 >> "C:\security\log\eventrule.txt"   
echo $share > "C:\security\log\shared.txt"   
echo $firewallcheck1 > "C:\security\log\firewallcheck1.txt"   
echo $firewallcheckk1 >> "C:\security\log\firewallcheck1.txt"   
echo $proxyEnable1 > "C:\security\log\proxy.txt"   
echo $ProxyServer1 >> "C:\security\log\proxy.txt"   
echo $fDenyTSConnections1 > "C:\security\log\remotecom.txt"   
echo $fAllowUnsolicited1 >> "C:\security\log\remotecom.txt"   
echo $sysdate2 > "C:\security\log\time.txt" 
echo $messanger1 > "C:\security\log\messanger.txt" 
echo $skype1 >> "C:\security\log\messanger.txt" 
##########################################################################################
$ss_notouch = "expire"
try{
$vid_check=(systeminfo | findstr /i bios)
IF($vid_check -match "xen"){
$ss_notouch="vdi"
}
}
catch{
}
[string]$hostname=[int]$sal_num
try{
$ip_add=$(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3})'}| out-null; $Matches[1])
}
catch{
$ip_add=$(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'}| out-null; $Matches[1])
}

$outip="***            IP_Address : "+$ip_add    
del C:\security\secpol.cfg   
$msg = $ip_add + "," + $realtime_v3.sysmonuse + "," + $auto_v3.autoupdateuse + "," + $auto_v3.autoupdateperiod + "," + $v3_check + "," + $ss_active + "," + $ss_time + "," + $ie_v + "," + $u_name + "," + $Critical_count + "," + $pw_pol2 + "," + $hash + "," + $pw_expire1 + "," + $pw_warn + "," + $updateactive + "," + $MinimumPasswordAge + "," + $MaximumPasswordAge + "," + $MinimumPasswordLength + "," + $PasswordComplexity + "," + $PasswordHistorySize + "," + $LockoutBadCount + "," + $ResetLockoutCount + "," + $LockoutDuration + "," + $AuditSystemEvents + "," + $AuditObjectAccess + "," + $AuditPrivilegeUse + "," + $AuditPolicyChange  + "," + $AuditAccountManage + "," + $AuditAccountLogon + "," + $AuditLogonEvents + "," + $firewallcheck + "," + $firewallcheckk + "," + $proxyEnable  + "," + $ProxyServer + "," + $fDenyTSConnections + "," + $fAllowUnsolicited + "," + $share_count + "," + $weakcount + "," + $skype + "," + $messanger + "," + $ss_notouch
"점검일자 $(date)    :   " + $msg >> "C:\security\log\msg.txt" 
try{ 
function SendTo-SysLog {    
           Param(    
           [string] $IP = "50.50.10.161",    
           [int] $Port = "5045"    
           )    
$msg = $ip_add + "," + $realtime_v3.sysmonuse + "," + $auto_v3.autoupdateuse + "," + $auto_v3.autoupdateperiod + "," + $v3_check + "," + $ss_active + "," + $ss_time + "," + $ie_v + "," + $u_name + "," + $Critical_count + "," + $pw_pol2 + "," + $hash + "," + $pw_expire1 + "," + $pw_warn + "," + $updateactive + "," + $MinimumPasswordAge + "," + $MaximumPasswordAge + "," + $MinimumPasswordLength + "," + $PasswordComplexity + "," + $PasswordHistorySize + "," + $LockoutBadCount + "," + $ResetLockoutCount + "," + $LockoutDuration + "," + $AuditSystemEvents + "," + $AuditObjectAccess + "," + $AuditPrivilegeUse + "," + $AuditPolicyChange  + "," + $AuditAccountManage + "," + $AuditAccountLogon + "," + $AuditLogonEvents + "," + $firewallcheck + "," + $firewallcheckk + "," + $proxyEnable  + "," + $ProxyServer + "," + $fDenyTSConnections + "," + $fAllowUnsolicited + "," + $share_count + "," + $weakcount + "," + $skype + "," + $messanger + "," + $ss_notouch
$socket = new-object System.Net.Sockets.TcpClient($IP, $Port)    
$stream = $socket.GetStream()    
$writer = new-object System.IO.StreamWriter $stream    
$writer.WriteLine($msg)    
$writer.Close()    
$stream.Close()    
$socket.Close()    
}
function SendTo-SysLog2 {    
           Param(    
           [string] $IP = "172.29.31.87",    
           [int] $Port = "5045"
           )    
$msg = $ip_add + "," + $realtime_v3.sysmonuse + "," + $auto_v3.autoupdateuse + "," + $auto_v3.autoupdateperiod + "," + $v3_check + "," + $ss_active + "," + $ss_time + "," + $ie_v + "," + $u_name + "," + $Critical_count + "," + $pw_pol2 + "," + $hash + "," + $pw_expire1 + "," + $pw_warn + "," + $updateactive + "," + $MinimumPasswordAge + "," + $MaximumPasswordAge + "," + $MinimumPasswordLength + "," + $PasswordComplexity + "," + $PasswordHistorySize + "," + $LockoutBadCount + "," + $ResetLockoutCount + "," + $LockoutDuration + "," + $AuditSystemEvents + "," + $AuditObjectAccess + "," + $AuditPrivilegeUse + "," + $AuditPolicyChange  + "," + $AuditAccountManage + "," + $AuditAccountLogon + "," + $AuditLogonEvents + "," + $firewallcheck + "," + $firewallcheckk + "," + $proxyEnable  + "," + $ProxyServer + "," + $fDenyTSConnections + "," + $fAllowUnsolicited + "," + $share_count + "," + $weakcount + "," + $skype + "," + $messanger + "," + $ss_notouch
$socket = new-object System.Net.Sockets.TcpClient($IP, $Port)    
$stream = $socket.GetStream()    
$writer = new-object System.IO.StreamWriter $stream    
$writer.WriteLine($msg)    
$writer.Close()    
$stream.Close()    
$socket.Close()    
}   
try{
SendTo-SysLog
}
catch{
SendTo-SysLog2
}
} 
catch{ 
(New-Object -ComObject Wscript.Shell).Popup("""PC 로그전송 실패!!! 정보보호팀으로 연락주시기 바랍니다.""",5,"""정보보호팀 메세지""",0x0)
} 
gci C:\security\error | where-object -FilterScript{$_.length -gt 50MB} | Remove-item -force 
