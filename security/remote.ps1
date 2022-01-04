try{ 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableClip" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableCdm" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "fDisableCcm" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ffDisableLPT" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v "ffDisableCameraRedir" /t REG_DWORD /d 1 /f 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v "fDenyTSConnections" /t REG_DWORD /d 0 /f 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisallowRun" /t REG_DWORD /d 1 /f 
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun" /v "mmc" /d mmc.exe /f 
$fDisableClip = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDisableClip  
$fDisableCdm = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDisableCdm  
$fDisableCcm = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').fDisableCcm  
$ffDisableLPT = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').ffDisableLPT  
$ffDisableCameraRedir = (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services').ffDisableCameraRedir  
$DisallowRun = (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer').DisallowRun  
$mmc = (Get-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun').mmc  
$enableremote= (Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections  
netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow 
powercfg -change -monitor-timeout-ac 0 
powercfg -change -monitor-timeout-dc 0 
powercfg -change -disk-timeout-ac 0 
powercfg -change -disk-timeout-dc 0 
powercfg -change -standby-timeout-ac 0 
powercfg -change -standby-timeout-dc 0 
powercfg -change -hibernate-timeout-ac 0 
powercfg -change -hibernate-timeout-dc 0 
if($fDisableClip -eq $null){    
$fDisableClip = "null" 
} 
if($fDisableCdm -eq $null){    
$fDisableCdm = "null" 
} 
if($fDisableCcm -eq $null){    
$fDisableCcm = "null" 
} 
if($ffDisableLPT -eq $null){    
$ffDisableLPT = "null" 
} 
if($ffDisableCameraRedir -eq $null){    
$ffDisableCameraRedir = "null" 
} 
if($DisallowRun -eq $null){    
$DisallowRun = "null" 
} 
if($mmc -eq $null){    
$mmc = "null" 
} 
if($enableremote -eq $null){    
$enableremote = "null" 
} 
} 
catch{ 
(New-Object -ComObject Wscript.Shell).Popup("""스크립트 오류 발생. 정보보호팀으로 연락주시기 바랍니다.""",5,"""정보보호팀 메세지""",0x0)
} 
try{
$ip_add=$(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,2}\.\d{1,3}\.\d{1,3}\.\d{1,3})'}| out-null; $Matches[1])
}
catch{
$ip_add=$(ipconfig | where {$_ -match 'IPv4.+\s(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'}| out-null; $Matches[1])
}

$msg = $ip_add + "," + [string]$fDisableClip + "," + $fDisableCdm + "," + $fDisableCcm + "," + $ffDisableLPT + "," + $ffDisableCameraRedir + "," + $DisallowRun + "," + $mmc 
"점검일자 $(date)    :   " + $msg >> "C:\security\relog.txt"
try{  
function SendTo-SysLog{     
           Param(     
           [string] $IP = "50.50.10.161",     
           [int] $Port = "5048" 
           )     
$msg = [string]$fDisableClip + "," + $fDisableCdm + "," + $fDisableCcm + "," + $ffDisableLPT + "," + $ffDisableCameraRedir + "," + $DisallowRun + "," + $mmc 
$socket = new-object System.Net.Sockets.TcpClient($IP, $Port)     
$stream = $socket.GetStream()     
$writer = new-object System.IO.StreamWriter $stream     
$writer.WriteLine($msg)     
$writer.Close()     
$stream.Close()     
$socket.Close()     
}
function SendTo-SysLog2{     
           Param(     
           [string] $IP = "172.29.31.87",     
           [int] $Port = "5047" 
           )     
$msg = [string]$fDisableClip + "," + $fDisableCdm + "," + $fDisableCcm + "," + $ffDisableLPT + "," + $ffDisableCameraRedir + "," + $DisallowRun + "," + $mmc 
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
(New-Object -ComObject Wscript.Shell).Popup("""서버와 통신이 성공하지 않았습니다. 정보보호팀으로 연락주시기 바랍니다.""",5,"""정보보호팀 메세지""",0x0) 
} 
