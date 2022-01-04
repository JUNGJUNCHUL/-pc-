@echo off

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system" 
if '%errorlevel%' NEQ '0' ( 
    echo 관리 권한을 요청 ... 
    goto UACPrompt 
) else ( goto gotAdmin ) 
:UACPrompt 
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs" 
    set params = %*:"="" 
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs" 
    "%temp%\getadmin.vbs"
    rem del "%temp%\getadmin.vbs" 
    exit /B 
:gotAdmin 
pushd "%CD%" 
    CD /D "%~dp0"
powershell (New-Object -ComObject Wscript.Shell).Popup("""설치가 진행되는 동안 기다려주세요. PC에 따라 몇분 소요 될 수 있으며, 설치가 완료되면 자동으로 점검항목창이 실행이 됩니다.""",5,"""정보보호팀 메세지""",0x0)
rmdir /S /Q "C:\security"
xcopy C:\security2\* C:\security\ /e /h /k /y
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\jcjung" /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\jcjung" /v DisplayName /t REG_SZ /d jcjung /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\jcjung" /v version /t REG_SZ /d 1.0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\jcjung" /v UninstallString /t REG_SZ /d C:\security\nicePC\un.bat /f
powershell.exe "dir C:\security -Recurse | Unblock-File" 2>nul
mklink "%USERPROFILE%\Desktop\내PC지킴이.hta" "C:\security\JCui.hta"
schtasks.exe /create /F /tn "Security Daily Check" /tr "c:\security\JCcheck.bat" /sc daily /st 11:59 /RL HIGHEST > NUL
start /MIN c:\security\JCcheck.bat >NUL
exit