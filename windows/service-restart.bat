@ECHO OFF & SETLOCAL ENABLEEXTENSIONS

CD /d %~dp0
SFC 2>&1 | FIND /i "/SCANNOW" >NUL:
IF ERRORLEVEL 1 GOTO :ELEVATE
GOTO :ADMINTASKS

:ELEVATE

ECHO Elevated privileges are temporarily required, just to register or remove the dnscrypt-proxy service.
MSHTA "javascript: var shell = new ActiveXObject('shell.application'); shell.ShellExecute('%~nx0', '', '', 'runas', 1); close();"
EXIT

:ADMINTASKS

REM If DNSCrypt-Proxy is not yet running restart will fail
Tasklist /FI "IMAGENAME eq dnscrypt-proxy.exe" /NH | Find "dnscrypt-proxy.exe" >NUL:
IF ERRORLEVEL 1 GOTO :SVCSTART

ECHO Re-Starting Service...
dnscrypt-proxy.exe -service restart
GOTO :SAYTHANKS

:SVCSTART

ECHO Starting Service...
dnscrypt-proxy.exe -service start

:SAYTHANKS

ECHO.
SET /P _=Thank you for using dnscrypt-proxy! Hit [RETURN] to finish
EXIT
