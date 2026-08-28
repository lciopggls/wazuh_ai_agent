@echo off
REM Wazuh Active Response wrapper for endpoint-response.ps1.

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0endpoint-response.ps1"
exit /b %ERRORLEVEL%
