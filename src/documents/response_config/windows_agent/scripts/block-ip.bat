@echo off
REM Wazuh Active Response wrapper for block-ip.ps1.
REM The Wazuh JSON protocol is received on stdin and inherited by PowerShell.

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0block-ip.ps1"
exit /b %ERRORLEVEL%
