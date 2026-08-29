@echo off
REM Active Response wrapper for the fixed demo port script.
REM The JSON control message is received on stdin and inherited by PowerShell.

"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0block-port.ps1"
exit /b %ERRORLEVEL%
