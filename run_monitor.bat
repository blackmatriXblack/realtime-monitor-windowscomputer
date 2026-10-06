@echo off
cd /d "%~dp0"
python rolling_log_monitor.py %*
pause