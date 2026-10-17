@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"
title ZhiAnJian - Intelligent Security Detection and Vulnerability Report System
echo ================================================================
echo    ZhiAnJian - Intelligent Security Detection and Vulnerability Report System
echo    Local web app. The browser will open automatically.
echo ================================================================
echo.

set "PYCMD="
py -3.10 -c "import sys" >nul 2>nul
if not errorlevel 1 set "PYCMD=py -3.10"
if not defined PYCMD (
    python -c "import sys" >nul 2>nul
    if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD (
    echo [ERROR] Python 3.10+ was not found on this computer.
    echo Please install Python 3.10  ^(tick "Add Python to PATH"^) and run again.
    echo Download: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found:
%PYCMD% --version

REM First run: install dependencies automatically if Flask is missing.
%PYCMD% -c "import flask, docx, reportlab" >nul 2>nul
if errorlevel 1 (
    echo.
    echo [First run] Installing dependencies from requirements.txt, please wait ...
    %PYCMD% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo.
        echo [ERROR] Failed to install dependencies. Check the network connection,
        echo then run this file again. You can also run manually:
        echo     %PYCMD% -m pip install -r requirements.txt
        pause
        exit /b 1
    )
)

echo.
echo Starting service at http://127.0.0.1:8080  ^(set ZS_PORT to change^)
echo KEEP THIS WINDOW OPEN while using the system. Close it to stop.
echo.
%PYCMD% app.py

echo.
echo Service stopped. Press any key to close this window.
pause >nul