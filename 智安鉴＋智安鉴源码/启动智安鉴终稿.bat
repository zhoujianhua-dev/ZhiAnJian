@echo off
title ZhiAnJian Final - Extract and Run
cd /d "%~dp0"
echo ================================================================
echo   ZhiAnJian Final - will open http://127.0.0.1:8742
echo   DB: bundled MySQL in .\mysql (port 3307, root / empty password)
echo ================================================================
echo.

set "PYCMD="
py -3.10 -c "import sys" >nul 2>nul
if not errorlevel 1 set "PYCMD=py -3.10"
if not defined PYCMD (
    py -3 -c "import sys" >nul 2>nul
    if not errorlevel 1 set "PYCMD=py -3"
)
if not defined PYCMD (
    python -c "import sys" >nul 2>nul
    if not errorlevel 1 set "PYCMD=python"
)
if not defined PYCMD (
    echo [ERROR] Python 3.10+ not found. Please install Python 3.10
    echo         ^(tick "Add Python to PATH"^), then run this file again.
    echo         Download: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found:
%PYCMD% --version

%PYCMD% -c "import flask, docx, reportlab, pymysql" >nul 2>nul
if errorlevel 1 (
    echo.
    echo [First run] Installing dependencies, please wait ...
    %PYCMD% -m pip install -r requirements.txt
    if errorlevel 1 (
        echo [ERROR] Failed to install dependencies. Check network and retry.
        pause
        exit /b 1
    )
)

REM ---- if MySQL 3307 is already up, skip starting it ----
netstat -ano | findstr ":3307" | findstr "LISTENING" >nul 2>nul
if not errorlevel 1 goto dbready

REM ---- mysqld cannot handle non-ASCII paths, so map this folder
REM      to a free drive letter (X/Y/W/V/U/T) and run it from there ----
set "DRV="
for %%L in (X Y W V U T) do if not defined DRV call :trydrv %%L
if not defined DRV (
    echo [ERROR] Could not map a temporary drive letter ^(X/Y/W/V/U/T busy^).
    pause
    exit /b 1
)
echo [DB] Starting bundled MySQL on port 3307 via %DRV% ...
start "MySQL-3307" /min "%DRV%:\mysql\bin\mysqld.exe" --no-defaults --basedir="%DRV%:\mysql" --datadir="%DRV%:\mysql\data" --lc-messages-dir="%DRV%:\mysql\share" --port=3307 --mysqlx=0 --console

set /a TRIES=0
:waitdb
netstat -ano | findstr ":3307" | findstr "LISTENING" >nul 2>nul
if not errorlevel 1 goto dbready
set /a TRIES+=1
if %TRIES% GEQ 30 (
    echo [ERROR] MySQL did not start. Check the MySQL-3307 window.
    pause
    exit /b 1
)
ping -n 2 127.0.0.1 >nul
goto waitdb

:dbready
echo [DB] MySQL 3307 is ready.
netstat -ano | findstr ":8742" | findstr "LISTENING" >nul 2>nul
if not errorlevel 1 (
    echo [WARN] App is already running at http://127.0.0.1:8742
    echo        Close the old window first if you want to restart it.
    pause
    exit /b 1
)
set "ZS_PORT=8742"
set "ZS_DB_HOST=127.0.0.1"
set "ZS_DB_PORT=3307"
set "ZS_DB_USER=root"
set "ZS_DB_PASSWORD="
echo [APP] Starting ZhiAnJian on http://127.0.0.1:8742
echo       KEEP THIS WINDOW OPEN while using the system.
echo.
%PYCMD% app.py

echo.
echo Service stopped. Press any key to close.
pause >nul
exit /b 0

:trydrv
set "L=%1"
if exist "%L%:\." (
    if exist "%L%:\mysql\data\auto.cnf" (
        subst %L%: /d >nul 2>nul
        if not exist "%L%:\." subst %L%: "%~dp0." >nul 2>nul
    )
) else (
    subst %L%: "%~dp0." >nul 2>nul
)
if exist "%L%:\." set "DRV=%L%"
goto :eof
