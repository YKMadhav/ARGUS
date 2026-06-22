@echo off
setlocal enabledelayedexpansion

:: ─────────────────────────────────────────────
:: ARGUS - Windows Launcher
:: Run as Administrator (required for Npcap sniffing + firewall blocking)
:: ─────────────────────────────────────────────

:: Check for admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Please run this script as Administrator.
    echo     Right-click start_argus.bat and choose "Run as administrator"
    pause
    exit /b 1
)

cd /d "%~dp0"
mkdir logs 2>nul

:: ── Set defaults (override by setting env vars before running) ──
if not defined ARGUS_INTERFACE       set ARGUS_INTERFACE=
if not defined ARGUS_NETWORK_CIDR    set ARGUS_NETWORK_CIDR=
if not defined ARGUS_BLOCK_MODE      set ARGUS_BLOCK_MODE=monitor
if not defined ARGUS_PROTECTED_IPS   set ARGUS_PROTECTED_IPS=
if not defined ARGUS_MIN_SCAN_PORTS  set ARGUS_MIN_SCAN_PORTS=20
if not defined ARGUS_MIN_SCAN_SYNS   set ARGUS_MIN_SCAN_SYNS=15
if not defined ARGUS_MIN_SCAN_TARGETS set ARGUS_MIN_SCAN_TARGETS=8
if not defined ARGUS_MIN_TARGET_PORTS set ARGUS_MIN_TARGET_PORTS=8

echo.
echo  ==========================================
echo   ARGUS  --  Windows Edition
echo  ==========================================
echo   Block Mode   : %ARGUS_BLOCK_MODE%
echo   Interface    : %ARGUS_INTERFACE% (auto if blank)
echo   Network CIDR : %ARGUS_NETWORK_CIDR% (auto if blank)
echo  ==========================================
echo.

:: ── Activate venv ──
if not exist "venv\Scripts\activate.bat" (
    echo [!] Virtual environment not found.
    echo     Run setup_windows.bat first.
    pause
    exit /b 1
)
call venv\Scripts\activate.bat

:: ── Start detection engine in a new window ──
echo [*] Starting ARGUS detection engine...
start "ARGUS Detection" cmd /k "cd /d %~dp0 && call venv\Scripts\activate.bat && python live_detect.py"

:: ── Wait a moment then start dashboard ──
timeout /t 3 /nobreak >nul
echo [*] Starting dashboard at http://localhost:8501 ...
start "ARGUS Dashboard" cmd /k "cd /d %~dp0 && call venv\Scripts\activate.bat && streamlit run dashboard.py"

echo.
echo  ARGUS is running.
echo  Dashboard  : http://localhost:8501
echo  Detect log : logs\argus.log
echo  Alerts     : logs\alerts.json
echo.
echo  Close the "ARGUS Detection" and "ARGUS Dashboard" windows to stop.
echo.
pause
