@echo off
setlocal enabledelayedexpansion

echo.
echo  ==========================================
echo   ARGUS Windows Setup
echo  ==========================================
echo.

:: Check for Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] Python not found.
    echo     Download and install Python 3.10+ from https://www.python.org/downloads/
    echo     Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version') do echo [+] Found %%i

:: Create virtualenv
echo [*] Creating virtual environment...
python -m venv venv
if %errorLevel% neq 0 (
    echo [!] Failed to create venv.
    pause
    exit /b 1
)
echo [+] Virtual environment created.

:: Activate
call venv\Scripts\activate.bat

:: Upgrade pip
echo [*] Upgrading pip...
python -m pip install --upgrade pip --quiet

:: Install dependencies
echo [*] Installing Python packages (this may take a minute)...
pip install scapy pywin32 streamlit plotly pandas numpy scikit-learn joblib --quiet
if %errorLevel% neq 0 (
    echo [!] Package install failed. Check your internet connection.
    pause
    exit /b 1
)
echo [+] Packages installed.

echo.
echo  ==========================================
echo   Setup complete!
echo  ==========================================
echo.
echo  IMPORTANT: Before running ARGUS you must install Npcap:
echo    https://npcap.com/#download
echo    - Download the installer and run it
echo    - Enable "WinPcap API-compatible mode" during install
echo.
echo  Then run start_argus.bat as Administrator.
echo.
pause
