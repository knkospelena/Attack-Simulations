@echo off
REM ╔══════════════════════════════════════════════════════════════════╗
REM ║      SOC ATTACK SIMULATION TOOL — BN301                         ║
REM ║      Auto-setup script for Windows                              ║
REM ╚══════════════════════════════════════════════════════════════════╝
REM Usage: Double-click run.bat  OR  run it from Command Prompt / PowerShell

title SOC Attack Simulation Tool — BN301

echo.
echo ══════════════════════════════════════════════════════════════
echo   SOC ATTACK SIMULATION TOOL — BN301
echo   Security Operations Center  ^|  Auto-Setup (Windows)
echo ══════════════════════════════════════════════════════════════
echo.

REM ── Change to script directory ────────────────────────────────────
cd /d "%~dp0"

REM ── 1. Check Python ───────────────────────────────────────────────
echo [*] Checking Python 3...
python --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    py --version >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo [!] Python not found!
        echo [!] Download and install Python 3.10+ from:
        echo     https://www.python.org/downloads/
        echo [!] Make sure to check "Add Python to PATH" during install.
        echo.
        REM Try winget (Windows 11 / updated Win10)
        winget --version >nul 2>&1
        IF %ERRORLEVEL% EQU 0 (
            echo [*] Attempting auto-install via winget...
            winget install -e --id Python.Python.3.11 --accept-package-agreements --accept-source-agreements
            IF %ERRORLEVEL% NEQ 0 (
                echo [!] winget install failed. Please install Python manually.
                pause
                exit /b 1
            )
            echo [+] Python installed via winget. Please restart this script.
            pause
            exit /b 0
        )
        pause
        exit /b 1
    ) ELSE (
        SET PYTHON=py
    )
) ELSE (
    SET PYTHON=python
)

FOR /F "tokens=*" %%i IN ('%PYTHON% --version 2^>^&1') DO SET PY_VER=%%i
echo [+] Found: %PY_VER%

REM ── 2. Create / activate virtual environment ──────────────────────
echo [*] Setting up virtual environment...
IF NOT EXIST ".venv" (
    %PYTHON% -m venv .venv
    IF %ERRORLEVEL% NEQ 0 (
        echo [!] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo [+] Virtual environment created.
) ELSE (
    echo [+] Virtual environment already exists.
)

CALL .venv\Scripts\activate.bat

REM ── 3. Upgrade pip & install packages ─────────────────────────────
echo [*] Installing Python packages...
python -m pip install --upgrade pip --quiet
python -m pip install -r requirements.txt --quiet
IF %ERRORLEVEL% NEQ 0 (
    echo [!] Failed to install Python packages. Check requirements.txt.
    pause
    exit /b 1
)
echo [+] Python packages installed.

REM ── 4. Check nmap ────────────────────────────────────────────────
echo [*] Checking nmap...
nmap --version >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] nmap not found.
    echo [*] Attempting to install nmap via winget...
    winget install -e --id Insecure.Nmap --accept-package-agreements --accept-source-agreements >nul 2>&1
    IF %ERRORLEVEL% NEQ 0 (
        echo [!] Auto-install failed.
        echo [!] Download nmap manually from: https://nmap.org/download.html#windows
        echo [!] Add nmap to your PATH after installing.
        pause
        exit /b 1
    )
    echo [+] nmap installed. You may need to restart this script for PATH to update.
    pause
    exit /b 0
) ELSE (
    FOR /F "tokens=*" %%i IN ('nmap --version 2^>^&1 ^| findstr /i "nmap"') DO (
        echo [+] %%i
        GOTO :nmap_done
    )
)
:nmap_done

REM ── 5. Check hydra (optional) ─────────────────────────────────────
echo [*] Checking hydra (optional)...
hydra -h >nul 2>&1
IF %ERRORLEVEL% NEQ 0 (
    echo [!] hydra not found. Brute force attacks will be unavailable.
    echo [!] On Kali WSL: sudo apt install hydra
    echo [!] Or use WSL2 / Kali for full brute force support.
) ELSE (
    echo [+] hydra found.
)

REM ── 6. Launch ─────────────────────────────────────────────────────
echo.
echo ══════════════════════════════════════════════════════════════
echo   [OK]  All dependencies satisfied. Starting server...
echo   Open your browser at: http://localhost:5050
echo   Press Ctrl+C to stop
echo ══════════════════════════════════════════════════════════════
echo.

python app.py

pause
