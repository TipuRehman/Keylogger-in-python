@echo off
echo ===============================================
echo Keylogger with Z/A Hotkeys Control Panel
echo ===============================================
echo Z = View Report | A = Close Report
echo ===============================================
echo.

:: Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: This script requires administrator privileges.
    echo Please right-click on this batch file and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

:: Set paths
set "SCRIPT_DIR=%~dp0"
set "KEYLOGGER_PY=%SCRIPT_DIR%keylogger.py"
set "SERVICE_NAME=KeyloggerZAService"
set "PYTHON_EXE=pythonw.exe"
set "SERVICE_BATCH=%SCRIPT_DIR%run_keylogger_service.bat"

:: Create folders if they don't exist
mkdir "%SCRIPT_DIR%\logs" 2>nul
mkdir "%SCRIPT_DIR%\logs\reports" 2>nul
mkdir "%SCRIPT_DIR%\logs\reports\fifteen_min" 2>nul

echo Checking for required files...
if not exist "%KEYLOGGER_PY%" (
    echo ERROR: Could not find keylogger.py in the current directory.
    echo Please make sure the script is in the same folder as this batch file.
    echo.
    pause
    exit /b 1
)

:: Check if Python is installed
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH.
    echo Please install Python and make sure it's added to your PATH.
    echo.
    pause
    exit /b 1
)

:: Install required Python packages
echo Installing required Python packages...
pip install pynput psutil pywin32

:: Create service runner batch file
echo @echo off > "%SERVICE_BATCH%"
echo cd /d "%SCRIPT_DIR%" >> "%SERVICE_BATCH%"
echo "%PYTHON_EXE%" "%KEYLOGGER_PY%" >> "%SERVICE_BATCH%"

echo.
echo Select an option:
echo 1. Run directly (normal mode)
echo 2. Install as Windows service
echo 3. Start service
echo 4. Stop service
echo 5. Remove service
echo 6. Exit
echo.

set /p choice="Enter your choice (1-6): "

if "%choice%"=="1" (
    echo.
    echo Running the keylogger directly...
    echo Press Z to view reports, A to close the viewer, and Ctrl+C to stop.
    cd /d "%SCRIPT_DIR%"
    python "%KEYLOGGER_PY%"
    
) else if "%choice%"=="2" (
    echo.
    echo Installing keylogger as a service...
    
    :: Check for NSSM
    where nssm >nul 2>&1
    if %errorLevel% neq 0 (
        echo Downloading NSSM...
        powershell -Command "Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile '%SCRIPT_DIR%\nssm.zip'" 2>nul
        if %errorLevel% neq 0 (
            powershell -Command "(New-Object Net.WebClient).DownloadFile('https://nssm.cc/release/nssm-2.24.zip', '%SCRIPT_DIR%\nssm.zip')"
        )
        
        echo Extracting NSSM...
        powershell -Command "Expand-Archive -Path '%SCRIPT_DIR%\nssm.zip' -DestinationPath '%SCRIPT_DIR%\nssm-temp' -Force"
        mkdir "%SCRIPT_DIR%\tools" 2>nul
        copy "%SCRIPT_DIR%\nssm-temp\nssm-2.24\win64\nssm.exe" "%SCRIPT_DIR%\tools\nssm.exe" >nul 2>&1
        if %errorLevel% neq 0 (
            copy "%SCRIPT_DIR%\nssm-temp\nssm-2.24\win32\nssm.exe" "%SCRIPT_DIR%\tools\nssm.exe" >nul
        )
        rmdir /s /q "%SCRIPT_DIR%\nssm-temp" 2>nul
        del "%SCRIPT_DIR%\nssm.zip" 2>nul
        set "NSSM_EXE=%SCRIPT_DIR%\tools\nssm.exe"
    ) else (
        set "NSSM_EXE=nssm"
    )
    
    :: Remove existing service if it exists
    sc query "%SERVICE_NAME%" >nul 2>&1
    if %errorLevel% equ 0 (
        sc stop "%SERVICE_NAME%" >nul 2>&1
        sc delete "%SERVICE_NAME%" >nul 2>&1
        timeout /t 2 >nul
    )
    
    :: Create the service
    "%NSSM_EXE%" install "%SERVICE_NAME%" "%SERVICE_BATCH%"
    "%NSSM_EXE%" set "%SERVICE_NAME%" DisplayName "Keylogger Service with Z/A Hotkeys"
    "%NSSM_EXE%" set "%SERVICE_NAME%" Description "Monitors keystrokes with Z/A hotkeys"
    "%NSSM_EXE%" set "%SERVICE_NAME%" Start SERVICE_AUTO_START
    "%NSSM_EXE%" set "%SERVICE_NAME%" Type SERVICE_INTERACTIVE_PROCESS
    "%NSSM_EXE%" set "%SERVICE_NAME%" ObjectName LocalSystem
    
    echo Service installed successfully! Select option 3 to start it.
    
) else if "%choice%"=="3" (
    echo.
    echo Starting the service...
    sc start "%SERVICE_NAME%"
    if %errorLevel% equ 0 (
        echo Service started! Press Z to view reports, A to close.
    ) else (
        echo Error starting service. Make sure it's installed first.
    )
    
) else if "%choice%"=="4" (
    echo.
    echo Stopping the service...
    sc stop "%SERVICE_NAME%"
    
) else if "%choice%"=="5" (
    echo.
    echo Removing the service...
    sc stop "%SERVICE_NAME%" >nul 2>&1
    sc delete "%SERVICE_NAME%"
    
) else if "%choice%"=="6" (
    echo.
    echo Exiting...
    exit /b 0
    
) else (
    echo.
    echo Invalid choice.
)

pause