@echo off
rem ==========================================================
rem  file_integrity.c : compile and run in one step
rem  Usage: double-click this file, or type .\build.bat in the VS Code terminal
rem ==========================================================

rem 1. Find the Visual Studio install folder with vswhere
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] Visual Studio or Build Tools is not installed.
    echo         Install the "Desktop development with C++" workload.
    pause
    exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSPATH=%%i"
if not defined VSPATH (
    echo [ERROR] C++ build tools are not installed.
    echo         Add the "Desktop development with C++" workload in Visual Studio Installer.
    pause
    exit /b 1
)

rem 2. Load the compiler environment (cl.exe, bcrypt.lib) for this window only
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul

rem 3. Move to the folder that holds this file and compile
cd /d "%~dp0"
cl /nologo /W4 /utf-8 file_integrity.c
if errorlevel 1 (
    echo [ERROR] Compile failed. Check the messages above.
    pause
    exit /b 1
)

rem 4. Run the program
echo.
file_integrity.exe
echo.
pause
