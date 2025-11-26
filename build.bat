@echo off
REM Simple batch wrapper to attempt a build on Windows.
REM This expects MSYS2/mingw or make available in PATH. If not available, see build.ps1 for guidance.

where make >nul 2>&1
if %ERRORLEVEL%==0 (
    echo Found make, invoking make
    make
    exit /b %ERRORLEVEL%
) else (
    echo make not found in PATH.
    echo If you have MSYS2 installed, open the MSYS2 MinGW64 shell and run `make` there.
    echo Alternatively, run PowerShell script build.ps1 for guided options.
    exit /b 1
)
