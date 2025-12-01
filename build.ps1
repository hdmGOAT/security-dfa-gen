<#
PowerShell helper to build the project for Windows.

Options:
- Use this script on Windows with MSYS2/Mingw or Visual Studio Developer Command Prompt.
- On Linux you can cross-compile using mingw-w64 toolchain (install package that provides x86_64-w64-mingw32-g++), then run `make windows`.

This script attempts these strategies (in order):
1. If running on Windows and MSYS2 is available, invoke `make` inside MSYS2 environment.
2. If running on Windows and Visual Studio `cl.exe` is available, recommend using a VS project or build manually.
3. If cross-compiler `x86_64-w64-mingw32-g++` is available in PATH, invoke `make windows` to cross-compile.

Examples:
PS> .\build.ps1          # tries sensible default
PS> .\build.ps1 -CrossPrefix i686-w64-mingw32-  # use 32-bit mingw prefix
#>
param(
    [string]$CrossPrefix = "x86_64-w64-mingw32-",
    [switch]$Verbose
)

function Write-Info($m) { Write-Host "[info] $m" -ForegroundColor Cyan }
function Write-Err($m) { Write-Host "[error] $m" -ForegroundColor Red }

Push-Location -Path "$PSScriptRoot"

# 1) Check for native MSYS2/make setup (pacman provided tools)
if ($IsWindows) {
    Write-Info "Running on Windows. Checking for MSYS2/make or mingw-w64 toolchain..."
    $msysMake = Get-Command make -ErrorAction SilentlyContinue
    if ($msysMake) {
        Write-Info "Found 'make' in PATH. Running 'make' to build native binaries."
        cmd /c "make"
        Pop-Location
        exit $LASTEXITCODE
    }

    # 2) Check for Visual Studio tools (cl.exe)
    $cl = Get-Command cl.exe -ErrorAction SilentlyContinue
    if ($cl) {
        Write-Info "Found MSVC (cl.exe). This repo uses a Makefile; building with MSVC requires adjusting the build system or using MSYS2."
        Write-Info "Recommended: Install MSYS2 and use mingw-w64 or generate a Visual Studio project."
        Pop-Location
        exit 0
    }
}

# 3) Cross-compile on Linux/macOS using mingw-w64
Write-Info "Checking for cross-compiler '${CrossPrefix}g++'..."
$cross = Get-Command "${CrossPrefix}g++" -ErrorAction SilentlyContinue
if ($cross) {
    Write-Info "Found cross-compiler. Invoking 'make windows' using prefix ${CrossPrefix}."
    # Use mingw cross-compiler by calling make with variables
    & make windows CROSS_PREFIX=$CrossPrefix
    Pop-Location
    exit $LASTEXITCODE
}

Write-Err "No suitable build toolchain found."
Write-Err "Options:"
Write-Err "  - Install MSYS2/mingw-w64 on Windows and run this script from an MSYS2 shell."
Write-Err "  - Install mingw-w64 cross-compiler on Linux (package name often 'mingw-w64' or 'gcc-mingw-w64') and run: make windows"
Pop-Location
exit 1
