@echo off
setlocal enabledelayedexpansion

echo.
echo ============================================
echo   TaskPrivEscScanner Build Script
echo ============================================
echo.

:: Check for dotnet
where dotnet >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo [*] Found dotnet CLI
    echo [*] Building Release configuration...
    echo.
    dotnet build -c Release
    if %ERRORLEVEL% EQU 0 (
        echo.
        echo [+] Build successful!
        echo [+] Output: bin\Release\net4.8\TaskPrivEscScanner.exe
        goto :end
    ) else (
        echo [-] dotnet build failed, trying MSBuild...
    )
)

:: Try MSBuild
echo [*] Searching for MSBuild...

:: VS2022
for %%e in (Community Professional Enterprise) do (
    if exist "%ProgramFiles%\Microsoft Visual Studio\2022\%%e\MSBuild\Current\Bin\MSBuild.exe" (
        set "MSBUILD=%ProgramFiles%\Microsoft Visual Studio\2022\%%e\MSBuild\Current\Bin\MSBuild.exe"
        goto :build
    )
)

:: VS2019
for %%e in (Community Professional Enterprise) do (
    if exist "%ProgramFiles(x86)%\Microsoft Visual Studio\2019\%%e\MSBuild\Current\Bin\MSBuild.exe" (
        set "MSBUILD=%ProgramFiles(x86)%\Microsoft Visual Studio\2019\%%e\MSBuild\Current\Bin\MSBuild.exe"
        goto :build
    )
)

:: .NET Framework MSBuild
if exist "%ProgramFiles(x86)%\MSBuild\14.0\Bin\MSBuild.exe" (
    set "MSBUILD=%ProgramFiles(x86)%\MSBuild\14.0\Bin\MSBuild.exe"
    goto :build
)

echo.
echo [-] ERROR: No build tools found!
echo [-] Please install one of the following:
echo     - .NET SDK (https://dotnet.microsoft.com/download)
echo     - Visual Studio 2019 or later
echo.
goto :end

:build
echo [*] Using: !MSBUILD!
echo [*] Building Release configuration...
echo.
"!MSBUILD!" TaskPrivEscScanner.csproj /p:Configuration=Release /verbosity:minimal /nologo
if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Build successful!
    echo [+] Output: bin\Release\net4.8\TaskPrivEscScanner.exe
) else (
    echo.
    echo [-] Build failed!
    echo [-] Check error messages above
)

:end
echo.
pause
