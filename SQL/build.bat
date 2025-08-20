@echo off
setlocal

REM Set paths - CORRECTED FOR YOUR ACTUAL STRUCTURE
set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
set "ILMERGE=..\packages\ILMerge.3.0.41\tools\net452\ILMerge.exe"
set "PROJECT=SQLWinds.csproj"
set "OUTPUT_DIR=bin\Release"

REM Build the project
echo [*] Building SQLWinds...
"%MSBUILD%" "%PROJECT%" /p:Configuration=Release /p:Platform=AnyCPU /nologo

if %errorlevel% neq 0 (
    echo [-] Build failed
    exit /b %errorlevel%
)

REM Wait for build to complete
timeout /t 2 /nobreak > nul

REM Run ILMerge (only include Newtonsoft.Json.dll)
echo [*] Creating single EXE...
if exist "%OUTPUT_DIR%\Newtonsoft.Json.dll" (
    "%ILMERGE%" /out:"%OUTPUT_DIR%\SQLWinds-Standalone.exe" ^
    /target:exe ^
    /ndebug ^
    /targetplatform:"v4,C:\Windows\Microsoft.NET\Framework64\v4.0.30319" ^
    "%OUTPUT_DIR%\SQLWinds.exe" ^
    "%OUTPUT_DIR%\Newtonsoft.Json.dll"
) else (
    echo [*] Newtonsoft.Json.dll not found - creating standalone EXE without it
    "%ILMERGE%" /out:"%OUTPUT_DIR%\SQLWinds-Standalone.exe" ^
    /target:exe ^
    /ndebug ^
    /targetplatform:"v4,C:\Windows\Microsoft.NET\Framework64\v4.0.30319" ^
    "%OUTPUT_DIR%\SQLWinds.exe"
)

if %errorlevel% equ 0 (
    echo [+] SUCCESS: Single EXE created at "%cd%\%OUTPUT_DIR%\SQLWinds-Standalone.exe"
    exit /b 0
) else (
    echo [-] ILMerge failed
    exit /b 1
)