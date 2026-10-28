@echo off
rem Builds ActiveDirectoryDumper from the command line or from the VS Code build task.
rem Usage: build.cmd [Configuration] [Platform]   (defaults: Release x64)
rem Requires Visual Studio 2022 or Build Tools 2022 with the ".NET desktop build tools" workload
rem (MSBuild, .NET Framework 4.8 targeting pack, NuGet). nuget.exe is downloaded on first use.
setlocal
set "ROOT=%~dp0"
set "CONFIG=%~1"
if "%CONFIG%"=="" set "CONFIG=Release"
set "PLATFORM=%~2"
if "%PLATFORM%"=="" set "PLATFORM=x64"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [!] vswhere.exe not found. Install Visual Studio 2022 or Build Tools 2022.
    exit /b 1
)
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do set "MSBUILD=%%i"
if not defined MSBUILD (
    echo [!] MSBuild.exe not found. Add the ".NET desktop build tools" workload in the Visual Studio Installer.
    exit /b 1
)

set "NUGET=%ROOT%.tools\nuget.exe"
if not exist "%NUGET%" (
    echo [+] Downloading nuget.exe
    if not exist "%ROOT%.tools" mkdir "%ROOT%.tools"
    powershell -NoProfile -ExecutionPolicy Bypass -Command "[Net.ServicePointManager]::SecurityProtocol = 'Tls12'; Invoke-WebRequest -UseBasicParsing https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile '%NUGET%'" || exit /b 1
)

echo [+] Restoring NuGet packages
"%NUGET%" restore "%ROOT%ActiveDirectoryDumper.sln" -NonInteractive -Verbosity quiet || exit /b 1

echo [+] Building %CONFIG%^|%PLATFORM% with "%MSBUILD%"
"%MSBUILD%" "%ROOT%ActiveDirectoryDumper.sln" /nologo /v:m /m /p:Configuration=%CONFIG% /p:Platform=%PLATFORM% || exit /b 1

echo [+] Done. Output: %ROOT%ActiveDirectoryDumper\bin\%PLATFORM%\%CONFIG%\ActiveDirectoryDumper.exe
endlocal
