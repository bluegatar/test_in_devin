@echo off
REM ============================================================================
REM  Build the eCapture Fiddler Classic extension (ECaptureFiddler.dll)
REM
REM  Needs ONE of (in order of preference):
REM    1. .NET SDK            -> "dotnet build"   (run: dotnet --list-sdks)
REM    2. Visual Studio /      -> "msbuild"        (Developer Command Prompt or
REM       Build Tools (MSBuild)                      auto-found via vswhere)
REM
REM  Plus: the .NET Framework 4.8 Developer Pack (targeting pack) and a local
REM  Fiddler Classic install (to reference Fiddler.exe).
REM
REM  Usage:
REM    build.bat                         (auto-detect Fiddler)
REM    build.bat "C:\Path\To\Fiddler"    (explicit Fiddler folder)
REM ============================================================================
setlocal EnableDelayedExpansion

set "FIDDLER_DIR=%~1"
if "%FIDDLER_DIR%"=="" if exist "%LOCALAPPDATA%\Programs\Fiddler\Fiddler.exe"    set "FIDDLER_DIR=%LOCALAPPDATA%\Programs\Fiddler"
if "%FIDDLER_DIR%"=="" if exist "%ProgramFiles%\Fiddler\Fiddler.exe"            set "FIDDLER_DIR=%ProgramFiles%\Fiddler"
if "%FIDDLER_DIR%"=="" if exist "%ProgramFiles(x86)%\Fiddler2\Fiddler.exe"      set "FIDDLER_DIR=%ProgramFiles(x86)%\Fiddler2"

REM strip a trailing backslash if present
if "%FIDDLER_DIR:~-1%"=="\" set "FIDDLER_DIR=%FIDDLER_DIR:~0,-1%"

if "%FIDDLER_DIR%"=="" (
  echo [ERROR] Could not find Fiddler.exe automatically.
  echo         Pass the Fiddler install folder, e.g.:
  echo             build.bat "C:\Users\you\AppData\Local\Programs\Fiddler"
  exit /b 1
)
if not exist "%FIDDLER_DIR%\Fiddler.exe" (
  echo [ERROR] Fiddler.exe not found in: %FIDDLER_DIR%
  exit /b 1
)
echo Using Fiddler at: %FIDDLER_DIR%
set "PROJ=%~dp0ECaptureFiddler.csproj"

REM ---- 1) .NET SDK? (the runtime alone is NOT enough; require an SDK) --------
set "HAS_SDK="
for /f "delims=" %%i in ('dotnet --list-sdks 2^>nul') do set "HAS_SDK=1"
if defined HAS_SDK (
  echo Building with dotnet SDK...
  dotnet build "%PROJ%" -c Release /p:FiddlerPath="%FIDDLER_DIR%"
  if errorlevel 1 goto :fail
  goto :ok
)
echo [info] No .NET SDK found ^(only the runtime, or none^). Trying MSBuild...

REM ---- 2) MSBuild via vswhere, then common paths ----------------------------
set "MSBUILD="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
  for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -prerelease -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe 2^>nul`) do set "MSBUILD=%%i"
)
if not defined MSBUILD where msbuild >nul 2>nul && set "MSBUILD=msbuild"

if defined MSBUILD (
  echo Building with MSBuild: !MSBUILD!
  "!MSBUILD!" "%PROJ%" /t:Restore;Build /p:Configuration=Release /p:FiddlerPath="%FIDDLER_DIR%"
  if errorlevel 1 goto :fail
  goto :ok
)

echo.
echo [ERROR] No build tool found. Install ONE of:
echo   * .NET SDK (easiest):  https://aka.ms/dotnet/download   then re-run build.bat
echo   * VS Build Tools:      https://aka.ms/vs/17/release/vs_BuildTools.exe
echo                          (select ".NET desktop build tools")
echo   Also install the ".NET Framework 4.8 Developer Pack" if the build later
echo   complains it cannot find reference assemblies for .NETFramework v4.8.
exit /b 1

:fail
echo.
echo [ERROR] Build failed. If the error mentions reference assemblies for
echo         .NETFramework,Version=v4.8 not found, install the
echo         ".NET Framework 4.8 Developer Pack":
echo             https://dotnet.microsoft.com/download/dotnet-framework/net48
exit /b 1

:ok
echo.
echo [OK] Build succeeded.
echo Output DLL: %~dp0bin\Release\ECaptureFiddler.dll
echo Copy it to: %%USERPROFILE%%\Documents\Fiddler2\Inspectors\
echo Then right-click the DLL -^> Properties -^> Unblock, and restart Fiddler.
endlocal
