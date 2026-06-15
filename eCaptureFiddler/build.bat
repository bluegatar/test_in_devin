@echo off
REM ============================================================================
REM  Build the eCapture Fiddler Classic extension (ECaptureFiddler.dll)
REM
REM  Requirements (on Windows):
REM    - Fiddler Classic installed
REM    - .NET SDK (dotnet) OR Visual Studio Build Tools with MSBuild
REM    - .NET Framework 4.8 Developer Pack
REM
REM  Usage:
REM    build.bat                         (auto-detect Fiddler)
REM    build.bat "C:\Path\To\Fiddler"    (explicit Fiddler folder)
REM ============================================================================
setlocal

set "FIDDLER_DIR=%~1"

if "%FIDDLER_DIR%"=="" (
  if exist "%LOCALAPPDATA%\Programs\Fiddler\Fiddler.exe" set "FIDDLER_DIR=%LOCALAPPDATA%\Programs\Fiddler"
)
if "%FIDDLER_DIR%"=="" (
  if exist "%ProgramFiles%\Fiddler\Fiddler.exe" set "FIDDLER_DIR=%ProgramFiles%\Fiddler"
)
if "%FIDDLER_DIR%"=="" (
  if exist "%ProgramFiles(x86)%\Fiddler2\Fiddler.exe" set "FIDDLER_DIR=%ProgramFiles(x86)%\Fiddler2"
)

if "%FIDDLER_DIR%"=="" (
  echo [ERROR] Could not find Fiddler.exe automatically.
  echo         Pass the Fiddler install folder, e.g.:
  echo             build.bat "C:\Users\you\AppData\Local\Programs\Fiddler"
  exit /b 1
)

echo Using Fiddler at: %FIDDLER_DIR%

where dotnet >nul 2>nul
if %ERRORLEVEL%==0 (
  echo Building with dotnet...
  dotnet build "%~dp0ECaptureFiddler.csproj" -c Release /p:FiddlerPath="%FIDDLER_DIR%"
  goto :done
)

where msbuild >nul 2>nul
if %ERRORLEVEL%==0 (
  echo Building with msbuild...
  msbuild "%~dp0ECaptureFiddler.csproj" /t:Restore,Build /p:Configuration=Release /p:FiddlerPath="%FIDDLER_DIR%"
  goto :done
)

echo [ERROR] Neither dotnet nor msbuild found on PATH.
echo         Install the .NET SDK or open a "Developer Command Prompt for VS".
exit /b 1

:done
echo.
echo Output DLL: %~dp0bin\Release\ECaptureFiddler.dll
echo Copy it to:  %%USERPROFILE%%\Documents\Fiddler2\Inspectors\
endlocal
