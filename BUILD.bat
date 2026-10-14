@echo off
echo ===================================================
echo   OnyxEngine - Native Memory Suite Builder
echo ===================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Rust / Cargo not found in PATH!
    echo Please install Rust from https://rustup.rs/
    pause
    exit /b 1
)

echo [1/3] Compiling Release Binaries (Workspace)...
cargo build --release
if %errorlevel% neq 0 (
    echo [ERROR] Build failed!
    pause
    exit /b 1
)

echo.
echo [2/3] Preparing Output in bin\ ...
if not exist "bin" mkdir "bin"

if exist "target\release\OnyxEngine.exe" copy /y "target\release\OnyxEngine.exe" "bin\OnyxEngine.exe" >nul
if exist "target\release\allochook_dll.dll" copy /y "target\release\allochook_dll.dll" "bin\allochook_dll.dll" >nul
if exist "target\release\d3dhook_dll.dll" copy /y "target\release\d3dhook_dll.dll" "bin\d3dhook_dll.dll" >nul
if exist "target\release\luaclient_dll.dll" copy /y "target\release\luaclient_dll.dll" "bin\luaclient_dll.dll" >nul
if exist "target\release\speedhack_dll.dll" copy /y "target\release\speedhack_dll.dll" "bin\speedhack_dll.dll" >nul
if exist "target\release\vehdebug_dll.dll" copy /y "target\release\vehdebug_dll.dll" "bin\vehdebug_dll.dll" >nul
if exist "lua53-64.dll" copy /y "lua53-64.dll" "bin\lua53-64.dll" >nul

echo.
echo [3/3] Build Completed Successfully!
echo Binaries are located in: bin\
echo Executable: bin\OnyxEngine.exe
echo.
pause
