@echo off
setlocal
title OnyxEngine - Build Script
echo ===================================================
echo   OnyxEngine (Cheat Engine 7.7 in Rust)
echo   Standalone Release Compiler
echo ===================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Rust and Cargo were not found in PATH!
    echo Please install Rust from: https://rustup.rs/
    echo Make sure to restart your terminal after installing.
    echo.
    pause
    exit /b 1
)

echo [*] Compiling OnyxEngine (Release mode - Optimized)...
cargo build --release --bin OnyxEngine
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Build failed! Check the compiler output above.
    pause
    exit /b 1
)

echo.
echo [*] Deploying executable and runtime libraries...
if not exist "bin" mkdir "bin"

if exist "target\release\OnyxEngine.exe" (
    copy /y "target\release\OnyxEngine.exe" "bin\OnyxEngine.exe" >nul
) else (
    echo [ERROR] target\release\OnyxEngine.exe was not found!
    pause
    exit /b 1
)

if exist "lua53-64.dll" (
    copy /y "lua53-64.dll" "bin\lua53-64.dll" >nul
)

echo.
echo ===================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo.
echo   Output Executable: bin\OnyxEngine.exe
echo   Runtime DLL:       bin\lua53-64.dll
echo ===================================================
echo.
pause
