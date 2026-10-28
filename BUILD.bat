@echo off
setlocal
title OnyxEngine - Unified Build System (Rust Backend + Pascal Frontend)
echo ===================================================================
echo   OnyxEngine: Rust Backend (DLL) + Pascal/Lazarus Frontend
echo ===================================================================
echo.

:: 1. Check Rust / Cargo
where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Rust and Cargo were not found in PATH!
    echo Please install Rust from: https://rustup.rs/
    pause
    exit /b 1
)

:: 2. Compile Rust Backend DLL (onyx_backend.dll)
echo [*] Step 1/3: Compiling Rust Backend DLL (onyx_backend.dll)...
cargo build --release -p onyx_backend
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Rust Backend compilation failed!
    pause
    exit /b 1
)

if not exist "bin" mkdir "bin"
copy /y "target\release\onyx_backend.dll" "bin\onyx_backend.dll" >nul
copy /y "target\release\onyx_backend.dll" "UI\bin\onyx_backend.dll" >nul
echo [OK] onyx_backend.dll generated and deployed.
echo.

:: 3. Check Lazarus / lazbuild
set LAZBUILD_EXE=lazbuild
where lazbuild >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\lazarus\lazbuild.exe" (
        set LAZBUILD_EXE=C:\lazarus\lazbuild.exe
    ) else (
        echo [WARNING] lazbuild was not found in PATH or C:\lazarus.
        echo Skipping Pascal frontend build.
        goto finish
    )
)

:: 4. Compile Pascal Frontend (Cheat Engine)
echo [*] Step 2/3: Compiling Pascal/Lazarus Frontend with OnyxBackend bridge...
"%LAZBUILD_EXE%" --build-mode="Release 64-Bit" "UI\cheatengine.lpi"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Pascal frontend compilation failed!
    pause
    exit /b 1
)
echo [OK] OnyxEngine-x86_64.exe compiled successfully.
echo.

:: 5. Copy release artifacts to bin\
echo [*] Step 3/3: Synchronizing distribution bin directory...
if exist "UI\bin\OnyxEngine-x86_64.exe" (
    copy /y "UI\bin\OnyxEngine-x86_64.exe" "bin\OnyxEngine-CE.exe" >nul
)
if exist "UI\bin\cheatengine-x86_64.exe" (
    copy /y "UI\bin\cheatengine-x86_64.exe" "bin\OnyxEngine-CE.exe" >nul
)
if exist "UI\bin\lua53-64.dll" (
    copy /y "UI\bin\lua53-64.dll" "bin\lua53-64.dll" >nul
)
if exist "UI\bin\*.dll" (
    copy /y "UI\bin\*.dll" "bin\" >nul
)

:finish
echo.
echo ===================================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo.
echo   [Backend]  bin\onyx_backend.dll (Rust C-ABI high performance)
echo   [Frontend] bin\OnyxEngine-CE.exe (Pascal / Lazarus UI)
echo ===================================================================
echo.
pause
