@echo off
setlocal
title OnyxEngine - Build Script (Backend and Classic Frontend)
echo ===================================================
echo   OnyxEngine (Cheat Engine 7.7)
echo   Unified Release Compiler
echo ===================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Rust and Cargo were not found in PATH!
    echo Please install Rust from: https://rustup.rs/
    pause
    exit /b 1
)

echo [*] Compiling OnyxEngine Backend DLL (Release mode - Optimized)...
cargo build --release -p onyx_backend -p onyx_scanner -p onyx_pointer -p onyx_disasm -p onyx_freezer -p speedhack_dll -p vehdebug_dll -p d3dhook_dll -p allochook_dll -p luaclient_dll -p taskmgr_cloak_dll -p onyx_dll_mapper -p onyx_aob_tool
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Backend compilation failed!
    pause
    exit /b 1
)

echo.
echo [*] Deploying backend libraries to bin and CE directories...
if not exist "bin" mkdir "bin"
if not exist "bin\modules\injections" mkdir "bin\modules\injections"
if not exist "bin\plugins" mkdir "bin\plugins"
if not exist "UI\bin\plugins" mkdir "UI\bin\plugins"

copy /y "target\release\onyx_backend.dll" "bin\onyx_backend.dll" >nul
copy /y "target\release\onyx_backend.dll" "UI\bin\onyx_backend.dll" >nul

copy /y "target\release\onyx_scanner.dll" "bin\onyx_scanner.dll" >nul
copy /y "target\release\onyx_pointer.dll" "bin\onyx_pointer.dll" >nul
copy /y "target\release\onyx_disasm.dll" "bin\onyx_disasm.dll" >nul
copy /y "target\release\onyx_freezer.dll" "bin\onyx_freezer.dll" >nul

copy /y "target\release\taskmgr_cloak.dll" "bin\taskmgr_cloak.dll" >nul
copy /y "target\release\taskmgr_cloak.dll" "bin\modules\injections\taskmgr_cloak.dll" >nul
copy /y "target\release\taskmgr_cloak.dll" "UI\bin\taskmgr_cloak.dll" >nul

copy /y "target\release\speedhack_dll.dll" "bin\modules\injections\speedhack_dll.dll" >nul
copy /y "target\release\vehdebug_dll.dll" "bin\modules\injections\vehdebug_dll.dll" >nul
copy /y "target\release\d3dhook_dll.dll" "bin\modules\injections\d3dhook_dll.dll" >nul
copy /y "target\release\allochook_dll.dll" "bin\modules\injections\allochook_dll.dll" >nul
copy /y "target\release\luaclient_dll.dll" "bin\modules\injections\luaclient_dll.dll" >nul

copy /y "target\release\onyx_dll_mapper.dll" "bin\plugins\onyx_dll_mapper.dll" >nul
copy /y "target\release\onyx_dll_mapper.dll" "UI\bin\plugins\onyx_dll_mapper.dll" >nul
copy /y "target\release\onyx_aob_tool.dll" "bin\plugins\onyx_aob_tool.dll" >nul
copy /y "target\release\onyx_aob_tool.dll" "UI\bin\plugins\onyx_aob_tool.dll" >nul

if exist "lua53-64.dll" (
    copy /y "lua53-64.dll" "bin\lua53-64.dll" >nul
)

echo.
echo ===================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo.
echo   Distribution Executable: bin\OnyxEngine-CE.exe
echo   Backend Engine DLL:      bin\onyx_backend.dll
echo ===================================================
echo.
pause
