@echo off
setlocal
title OnyxEngine - Build Script (Backend, Modules, Injections and Plugins)
echo ===================================================
echo   OnyxEngine (Cheat Engine 7.7)
echo   Unified Modular Release Compiler
echo ===================================================
echo.

where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Rust and Cargo were not found in PATH!
    echo Please install Rust from: https://rustup.rs/
    pause
    exit /b 1
)

echo [*] Compiling OnyxEngine Workspace DLLs (Release mode - Optimized)...
cargo build --release --workspace
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Workspace compilation failed!
    pause
    exit /b 1
)

echo.
echo [*] Deploying modular libraries to bin, modules, and plugins directories...
if not exist "bin" mkdir "bin"
if not exist "bin\modules" mkdir "bin\modules"
if not exist "bin\modules\injections" mkdir "bin\modules\injections"
if not exist "bin\plugins" mkdir "bin\plugins"
if not exist "UI\bin" mkdir "UI\bin"
if not exist "UI\bin\modules" mkdir "UI\bin\modules"
if not exist "UI\bin\modules\injections" mkdir "UI\bin\modules\injections"
if not exist "UI\bin\plugins" mkdir "UI\bin\plugins"

:: Core Engine DLLs
copy /y "target\release\onyx_backend.dll" "bin\onyx_backend.dll" >nul
copy /y "target\release\onyx_backend.dll" "UI\bin\onyx_backend.dll" >nul
copy /y "target\release\onyx_scanner.dll" "bin\onyx_scanner.dll" >nul
copy /y "target\release\onyx_pointer.dll" "bin\onyx_pointer.dll" >nul
copy /y "target\release\onyx_disasm.dll" "bin\onyx_disasm.dll" >nul
copy /y "target\release\onyx_freezer.dll" "bin\onyx_freezer.dll" >nul

:: Analysis & Runtime Modules
copy /y "target\release\onyx_aa.dll" "bin\modules\onyx_aa.dll" >nul
copy /y "target\release\onyx_mono.dll" "bin\modules\onyx_mono.dll" >nul
copy /y "target\release\onyx_mono_hook.dll" "bin\modules\onyx_mono_hook.dll" >nul
copy /y "target\release\onyx_dotnet.dll" "bin\modules\onyx_dotnet.dll" >nul
copy /y "target\release\onyx_gdb_server.dll" "bin\modules\onyx_gdb_server.dll" >nul
copy /y "target\release\onyx_overlay.dll" "bin\modules\onyx_overlay.dll" >nul
copy /y "target\release\onyx_hook.dll" "bin\modules\onyx_hook.dll" >nul

copy /y "target\release\onyx_aa.dll" "UI\bin\modules\onyx_aa.dll" >nul
copy /y "target\release\onyx_mono.dll" "UI\bin\modules\onyx_mono.dll" >nul
copy /y "target\release\onyx_mono_hook.dll" "UI\bin\modules\onyx_mono_hook.dll" >nul
copy /y "target\release\onyx_dotnet.dll" "UI\bin\modules\onyx_dotnet.dll" >nul
copy /y "target\release\onyx_gdb_server.dll" "UI\bin\modules\onyx_gdb_server.dll" >nul
copy /y "target\release\onyx_overlay.dll" "UI\bin\modules\onyx_overlay.dll" >nul
copy /y "target\release\onyx_hook.dll" "UI\bin\modules\onyx_hook.dll" >nul

:: Injectable Stealth & Hook DLLs
copy /y "target\release\onyx_shield.dll" "bin\modules\injections\onyx_shield.dll" >nul
copy /y "target\release\onyx_shield.dll" "UI\bin\modules\injections\onyx_shield.dll" >nul
copy /y "target\release\taskmgr_cloak.dll" "bin\taskmgr_cloak.dll" >nul
copy /y "target\release\taskmgr_cloak.dll" "bin\modules\injections\taskmgr_cloak.dll" >nul
copy /y "target\release\taskmgr_cloak.dll" "UI\bin\taskmgr_cloak.dll" >nul
copy /y "target\release\taskmgr_cloak.dll" "UI\bin\modules\injections\taskmgr_cloak.dll" >nul

copy /y "target\release\speedhack_dll.dll" "bin\modules\injections\speedhack_dll.dll" >nul
copy /y "target\release\speedhack_dll.dll" "UI\bin\modules\injections\speedhack_dll.dll" >nul
copy /y "target\release\vehdebug_dll.dll" "bin\modules\injections\vehdebug_dll.dll" >nul
copy /y "target\release\vehdebug_dll.dll" "UI\bin\modules\injections\vehdebug_dll.dll" >nul
copy /y "target\release\d3dhook_dll.dll" "bin\modules\injections\d3dhook_dll.dll" >nul
copy /y "target\release\d3dhook_dll.dll" "UI\bin\modules\injections\d3dhook_dll.dll" >nul
copy /y "target\release\allochook_dll.dll" "bin\modules\injections\allochook_dll.dll" >nul
copy /y "target\release\allochook_dll.dll" "UI\bin\modules\injections\allochook_dll.dll" >nul
copy /y "target\release\luaclient_dll.dll" "bin\modules\injections\luaclient_dll.dll" >nul
copy /y "target\release\luaclient_dll.dll" "UI\bin\modules\injections\luaclient_dll.dll" >nul
copy /y "target\release\callstack_spoof.dll" "bin\modules\injections\callstack_spoof.dll" >nul
copy /y "target\release\callstack_spoof.dll" "UI\bin\modules\injections\callstack_spoof.dll" >nul
copy /y "target\release\pe_strip.dll" "bin\modules\injections\pe_strip.dll" >nul
copy /y "target\release\pe_strip.dll" "UI\bin\modules\injections\pe_strip.dll" >nul
copy /y "target\release\syscalls_indirect.dll" "bin\modules\injections\syscalls_indirect.dll" >nul
copy /y "target\release\syscalls_indirect.dll" "UI\bin\modules\injections\syscalls_indirect.dll" >nul

:: Plugins
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
echo   Modules Deployed:        bin\modules\
echo   Injections Deployed:     bin\modules\injections\
echo   Plugins Deployed:        bin\plugins\
echo ===================================================
echo.
pause
