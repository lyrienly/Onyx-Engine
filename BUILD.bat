@echo off
setlocal enabledelayedexpansion
title OnyxEngine - Unified Build System (Rust Backend + Pascal Frontend)
echo ===================================================================
echo   OnyxEngine: Unified Build Pipeline
echo   Rust Modular Workspace + Pascal / Lazarus Frontend
echo ===================================================================
echo.

:: 1. Verify Rust / Cargo
where cargo >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Cargo was not found in PATH!
    echo Please ensure Rust is installed and in your environment PATH.
    pause
    exit /b 1
)

:: 2. Verify Lazarus / lazbuild
set LAZBUILD_EXE=lazbuild
where lazbuild >nul 2>nul
if %errorlevel% neq 0 (
    if exist "C:\lazarus\lazbuild.exe" (
        set LAZBUILD_EXE=C:\lazarus\lazbuild.exe
    ) else (
        echo [ERROR] lazbuild was not found in PATH or at C:\lazarus\lazbuild.exe.
        pause
        exit /b 1
    )
)

:: 3. Compile Rust Workspace (Release Mode)
echo [*] Step 1/3: Compiling Rust Workspace (Release Mode)...
cargo build --release --workspace
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Rust workspace compilation failed!
    pause
    exit /b 1
)
echo [OK] Rust modular libraries compiled successfully.
echo.

:: 4. Deploy Modular Binaries and Libraries
echo [*] Step 2/3: Deploying native libraries and plugins...
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
copy /y "target\release\onyx_backend.dll" "UI\bin\modules\onyx_backend.dll" >nul

copy /y "target\release\onyx_scanner.dll" "bin\onyx_scanner.dll" >nul
copy /y "target\release\onyx_scanner.dll" "UI\bin\onyx_scanner.dll" >nul
copy /y "target\release\onyx_scanner.dll" "UI\bin\modules\onyx_scanner.dll" >nul

copy /y "target\release\onyx_pointer.dll" "bin\onyx_pointer.dll" >nul
copy /y "target\release\onyx_pointer.dll" "UI\bin\onyx_pointer.dll" >nul
copy /y "target\release\onyx_pointer.dll" "UI\bin\modules\onyx_pointer.dll" >nul

copy /y "target\release\onyx_disasm.dll" "bin\onyx_disasm.dll" >nul
copy /y "target\release\onyx_disasm.dll" "UI\bin\onyx_disasm.dll" >nul
copy /y "target\release\onyx_disasm.dll" "UI\bin\modules\onyx_disasm.dll" >nul

copy /y "target\release\onyx_freezer.dll" "bin\onyx_freezer.dll" >nul
copy /y "target\release\onyx_freezer.dll" "UI\bin\onyx_freezer.dll" >nul
copy /y "target\release\onyx_freezer.dll" "UI\bin\modules\onyx_freezer.dll" >nul

:: Modules
copy /y "target\release\onyx_aa.dll" "bin\modules\onyx_aa.dll" >nul
copy /y "target\release\onyx_aa.dll" "UI\bin\modules\onyx_aa.dll" >nul
copy /y "target\release\onyx_mono.dll" "bin\modules\onyx_mono.dll" >nul
copy /y "target\release\onyx_mono.dll" "UI\bin\modules\onyx_mono.dll" >nul
copy /y "target\release\onyx_mono_hook.dll" "bin\modules\onyx_mono_hook.dll" >nul
copy /y "target\release\onyx_mono_hook.dll" "UI\bin\modules\onyx_mono_hook.dll" >nul
copy /y "target\release\onyx_dotnet.dll" "bin\modules\onyx_dotnet.dll" >nul
copy /y "target\release\onyx_dotnet.dll" "UI\bin\modules\onyx_dotnet.dll" >nul
copy /y "target\release\onyx_gdb_server.dll" "bin\modules\onyx_gdb_server.dll" >nul
copy /y "target\release\onyx_gdb_server.dll" "UI\bin\modules\onyx_gdb_server.dll" >nul
copy /y "target\release\onyx_overlay.dll" "bin\modules\onyx_overlay.dll" >nul
copy /y "target\release\onyx_overlay.dll" "UI\bin\modules\onyx_overlay.dll" >nul
copy /y "target\release\onyx_hook.dll" "bin\modules\onyx_hook.dll" >nul
copy /y "target\release\onyx_hook.dll" "UI\bin\modules\onyx_hook.dll" >nul

:: Injections & Stealth
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

:: MCP Native Bridge
copy /y "target\release\onyx_mcp.dll" "bin\onyx_mcp.dll" >nul
copy /y "target\release\onyx_mcp.dll" "bin\modules\onyx_mcp.dll" >nul
copy /y "target\release\onyx_mcp.dll" "UI\bin\onyx_mcp.dll" >nul
copy /y "target\release\onyx_mcp.dll" "UI\bin\modules\onyx_mcp.dll" >nul
if exist "target\release\onyx_mcp_server.exe" (
    copy /y "target\release\onyx_mcp_server.exe" "bin\onyx_mcp_server.exe" >nul
    copy /y "target\release\onyx_mcp_server.exe" "UI\bin\onyx_mcp_server.exe" >nul
)

:: Plugins
copy /y "target\release\onyx_dll_mapper.dll" "bin\plugins\onyx_dll_mapper.dll" >nul
copy /y "target\release\onyx_dll_mapper.dll" "UI\bin\plugins\onyx_dll_mapper.dll" >nul
copy /y "target\release\onyx_aob_tool.dll" "bin\plugins\onyx_aob_tool.dll" >nul
copy /y "target\release\onyx_aob_tool.dll" "UI\bin\plugins\onyx_aob_tool.dll" >nul

if exist "lua53-64.dll" (
    copy /y "lua53-64.dll" "bin\lua53-64.dll" >nul
    copy /y "lua53-64.dll" "UI\bin\lua53-64.dll" >nul
)
echo [OK] Libraries and modular plugins deployed.
echo.

:: 5. Compile Pascal / Lazarus Frontend
echo [*] Step 3/3: Compiling Pascal/Lazarus Frontend (Release 64-Bit)...
"%LAZBUILD_EXE%" -B --build-mode="Release 64-Bit" "UI\onyxengine.lpi"
if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Pascal frontend compilation failed!
    pause
    exit /b 1
)

:: Synchronize distribution executables
if exist "UI\bin\OnyxEngine-x86_64.exe" (
    copy /y "UI\bin\OnyxEngine-x86_64.exe" "bin\OnyxEngine-CE.exe" >nul
    copy /y "UI\bin\OnyxEngine-x86_64.exe" "UI\bin\OnyxEngine-CE.exe" >nul
)

echo [OK] OnyxEngine-CE.exe generated and synchronized.
echo.
echo ===================================================================
echo   BUILD COMPLETED SUCCESSFULLY!
echo.
echo   Distribution Executable: bin\OnyxEngine-CE.exe
echo   Backend Engine DLL:      bin\onyx_backend.dll
echo   Modular Libraries:       bin\modules\
echo   Stealth Injections:      bin\modules\injections\
echo   Plugins Deployed:        bin\plugins\
echo ===================================================================
echo.
