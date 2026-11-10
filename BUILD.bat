@echo off
setlocal enabledelayedexpansion
title OnyxEngine - Unified Build System [x64 + x86 Release Pipeline]
echo ===================================================================
echo   OnyxEngine: Unified Multi-Arch Build Pipeline
echo   Rust Modular Workspace + Pascal / Lazarus Frontend
echo   Targets: x86_64 [64-Bit] and i686 [32-Bit / x86]
echo ===================================================================
echo.

set BUILD_TARGET=%1
if "%BUILD_TARGET%"=="" set BUILD_TARGET=all

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

:: Create base output directories
if not exist "bin" mkdir "bin"
if not exist "bin\modules" mkdir "bin\modules"
if not exist "bin\modules\injections" mkdir "bin\modules\injections"
if not exist "bin\plugins" mkdir "bin\plugins"
if not exist "UI\bin" mkdir "UI\bin"
if not exist "UI\bin\modules" mkdir "UI\bin\modules"
if not exist "UI\bin\modules\injections" mkdir "UI\bin\modules\injections"
if not exist "UI\bin\plugins" mkdir "UI\bin\plugins"

:: Determine architectures to build
set BUILD_X64=0
set BUILD_X86=0

if /i "%BUILD_TARGET%"=="all" (
    set BUILD_X64=1
    set BUILD_X86=1
)
if /i "%BUILD_TARGET%"=="release" (
    set BUILD_X64=1
    set BUILD_X86=1
)
if /i "%BUILD_TARGET%"=="x64" (
    set BUILD_X64=1
)
if /i "%BUILD_TARGET%"=="64" (
    set BUILD_X64=1
)
if /i "%BUILD_TARGET%"=="x86" (
    set BUILD_X86=1
)
if /i "%BUILD_TARGET%"=="32" (
    set BUILD_X86=1
)
if /i "%BUILD_TARGET%"=="i686" (
    set BUILD_X86=1
)

:: -------------------------------------------------------------------
:: 3. BUILD 64-BIT [x86_64]
:: -------------------------------------------------------------------
if %BUILD_X64% equ 1 (
    echo [*] Step 1: Compiling Rust Workspace [x86_64 Release Mode]...
    cargo build --release --workspace --target x86_64-pc-windows-msvc
    if !errorlevel! neq 0 (
        echo [ERROR] Rust x86_64 workspace compilation failed!
        pause
        exit /b 1
    )
    echo [OK] Rust x86_64 modular libraries compiled.
    echo.

    echo [*] Step 2: Compiling Pascal/Lazarus Frontend [Release 64-Bit]...
    "%LAZBUILD_EXE%" -B --build-mode="Release 64-Bit" "UI\onyxengine.lpi"
    if !errorlevel! neq 0 (
        echo [ERROR] Pascal 64-bit compilation failed!
        pause
        exit /b 1
    )
    echo [OK] Pascal 64-Bit frontend compiled successfully.
    echo.

    echo [*] Deploying x86_64 Binaries...
    set RUST_X64=target\x86_64-pc-windows-msvc\release

    copy /y "!RUST_X64!\onyx_backend.dll" "bin\onyx_backend.dll" >nul
    copy /y "!RUST_X64!\onyx_backend.dll" "UI\bin\onyx_backend.dll" >nul
    copy /y "!RUST_X64!\onyx_backend.dll" "UI\bin\modules\onyx_backend.dll" >nul

    copy /y "!RUST_X64!\onyx_scanner.dll" "bin\onyx_scanner.dll" >nul
    copy /y "!RUST_X64!\onyx_scanner.dll" "UI\bin\onyx_scanner.dll" >nul
    copy /y "!RUST_X64!\onyx_scanner.dll" "UI\bin\modules\onyx_scanner.dll" >nul

    copy /y "!RUST_X64!\onyx_pointer.dll" "bin\onyx_pointer.dll" >nul
    copy /y "!RUST_X64!\onyx_pointer.dll" "UI\bin\onyx_pointer.dll" >nul
    copy /y "!RUST_X64!\onyx_pointer.dll" "UI\bin\modules\onyx_pointer.dll" >nul

    copy /y "!RUST_X64!\onyx_disasm.dll" "bin\onyx_disasm.dll" >nul
    copy /y "!RUST_X64!\onyx_disasm.dll" "UI\bin\onyx_disasm.dll" >nul
    copy /y "!RUST_X64!\onyx_disasm.dll" "UI\bin\modules\onyx_disasm.dll" >nul

    copy /y "!RUST_X64!\onyx_freezer.dll" "bin\onyx_freezer.dll" >nul
    copy /y "!RUST_X64!\onyx_freezer.dll" "UI\bin\onyx_freezer.dll" >nul
    copy /y "!RUST_X64!\onyx_freezer.dll" "UI\bin\modules\onyx_freezer.dll" >nul

    copy /y "!RUST_X64!\onyx_aa.dll" "bin\modules\onyx_aa.dll" >nul
    copy /y "!RUST_X64!\onyx_aa.dll" "UI\bin\modules\onyx_aa.dll" >nul
    copy /y "!RUST_X64!\onyx_mono.dll" "bin\modules\onyx_mono.dll" >nul
    copy /y "!RUST_X64!\onyx_mono.dll" "UI\bin\modules\onyx_mono.dll" >nul
    copy /y "!RUST_X64!\onyx_mono_hook.dll" "bin\modules\onyx_mono_hook.dll" >nul
    copy /y "!RUST_X64!\onyx_mono_hook.dll" "UI\bin\modules\onyx_mono_hook.dll" >nul
    copy /y "!RUST_X64!\onyx_dotnet.dll" "bin\modules\onyx_dotnet.dll" >nul
    copy /y "!RUST_X64!\onyx_dotnet.dll" "UI\bin\modules\onyx_dotnet.dll" >nul
    copy /y "!RUST_X64!\onyx_gdb_server.dll" "bin\modules\onyx_gdb_server.dll" >nul
    copy /y "!RUST_X64!\onyx_gdb_server.dll" "UI\bin\modules\onyx_gdb_server.dll" >nul
    copy /y "!RUST_X64!\onyx_overlay.dll" "bin\modules\onyx_overlay.dll" >nul
    copy /y "!RUST_X64!\onyx_overlay.dll" "UI\bin\modules\onyx_overlay.dll" >nul
    copy /y "!RUST_X64!\onyx_hook.dll" "bin\modules\onyx_hook.dll" >nul
    copy /y "!RUST_X64!\onyx_hook.dll" "UI\bin\modules\onyx_hook.dll" >nul

    copy /y "!RUST_X64!\onyx_shield.dll" "bin\modules\injections\onyx_shield.dll" >nul
    copy /y "!RUST_X64!\onyx_shield.dll" "UI\bin\modules\injections\onyx_shield.dll" >nul
    copy /y "!RUST_X64!\taskmgr_cloak.dll" "bin\taskmgr_cloak.dll" >nul
    copy /y "!RUST_X64!\taskmgr_cloak.dll" "bin\modules\injections\taskmgr_cloak.dll" >nul
    copy /y "!RUST_X64!\taskmgr_cloak.dll" "UI\bin\taskmgr_cloak.dll" >nul
    copy /y "!RUST_X64!\taskmgr_cloak.dll" "UI\bin\modules\injections\taskmgr_cloak.dll" >nul

    copy /y "!RUST_X64!\speedhack_dll.dll" "bin\modules\injections\speedhack_dll.dll" >nul
    copy /y "!RUST_X64!\speedhack_dll.dll" "UI\bin\modules\injections\speedhack_dll.dll" >nul
    copy /y "!RUST_X64!\vehdebug_dll.dll" "bin\modules\injections\vehdebug_dll.dll" >nul
    copy /y "!RUST_X64!\vehdebug_dll.dll" "UI\bin\modules\injections\vehdebug_dll.dll" >nul
    copy /y "!RUST_X64!\d3dhook_dll.dll" "bin\modules\injections\d3dhook_dll.dll" >nul
    copy /y "!RUST_X64!\d3dhook_dll.dll" "UI\bin\modules\injections\d3dhook_dll.dll" >nul
    copy /y "!RUST_X64!\allochook_dll.dll" "bin\modules\injections\allochook_dll.dll" >nul
    copy /y "!RUST_X64!\allochook_dll.dll" "UI\bin\modules\injections\allochook_dll.dll" >nul
    copy /y "!RUST_X64!\luaclient_dll.dll" "bin\modules\injections\luaclient_dll.dll" >nul
    copy /y "!RUST_X64!\luaclient_dll.dll" "UI\bin\modules\injections\luaclient_dll.dll" >nul
    copy /y "!RUST_X64!\callstack_spoof.dll" "bin\modules\injections\callstack_spoof.dll" >nul
    copy /y "!RUST_X64!\callstack_spoof.dll" "UI\bin\modules\injections\callstack_spoof.dll" >nul
    copy /y "!RUST_X64!\pe_strip.dll" "bin\modules\injections\pe_strip.dll" >nul
    copy /y "!RUST_X64!\pe_strip.dll" "UI\bin\modules\injections\pe_strip.dll" >nul
    copy /y "!RUST_X64!\syscalls_indirect.dll" "bin\modules\injections\syscalls_indirect.dll" >nul
    copy /y "!RUST_X64!\syscalls_indirect.dll" "UI\bin\modules\injections\syscalls_indirect.dll" >nul

    copy /y "!RUST_X64!\onyx_mcp.dll" "bin\onyx_mcp.dll" >nul
    copy /y "!RUST_X64!\onyx_mcp.dll" "bin\modules\onyx_mcp.dll" >nul
    copy /y "!RUST_X64!\onyx_mcp.dll" "UI\bin\onyx_mcp.dll" >nul
    copy /y "!RUST_X64!\onyx_mcp.dll" "UI\bin\modules\onyx_mcp.dll" >nul
    if exist "!RUST_X64!\onyx_mcp_server.exe" (
        copy /y "!RUST_X64!\onyx_mcp_server.exe" "bin\onyx_mcp_server.exe" >nul
        copy /y "!RUST_X64!\onyx_mcp_server.exe" "UI\bin\onyx_mcp_server.exe" >nul
    )

    copy /y "!RUST_X64!\onyx_dll_mapper.dll" "bin\plugins\onyx_dll_mapper.dll" >nul
    copy /y "!RUST_X64!\onyx_dll_mapper.dll" "UI\bin\plugins\onyx_dll_mapper.dll" >nul
    copy /y "!RUST_X64!\onyx_aob_tool.dll" "bin\plugins\onyx_aob_tool.dll" >nul
    copy /y "!RUST_X64!\onyx_aob_tool.dll" "UI\bin\plugins\onyx_aob_tool.dll" >nul

    if exist "!RUST_X64!\OnyxEngine.exe" (
        copy /y "!RUST_X64!\OnyxEngine.exe" "bin\OnyxEngine-Rust.exe" >nul
        copy /y "!RUST_X64!\OnyxEngine.exe" "UI\bin\OnyxEngine-Rust.exe" >nul
    )

    if exist "UI\bin\OnyxEngine-x86_64.exe" (
        copy /y "UI\bin\OnyxEngine-x86_64.exe" "bin\OnyxEngine-CE.exe" >nul
        copy /y "UI\bin\OnyxEngine-x86_64.exe" "bin\OnyxEngine-x86_64.exe" >nul
        copy /y "UI\bin\OnyxEngine-x86_64.exe" "UI\bin\OnyxEngine-CE.exe" >nul
    )
)

:: -------------------------------------------------------------------
:: 4. BUILD 32-BIT [x86 / i686]
:: -------------------------------------------------------------------
if %BUILD_X86% equ 1 (
    echo [*] Step 3: Compiling Rust Workspace [i686 / x86 Release Mode]...
    cargo build --release --workspace --target i686-pc-windows-msvc
    if !errorlevel! neq 0 (
        echo [ERROR] Rust i686 workspace compilation failed!
        pause
        exit /b 1
    )
    echo [OK] Rust i686 modular libraries compiled.
    echo.

    echo [*] Step 4: Compiling Pascal/Lazarus Frontend [Release 32-Bit]...
    "%LAZBUILD_EXE%" -B --build-mode="Release 32-Bit" "UI\onyxengine.lpi"
    if !errorlevel! neq 0 (
        echo [ERROR] Pascal 32-bit compilation failed!
        pause
        exit /b 1
    )
    echo [OK] Pascal 32-Bit frontend compiled successfully.
    echo.

    if not exist "bin\win32_bins" mkdir "bin\win32_bins"
    set RUST_X86=target\i686-pc-windows-msvc\release
    copy /y "!RUST_X86!\*.dll" "bin\win32_bins\" >nul 2>nul
    copy /y "!RUST_X86!\*.exe" "bin\win32_bins\" >nul 2>nul
    if exist "UI\bin\OnyxEngine-i386.exe" (
        copy /y "UI\bin\OnyxEngine-i386.exe" "bin\OnyxEngine-i386.exe" >nul
        copy /y "UI\bin\OnyxEngine-i386.exe" "bin\win32_bins\OnyxEngine-i386.exe" >nul
    )
)

:: Sync runtime vendors to bin/
if exist "UI\bin\lua53-64.dll" copy /y "UI\bin\lua53-64.dll" "bin\lua53-64.dll" >nul
if exist "UI\bin\lua53-32.dll" copy /y "UI\bin\lua53-32.dll" "bin\lua53-32.dll" >nul
if exist "UI\bin\clibs64" (
    if not exist "bin\clibs64" mkdir "bin\clibs64"
    copy /y "UI\bin\clibs64\*" "bin\clibs64\" >nul
    if exist "UI\bin\clibs64\lfs.dll" (
        copy /y "UI\bin\clibs64\lfs.dll" "bin\lfs.dll" >nul
        copy /y "UI\bin\clibs64\lfs.dll" "bin\lfs53.dll" >nul
    )
)
if exist "UI\bin\clibs32" (
    if not exist "bin\clibs32" mkdir "bin\clibs32"
    copy /y "UI\bin\clibs32\*" "bin\clibs32\" >nul
)
if exist "UI\bin\win64" (
    if not exist "bin\win64" mkdir "bin\win64"
    copy /y "UI\bin\win64\*" "bin\win64\" >nul
)
if exist "UI\bin\win32" (
    if not exist "bin\win32" mkdir "bin\win32"
    copy /y "UI\bin\win32\*" "bin\win32\" >nul
)
if exist "driver\bin\Release\OnyxDriver.sys" copy /y "driver\bin\Release\OnyxDriver.sys" "bin\OnyxDriver.sys" >nul

:: -------------------------------------------------------------------
:: 5. PACKAGE RELEASES
:: -------------------------------------------------------------------
if /i "%BUILD_TARGET%"=="all" (
    echo [*] Step 5: Packaging official Release zip archives...
    powershell -NoProfile -ExecutionPolicy Bypass -File .\package_release.ps1
)
if /i "%BUILD_TARGET%"=="release" (
    echo [*] Step 5: Packaging official Release zip archives...
    powershell -NoProfile -ExecutionPolicy Bypass -File .\package_release.ps1
)

echo.
echo ===================================================================
echo   BUILD AND PACKAGING COMPLETED SUCCESSFULLY!
echo.
if %BUILD_X64% equ 1 echo   [x64] Distribution: bin\OnyxEngine-CE.exe
if %BUILD_X86% equ 1 echo   [x86] Distribution: bin\OnyxEngine-i386.exe
if exist "release\OnyxEngine-v1.0.0-win64.zip" echo   [Release 64-Bit]: release\OnyxEngine-v1.0.0-win64.zip
if exist "release\OnyxEngine-v1.0.0-win32.zip" echo   [Release 32-Bit]: release\OnyxEngine-v1.0.0-win32.zip
echo ===================================================================
echo.
