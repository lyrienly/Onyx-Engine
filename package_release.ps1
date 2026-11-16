param(
    [string]$Version = "1.0.0"
)

$ErrorActionPreference = "Stop"
$RootDir = $PSScriptRoot
Set-Location $RootDir

$ReleaseDir = Join-Path $RootDir "release"
if (-not (Test-Path $ReleaseDir)) {
    New-Item -ItemType Directory -Path $ReleaseDir | Out-Null
}

function Build-Package {
    param(
        [string]$Arch,           # "win32" or "win64"
        [string]$TargetTriple,   # "i686-pc-windows-msvc" or "x86_64-pc-windows-msvc"
        [string]$ExeName         # "OnyxEngine-i386.exe" or "OnyxEngine-x86_64.exe"
    )

    $PkgName = "OnyxEngine-v$Version-$Arch"
    $PkgDir = Join-Path $ReleaseDir $PkgName
    if (Test-Path $PkgDir) {
        Remove-Item -Recurse -Force $PkgDir
    }

    Write-Host "===================================================" -ForegroundColor Cyan
    Write-Host " Assembling Release Package: $PkgName" -ForegroundColor Cyan
    Write-Host "===================================================" -ForegroundColor Cyan

    New-Item -ItemType Directory -Path (Join-Path $PkgDir "modules\injections") -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $PkgDir "plugins") -Force | Out-Null

    # 1. Main Executables (Pascal / Lazarus Native UI)
    $LazarusExe = Join-Path $RootDir "UI\bin\$ExeName"
    if (Test-Path $LazarusExe) {
        Copy-Item -Path $LazarusExe -Destination (Join-Path $PkgDir "OnyxEngine-CE.exe") -Force
        Copy-Item -Path $LazarusExe -Destination (Join-Path $PkgDir $ExeName) -Force
    } else {
        Write-Warning "Lazarus binary not found at $LazarusExe"
    }

    # 2. Core Rust Engine DLLs
    $RustOut = Join-Path $RootDir "target\$TargetTriple\release"
    $CoreDlls = @("onyx_backend.dll", "onyx_scanner.dll", "onyx_pointer.dll", "onyx_disasm.dll", "onyx_freezer.dll", "onyx_mcp.dll")
    foreach ($dll in $CoreDlls) {
        $p = Join-Path $RustOut $dll
        if (Test-Path $p) {
            Copy-Item -Path $p -Destination (Join-Path $PkgDir $dll) -Force
            Copy-Item -Path $p -Destination (Join-Path $PkgDir "modules\$dll") -Force
        }
    }

    $McpExe = Join-Path $RustOut "onyx_mcp_server.exe"
    if (Test-Path $McpExe) {
        Copy-Item -Path $McpExe -Destination (Join-Path $PkgDir "onyx_mcp_server.exe") -Force
    }

    # 3. Modules
    $Modules = @("onyx_aa.dll", "onyx_mono.dll", "onyx_mono_hook.dll", "onyx_dotnet.dll", "onyx_gdb_server.dll", "onyx_overlay.dll", "onyx_hook.dll")
    foreach ($m in $Modules) {
        $p = Join-Path $RustOut $m
        if (Test-Path $p) {
            Copy-Item -Path $p -Destination (Join-Path $PkgDir "modules\$m") -Force
        }
    }

    # 4. Injections & Stealth
    $Injections = @("onyx_shield.dll", "taskmgr_cloak.dll", "speedhack_dll.dll", "vehdebug_dll.dll", "d3dhook_dll.dll", "allochook_dll.dll", "luaclient_dll.dll", "callstack_spoof.dll", "pe_strip.dll", "syscalls_indirect.dll")
    foreach ($inj in $Injections) {
        $p = Join-Path $RustOut $inj
        if (Test-Path $p) {
            Copy-Item -Path $p -Destination (Join-Path $PkgDir "modules\injections\$inj") -Force
            if ($inj -eq "taskmgr_cloak.dll") {
                Copy-Item -Path $p -Destination (Join-Path $PkgDir "taskmgr_cloak.dll") -Force
            }
        }
    }

    # 5. Plugins
    $Plugins = @("onyx_dll_mapper.dll", "onyx_aob_tool.dll")
    foreach ($plg in $Plugins) {
        $p = Join-Path $RustOut $plg
        if (Test-Path $p) {
            Copy-Item -Path $p -Destination (Join-Path $PkgDir "plugins\$plg") -Force
        }
    }

    # 6. Copy Shared Assets from UI\bin
    $UiBin = Join-Path $RootDir "UI\bin"
    $CommonDirs = @("autorun", "languages", "lua_extra", "include")
    foreach ($d in $CommonDirs) {
        $src = Join-Path $UiBin $d
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $PkgDir $d) -Recurse -Force
        }
    }

    $RootLua = Join-Path $RootDir "lua"
    if (Test-Path $RootLua) {
        Copy-Item -Path $RootLua -Destination (Join-Path $PkgDir "lua") -Recurse -Force
    }

    # Architecture-specific runtimes and hooks
    if ($Arch -eq "win32") {
        if (Test-Path (Join-Path $UiBin "lua53-32.dll")) {
            Copy-Item -Path (Join-Path $UiBin "lua53-32.dll") -Destination (Join-Path $PkgDir "lua53-32.dll") -Force
            Copy-Item -Path (Join-Path $UiBin "lua53-32.dll") -Destination (Join-Path $PkgDir "lua53.dll") -Force
        }
        if (Test-Path (Join-Path $UiBin "clibs32")) {
            Copy-Item -Path (Join-Path $UiBin "clibs32") -Destination (Join-Path $PkgDir "clibs32") -Recurse -Force
            if (Test-Path (Join-Path $UiBin "clibs32\lfs.dll")) {
                Copy-Item -Path (Join-Path $UiBin "clibs32\lfs.dll") -Destination (Join-Path $PkgDir "lfs.dll") -Force
                Copy-Item -Path (Join-Path $UiBin "clibs32\lfs.dll") -Destination (Join-Path $PkgDir "lfs53.dll") -Force
            }
        }
        if (Test-Path (Join-Path $UiBin "win32")) {
            Copy-Item -Path (Join-Path $UiBin "win32") -Destination (Join-Path $PkgDir "win32") -Recurse -Force
        }
        $ArchFiles = @("CED3D10Hook.dll", "CED3D11Hook.dll", "ced3d9hook.dll", "d3dhook.dll", "libipt-32.dll", "libmikmod32.dll")
        foreach ($af in $ArchFiles) {
            $src = Join-Path $UiBin $af
            if (Test-Path $src) {
                Copy-Item -Path $src -Destination (Join-Path $PkgDir $af) -Force
            }
        }
    } else {
        if (Test-Path (Join-Path $UiBin "lua53-64.dll")) {
            Copy-Item -Path (Join-Path $UiBin "lua53-64.dll") -Destination (Join-Path $PkgDir "lua53-64.dll") -Force
            Copy-Item -Path (Join-Path $UiBin "lua53-64.dll") -Destination (Join-Path $PkgDir "lua53.dll") -Force
        }
        if (Test-Path (Join-Path $UiBin "lua53-32.dll")) {
            Copy-Item -Path (Join-Path $UiBin "lua53-32.dll") -Destination (Join-Path $PkgDir "lua53-32.dll") -Force
        }
        if (Test-Path (Join-Path $UiBin "clibs64")) {
            Copy-Item -Path (Join-Path $UiBin "clibs64") -Destination (Join-Path $PkgDir "clibs64") -Recurse -Force
            if (Test-Path (Join-Path $UiBin "clibs64\lfs.dll")) {
                Copy-Item -Path (Join-Path $UiBin "clibs64\lfs.dll") -Destination (Join-Path $PkgDir "lfs.dll") -Force
                Copy-Item -Path (Join-Path $UiBin "clibs64\lfs.dll") -Destination (Join-Path $PkgDir "lfs53.dll") -Force
            }
        }
        if (Test-Path (Join-Path $UiBin "clibs32")) {
            Copy-Item -Path (Join-Path $UiBin "clibs32") -Destination (Join-Path $PkgDir "clibs32") -Recurse -Force
        }
        if (Test-Path (Join-Path $UiBin "win64")) {
            Copy-Item -Path (Join-Path $UiBin "win64") -Destination (Join-Path $PkgDir "win64") -Recurse -Force
        }
        if (Test-Path (Join-Path $UiBin "win32")) {
            Copy-Item -Path (Join-Path $UiBin "win32") -Destination (Join-Path $PkgDir "win32") -Recurse -Force
        }
        $ArchFiles = @(
            "CED3D10Hook.dll", "CED3D10Hook64.dll",
            "CED3D11Hook.dll", "CED3D11Hook64.dll",
            "ced3d9hook.dll", "ced3d9hook64.dll",
            "d3dhook.dll", "d3dhook64.dll",
            "libipt-32.dll", "libipt-64.dll",
            "libmikmod32.dll", "libmikmod64.dll",
            "vehdebug-x86_64.dll"
        )
        foreach ($af in $ArchFiles) {
            $src = Join-Path $UiBin $af
            if (Test-Path $src) {
                Copy-Item -Path $src -Destination (Join-Path $PkgDir $af) -Force
            }
        }
    }

    # Static scripts & resources
    $StaticFiles = @("buildsigs.bat", "class.lua", "classwrapper.lua", "commonmodulelist.txt", "DBK64.inf", "defines.lua", "donottrace.txt", "main.lua", "onyxlua.txt", "overlay.fx", "packfiles.bat", "standalonephase1.dat", "tiny.dat", "OwMemDriver.sys")
    foreach ($sf in $StaticFiles) {
        $src = Join-Path $UiBin $sf
        if (Test-Path $src) {
            Copy-Item -Path $src -Destination (Join-Path $PkgDir $sf) -Force
        }
    }

    if (Test-Path (Join-Path $RootDir "Onyx.ico")) {
        Copy-Item -Path (Join-Path $RootDir "Onyx.ico") -Destination (Join-Path $PkgDir "Onyx.ico") -Force
    }

    # 7. Create ZIP archive
    $ZipPath = Join-Path $ReleaseDir "$PkgName.zip"
    if (Test-Path $ZipPath) {
        Remove-Item -Force $ZipPath
    }
    Write-Host "[*] Compressing $PkgName into $ZipPath..." -ForegroundColor Green
    Compress-Archive -Path "$PkgDir\*" -DestinationPath $ZipPath -CompressionLevel Optimal
    Write-Host "[OK] Created $ZipPath" -ForegroundColor Green
}

Build-Package -Arch "win64" -TargetTriple "x86_64-pc-windows-msvc" -ExeName "OnyxEngine-x86_64.exe"
Build-Package -Arch "win32" -TargetTriple "i686-pc-windows-msvc" -ExeName "OnyxEngine-i386.exe"

Write-Host "===================================================" -ForegroundColor Green
Write-Host " RELEASE PACKAGES GENERATED SUCCESSFULLY!" -ForegroundColor Green
Write-Host " 64-Bit Release: release\OnyxEngine-v$Version-win64.zip" -ForegroundColor Green
Write-Host " 32-Bit Release: release\OnyxEngine-v$Version-win32.zip" -ForegroundColor Green
Write-Host "===================================================" -ForegroundColor Green

