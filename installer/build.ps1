# Behavedr - Windows Installer Build Script
# Copyright (c) 2026 CroatiaSecurity. All rights reserved.
#
# Produces a signed-ready installer from source without external CI dependencies.
# Requires: .NET 10 SDK, Inno Setup 6+
#
# Usage:
#   .\installer\build.ps1
#   .\installer\build.ps1 -SkipClean
#   .\installer\build.ps1 -Runtime win-arm64

param(
    [string]$Runtime = "win-x64",
    [switch]$SkipClean,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = $PSScriptRoot
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Behavedr - Installer Build ($Runtime)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ---------------------------------------------------------------------------
# 1. Read version from Directory.Build.props (single source of truth)
# ---------------------------------------------------------------------------
$PropsFile = Join-Path $RepoRoot "Directory.Build.props"
if (-not (Test-Path $PropsFile)) {
    throw "Directory.Build.props not found at: $PropsFile"
}

[xml]$PropsXml = Get-Content $PropsFile -Raw
$Version = $PropsXml.Project.PropertyGroup[0].Version
if ([string]::IsNullOrWhiteSpace($Version)) {
    throw "Could not read Version from Directory.Build.props"
}

Write-Host "[version]  $Version" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 2. Clean previous build artifacts
# ---------------------------------------------------------------------------
$SrcDir     = Join-Path $RepoRoot "src"
$PublishDir = Join-Path $RepoRoot "publish"
$DistDir    = Join-Path $RepoRoot "dist"

if (-not $SkipClean) {
    Write-Host "[clean]    Removing bin/obj and publish outputs..." -ForegroundColor Yellow
    Get-ChildItem -Path $SrcDir -Include bin, obj -Directory -Recurse |
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $PublishDir) { Remove-Item $PublishDir -Recurse -Force }
    if (Test-Path $DistDir)    { Remove-Item $DistDir -Recurse -Force }
}

# ---------------------------------------------------------------------------
# 3. Restore and build
# ---------------------------------------------------------------------------
$AgentProj = Join-Path $SrcDir "Behavedr.Agent\Behavedr.Agent.csproj"
if (-not (Test-Path $AgentProj)) {
    throw "Agent project not found: $AgentProj"
}

Write-Host "[restore]  Restoring packages..." -ForegroundColor Yellow
& dotnet restore $AgentProj --verbosity quiet
if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed (exit $LASTEXITCODE)" }

# ---------------------------------------------------------------------------
# 4. Run tests (unless skipped)
# ---------------------------------------------------------------------------
$TestProj = Join-Path $RepoRoot "tests\Behavedr.Tests\Behavedr.Tests.csproj"
if (-not $SkipTests -and (Test-Path $TestProj)) {
    Write-Host "[test]     Running tests..." -ForegroundColor Yellow
    & dotnet test $TestProj -c Release --verbosity quiet --no-restore
    if ($LASTEXITCODE -ne 0) { throw "Tests failed (exit $LASTEXITCODE)" }
    Write-Host "[test]     All tests passed" -ForegroundColor Green
}

# ---------------------------------------------------------------------------
# 5. Publish self-contained single-file binary
# ---------------------------------------------------------------------------
$PublishOut = Join-Path $PublishDir "agent-$Runtime"

Write-Host "[publish]  Publishing $Runtime (self-contained, single-file)..." -ForegroundColor Yellow
& dotnet publish $AgentProj `
    -c Release `
    -r $Runtime `
    --self-contained `
    -p:PublishSingleFile=true `
    -p:IncludeAllContentForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none `
    -p:DebugSymbols=false `
    -p:Version=$Version `
    -o $PublishOut `
    --verbosity quiet

if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed (exit $LASTEXITCODE)" }

# Copy appsettings.json and Assets
$AppSettings = Join-Path $SrcDir "Behavedr.Agent\appsettings.json"
if (Test-Path $AppSettings) { Copy-Item $AppSettings $PublishOut -Force }

$AssetsDir = Join-Path $RepoRoot "Assets"
if (Test-Path $AssetsDir) {
    $DestAssets = Join-Path $PublishOut "Assets"
    New-Item -ItemType Directory -Force -Path $DestAssets | Out-Null
    Copy-Item "$AssetsDir\*" $DestAssets -Recurse -Force
}

# Copy packaging README
$PkgReadme = Join-Path $ScriptRoot "..\packaging\windows\README.txt"
if (Test-Path $PkgReadme) { Copy-Item $PkgReadme $PublishOut -Force }

Write-Host "[publish]  Output: $PublishOut" -ForegroundColor Green
Write-Host ""

# ---------------------------------------------------------------------------
# 6. Locate Inno Setup compiler (no Chocolatey dependency)
# ---------------------------------------------------------------------------
Write-Host "[iscc]     Locating Inno Setup compiler..." -ForegroundColor Yellow

$IsccSearchPaths = @(
    "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 6\ISCC.exe",
    "${env:ProgramFiles(x86)}\Inno Setup 7\ISCC.exe",
    "$env:ProgramFiles\Inno Setup 7\ISCC.exe"
)

$IsccExe = $null
foreach ($Path in $IsccSearchPaths) {
    if (Test-Path $Path) { $IsccExe = $Path; break }
}

if (-not $IsccExe) {
    $IsccExe = (Get-Command ISCC.exe -ErrorAction SilentlyContinue).Source
}

if (-not $IsccExe) {
    Write-Host ""
    Write-Host "ERROR: Inno Setup compiler (ISCC.exe) not found." -ForegroundColor Red
    Write-Host "Install Inno Setup 6 from: https://jrsoftware.org/isdl.php" -ForegroundColor Red
    Write-Host ""
    Write-Host "Portable zip was still created at: $PublishOut" -ForegroundColor Yellow
    exit 1
}

Write-Host "[iscc]     Found: $IsccExe" -ForegroundColor Green

# ---------------------------------------------------------------------------
# 7. Compile the installer
# ---------------------------------------------------------------------------
$IssFile = Join-Path $RepoRoot "packaging\windows\behavedr.iss"
if (-not (Test-Path $IssFile)) {
    throw "Inno Setup script not found: $IssFile"
}

$OutputDir = Join-Path $DistDir "windows"
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$PublishAbs = (Resolve-Path $PublishOut).Path

Write-Host "[iscc]     Compiling installer..." -ForegroundColor Yellow
& $IsccExe $IssFile "/DMyAppVersion=$Version" "/DPublishDir=$PublishAbs" "/DOutputDir=$OutputDir"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup compilation failed (exit $LASTEXITCODE)" }

Write-Host ""
Write-Host "================================================================" -ForegroundColor Green
Write-Host "  Build complete" -ForegroundColor Green
Write-Host "  Installer: dist\windows\Behavedr-Setup-$Version-$Runtime.exe" -ForegroundColor Green
Write-Host "  Portable:  publish\agent-$Runtime\" -ForegroundColor Green
Write-Host "================================================================" -ForegroundColor Green
