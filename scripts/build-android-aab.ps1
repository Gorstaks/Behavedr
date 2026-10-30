#Requires -Version 5.1
<#
.SYNOPSIS
  Build a Google Play Android App Bundle (.aab) for Behavedr.Mobile.

.DESCRIPTION
  Requires:
    - .NET 10 SDK
    - MAUI Android workload:  dotnet workload install maui-android
    - Android SDK (ANDROID_HOME) with platform 34/35 + build-tools
    - JDK 17+

  Output: publish/android-aab/Behavedr-<version>-android.aab

.EXAMPLE
  .\scripts\build-android-aab.ps1
  .\scripts\build-android-aab.ps1 -SignWithReleaseKeystore
#>
param(
    [switch]$SignWithReleaseKeystore,
    [string]$OutputDir = "",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"
$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$csproj = Join-Path $RepoRoot "src\Behavedr.Mobile\Behavedr.Mobile.csproj"
if (-not (Test-Path $csproj)) { throw "Mobile project not found: $csproj" }

$props = Get-Content (Join-Path $RepoRoot "Directory.Build.props") -Raw
if ($props -match '<Version>([^<]+)</Version>') { $Version = $Matches[1] } else { $Version = "0.0.0" }

if (-not $OutputDir) {
    $OutputDir = Join-Path $RepoRoot "publish\android-aab"
}

Write-Host "[aab] Version=$Version  Out=$OutputDir" -ForegroundColor Cyan

# Workload check
$wl = & dotnet workload list 2>&1 | Out-String
if ($wl -notmatch 'maui-android|android') {
    Write-Host "[aab] Installing maui-android workload..." -ForegroundColor Yellow
    & dotnet workload install maui-android
    if ($LASTEXITCODE -ne 0) { throw "dotnet workload install maui-android failed" }
}

if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    $candidates = @(
        "$env:LOCALAPPDATA\Android\Sdk",
        "$env:USERPROFILE\AppData\Local\Android\Sdk"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) {
            $env:ANDROID_HOME = $c
            $env:ANDROID_SDK_ROOT = $c
            Write-Host "[aab] Using ANDROID_HOME=$c" -ForegroundColor Green
            break
        }
    }
}

if (-not $env:ANDROID_HOME -and -not $env:ANDROID_SDK_ROOT) {
    throw "ANDROID_HOME / ANDROID_SDK_ROOT not set and no SDK found under LocalAppData\Android\Sdk"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

& dotnet publish $csproj `
    -c $Configuration `
    -f net10.0-android `
    -p:MobileTfms=net10.0-android `
    -p:AndroidPackageFormat=aab `
    -p:AndroidPackageFormats=aab `
    -p:Version=$Version `
    -p:ApplicationDisplayVersion=$Version `
    -o $OutputDir

if ($LASTEXITCODE -ne 0) { throw "dotnet publish AAB failed (exit $LASTEXITCODE)" }

$aabs = Get-ChildItem -Path $OutputDir,$RepoRoot\src\Behavedr.Mobile -Recurse -Filter *.aab -ErrorAction SilentlyContinue
if (-not $aabs -or $aabs.Count -eq 0) {
    throw "Publish succeeded but no .aab file was found under $OutputDir"
}

$canonical = Join-Path $OutputDir "Behavedr-$Version-android.aab"
Copy-Item -Force $aabs[0].FullName $canonical
Write-Host "[aab] Built: $($aabs[0].FullName)" -ForegroundColor Green
Write-Host "[aab] Copy:  $canonical" -ForegroundColor Green

if ($SignWithReleaseKeystore) {
    $ks = Join-Path $RepoRoot "keys\android\behavedr-release.p12"
    $pwFile = Join-Path $RepoRoot "keys\android\behavedr-release.password.txt"
    if (-not (Test-Path $ks)) { throw "Keystore missing: $ks" }
    if (-not (Test-Path $pwFile)) { throw "Password file missing: $pwFile" }
    $storePass = (Get-Content -Raw $pwFile).Trim()
    $jarsigner = Get-Command jarsigner -ErrorAction SilentlyContinue
    if (-not $jarsigner) { throw "jarsigner not on PATH (install JDK 17+)" }
    & jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 `
        -keystore $ks -storetype pkcs12 `
        -storepass $storePass -keypass $storePass `
        $canonical behavedr
    if ($LASTEXITCODE -ne 0) { throw "jarsigner failed" }
    Write-Host "[aab] Signed with release keystore" -ForegroundColor Green
}

Write-Host ""
Write-Host "Upload to Play Console:" -ForegroundColor Cyan
Write-Host "  $canonical"
return $canonical
