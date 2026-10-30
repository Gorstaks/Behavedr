<#
.SYNOPSIS
  Sign Behavedr release assets with RSA-4096 PSS (SHA-256) and emit SHA256SUMS.

.DESCRIPTION
  Produces a .sig sidecar for each input file using the same algorithm the agent
  verifies in UpdateSignatureVerifier (RSA-PSS SHA-256, salt length = digest).

  Requires OpenSSL 3.x on PATH.

.PARAMETER AssetsDir
  Directory containing release files (zips, installer, APK).

.PARAMETER PrivateKeyPath
  Path to RSA private key PEM (update-signing-key.pem). Never commit this file.

.PARAMETER SkipIfMissingKey
  Exit 0 without signing when the key is absent (CI soft path for forks).

.EXAMPLE
  .\tools\sign-release.ps1 -AssetsDir .\release-assets -PrivateKeyPath .\update-signing-key.pem
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $AssetsDir,

    [Parameter(Mandatory = $false)]
    [string] $PrivateKeyPath = "update-signing-key.pem",

    [switch] $SkipIfMissingKey
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path $AssetsDir)) {
    throw "Assets directory not found: $AssetsDir"
}

if (-not (Test-Path $PrivateKeyPath)) {
    if ($SkipIfMissingKey) {
        Write-Warning "Private key not found at $PrivateKeyPath - skipping RSA-PSS signing"
        exit 0
    }
    throw "Private key not found: $PrivateKeyPath"
}

$openssl = Get-Command openssl -ErrorAction SilentlyContinue
if (-not $openssl) {
    throw "openssl not found on PATH. Install OpenSSL 3.x."
}

$assets = Get-ChildItem -Path $AssetsDir -File | Where-Object {
    $_.Name -notmatch '\.sig$' -and $_.Name -ne 'SHA256SUMS' -and $_.Name -ne 'SHA256SUMS.sig'
}

if ($assets.Count -eq 0) {
    throw "No assets to sign in $AssetsDir"
}

Write-Host "Signing $($assets.Count) asset(s) with RSA-PSS SHA-256..."

foreach ($file in $assets) {
    $sigPath = "$($file.FullName).sig"
    # saltlen:digest matches .NET RSASignaturePadding.Pss (salt = hash length)
    & openssl dgst -sha256 `
        -sigopt rsa_padding_mode:pss `
        -sigopt rsa_pss_saltlen:digest `
        -sign $PrivateKeyPath `
        -out $sigPath `
        $file.FullName
    if ($LASTEXITCODE -ne 0) {
        throw "openssl sign failed for $($file.Name)"
    }
    Write-Host "  signed $($file.Name) -> $($file.Name).sig"
}

# SHA256SUMS (GNU coreutils style: "HASH  filename")
$sumsPath = Join-Path $AssetsDir "SHA256SUMS"
$lines = foreach ($file in $assets) {
    $hash = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash.ToLowerInvariant()
    "{0}  {1}" -f $hash, $file.Name
}
$lines | Set-Content -Path $sumsPath -Encoding utf8NoBOM
Write-Host "Wrote $sumsPath"

# Sign the checksum manifest itself
$sumsSig = "$sumsPath.sig"
& openssl dgst -sha256 `
    -sigopt rsa_padding_mode:pss `
    -sigopt rsa_pss_saltlen:digest `
    -sign $PrivateKeyPath `
    -out $sumsSig `
    $sumsPath
if ($LASTEXITCODE -ne 0) {
    throw "openssl sign failed for SHA256SUMS"
}
Write-Host "  signed SHA256SUMS -> SHA256SUMS.sig"
Write-Host "Done."
