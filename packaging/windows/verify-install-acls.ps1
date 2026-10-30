<#
.SYNOPSIS
  Post-install ACL verification for Behavedr on Windows (SYSTEM-only install tree).

.DESCRIPTION
  Confirms Program Files\Behavedr (or custom path) is not world-writable and that
  critical binaries deny modify rights to Users/Everyone. Run elevated after install.

.EXAMPLE
  .\packaging\windows\verify-install-acls.ps1
  .\packaging\windows\verify-install-acls.ps1 -InstallPath 'C:\Program Files\Behavedr'
#>
[CmdletBinding()]
param(
    [string] $InstallPath = "${env:ProgramFiles}\Behavedr"
)

$ErrorActionPreference = "Stop"
$failed = 0

function Test-NotWorldWritable([string] $Path) {
    if (-not (Test-Path $Path)) {
        Write-Warning "Missing: $Path"
        return $false
    }
    $acl = Get-Acl -Path $Path
    foreach ($ace in $acl.Access) {
        $id = $ace.IdentityReference.Value
        if ($id -match 'Everyone|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users') {
            $rights = $ace.FileSystemRights.ToString()
            if ($ace.AccessControlType -eq 'Allow' -and $rights -match 'Write|Modify|FullControl|CreateFiles|Delete') {
                Write-Host "FAIL: $Path grants $rights to $id" -ForegroundColor Red
                return $false
            }
        }
    }
    Write-Host "OK:   $Path" -ForegroundColor Green
    return $true
}

Write-Host "Behavedr install ACL verification"
Write-Host "Path: $InstallPath"
Write-Host ""

if (-not (Test-Path $InstallPath)) {
    Write-Error "Install path not found: $InstallPath"
    exit 2
}

$targets = @(
    $InstallPath,
    (Join-Path $InstallPath 'Behavedr.exe'),
    (Join-Path $InstallPath 'appsettings.json')
) | Where-Object { $_ -and (Test-Path $_) }

foreach ($t in $targets) {
    if (-not (Test-NotWorldWritable $t)) { $failed++ }
}

if ($failed -gt 0) {
    Write-Host "`nFAIL: $failed path(s) failed ACL checks" -ForegroundColor Red
    exit 1
}

Write-Host "`nAll checked paths look non-world-writable." -ForegroundColor Green
exit 0
