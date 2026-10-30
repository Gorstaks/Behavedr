# Behavedr mTLS Certificate Generation Script
# Generates a self-signed CA, server cert, and client cert for agent-server mTLS.
#
# Usage:
#   pwsh tools/generate-certs.ps1
#   pwsh tools/generate-certs.ps1 -OutputDir ./my-certs -ServerDns my-server.local
#
# Output (in $OutputDir):
#   ca.crt / ca.key          - Certificate Authority
#   server.pfx               - Server certificate (for the Behavedr server)
#   client.pfx               - Client certificate (for the agent)
#   ca.crt                   - CA cert to distribute to agents for pinning
#
# All certs valid for 2 years. Regenerate when expired.

param(
    [string]$OutputDir = "./certs",
    [string]$ServerDns = "localhost",
    [string]$CaName = "Behavedr CA",
    [int]$ValidDays = 730,
    [string]$Password = $env:BEHAVEDR_CERT_PASSWORD
)

$ErrorActionPreference = "Stop"

# Require password via environment variable or prompt
if ([string]::IsNullOrEmpty($Password)) {
    $securePass = Read-Host -Prompt "Enter PFX password (or set BEHAVEDR_CERT_PASSWORD env var)" -AsSecureString
    $Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePass))
}

if ([string]::IsNullOrEmpty($Password)) {
    Write-Error "Password is required. Set BEHAVEDR_CERT_PASSWORD or provide at prompt."
    exit 1
}

# Ensure output directory
New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "Generating Behavedr mTLS certificates..." -ForegroundColor Cyan
Write-Host "  Output: $OutputDir"
Write-Host "  Server DNS: $ServerDns"
Write-Host "  Valid for: $ValidDays days"
Write-Host ""

# --- CA Certificate ---
Write-Host "[1/3] Generating CA certificate..." -ForegroundColor Yellow

$caParams = @{
    Subject           = "CN=$CaName, O=CroatiaSecurity, C=HR"
    KeyExportPolicy   = "Exportable"
    KeyLength         = 4096
    KeyAlgorithm      = "RSA"
    HashAlgorithm     = "SHA256"
    CertStoreLocation = "Cert:\CurrentUser\My"
    NotAfter          = (Get-Date).AddDays($ValidDays)
    KeyUsage          = "CertSign", "CRLSign"
    TextExtension     = @("2.5.29.19={text}CA=true&pathlen=1")
}
$caCert = New-SelfSignedCertificate @caParams

# Export CA cert (public only)
$caCertPath = Join-Path $OutputDir "ca.crt"
Export-Certificate -Cert $caCert -FilePath $caCertPath -Type CERT | Out-Null

# Export CA with private key
$caPass = ConvertTo-SecureString $Password -AsPlainText -Force
$caPfxPath = Join-Path $OutputDir "ca.pfx"
Export-PfxCertificate -Cert $caCert -FilePath $caPfxPath -Password $caPass | Out-Null

Write-Host "  CA: $caCertPath" -ForegroundColor Green

# --- Server Certificate ---
Write-Host "[2/3] Generating server certificate..." -ForegroundColor Yellow

$serverParams = @{
    Subject           = "CN=$ServerDns, O=CroatiaSecurity, C=HR"
    KeyExportPolicy   = "Exportable"
    KeyLength         = 2048
    KeyAlgorithm      = "RSA"
    HashAlgorithm     = "SHA256"
    CertStoreLocation = "Cert:\CurrentUser\My"
    NotAfter          = (Get-Date).AddDays($ValidDays)
    Signer            = $caCert
    DnsName           = $ServerDns, "localhost", "127.0.0.1"
    KeyUsage          = "DigitalSignature", "KeyEncipherment"
    TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")  # Server Auth
}
$serverCert = New-SelfSignedCertificate @serverParams

$serverPass = ConvertTo-SecureString $Password -AsPlainText -Force
$serverPfxPath = Join-Path $OutputDir "server.pfx"
Export-PfxCertificate -Cert $serverCert -FilePath $serverPfxPath -Password $serverPass | Out-Null

Write-Host "  Server: $serverPfxPath" -ForegroundColor Green

# --- Client Certificate ---
Write-Host "[3/3] Generating client certificate..." -ForegroundColor Yellow

$clientParams = @{
    Subject           = "CN=Behavedr Agent, O=CroatiaSecurity, C=HR"
    KeyExportPolicy   = "Exportable"
    KeyLength         = 2048
    KeyAlgorithm      = "RSA"
    HashAlgorithm     = "SHA256"
    CertStoreLocation = "Cert:\CurrentUser\My"
    NotAfter          = (Get-Date).AddDays($ValidDays)
    Signer            = $caCert
    KeyUsage          = "DigitalSignature"
    TextExtension     = @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")  # Client Auth
}
$clientCert = New-SelfSignedCertificate @clientParams

$clientPass = ConvertTo-SecureString $Password -AsPlainText -Force
$clientPfxPath = Join-Path $OutputDir "client.pfx"
Export-PfxCertificate -Cert $clientCert -FilePath $clientPfxPath -Password $clientPass | Out-Null

Write-Host "  Client: $clientPfxPath" -ForegroundColor Green

# --- Cleanup cert store (optional) ---
Remove-Item "Cert:\CurrentUser\My\$($caCert.Thumbprint)" -ErrorAction SilentlyContinue
Remove-Item "Cert:\CurrentUser\My\$($serverCert.Thumbprint)" -ErrorAction SilentlyContinue
Remove-Item "Cert:\CurrentUser\My\$($clientCert.Thumbprint)" -ErrorAction SilentlyContinue

# --- Summary ---
Write-Host ""
Write-Host "Done! Certificate files:" -ForegroundColor Cyan
Write-Host "  CA (public):     $caCertPath"
Write-Host "  CA (pfx):        $caPfxPath"
Write-Host "  Server (pfx):    $serverPfxPath"
Write-Host "  Client (pfx):    $clientPfxPath"
Write-Host ""
Write-Host "Password for all PFX files: $Password" -ForegroundColor Yellow
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  1. Place ca.crt on the agent (for server cert pinning)"
Write-Host "  2. Place client.pfx on the agent (for mTLS client auth)"
Write-Host "  3. Place server.pfx on the server (for TLS termination)"
Write-Host "  4. Configure appsettings.json:"
Write-Host '     "Communication": {'
Write-Host '       "CaCertPath": "certs/ca.crt",'
Write-Host '       "ClientCertPath": "certs/client.pfx",'
Write-Host '       "ClientCertPassword": "behavedr-dev"'
Write-Host '     }'
