param(
  [Parameter(Mandatory=$true)][ValidateSet('payload','installer')][string]$Stage
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:OTS_RELEASE_CHANNEL -ne 'production') { throw 'Release signing is restricted to explicit production builds' }
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'Production certificate import is restricted to disposable CI runners' }
if ($env:OTS_SIGNING_CERT_SHA256 -notmatch '^[a-fA-F0-9]{64}$' -or
    [string]::IsNullOrWhiteSpace($env:OTS_CODESIGN_PFX_BASE64) -or
    [string]::IsNullOrWhiteSpace($env:OTS_CODESIGN_PFX_PASSWORD)) {
  throw 'Production signing requires provisioned certificate, publisher pin and protected signing secrets'
}
$expected = $env:OTS_SIGNING_CERT_SHA256.ToUpperInvariant()
$bytes = [Convert]::FromBase64String($env:OTS_CODESIGN_PFX_BASE64)
$temp = Join-Path $env:RUNNER_TEMP ([IO.Path]::GetRandomFileName() + '.pfx')
$cert = $null
try {
  [IO.File]::WriteAllBytes($temp,$bytes)
  $password=ConvertTo-SecureString $env:OTS_CODESIGN_PFX_PASSWORD -AsPlainText -Force
  $cert=Import-PfxCertificate -FilePath $temp -Password $password -CertStoreLocation Cert:\CurrentUser\My -Exportable:$false
  if (@($cert).Count -ne 1 -or -not $cert.HasPrivateKey -or
      $cert.GetCertHashString('SHA256') -ne $expected) {
    throw 'PFX certificate does not match pinned trusted publisher identity'
  }
  $files = if ($Stage -eq 'installer') {
    @(Get-Item -LiteralPath 'artifacts/release/OTS-Firewall79X-Setup.exe')
  } else {
    @(Get-ChildItem -LiteralPath 'artifacts/publish' -Recurse -File |
      Where-Object { $_.Name -like 'OTS*.exe' -or $_.Name -like 'OTS*.dll' })
  }
  if (@($files).Count -eq 0) { throw 'No eligible OTS executables to sign' }
  foreach ($file in $files) {
    $signature=Set-AuthenticodeSignature -FilePath $file.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer 'http://timestamp.digicert.com'
    if ($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or
        $signature.SignerCertificate.GetCertHashString('SHA256') -ne $expected) {
      throw "Publisher signature verification failed for $($file.Name): $($signature.Status)"
    }
  }
  Write-Host "Verified publisher Authenticode signatures for $(@($files).Count) OTS files"
}
finally {
  [System.Security.Cryptography.CryptographicOperations]::ZeroMemory($bytes)
  Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue
  if ($null -ne $cert) {
    foreach ($item in @($cert)) {
      Remove-Item -Path ("Cert:\CurrentUser\My\" + $item.Thumbprint) -Force -ErrorAction SilentlyContinue
    }
  }
}
