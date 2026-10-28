param([switch]$RequirePublisherSignature)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$manifestPath = 'artifacts/BUILD_MANIFEST.json'
$sbomPath = 'artifacts/SBOM.json'
$setupPath = 'artifacts/release/OTS-Firewall79X-Setup.exe'
$checksumPath = 'artifacts/release/OTS-Firewall79X-Setup.exe.sha256'
foreach ($path in @($manifestPath,$sbomPath,$setupPath,$checksumPath)) {
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Missing release evidence: $path" }
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
$sbom = Get-Content -LiteralPath $sbomPath -Raw | ConvertFrom-Json
if ($manifest.version -ne '0.1.0' -or $sbom.bomFormat -ne 'CycloneDX' -or
    $sbom.specVersion -ne '1.5' -or @($manifest.files).Count -lt 1) {
  throw 'Invalid build manifest or software bill of materials'
}
if ($RequirePublisherSignature -and $env:OTS_SIGNING_CERT_SHA256 -notmatch '^[a-fA-F0-9]{64}
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $manifest.files) {
  $relative = [string]$entry.path
  if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('..') -or
      [System.IO.Path]::IsPathRooted($relative) -or -not $seen.Add($relative)) {
    throw "Unsafe or duplicate build manifest path: $relative"
  }
  $path = Join-Path $root $relative
  $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
  if (-not $resolved.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar,
      [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Build manifest path escaped the publish root'
  }
  $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
  if ($actual -ne [string]$entry.sha256) { throw "Build manifest digest mismatch: $relative" }
  if ($RequirePublisherSignature -and [IO.Path]::GetFileName($relative) -match '^OTS.*\.(exe|dll)
}
$actualInstallerHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($expectedLine -cne "$actualInstallerHash  OTS-Firewall79X-Setup.exe") {
  throw 'Release installer checksum file is invalid or mismatched'
}
$signature = Get-AuthenticodeSignature -LiteralPath $setupPath
$signatureValid = $signature.Status -eq 'Valid'
$trustedPublisher = $false
$expectedCert = [string]$env:OTS_SIGNING_CERT_SHA256
if ($signatureValid -and -not [string]::IsNullOrWhiteSpace($expectedCert) -and $signature.SignerCertificate) {
  $trustedPublisher = $signature.SignerCertificate.GetCertHashString('SHA256') -eq
    ($expectedCert -replace '\s','').ToUpperInvariant()
}
if ($RequirePublisherSignature -and -not ($signatureValid -and $trustedPublisher)) {
  throw 'Production release blocked: signed installer and separately configured publisher certificate fingerprint are required'
}
$report = [ordered]@{
  version = [string]$manifest.version
  publishFilesChecked = $seen.Count
  sbomComponents = @($sbom.components).Count
  installerSha256 = $actualInstallerHash
  authenticodeStatus = [string]$signature.Status
  trustedPublisherFingerprintMatch = $trustedPublisher
  productionAuthenticityApproved = $signatureValid -and $trustedPublisher
  disclaimer = 'Development preview; an installer hash alone does not establish publisher authenticity.'
}
$report | ConvertTo-Json -Depth 5 | Set-Content artifacts/release/PROVENANCE_REPORT.json -Encoding utf8
Write-Host ("Build integrity verified for {0} files; Authenticode={1}; trusted publisher={2}" -f $seen.Count,$signature.Status,$trustedPublisher)
) {
    $payloadSignature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($payloadSignature.Status -ne 'Valid' -or -not $payloadSignature.SignerCertificate -or
        $payloadSignature.SignerCertificate.GetCertHashString('SHA256') -ne $env:OTS_SIGNING_CERT_SHA256.ToUpperInvariant()) {
      throw "Bundled executable fails pinned Authenticode verification: $relative"
    }
  }
}
$actualInstallerHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($expectedLine -cne "$actualInstallerHash  OTS-Firewall79X-Setup.exe") {
  throw 'Release installer checksum file is invalid or mismatched'
}
$signature = Get-AuthenticodeSignature -LiteralPath $setupPath
$signatureValid = $signature.Status -eq 'Valid'
$trustedPublisher = $false
$expectedCert = [string]$env:OTS_SIGNING_CERT_SHA256
if ($signatureValid -and -not [string]::IsNullOrWhiteSpace($expectedCert) -and $signature.SignerCertificate) {
  $trustedPublisher = $signature.SignerCertificate.GetCertHashString('SHA256') -eq
    ($expectedCert -replace '\s','').ToUpperInvariant()
}
if ($RequirePublisherSignature -and -not ($signatureValid -and $trustedPublisher)) {
  throw 'Production release blocked: signed installer and separately configured publisher certificate fingerprint are required'
}
$report = [ordered]@{
  version = [string]$manifest.version
  publishFilesChecked = $seen.Count
  sbomComponents = @($sbom.components).Count
  installerSha256 = $actualInstallerHash
  authenticodeStatus = [string]$signature.Status
  trustedPublisherFingerprintMatch = $trustedPublisher
  productionAuthenticityApproved = $signatureValid -and $trustedPublisher
  disclaimer = 'Development preview; an installer hash alone does not establish publisher authenticity.'
}
$report | ConvertTo-Json -Depth 5 | Set-Content artifacts/release/PROVENANCE_REPORT.json -Encoding utf8
Write-Host ("Build integrity verified for {0} files; Authenticode={1}; trusted publisher={2}" -f $seen.Count,$signature.Status,$trustedPublisher)
) {
  throw 'Production release requires a 256-bit pinned publisher-certificate fingerprint'
}
$root = (Resolve-Path 'artifacts/publish').Path
$seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
foreach ($entry in $manifest.files) {
  $relative = [string]$entry.path
  if ([string]::IsNullOrWhiteSpace($relative) -or $relative.Contains('..') -or
      [System.IO.Path]::IsPathRooted($relative) -or -not $seen.Add($relative)) {
    throw "Unsafe or duplicate build manifest path: $relative"
  }
  $path = Join-Path $root $relative
  $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).Path
  if (-not $resolved.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar,
      [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Build manifest path escaped the publish root'
  }
  $actual = (Get-FileHash -LiteralPath $resolved -Algorithm SHA256).Hash
  if ($actual -ne [string]$entry.sha256) { throw "Build manifest digest mismatch: $relative" }
  if ($RequirePublisherSignature -and [IO.Path]::GetFileName($relative) -match '^OTS.*\.(exe|dll)
}
$actualInstallerHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($expectedLine -cne "$actualInstallerHash  OTS-Firewall79X-Setup.exe") {
  throw 'Release installer checksum file is invalid or mismatched'
}
$signature = Get-AuthenticodeSignature -LiteralPath $setupPath
$signatureValid = $signature.Status -eq 'Valid'
$trustedPublisher = $false
$expectedCert = [string]$env:OTS_SIGNING_CERT_SHA256
if ($signatureValid -and -not [string]::IsNullOrWhiteSpace($expectedCert) -and $signature.SignerCertificate) {
  $trustedPublisher = $signature.SignerCertificate.GetCertHashString('SHA256') -eq
    ($expectedCert -replace '\s','').ToUpperInvariant()
}
if ($RequirePublisherSignature -and -not ($signatureValid -and $trustedPublisher)) {
  throw 'Production release blocked: signed installer and separately configured publisher certificate fingerprint are required'
}
$report = [ordered]@{
  version = [string]$manifest.version
  publishFilesChecked = $seen.Count
  sbomComponents = @($sbom.components).Count
  installerSha256 = $actualInstallerHash
  authenticodeStatus = [string]$signature.Status
  trustedPublisherFingerprintMatch = $trustedPublisher
  productionAuthenticityApproved = $signatureValid -and $trustedPublisher
  disclaimer = 'Development preview; an installer hash alone does not establish publisher authenticity.'
}
$report | ConvertTo-Json -Depth 5 | Set-Content artifacts/release/PROVENANCE_REPORT.json -Encoding utf8
Write-Host ("Build integrity verified for {0} files; Authenticode={1}; trusted publisher={2}" -f $seen.Count,$signature.Status,$trustedPublisher)
) {
    $payloadSignature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($payloadSignature.Status -ne 'Valid' -or -not $payloadSignature.SignerCertificate -or
        $payloadSignature.SignerCertificate.GetCertHashString('SHA256') -ne $env:OTS_SIGNING_CERT_SHA256.ToUpperInvariant()) {
      throw "Bundled executable fails pinned Authenticode verification: $relative"
    }
  }
}
$actualInstallerHash = (Get-FileHash -LiteralPath $setupPath -Algorithm SHA256).Hash.ToLowerInvariant()
$expectedLine = (Get-Content -LiteralPath $checksumPath -Raw).Trim()
if ($expectedLine -cne "$actualInstallerHash  OTS-Firewall79X-Setup.exe") {
  throw 'Release installer checksum file is invalid or mismatched'
}
$signature = Get-AuthenticodeSignature -LiteralPath $setupPath
$signatureValid = $signature.Status -eq 'Valid'
$trustedPublisher = $false
$expectedCert = [string]$env:OTS_SIGNING_CERT_SHA256
if ($signatureValid -and -not [string]::IsNullOrWhiteSpace($expectedCert) -and $signature.SignerCertificate) {
  $trustedPublisher = $signature.SignerCertificate.GetCertHashString('SHA256') -eq
    ($expectedCert -replace '\s','').ToUpperInvariant()
}
if ($RequirePublisherSignature -and -not ($signatureValid -and $trustedPublisher)) {
  throw 'Production release blocked: signed installer and separately configured publisher certificate fingerprint are required'
}
$report = [ordered]@{
  version = [string]$manifest.version
  publishFilesChecked = $seen.Count
  sbomComponents = @($sbom.components).Count
  installerSha256 = $actualInstallerHash
  authenticodeStatus = [string]$signature.Status
  trustedPublisherFingerprintMatch = $trustedPublisher
  productionAuthenticityApproved = $signatureValid -and $trustedPublisher
  disclaimer = 'Development preview; an installer hash alone does not establish publisher authenticity.'
}
$report | ConvertTo-Json -Depth 5 | Set-Content artifacts/release/PROVENANCE_REPORT.json -Encoding utf8
Write-Host ("Build integrity verified for {0} files; Authenticode={1}; trusted publisher={2}" -f $seen.Count,$signature.Status,$trustedPublisher)
