$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$root = (Resolve-Path '.').Path
$exe = Join-Path $root 'artifacts/release/OTS-Firewall79X-Setup.exe'
$checksum = Join-Path $root 'artifacts/release/OTS-Firewall79X-Setup.exe.sha256'
$zipFile = Join-Path $root 'artifacts/release/OTS-Firewall79X-Windows-x64.zip'
if (-not (Test-Path -PathType Leaf $exe) -or -not (Test-Path -PathType Leaf $checksum) -or -not (Test-Path -PathType Leaf $zipFile)) {
  throw 'Required Windows installer, .sha256 checksum, or release ZIP is missing'
}
$realLength = (Get-Item $exe).Length
if ($realLength -lt 10MB) { throw "Setup.exe is only $realLength bytes; a Git LFS pointer or incomplete file cannot be distributed" }
$hash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
$checksumText = [IO.File]::ReadAllText($checksum).Trim()
if ($checksumText -cne "$hash  OTS-Firewall79X-Setup.exe") { throw 'Installer checksum does not match exact contents' }
# Inspect Windows PE signature and machine type (Inno Setup can be 32-bit while installing x64 apps).
$stream = [IO.File]::OpenRead($exe)
try {
  $header = [byte[]]::new(64)
  if ($stream.Read($header,0,64) -ne 64 -or $header[0] -ne 77 -or $header[1] -ne 90) { throw 'Not a valid MZ executable' }
  $peOffset = [BitConverter]::ToInt32($header,0x3c)
  if ($peOffset -lt 64 -or $peOffset -gt 4096) { throw 'Invalid Windows PE offset' }
  $stream.Position = $peOffset
  $pe = [byte[]]::new(6)
  if ($stream.Read($pe,0,6) -ne 6 -or $pe[0] -ne 80 -or $pe[1] -ne 69 -or $pe[2] -ne 0 -or $pe[3] -ne 0) { throw 'Missing Windows PE signature' }
  $machine = [BitConverter]::ToUInt16($pe,4)
  if ($machine -notin @(0x14c,0x8664)) { throw "Unexpected installer PE machine 0x$($machine.ToString('x'))" }
}
finally { $stream.Dispose() }
Add-Type -AssemblyName System.IO.Compression
$zip = [IO.Compression.ZipFile]::OpenRead($zipFile)
try {
  $exeEntry = $zip.GetEntry('installer/OTS-Firewall79X-Setup.exe')
  $hashEntry = $zip.GetEntry('installer/OTS-Firewall79X-Setup.exe.sha256')
  if ($null -eq $exeEntry -or $null -eq $hashEntry) { throw 'Release ZIP is missing the installer/ executable or checksum' }
  if ($exeEntry.Length -ne $realLength -or $exeEntry.Length -lt 10MB) { throw 'Release ZIP contains the wrong installer size or an LFS pointer' }
  $inside = $exeEntry.Open()
  try { $zipHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([IO.Stream]$inside)).ToLowerInvariant() }
  finally { $inside.Dispose() }
  if ($zipHash -cne $hash) { throw 'Release ZIP executable bytes do not match the built EXE' }
  $reader = [IO.StreamReader]::new($hashEntry.Open())
  try { $insideChecksum = $reader.ReadToEnd().Trim() }
  finally { $reader.Dispose() }
  if ($insideChecksum -cne $checksumText) { throw 'Release ZIP checksum does not match the standalone checksum' }
}
finally { $zip.Dispose() }
Write-Host "PASS: real Windows PE installer ($realLength bytes), checksum $hash, and installer/ files inside release ZIP"
