$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
function Native([scriptblock]$Command) { & $Command; if ($LASTEXITCODE -ne 0) { throw "Native command failed: $Command" } }
New-Item -ItemType Directory -Force artifacts/release | Out-Null
Native { dotnet restore OTS.Firewall79X.sln --locked-mode }
Native { dotnet build OTS.Firewall79X.sln -c Release --no-restore -m:1 }
Native { dotnet run --project tests/OTS.Firewall79X.Tests -c Release --no-build }
if ($env:GITHUB_ACTIONS -eq 'true') { Native { dotnet tests/OTS.Firewall79X.UiCapture/bin/Release/net10.0-windows/OTS.Firewall79X.UiCapture.dll artifacts/ui-preflight --render-only } }
foreach ($name in @('App','Service','Recovery')) {
  $output = "artifacts/publish/$($name.ToLowerInvariant())"
  Native { dotnet publish "src/OTS.Firewall79X.$name/OTS.Firewall79X.$name.csproj" -c Release -r win-x64 --self-contained true -p:RuntimeFrameworkVersion=10.0.14 -o $output }
}
$components = @{}
Get-ChildItem src -Recurse -Filter project.assets.json | ForEach-Object {
  $assets = Get-Content $_.FullName -Raw | ConvertFrom-Json
  foreach ($lib in $assets.libraries.PSObject.Properties) {
    if ($lib.Value.type -eq 'package') {
      $parts = $lib.Name.Split('/')
      $components[$lib.Name] = @{type='library';name=$parts[0];version=$parts[1];purl="pkg:nuget/$($parts[0])@$($parts[1])"}
    }
  }
}
@{bomFormat='CycloneDX';specVersion='1.5';version=1;metadata=@{timestamp=(Get-Date).ToUniversalTime().ToString('o');component=@{type='application';name='OTS Firewall79X';version='0.1.0'}};components=@($components.Values)} | ConvertTo-Json -Depth 10 | Set-Content artifacts/SBOM.json -Encoding utf8
$manifest = @{version='0.1.0';commit=$env:GITHUB_SHA;sdk=(dotnet --version);runtime='10.0.14';built=(Get-Date).ToUniversalTime().ToString('o');files=@()}
Get-ChildItem artifacts/publish -Recurse -File | ForEach-Object { $manifest.files += @{path=$_.FullName.Substring((Resolve-Path artifacts/publish).Path.Length+1);sha256=(Get-FileHash $_.FullName -Algorithm SHA256).Hash} }
$manifest | ConvertTo-Json -Depth 6 | Set-Content artifacts/BUILD_MANIFEST.json -Encoding utf8
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
if (-not (Test-Path $iscc)) { throw 'Inno Setup 6 compiler unavailable on this Windows build host' }
Native { & $iscc installer/Firewall79X.iss }
$exe = 'artifacts/release/OTS-Firewall79X-Setup.exe'
if (-not (Test-Path $exe)) { throw 'Compiled installer missing' }
$bytes = [System.IO.File]::ReadAllBytes((Resolve-Path $exe))
if ($bytes[0] -ne 77 -or $bytes[1] -ne 90) { throw 'Installer is not a Windows PE executable' }
$installerHash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
"$installerHash  OTS-Firewall79X-Setup.exe" | Set-Content artifacts/release/OTS-Firewall79X-Setup.exe.sha256 -Encoding ascii
# Authenticated publisher identity is mandatory for production; preview stays explicitly unsigned.
& ./scripts/verify-release-provenance.ps1 -RequirePublisherSignature:($env:OTS_RELEASE_CHANNEL -eq 'production')
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) { throw 'Release provenance gate failed' }
Copy-Item RELEASE_NOTES.md,KNOWN_LIMITATIONS.md,artifacts/SBOM.json,artifacts/BUILD_MANIFEST.json artifacts/release/
Compress-Archive -Path artifacts/release/* -DestinationPath artifacts/OTS-Firewall79X-Windows-x64.zip -Force
Move-Item artifacts/OTS-Firewall79X-Windows-x64.zip artifacts/release/ -Force
Get-ChildItem artifacts/release -File | Where-Object Name -ne 'SHA256SUMS.txt' | Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(),$_.Name } | Set-Content artifacts/release/SHA256SUMS.txt -Encoding ascii
