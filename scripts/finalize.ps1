$ErrorActionPreference = 'Stop'
$report = Get-Content artifacts/vulnerability-report.json -Raw | ConvertFrom-Json
# A failed or empty inventory is NOT a clean dependency scan.
$projects = @($report.projects | Where-Object { $null -ne $_ -and -not [string]::IsNullOrWhiteSpace([string]$_.path) })
if ($projects.Count -lt 1) { throw 'Dependency vulnerability inventory returned no projects; refusing release' }
if (@($projects | Where-Object { @($_.frameworks).Count -lt 1 }).Count -gt 0) {
  throw 'Dependency vulnerability inventory omitted project framework data'
}
$severe = @()
foreach($project in $report.projects) {
  foreach($framework in $project.frameworks) {
    foreach($package in (@($framework.topLevelPackages) + @($framework.transitivePackages))) {
      foreach($vulnerability in $package.vulnerabilities) {
        if($vulnerability.severity -in @('High','Critical')) { $severe += "$($package.id): $($vulnerability.severity)" }
      }
    }
  }
}
if($severe.Count -gt 0) { throw ('High/critical dependency findings: ' + ($severe -join ', ')) }
Copy-Item artifacts/ui/00-desktop.png artifacts/release/OTS-Firewall79X-Preview.png
Copy-Item artifacts/ui/08-dashboard-8k.png artifacts/release/OTS-Firewall79X-Preview-8K.png
Copy-Item artifacts/core-test-results.json,artifacts/windows-test-results.json,artifacts/vulnerability-report.json artifacts/release/
Remove-Item artifacts/release/OTS-Firewall79X-Windows-x64.zip,artifacts/release/SHA256SUMS.txt -ErrorAction SilentlyContinue
# The user-facing release ZIP must contain the real installer at installer/, never
# the 134-byte Git LFS pointer present in GitHub's default source-code ZIP.
$package = 'artifacts/package'
if (Test-Path $package) { Remove-Item $package -Recurse -Force }
New-Item -ItemType Directory -Force "$package/installer" | Out-Null
Copy-Item artifacts/release/OTS-Firewall79X-Setup.exe,artifacts/release/OTS-Firewall79X-Setup.exe.sha256 "$package/installer/"
Copy-Item installer/README.md "$package/installer/"
Get-ChildItem artifacts/release -File | Where-Object { $_.Name -notin @('OTS-Firewall79X-Setup.exe','OTS-Firewall79X-Setup.exe.sha256','SHA256SUMS.txt','OTS-Firewall79X-Windows-x64.zip') } | ForEach-Object { Copy-Item $_.FullName $package }
Compress-Archive -Path "$package/*" -DestinationPath artifacts/OTS-Firewall79X-Windows-x64.zip -Force
Move-Item artifacts/OTS-Firewall79X-Windows-x64.zip artifacts/release/ -Force
Get-ChildItem artifacts/release -File | Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(),$_.Name } | Set-Content artifacts/release/SHA256SUMS.txt -Encoding ascii
