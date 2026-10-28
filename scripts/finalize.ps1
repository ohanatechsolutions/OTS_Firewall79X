$ErrorActionPreference = 'Stop'
$report = Get-Content artifacts/vulnerability-report.json -Raw | ConvertFrom-Json
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
Compress-Archive -Path artifacts/release/* -DestinationPath artifacts/OTS-Firewall79X-Windows-x64.zip -Force
Move-Item artifacts/OTS-Firewall79X-Windows-x64.zip artifacts/release/ -Force
Get-ChildItem artifacts/release -File | Sort-Object Name | ForEach-Object { '{0}  {1}' -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant(),$_.Name } | Set-Content artifacts/release/SHA256SUMS.txt -Encoding ascii
