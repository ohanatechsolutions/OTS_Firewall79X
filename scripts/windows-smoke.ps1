$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This installation test is restricted to a disposable GitHub Actions Windows runner.' }
$results = [System.Collections.Generic.List[object]]::new()
function Check([string]$Name, [scriptblock]$Action) {
  try { & $Action; $results.Add(@{test=$Name;status='PASS'}); Write-Host "PASS $Name" }
  catch { $results.Add(@{test=$Name;status='FAIL';error=$_.Exception.Message}); throw }
  finally { $results | ConvertTo-Json -Depth 5 | Set-Content artifacts/windows-test-results.json }
}
function RunExe([string]$File,[string]$Arguments) {
  $p = Start-Process -FilePath $File -ArgumentList $Arguments -Wait -PassThru
  if ($p.ExitCode -ne 0) { throw "$File exited $($p.ExitCode)" }
}
function FirewallDigest {
  $policy = New-Object -ComObject HNetCfg.FwPolicy2
  $rules = @($policy.Rules | ForEach-Object { "$($_.Name)|$($_.Enabled)|$($_.Direction)|$($_.Action)|$($_.ApplicationName)|$($_.RemoteAddresses)|$($_.LocalPorts)" } | Sort-Object)
  return ($rules -join "`n")
}
$before = FirewallDigest
$setup = (Resolve-Path artifacts/release/OTS-Firewall79X-Setup.exe).Path
$root = "$env:ProgramFiles\OTS Firewall79X"
$helper = "$root\recovery\OTS.Firewall79X.Recovery.exe"
Check 'Clean install with bundled runtimes' { RunExe $setup '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=artifacts/install.log'; if ((Get-Service OTSFirewall79X).Status -ne 'Running') { throw 'Service is not running' } }
Check 'Real PE application and recovery binaries installed' { foreach ($file in @("$root\OTS Firewall79X.exe", $helper, "$root\service\OTS.Firewall79X.Service.exe")) { $b=[IO.File]::ReadAllBytes($file);if($b[0] -ne 77 -or $b[1] -ne 90){throw "Not PE: $file"} } }
Check 'UI launches and remains alive' { $ui=Start-Process "$root\OTS Firewall79X.exe" -PassThru;Start-Sleep -Seconds 5;if($ui.HasExited){throw 'UI exited unexpectedly'};Stop-Process -Id $ui.Id }
Check 'One-click activation' { RunExe $helper '--on --quiet';Start-Sleep -Seconds 8;if((Get-Service OTSFirewall79X).Status -ne 'Running'){throw 'Service stopped after activation'} }
Check 'Catalog and transaction self-check' { RunExe $helper '--selftest --quiet' }
Check 'Pause and resume commands' { RunExe $helper '--pause --quiet';RunExe $helper '--on --quiet' }
Check 'Off and recovery' { RunExe $helper '--off --quiet';RunExe $helper '--restore --quiet' }
Check 'Existing firewall rules preserved' { if ((FirewallDigest) -ne $before) { throw 'Firewall rules changed' } }
Check 'In-place upgrade preserves recoverability' { RunExe $setup '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=artifacts/upgrade.log';RunExe $helper '--on --quiet';RunExe $helper '--off --quiet' }
Check 'Clean uninstall removes service and application' { RunExe "$root\unins000.exe" '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART';if(Get-Service OTSFirewall79X -ErrorAction SilentlyContinue){throw 'Service remains'};if(Test-Path "$root\OTS Firewall79X.exe"){throw 'Application remains'} }
Check 'Firewall rules preserved after uninstall' { if ((FirewallDigest) -ne $before) { throw 'Firewall rules changed during uninstall' } }
