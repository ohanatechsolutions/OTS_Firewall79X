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
function FirewallSnapshot([string]$Stage) {
  $current=FirewallDigest
  $current | Set-Content "artifacts/firewall-$Stage.log"
  return $current
}
function AssertFirewallUnchanged([string]$Stage) {
  $current = FirewallSnapshot $Stage
  # Windows creates transient packaged-app resource rules when a new user profile
  # is initialized. Keep them in the full forensic snapshots, but exclude only
  # Microsoft's ms-resource packaged-app rules from the equality assertion.
  # All other rules, including OTS-owned rules, must remain identical.
  $ignoreWindowsPackageRule = '^@\{Microsoft\.[^|]*\?ms-resource://'
  $baselineStable = @($before -split "`n" | Where-Object { $_ -notmatch $ignoreWindowsPackageRule })
  $currentStable = @($current -split "`n" | Where-Object { $_ -notmatch $ignoreWindowsPackageRule })
  $diff = Compare-Object -ReferenceObject $baselineStable -DifferenceObject $currentStable | Out-String -Width 1000
  if ($diff.Trim().Length -gt 0) {
    $diff | Set-Content "artifacts/firewall-difference-$Stage.log"
    throw "Stable firewall rules changed during $Stage. Difference: $diff"
  }
}
$policyPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'
$oldAutorun = (Get-ItemProperty $policyPath -Name NoDriveTypeAutoRun -ErrorAction SilentlyContinue).NoDriveTypeAutoRun
$oldNoAutorun = (Get-ItemProperty $policyPath -Name NoAutorun -ErrorAction SilentlyContinue).NoAutorun
$oldNonVolume = (Get-ItemProperty $policyPath -Name NoAutoplayfornonVolume -ErrorAction SilentlyContinue).NoAutoplayfornonVolume
$before = FirewallSnapshot baseline
$setup = (Resolve-Path artifacts/release/OTS-Firewall79X-Setup.exe).Path
$root = "$env:ProgramFiles\OTS Firewall79X"
$helper = "$root\recovery\OTS.Firewall79X.Recovery.exe"
Check 'Clean install with bundled runtimes' { RunExe $setup '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=artifacts/install.log'; if ((Get-Service OTSFirewall79X).Status -ne 'Running') { throw 'Service is not running' }; if ((Get-Service OTSFirewall79XWatchdog).Status -ne 'Running') { throw 'Watchdog is not running' } }
Check 'Real PE application and recovery binaries installed' { foreach ($file in @("$root\OTS Firewall79X.exe", $helper, "$root\service\OTS.Firewall79X.Service.exe")) { $b=[IO.File]::ReadAllBytes($file);if($b[0] -ne 77 -or $b[1] -ne 90){throw "Not PE: $file"} } }
Check 'UI launches and remains alive' { $ui=Start-Process "$root\OTS Firewall79X.exe" -PassThru;Start-Sleep -Seconds 5;if($ui.HasExited){throw 'UI exited unexpectedly'};Stop-Process -Id $ui.Id }
Check 'One-click activation' { RunExe $helper '--on --quiet';Start-Sleep -Seconds 8;if((Get-Service OTSFirewall79X).Status -ne 'Running'){throw 'Service stopped after activation'} }
Check 'Dark UI screens, compact layout, and search' { dotnet tests/OTS.Firewall79X.UiCapture/bin/Release/net10.0-windows/OTS.Firewall79X.UiCapture.dll artifacts/ui; if($LASTEXITCODE -ne 0){throw 'UI rendering failed'} }
$null=FirewallSnapshot after-ui
Check 'Windows telemetry, authenticated IPC and hostile framing' { dotnet tests/OTS.Firewall79X.WindowsTests/bin/Release/net10.0-windows/OTS.Firewall79X.WindowsTests.dll; if($LASTEXITCODE -ne 0){throw 'Windows integration probe failed'} }
Check 'Standard user can read status but cannot mutate protection' {
  $username = 'OTSProbeUser'
  $password = ConvertTo-SecureString ([Guid]::NewGuid().ToString('N') + 'Aa!79') -AsPlainText -Force
  New-LocalUser -Name $username -Password $password -AccountNeverExpires | Out-Null
  try {
    Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $username
    $cred = [pscredential]::new("$env:COMPUTERNAME\$username", $password)
    $dll = (Resolve-Path tests/OTS.Firewall79X.WindowsTests/bin/Release/net10.0-windows/OTS.Firewall79X.WindowsTests.dll).Path
    $dotnet = (Get-Command dotnet).Source
    $p = Start-Process -FilePath $dotnet -ArgumentList ('"' + $dll + '" --unprivileged') -Credential $cred -LoadUserProfile -Wait -PassThru
    if($p.ExitCode -ne 0){throw "Nonadministrator boundary probe failed: $($p.ExitCode)"}
  } finally { Remove-LocalUser -Name $username }
}
$null=FirewallSnapshot after-user-profile
Check 'Catalog and transaction self-check' { RunExe $helper '--selftest --quiet' }
Check 'Pause and resume commands' { RunExe $helper '--pause --quiet';RunExe $helper '--on --quiet' }
Check 'Off and recovery' { RunExe $helper '--off --quiet';RunExe $helper '--restore --quiet' }
Check 'Restoration preserves all original AutoRun and AutoPlay policies' {
  foreach ($pair in @(@('NoDriveTypeAutoRun',$oldAutorun),@('NoAutorun',$oldNoAutorun),@('NoAutoplayfornonVolume',$oldNonVolume))) {
    $props=Get-ItemProperty -Path $policyPath -Name $pair[0] -ErrorAction SilentlyContinue
    $current=if($null -ne $props){$props.PSObject.Properties[$pair[0]].Value}else{$null}
    if($current -ne $pair[1]){throw "Original $($pair[0]) policy was not restored"}
  }
}
Check 'Later independent changes are preserved on OFF' {
  RunExe $helper '--on --quiet'
  Set-ItemProperty $policyPath -Name NoDriveTypeAutoRun -Value 128 -Type DWord
  RunExe $helper '--off --quiet'
  if((Get-ItemProperty $policyPath -Name NoDriveTypeAutoRun).NoDriveTypeAutoRun -ne 128){throw 'Later external change overwritten'}
  if($null -eq $oldAutorun){Remove-ItemProperty $policyPath -Name NoDriveTypeAutoRun}else{Set-ItemProperty $policyPath -Name NoDriveTypeAutoRun -Value $oldAutorun -Type DWord}
}
Check 'Existing firewall rules preserved' { AssertFirewallUnchanged after-off }
Check 'Independent watchdog detects stopped primary and reports without UI' {
  Stop-Service OTSFirewall79X
  try {
    Start-Sleep -Seconds 80
    $incidents = @(Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=(Get-Date).AddMinutes(-5)} -ErrorAction Stop |
      Where-Object { $_.ProviderName -eq 'OTSFirewall79XWatchdog' -and $_.Message -like '*Independent watchdog*' })
    if ($incidents.Count -lt 1) { throw 'Watchdog did not record an independent outage' }
  } finally { Start-Service OTSFirewall79X }
}
Check 'Client rejects an impostor named-pipe server' {
  Stop-Service OTSFirewall79X
  try {
    dotnet tests/OTS.Firewall79X.WindowsTests/bin/Release/net10.0-windows/OTS.Firewall79X.WindowsTests.dll --impostor
    if($LASTEXITCODE -ne 0){throw 'Named-pipe server identity probe failed'}
  } finally { Start-Service OTSFirewall79X }
}
Check 'In-place upgrade preserves recoverability' { RunExe $setup '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=artifacts/upgrade.log';RunExe $helper '--on --quiet';RunExe $helper '--off --quiet' }
Check 'Clean uninstall removes service and application' { RunExe "$root\unins000.exe" '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART';if(Get-Service OTSFirewall79X -ErrorAction SilentlyContinue){throw 'Service remains'};if(Get-Service OTSFirewall79XWatchdog -ErrorAction SilentlyContinue){throw 'Watchdog remains'};if(Test-Path "$root\OTS Firewall79X.exe"){throw 'Application remains'} }
Check 'Firewall rules preserved after uninstall' { AssertFirewallUnchanged after-uninstall }
