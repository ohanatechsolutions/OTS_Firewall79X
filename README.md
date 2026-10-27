# OTS Firewall79X

Native Windows desktop security application by **Ohana Tech Solutions**.

**Status: incomplete development preview, version 0.1.0. Not a production security release.** The original [79-layer specification](docs/BUILD_SPECIFICATION.md) remains the acceptance target. [Coverage and gaps](LAYER_COVERAGE.md) distinguish limited implementations from missing capabilities. No claim is made that all 79 layers are complete.

## Install and use

When a verified release is available, download `OTS-Firewall79X-Windows-x64.zip` from [Releases](https://github.com/ohanatechsolutions/OTS_Firewall79X/releases), extract it, and run `OTS-Firewall79X-Setup.exe`. The ZIP contains a compiled installer, not just source code. Approve Windows UAC, open the desktop shortcut, and select **Turn ON**. The installer bundles the .NET runtime and registers the background service. No SDK, Python, Docker, account, API key, browser extension, or manual component setup is required.

The current preview is unsigned. Its build/install verification status is documented in [TEST_RESULTS.md](TEST_RESULTS.md). Do not treat a checksum as publisher authentication.

## Implemented behavior

- Native WPF dashboard, full numbered layer catalog, event history, per-process TCP table, reports, optional user-session tools, and separate recovery executable.
- Windows service with local ACL-protected named pipes; mutation requires an elevated administrator token. The GUI itself is not elevated.
- Existing Windows Firewall policy inspection and exact-match conflict analysis. Firewall rules and profile defaults are not overwritten.
- Reversible AutoRun hardening using a durable intent journal and compare-before-restore semantics.
- Event Log subscriptions, services/drivers/accounts/USB inventory, connection and ARP baselines, narrow detection heuristics, and loopback-only canaries.
- Optional current-user filesystem, camera/microphone registry, clipboard-address, browser-extension inventory, and native Defender scan requests.
- Selected-folder secret-indicator scan, optional Pwned Passwords range check, reports, authenticated encrypted report archives, and versioned selected-folder backups with verified non-overwriting restore.

## System requirements

x64 Windows 11, or compatible Windows 10 builds (installer minimum 1809). Microsoft currently supports .NET 10 only on particular Windows editions/versions; Windows 10 Home compatibility and Windows 10/11 hardware testing are **not yet verified**. Windows Server 2025 CI is not a substitute for those tests. Administrator rights are required for installation and protected actions. Microsoft Defender-dependent features require its supported APIs/components. Optional breach queries require internet; baseline local monitoring does not.

## Controls and status

ON starts the service collectors and journaled AutoRun hardening. OFF and Restore undo only settings still equal to OTS-applied values. Pause records a 15-minute deadline. Existing independent Windows security remains active when OTS is off. The preview deliberately reports **Partially Protected** while features remain incomplete. Capability score measures declared layer health, not a probability of protection. Actual OTS block count remains zero because this preview does not install a network blocking engine. Observed Windows blocks are separately described in events.

Interactive monitors require the app to remain open and the opt-in checkbox. No clipboard contents or plaintext matched secrets are written to logs. Reports can include IP addresses and file locations. Protected service data is stored under ProgramData/Ohana Tech Solutions/Firewall79X, with SYSTEM/administrators-only access.

## Recovery and uninstall

Use **Settings & Recovery → Restore previous configuration**, or the separate Start menu recovery shortcut. [Offline recovery instructions](docs/RECOVERY.md) describe stopping a failed service and restoring owned settings without deleting unrelated firewall rules. Standard Windows Apps uninstall runs restoration before removing binaries. Protected logs and journals are retained for diagnostics; no personal files are deleted. Upgrade stops/restores the old instance before replacing files; re-enable afterward.

## Developer builds

Build requirements apply to contributors, not installed users: pinned .NET SDK 10.0.403 and Inno Setup 6 on Windows. Run `scripts/build.ps1`; `scripts/windows-smoke.ps1` is restricted to disposable GitHub Actions runners. Dependencies are locked. `dotnet run --project tests/OTS.Firewall79X.Tests -c Release` executes core regressions. CI produces an installer, release ZIP, SBOM, checksums, build manifest, and real result files.

See [architecture](docs/ARCHITECTURE.md), [limitations](KNOWN_LIMITATIONS.md), [dependencies](EXTERNAL_TOOLS.md), and [security reporting](SECURITY.md).
