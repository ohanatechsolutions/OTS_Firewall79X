# OTS Firewall79X

Native Windows desktop security application by **Ohana Tech Solutions**.

**Status: incomplete development preview, version 0.1.0. Not a production security release.** The original [79-layer specification](docs/BUILD_SPECIFICATION.md) remains the acceptance target. [Coverage and gaps](LAYER_COVERAGE.md) distinguish limited implementations from missing capabilities. No claim is made that all 79 layers are complete.

## Install and use

**Do not install from GitHub's Code → Download ZIP or Source code ZIP.** These are *source archives*, and the LFS-backed `.exe` can be a 134-byte pointer that Windows cannot execute. For an actual standalone compiled installer, download **OTS-Firewall79X-Windows-x64.zip** or **OTS-Firewall79X-Setup.exe** from [Releases](https://github.com/ohanatechsolutions/OTS_Firewall79X/releases). Extract the release ZIP, open **installer/**, and double-click **OTS-Firewall79X-Setup.exe**. See [installer instructions](installer/README.md). The release ZIP contains the real installer plus its matching `.sha256` file. Approve Windows UAC, open the desktop shortcut, and select **Turn ON**. The installer bundles the .NET runtime and registers the background service. No SDK, Python, Docker, account, API key, browser extension, or manual component setup is required.

After a passing Windows CI build, the [`installer/`](installer/) directory contains `OTS-Firewall79X-Setup.exe` tracked with Git LFS and its matching `OTS-Firewall79X-Setup.exe.sha256`. A normal GitHub source ZIP may provide only a non-executable LFS pointer; download the release asset instead, or use `git lfs pull` if you are a developer cloning the repository. From the `installer` folder, verify the download with `Get-FileHash .\OTS-Firewall79X-Setup.exe -Algorithm SHA256` and compare it with the `.sha256` file.

The current preview is unsigned. Its build/install verification status is documented in [TEST_RESULTS.md](TEST_RESULTS.md). Do not treat a checksum as publisher authentication.

## Implemented behavior

- Native WPF dashboard, full numbered layer catalog, event history, rate-limited desktop alerts, per-process TCP table, reports, optional user-session tools, and separate recovery executable.
- Windows service with local ACL-protected named pipes; mutation requires an elevated administrator token. The GUI itself is not elevated.
- Existing Windows Firewall policy inspection and exact-match conflict analysis. Firewall rules and profile defaults are not overwritten.
- Reversible AutoRun hardening using a durable intent journal and compare-before-restore semantics.
- Read-only UAC, DEP, LSA protection, and SMBv1 server-hardening indicators with explicit unknown statuses (not a full host hardening assessment).
- HMAC authentication of retained security-log entries on service startup; chained records now continue across restarts. Legacy unlinked segments are disclosed.
- Event Log subscriptions, services/drivers/accounts/USB inventory, connection and ARP baselines, narrow detection heuristics, and loopback-only canaries.
- Conservative OpenSSH server configuration review with first-value semantics and explicit Include/Match uncertainty; Docker-management TCP 2375/2376 listener exposure audits distinguish loopback and network-visible bindings (read-only; neither feature changes services).
- Automatic when protection is ON: read-only HTTPS Feodo Tracker recommended IPv4 C2 intelligence: bounded and date-validated input, periodic refresh, matching against observed established TCP destinations, and high-priority alerts. It does not add firewall rules; a stale or unavailable source is explicitly reported.
- Conditional Windows DNS Client Event 3008 query-result correlation: warns when the same external domain quickly changes from a public to a private/local address (layer 8), without blocking or changing DNS. Split-DNS/VPN setups can produce legitimate alerts. The DNS channel is not silently enabled.
- Conditional native Windows Event 4663 file-read telemetry for browser credential/session storage (layer 31) and per-process high-volume file-read alerts (layer 34), **only where existing Windows Audit File System policy and matching SACLs generate events**. No secrets or file contents are collected; neither detector proves exfiltration.
- Optional current-user filesystem, camera/microphone registry, clipboard-address, browser-extension inventory, and native Defender scan requests.
- Selected-folder secret-indicator scan, optional Pwned Passwords range check, reports, authenticated encrypted report archives, and versioned selected-folder backups with verified non-overwriting restore.

## Desktop UI and branding

The WPF client has seven dark slate (#0F172A / #1E293B) security screens, steel-blue (#34587C) accents, rounded glass-style cards, a live shield status badge, event feed, searchable security layers, high-contrast data grids, native dark window chrome and visible development-preview notices. The interface displays actual local service evidence rather than invented protection percentages. The original high-resolution supplied artwork lives in `src/OTS.Firewall79X.App/Assets/`: `Brand.png` is the in-app logo; `Brand.ico` is used by the Windows executable, title bar, recovery executable, installer, shortcuts and notification area. The earlier `AppLogo.png` and `AppIcon.ico` assets remain in the repository as alternate source artwork, without overriding active branding. This is a firewall product; the visual refresh does not add clipboard-history storage or synchronization. CI exercises all seven screens, a compact layout and layer search, and creates PNG previews in build artifacts.

## System requirements

x64 Windows 11, or compatible Windows 10 builds (installer minimum 1809). Microsoft currently supports .NET 10 only on particular Windows editions/versions; Windows 10 Home compatibility and Windows 10/11 hardware testing are **not yet verified**. Windows Server 2025 CI is not a substitute for those tests. Administrator rights are required for installation and protected actions. Microsoft Defender-dependent features require its supported APIs/components. Optional breach queries require internet; baseline local monitoring does not.

## Controls and status

ON starts the service collectors and journaled AutoRun hardening. OFF and Restore undo only settings still equal to OTS-applied values. Pause records a 15-minute deadline. Existing independent Windows security remains active when OTS is off. The preview deliberately reports **Partially Protected** while features remain incomplete. Capability score measures declared layer health, not a probability of protection. Actual OTS block count remains zero because this preview does not install a network blocking engine. Observed Windows blocks are separately described in events.

Interactive monitors require the app to remain open and the opt-in checkbox. No clipboard contents or plaintext matched secrets are written to logs. Reports can include IP addresses and file locations. Protected service data is stored under ProgramData/Ohana Tech Solutions/Firewall79X, with SYSTEM/administrators-only access.

## Recovery and uninstall

Use **Settings & Recovery → Restore previous configuration**, or the separate Start menu recovery shortcut. [Offline recovery instructions](docs/RECOVERY.md) describe stopping a failed service and restoring owned settings without deleting unrelated firewall rules. Standard Windows Apps uninstall runs restoration before removing binaries. Protected logs and journals are retained for diagnostics; no personal files are deleted. Upgrade stops/restores the old instance before replacing files; re-enable afterward.

## Developer builds

Build requirements apply to contributors, not installed users: pinned .NET SDK 10.0.403 and Inno Setup 6 on Windows. Run `scripts/build.ps1`; `scripts/windows-smoke.ps1` is restricted to disposable GitHub Actions runners. Dependencies are locked. `dotnet run --project tests/OTS.Firewall79X.Tests -c Release` executes core regressions. CI produces an installer, release ZIP, SBOM, checksums, build manifest, screen previews, and real test result files.

See [architecture](docs/ARCHITECTURE.md), [limitations](KNOWN_LIMITATIONS.md), [dependencies](EXTERNAL_TOOLS.md), and [security reporting](SECURITY.md).
