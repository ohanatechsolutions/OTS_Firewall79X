# Section I — Layers 75–79: implementation and acceptance record

**Scope:** Additional Security Coverage. **Release status:** preview / limited until Windows CI and physical-device acceptance pass. None of these five layers replaces Microsoft Defender or the Windows firewall. See `docs/BUILD_SPECIFICATION.md`.

## 75 — Known-malicious domain blocking

- **Code:** `Core/AdditionalCoverage.cs`, `Windows/MaliciousDomainProtection.cs`, `Windows/EventSensors.cs`, `Windows/Engine.cs`, `App/MainWindow.xaml(.cs)`.
- **Source:** a public HTTPS, unauthenticated, URLhaus-derived host list from `malware-filter.gitlab.io`. The official URLhaus bulk API requires an authentication key. This independent redistribution is **not cryptographically signed by URLhaus**. The collector validates a recognized format, published timestamp, host syntax, URL and response-size budgets; rejects stale, malformed or sparse responses; never reuses a stale cached list. Source availability and redistribution terms are external dependencies.
- **Default:** **observation only**. Where enabled, Windows DNS Client Event 3008 lookups are compared to current exact-host indicators. No DNS interception or system setting change occurs during observation.
- **Enforcement:** after a clear GUI warning and administrator/UAC authorization, the `domains-on` command may add up to 1,000 exact hostnames to an isolated OTS-managed section in the Windows hosts file (`0.0.0.0` and `::` mappings). `domains-off`, turning off monitoring, recovery, startup after an interrupted session, and service shutdown remove *only* the managed section. Current hosts data is checked before atomic replacement; corrupted/modified managed markers abort automatic changes rather than overwriting others.
- **Allowlist:** optional `%ProgramData%\Ohana Tech Solutions\Firewall79X\domain-allowlist.txt` — one exact hostname or suffix per line, `#` comments. The service refuses malformed entries. Must be admin-managed under the protected product directory.
- **Limitations:** a hosts file is not a general DNS firewall. It does not catch unlisted subdomains, all encrypted DNS/DoH resolvers, or direct-IP connections. Feed payload has no independent publisher signature. Recovery requires healthy filesystem permissions; non-UTF-8 hosts files and external conflicts fail closed. A fail-safe feed-expiry rollback removes the owned block.

## 76 — Download, temporary and removable file scanning

- **Code:** `Windows/AdditionalHostMonitor.cs`; `App/UserMonitor.cs` remains an optional per-session collector.
- **Behavior:** the privileged background service watches discovered Windows user-profile Downloads and local Temp folders, plus ready removable drives. New or changed stable, regular files of up to 128 MiB are submitted to the **installed Microsoft Defender `MpCmdRun.exe`**, without a separate antivirus download. Bounded queue, size checks, symlink skips, de-duplication, timeout, file-event loss/overflow reporting.
- **Verdicts / quarantine:** Microsoft Defender, according to its installed policy, owns detection, remediation, quarantine and restoration via **Windows Security → Protection history**. OTS never moves or deletes suspect files or claims a clean scan from process-exit code alone. Monitoring is reported unavailable if the Defender CLI is absent.
- **Limitations:** file creation can outpace sampling; inaccessible, reparse, zero-byte, over-limit or already-existing files may be missed. Virus signatures and real-time AV status are controlled by Microsoft Defender; scanner process existence is not signature attestation.

## 77 — USB and removable device alerts

- **Code:** `Windows/AdditionalHostMonitor.cs`.
- **Behavior:** initial WMI `Win32_PnPEntity` inventory is the baseline. Service subscribes to `Win32_DeviceChangeEvent` and refreshes identity sets, reporting newly seen storage, HID/input and unknown USB device types. `Win32_VolumeChangeEvent` adds/removes removable-drive file watchers; periodic discovery is a fallback.
- **Safety:** **no** device disabling or blocking, especially keyboards or mice.
- **Limitations:** device class heuristics depend on Windows drivers; WMI provider failures and rapid disconnects can lose events. Not hardware qualified.

## 78 — Ransomware behavior monitoring

- **Code:** `Core/AdditionalCoverage.cs`, `Windows/AdditionalHostMonitor.cs`, existing `App/UserMonitor.cs`.
- **Behavior:** service-backed file observation across available user Documents/Downloads, local Temp, and removable drives. An alert requires **at least 35 distinct paths and 12 destructive renames/deletions within 15 seconds**; 750 ms same-file deduplication and 2-minute alert suppression reduce repetitive false positives. File changes to a preexisting `OTS-Firewall79X-Canary.txt` are called out separately.
- **Safety / limitations:** events are metadata-only; no automated process termination, rollback, or reading of user content. Canary presence depends on optional user-monitor setup. Normal bulk renames or sync tools can trigger warnings. USN-journal or minifilter completeness, ransomware adversarial tests, and causal process attribution remain outstanding.

## 79 — Beaconing detection

- **Code:** `Core/AdditionalCoverage.cs`, `Windows/LayerChecks.cs`.
- **Behavior:** on observed new established TCP connections, maintain bounded per-PID/process/destination histories; require at least nine samples spanning eight minutes, with a 30–1,800 second mean interval and below 12% timing variation. Exclude common browser/Windows background executables from the conservative timing classifier. Warnings explicitly state that periodic communication is **not a malware verdict**.
- **Limitations:** snapshot polling misses brief connections and all UDP; no ETW/WFP session telemetry or verified malicious endpoint attribution. PID reuse and intentional jitter may affect detection. The process exclusion list can hide a compromised benign process.

## Test plan and release gates

Unit regressions in `tests/OTS.Firewall79X.Tests/Program.cs` cover domain format and timestamp rejection, managed hosts-preservation and tamper refusal, destructive-file thresholds and false-positive suppression, and beacon classification. The Windows integration project has an isolated real Win32 File.Replace and restore fixture; it **never edits the host's actual system hosts file**.

Before marking any of 75–79 fully complete, the release owner must collect:
1. Passing GitHub Actions Windows build, unit/integration tests, installer, upgrade/uninstall/recovery checks, with an immutable run URL and artifact checksums.
2. Live Windows 10 and Windows 11 x64 physical-device tests, including Windows 11 Home, USB attach/detach across HID/storage types, offline and low-battery behavior.
3. Defender positive-malware test using safe authorized AV test material and Protection History verification; high-rate download and temp-folder overflow recovery tests.
4. Reversible domain enforcement tests against a safe controlled test name and explicit allowlist, preexisting hosts file, power loss, Windows Update, DoH bypass and no-network failure.
5. Adversarial ransomware workload vs safe bulk renaming and backup workloads; beaconing vs common periodic applications; measurable false-positive and CPU/memory budgets.

**No standalone Section I certificate is claimed merely because these components build.**
