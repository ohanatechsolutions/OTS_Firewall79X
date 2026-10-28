# Section D — Host and Endpoint Monitoring, Layers 25–40

**Scope:** read-only host evidence and conservative event-driven security indicators.
**Status:** development implementation; not fully accepted or production-certified.
**Working branch:** feat/section-d-host-endpoint-20261027

These improvements use built-in Windows registry, native event logs, WMI, filesystem metadata, and bounded inspection of installed Windows tools. No separate applications, subscriptions or manual dependencies are added.

## Layer-by-layer implementation and remaining gaps

| Layer | Delivered evidence / capability | Acceptance gaps (do not mark complete) |
|---|---|---|
| 25 Persistence / installation | Machine services/Run/software, loaded-user Run keys, scheduled-task definitions, multiple loaded-user browser extension directories, native task registration events | Task Scheduler effective registration/exec and unloaded profiles, actual browser extension integrity, hardware integration tests |
| 26 Kernel drivers / rootkits | Driver inventory, PnP IsSigned flags, CodeIntegrity warnings and service events | Signed-publisher chain, revocation, kernel-memory/rootkit sensor and comprehensive kernel integrity |
| 27 Privilege escalation | Additional real Windows account, group, policy, privilege-use and log-clear events | Required audit categories and complete account/domain/EDR event coverage |
| 28 Camera / microphone | Registry LastUsedTimeStart/Stop fingerprints across loaded users in service, independent of open UI | Windows privacy telemetry can lag or omit access; app attribution and device stream cross-validation |
| 29 Mining / resource abuse | Sustained CPU plus mining-associated process name or pool-port signal; no alert on CPU alone | Unrecognized miners, legitimate mining false positives, short-lived processes and full GPU metrics |
| 30 Runtime activity | Native System, Security, WMI-Activity, TaskScheduler, CodeIntegrity, PowerShell and Defender event subscriptions where enabled | ETW kernel coverage, event-loss verification, disabled policies and hardware evidence |
| 31 Browser session secrets | Windows Security 4663 audited read monitoring, unexpected reader attribution, private in-memory path fingerprints | Matching SACL must exist; complete access coverage and credible test cases |
| 32 Clipboard hijacking | Existing opt-in desktop address substitution heuristic without logging clipboard contents | Background per-user monitoring when app closed, process attribution, actual false-positive tests |
| 33 Trust configuration | Machine root store, hosts-file, DNS, loaded-user proxy registry fingerprints | Unloaded hives, per-user cert stores, active proxy resolution and trust-chain validation |
| 34 Bulk reads / outbound transfer | Genuine 4663 burst by process, PID correlation with currently established public TCP connections | Actual copy/upload cannot be proved; SACL coverage, event loss, encrypted cloud traffic and byte counts |
| 35 File integrity | SHA-256 change fingerprints of OTS assemblies, core Windows security binaries and hosts | Persistent signed golden baseline, complete paths, trusted software-update rebaselining |
| 36 Execution | 4688 native process/command-line indicators, suspicious script binaries, Office-to-script parent relationship; WMI events | Provider permissions, missing parent fields, short-lived events, richer ancestry rules |
| 37 Boot chain | Secure Boot and TPM/drive-security evidence plus read-only bcdedit options | Measured boot, firmware attestation, localized BCD handling, physical platform compatibility |
| 38 Keylogger / input hook | Narrow Defender malware detection event classification for keylogging-related threat names | **Major gap: does not enumerate or verify cross-process input hooks or unknown keyloggers.** |
| 39 Package sources | Machine root store, software inventory, Windows Update and AppInstaller policy-source fingerprints | Authenticode publisher verification, signed manifests, winget/user sources, certificate revocation |
| 40 Containers | Docker listener candidate identification plus bounded Docker daemon.json and loaded-user WSL distribution metadata | Effective daemon settings, exposed containers, named-pipe permissions, WSL2 networking, remote engines |

## Safety, privacy, and status integrity

All new logic is monitoring or auditing; it never enables system-wide object access auditing, modifies file SACLs, blocks traffic, terminates a process, reads clipboard secrets, enumerates keystrokes, or modifies boot configuration. Browser extension directories, startup values and user privacy records are fingerprinted to report configuration changes without placing their raw values in alert detail.

Presence of a subscribed event log is evidence only for the named event channel, not for complete threat detection. Unavailable prerequisite channels/audit policy report unavailable. A port binding or executable name is not a malware verdict. The block counter must never increment for monitoring alerts.

## Verification and release blockers

The core tests contain positive, negative and malformed-input cases for PID parsing, public-connection correlation, mining, Defender detection names, BCD policy parsing, Docker daemon settings and suspicious execution. The branch must also pass Windows CI build, installer lifecycle and service smoke checks. Windows 10 and Windows 11 physical-machine qualification, UI/background-agent lifecycle, full negative/false-positive testing, driver trust validation, and a supported layer-38 keylogger sensor are outstanding.

All Section D checklist boxes remain unchecked pending the original BUILD_SPECIFICATION and production acceptance gates. Mainline release must not be represented as complete based solely on these changes.
