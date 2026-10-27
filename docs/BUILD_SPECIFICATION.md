# OTS Firewall79X
## MASTER AI SOFTWARE DEVELOPMENT, INTEGRATION & DELIVERY PROMPT

**Developer:** Ohana Tech Solutions (Ohana Tech)  
**Product:** OTS Firewall79X  
**Application Type:** Native Windows Desktop Security Application  
**Target:** Windows 10 / Windows 11 — 64-bit  
**Final Application Format:** `.exe`  
**Installer Format:** `.exe`  
**GitHub Destination:** Existing `OTS Firewall79X` repository under the Ohana Tech Solutions GitHub account  
**Development Objective:** Complete, functional, fully integrated, production-ready software.

---

# 1. ROLE & MISSION

Act as a Principal Software Engineer, Senior Windows Systems Developer, Cybersecurity Architect, DevSecOps Specialist, Quality Assurance Engineer, Release Engineer, and Technical Documentation Engineer.

Your mission is to **design, develop, integrate, compile, test, package, and deliver OTS Firewall79X as a complete, operational Windows desktop application.**

You are responsible for the entire software development lifecycle.

**This is an execution and delivery assignment, not merely a request for a software architecture, prototype, demonstration, or collection of source-code examples.**

The final deliverable must be an actual Windows application that I can download from GitHub, install, launch, and use without performing development work myself.

## Absolute Development Mandate

You must independently perform all work required to produce the finished application, including:

1. Architecture and software design.
2. Complete source-code development.
3. All 79 security-layer implementations.
4. Windows operating-system integration.
5. User-interface development.
6. Privileged background-service development.
7. Dependency management and integration.
8. Security testing and error handling.
9. Unit, integration, regression, and end-to-end testing.
10. Automated build and compilation.
11. Installer creation.
12. Complete application packaging.
13. Documentation and recovery procedures.
14. GitHub repository organization and synchronization.
15. Final Windows executable and installation verification.
16. Release publishing and delivery.

**Do not transfer any of these development responsibilities to me.**

Do not ask me to manually write code, create configuration files, compile executables, install development environments, run build scripts, configure services, or assemble components.

Make reasonable engineering decisions independently and document them in `ASSUMPTIONS.md`.

Continue through all implementation and verification phases using the tools and permissions available to you.

Do not stop at a prototype or claim completion because the source code has been written.

If an external permission, unavailable tool, inaccessible repository, required signing certificate, or other genuine blocker prevents completion, explain the specific blocker accurately. Never claim you performed an action you could not perform.

---

# 2. THE FINISHED-PRODUCT REQUIREMENT

## What I Expect to Receive

I want **OTS Firewall79X to be a complete install-and-run Windows application.**

My entire installation experience should be:

1. Open the OTS Firewall79X GitHub repository.
2. Download the finished Windows release ZIP.
3. Extract the ZIP using Windows' built-in extraction capability.
4. Double-click `OTS-Firewall79X-Setup.exe`.
5. Complete the standard Windows installer, approving the administrator prompt if required.
6. Launch OTS Firewall79X from the desktop or Start menu.
7. Click the main **ON** button to activate the available security stack.

**That is the full experience.**

No compiling, coding, manual dependency setup, developer tools, command-line installation, or third-party software configuration should be necessary.

### Mandatory Executable Requirements

The finished software must provide:

- `OTS Firewall79X.exe` — the actual desktop application.
- `OTS-Firewall79X-Setup.exe` — the actual Windows installer.
- A ready-to-install ZIP containing the finished installer and any necessary release documentation.
- All required background services and supporting components installed automatically.
- Automatic creation of desktop and Start menu shortcuts.
- Standard Windows uninstall support.
- A working update and upgrade mechanism.
- Safe preservation of the user's original system configuration.

The `.exe` must be a genuine compiled Windows executable, not a renamed script, `.iss` file, `.bat`, `.ps1`, `.py`, or source-code launcher.

An installer configuration file is not an acceptable substitute for a compiled installer.

A GitHub Actions workflow that *could* eventually build an installer is not an acceptable substitute for delivering that installer.

The finished executable must actually exist and be included in the final release.

---

# 3. SELF-CONTAINED SOFTWARE — NO EXTERNAL SETUP

## Zero Manual Dependencies

The application must be self-contained from the end user's perspective.

**I do not want to install, connect, subscribe to, configure, or maintain additional applications to make OTS Firewall79X operational.**

Specifically, installation and normal use must not require me to separately install or configure:

- Python or Python packages.
- Node.js or npm.
- Go, Rust, or development toolchains.
- Visual Studio or the .NET SDK.
- Docker, WSL, or virtual machines.
- Suricata.
- Zeek.
- ClamAV.
- YARA.
- Sysmon.
- Additional firewall software.
- External dashboard software.
- Separate database servers.
- Browser extensions.
- Cloud accounts.
- API keys or paid subscriptions.
- External monitoring agents.
- GitHub authentication for normal application use.

### Dependency Integration Policy

You may use established open-source libraries, security engines, and existing Windows capabilities when appropriate.

However, every required component must be:

1. Built into OTS Firewall79X;
2. Bundled with its installer and configured automatically; or
3. Supplied by Windows itself and accessed through supported native interfaces.

Do not require the user to manually install these components.

Do not download executable dependencies on first launch. The release package must contain the components required for baseline operation.

Security intelligence updates may use an internet connection when available, but the essential local protection features must continue operating when offline.

Any third-party component must be evaluated for Windows compatibility, licensing, redistribution rights, security maintenance, and resource consumption.

Do not introduce additional software merely because it appears in the original layer descriptions. Prefer native Windows capabilities when they provide equivalent functionality.

If a capability genuinely requires an external service, hardware device, account, or third-party infrastructure that cannot be bundled, implement any meaningful local functionality available and explicitly identify the remaining limitation. Never simulate the missing service or falsely advertise full protection.

### Native Windows Integration

Prefer Windows-native functionality using:

- Windows Filtering Platform (WFP).
- Windows Defender Firewall APIs.
- Windows Event Log and Event Tracing for Windows (ETW).
- Windows Security and Microsoft Defender interfaces where supported.
- Windows Service Control Manager.
- Windows Task Scheduler when appropriate.
- Windows Credential Manager and DPAPI.
- Windows Cryptography APIs.
- Windows notification APIs.
- Supported Windows networking and process-monitoring interfaces.

Do not replace or disable existing Windows security products simply to accommodate OTS Firewall79X.

---

# 4. REQUIRED TECHNOLOGY & APPLICATION FORMAT

## Primary Platform

Develop OTS Firewall79X specifically for:

- Windows 10, 64-bit.
- Windows 11, 64-bit.

Windows is the primary and required platform.

Do not prioritize Linux or macOS at the expense of completing the Windows application.

Architectural support for other operating systems may be considered later, but it must not introduce incomplete Windows features or additional setup requirements.

## Recommended Implementation

Use a native Windows-oriented architecture.

Preferred technology:

- **Application/UI:** C# with WPF and an actively supported .NET LTS release.
- **Background service:** C# Windows Service, with a small privileged native component only where necessary.
- **Networking and firewall control:** Windows Filtering Platform and supported Windows Firewall APIs.
- **Local storage:** Embedded SQLite or an equivalent database requiring no separate server.
- **Configuration:** Built-in validated configuration with safe defaults.
- **Installer:** A professional compiled Windows `.exe` installer.
- **Build system:** Automated Windows GitHub Actions workflows.

You may choose a more appropriate implementation if there is a strong technical reason, but it must still deliver a self-contained Windows desktop application without additional runtime installation steps.

Bundle the required .NET runtime with the installer where necessary.

A browser-based dashboard or localhost website must not substitute for the desktop application.

The application must include its own native graphical interface.

A command-line interface may be included for advanced administration, troubleshooting, and recovery, but must never be required for ordinary use.

---

# 5. PRODUCT CONCEPT — THE ONE-BUTTON SECURITY STACK

OTS Firewall79X is a layered defense-in-depth application designed to monitor, harden, and protect a computer owned and administered by the user.

The central concept is simple:

**ONE LARGE ON/OFF BUTTON CONTROLS THE ENTIRE SECURITY STACK.**

The application contains 79 defined security layers, grouped into nine categories.

The user should not need to understand individual firewall rules, command-line settings, network interfaces, threat feeds, or operating-system internals.

## Main Dashboard

The primary window must provide:

- One large, clearly labeled **ON/OFF** security toggle.
- Overall protection status.
- Live security posture score from 0 to 100.
- Live blocked-threat counter.
- Live security-event counter.
- Current protection health.
- Current system resource consumption.
- Last successful security update.
- A visible warning when any important protection layer is unavailable.

### Protection Status

Use the following honest status states:

**Fully Protected** — all required and applicable core protection layers are operational according to their declared mode.

**Partially Protected** — one or more applicable protection layers are unavailable, degraded, improperly configured, or awaiting a necessary prerequisite.

**Not Protected** — the application's protection stack is disabled.

The dashboard must never claim that the computer is completely immune to malware, hacking, or other threats.

A layer that is monitoring traffic must not be represented as actively blocking traffic.

An observed threat must not increase the blocked-threat counter unless a real blocking action occurred.

## Details Tab

Provide:

- All 79 layers with their names and descriptions.
- Current per-layer activation state.
- Operating mode: enforcing, monitoring, auditing, idle, unavailable, or not applicable.
- Layer-specific settings and toggles.
- Detected threats.
- Actual blocked threats.
- Security event history.
- Rule activity.
- CPU and RAM utilization.
- Resource consumption by individual layer.
- Last successful layer health check.
- Errors and recovery suggestions.

## Additional Interface Sections

Include a clean, modern layout with:

1. Dashboard.
2. Security Layers.
3. Threat Activity.
4. Network Activity.
5. System Health.
6. Reports.
7. Settings.
8. Recovery and Restore.
9. About OTS Firewall79X.

Maintain a lightweight interface with subtle, professional Ohana Tech Solutions branding.

No advertising, upselling, mandatory registration, or third-party account creation.

---

# 6. THE ONE-CLICK ACTIVATION MANDATE

After installation, clicking **ON** must automatically:

1. Request Windows administrator elevation through the normal Windows security interface where necessary.
2. Detect the Windows version and system capabilities.
3. Identify active network adapters.
4. Detect the current gateway, DNS servers, and local network.
5. Identify existing firewall policies and essential network services.
6. Determine which of the 79 layers apply.
7. Generate necessary local configuration automatically.
8. Create encrypted local application secrets where required.
9. Snapshot all operating-system settings the application intends to modify.
10. Start the required background services.
11. Activate applicable monitoring and auditing layers.
12. Activate only enforcement rules that pass defined safety checks.
13. Start the resource governor.
14. Start protection health monitoring.
15. Start the security-event processing pipeline.
16. Calculate the initial security posture score.
17. Display the resulting protection status.

The user must not need to configure individual layers.

### Automatic Detection

The application must intelligently detect when a security layer does not apply.

Examples:

- No containers installed.
- No Bluetooth adapter.
- No SSH server.
- No removable storage connected.
- No secondary backup drive.
- No external log destination.
- No user-provided credentials for breach checking.

Such layers must report their actual status rather than generate errors or claim nonexistent protection.

An unavailable capability must never be marked as implemented or healthy through placeholder results.

### Observe-Then-Enforce

Any security layer that could interrupt normal system or network activity must support safe initial observation.

The application must gather adequate evidence and verify connectivity before applying automatic blocks.

If safety or confidence requirements cannot be satisfied, the layer must remain in monitoring mode and report that condition.

Do not arbitrarily promote a layer into enforcement based solely on elapsed time.

---

# 7. SAFETY, SYSTEM INTEGRITY & AUTOMATIC RESTORATION

These requirements are mandatory.

They are foundational application features and are not counted among the 79 layers.

## 7.1 Prevent Administrative Lockout

OTS Firewall79X must avoid interrupting the current administrator session, required management connections, gateway access, DNS resolution, and essential local networking.

Before modifying firewall rules, identify:

- Existing network policies.
- Required administrative access.
- Existing established connections.
- Locally hosted services.
- Network interfaces and routes.
- Known trusted networks.
- Existing system firewall exceptions.

Do not apply broad rules that unnecessarily expose the computer or allow all local-network traffic without security justification.

## 7.2 Snapshot Before Modification

Before changing any operating-system configuration, save a validated snapshot of all settings the application will modify.

Maintain a transaction journal of changes.

Support:

- Pre-activation snapshots.
- Per-change rollback.
- Full application rollback.
- Recovery after unexpected termination.
- Recovery after an interrupted installation.
- Recovery after an unsuccessful upgrade.

**OFF must undo OTS Firewall79X's own modifications without destroying legitimate changes made afterward by Windows, the user, or other software.**

Do not blindly overwrite newer third-party settings in an attempt to restore an older snapshot.

## 7.3 Automatic Safety Rollback

After applying an enforcing change:

- Verify network connectivity.
- Verify gateway reachability.
- Verify DNS resolution.
- Verify applicable administrator-management access.
- Verify critical application services.

If an essential health check fails, automatically revert the last unsafe change.

Use a short recovery timeout, configurable with a safe default.

Do not require the user to find and manually delete firewall rules.

## 7.4 Emergency Recovery

Include:

- An emergency **Restore Previous Configuration** button.
- A corresponding recovery CLI command.
- A separate recovery executable.
- A recovery mechanism accessible if the main interface fails.
- Boot-time recovery procedures.
- A reliable method to disable only rules created by OTS Firewall79X.

Recovery must not indiscriminately remove rules belonging to Windows or other installed software.

## 7.5 Protection Against Unauthorized Changes

Use appropriate Windows administrator authorization for operations that modify protected system configuration.

Use Windows UAC and supported Windows access-control mechanisms.

Do not build a custom password collection interface that imitates Windows authentication.

Provide a protected **Pause for 15 Minutes** option.

## 7.6 Fail-Safe Operation

If the application crashes:

- Preserve essential existing Windows protection.
- Avoid network lockout.
- Attempt safe service recovery.
- Record the failure.
- Restore unsafe or incomplete transactions.
- Show the correct protection status afterward.

Do not assume that fail-closed behavior is always safer. Preserve essential connectivity and recovery access while avoiding unwanted exposure.

## 7.7 No Unnecessary Disruption

Do not implement aggressive or high-false-positive enforcement such as:

- Blanket outbound blocking.
- Geographic IP blocking.
- Mandatory VPN routing.
- VPN kill switches.
- Blanket USB-device blocking.
- Broad application allowlisting.
- Forced DNS-provider replacement.
- Automatic process termination without narrowly defined authorization.
- Disabling essential Windows services.

All actions must prioritize reversibility, compatibility, low false positives, and system stability.

---

# 8. COMPLETE SECURITY ARCHITECTURE

## 8.1 Modular Layer Framework

Each security layer must use a standardized interface containing:

- Unique layer ID.
- Layer name.
- Security category.
- Description.
- Operating mode.
- Priority.
- Windows compatibility.
- Hardware and service prerequisites.
- Friction and operational risk level.
- Enable operation.
- Disable operation.
- Health check.
- Status reporting.
- Statistics.
- Resource consumption.
- Error handling.
- Rollback behavior.
- Test interface.

Layers must be independently maintainable and testable.

A layer must not be marked operational merely because its module loads.

Verify that the underlying monitoring or protection mechanism is actually functioning.

## 8.2 Layer Manager

Implement centralized orchestration that:

- Starts layers in the appropriate dependency order.
- Detects conflicting policies.
- Manages layer lifecycle.
- Performs health checks.
- Coordinates rule updates.
- Prevents duplicate enforcement.
- Throttles expensive operations.
- Records errors.
- Reports accurate status.
- Restarts failed components when safe.
- Coordinates clean shutdown and rollback.

## 8.3 Privilege Separation

Keep the desktop UI and untrusted data-processing components separate from privileged system operations.

Use a narrow, authenticated local communication interface with appropriate Windows ACLs.

Do not expose the privileged component through an unauthenticated local web server.

## 8.4 Performance Management

Optimize for an ordinary Windows home or work computer.

Do not continuously run every heavyweight security analyzer at maximum intensity.

The resource governor must dynamically manage CPU, memory, disk activity, and battery usage.

Use event-driven monitoring wherever possible.

Support reduced-impact operation when the laptop is on battery power.

Provide accurate resource statistics rather than invented per-layer metrics.

## 8.5 Reliable Local Storage

Use structured logs, an embedded event database, and bounded storage policies.

Log files must support:

- Rotation.
- Compression.
- Disk-space limits.
- Tamper-evidence where feasible.
- Safe handling of sensitive information.
- Retention settings.
- Export for troubleshooting.

---

# 9. THE COMPLETE 79-LAYER SECURITY CATALOG

**All 79 numbered layers below are mandatory development scope.**

Preserve the functionality and numbering of the original catalog.

Windows-native implementations are preferred. Cross-platform tools mentioned below are implementation references, not mandatory separately installed programs.

Each layer must have meaningful working functionality, actual telemetry where appropriate, tests, and a documented operational status.

Do not silently omit layers.

Do not substitute simulated statistics, fake detections, or placeholder code for implementation.

## A. Network Protection — Layers 1–10

**1. Default-Deny Inbound Firewall**

Stateful inbound filtering that protects unsolicited inbound connections while preserving explicitly authorized services and required connectivity.

**2. Rate Limiting and Flood Protection**

Protect against excessive connection attempts, SYN floods, ICMP abuse, UDP floods, and other detectable network-level resource abuse using supported Windows facilities.

**3. Port Scan Detection**

Detect suspicious scanning behavior and apply safe, expiring source restrictions where reliable and supported.

**4. Anti-Spoofing and Malformed Packet Filtering**

Detect or reject supported spoofed, malformed, or clearly invalid traffic without breaking legitimate fragmentation or network protocols.

**5. Threat-Intelligence IP Blocking**

Integrate verified, reputable intelligence sources such as Spamhaus and abuse.ch. Apply high-confidence restrictions only, with freshness, false-positive, and essential-network safeguards.

**6. IPv6 Protection Parity**

Ensure appropriate IPv6 monitoring and protection rather than securing only IPv4.

**7. Cloud Metadata Endpoint Protection**

Protect access to cloud metadata addresses such as `169.254.169.254` when relevant. Avoid unnecessary system-wide changes on ordinary home PCs.

**8. DNS Rebinding Protection**

Detect suspicious DNS responses that could expose local resources. Apply blocking only when supported safely and without breaking legitimate internal-domain resolution.

**9. Untrusted Network Protection**

Recognize trusted and untrusted network profiles and apply safer inbound policies on public or unfamiliar Wi-Fi, including compatible Windows sharing controls.

**10. Bluetooth Security Monitoring**

Monitor unexpected Bluetooth pairing, connections, and discoverability, applying supported reversible hardening where appropriate.

## B. Deception — Layers 11–13

**11. Honeytokens and Canary Files**

Create isolated decoy credentials and files, monitor access, and generate high-severity alerts. Never create functioning credentials or expose real secrets.

**12. Canary DNS and URLs**

Implement local canary access monitoring and provide externally reachable canary functionality only when a suitable endpoint actually exists. Never claim off-machine monitoring from a purely local implementation.

**13. Decoy Services and Honeypots**

Provide isolated, low-risk decoy listeners or simulated services on unused ports, with event capture, safety restrictions, and optional expiring source bans. Avoid exposing vulnerable real services.

## C. Network and Traffic Visibility — Layers 14–24

**14. Intrusion Detection**

Integrate a Windows-compatible intrusion detection engine or equivalent established detection capability. Support validated detection rules and updates.

**15. Network Metadata and Attack Classification**

Collect available network telemetry and correlate relevant events to recognizable attack behaviors and MITRE ATT&CK techniques.

**16. Connection and DNS Journal**

Record supported per-process network connections and DNS observations. Detect unusual outbound destinations, tunneling indicators, and first-time connection behavior.

**17. ARP Spoofing Alerts**

Detect suspicious ARP changes and possible local-network interception attempts.

**18. Rogue DHCP and Evil-Twin Wi-Fi Detection**

Detect suspicious DHCP or wireless-network changes using telemetry actually available from Windows and the installed wireless adapter.

**19. Listening Port and Attack-Surface Monitor**

Identify listening ports and services. Alert when new services unexpectedly begin accepting connections.

**20. New LAN Device Alerts**

Observe and report newly discovered local-network devices using passive telemetry and safe network discovery where enabled.

**21. Unsafe Network Alerts**

Warn when connected to open, obsolete, or otherwise weakly secured wireless networks.

**22. Suspicious SMTP Activity**

Identify unexpected outbound SMTP activity from applications not normally associated with email transmission.

**23. Remote-Access Monitoring**

Detect newly enabled or installed remote-management services, including RDP, VNC, and recognizable remote-support applications.

**24. Clock Drift Monitoring**

Detect material system clock drift or suspicious time changes that could affect security verification and logs.

## D. Host and Endpoint Monitoring — Layers 25–40

**25. Persistence and Software Installation Monitoring**

Track new services, scheduled tasks, startup entries, browser extensions where accessible, and installed software or drivers.

**26. Rootkit and Kernel Driver Monitoring**

Monitor suspicious driver installation and available Windows kernel-integrity indicators using supported APIs and established tools where bundled.

**27. Privilege Escalation Monitoring**

Alert on new administrator accounts, unexpected privilege changes, security-policy changes, and suspicious elevation events.

**28. Camera and Microphone Access Alerts**

Use supported Windows privacy and device-access telemetry to identify unexpected camera or microphone activity.

**29. Cryptominer and Resource-Abuse Detection**

Detect patterns of suspicious sustained resource consumption, mining-related behavior, and unauthorized compute activity.

**30. Runtime and System Activity Monitoring**

Use Windows Event Log, ETW, security auditing, and optionally bundled supported monitoring components to observe relevant runtime activity.

**31. Browser Credential and Session Protection**

Detect suspicious access to browser credential and session storage using available filesystem and process telemetry without reading or transmitting actual secrets unnecessarily.

**32. Clipboard Hijacking Detection**

Detect supported indicators of malicious clipboard modification, including unexpected changes to copied payment or cryptocurrency addresses. Preserve clipboard privacy.

**33. System Trust Configuration Monitoring**

Watch trusted root certificates, proxy settings, hosts-file changes, and network or DNS configuration tampering.

**34. Bulk-Copy and Exfiltration Alerts**

Detect suspicious high-volume copying or movement of protected files where sufficient telemetry exists. Do not falsely claim complete visibility into encrypted cloud transfers.

**35. File and Binary Integrity Monitoring**

Monitor selected system files, application binaries, startup configuration, and critical security settings. Alert on unexpected modifications.

**36. Suspicious Execution Monitoring**

Detect relevant abuse patterns involving PowerShell, WMI, script hosts, suspicious command lines, process relationships, user-writable execution paths, disguised executables, and other detectable malicious execution behavior.

**37. Boot-Chain Integrity Monitoring**

Monitor available Secure Boot, TPM, boot-configuration, and startup-integrity indicators.

**38. Keylogger and Input-Hook Detection**

Detect suspicious input-monitoring behavior where supported. Clearly disclose any Windows telemetry limitations.

**39. Package and Software Source Integrity**

Monitor relevant software repositories, trusted publishers, package-source configuration, and certificate or update-source changes.

**40. Container Exposure Audit**

Check locally installed container platforms, where present, for exposed management interfaces, unsafe network publishing, and insecure permissions. Skip cleanly if none are installed.

## E. Access and Accounts — Layers 41–45

**41. Brute-Force Protection**

Detect repeated failed login attempts for supported local and remote services and apply safe restrictions where feasible, with trusted-access exclusions.

**42. SSH Hardening Audit**

Audit OpenSSH configuration when installed, including root-equivalent access, password authentication, key security, and exposed services. Report-only by default.

**43. Credential Breach Checking**

Provide an optional privacy-preserving credential breach-checking feature, using k-anonymity where supported. Remain idle without user-provided inputs; never upload plaintext passwords.

**44. Account Security Audit**

Identify stale local accounts, insecure authentication policies, unexpected administrator access, and other detectable account-security weaknesses.

**45. Login and Privilege-Use Alerts**

Monitor supported local logins, remote logins, failed authentication, and administrator elevation.

## F. Hardening and Audits — Layers 46–52

**46. Windows Security Hardening Audit**

Audit available protections such as ASLR, DEP, Secure Boot, TPM, Defender status, firewall profiles, encryption, password policy, device security, insecure permissions, and screen-lock configuration.

**47. Reversible Automatic Hardening**

Apply a narrow set of safe, validated Windows security improvements. Include appropriate AutoRun/AutoPlay, legacy-protocol, and built-in security checks. Every modification requires rollback support.

**48. Browser Security Audit**

Inspect supported browsers for detectable risky configuration, untrusted extensions, and missing security settings without unnecessarily collecting browsing history.

**49. External Exposure Assessment**

Report local exposure and optionally query available public exposure intelligence. Clearly distinguish internal observations from genuine externally verified scans.

**50. Secrets Hygiene Scanner**

Detect likely exposed credentials, private keys, and tokens in user-authorized files and development directories. Protect scan results and avoid retaining plaintext secrets.

**51. Remote Feature and Hardware Security Audit**

Audit supported management and remote-access capabilities such as Wake-on-LAN, Intel AMT where present, remote assistance, DMA-related settings, and exposed administrative interfaces.

**52. Updates and Vulnerability Assessment**

Detect missing Windows security updates and known vulnerabilities in identifiable software using verified vulnerability data. Report firmware and BIOS findings only where reliable information exists.

## G. Self-Protection and Safety — Layers 53–65

**53. Watchdog Service**

Monitor critical application components and safely restart failed services when appropriate.

**54. Dead-Man's Switch**

Detect when required protection services or the watchdog stop reporting health.

**55. Privilege Separation**

Separate ordinary UI components from privileged firewall management and protected configuration operations.

**56. Hostile Input Handling**

Safely parse untrusted filenames, event data, DNS names, logs, and other inputs. Use validation, isolation, fuzz testing, and least-privilege execution.

**57. Verified Security Updates and Feeds**

Validate update authenticity and integrity using appropriate signing and verification mechanisms. Reject corrupted or untrusted updates.

**58. Supply-Chain Protection**

Pin dependencies, verify build inputs, generate an SBOM, and run vulnerability checks against the application's software dependencies.

**59. Rule Safety Guard**

Check active security rules against expected configuration, identify unsafe deviations, and coordinate safe rollback without overwriting legitimate third-party changes.

**60. Alert Pipeline**

Provide desktop notifications, severity levels, duplicate suppression, alert history, and summaries. External messaging integrations are optional and must not be required.

**61. Secure Structured Logging**

Provide structured logs, retention controls, rotation, compression, bounded storage, and tamper-evident protections where feasible.

**62. Resource Governor**

Continuously manage the workload of heavyweight scanners, traffic analysis, and monitoring based on CPU, memory, disk usage, and battery state.

**63. Threat Feed Freshness**

Monitor intelligence and detection-rule age. Identify missing, stale, corrupted, or failed updates.

**64. Protected Secrets Storage**

Use Windows DPAPI, Credential Manager, or supported system cryptography to protect application secrets and keys.

**65. UI and Privileged Service Access Protection**

Restrict administrative operations through proper Windows access control, authenticated IPC, authorization checks, and abuse prevention.

## H. Response, Resilience, and Reporting — Layers 66–74

**66. Forensic Snapshot**

On selected high-severity events, securely preserve available process, connection, system-state, and recent event evidence.

**67. Security Posture Score**

Calculate a transparent 0–100 security score with weighted categories, explanations, data-confidence indicators, and actionable recommendations.

**68. Encrypted Versioned Backups**

Provide encrypted, versioned backups with restore verification. Prefer an independently protected destination when available. Clearly explain when backups remain vulnerable because they reside on the same machine.

**69. Offline Recovery Kit**

Generate recovery scripts, configuration exports, and printable instructions. Create bootable recovery media only when compatible media, authorized software, and the required Windows components are available.

**70. Resilient Log Export**

Support encrypted export and shipping to a configured external destination. Without an external destination, retain bounded local archives and report that off-device protection is not configured.

**71. Automated Regression Tests**

Test layer behavior, configuration safety, recovery, rule preservation, and compatibility after software updates.

**72. Quarterly Security Reports**

Generate scheduled reports showing security posture trends, detection activity, layer health, major alerts, and recommended improvements.

**73. Firewall Conflict and Shadowing Analysis**

Detect duplicate, conflicting, shadowed, ineffective, or overly permissive security rules using supported Windows policy representations.

**74. Security Documentation Generator**

Automatically produce a readable report of all 79 layers, supported capabilities, enabled protections, limitations, and current configuration.

## I. Additional Security Coverage — Layers 75–79

**75. Known-Malicious Domain Blocking**

Block validated high-confidence malicious domains when a safe Windows-compatible DNS or network enforcement method exists. Preserve legitimate system resolution and support observation before enforcement.

**76. Download and Temporary File Malware Scanning**

Scan new files in Downloads, temporary folders, and removable drives using appropriately integrated scanning capabilities. Apply quarantine only when detection confidence and file-recovery safeguards justify it.

**77. USB and Removable Device Alerts**

Notify when new storage and input devices appear. Never automatically block or disable essential keyboards, mice, or other input devices.

**78. Ransomware Behavior Monitoring**

Detect suspicious mass file changes, unusual renaming, and access to protected ransomware canary files. Alert by default, without aggressive automatic process termination.

**79. Beaconing Detection**

Analyze available network connection history for suspicious recurring outbound communications and other recognizable command-and-control beaconing indicators.

---

# 10. COMPLETE IMPLEMENTATION STANDARD FOR EVERY LAYER

For every layer, provide:

1. Actual implementation code.
2. Initialization and shutdown logic.
3. Configuration schema.
4. Windows API or engine integration.
5. Protection or monitoring mechanism.
6. Error handling.
7. Structured event output.
8. Health verification.
9. Statistics and resource metrics where measurable.
10. User-interface integration.
11. Unit tests.
12. Integration tests.
13. Reversible configuration changes where applicable.
14. Known limitations.
15. Compatibility and dependency information.
16. Documentation explaining the layer's protection.
17. A safe, repeatable way to test its function.

### No Fake Functionality

The following are unacceptable:

- Empty modules presented as completed layers.
- Hardcoded healthy statuses.
- Simulated threat counters presented as real events.
- Dummy statistics.
- Placeholder scanning engines.
- Buttons without actual functions.
- Exceptions silently ignored.
- Fake antivirus detections.
- Successful test reports for tests that never ran.
- A source-code folder represented as a completed Windows installer.

If a Windows capability is unavailable, report it accurately.

**Never reduce the scope by silently omitting a layer, and never achieve apparent completion by falsifying layer status.**

All 79 layers must be accounted for in a generated coverage manifest.

---

# 11. COMPLETE DEVELOPMENT EXECUTION PLAN

Execute all phases as one continuous development assignment.

Do not treat each phase as a separate project that requires me to initiate the next phase.

## Phase 1 — Repository and Architecture

- Connect to the existing OTS Firewall79X repository.
- Inspect the existing files and branches.
- Preserve valuable working code.
- Establish the correct application structure.
- Create architectural documentation.
- Define all 79 layer contracts.
- Build shared configuration and logging systems.
- Set up automated compilation and testing.

## Phase 2 — Windows Application Foundation

- Develop the native Windows desktop application.
- Implement the UI framework.
- Implement the background Windows service.
- Implement secure UI-to-service communication.
- Implement Windows administrator authorization.
- Implement system detection.
- Implement layer orchestration.
- Implement snapshots and rollback.
- Implement watchdog and recovery mechanisms.

## Phase 3 — Core Network Protection

Complete and integrate:

- Layers 1–10.
- Layers 11–13.
- Layers 41–45.

Verify safe firewall behavior and recovery before enabling automatic enforcement.

## Phase 4 — Monitoring and Detection

Complete and integrate:

- Layers 14–24.
- Layers 25–40.
- Layers 75–79.

Implement actual supported telemetry and avoid duplicating existing Windows security functionality unnecessarily.

## Phase 5 — Hardening, Safety, and Resilience

Complete and integrate:

- Layers 46–52.
- Layers 53–65.
- Layers 66–70.

Verify privilege boundaries, backups, reporting infrastructure, and safe restoration.

## Phase 6 — User Experience

Complete:

- Main security toggle.
- Dashboard.
- Layer details.
- Event history.
- Network monitoring display.
- Posture score.
- Threat counters.
- Notification center.
- Recovery interface.
- Reporting screens.
- Settings.
- Professional Ohana Tech branding.

Every visible button, counter, status indicator, and settings control must be functional.

## Phase 7 — Final Security Analysis and Documentation

Complete:

- Layer 71 — Regression Tests.
- Layer 72 — Quarterly Reports.
- Layer 73 — Rule Conflict Analysis.
- Layer 74 — Documentation Generator.

Perform final integration and security testing.

## Phase 8 — Compilation and Windows Installation

Compile the actual Windows application.

Create the complete Windows `.exe` installer.

Bundle the required dependencies.

Configure all required Windows services and installation permissions.

Verify:

- Installation.
- Launching.
- Admin elevation.
- Firewall activation.
- Monitoring.
- Service auto-start.
- Reboot persistence.
- Upgrade.
- Pause and resume.
- Full uninstall.
- Configuration restoration.
- Absence of development-tool dependencies.

## Phase 9 — GitHub Delivery

Commit and push the completed application and release-related files.

Build the Windows release package.

Publish the finished installable ZIP and executable installer through GitHub Releases.

Run the final release-verification checklist.

---

# 12. GITHUB REPOSITORY REQUIREMENTS

## Destination

Use my existing **OTS Firewall79X** repository in my Ohana Tech Solutions GitHub account.

Use its exact existing repository identifier. Do not create a duplicate repository or silently rename it.

All OTS Firewall79X development work must be consolidated into this repository.

Before beginning modifications:

1. Confirm the intended repository.
2. Inspect its current contents.
3. Inspect the current default branch.
4. Identify any existing implementation worth preserving.
5. Follow a safe development and merge workflow.

Do not force-push over unrelated work, delete branches, or overwrite changes belonging to others without authorization.

### Recommended Repository Structure

```text
OTS-Firewall79X/
│
├── src/
│   ├── OTS.Firewall79X.App/
│   ├── OTS.Firewall79X.Core/
│   ├── OTS.Firewall79X.Service/
│   ├── OTS.Firewall79X.Security/
│   ├── OTS.Firewall79X.Network/
│   ├── OTS.Firewall79X.Layers/
│   ├── OTS.Firewall79X.Storage/
│   ├── OTS.Firewall79X.Recovery/
│   └── OTS.Firewall79X.Installer/
│
├── tests/
│   ├── Unit/
│   ├── Integration/
│   ├── Security/
│   ├── Regression/
│   ├── Recovery/
│   └── EndToEnd/
│
├── assets/
│   ├── icons/
│   └── branding/
│
├── config/
│   └── defaults/
│
├── docs/
│   ├── architecture/
│   ├── security-layers/
│   ├── installation/
│   ├── troubleshooting/
│   └── recovery/
│
├── scripts/
│   ├── build/
│   └── test/
│
├── installer/
│   ├── OTS-Firewall79X-Setup.exe
│   └── SHA256SUMS.txt
│
├── dist/
│   └── OTS-Firewall79X-Windows-x64.zip
│
├── .github/
│   ├── workflows/
│   │   ├── build.yml
│   │   ├── test.yml
│   │   ├── security.yml
│   │   └── release.yml
│   └── ISSUE_TEMPLATE/
│
├── README.md
├── LICENSE
├── CHANGELOG.md
├── CONTRIBUTING.md
├── CODE_OF_CONDUCT.md
├── SECURITY.md
├── ASSUMPTIONS.md
├── EXTERNAL_TOOLS.md
├── KNOWN_LIMITATIONS.md
├── LAYER_COVERAGE.md
├── TEST_RESULTS.md
├── RELEASE_NOTES.md
├── BUILD_MANIFEST.json
├── SBOM.json
├── .gitignore
└── .gitattributes
```

This structure is illustrative. Adjust it when technically justified.

### Required GitHub Artifacts

The repository must contain:

- Complete application source code.
- All security-layer modules.
- Supporting service code.
- Installer source/configuration.
- Compiled Windows installer in `installer/`.
- Windows release ZIP in `dist/`.
- Dependency manifests.
- Configuration defaults.
- Automated build workflows.
- Automated test workflows.
- Documentation.
- Security and vulnerability disclosure guidance.
- Release notes.
- SHA-256 checksums.
- Software bill of materials.
- Actual test results.
- Complete 79-layer coverage report.

Do not overwrite an existing license without authorization. If the repository lacks a license, document a recommended choice and its implications; do not invent legal approval.

If binary size exceeds GitHub's repository file limits, use GitHub Release assets for those binaries, document their exact download location, and ensure the release ZIP remains directly obtainable from GitHub.

### Compiled Installer Requirement

The compiled installer must be accessible from the repository or its GitHub Releases.

It must not exist only as an `.iss`, `.wxs`, `.csproj`, or other installer project file.

The executable must actually be compiled.

### GitHub Release Requirement

Create a release containing:

```text
OTS-Firewall79X-Windows-x64.zip
OTS-Firewall79X-Setup.exe
SHA256SUMS.txt
RELEASE_NOTES.md
```

The downloadable ZIP must contain a ready-to-run installer rather than only source code.

The automatically generated GitHub source-code ZIP is not equivalent to the finished installer ZIP.

### Integrity and Code Signing

Generate and publish real SHA-256 checksums for completed binary artifacts.

Sign executables with a genuine trusted code-signing certificate if one is available and authorized.

Never fabricate certificate trust or report an unsigned executable as digitally signed.

If trusted code signing is unavailable, report that limitation without blocking the creation and testing of the installer.

---

# 13. AUTOMATED BUILD AND RELEASE

Configure GitHub Actions to automatically:

1. Restore dependencies.
2. Validate source code.
3. Compile the Windows desktop app.
4. Compile the background service.
5. Execute unit tests.
6. Execute integration tests.
7. Run applicable security checks.
8. Generate the SBOM.
9. Build the installer.
10. Package the ready-to-install ZIP.
11. Generate SHA-256 hashes.
12. Upload build artifacts.
13. Create release artifacts for approved release builds.

The workflows must be operational, not illustrative examples.

Use real Windows build runners and appropriate available test environments.

A successful workflow must produce the required release artifacts.

A build workflow that exits successfully without generating a valid installer must be treated as failed.

Preserve enough build information to reproduce the release.

---

# 14. STRICT TESTING AND QUALITY ASSURANCE

**Do not declare OTS Firewall79X complete merely because the source code compiles.**

Verify that the software works.

## 14.1 Clean Installation

Test:

- Fresh Windows-compatible environment.
- Installer execution.
- Required files copied.
- Services registered.
- Desktop and Start menu entries created.
- Main application launched.
- UI connected to background service.
- No missing runtime dependencies.

## 14.2 One-Click Activation

Verify:

- Administrator authorization.
- Initial system snapshot.
- OS and hardware detection.
- Security-layer initialization.
- Safe firewall policy generation.
- Real layer health statuses.
- Network connectivity preserved.
- Protection score calculation.
- Accurate event and blocked-threat counters.

## 14.3 Security Behavior Tests

Using authorized, isolated test conditions, verify representative behavior including:

- Inbound connection filtering.
- Port-scan detection.
- Failed-login monitoring.
- Honeytoken access alerts.
- Suspicious execution alerts.
- Malicious-domain detection using safe test fixtures.
- New device notifications.
- Integrity-monitoring changes.
- Ransomware canary alerts.
- Repeated outbound connection analysis.

Use contained test fixtures and mock external threats where real attacks are unnecessary.

Do not conduct intrusive tests against public systems or networks without authorization.

## 14.4 Safety Tests

Verify:

- Existing firewall rules are preserved.
- Internet access is not unnecessarily interrupted.
- Trusted administrative access is maintained.
- Unsafe rule changes automatically roll back.
- The emergency restore function works.
- Turning OFF removes only application-owned changes.
- Uninstall restores applicable prior configuration.
- Recovery works when the primary UI is unavailable.

## 14.5 Failure and Chaos Tests

Simulate:

- Background service crash.
- UI crash.
- Corrupted configuration.
- Interrupted installation.
- Interrupted upgrade.
- Missing threat feeds.
- Network disconnection.
- Low disk space.
- Restricted filesystem permissions.
- Failed dependency initialization.
- Sudden application termination.
- Reboot while protection is enabled.

Verify safe, deterministic recovery.

## 14.6 Resource Tests

Measure:

- Idle CPU utilization.
- Idle RAM utilization.
- Active monitoring overhead.
- Peak memory consumption.
- Disk activity.
- Event logging throughput.
- Startup impact.
- Battery-aware throttling.
- Resource governor effectiveness.

Record actual measurements and testing conditions.

Do not invent benchmarks.

## 14.7 Clean Uninstallation

Verify:

- Application removal.
- Background service removal.
- Shortcut cleanup.
- Removal of application-owned scheduled tasks.
- Cleanup of application-created rules.
- Restoration of reversible modified settings.
- Preservation of unrelated Windows settings.
- Recovery of normal networking.

## 14.8 Test Reporting

Every test must be reported as:

- **PASS** — executed successfully.
- **FAIL** — executed and failed.
- **BLOCKED** — cannot execute because of a documented environmental limitation.
- **NOT RUN** — has not been executed.

Never report a test as passing simply because test code exists.

Use real GitHub Actions logs and test results where available.

For hardware-specific capabilities that cannot be validated on hosted Windows runners, include reproducible test procedures and clearly record the unverified hardware behavior.

---

# 15. COMPLETION GATES

Before publishing a final release, satisfy the following gates.

## Gate A — Architecture

- Modular design established.
- All 79 layers accounted for.
- No undocumented critical dependencies.
- Windows support defined.
- Safety and recovery architecture implemented.

## Gate B — Functionality

- Desktop application runs.
- Main toggle functions.
- Background services function.
- Applicable layers perform meaningful operations.
- Real monitoring data reaches the UI.
- Rule enforcement works where supported.
- Errors and partial protection are accurately reported.

## Gate C — Security and Stability

- Privilege separation verified.
- Safe firewall behavior verified.
- Rollback and recovery tested.
- Sensitive data protected.
- No known critical or high-severity defects left unaddressed without explicit disclosure.

## Gate D — Installation

- Real `.exe` application compiled.
- Real `.exe` installer compiled.
- Required dependencies bundled.
- No additional user-installed programs needed.
- Clean installation tested.
- Uninstallation tested.

## Gate E — GitHub Delivery

- Source committed.
- Appropriate branch merged.
- Default branch contains the release source.
- Automated build passes.
- Test reports published.
- Installer available.
- Release ZIP available.
- SHA-256 checksums available.
- Documentation complete.

## Gate F — 79-Layer Coverage Audit

Generate a final checklist with the following columns:

| ID | Layer | Implementation File | Mode | Status | Tests | Limitations |
|---|---|---|---|---|---|---|

Include all 79 layers.

Allowed statuses include:

- Implemented and tested.
- Implemented with limitations.
- Not applicable in the tested environment.
- Blocked by a documented prerequisite.
- Incomplete.

**No layer may be silently omitted or labeled complete without supporting implementation and test evidence.**

If any required layer remains incomplete, the project remains incomplete. Report its exact status rather than claiming all 79 layers are finished.

---

# 16. REQUIRED USER DOCUMENTATION

Create user documentation for:

- Installing OTS Firewall79X.
- Launching the application.
- Activating protection.
- Understanding the security score.
- Understanding layer statuses.
- Viewing threat activity.
- Pausing or disabling protection.
- Updating the application.
- Restoring the previous system configuration.
- Recovering from a failed service.
- Uninstalling.
- Troubleshooting.
- Known platform and hardware limitations.

The normal user documentation must be understandable without programming knowledge.

Avoid instructing the user to install developer tools, use PowerShell for routine setup, or modify configuration files.

Technical documentation may separately explain developer builds and internal architecture.

---

# 17. DEVELOPMENT AUTONOMY & COMPLETION RULES

These requirements govern the entire assignment.

### Rule 1 — Build the actual application

Do not substitute architectural proposals or sample code for a finished software deliverable.

### Rule 2 — Use the existing GitHub repository

Perform the development through the connected GitHub tools. Commit the work to the existing project using a safe workflow.

### Rule 3 — Make independent engineering decisions

Choose appropriate Windows APIs, libraries, storage technologies, UI components, and supporting tools without repeatedly requesting approval.

Document important decisions.

### Rule 4 — Do not assign development tasks to me

Do not tell me to:

- Build or compile the application.
- Install Visual Studio.
- Install Python.
- Install additional security engines.
- Configure environment variables.
- Download and assemble missing program components.
- Write configuration files.
- Repair the repository manually.
- Execute installer-building scripts.
- Finish integration independently.

### Rule 5 — Do not claim unperformed work

If you cannot compile an executable, do not say it was compiled.

If you cannot run Windows testing, do not say Windows testing passed.

If GitHub rejected a push, do not say the repository was updated.

If a layer is nonfunctional, do not list it as working.

### Rule 6 — Do not hide dependencies

Every operationally necessary component must be included in the installer or supplied by Windows.

Optional internet-dependent features must identify their requirements.

### Rule 7 — Preserve working functionality

Do not delete or break functional implementation merely to reorganize the repository.

### Rule 8 — Fix defects before release

Resolve failing builds, broken integration, missing executables, installer defects, and critical functionality failures before declaring a release complete.

### Rule 9 — Continue through all phases

Do not stop after architecture, scaffolding, source generation, UI design, or initial testing.

Continue implementation, integration, validation, and packaging within the available execution environment.

### Rule 10 — Respect genuine blockers

If repository authorization, platform access, signing credentials, third-party licensing, or hardware access creates a genuine blocker, document it precisely.

Do not circumvent security permissions or fabricate completion.

### Rule 11 — Deliver finished artifacts, not promises

The final response must link to the actual GitHub repository, completed release, and executable artifacts when they have genuinely been created.

### Rule 12 — Keep core usage simple

A nontechnical Windows user must be able to install, activate, monitor, and disable the application entirely through its graphical interface.

---

# 18. FINAL RELEASE REPORT

When the project is finished, deliver a final development and release report containing:

**Application:** OTS Firewall79X  
**Developer:** Ohana Tech Solutions  
**Target Platform:** Windows 10/11 x64  
**Application Executable:** `OTS Firewall79X.exe`  
**Installer:** `OTS-Firewall79X-Setup.exe`  
**Release ZIP:** `OTS-Firewall79X-Windows-x64.zip`

Include:

1. GitHub repository link.
2. Exact release version.
3. Direct GitHub release download link.
4. Commit hash used to build the release.
5. Confirmation that the Windows executable was compiled.
6. Confirmation that the installer was compiled.
7. Confirmation that the release ZIP contains the finished installer.
8. Summary of Windows build and installation results.
9. Actual testing results and logs.
10. All 79 layers' implementation statuses.
11. Known limitations.
12. SHA-256 checksums.
13. Signing status.
14. Final user installation instructions.

If the release is not genuinely ready to install and use, label it incomplete and identify the remaining work.

---

# 19. FINAL ACCEPTANCE STANDARD

The assignment is successfully completed only when:

**I can visit my OTS Firewall79X GitHub repository, download the finished Windows release ZIP, extract it, run the included `.exe` installer, open OTS Firewall79X, and activate its functioning security features without installing or configuring additional applications.**

The application must deliver genuine protection, monitoring, transparent capability reporting, safe rollback, and reliable installation.

The 79-layer catalog must have complete implementation accountability, with no unsupported claims of functionality.

The software must be professionally organized, maintainable, recoverable, and appropriately branded as an Ohana Tech Solutions product.

**The finished product is the objective. Source code alone is not the deliverable.**

---

# 20. EXECUTION DIRECTIVE

Begin by connecting to and inspecting the existing OTS Firewall79X GitHub repository.

Then immediately proceed with architecture, development, Windows integration, security-layer implementation, testing, installer compilation, packaging, GitHub synchronization, and release publication.

Do not request routine approvals between development phases.

Do not stop after providing a plan.

Do not consider the project finished until the actual compiled application and installer have been produced, verified, and published, with all unfinished capabilities explicitly disclosed.

**Build the software. Test the software. Package the software. Deliver the software.**