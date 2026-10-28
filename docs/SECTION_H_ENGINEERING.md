# Section H — Response, Resilience, and Reporting (Layers 66–74)

This page describes the implementation evidence introduced by the Section H branch. It is **not** an independent Windows hardware certification or a statement that the 79-layer product is finished. The authoritative layer acceptance criteria remain in `docs/BUILD_SPECIFICATION.md`.

## Implementation matrix

| Layer | Added or improved behavior | Operational limits / remaining acceptance |
|---|---|---|
| **66 Forensic Snapshot** | High-severity collector signals trigger an atomic, bounded JSON capture of the current dashboard, recent alerts and process-associated TCP observations. An independent SHA-256 payload digest is checked after writing. Retention targets 20 good snapshots; damaged evidence is preserved. | Service must survive until its next health cycle; no memory image, trusted timestamp or external tamper-evident store. SHA-256 does **not** authenticate the writer against a local administrator. Crash/power-failure tests needed. |
| **67 Security Posture Score** | Weighted 0–100 existing score, existing observed-check confidence and prioritized remediation items in the operational dossier; unsupported/idle conditions cannot inflate health. | Weights are product heuristics; a healthy detection sensor does not imply active prevention. Calibrate with real Windows coverage/false positives. |
| **68 Encrypted Versioned Backups** | Verified non-overwriting AES-256-GCM selected-folder backups retain file last-modified UTC metadata; a restored version requires a new folder and verifies file hashes. | An opt-in daily service scheduler now writes encrypted versions to selected removable/network destinations using machine-DPAPI-wrapped credentials. No automatic job without administrator setup; unavailable drives and credential errors are reported. ACLs, empty directories, links and full-system images remain unsupported. 60 MiB/5,000-file budget. |
| **69 Offline Recovery Kit** | On activation, the protected service writes a copy-verified local recovery bundle with hash manifest, saved OTS journal/activation snapshot when available, readable instructions and an optional recovery script. Copies the recovery EXE only when co-located with the service. | The Start menu recovery EXE remains primary. No bootable rescue medium. The script is **not** an unsigned security-policy bypass and cannot substitute for a missing executable or Windows recovery media. |
| **70 Resilient Log Export** | AES-GCM encrypted export queue, post-encryption verification, off-device destination type guard, verified copy, bounded retries and no overwrite of remote archives. | An opt-in elevated configuration dialog now provides destination and recoverable passphrase, persisted with machine DPAPI. While service is ON, closed rotated gzip segments are encrypted, queued and copied to selected removable/network destinations with read-back SHA-256 verification, crash-idempotent receipts, safe retries and failure alerts. Initial success requires actual verified delivery; service-account path accessibility and physical removable/network tests remain outstanding. Production `Ship` rejects fixed internal disks. |
| **71 Automated Regression Tests** | Added corruption tests, valid/invalid CIDRs and port ranges, quarter restart/catch-up, recovery manifest and export copy integrity, backup timestamps, and documentation completeness. | Test suite is not a complete positive/negative/failure/rollback/hardware compatibility matrix for all **79** layers. Windows 10/11 physical tests and CI result review required. |
| **72 Quarterly Security Reports** | A bounded, persisted daily sample file feeds quarter-specific reports with score/telemetry confidence, daily layer health, sampled major alerts, available event counters and proposed improvements. Reports for missed quarters are created when an active monitoring cycle resumes. | Only actual sampled days appear. The desktop/service must be active for readings; gaps are not imputed. Sampled recent high alerts are not an exhaustive quarterly detection tally. |
| **73 Firewall Conflict and Shadowing Analysis** | Bounded partial-overlap hints for parseable IPv4/IPv6 CIDRs, port ranges, application scope, protocols and profile bitmasks, in addition to duplicate/exact opposing rules and broad allows. | **Potential overlap is not shadowing**. COM rule data omits full WFP/IPsec/GPO precedence, interface and service scopes, dynamic address keywords, local-address and remote-port constraints. No rules are automatically deleted. |
| **74 Security Documentation Generator** | On-demand dossier includes every ID 1–79, category/name, current operational mode, health, evidence, check timestamp, limitations and priority review items. | A locally generated snapshot of service telemetry, not independent attestation. No claim of fully qualified coverage. |

## New source entry points

- `src/OTS.Firewall79X.Core/ResponseEvidence.cs`: capture integrity, daily posture history, quarterly catch-up and 79-layer dossier.
- `src/OTS.Firewall79X.Core/RecoveryKit.cs`: printable local recovery bundle with checked copies.
- `src/OTS.Firewall79X.Core/OffDeviceLogExport.cs`: encrypted queue and verified removable/network shipping primitives.
- `src/OTS.Firewall79X.Core/FirewallOverlap.cs`: conservative bounded overlap analysis.
- `src/OTS.Firewall79X.Windows/Engine.cs`: integration of 66, 69, 72 and 74 with honest conditional status on 68/70/71.
- `src/OTS.Firewall79X.Windows/WindowsSettings.cs`: Layer 73 analysis from actual enumerated Windows Firewall rules.
- `tests/OTS.Firewall79X.Tests/Program.cs`: focused positive, negative and corruption regression checks.

## Evidence and privacy

The snapshots, recovered settings and trend history are written to the service's secured ProgramData storage. Reports can contain IP addresses, process names, file paths, and security configuration. Do not publish raw files. Never export plaintext service logs to a network or removable destination. An export passphrase must be recoverable separately from the protected machine; no automatic, insecure default key is issued.

A local administrative account can edit/delete data and its associated unkeyed SHA-256 hash. For stronger forensic assurance, require signed off-device evidence manifests, independent timestamps, and protected access to the archive destination.

## Acceptance work still required

1. Compile and execute the expanded Windows test suite; exercise installer upgrades and repair flows. Inspect CI failures rather than declaring success from source changes.
2. Qualify the new explicit opt-in off-device export workflow and protected credential storage on physical Windows machines; test unexpected power loss, unavailable targets, file-handle failures, retry deduplication and off-device deletion/retention policy.
3. Validate scheduled folder backups with real removable/network volumes, second-device passphrase recovery, permissions, ACLs and service-account access.
4. Verify all 79 layers independently on physical Windows 10/11 x64 and Windows 11 Home, including real Windows Firewall/GPO precedence testbeds and non-administrative user sessions.
5. Produce trusted signature and update verification, bootable media only where Windows licensing/tooling and removable-device authorization permit, and full off-host evidence chain controls.

**Release conclusion:** Section H gains significant real implementations, but several original acceptance requirements remain unverified or unimplemented. Do not mark every Section H item complete or ship a production-security claim based solely on this branch.

## Optional scheduling integration (second engineering pass)

- The native WPF Tools & reports screen now exposes enable/disable controls for both scheduled encrypted backups (layer 68) and encrypted off-device log shipping (layer 70).
- A Windows-UAC-elevated recovery helper collects source/destination and passphrase **after** elevation. The passphrase is never placed in a command-line argument, environment variable, event log or plaintext settings file.
- The privileged service validates removable/network targets, encrypts the retained passphrase with machine DPAPI in protected ProgramData storage, and runs bounded jobs when the OTS security stack is ON. A running machine without a configured off-device destination never performs remote shipping.
- On selected off-device targets, backups run approximately daily while the service is ON, generate unique non-overwriting archives and verify decryption/manifest before reporting success. Closed rotated gzip segments are encrypted into a local queue and retried, with a byte-for-byte verified existing receipt accepted after a crash before queue deletion.
- Real removable drive, UNC credentials, SYSTEM service access, device removal, crash durability, storage quota, and malware tampering tests are not claimed by the Windows Server CI smoke runner. The local machine DPAPI store protects at rest but local administrators remain trusted. The user must keep the recovery passphrase separately.

**Baseline operation does not require configuring a backup target or external service.** All optional jobs start disabled and have honest Idle/Unavailable states until configured and verified.
