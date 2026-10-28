# Section G — Self-Protection and Safety (layers 53–65)

**Scope:** Windows 10/11 x64; privileged service, separate watchdog instance, unprivileged WPF client, release pipeline and local event storage.

**Release classification: DEVELOPMENT PREVIEW.** No feature below may be marked certified solely because a source implementation exists. Genuine production signing, Windows hardware qualification, independent penetration testing and all-layer regression evidence are still required.

| Layer | Delivered in this branch | Remaining acceptance evidence or dependency |
|---|---|---|
| 53 — Watchdog | Second independently running Windows service from the same bundled executable; SCM crash restart policy; no unbounded inline restarts | Observe crash, hang, reboot, upgrade and service-account policy on physical Windows 10/11; SCM settings verified on hosts |
| 54 — Dead-man switch | Independently checks authenticated service status every 20 seconds; records an error in Windows Application Event Log after three failed probes, recovery event when healthy | Entire OS power-off cannot be reported locally; test WER/crash dumps and event retention in each supported OS |
| 55 — Privilege separation | UI stays unprivileged; named-pipe server checks impersonated administrator for state changes; client verifies server PID against installed service | External independent audit of impersonation, ACL inheritance, UAC helper, service token and all attack surfaces |
| 56 — Hostile input | Bounded framed JSON; explicit request field whitelist and duplicate rejection; deterministic malformed IPC and feed test corpus | Full coverage-guided fuzzing of DNS/log/XML/packet/telemetry inputs and process isolation |
| 57 — Verified updates | Pinned ECDSA P-256 signed artifact verifier checks signed metadata, age, publisher, version, file size, path safety and SHA-256 before accepting staged files; production Authenticode gate | **BLOCKED:** independently provisioned real trusted publisher certificate/key; authenticated download/update installer, transactional activation and rollback; preview does NOT auto-install unsigned code |
| 58 — Supply chain | Existing package locks/SBOM/dependency scan plus build manifest file rehash and installer digest validation; production requires pinned Authenticode identity | Reproducible build and independent trusted build provenance/attestation; release certificate |
| 59 — Rule safety | Existing allowlisted change journal, prepared/applied durability and drift-aware restore | Future OTS-created firewall rules need policy conflict analysis and independent rollback tests |
| 60 — Alerts | Protected persistent event history, replay of authenticated records across restarts, deduplication, desktop notifications; watchdog reports to Windows Event Log even without desktop | End-to-end alarm delivery, notification suppression/persistence and behavior under disk-full/UI-closed failure scenarios |
| 61 — Logs | HMAC validation across retained segments, restored totals, detection of chain gaps and corruption; refuse to append to failed history | Off-device protected retention, key rotation/migration, backup and forensic export validation |
| 62 — Governor | Measured CPU and memory, battery-aware telemetry, disk-free-space backoff, defer optional snapshot/report I/O | Windows low-memory/disk full/battery stress and long-running benchmarks |
| 63 — Feed freshness | Existing strict timestamp/format validation and fail-stale Feodo observation-only feed; signature envelope verifier available for future signed feeds | Feed is **not signed** and no blocking is active; trusted publisher keys/ruleset authenticity and full feed fleet remain |
| 64 — Secret storage | Machine DPAPI-protected local integrity secret with SYSTEM/Administrators-only directory ACL and reparse-point rejection | Rotating keys while preserving old logs, cross-machine restore/recovery, access-control threat model on physical hosts |
| 65 — UI/service boundary | Local-only pipe ACL with network SID denial, 5-second server budget, registered service PID authentication, admin authorization, strict request schema | Independent IPC spoofing/DoS/fuzz red-team testing under each supported Windows SKU |

## Security invariants

- Neither the watchdog nor the signature verifier modifies firewall configuration or executes downloaded software.
- A signature inside a received manifest cannot nominate its own trust anchor. Unsigned preview files remain explicitly **untrusted for automatic update**.
- A publisher signature and a checksum are different: the latter detects accidental alteration but does not prove who built a release.
- On stopped/disabled stack, existing Microsoft Defender and Windows Firewall stay in place.
- A failed protected event history is retained for investigation; new alerts continue in bounded RAM and a warning is surfaced rather than silently altering the evidence.
- OFF/restore must preserve third-party changes rather than forcibly overwrite them.
- Watchdog health should be evaluated separately from core service health. A local watchdog is not off-device monitoring.

## Automated evidence

- `tests/OTS.Firewall79X.Tests/Program.cs`: signed manifest positive and negative tests; impersonator key, downgrade, expiry, path traversal, corrupted payload; strict IPC schema; restart budget; resource governor and stale heartbeat.
- `scripts/windows-smoke.ps1`: installs both services, verifies watchdog status, stops the primary service, waits for an independent logged incident, tests upgrade, rollback, and both services' uninstall.
- `scripts/verify-release-provenance.ps1`: validates every publish-tree file against the build manifest, SBOM, installer checksum and Authenticode status. Set `OTS_RELEASE_CHANNEL=production` only in a signed, pinned-publisher release pipeline; it will refuse unsigned or wrong-publisher releases.
- `.github/workflows/windows.yml`: Windows Server 2025 runner build, tests and installer smoke are development CI evidence only, **not physical Windows 10/11 certification**.

## Release gates not waived

Do not publish a production-ready designation until an independently provisioned publisher signing identity, signed update distribution and rollback, independent security review, physical Windows compatibility tests, and full end-to-end acceptance have passed. See `docs/BUILD_SPECIFICATION.md`, `LAYER_COVERAGE.md` and the 79-layer completion checklist.
