# Section G — Self-Protection and Safety (layers 53–65)

**Scope:** Windows 10/11 x64; privileged service, separate watchdog instance, unprivileged WPF client, release pipeline and local event storage.

**Release classification: DEVELOPMENT PREVIEW.** No feature below may be marked certified solely because a source implementation exists. Genuine production signing, Windows hardware qualification, independent penetration testing and all-layer regression evidence are still required.

| Layer | Delivered in this branch | Remaining acceptance evidence or dependency |
|---|---|---|
| 53 — Watchdog | Second independently running Windows service from the same bundled executable; SCM crash restart policy; no unbounded inline restarts | Observe crash, hang, reboot, upgrade and service-account policy on physical Windows 10/11; SCM settings verified on hosts |
| 54 — Dead-man switch | Independently checks authenticated service status every 20 seconds; records an error in Windows Application Event Log after three failed probes, recovery event when healthy | Entire OS power-off cannot be reported locally; test WER/crash dumps and event retention in each supported OS |
| 55 — Privilege separation | UI stays unprivileged; named-pipe server checks impersonated administrator for state changes; client verifies server PID against installed service | External independent audit of impersonation, ACL inheritance, UAC helper, service token and all attack surfaces |
| 56 — Hostile input | Bounded framed JSON; explicit request field whitelist and duplicate rejection; deterministic malformed IPC and feed test corpus | Added deterministic malformed DNS/feed/log and request-frame corpora; coverage-guided native fuzzing of all packet/ETW/IPC boundaries and process isolation remain necessary |
| 57 — Verified updates | Pinned ECDSA P-256 signed artifact verifier rejects tampering, downgrade, expiry, reparse-point staging ancestors and oversized aggregate manifests; production Authenticode gate remains fail closed | **BLOCKED:** independently provisioned real trusted publisher certificate/key; authenticated download/update installer, transactional activation and rollback; preview does NOT auto-install unsigned code |
| 58 — Supply chain | Existing package locks/SBOM/dependency scan plus build manifest file rehash and installer digest validation; production requires pinned Authenticode identity | Reproducible build and independent trusted build provenance/attestation; release certificate |
| 59 — Rule safety | Existing allowlisted change journal, prepared/applied durability and drift-aware restore | Temporary OTS source rules now require exact expected name, destination, direction, protocol, profile, action, enabled flag and description for cleanup; changed/spoofed rules are preserved and alerted. External WFP/GPO shadowing, interrupted-rule mutation and physical recovery still require validation |
| 60 — Alerts | Protected persisted event history, authenticated replay and deduplication; high-severity service events also attempt Windows Application Event Log delivery without the desktop, while the independent watchdog reports outages | End-to-end alarm delivery, notification suppression/persistence and behavior under disk-full/UI-closed failure scenarios |
| 61 — Logs | Backward-compatible key-versioned HMAC chain with machine-DPAPI protected keyring; 90-day rotation preserves previous retained records; reject corrupt keyring/history and partial replay, preserve failed evidence | Off-device protected retention, key rotation/migration, backup and forensic export validation |
| 62 — Governor | Measured CPU and memory, battery-aware telemetry, disk-free-space backoff, defer optional snapshot/report I/O | Windows low-memory/disk full/battery stress and long-running benchmarks |
| 63 — Feed freshness | Existing strict timestamp/format validation and fail-stale Feodo observation-only feed; signature envelope verifier available for future signed feeds | Feed is **not signed**; Section A can apply short-lived verified-observation restrictions to a specific matching destination, but this is NOT signed-intelligence assurance. Publisher keys/ruleset authenticity, stale-rule failure tests and full feed fleet remain |
| 64 — Secret storage | Machine DPAPI-protected original key and versioned rotating keyring; no user key-entry step; SYSTEM/Administrators-only directory ACL and reparse-point rejection; historical records remain verifiable through key rotation | Physical Windows ACL testing, backup/escrow and cross-machine restore, retired-key pruning and full key-compromise recovery remain necessary |
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

## Protected key lifecycle and safe failure policy

- Version 0 retains compatibility with legacy 32-byte HMAC event records. New rotated records bind their positive key identifier into the authenticated payload.
- The new keyring is machine-DPAPI protected in the existing SYSTEM/Administrators-controlled log directory; the previous legacy key is retained until a supported key retirement and backup process exists.
- After 90 days, the service attempts key rotation on its next security event. A durable protected ring is written before switching to the new key in memory. If storage/DPAPI fails, the event pipeline degrades rather than rewriting old evidence with an unauthenticated key.
- **No signed update is automatically applied:** the independently provisioned publisher key and complete update transaction/rollback are not present. A publisher signature cannot be fabricated from a checksum or self-declared key in a downloaded release.
- All event counters reconstructed from retained segments measure **retained authenticated history**, not guaranteed lifetime history once old archives are rotated away. Off-device retention and protected retention checkpoints remain outstanding.
