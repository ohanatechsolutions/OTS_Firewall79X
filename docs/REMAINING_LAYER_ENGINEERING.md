# OTS Firewall79X — remaining 79-layer engineering and acceptance

**As of November 13, 2026:** `main` is an incomplete development preview. The latest successful Windows Server 2025 CI, [run 43426807917](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/43426807917), verifies 122/122 core tests, an installer, Windows service smoke tests, dependency gates and integrity checks. It does **not** prove 79 independent prevention mechanisms or physical Windows 10/11 support.

## User testing remains deferred

The owner explicitly requests **all 79 layer implementations to be code-complete before owner-operated testing begins**. Do not ask the owner to install or run the current incomplete preview. Engineering can use Windows CI, isolated disposable test environments and mock/synthetic/negative regression fixtures meanwhile. A genuinely final production certification *cannot* be established without subsequent hardware acceptance and independent security review.

**Do not equate** presence in `catalog.json`, an `Implemented with limitations` marker, a passing generic self-check, or a passing build with full original-spec protection. Every row in [LAYER_COVERAGE.md](../LAYER_COVERAGE.md) remains open for complete acceptance evidence. The automated `scripts/verify-layer-coverage.ps1` ensures the original 79 IDs/names cannot quietly disappear; the production build gate requires 79 certified rows and currently refuses production.

## Eight explicitly incomplete mechanisms — implement before owner testing

| ID | Missing engineering | Required positive/negative/safety evidence |
|---|---|---|
| **4** | Supported, live Windows Filtering Platform (WFP) filtering of verifiably invalid/spoofed traffic, not merely standalone IP-header parsing | Controlled IPv4/IPv6, fragment/extension, malformed and valid packet tests; installer/uninstaller cleanup and safe network rollback |
| **8** | Actual DNS rebinding prevention for supported resolver paths, with split-horizon/enterprise allowlisting and no false assurance for DNS-over-HTTPS | Synthetic and real DNS response transitions, false-positive internal domain tests, process/host scoping, OFF/uninstall restore |
| **10** | Bluetooth Low Energy, live pairing/session change authorization and independently supported discoverability handling | Physical Bluetooth Classic/BLE adapter matrix, alert/noise tests, permissions review and never disabling essential input devices |
| **31** | Reliable supported browser credential/session file-read auditing when policy and SACL prerequisites are absent, without acquiring credential values | Per-browser/file/version and unusual-reader tests, standard-user access boundaries, privacy check, safe audit-policy restoration |
| **34** | Higher-fidelity file copy/transfer correlation with bounded process attribution and honest visibility limitations for encrypted cloud exfiltration | Controlled authorized bulk copying, legitimate backup/indexer false positives, network correlations, missing-event fallback |
| **38** | Supported input-hook/keylogger detection beyond already-labelled Microsoft Defender detections; design must not intercept/store keystrokes | Representative supported Windows APIs/providers and controlled benign/malicious input-hook tests, unknown-sensor classification |
| **57** | Publisher-pinned signed update source, authenticated download, safe staging, apply/rollback, and verified post-install version | Valid/impostor/expired/replayed/downgrade/tampered update tests, interrupted-install restore, signing identity verification |
| **63** | Authenticated threat-intelligence and detection-rule provenance across IP, DNS and IDS feeds; local freshness alone is insufficient | Signed feed samples, revoked/expired/untrusted keys, rollback/replay, stale/corrupt/offline behavior, essential-network exclusions |

## Cross-cutting requirements across the other 71 layers

1. **Networking:** full IPv4/IPv6 safety parity and reliable WFP rule ownership, packet/connection telemetry, rate-limiting, scan-detection evidence, intrusion signatures, DNS, WLAN and gateway tests (especially 2–9 and 14–24).
2. **Endpoint:** sufficient event-provider fidelity, real-time telemetry coverage, privacy-preserving process attribution, appropriate kernel/driver/boot integrity evidence, ransomware/USB/Defender behavior and false-positive bounds (25–40, 75–79).
3. **Fail-safe operation:** power loss, installation interruption, Windows firewall state rollback, changes by third-party software, service restart, disk full, actual log integrity across rotations and release downgrade resistance (53–71).
4. **Offline resilience and reporting:** measured backup/restore verification on external destinations, practical recovery workflows and signed-update provenance; avoid treating local same-disk copies as independent backup (66–74).
5. **Per-layer acceptance:** original behavior, actual enforcement or observation, positive/negative tests, false positives, resource budgets, non-admin permissions, recovery, Windows 10/11 compatibility and hardware/driver support explicitly documented in all 79 rows.

## Delivery sequencing and stop/go rule

Keep building and validating the missing native security mechanisms in isolated CI environments; record exact code, fixtures, Windows test results and limitations against the originating layer ID. **Do not approve owner hands-on testing merely because all unit tests pass**. It becomes eligible only after each original layer has a genuine implemented path rather than a stub, simulation, or status message, and an internal preflight has found no unresolved critical defects. Windows hardware acceptance, trusted publisher signing, the historical Gitleaks audit, and independent security review then follow for actual production release.

Remaining work is engineering work, **not user homework**. Never mark a layer fully certified without its evidence; never disable existing Microsoft Defender or Windows Firewall on the owner's production PC for the sake of a coverage score.
