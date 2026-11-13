# Test status

## Latest verified CI evidence — November 13, 2026

**PASS: commit `5f4a4d2f3c7bb9638a0d2f20f8e42c1a7c6e2a3e`** on Windows Server 2025 CI: [Windows build and installation verification, run 43419857452](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/43419857452).

- **114/114 core regression tests passed**, including new OSV batch-pagination validation, secure archive/backup memory hardening, legacy file-only archive compatibility, bounded empty-directory backup restore, hostile directory-path rejection, clock rollback behavior, and Windows dotted IPv4-mask overlap analysis.
- **PASS:** application/service/recovery compilation, UI checks, Windows integration/privilege boundary probes, clean install, ON/OFF/restore, watchdog outage detection, in-place upgrade, uninstall and firewall-rule preservation.
- **PASS:** dependency vulnerability inventory and release finalization gates; real installer/ZIP size, PE format, matching SHA-256 and packaged `installer/` contents.
- Verified unsigned installer in that run: **118,221,526 bytes**; SHA-256 `2e0941e34c8ffa09f44e18d72ebc3395784a10dcea9c0cf0436cc7bc4fe04f7d`. This hash identifies **only the run's generated artifact**, not a trusted publisher, and does not match earlier prereleases.
- GitHub Actions job artifacts are short-lived. **No new GitHub Release was published by this push**: publishing is explicit/manual and now gated on the separate full-history secret-pattern scan, whose previous runs recorded unresolved potential findings.

**Release classification remains INCOMPLETE DEVELOPMENT PREVIEW.** This CI run does NOT establish physical Windows 10/11 Home compatibility, 79/79 full defense coverage, full kernel/WFP packet prevention, independent security efficacy, signed trusted update delivery, or a completed production acceptance gate. Keep Windows Firewall and Microsoft Defender enabled.


## Executed evidence

- **PASS:** all application, service, recovery, core and Windows adapter projects compile using .NET SDK 10.0.403; latest local build has zero warnings/errors.
- **PASS:** 33/33 core regression checks, including 1,000 malformed framing samples, durable interrupted transactions, preservation of external changes, detection heuristics, coverage reports, and AES-GCM archive authentication/tamper tests, verified folder restoration, non-overwrite behavior and archive path-traversal rejection, repeated journal cycling and invalid-state rejection.
- **PASS:** first Windows Server 2025 CI build at commit `e076dc3e9a541333ddde8a54866a8120b7d34922`: real application/recovery PE executables and installer compiled; clean install; UI launch; activation; local self-check; pause/resume; OFF/restore; firewall-rule preservation; upgrade; clean uninstall and post-uninstall rule preservation. [Run logs](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40506910435).
- **PASS:** all 15 Windows integration checks at commit `a24a756081e9f61d08e5e1d0b55a459c609b5496`, including standard-user rejection of privileged commands, malformed IPC, real telemetry, original AutoRun restoration, and preservation of later independent changes. [Run logs](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40507817244). A prior pass does not verify later source changes.

## Not established

Windows 10/11 physical-device compatibility, WLAN/Bluetooth/TPM/USB hardware behavior, reboot persistence, full installer interruption/chaos tests, trusted code signing/automatic updates, complete 79-layer integration, and target-laptop resource benchmarks are **NOT RUN** or **BLOCKED by unavailable target hardware/signing identity**, as applicable. No hardware behavior or full acceptance gate is reported passing without evidence.

The workflow emits core-test-results.json, windows-test-results.json, windows-observed-status.json, vulnerability-report.json, installer logs, BUILD_MANIFEST.json and SHA256SUMS.txt. The finalized release ZIP includes its actual executed test results. High/critical dependency findings prevent finalization. Checksums do not establish a trusted publisher identity.

## Installer distribution repair — October 27, 2026 (Hawaii time)

- **PASS:** Windows CI run [#25](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40636379755) completed build, smoke tests, privilege-boundary probes, upgrade and uninstall, and release of a real 117,795,317-byte installer. Its hash was `6cf1041de3ddb92566ac117d931661fb99afea61b4ddd7eac23c6076322c98fd`.
- **ROOT CAUSE:** Source ZIP archives may contain the LFS pointer (134 bytes) rather than the actual 117 MB `.exe`, prompting Windows to say the application cannot run. The *Release* installer was a valid PE binary; user PC execution has not been independently verified.
- **NEW GATE:** verify SHA-256 for real installer and embedded release-ZIP installer, reject LFS pointer files, ensure expected PE header, verify packaging. See `scripts/verify-distribution.ps1` and the CI run for this revision; do not mark the new gate passed until that run succeeds.
