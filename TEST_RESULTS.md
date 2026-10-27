# Test status

## Executed evidence

- **PASS:** all application, service, recovery, core and Windows adapter projects compile using .NET SDK 10.0.403; latest local build has zero warnings/errors.
- **PASS:** 31/31 core regression checks, including 1,000 malformed framing samples, durable interrupted transactions, preservation of external changes, detection heuristics, coverage reports, and AES-GCM archive authentication/tamper tests, verified folder restoration, non-overwrite behavior and archive path-traversal rejection.
- **PASS:** first Windows Server 2025 CI build at commit `e076dc3e9a541333ddde8a54866a8120b7d34922`: real application/recovery PE executables and installer compiled; clean install; UI launch; activation; local self-check; pause/resume; OFF/restore; firewall-rule preservation; upgrade; clean uninstall and post-uninstall rule preservation. [Run logs](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40506910435).
- **PASS:** all 15 Windows integration checks at commit `a24a756081e9f61d08e5e1d0b55a459c609b5496`, including standard-user rejection of privileged commands, malformed IPC, real telemetry, original AutoRun restoration, and preservation of later independent changes. [Run logs](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40507817244). A prior pass does not verify later source changes.

## Not established

Windows 10/11 physical-device compatibility, WLAN/Bluetooth/TPM/USB hardware behavior, reboot persistence, full installer interruption/chaos tests, trusted code signing/automatic updates, complete 79-layer integration, and target-laptop resource benchmarks are **NOT RUN** or **BLOCKED by unavailable target hardware/signing identity**, as applicable. No hardware behavior or full acceptance gate is reported passing without evidence.

The workflow emits core-test-results.json, windows-test-results.json, windows-observed-status.json, vulnerability-report.json, installer logs, BUILD_MANIFEST.json and SHA256SUMS.txt. The finalized release ZIP includes its actual executed test results. High/critical dependency findings prevent finalization. Checksums do not establish a trusted publisher identity.
