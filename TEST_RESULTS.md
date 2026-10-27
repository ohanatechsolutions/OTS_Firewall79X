# Test status

Core regressions: **PASS — 28/28 executed** in the Linux build environment using .NET SDK 10.0.403. Includes interrupted journal writes/recovery, external-change preservation, framing corpus, authenticated archive tamper tests, score behavior, heuristics, and report accountability. Exact machine-readable results are emitted by the test executable.

Windows backend compilation: PASS in cross-targeted build. Full desktop/service/recovery compilation and Windows installer tests are still being run; consult CI for the artifact's exact commit.

Windows 10/11 physical-device, Bluetooth/Wi-Fi/TPM/USB hardware, reboot persistence, standard-user IPC rejection, full chaos/interruption, trusted signing/update, complete 79-layer integration and performance benchmark tests: **NOT RUN** or **BLOCKED by unavailable target hardware/signing identity**, as applicable. These are not treated as passing.

The workflow writes actual core-test-results.json, windows-test-results.json, vulnerability-report.json, installer logs, build manifest and package hashes. A workflow definition is not evidence of execution.
