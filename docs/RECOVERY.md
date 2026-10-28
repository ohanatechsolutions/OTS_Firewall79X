# OTS Firewall79X recovery

1. If the desktop app works, open Settings & Recovery and select Restore previous configuration. Approve the real Windows UAC prompt.
2. If the desktop app fails, open OTS Firewall79X Recovery from Start. It is a separate compiled executable and requests Windows administrator authorization.
3. If the service is unreachable, the recovery tool first verifies the service is stopped, then restores its allowlisted journaled settings. A later change from another application is retained and marked as a conflict, not overwritten.
4. Use Windows Settings → Apps → OTS Firewall79X → Uninstall. Uninstallation stops if restoration fails, leaving recovery files available.
5. If Windows will not start, use standard Windows recovery/Safe Mode and run the installed recovery executable when available. This distribution is not bootable media and does not promise operation in every WinRE environment.

Advanced administrators can run `OTS.Firewall79X.Recovery.exe --restore` or `--off`. Do not delete Windows firewall rules indiscriminately. OTS's current journal only owns the machine AutoRun setting; it does not replace the firewall policy. Protected logs and journals remain after uninstall for diagnosis.

## Generated local recovery kit (Section H)

When the service is enabled, it attempts to prepare a protected `recovery-kit` directory under the Firewall79X ProgramData folder. The directory contains printable instructions, a SHA-256 file manifest, an optional checked copy of the separate recovery executable when co-located with the service, OTS-owned configuration exports if available, and a PowerShell helper intended only for an elevated interactive session. The script does not bypass PowerShell execution policy. If the copied executable is not present, use the installed Start menu recovery application.

This is **not** bootable recovery media. SHA-256 checks are corruption checks, not evidence of publisher authenticity. Do not copy recovery journals or logs to an unprotected external destination; they may expose system configuration. Use Microsoft-supported Windows recovery media for operating-system boot failures, and avoid overwriting settings changed by other programs after OTS activation. For generated bundle details and limitations, see [Section H engineering](SECTION_H_ENGINEERING.md).
