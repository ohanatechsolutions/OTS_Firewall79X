# OTS Firewall79X recovery

1. If the desktop app works, open Settings & Recovery and select Restore previous configuration. Approve the real Windows UAC prompt.
2. If the desktop app fails, open OTS Firewall79X Recovery from Start. It is a separate compiled executable and requests Windows administrator authorization.
3. If the service is unreachable, the recovery tool first verifies the service is stopped, then restores its allowlisted journaled settings. A later change from another application is retained and marked as a conflict, not overwritten.
4. Use Windows Settings → Apps → OTS Firewall79X → Uninstall. Uninstallation stops if restoration fails, leaving recovery files available.
5. If Windows will not start, use standard Windows recovery/Safe Mode and run the installed recovery executable when available. This distribution is not bootable media and does not promise operation in every WinRE environment.

Advanced administrators can run `OTS.Firewall79X.Recovery.exe --restore` or `--off`. Do not delete Windows firewall rules indiscriminately. OTS's current journal only owns the machine AutoRun setting; it does not replace the firewall policy. Protected logs and journals remain after uninstall for diagnosis.
