# Known limitations — incomplete development preview

This is **not the complete 79-layer product** and must not be presented as a production security suite. The coverage manifest records full requirement gaps even where a narrower implementation runs.

Major unfinished capabilities include packet flood mitigation, packet anti-spoofing/malformed filtering, validated threat-IP/domain enforcement, DNS rebinding defense, established network IDS integration, evil-twin analysis, browser credential-read telemetry, bulk-copy/exfiltration attribution, keylogger inspection, comprehensive vulnerability matching, trusted application auto-updates, off-device log shipping, and automatic post-update regression testing.

Windows event coverage depends on existing channel/audit settings. A subscription does not prove the audit policy emits every required event. Channels are not silently enabled. TCP tables and inventory checks poll and can miss short-lived activity. ARP observations are IPv4 only. Normal administrative changes, software installs, sync tools, legitimate address copies, and regular network clients can trigger heuristics.

Safe hardening is limited to AutoRun. OTS does not replace firewall policy or disable Defender. No new network-blocking rules are installed. The blocked counter does not count Windows blocks as OTS blocks. ON cannot make unavailable capabilities operational. Main dashboard remains Partially Protected.

Desktop balloon alerts require the running GUI and can be suppressed by Windows notification policy. User-session monitoring is opt-in and stops when the GUI closes; settings are currently per-session. Camera/microphone registry observations are incomplete. Browser audit inventories only default Chrome/Edge extension directories. Download scanning uses installed Microsoft Defender and does not request remediation. Its process exit code is not advertised as an independent malware verdict.

Logging is bounded and HMAC-chained, but end-to-end segment verification and durable event counters are incomplete. Counters reset at service startup. Local administrators remain trusted. Resource governor uses budgets, battery intervals, cached heavy inventories, and service CPU/memory backoff; adaptive disk scheduling is incomplete. Layer elapsed times are real; per-layer memory is not fabricated.

Encrypted archives support reports and selected-folder file backups, with a 60 MiB / 5,000-file limit and verified restoration into a new folder. Empty directories, links, ACLs, full-system images and scheduled general backups are not preserved. External shipping remains incomplete. Quarterly report scheduling lacks durable historical trend storage. Recovery kit is not bootable media. Full layer-by-layer configuration controls are unfinished.

Installer is unsigned; trusted update delivery requires a valid signing identity. Upgrade stops the previous protection instance and requires reactivation. Installer transaction rollback after arbitrary interruption, full reboot/chaos tests, unprivileged IPC attack tests, and real Windows 10/11 hardware validation require more evidence before final release. CI Server 2025 evidence does not imply Windows 10/11 passed.
