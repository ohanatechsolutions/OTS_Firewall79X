# Section C — Network and Traffic Visibility (layers 14–24)

Developer: Ohana Tech Solutions  
Scope: Windows 10/11 x64; existing privileged service and monitoring-only interfaces.  
Implementation branch: `feat/section-c-network-visibility-14-24`.

## Safety and evidence

All new OTS collectors are read-only. They do not install packet filters, alter Wi-Fi settings, configure DNS, capture SMTP payloads, or claim that a local listener is externally reachable. Native Microsoft Defender detections are identified as **Defender-owned**, not OTS firewall blocks.

### Per-layer functionality and remaining acceptance checks

| Layer | Implemented in this change | Required for certification |
|---|---|---|
| 14 — Intrusion Detection | Subscribes to native Windows Defender Network Protection audit/block events **1125/1126**. Checks Defender Network Protection/NIS state, reports no native IDS when disabled/unavailable. | Native Defender is an established vendor detection source, not a full independently bundled IDS; independently validated signature/rule updates, controlled malicious traffic detection tests, per-edition coverage and host qualification remain. |
| 15 — Network Metadata/ATT&CK | Attributes Windows Security login, brute-force and process execution signals to narrowly justified *possible* ATT&CK techniques T1021.001, T1110 and T1059.001. | Broader ETW/flow correlation and positive/negative dataset validation; technique labels are hypotheses, not attack confirmation. |
| 16 — Connection and DNS Journal | TCP IPv4/IPv6 PID snapshots, new UDP IPv4/IPv6 bound sockets with owning PID, DNS Client Event 3008 journaling; DNS PID only when explicitly reported by source. | Packet/ETW flow collector to capture ephemeral connections, UDP remote endpoints, reliable DNS-to-process attribution, tunneling evaluation and DoH coverage. |
| 17 — ARP/NDP Spoofing | Windows native neighbor inventory (IPv4/IPv6 via MSFT_NetNeighbor; IPv4 ARP fallback), repeat-confirmed MAC change and gateway prioritization. | Physical wired/wireless spoof simulations, false-positive handling for failover, validated attribution beyond cache-only observation. |
| 18 — Rogue DHCP/Evil Twin | DHCP/gateway baseline plus connected WLAN BSSID changes and **security downgrade** alerts; ordinary roaming treated as info-only. | Real rogue-offer packet visibility, wireless scan/attestation tests and adapter-specific verification. |
| 19 — Listener/Attack Surface | Compares TCP listener and UDP-bound socket snapshots and alerts on new nonloopback low-numbered TCP/UDP bindings. | External reachability checks, policy-aware exposure classification and detection of transient sockets. |
| 20 — New LAN Device | Passive new neighbor alerts across both IP families (subject to Windows provider availability). | Optional safe discovery with explicit opt-in and hardware testing; silent devices are not enumerated. |
| 21 — Unsafe Network | Existing WLAN API plus weak WPA1/WEP/TKIP classification, downgrade checks. | Wireless adapter + WPA2/WPA3/OWE/enterprise test matrix and policy-specific restrictions. |
| 22 — Suspicious SMTP | New TCP events with PID/process attribution on ports 25, 465, 587, 2525, conservative known mail-client exclusions. | ETW capture of brief/non-standard sessions, sandbox test of suspicious apps and false-positive calibration. |
| 23 — Remote Access | Wider service family (RDP, SSH, WinRM, RemoteRegistry, VNC, AnyDesk, TeamViewer, ScreenConnect, RustDesk), RDP enabled transition and common listener checks. | Per-user portable remote-support activity, new-install attribution and dynamic ports. |
| 24 — Clock Drift | Monotonic tick/time comparison (90-second step threshold), optional bounded HTTPS Date read from cloudflare.com (~15-minute cadence; 120-second threshold). | Secure authenticated time source, hardware/VM time-step tests, offline/proxy behavior and resilient trust checks. |

## Privacy and performance

* UDP table enumeration is read-only and capped at 8,000 entries, each address family limited to 16 MiB of OS-returned data.
* Native neighbor records are capped at 4,096 keys. If the IPv6 provider is unavailable, evidence explicitly reports the IPv4-only fallback.
* A socket being bound to a nonloopback interface is not equivalent to external reachability; no auto-block is performed.
* Clock comparison makes a HEAD request to `https://www.cloudflare.com/` (subject to system proxy). It does not use an authenticated NTP protocol or prove signed secure time. If unreachable, only the local monotonic comparison remains.
* DNS logs contain queried domain names and OS-reported status; user data is kept in the service's existing protected event storage. No email contents or packet payloads are collected.
* Alerts are investigation prompts. Connected Wi-Fi BSSID transitions alone are not labeled evil twins; MAC changes require two matching observations. Event persistence and rotation are supplied by the existing event store.

## Regression evidence

* Pure core tests: endpoint parsing, SMTP ports, two-sample neighbor confirmation, clock drift thresholds and evidence-grounded ATT&CK mapping.
* Windows service test: UDP owner-PID table, neighbor provider/fallback, Defender state availability, HTTPS clock-probe response/failure reporting and honest IDS mode.
* CI workflow: `.github/workflows/section-c.yml` on the isolated branch and pull request.

## Required production hardware trials (not certified by CI)

1. Windows 10 x64 and Windows 11 Home/Pro x64, with and without Defender Network Protection enabled. Test 1125 audit vs 1126 blocking with Microsoft-published safe evaluation paths.
2. IPv4/IPv6 hosts, DHCP renewal, router failover, VLAN/VPN and roaming; verify ARP/NDP changes are repeatable without routine false positives.
3. Wi-Fi open, WEP, WPA, WPA2 and WPA3 equipment, with a second BSSID and controlled security downgrade; document restrictions when WLAN API is denied.
4. Ephemeral TCP and UDP traffic, SMTP on all four monitored ports, and remote services on normal/nonstandard ports, comparing Windows capture traces.
5. Authorized system clock step/restore, offline operation, high latency, HTTPS proxy, and time server failures.
6. CPU/battery/storage budgets and log privacy, persistence, crash recovery and retained segment verification.

**Acceptance status:** This is a meaningful implementation expansion, not a completed or certified Section C. Keep all 11 completion-checklist boxes unchecked until the remaining positive/negative hardware tests and engine-capability gaps above are resolved. The whole application remains a development preview.
