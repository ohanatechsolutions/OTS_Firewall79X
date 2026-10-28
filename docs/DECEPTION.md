# Section B — Deception and Honeypots (layers 11–13)

## Implemented Windows service behavior

Section B is bundled with the privileged OTS Firewall79X service and starts and
stops with the main protection switch. It does not require an extra application,
account, DNS provider, cloud service, or manual listener configuration. All
decoys are **nonfunctional**: no credentials ever authenticate to a real service.

### Layer 11 — Local honeytokens and canary files

- A protected `ProgramData/Ohana Tech Solutions/Firewall79X/canaries` directory
  contains inert `decoy-credentials.txt`, `canary-url.txt`, and
  `canary-dns.txt`.
- The service observes modification, deletion, rename, and unexpected content
  changes via FileSystemWatcher plus an independent SHA-256 inspection every
  ten seconds. Changes to unrelated files do not produce alerts. Identical
  content writes without a changed digest are not classified as tampering.
- The service **attempts** to create narrow, success-only Windows audit rules
  (SACLs) on the three owned canary files only if the pre-existing Windows
  **Audit File System** success policy is enabled. It does **not** change that
  policy. Actual Windows Security Event 4663 read/write/delete events provide
  reported process, PID, and account, with deduplication; the app's own reads
  are suppressed. Rules the service adds are journaled for recovery after
  restart and removed when protection switches OFF.
- If audit-policy, privileges, SACL configuration, Security-log subscription,
  or actual 4663 event delivery is unavailable, file-read monitoring remains
  **conditional**, never silently claimed as universal. Security events can
  also be missed if they were not emitted by Windows or event logs are lost.

### Layer 12 — Local URL and DNS canaries

- Each activation creates an unpredictable URL path hosted on
  `127.0.0.1:<ephemeral port>`; the current URL is saved in
  `canary-url.txt`. Only an *exact* GET/HEAD request to the canary path is
  a canary hit (HTTP 204, no content). Other probes are reported under layer 13.
- `canary-dns.txt` contains a randomly created `ots-<hex>.invalid`
  hostname. Windows DNS Client Operational events 3006/3008 are examined for
  that exact name, if the channel is enabled. The monitor never initiates
  canary queries itself.
- A locally bound listener and DNS Client event stream **cannot detect remote
  access to a canary outside this host**. There is no external canary account,
  public domain, off-machine callback, or fabricated availability indicator.
  Off-machine functionality requires a separately verified, authenticated
  endpoint and is deliberately unavailable in this release.

### Layer 13 — Low-risk decoy service

- A dedicated TCP listener binds exclusively to IPv4 loopback; no 0.0.0.0,
  public IP, IPv6 wildcard, real web application, or vulnerable banner.
- Network reads are capped at 2 KiB per request, two-second deadline,
  six concurrent clients, eight queued connections and 120 accepted clients
  per 60 seconds. Invalid probes get static HTTP 404. Client request data
  is neither executed nor echoed, and only bounded metadata is logged.
- A best-effort IP Helper TCP-table snapshot records a matching process/PID
  when still available. Unattributed probes explicitly say "unavailable".
- Automatic firewall source bans are not installed: a loopback-only source
  ban would endanger local connectivity without a reliable remote source.
  Remote-access honeypots and temporary remote IP bans remain **not enabled**.

## Operational acceptance and safety

The full Windows CI tests exercise the installed service, its real localhost
canary URL, unknown URL probes, file-tamper event generation, and OFF/upgrade
uninstall recovery. Pure regressions cover exact canary paths, DNS hostnames,
and audited-file access masks, including negative/false-positive cases.
Layer status must remain **Monitoring**, not **Enforcing**, and the OTS
blocked-threat counter must remain unaffected.

**Still required before certifying layers 11–13 complete:** CI success,
physical Windows 10/11 and Windows 11 Home verification, SACL/4663 read
attribution tests with real audit policy, verified negative read scenarios,
stress tests with slow clients, crash/rollback tests, and an authenticated
external canary implementation if externally reachable monitoring becomes a
mandatory requirement. Until then the coverage manifest remains **limited**.

Do not use these decoys to store real passwords, secrets, or valuable files.
All events indicate activity warranting investigation; they are not a
guarantee that a process is malicious or that no compromise occurred.
