# Section E — Access and Accounts (41–45)

## Implementation and operating status

Section E now includes opt-in, administrator-authorized, two-minute RDP-only (TCP 3389) source restrictions. Automatic restrictions are **OFF by default** and are cleared on service restart, OFF and restoration. The user enables them in **Tools & reports** after an explicit remote-access lockout warning. The Windows firewall provider executes any rule; no claim is made that a Windows block has dropped a specific packet. No Windows user lockout policy is modified.

### Layer 41 — Brute-force protection
- Security event 4625, logon types 3/10, verified public IPv4/IPv6 source required for per-source monitoring. Threshold 8 failures in two minutes; alert cooldown five minutes.
- Optional narrow RDP enforcement requires **32 failed RDP logons with STATUS_NO_SUCH_USER across at least 5 different nonexistent account names**, all from one eligible public source within two minutes. Usernames are transiently HMAC-tagged in process memory and never written into OTS attack-rule details.
- Exact-IP TCP 3389 inbound rule, maximum eight concurrent RDP sources, two-minute expiry, max one block candidate per source per ten minutes. Local addresses, gateways, DNS, DHCP and nonpublic ranges cannot be blocked. Service startup, OFF, uninstall/restore and expiry reclaim OTS-owned rules.
- Known limitation: NAT/shared IP or a legitimate remote administrator can still be adversely affected; ensure remote/out-of-band access before enabling. Persistence relies on the Windows service manager restart policy; a crash can leave a rule until service restart, expiry sweep or recovery. No absolute lockout guarantee is possible.

### Layer 42 — SSH hardening audit
- Verifies registered Windows OpenSSH service and known listeners, invokes only the trusted Windows system sshd binary for read-only `sshd -T`, checks key ACLs and unresolved Match/Include policy.
- **Fails closed** if SCM service command has ANY extra startup options (not only `-f`), alternate binary or unknown effective contexts. Missing SSH is Not Applicable, not automatically a security success.
- User-specific `Match`, include paths, nondefault ports and external exposure are not independently attested.

### Layer 43 — Credential breach check
- Optional, user-triggered SHA-1 k-anonymity range lookups; five hex characters leave the device over TLS. Padded responses, size limits, strict format/count checks, no redirects/cookies and bounded cancellation.
- Input UTF-8 bytes and digest buffers are cleared; the .NET password string cannot be guaranteed erased. No check is made without the user choosing the feature. A no-match result is not a proof of password safety.

### Layer 44 — Account audit
- Local accounts, enabled built-in Administrator/Guest, password-required flags, Administrators group membership, potential 180-day stale accounts, NetUserModals password minimum/history/max-age and account lockout threshold. Separate baselines detect membership/policy changes.
- Missing data produces incomplete coverage rather than false all-clear; domain/Entra policy and credential quality are not established.

### Layer 45 — Login and privilege alerts
- Event subscription includes 4624/4625 interactive/network/RDP/new-credentials authentication, 4648 explicit credentials, 4634/4647 logoff, 4778/4779 RDP session transitions, 4800/4801 lock/unlock, 4740 account lockouts, 4672 privilege assignment, 4673/4674 sensitive privilege operations, account/group/policy changes, and 4688 observed elevated-process token.
- Dedicated access/privilege counters distinguish category coverage. Native Windows audit subcategories are checked, including Sensitive Privilege Use (0CCE9228 success/failure), Process Creation and account/group changes; they are never silently enabled. The layer reports unavailable whenever mandatory policy categories are missing.

## Acceptance still outstanding

- Positive and negative real-hardware tests on physical Windows 10 and 11, including Home and RDP/SSH combinations.
- RDP rule enforcement and expiry must be verified with authorized lab clients, NAT/shared-IP exceptions, management recovery, crash/service-restart/uninstall, and firewall policy precedence. Never enable restrictions on a remote-only production machine.
- Cover SSH service options, key ACLs, local/domain account samples and audit-policy changes on representative hosts.
- Independently capture password breach API network traffic to confirm privacy claims.
- Pass CI, installer signing/release and full 79-layer production gates; passing feature tests alone **does not certify production readiness**.
