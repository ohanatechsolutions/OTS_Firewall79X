# Section E — Access and Accounts: Layers 41–45

**Status:** enhanced implementation; all five layers still require certification against the full specification.

## Implemented
- Layer 41: Security 4625 events, restricted to remote logon types 3/10 with verified public IPv4/IPv6 source. Correlates eight failures in two minutes with five-minute deduplication and bounded memory. Local, private, mapped, documentation, and invalid addresses are excluded. Alerts only; no unsafe account lockout or automatic ban.
- Layer 42: When a Windows OpenSSH service is installed, run the trusted Windows OpenSSH sshd.exe -T read-only effective default configuration check; inspect service/listener state and access permissions of discovered authorized-key files. Unknown, conditional Match/Include and custom service configuration are not claimed as hardened.
- Layer 43: Optional user-triggered HIBP range lookup over HTTPS with Add-Padding. Only five hex hash characters leave the host. SHA-1 digest computed locally from UTF-8 input. Transient byte buffer zeroed, response constrained to 1 MiB and validated strictly, errors fail closed. .NET immutable strings cannot be reliably erased from RAM.
- Layer 44: Local account status, password requirements, built-in Administrator and Guest, local Administrators group membership, NetUserModalsGet password policy, opportunistic last-logon staleness, and change baselines.
- Layer 45: Audited Windows interactive/network/RDP/unlock/cached logon events, failures, explicit credentials, 4672 special logon, account/group changes, audit policy changes and 4688 full-token signals where the required auditing is enabled.

## Limitations / acceptance gates
- **Automatic brute-force restrictions are NOT implemented**. Any IP block must have allowlists, proven attribution, TTL expiry, independent cleanup, crash-safe persistence and rollback. Locking out legitimate remote administrators is unacceptable.
- Effective SSH -T is not authoritative for every Match context or alternate service binary; unknown ACLs prevent an all-clear. Listening ports do not establish external Internet reachability.
- WMI last-logon and password flags can be missing or stale. Domain, Entra and external identity-provider policies remain unverified.
- Logging coverage depends on Windows Security audit policy and Event Log subscription; no policy is silently changed. Token elevation and special privileges are not synonymous with malicious behavior.
- Core regression tests added for public remote address checks, threshold/cooldown, IPv6, SSH policy parsing and malformed HIBP responses.
- Windows 10 and 11 physical integration, RDP/SSH positive and negative tests, recovery, upgrade/uninstall, end-to-end credential traffic capture and false-positive qualification remain outstanding. Do not certify these layers or the complete application yet.
