# Section A — Network protection engineering evidence

This change strengthens **only** the inbound-source restriction path for layers 2 and 3.
It does **not** satisfy the full network-protection acceptance criteria. These are
security capabilities, not a count of completed catalog entries.

## New behavior
- Windows Security **5157** TCP telemetry now uses the Microsoft-documented endpoint layout: `SourceAddress`/`SourcePort` are LOCAL, `DestAddress`/`DestPort` are REMOTE, and inbound restrictions use `DestAddress` as the remote IP and `SourcePort` as the scanned local port. UDP, ICMP, invalid port fields and outbound 5157 records never trigger this auto-ban. Only when the **inbound direction
  field is explicitly %%14592**. Outbound events, malformed ports, private,
  loopback, link-local, documentation, reserved and IPv4-mapped IPv6 addresses are
  ineligible; local interface, DNS, DHCP and gateway addresses are rechecked
  immediately before installation.
- Twelve distinct blocked destination ports within 60 seconds create a scan alert.
  A more conservative threshold of **20 distinct ports** or **150 blocked attempts
  on at least four ports** within one minute triggers an exact-source temporary
  restriction. These are **already blocked connection events**, not raw packets.
- The registered SYSTEM service installs a five-minute Windows Firewall inbound
  *block* rule for only the offending IP. Each rule has a unique OTS-owned name.
  Thirty-two simultaneous rules maximum, a 20-minute retry cooldown, and a bounded
  observation history. Existing rules, profile defaults and Windows Defender are
  left alone.
- OTS removes its own rules on clean stack OFF and on service restart, and attempts
  expiration cleanup while running. Errors are logged instead of represented as
  successful enforcement. No OTS blocked-packet statistics are fabricated.

## Required limitations and outstanding acceptance
- Layer **1**: audit of firewall default inbound deny is not an independent
  validation of rule precedence, statefulness, exceptions or all managed policies.
- Layer **2**: event-triggered *source restrictions* are **not** SYN flood, ICMP,
  UDP volumetric, connection-rate, or link-saturation mitigation. WFP callout
  packet telemetry and lab flood tests are outstanding.
- Layer **3**: source rules are conditional on filtering-platform failure auditing;
  legitimate load, NAT and false-positive scenarios still require physical-host
  trials. A COM-created rule survives a hard service failure until service
  recovery; this is **not crash-atomic**, unlike a WFP dynamic session.
- Layer **4**: no OTS packet parsing or IPv6 extension/fragment validation.
  Windows TCP/IP filtering must not be misreported as an OTS engine.
- Layer **5**: Feodo feed remains *monitoring-only*. HTTPS is not a signed
  intelligence artifact, IPv6 feed indicators are absent, and automated blocking,
  provider validation and allowlist controls remain outstanding.
- Layer **6**: IPv4/IPv6 firewall profile coverage is not feature or telemetry
  parity. Full UDP, ICMPv6, neighbor and flow-telemetry tests remain outstanding.
- Layer **7**: metadata protection remains environment-aware read-only
  classification. Cloud-specific exclusions and tested safe policies are needed.
- Layer **8**: DNS rebinding remains a warning detector. DoH, VPN, private
  split-horizon, alternate resolvers and a safe interception/prevention mechanism
  remain to be implemented. DNS Client event support alone is not prevention.
- Layer **9**: untrusted network/sharing hardening requires profile-aware
  policy verification on real Windows systems.
- Layer **10**: Bluetooth PnP inventory and change alerts are not independent
  pairing authorization, discoverability or connection attestation.

## Verification
Core regression tests cover inbound direction, eligible IPv4/IPv6 addresses,
documentation/private exclusions, threshold hysteresis and cooldown. Windows CI
compiles both projects; full physical Windows 10/11 Home checks, diverse adapters,
VPN/cloud cases, security-log policy variation, and network protocol simulations
are required before claiming Section A is fully complete.

## Emergency recovery
If a Windows crash leaves a temporary rule behind and the service does not
restart, identify rules beginning with **OTS Firewall79X temporary inbound source**
in Windows Defender Firewall with Advanced Security. Remove *only* rules with
this exact prefix, or restart the OTS service to attempt owner-scoped cleanup.
Do not disable the Windows Firewall to recover connectivity.

## Native visibility additions

Windows `GetExtendedUdpTable` now collects PID-attributed IPv4/IPv6 **bound UDP endpoints**, not UDP flows or inspected payloads. IPv6/UDP enumeration failure is exposed as unavailable rather than quietly counted as parity. The read-only Public-profile audit flags broad inbound SMB 139/445 allow rules; policy precedence, share configuration, and active network category still require verification. Native Bluetooth radio enumeration and `BluetoothIsDiscoverable` / `BluetoothIsConnectable` report radio state in addition to PnP inventory changes. These observations do not constitute pairing approval or authentication records.

## Reactive observed Feodo intelligence restrictions

An outbound TCP connection actually observed to a fresh, strictly parsed Feodo Tracker IPv4 endpoint may trigger one five-minute exact-destination Windows Firewall outbound deny rule (maximum 16). The service rechecks that the destination is not a local adapter, DNS, gateway or DHCP address; on expiration or feed staleness it removes its own rules in normal operation. It also cleans up on stack OFF/service restart. This is not proactive full-feed blocking, independently signed feed verification, IPv6 coverage, proof of malware, proof of blocked packets or guaranteed session termination. A hard service crash may leave a rule until recovery.

## Corrected Security 5157 parsing

Earlier Section A builds mistakenly treated the LOCAL `SourceAddress` as the remote attacker and the REMOTE `DestPort` as a scanned local port. The corrected parser rejects unexpected direction, invalid address families/ports, unsupported protocol and special-purpose remote addresses. Both scan alerting and temporary exact-source restrictions use one validated remote destination/local source-port mapping. See Microsoft Event 5157 documentation: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157 .

## Firewall-rule ownership and test isolation

Rule cleanup now requires an exact registered rule prefix, exact public remote IP, direction, action, any-protocol selector, and either an exact current ownership group/marker or the precisely recognized legacy description. A prefix collision with any unrecognized rule causes fail-closed refusal instead of deleting or replacing it. Administrative users remain trusted; these tags are not cryptographic authorization. The Windows integration test no longer starts a second guard, which previously could remove real service-owned temporary rules during testing.

## Bluetooth Classic paired and connection-state observation

Added a passive Windows Bluetooth Classic cached-device enumeration using `BluetoothFindFirstDevice`/`BluetoothFindNextDevice`. It compares authenticated (paired/bonded) and connected flags to the previous observation and raises warnings for newly seen paired or connected devices. Device hardware addresses are never placed directly in alerts: only fingerprints are emitted. It does **not** issue Bluetooth inquiry, pairing, or radio changes. Bluetooth LE and alternative stacks may be unobservable, and Windows cached state does not independently prove user authorization. Real Bluetooth hardware validation remains required.

## Packet-header validation engine (layer 4 — not yet enforcing)

Added `IpPacketValidator.Inspect` as a bounded, memory-safe pure IPv4/IPv6 parser. IPv4 checks include header length, total length, checksum, fragmentation flag consistency and UDP length; IPv6 checks include payload length, extension-chain bounds, fragment reserved flags and UDP length. Unknown encrypted/unsupported protocols and truncated capture buffers produce **Unsupported**, not a blocking verdict. A structurally valid fragment is not deemed safe against overlap/evasion without reassembly. **Critical limitation:** no WFP callout/raw-packet delivery is integrated, so this parser is currently exercised only by tests and does not inspect real host traffic. Layer 4 must remain **Unavailable** in live health reports until safe native packet ingestion and enforced filtering are implemented and tested.

## Live Windows firewall COM lifecycle acceptance probe (CI-only)

A dedicated disposable-Windows-runner probe now requires `GITHUB_ACTIONS=true`, administrator privileges, and a **disabled** OTS service. It simulates validated blocked-event metadata, verifies the exact installed inbound source rule and reactive outbound intelligence rule through the real Windows Firewall COM API, advances expiration, and confirms removal plus complete absence of OTS-owned rules. The existing smoke-test baseline then checks that all unrelated Windows rules remained unchanged. This is **rule creation/rollback testing**, not a live SYN/UDP flood, IP spoofing attempt, or measured packet drop. It must not run on a personal machine.

### Windows Firewall single-host selector normalization

The ownership verifier accepts only a literal single IP, its exact one-host CIDR (/32 or /128), or its IPv4 all-ones netmask variant. It still rejects wildcard, broad subnet, ranges and multi-address selectors. The disposable Windows probe now reports the observed COM fields on mismatch, rather than a generic assertion.
