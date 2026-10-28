# Section A — Network Protection (Layers 1–10)

**Development preview: zero layers are independently certified against the entire original BUILD_SPECIFICATION.md.**
A live monitoring event, Windows policy setting, or passing CI test is not proof that every attack is prevented.

## Layer-by-layer current state

| Layer | Working capability | Remaining requirement |
|---|---|---|
| 1. Default-Deny Inbound Firewall | Read-only profile/rule audit; Windows Firewall provides real stateful inbound default deny where enabled | Effective GPO precedence, rule exceptions, safe enforcement and physical-machine tests |
| 2. Rate/Flood Protection | Windows Security 5157 already-blocked TCP event monitoring, limited reactive inbound exact-host restrictions | Real SYN, UDP, ICMP and link-saturation mitigation |
| 3. Port Scan Detection | Correct remote source and local destination-port attribution; time-window alert and temporary source restriction | Real-world false positives, NAT, scan traffic and rollback under crash |
| 4. Anti-Spoofing/Malformed Packet | Pure bounded IPv4/IPv6 parser with checksum/fragment/extension tests | Not connected to a live WFP packet source; cannot currently reject packets; runtime Unavailable |
| 5. Threat IP Blocking | Freshness-checked Feodo IPv4 feed with short-lived reactive outbound rules for observed matches | Signed/authenticated intelligence, IPv6 feed, reliable allowlists, network-verdict validation |
| 6. IPv6 Parity | TCP IPv4/IPv6 visibility, bound UDP sockets, IPv6 parser tests | ICMPv6, IPv6 neighbor/fragment and actual UDP flow capture |
| 7. Cloud Metadata Protection | Read-only cloud environment classification | Safe VM-specific endpoint rules and workload-aware exceptions |
| 8. DNS Rebinding | Conditional Windows DNS Client 3008 public-to-private warnings | Actual safe prevention, VPN/split-DNS/DoH handling, independent resolver verification |
| 9. Untrusted Network | Windows Firewall Public-profile default-deny audit and broad SMB allow-rule checks | Automatic reversible public/untrusted Wi-Fi hardening and effective sharing verification |
| 10. Bluetooth | Windows PnP, radio discoverability/connectability and passive cached Bluetooth Classic pairing/connection changes | Bluetooth LE, authorization/active-session attestation and real adapter qualification |

## Windows Security 5157 correctness repair

The recorded SourceAddress and SourcePort represent the LOCAL endpoint; DestAddress and DestPort are the REMOTE endpoint for the documented inbound Windows Security 5157 event. Earlier previews reversed them, risking the wrong source being classified. The BlockedConnectionEvent parser now requires inbound direction %%14592, TCP 6, matching IP families, a public/non-special REMOTE DestAddress and valid ports. It supplies local SourcePort for port-scan diversity; invalid, private, documentation, outbound and UDP/ICMP records are never eligible for this rule path.

The existing EventSensors monitor detects repeated already-blocked attempts. It does not ingest raw SYN, UDP or ICMP packets, and temporary rules are not volumetric flood protection. Windows Firewall provides actual rule enforcement, but creating a rule is not evidence of a dropped packet.

## Temporary firewall rule safety

Only named and verified exact-host Windows Firewall rules qualify for OTS cleanup. The OwnedFirewallRule identity checker requires the expected description, direction, action, protocol, profile, enabled state and RDP local port where relevant. Equivalent single-host Windows selectors, such as IPv4 /32 or /255.255.255.255 and IPv6 /128, are accepted only if equal to the named address. Any wildcard, range, broader subnet or multiple-address selector fails this identity check.

Windows Firewall COM-created rules are persistent, not crash-atomic WFP dynamic-session filters. Normal service expiration, stack OFF, startup and restore attempt owner-limited cleanup. Unrecognized or externally modified reserved-name rules are preserved and reported for administrator review. Never disable the system firewall during recovery or delete unrelated rules.

## Packet header validation and Bluetooth

IpPacketValidator.Inspect performs strict bounded, pure packet-buffer checks: IPv4 header length, declared total length, header checksum, flag and fragment consistency, transport length; IPv6 declared length, extension bounds, fragment reserved bits and UDP length. Truncated captures, ESP or unsupported protocols report Unsupported. A valid fragment header is not full reassembly/overlap safety. Without a live WFP callout or supported packet ingestion, layer 4 must remain Unavailable at runtime.

BluetoothDeviceAudit uses passive Windows Bluetooth Classic cached device enumeration and compares remembered authenticated/connected states. Newly seen paired or connected devices produce alerts with fingerprints rather than unmasked device addresses. The code never initiates pairing, inquiry or radio changes. Bluetooth LE and some other stacks may be invisible; no hardware acceptance has been performed.

## Verification and outstanding acceptance

[Windows CI 40659567574](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40659567574) passed the integrated Section A PR 33 build, core tests, installed application smoke checks, upgrade, uninstall and distribution verification.

[Windows CI 40658412471](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40658412471) passed the earlier Section A isolated temporary-rule creation, expiry and recovery probe. That larger branch was not merged due to subsequent cross-section conflicts; do not attribute all of its tests or additions to current main.

Physical Windows 10/11 Home/Pro, real wireless and Bluetooth adapters, VM/cloud hosts, live packet scanning, flood resilience, DNS split-horizon/DoH and power/resource stress tests remain unverified. The product is NOT a replacement for Windows Defender or Windows Firewall.

For original acceptance requirements, refer to docs/BUILD_SPECIFICATION.md; for per-layer mode and limits see LAYER_COVERAGE.md and KNOWN_LIMITATIONS.md.

## Operational thresholds and safeguards

The inbound scan detector reports a possible scan after twelve distinct blocked destination ports in 60 seconds. A temporary restriction requires a stricter threshold of twenty distinct ports or 150 blocked attempts on at least four ports in one minute. The service limits concurrent restrictions to 32, applies a five-minute expiry and a retry cooldown, and does not claim packet-drop measurement. Triggering remains conditional on the local Windows Security audit provider, public remote address eligibility and the internal-address allowlist.

The service attempts to remove only **verified OTS-owned** firewall rules on OFF, expiry and startup. A reserved-prefix name alone is insufficient proof of ownership. If a crash leaves a rule behind, use the service recovery/restore path and inspect its name, address, description, direction, protocol, action, profile, and enabled status before any manual change. Never blindly delete all reserved-prefix rules or disable Windows Firewall.

## Additional host-policy visibility

Windows `GetExtendedUdpTable` provides PID-attributed IPv4/IPv6 **bound UDP sockets**, not validated UDP flows, remote peers, or payload inspection. Public-profile audits inspect broad SMB TCP 139/445 inbound allow rules, but do not establish effective precedence over managed policies. Native Bluetooth radio enumeration exposes connectability and discoverability, not pairing authorization. Errors and provider limitations must appear as unavailable or partial observations rather than successful enforcement.

## CI-only firewall rule lifecycle test

A disposable Windows runner tests rule installation and owner-limited rollback with `GITHUB_ACTIONS=true`, administrator privileges, and an OFF OTS protection service. It verifies exact source/destination host selectors, expiry cleanup and unrelated-rule preservation through Windows Firewall COM. This is not a measured live SYN/UDP/ICMP flood, real spoofing attack, or physical-hardware acceptance test.

See [Section C network visibility](SECTION_C_NETWORK_VISIBILITY.md), [known limitations](../KNOWN_LIMITATIONS.md), and [recovery guidance](RECOVERY.md) for related feature restrictions.
