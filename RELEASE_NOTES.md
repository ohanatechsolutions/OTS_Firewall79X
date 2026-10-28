# OTS Firewall79X 0.1.0 — incomplete development preview

This build is not the completed 79-layer product. It contains working limited monitoring, audits, AutoRun hardening and restoration, a native desktop interface, and user-authorized tools including verified encrypted folder backups (60 MiB / 5,000-file limit). Missing and limited features are explicitly reported. The main dashboard does not claim full protection.

Download the compiled **OTS-Firewall79X-Windows-x64.zip** from GitHub Release Assets, extract it, open `installer/`, and run `OTS-Firewall79X-Setup.exe`. Do not use GitHub's auto-generated Source code ZIP: its LFS `.exe` can be a 134-byte text pointer that Windows cannot run. The standalone `.exe` is also attached directly to the Release. The installer bundles required runtimes and registers the service. Windows administrator approval is required. The application and installer are unsigned. SHA-256 checks download integrity, not publisher identity.

Windows CI tests and package hashes must be consulted for the specific artifact. The default GitHub Source Code ZIP is not an installer. Do not describe unexecuted hardware, reboot, chaos, or full-coverage tests as passing. Known limitations are included in this package.

## Section A network development update

The preview now includes a bounded inbound-source restriction path for verified high-volume Windows 5157 telemetry, with Windows Firewall-owned rule creation, expiration, cleanup on OFF/restart, local-address exclusions, and regression tests. IPv4/IPv6 bound UDP endpoint inventory, Public-profile broad SMB allow-rule review, and Bluetooth radio discovery/connectability observation have been added. These changes are **not** full SYN/UDP/ICMP flood protection, anti-spoofing packet filtering, signed IP intelligence blocking, DNS rebinding prevention, or hardware-certified coverage. Read [Section A network evidence](docs/SECTION_A_NETWORK_EVIDENCE.md).

Layer 5 can react to a sampled established connection to an IPv4 address listed in a currently fresh Feodo Tracker feed by temporarily restricting that exact outbound destination. The source is transported over HTTPS, not independently signed; this does not provide proactive full-feed coverage, IPv6 indicators, DNS/domain blocking, or a proven drop count. Rules are normally rolled back on feed expiry/failure, stack OFF, or restart; physical-host behavior is not certified.

## Section I — Additional Security Coverage (75–79)

The service now includes bounded background download/temporary/removable file scanning through Microsoft Defender, WMI USB attach alerts, ransomware-like file operation monitoring, and a per-process TCP beacon timing classifier. Malicious-domain feed observation is enabled only with a current URLhaus-derived public source. An **optional, explicit administrator-confirmed** Windows hosts sinkhole can block up to 1,000 validated exact hostname mappings and is removed on OTS shutdown/recovery/expiry; normal operation does not enable this block automatically.

The mirrored domain feed is **not cryptographically signed**, Defender owns actual malware verdicts/remediation, USB classification is approximate, and filesystem/network polling can miss activity or raise false positives. These layers are **implemented with significant limitations; not production-certified**. The precise remaining acceptance tests are listed in [docs/SECTION_I_IMPLEMENTATION.md](docs/SECTION_I_IMPLEMENTATION.md).
