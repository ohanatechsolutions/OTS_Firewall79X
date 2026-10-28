# OTS Firewall79X 0.1.0 — incomplete development preview

This build is not the completed 79-layer product. It contains working limited monitoring, audits, AutoRun hardening and restoration, a native desktop interface, and user-authorized tools including verified encrypted folder backups (60 MiB / 5,000-file limit). Missing and limited features are explicitly reported. The main dashboard does not claim full protection.

Download the compiled **OTS-Firewall79X-Windows-x64.zip** from GitHub Release Assets, extract it, open `installer/`, and run `OTS-Firewall79X-Setup.exe`. Do not use GitHub's auto-generated Source code ZIP: its LFS `.exe` can be a 134-byte text pointer that Windows cannot run. The standalone `.exe` is also attached directly to the Release. The installer bundles required runtimes and registers the service. Windows administrator approval is required. The application and installer are unsigned. SHA-256 checks download integrity, not publisher identity.

Windows CI tests and package hashes must be consulted for the specific artifact. The default GitHub Source Code ZIP is not an installer. Do not describe unexecuted hardware, reboot, chaos, or full-coverage tests as passing. Known limitations are included in this package.

## Section A network development update

The preview now includes a bounded inbound-source restriction path for verified high-volume Windows 5157 telemetry, with Windows Firewall-owned rule creation, expiration, cleanup on OFF/restart, local-address exclusions, and regression tests. IPv4/IPv6 bound UDP endpoint inventory, Public-profile broad SMB allow-rule review, and Bluetooth radio discovery/connectability observation have been added. These changes are **not** full SYN/UDP/ICMP flood protection, anti-spoofing packet filtering, signed IP intelligence blocking, DNS rebinding prevention, or hardware-certified coverage. Read [Section A network evidence](docs/SECTION_A_NETWORK_EVIDENCE.md).
