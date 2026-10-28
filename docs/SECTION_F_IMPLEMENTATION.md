# Section F — Hardening and Security Audits (Layers 46–52)

**Status: partial implementation, not certified or production-ready.** These audits do not prove that the computer is safe; no source file, UI health badge, or missing WMI result may be treated as proof of protection.

## Layer scope and evidence

| Layer | Added implementation | Outstanding acceptance requirement |
|---|---|---|
| 46 Windows Security Hardening Audit | DEP/UAC/LSA/SMBv1, TPM/OS drive encryption, Defender, process ASLR, machine idle-lock policy, local password/lockout policy, VBS/Device Guard. Provider failures are unknown, not healthy. | System-wide exploit protection, effective domain policy, actual interactive screen lock, permissions/ACL audit, firmware/TPM and encryption recovery validation. |
| 47 Reversible Automatic Hardening | Closed registry allowlist: NoDriveTypeAutoRun=255, NoAutorun=1, NoAutoplayfornonVolume=1. Existing journal snapshots before modification and restores only OTS-owned unmodified settings. | Test pre-existing and Group Policy-controlled settings, crashes, upgrades, reboot, MSI/installer uninstall and all per-setting rollback variants on real Windows. Legacy protocols are not silently disabled. |
| 48 Browser Security Audit | Bounded profile and extension enumeration for Chrome, Edge, Brave and Firefox; Chromium Safe Browsing policy indicators and extension manifest capabilities. Never reads cookies, passwords, sessions or browsing history. | Verify actual publisher and extension signing, Firefox policies/signature, effective centrally managed settings, all profiles and safe browsing versions in physical browser matrix. |
| 49 External Exposure Assessment | Local TCP listener/nonloopback and management-port visibility explicitly differentiated from externally verified reachability. | Authorized genuine external network observer is NOT configured. Current implementation cannot claim externally reachable services or absence of exposure. |
| 50 Secrets Hygiene Scanner | Authorized selected folder only; category/path-only findings; bounded 5,000 files, 256 KiB/file, 64 MiB total, 2 minutes, 2,500 indicators; reparse avoidance and generated-tree exclusions; more token patterns. | Reparse race/ACL/encoding and fixture tests, customizable exclusions, false-positive validation, encrypted report export as needed. |
| 51 Remote Feature and Hardware Audit | RDP/Remote Assistance, device wake WMI, Intel local service, DMA policy, nonloopback management-port indicators. | AMT firmware provisioning, actual DMA hardware capability, magic-packet behavior, BIOS/UEFI and external reachability. |
| 52 Updates and Vulnerability Assessment | Background read-only Windows Update Agent search for missing non-hidden software updates; severity count where provided; six-hour cache and honest provider failures. | VERIFIED THIRD-PARTY CVE CORRELATION IS NOT IMPLEMENTED: requires trusted advisory data, package/version identity, fixed-version mapping and stale-data checks. Driver/firmware vendor inventories require hardware tests. |

## Safety contract

No Windows firewall rules, Defender settings, BitLocker protectors, browser policy or password material are changed. Only three machine AutoRun/AutoPlay DWORDs are written through the established change journal. Pre-mutation intent is stored on disk; OFF compares current values and preserves third-party changes. Recovery executable and installation smoke tests exercise rollback. Unknown data and unauthenticated vulnerability inferences cannot be presented as verified.

## Validation added

Core unit tests cover detection categories without plaintext, binary/placeholder negative cases, and restoration/conflict preservation with multiple journal entries. Windows integration tests check all three hardening DWORDs, host-evidence availability, management-port classification, local versus external exposure disclaimers, and Windows Update provider status. Installer smoke tests check that all original hardening DWORD values are restored.

**Not yet run or passed by this document alone:** real Windows hosted workflow after this branch, physical Windows 10 and Windows 11 Home tests, managed browser profiles, actual external scanning, authorized firmware controls, third-party CVE evidence, and full source/hardware acceptance.

Do not mark any of the seven original checklist items certified until all their original specifications and validation gates pass.