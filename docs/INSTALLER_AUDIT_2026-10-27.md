# OTS Firewall79X — installer and security acceptance audit (2026-10-27 Hawaii time)

> Historical audit snapshot: statements below about a setup EXE tracked in Git LFS describe the repository **on October 27, 2026**, not the current branch. As of November 13, the current repository ignores the compiled installer and distributes full executable bytes through CI artifacts and explicitly published GitHub Release Assets. Preserve this audit as historical evidence; current instructions are in `installer/README.md`.

## Scope and methodology

Reviewed the user-requested one-click Windows 10/11 x64 installer and matching SHA-256, source/release distribution methods, CI release generation, service and recovery, security feature coverage, and prior code/quality requests. Existing run [#25](https://github.com/ohanatechsolutions/OTS_Firewall79X/actions/runs/40636379755) provided Windows Server 2025 evidence; a physical Windows 11 Home test was **not** performed. This document is not a certification or a completed 79-layer implementation.

## Defect: executable in source archive is an LFS pointer (confirmed)

`installer/OTS-Firewall79X-Setup.exe` in the Git object is a 134-byte Git LFS pointer. Its actual LFS object for preview.25 is a 117,795,317-byte Windows setup program (SHA-256 `6cf1041de3ddb92566ac117d931661fb99afea61b4ddd7eac23c6076322c98fd`). GitHub-generated *source-code* archives are not guaranteed to embed LFS objects. Attempting to execute the pointer can cause Windows' "This app can't run on your PC" message. A GitHub release ZIP is distinct from source ZIP.

**Repair:** Package the full setup EXE and matching checksum inside the `installer/` folder of the compiled Release ZIP, with an automated test of exact ZIP-to-standalone SHA-256 equality, PE format, real file size, and checksum. Explicitly warn users against using the source archive. LFS tracking of the source repository file remains; GitHub's separate archive setting is not changed by this patch.

## Additional repairs

- Explicit machine/executable integrity test at packaging, rather than relying on filename or first two bytes alone.
- Checksumming the exact installer delivered in the compiled ZIP and checking it matches the standalone release asset.
- Preserve in-memory archive plaintext cleanup on all restore outcomes, including I/O errors.
- Keep installation and release instructions aligned with the actual ZIP folder layout and published assets.

## Requirements and audit status

| Requirement | Assessment |
|---|---|
| Windows 10/11 x64 desktop application and real executable | Native WPF app builds. Windows Server 2025 CI confirms build/install; physical Windows 10/11 Home hardware test outstanding. |
| Download ZIP, install without SDK/other apps | Release ZIP bundles app/runtime, service, recovery; source ZIP LFS pointer is not installable. |
| `installer/` EXE and `.sha256` | Git LFS executable and checksum tracked in repository; compiled Release ZIP embeds actual executable and its checksum. |
| One-click ON/OFF, pause, restore | Implemented; Windows CI exercises operations. Only implemented subset becomes active. |
| Preserve existing Windows Firewall and restore owned changes | AutoRun journaling, compare-before-restore, firewall rule snapshot comparison in Windows smoke checks. |
| Security privilege boundary | Local named pipe, server-process check, elevated write requirements, unprivileged negative test. |
| 79 fully independent functional layers | **FAIL:** all 79 IDs documented, but implementation is partial; see `LAYER_COVERAGE.md`. No complete packet/IDS/threat feed blocking engines. |
| Production quality/reliability | **NOT VERIFIED:** arbitrary interruption/chaos, reboot persistence, hardware coverage, signed installer, automatic updates, full 79-layer tests. |
| UI and branding | Seven-screen slate/steel-blue WPF UI with supplied PNG/ICO active, existing UI screenshots/test evidence. |
| Branch cleanup | Only `main` remains at time of audit; prior UI merge is recorded in `docs/BRANCH_RECONCILIATION.md`. |
| Security update policy | No independently verified trusted automatic update delivery. |
| Publisher authenticity | Installer remains unsigned; SHA-256 is integrity-only. |

## Important remaining blockers

1. GitHub-generated source ZIP files can still include a 134-byte LFS pointer. This requires changing GitHub's repository LFS archive inclusion setting, or using the intentionally compiled Release ZIP. Neither this change nor SHA-256 can make a text pointer executable.
2. The original complete 79-layer specification is not implemented. Do not advertise full firewall/IDS/ransomware/antimalware protection from the current preview.
3. A physical Windows 11 Home execution, reboot persistence, SmartScreen signing and old Windows 10 build compatibility are not demonstrated by Windows Server CI.
4. Unsigned code lacks publisher authenticity. Developer signing credentials and independent security testing are not provided.

## Evidence

Review the successful Windows CI run for this audit's source revision and the related Release assets. The automated distribution gate must be green before describing the new installer ZIP as verified.
