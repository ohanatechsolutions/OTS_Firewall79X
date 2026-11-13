# Release gates

A Architecture: PARTIAL — native app, service, authenticated IPC, journal and full catalog exist; specialized engines remain incomplete.
B Functionality: PARTIAL — available functions have Windows integration evidence; full 79-layer scope is incomplete.
C Security/stability: PARTIAL — regression, privilege boundary, spoofed endpoint, hostile framing and recovery checks have passed on Windows CI; broader fault injection/hardware qualification remains.
D Installation: PARTIAL — actual EXE application/installer, bundled runtime, installation/upgrade/uninstall verified on Windows Server 2025 CI. Windows 10/11 hardware validation is outstanding.
E GitHub delivery: source and operational build/release workflow present. Exact main-branch and release publication evidence is provided by the associated GitHub run and release manifest.
F 79-layer coverage: FAIL — all IDs are accounted for, but required capabilities remain incomplete.

A stable production release is prohibited until all required gates pass. The automatically published development prerelease is not final acceptance and must be clearly labelled incomplete.


**Packaging-specific caveat:** Historical source archives could contain a non-executable Git LFS pointer under an `.exe` filename. The current source tree no longer tracks compiled installers. Only the verified release ZIP or standalone Release asset is an installer for ordinary users. The release ZIP now intentionally includes `installer/OTS-Firewall79X-Setup.exe` and its matching checksum. The matching verification gate is `scripts/verify-distribution.ps1`.

## Mechanical release coverage validation — November 13, 2026

`scripts/verify-layer-coverage.ps1` checks that the original 79 numbered requirements, `catalog.json`, and `LAYER_COVERAGE.md` agree exactly on IDs/names and contain all six substantive coverage fields. Every build runs it. A build configured with `OTS_RELEASE_CHANNEL=production` additionally fails until 79/79 rows explicitly carry the full independent-certification status. **Do not use a passing preview build, test count, runtime Healthy flag, or an unreviewed status edit as acceptance evidence.** The tracker currently has **zero** full-spec certified layers. Production acceptance requires tests and review for each row, not merely changing its text.

The owner has requested that no owner-performed testing be requested until engineering has completed every original layer mechanism. Windows Server 2025 CI continues in the interim; physical Windows 10/11 trials and final independent certification are release gates after code completion.
