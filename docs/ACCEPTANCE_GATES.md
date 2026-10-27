# Release gates

A Architecture: PARTIAL — native app, service, authenticated IPC, journal and full catalog exist; specialized engines remain incomplete.
B Functionality: PARTIAL — available functions have Windows integration evidence; full 79-layer scope is incomplete.
C Security/stability: PARTIAL — regression, privilege boundary, spoofed endpoint, hostile framing and recovery checks have passed on Windows CI; broader fault injection/hardware qualification remains.
D Installation: PARTIAL — actual EXE application/installer, bundled runtime, installation/upgrade/uninstall verified on Windows Server 2025 CI. Windows 10/11 hardware validation is outstanding.
E GitHub delivery: source and operational build/release workflow present. Exact main-branch and release publication evidence is provided by the associated GitHub run and release manifest.
F 79-layer coverage: FAIL — all IDs are accounted for, but required capabilities remain incomplete.

A stable production release is prohibited until all required gates pass. The automatically published development prerelease is not final acceptance and must be clearly labelled incomplete.
