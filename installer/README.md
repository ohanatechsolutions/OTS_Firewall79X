# OTS Firewall79X — install the actual Windows executable

**Important: Do not use GitHub's green Code → Download ZIP as an installer.** The repository tracks its large setup program through Git LFS, so GitHub-generated source ZIP files can contain a **134-byte LFS pointer** named `OTS-Firewall79X-Setup.exe`. That is text, not a Windows executable, and Windows will report that it cannot run.

## Working offline-capable installer

1. Sign in to GitHub if required (this repository is private).
2. Open [OTS Firewall79X Releases](https://github.com/ohanatechsolutions/OTS_Firewall79X/releases).
3. Download **OTS-Firewall79X-Windows-x64.zip** from the latest successful *development preview* release. This is a compiled package, **not** the auto-generated Source code ZIP.
4. Extract it. Open the **installer** subfolder and run **OTS-Firewall79X-Setup.exe**. Approve Windows administrator authorization. Alternatively, download the standalone setup EXE from Release Assets.
5. The real installer is over 100 MB, not 134 bytes. It is for x64 Windows 10/11, and its app has not yet been qualified on a physical Windows 11 Home PC.

The release ZIP contains both `installer/OTS-Firewall79X-Setup.exe` and `installer/OTS-Firewall79X-Setup.exe.sha256`. From PowerShell in the extracted `installer` folder:

```powershell
$actual = (Get-FileHash '.\OTS-Firewall79X-Setup.exe' -Algorithm SHA256).Hash.ToLowerInvariant()
$expected = (Get-Content '.\OTS-Firewall79X-Setup.exe.sha256' -Raw).Split(' ')[0].Trim().ToLowerInvariant()
if ($actual -ne $expected) { throw 'Installer checksum mismatch; do not execute this file.' }
if ((Get-Item '.\OTS-Firewall79X-Setup.exe').Length -lt 10MB) { throw 'The file is incomplete or a Git LFS pointer.' }
'Installer SHA-256 matches.'
```

A checksum verifies downloaded bytes, **not publisher identity**. The current preview is unsigned, and the original 79-layer product remains incomplete. See [known limitations](../KNOWN_LIMITATIONS.md) and [audit](../docs/INSTALLER_AUDIT_2026-10-27.md).

## Developers cloning the repository

To retrieve the real `.exe` from the LFS-backed repository path, use Git with Git LFS installed and run `git lfs pull`. **Normal end users do not need Git or LFS; use the compiled Release ZIP instead.**
