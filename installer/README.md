# Windows installer

This folder contains the Inno Setup source (`Firewall79X.iss`) and, following successful Windows CI synchronization, the actual `OTS-Firewall79X-Setup.exe` and matching `OTS-Firewall79X-Setup.exe.sha256`.

The compiled installer is larger than GitHub's 100 MiB Git blob limit and is stored through **Git LFS**. A regular clone with Git LFS enabled retrieves the full installer. A downloaded source ZIP may contain only its Git LFS pointer unless the repository setting **Settings → Archives → Include Git LFS objects in archives** is enabled. For an immediate standalone download, use the matching installer attached to the [GitHub Releases](https://github.com/ohanatechsolutions/OTS_Firewall79X/releases) page.

From PowerShell in this folder, run:

```powershell
(Get-FileHash .\OTS-Firewall79X-Setup.exe -Algorithm SHA256).Hash.ToLowerInvariant()
Get-Content .\OTS-Firewall79X-Setup.exe.sha256
```

The 64-digit digests must match. The checksum verifies integrity, **not publisher identity**; this development preview is unsigned and does not implement the full security specification.
