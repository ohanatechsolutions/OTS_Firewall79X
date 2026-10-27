# Components and redistribution

Runtime dependencies bundled by self-contained publishing: .NET 10 runtime and Windows Desktop runtime, System.Management, System.Diagnostics.EventLog, System.Security.Cryptography.ProtectedData, System.ServiceProcess.ServiceController and transitive packages. Microsoft .NET libraries are maintained under their upstream licenses; bundled runtime license/notice files are retained. NuGet lockfiles include exact versions and integrity hashes. The generated CycloneDX inventory identifies packages.

Build-only: Microsoft .NET SDK 10.0.403, Inno Setup 6 (compiler available on Windows CI image), GitHub Actions checkout/setup-dotnet/upload-artifact pinned by commit. Inno Setup produces the installer; end users do not separately install it.

OS-provided: Windows Firewall COM, IP Helper, Event Log, WMI, registry, service manager, UAC, named pipes, DPAPI, and Microsoft Defender MpCmdRun when present. No Defender binary is redistributed or downloaded; existing Windows components are invoked.

Optional online check: Pwned Passwords range endpoint, https://api.pwnedpasswords.com/range/ , requested only from its dedicated UI action. Five hash-prefix characters are transmitted; plaintext is not sent; no account/API key required for this range API. No automatic telemetry upload.

No external IDS engine, threat-intelligence feed, signed packet driver, or code-signing certificate is bundled. Those capabilities are not claimed.
