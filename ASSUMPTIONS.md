# Engineering assumptions

- Exact existing destination: `ohanatechsolutions/OTS_Firewall79X`; repository was empty at initial inspection. No prior license or application was replaced.
- Windows .NET 10 LTS/WPF with self-contained x64 distribution; runtime 10.0.14 and SDK 10.0.403 observed from official Microsoft distribution. Supported-OS reference: https://github.com/dotnet/core/blob/main/release-notes/10.0/supported-os.md . Windows 10 compatibility must not be confused with current vendor support.
- No custom unsigned kernel driver, TLS interception root certificate, external account, or mandatory cloud service is installed.
- Safe automatic hardening is restricted to machine AutoRun policy. Existing firewall policies are inspected, not replaced, because remote management/third-party rules cannot be safely inferred from an empty project.
- Off preserves independently enabled Windows security and later external setting changes. Protection and detection claims are constrained to observed mechanisms.
- Source delivery is on a feature branch before integration. Stable release requires all acceptance gates. An explicitly labelled development prerelease may carry tested binaries without claiming final completion.
- No code-signing credentials are available. Trusted automatic application updates remain unavailable rather than trusting an unsigned replacement.
- No open-source license is selected on the owner's behalf; recommended MIT licensing and implications are documented for later authorization.
