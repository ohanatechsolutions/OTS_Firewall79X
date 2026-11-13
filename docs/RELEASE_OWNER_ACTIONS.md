# Release owner actions — OTS Firewall79X

**Status: incomplete development preview. Do not advertise the suite as 79 production-certified protections.**

All ordinary application implementation, unit testing, packaging and GitHub workflow development remain engineering responsibilities. The following items genuinely require physical access, outside authority, or identities that should not be transferred to ChatGPT.

## 1. Investigate historical secret findings (release blocker)

The manual **Publication security scan** failed on November 4, 2026 (examples: runs 41754228545 and 41753936034). It exited on potential Gitleaks findings; that does **not** establish whether the flagged text is an actual live secret. Investigate **metadata-only** finding paths, commits and rule IDs from the private GitHub Actions job summary in a controlled environment. Do not paste secret values into issues, logs, PRs or this conversation.

- If a finding is a real credential, **revoke/rotate** that credential at its issuer and check access logs; deleting current source does not revoke exposure in Git history or previous release assets.
- If a finding is a false positive, document a scoped rationale and add a narrowly targeted, independently reviewed allowlist entry; never globally disable or ignore the scanner.
- Evaluate exposure from historical Git LFS objects and previous binary release assets separately. The Gitleaks text scanner does not cover those bytes.
- Rerun the manual scan and require a verified **success** before publishing a new development preview. Do not rewrite public Git history without a separately reviewed migration/notification plan.

## 2. Provide a trusted code-signing identity (required for production)

Obtain a legitimate publisher signing certificate issued to the intended legal publisher. Keep the private key in a trusted signing environment/secret store; do **not** share the raw PFX or password in chat or commit them to Git. The current scripts support a separately pinned publisher SHA-256 thumbprint and an explicitly authorized signing workflow. The release must verify the actual signed installer and bundled binaries with that independently configured fingerprint. A SHA-256 file alone is not code signing.

## 3. Physical Windows device acceptance (required for production)

Test on supported, fully patched **Windows 10 and Windows 11 x64**, including **Windows 11 Home** and representative nonadministrator accounts. On disposable or recoverable test machines:

- Verify a real Release asset EXE is executable and installs without extra apps; test activation, OFF, Restore, upgrades, uninstall and recovery across reboot, offline, disk-full and interrupted operations.
- Validate actual firewall rule ownership and expiration, audit-channel availability, RDP lockout safety, WLAN/Bluetooth/USB devices, Defender scan outcomes, battery/disk load, multiple monitors and DPI.
- Configure a test removable drive and network share for encrypted off-device logs; verify the service account can write, delivered files restore under the recovery passphrase, and failures never discard local queued evidence.
- Use an isolated, authorized lab for negative/positive attack tests. Do not test abusive traffic, login restrictions or live threat domains on a production network.
- Record the OS build, test steps, result, logs, hashes and rollback outcome for each of the **79 original layer acceptance criteria** in the build specification.

## 4. Independent release security review

Arrange review of privileged named-pipe authentication, Windows service privileges, update installer provenance, filesystem reparse/race behavior, signature/recovery flow, history findings and external threat feeds. Software should not receive a production label until all release gates in `docs/ACCEPTANCE_GATES.md` pass.

## 5. Release publication

After all mandatory gates pass, use **Actions → Windows build and installation verification → Run workflow** on `main` to create a *development preview* via the existing explicit release job. The history scan now blocks that publication if potential findings remain. For production, use only an independently authenticated publisher signing setup, passing CI, verified install tests, and a separate release decision. Never download the auto-generated GitHub Source Code ZIP as an installer.

These are owner/external dependencies; they are not evidence that all 79 security mechanisms are complete. Engineering must still implement and test the missing functionality documented in `LAYER_COVERAGE.md`.
