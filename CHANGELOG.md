# Changelog

## 0.1.0 — development preview

Initial native WPF application, Windows service, protected IPC, journaled AutoRun hardening and recovery, Windows observations and heuristics, 79-layer capability catalog, reporting/tools, self-contained packaging, and regression tests. Scope remains incomplete; see LAYER_COVERAGE.md.

## Steel-blue interface refresh

- Dark slate desktop workspace with rounded cards, keyboard focus states, shield status, searchable layers, and live security activity tiles.
- Supplied Ohana firewall PNG in the interface and ICO in the executable, installer, window, shortcuts and notification area.
- Windows UI capture harness renders all seven tabs and compact layout; protection scope is unchanged.

## 2026-11-13 — source hardening (development preview)

- Expanded DNS rebinding observation to cover mixed public/private answers, special-use addresses and strict host/answer parsing; still no packet interception.
- Hardened off-device encrypted-log export against linked directory ancestors and symlink delivery receipts; added regression coverage.
- Made the manual release workflow depend on the historical secret-pattern check; a finding blocks publication rather than bypassing the security gate.
- Added an owner-only release handoff checklist; no production certification claimed.

## 2026-11-13 — bounded monitoring and release-evidence follow-up

- Reclaim expired source histories before declining new sources when the inbound-monitoring table is saturated; no automatic ban is based solely on table pressure.
- Validate IPv4/IPv6 TCP header data offsets, first IPv6 fragments and Hop-by-Hop header position while explicitly distinguishing short captures from malformed packets. The parser is not attached to live WFP traffic.
- Fail Windows CI if the dependency inventory command fails or returns empty/missing framework evidence.
- Added core regressions for all above behaviors.

## 2026-11-13 — distribution instructions corrected

- Removed obsolete current-branch claims that Git LFS contains the executable; installers are generated in GitHub Actions and distributed only through Release Assets.
- Preserved October 27 installer audit as an explicitly dated historical snapshot; current source archives are never installable packages.
- Clarified that release publication is blocked on unresolved secret-pattern scan findings.

## 2026-11-13 — OSV advisory query pagination and bounds

- Implemented up to four strict OSV querybatch request rounds, following per-package continuation tokens for only the incomplete packages. Duplicate advisory IDs are deduplicated and unsupported/oversized data fails closed.
- Bounded streamed responses to 1 MiB per request and explicitly mark repeated tokens or exceeded page budget as incomplete, never an all-clear.
- Added core regression cases for mixed query pagination, malicious token types and wrong response cardinality.

## 2026-11-13 — ransomware signal clock recovery

- Reset stale file-event windows on an out-of-order time sample; preserve a two-minute alert cooldown when the wall clock rolls backward. The heuristic remains observation-only and cannot guarantee prevention or process attribution.
- Added regression cases for destructive bursts before and after rollback.

## 2026-11-13 — encrypted evidence memory and read hardening

- Read encrypted archives from a single size-checked open stream, rejecting size changes instead of trusting a separate pre-read file stat.
- Best-effort clearing of internal encryption/ciphertext/key buffers and partial plaintext when authentication fails, without mutating caller-owned input buffers.
- Wipe temporary plaintext backup ZIP buffers after encryption/verification; add regression tests for caller-buffer preservation and invalid archive sizes.

## 2026-11-13 — selected-folder backups retain empty directories

- Introduced backward-compatible authenticated directory markers so encrypted folder versions restore empty nested directories, not only files.
- Enforced independent 5,000-file/5,000-directory ceilings, canonical relative paths, no-symlink restore paths, zero-length directory markers and no-overwrite restoration.
- Added a nested empty-directory backup, verification, restore and non-overwrite regression.

## 2026-11-13 — firewall-overlap analysis of Windows dotted IPv4 masks

- Recognize contiguous dotted-decimal subnet masks emitted by Windows Firewall COM when checking potential rule overlaps; reject noncontiguous masks and cross-family comparisons.
- Added positive, negative and malformed-mask regression checks. This is read-only analysis and does not establish actual WFP/GPO precedence.

## 2026-11-13 — GUI encrypted report and non-overwrite protections

- Clear transient plaintext/verification byte arrays after encrypted report save and verification, including failures; the immutable managed report string still cannot be guaranteed erased.
- Disallow selecting an existing encrypted-folder backup filename before beginning a new backup, matching the established no-overwrite policy.

## 2026-11-13 — fail-closed signed-package staging verification

- Reject unsigned sidecar payloads, hidden files and nested directories in a purportedly signed staging folder. Strengthened Windows filename and reserved-device validation.
- Validate artifact size from the opened file stream and enforce exact signed-file inventory cardinality; add malicious extra-file/folder and reserved-path tests.
- Signing identity, authenticated update distribution, execution and rollback remain release blockers; this is not a completed automatic updater.

## 2026-11-13 — local anti-rollback guard for feed publication timestamps

- Persist a per-feed UTC publication high-water mark under protected OTS service data. A newly downloaded, even still-fresh, Feodo or URLhaus-derived snapshot cannot replace a newer accepted publication after a service restart.
- Reject malformed/linked state files and stale/future timestamps; preserve a fail-closed state on storage or parsing errors. Separate 24h (Feodo) and 12h (domain mirror) freshness windows.
- Add core regressions for newer, equal, older, stale, future and corrupted publications. This is anti-replay defense in depth, **not publisher signature authentication**.

## 2026-11-13 — independent optional RDP restriction decision

- Fixed event-handler gating that accidentally nested the high-confidence Layer 41 RDP restriction inside a different eight-failure notification cooldown. Reaching 32 nonexistent-account RDP failures now evaluates the independently authorized temporary rule even when the notification is suppressed.
- Retains explicit administrator opt-in, distinct-name requirement, trusted-address exclusions, exact TCP 3389 rule, short expiry and no blocking on ordinary wrong-password events.
- Added regression confirming a valid restriction candidate may coincide with a suppressed low-threshold alert. Windows end-to-end live 4625 rule installation/rollback remains a physical acceptance requirement.

## 2026-11-13 — restart-persistent bounded binary integrity observations

- Layer 35 now maintains protected local SHA-256 observations for OTS assemblies and a small set of core Windows binaries across service restarts. Changes yield an explicit warning; corrupt or linked baseline state is not automatically reset.
- Checks actual file-stream size before hashing and declines linked files/ancestors; caps stored observations and serialized data. A baseline learned on first observation is NOT a trusted publisher signature or proof a binary was originally clean.
- Regression tests cover first observation, unchanged hashes, changed hash after reloading and rejection of a corrupt saved state.

## 2026-11-13 — rollback-safe authentication windows and fail-closed corrupt integrity state

- Reset one source's stale attempted-logon window if the host clock goes backward, preserving warning and opt-in restriction cooldowns so old attempts cannot appear as a new burst.
- Handle malformed persistent binary-integrity JSON as an unavailable audit rather than crashing an entire runtime check cycle or silently replacing damaged evidence.
- Add time-rollback regression tests.

## 2026-11-13 — atomic, non-overwriting encrypted archive creation

- Changed core AES-GCM archive creation to write through a unique same-directory temporary file, flush, and move without overwriting. Failed commits remove only their own staging file and preserve any prior archive.
- Aligned encrypted-report GUI save behavior with the same versioned no-overwrite policy.
- Added regression proving an attempted overwrite preserves the original ciphertext and leaves no staging artifact.
