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
