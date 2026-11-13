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
