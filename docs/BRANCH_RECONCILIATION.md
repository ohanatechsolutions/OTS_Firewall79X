# Branch reconciliation — OTS Firewall79X

The previous UI development line was preserved in `recovery/unmerged-ui-review-2026-10-27`, head `112c8116b7b5601becf495dd8f947f6e14c5c19c`. The independent dark-mode `main` line ended at `112f5a088f360ce0c6a4d8d49ac250d7e1392fe0`.

## Integration decision

The tested recovery-branch seven-screen implementation is the active UI, including its native Windows dark title bar, full-resolution user-supplied `Brand.png` and `Brand.ico` assets, rich security activity cards, integrated live status, screenshot capture checks, improved installer coverage, service protections, and CI artifact collection.

The separately developed main-branch `AppLogo.png` and `AppIcon.ico` are retained in the assets folder rather than discarded; README details from main are retained and corrected to match the actual active assets and UI. Existing underlying security engine and limitations remain unchanged.

The integration commit has **both heads as parents** (main first, recovery branch second), retaining each line of git history, not squashing or force-updating a branch.

## Verification

Both parent heads individually passed GitHub Actions Windows CI, including Windows installer testing. The reconciled main commit must also pass its own Windows workflow before branch cleanup is recommended. Do not claim all 79 defenses are implemented. No firewall control logic is changed as part of this merge.
