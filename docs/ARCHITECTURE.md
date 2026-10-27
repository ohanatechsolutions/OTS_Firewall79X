# Architecture and boundaries

Core contains the complete catalog, framed JSON protocol, scoring, deterministic detection helpers, atomic persistence, compare-before-restore journal, and report generator. Windows contains the OS adapters, event collector, protected log store, telemetry checks, service engine, and IPC server. Service hosts the engine through SCM. App is an unprivileged WPF process. Recovery is a separate UAC-required executable with an allowlisted command set.

No network HTTP administrative endpoint exists. Named pipes deny network tokens, allow interactive local reads, and require an impersonated elevated administrator token for mutations. Messages are bounded before allocation. Recovery can restore offline only after the service stops. Active state and pause deadlines are persisted; incomplete journal entries are recovered before reactivation.

System changes are limited to machine AutoRun policy; no broad firewall modifications are guessed. Prepared intent is flushed before changing the OS. Restoration only writes an old value if the current value still equals the applied value. External later changes remain intact. Full compare-and-swap across arbitrary registry writers is not possible; concurrent modification stress testing remains required.

Sensors use fixed WMI queries, native IP Helper, Event Log, registry and filesystem APIs. They do not execute downloaded scripts or arbitrary shell commands. Source observations are interpreted as heuristics rather than certain malicious verdicts. Restricted/exited process metrics are omitted with a stated limitation.

The UI calls a UAC helper for changes; sensitive user-scope tasks run as the current user. Password breach requests are explicit and range-based. Encrypted report archives use AES-256-GCM, random nonce/salt and PBKDF2-SHA256 (600,000 iterations). Secrets scanning returns indicator types/paths without values. Interactive monitors stop with the UI or global OFF.

Service logging uses an administrator/SYSTEM directory, DPAPI-encrypted HMAC key, bounded JSONL segments and gzip rotation. Chain verification and persisted cross-segment counters remain incomplete. Full security acceptance and hardware qualification are outstanding.
