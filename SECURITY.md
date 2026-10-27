# Security policy

This incomplete development preview is not a substitute for maintained Windows security. Do not submit real credentials, clipboard contents, or personal logs in public issues. Use GitHub private vulnerability reporting if enabled; otherwise contact the repository owner privately through an already established channel. No unverified reporting address is invented here.

Trust boundaries: unprivileged GUI; UAC-authorized helper; SYSTEM service; local-only named-pipe IPC with command allowlist and per-request token authorization; protected ProgramData state. Local administrators remain trusted. Only fixed allowlisted system settings can be journaled. No remotely exposed administrative HTTP server exists.

Threat model and required follow-up: fuzz Windows/native parsers, test pipe-name squatting and token impersonation boundaries, audit reparse-point handling, validate installer interruption recovery, verify encrypted archives and bounded event storage under fault injection, and test standard-user command rejection in Windows. These are release requirements, not presumed passing results.
