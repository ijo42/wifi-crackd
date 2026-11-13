# Security boundaries

This companion exposes passive receive/observation only. It does not expose or call upstream attack, injection, deauthentication transmission, password recovery, WPS session or disruptive Wi-Fi operations. The optional upstream driver dependency includes broader functionality, but this CLI/UI does not provide access to it.

- Loopback only, random per-process Bearer token, Host/Origin checks, no LAN bind option.
- Keep local connection URLs/tokens secret. Do not attach private service state, logs containing credentials, captures, or survey MAC addresses to public issues.
- RUN_COMMAND is a broad Android permission. Grant only to trusted apps; see README for opt-in and revocation.
- Received deauth/disassociation events are **observations**, not proof of attack or sender identity. Spoofing, retransmissions, missed channels/frames and legitimate disconnections are possible. Protected reason bodies are not decoded.
- Event ring retains at most 150 entries; counters reset on a new survey. Nothing is automatically uploaded or persisted as a packet capture.

No security contact/repository has been configured yet; publication is pending repository ownership. Before public release, the repository owner must provide a private vulnerability-reporting channel (e.g. enable GitHub private vulnerability reporting). Do not post secrets in public issues.
