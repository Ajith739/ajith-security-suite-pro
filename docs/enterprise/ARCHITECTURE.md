# Enterprise upgrade: pre-implementation architecture and feature audit

Checkpoint: C:/Users/Welcome/.codex/security-enterprise-checkpoint-20261015 (339 files and SHA-256 manifest). Existing UI edits preserved. Reference read: eight-page Security Plugin Developer Build Guide.pdf in Downloads (named without the requested (4) suffix); standalone Pro architecture takes precedence over its older Free/add-on structure and compatibility baseline.

## Dependency map

Request -> Settings/Network canonical visitor IP -> trusted-proxy verification -> IP_Blocks public/auth enforcement -> Login_Protection attempt/lockout rules -> Two_Factor challenge/TOTP/backup replay guard or Passkeys bundled WebAuthn verifier -> WordPress auth cookies. Recovery uses encrypted provider credentials and password-bound OTP setup/login challenges.

Activity_Logger -> indexed activity table -> Activity_View_Data / Dashboard_Data -> admin views. New event dispatch will follow a successful local insert, project only minimized metadata into a bounded asynchronous delivery queue, and retain local logging when remote services fail.

File_Integrity / Scheduler (WP-Cron) -> resumable Scan_Engine -> Path_Guard + Security_Runtime + Malware_Analyzer -> scan findings/history -> Quarantine_Manager (locked, staged, verified moves/restores). Signed structured signature data will extend the existing analyzer, never execute downloaded PHP.

Admin AJAX gwqsh_action -> central nonce + capability gate -> explicitly whitelisted actions -> sanitized service configuration -> existing WordPress options, database tables, and cron. No new public administration REST route is needed. Existing Passkeys/Recovery public authentication endpoints remain separately constrained.

## Initial status and phases

| Feature | Initial status | Intended integration |
|---|---|---|
| Country access control | Attribution present; enforcement missing | Network attribution + existing authentication/public request hooks, disabled by default |
| Threat reputation | Missing | Opt-in fixed-host adapter, bounded asynchronous lookup, verified cached decisions |
| Advanced alerts | One direct lockout email | Successful local event insert -> deduplicated bounded queue -> wp_mail / Slack |
| Signed signatures | Heuristic analyzer; no signed publisher feed | Verified monotonic Ed25519 data store + existing analyzer |
| WAF | Bounded public GET SQL/XSS/scanner blocking | Existing WAF + rule metadata, report-only new rules, atomic rate counters |
| Remediation | Extensive locked quarantine and verified restore present | Preserve and regression test; add required reauthentication at new high-risk entry points |
| Log shipping | Missing | Same bounded queue, fixed production HTTPS collector adapter |
| 2FA / passkeys | Implemented replay guard, CAS backup consumption, exact origin, UP/UV verification | Audit noninteractive paths, rate counters, password/factor binding |
| Privacy | Retention exists; export/erase/anonymization missing | WordPress privacy hooks, minimized remote projection, retention cleanup |
| Wizard | Missing | Optional resumable disclosure in existing Settings; never auto-apply on upgrades |
| Licensing | Static Pro label; no licensing server | Provider-neutral local state machine; unavailable until provider supplied |
| Hardening / multisite | Existing managed markers and per-site options | Preserve hooks; ensure network permissions and site-scoped initialization |

## Rules for implementation

No new services enabled automatically. No fake license validity, feed reputation, country statistics or signature publisher. Preserve current layouts, hero/Three.js files, existing option keys and security records. Additive, versioned idempotent tables only where required for race-safe bounded work. Implement A foundation, B alerts/signatures/auth, C country/reputation/privacy/shipping, D WAF and remediation checks, E wizard/licensing/UI/tests. Test each phase before proceeding. Commercial endpoints/credentials/signing authority and external compatibility remain explicit release gates.
