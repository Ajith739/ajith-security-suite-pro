# Decisions — 2026-10-20

- Reused GWQSH modules and wp_gwqsh_* storage; no parallel authentication, findings or event schema.
- Replaced throwing Ed25519 calls with a shared fail-closed guard after reproducing the WordPress fallback exception. Native and fallback APIs can differ in malformed-input handling.
- Added a separately disabled enforcement setting for new SQL correlations, so previously approved generic rules cannot approve new code implicitly.
- Retained category/severity labels and added numeric metadata/UUIDs for integrations. Confidence scores are qualitative engineering estimates.
- Deprecated unattended Guardian source replacement. It conflicts with the explicit requirement for confirmed cleanup; the tradeoff is that early detection alone cannot prevent execution. Existing authorized quarantine functionality and past evidence remain.
- Reused existing activity filters/redaction for reporting, with zero-event calendar days, a 200-row detail cap and explicit unknown historical severity/status. Kept the existing CSV exporter and bundled no CDN/PDF library.
- Kept all dashboard, hero, login, 2FA and File Integrity designs/styles/animations unchanged. Added one same-style Activity Log quick action and existing-section WAF configuration field. Browser visual regression is pending.
- Kept existing WordPress minimum and database version. The test installation is WordPress 6.8.3; no compatibility matrix beyond that is implied.
