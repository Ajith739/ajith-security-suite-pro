# Gracewell Security Suite Pro — 1.3.0-rc.5

**Development release candidate. Staging only; not independently security certified.**

## What was merged

- Based on the user's `(9).zip`, preserving its bounded multipart, REST, XML, upload and native-request WAF inspection, virtual-patch integration and additional developer tests.
- From RC4: conservative private-file-path bot probe detection, optional repeated-probe IP holds (off by default), WAF configuration controls, two bot rule metadata entries, policy-aware XML-RPC filtering, restricted standalone scanner file reads, exact password-breach suffix parsing, and endpoint-scoped virtual patch evaluator fixes.
- From RC3: read-only Security Doctor diagnostics in Settings and administrator-gated `wp gracewell doctor --user=<admin> --format=json|text` command.
- Retained `(9)`'s concurrency-safe counter admission logic and deeper REST/virtual-patch input handling rather than overwriting those with older RC4 implementations.
- No intentional database schema changes; existing option keys remain supported.

## Verification performed in this build environment

- PHP syntax checked for every source file and bundled isolated test file (146/146).
- The existing multipart WAF fixture set: 21/21 pass.
- New RC5 isolated smoke checks: 32/32 pass (bot paths, mode policy, XML-RPC, virtual patch scope, scanner containment and breach matching).
- Isolated WAF coverage/corpus and no-DOM tests completed without failure.
- Broad WAF inspector regression: 14/15, remaining XML parser check requires PHP DOM extension unavailable in build runtime.
- XML fixture script cannot execute in this build runtime because `mbstring` is not installed. Retest on target PHP with DOM and mbstring.
- WordPress database integration, PHP/Apache/Nginx/FPM execution, live WooCommerce checkout, backup restore, and end-to-end security attack benchmarks **not** executed. Earlier `(9)` docs report failures in a separate, fuller PHPUnit run; do not interpret this build as fixing all of them.

## Deployment precautions

1. Use a **disposable staging WordPress installation**, with a complete offsite database/files backup and a tested rollback procedure.
2. Deactivate the previous edition but **do not uninstall/delete it**, to preserve shared data. Keep Free/Pro mutually exclusive.
3. Install and activate this ZIP under the existing `gracewell-security-suite-pro` plugin slug. Confirm that site data and previously enrolled authentication methods remain available.
4. Validate PHP 8.0+ with DOM, mbstring (for full test scripts), sodium and expected database/server extensions.
5. Verify logged-out and logged-in requests, Gutenberg editing, WooCommerce checkout, REST endpoints, webhooks, file uploads, and XML-RPC/report-only behavior.
6. Open Settings → Security Readiness Diagnostics. The panel is a **configuration checklist**, not a protection score.
7. Leave automatic IP holds **disabled** until reverse-proxy IP trust, NAT/shared networks and false-positive cases are verified.
8. Validate the early HTTP firewall path separately. A WordPress `init` WAF does **not** inspect static/private files served directly by the web server; add server-level denial rules and verify them.
9. Run the original project's integration/PHPUnit suite from a **separate trusted development checkout**, never production. The development suite and `tests/.runtime` have been excluded from this installable ZIP.
10. Treat signed threat feeds as inactive until a real, authorized, monitored feed service with valid keys is configured. Do not assume Wordfence parity or full malware repair.

### Open acceptance blockers

- Full WordPress/MySQL integration regression suite passing, including existing `(9)` failures.
- PHP DOM/XML fixtures passing on a suitable runtime.
- WAF false-positive testing across authoring, media, forms, WooCommerce and third-party plugins.
- Early-loader/server-layer deployment security review, and sustained traffic performance measurements.
- Quarantine/database backup/restore verification with clean rollback in staging.
- Separate validation of whether the hardened standalone scanner is called by the live scan pipeline and of live threat-feed provision.

This archive intentionally excludes local WP runtime, credentials, build scripts and test dependencies.
