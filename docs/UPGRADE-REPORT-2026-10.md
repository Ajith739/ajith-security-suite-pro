# Gracewell Security Suite Pro 1.1.0

Implemented on 14 October 2026 against the existing working tree. Earlier edits were preserved. Original source snapshot: `D:/GracewellUpgrade/baseline-20261014`.

## Completed fixes

1. **Performance:** WebGL decoration is opt-in; enrollment aggregation is cached; admin assets remain scoped; scan state is compressed, bounded and checksummed; state hydration cannot consume the processing budget; directory cursors resume across batches; path and pagination indexes added.
2. **Time:** shared site-local SQL date interpretation with `wp_timezone()`/`wp_date()`; epoch display uses the site's timezone; reporting and retention cutoffs use WordPress local time. Existing historical dates are preserved.
3. **Proxy:** explicit trusted IP/CIDR configuration, IPv4/IPv6 normalization, selected-header-only behavior, right-to-left forwarding-chain parsing, malformed-header rejection and untrusted-peer fallback.
4. **Country:** asynchronous cached public IP lookup, bounded queue, negative caching, provider abstraction and localhost/private labels. Blocked requests perform no synchronous external lookup.
5. **Dashboard:** readable activity chips, larger/wrapped values, stacked phone records and responsive Pro card with accurate configuration messaging.
6. **Notifications:** shared bottom-right success/error/warning/info toasts, manual close, bounded stacking, auto-dismiss and reduced-motion support; page feedback leaves the hero clean.
7. **Access Controls:** responsive two-column layout, trusted visitor management, separate proxy trust settings and working per-role login protection. Unknown accounts remain protected.
8. **Empty/errors:** reusable PHP/JS components map timeline/authentication/geography and 403/404/500 assets to meaningful states with clear descriptions and applicable actions.
9. **Hardening:** consistent hover/focus transitions, dark-mode colors and touch fallback.
10. **IP restrictions:** temporary/permanent IPv4/IPv6 bans, reasons, expiry, unblock and paginated history; final authentication enforcement; current-session/allowlisted-IP safeguards; audit/firewall integration.
11. **Scheduling:** hourly/twice-daily/daily/weekly/custom cron recurrence, quick/full modes, selected scopes, background run-now, next/last status, overlap prevention and run logging.
12. **Diff:** added/removed colors, amber replacement markers, wrapped code, bounded scrolling and dark-mode support.
13. **Threat sources:** geographic projection of this site's retained denials with cached attribution and an illustrated fallback. No invented global live intelligence.
14. **Settings:** general, security, access, role rules, two-factor policy/roles, firewall, hardening, notifications, appearance, performance, advanced, integrations and scans; section/all reset; versioned secret-free import/export; legacy general-settings imports supported.
15. **Passkeys:** enrollment, rename, removal and native WordPress passwordless login; exact-origin checks, required user verification, signature/counter validation, password-bound enrollment and atomic one-use tickets. Bundled verifier is namespace-isolated.
16. **Email/SMS:** verified recovery destinations, expiring HMAC-protected codes, per-method resend cooldown, account attempt budgets, password-challenge binding and atomic one-use verification. Twilio and registered SMS adapters are supported.
17. **Security engine:** reusable services, final IP-denial authentication gate, credential revocation on enrollment reset, scope-aware missing-file decisions and safe storage-failure responses.
18. **Sales:** updated metadata/readme/version, product copy, keywords, feature summary, screenshot plan, changelog and provider/dependency disclosures.

## New components

`GWQSH_Time`, `GWQSH_Network`, `GWQSH_UI`, `GWQSH_IP_Blocks`, `GWQSH_Scheduler`, `GWQSH_Passkeys`, `GWQSH_Recovery`, `GWQSH_Customization`; shared `upgrade.css`, `upgrade.js`, `passkey-login.js`, and `upgrade-panels.php`. The scoped MIT WebAuthn runtime lives in `includes/vendor/webauthn`; development tooling and examples are excluded from production ZIPs.

The exact source change inventory is appended below after verification; comparison uses the preserved baseline rather than the already-dirty Git index.

## Database and lifecycle

Schema **1.5.0** adds `{prefix}gwqsh_ip_blocks` (active IP/expiry/history indexes) and `{prefix}gwqsh_auth_challenges` (hashed token primary key and expiry index). Findings gain a path-prefix index and `(is_resolved,detected_at,id)` pagination index. Existing records remain intact.

Passkey public keys and owner-only display metadata use user meta. Provider tokens use encrypted storage. Backup codes use salted HMACs and compare-and-swap. Schedule/provider policy uses plugin-owned options. Old chunked scan state remains readable alongside compressed encoding.

Deactivation clears new cron hooks. Uninstall removes new tables/meta only under the existing data-deletion preference. Enrollment reset revokes passkeys and enrolled backups.

## Verification and limitations

Machine-readable results: `upgrade-focused-tests.xml`, `upgrade-service-tests.xml`, `upgrade-integrity-tests.xml`, `upgrade-remaining-tests.xml`, `upgrade-final-regression-tests.xml`, `upgrade-browser-results.json`, `upgrade-phpcs.json`, and `upgrade-benchmark.json`.

The final browser pass verified eight pages in light/dark at 375/768/1280 pixels (48 combinations), correct page routing, manual ban/unban, invalid nonce rejection, dismissible toast and real WebAuthn verification with a virtual authenticator (register/rename/passwordless login/remove). No browser page errors or missing plugin assets were reported. Re-enrollment after removing the last credential was also verified. Temporary accounts and their records were removed.

Completed backend reports cover **169 distinct tests / 3,822 assertions**, with **zero failures/errors and six Windows-dependent skips** (140 remaining + 17 integrity + 12 new service tests). A final overlapping regression pass adds **27 tests / 227 assertions**, all passing. The separate full-tree coverage/malware-fixture test completed successfully in an interrupted six-test run; the following redundant full-tree offline-checksum traversal was stopped. The completed offline-checksum test now uses real `wp-includes` files, and the release scanner regression uses isolated real fixture directories. No claim is made that an uninterrupted whole-suite run passed.

PHP syntax checks passed for **62 runtime/view/bootstrap files**; JavaScript syntax checks passed. WordPress coding standards checks on the eight new services, scan engine and shared panel reported **zero errors/warnings**. A final passkey-service check also passed after the re-enrollment fix. Live SMS delivery, physical authenticators and a full WordPress/PHP compatibility matrix remain unverified.

Measured local data-adapter times were dashboard **26.24 ms / 26 queries**, login **6.08 ms / 6 queries**, firewall **26.02 ms / 8 queries**, integrity **287.98 ms / 7 queries**. These are local measurements, not complete page timings or before/after speedup claims. Default-disabled hero decoration avoids loading approximately **1.29 MB** of JavaScript. Representative repetitive scan metadata compressed from **1,480,011 to 23,932 bytes**; actual compression varies.

Release: `D:/GracewellUpgrade/release/gracewell-security-suite-pro-1.1.0.zip`, **212 runtime/license files**. Runtime dependency inclusion and development-file exclusion were checked. SHA-256: `1CE9B7F1FA20C66FB22A9F70A55C94C6E152C83169E9CC079B45EE735E1468E3`.

Deployment prerequisites: PHP **8.0+**; HTTPS or localhost and compatible WebAuthn support; configured email/SMS delivery; explicit opt-in for public-IP attribution. WP-Cron requires traffic or a server trigger. Quick/limited/custom-root scans cannot establish a complete baseline. Other WordPress/PHP versions, real authenticators, live delivery and POSIX permission/symlink cases require deployment/CI checks. Local testing uses WordPress **7.1.3 / PHP 8.0.30**.

Country blocking, external global intelligence, commercial license billing and support SLA infrastructure are not implemented sales claims. The seller must establish sales terms and illustration redistribution rights. Testing screenshots contain temporary identities and require redaction before marketing use.

## Storage incident and remediation

Long transactional full-tree regressions amplified chunk-state writes and exhausted C:. The interrupted scanner source was restored from the preserved baseline; source files were checked for empty/truncated writes. Development/test artifacts were moved to D:.

The shared options table held **286 rows / about 7.9 MB of live values** despite about **3.2 GB** of allocation. A binary-safe SHA-256-verified private backup preceded data-preserving recreation/analyze. Row count stayed **286**, reclaiming approximately **3 GB** without deleting option rows.

Compressed state reduces write amplification; immutable generations preserve rollback compatibility. Work begins after hydration so slower hosts cannot repeatedly save zero-progress batches. Missing-file checks now exclude specifically uncovered directories instead of suppressing every absence finding after an unrelated subtree limitation.

A final data-preserving compaction after testing retained all **290 option rows** and restored about **3.19 GB** of free space on C:. Aborted test fixture files were relocated to private D: storage. Pre-existing site fixtures were preserved.

## Deployment testing checklist

- [x] Proxy trust, IPv4/IPv6, local timezone, private-IP labels and cached provider behavior.
- [x] Temporary/permanent restrictions, expiry/history and final native authentication denial.
- [x] Schedule validation, changes, disabling and duplicate prevention; scan batches and coverage restrictions.
- [x] Recovery hashing, expiry/cooldown/binding and one-use consumption with mail/SMS test adapters.
- [x] Native WebAuthn verification and responsive admin pages with a virtual authenticator.
- [x] PHP/JavaScript syntax, targeted coding standards and production package generation.
- [ ] Live email receipt and configured SMS-provider delivery.
- [ ] Physical/security-key and mobile passkeys over deployment HTTPS.
- [ ] Linux filesystem-permission/symlink checks, multisite and supported-version CI matrix.
- [ ] Deployment WordPress Plugin Check, independent security review and marketplace asset/license approval.

## SEO/sales assets

`readme.txt`, `docs/PRODUCT-POSITIONING.md`, and `THIRD-PARTY-NOTICES.txt` provide short/long copy, feature bullets, keyword/tag suggestions, screenshot recommendations, changelog, provider disclosures and verifier attribution. The plugin slug/text domain stays `gracewell-security-suite-pro`.

## Exact file inventory

### Modified source files

- `admin/views/dashboard.php`
- `admin/views/login-protection.php`
- `admin/views/settings.php`
- `assets/js/dashboard.js`
- `assets/js/file-integrity.js`
- `assets/js/firewall-cleanup.js`
- `assets/js/login-protection.js`
- `assets/js/qs-core.js`
- `assets/js/settings.js`
- `assets/js/two-factor.js`
- `bin/build-release.php`
- `composer.json`
- `composer.lock`
- `gracewell-security-suite-pro.php`
- `includes/class-gwqsh-activity-logger.php`
- `includes/class-gwqsh-admin.php`
- `includes/class-gwqsh-ajax.php`
- `includes/class-gwqsh-dashboard-data.php`
- `includes/class-gwqsh-db.php`
- `includes/class-gwqsh-file-integrity.php`
- `includes/class-gwqsh-firewall.php`
- `includes/class-gwqsh-login-protection.php`
- `includes/class-gwqsh-login-view-data.php`
- `includes/class-gwqsh-scan-engine.php`
- `includes/class-gwqsh-settings.php`
- `includes/class-gwqsh-two-factor-view-data.php`
- `includes/class-gwqsh-two-factor.php`
- `README.md`
- `readme.txt`
- `tests/IntegrityWorkflowTest.php`
- `tests/LoginProtectionTest.php`
- `tests/ReleaseTest.php`
- `tests/ScanStateTest.php`
- `THIRD-PARTY-NOTICES.txt`
- `uninstall.php`

### Added source files

- `admin/views/upgrade-panels.php`
- `assets/css/scoped/upgrade.css`
- `assets/js/passkey-login.js`
- `assets/js/upgrade.js`
- `bin/bundle-webauthn.cjs`
- `docs/PRODUCT-POSITIONING.md`
- `docs/RELEASE-README.txt`
- `docs/UPGRADE-PLAN-2026-10.md`
- `docs/UPGRADE-REPORT-2026-10.md`
- `includes/class-gwqsh-customization.php`
- `includes/class-gwqsh-ip-blocks.php`
- `includes/class-gwqsh-network.php`
- `includes/class-gwqsh-passkeys.php`
- `includes/class-gwqsh-recovery.php`
- `includes/class-gwqsh-scheduler.php`
- `includes/class-gwqsh-time.php`
- `includes/class-gwqsh-ui.php`
- `tests/upgrade-benchmark.php`
- `tests/upgrade-browser-environment.php`
- `tests/upgrade-browser.cjs`
- `tests/upgrade-db-maintenance.php`
- `tests/upgrade-process-status.php`
- `tests/UpgradeServicesTest.php`

Bundled verifier: `includes/vendor/webauthn/src` (16 runtime/license/notice files). Machine-readable inventory: `upgrade-changed-files.json`.
