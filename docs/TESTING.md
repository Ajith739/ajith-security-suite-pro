> Historical verification notes below predate the prefix migration. Current runtime identifiers use GWQSH_/gwqsh_; see SECURITY.md and the submission verification report.

# Security Suite Pro 1.0.0 verification

Verified locally on 2 October 2026 with WordPress 7.1.2, PHP 8.2.12, and Microsoft Edge in headless Playwright. Playwright and QR-decoder tooling was installed in the system temporary directory, outside the plugin. Minimum WordPress 5.3/PHP 7.4 combinations have not been executed; no unverified compatibility-test claim is made in readme.txt.

## Automated checks

- PHPUnit: 22 tests, 91 assertions. Run `composer install` to restore development tools, then `composer test` (or `php vendor/phpunit/phpunit/phpunit -c phpunit.xml.dist`) against a development WordPress installation.
- ReleaseTest creates real temporary files for Modified, Missing, and Suspicious, and rolls back database writes/removes fixtures. It also verifies source escaping and the large-file diff limit. Never run development tests against production data.
- PHP syntax and JavaScript syntax checked for all plugin-owned source files.
- Seven admin pages, light/dark themes, at 320/375/425/768/1024/1280/1440/1920 pixels: expanded/collapsed WordPress sidebar checks are included. See follow-up results below.
- QR decoded with a QR reader and matched the exact account, issuer, secret, SHA1, six digits and 30-second otpauth URI.
- Browser authentication: per-user enforcement despite a stale disabled global flag, enrollment rejection/verification, password-to-factor challenge, valid/invalid/expired TOTP, replay rejection, backup persistence and single consumption, regeneration invalidation, replacement-secret persistence, required setup, subscriber access restriction, admin requirement/reset, invalid nonce rejection, Help changelog.
- Custom route: reserved slug rejection, enabled custom route, blocked standard unauthenticated login/admin routes, authenticated administrator access, preserved AJAX/lost-password/reset routes, immediate restoration when disabled, logout, valid password reset submission, and login after reset.
- Actual live manual scan: 5,274 files, zero findings. First upstream-dependent HTTP scan took approximately 139 seconds; cached CLI repeat took two seconds. Controls report loading and structured errors; network/server timeouts can still limit a scan.

## Stored data and migrations

Existing per-user enrollment, TOTP secrets and unused verification hashes are preserved. There is no global 2FA switch: enrolled users require a factor even if a stale disabled global value or plugin-master value exists. `gqs_two_factor_settings` retains only administrator requirements, optional other-role enrollment, and remembered devices. The one-time `gqs_per_user_2fa_migration` removes retired global/email flags, Security Suite Pro email preferences and Security Suite Pro recovery-email metadata; native WordPress email/account fields are untouched.

`gqs_backup_codes` now stores verification hashes and authenticated encrypted display copies together. Only the owner receives decrypted unused values. Atomic consumption removes both representations and keeps a used marker. Legacy plaintext is migrated lazily without losing unused codes. Existing hash-only codes remain valid but cannot be reconstructed; the UI explains intentional regeneration for displayable values. Regeneration is never automatic on refresh. Sodium secretbox or AES-256-GCM uses WordPress-salt-derived keys, and no new dependency is required.

A one-time `gqs_manual_scan_migration` clears only the obsolete file-integrity schedule hook and frequency/time options. Activity retention cron remains. No destructive schema migration is introduced. The installed schema-version marker is reconciled with 1.0.0 without deleting existing settings.

## Risk calculation

Runtime checks use XML-RPC 15, file editor 15, version disclosure 10, enumeration 15, security headers 33, and upload execution protection 12 points (100 total). Upload protection requires the managed on-disk rule as well as the enabled setting. Disabled plugin checks fail. Score is the sum of passed weights; passed plus failed equals six. Risk: Low >=85, Medium >=60, High >=35, otherwise Critical. The wider dashboard security score remains a separate aggregate.

## Remaining manual verification

- Scan the QR with real Google/Microsoft/Authy applications.
- Exercise minimum supported PHP/WordPress versions, a multisite installation, non-Apache upload execution rules, and third-party authentication/callback integrations.
- Review diff appearance and restore/quarantine behavior on deliberately altered copies of real core files in a disposable installation. Automated fixtures verify detection, bounded differences and escaping; production findings are never simulated.
- Keyboard/screen-reader usability, real touch devices, and clipboard-denied browser environments.

## Changed files

- `SECURITY.md`
- `TESTING.md`
- `admin/views/activity-log.php`
- `admin/views/dashboard.php`
- `admin/views/file-integrity.php`
- `admin/views/hardening.php`
- `admin/views/login-protection.php`
- `admin/views/settings.php`
- `admin/views/two-factor.php`
- `assets/css/admin-compat.css`
- `assets/css/scoped/page-fixes.css`
- `assets/img/quietshield-menu.svg`
- `assets/img/quietshield.svg`
- `assets/js/dashboard.js`
- `assets/js/file-integrity.js`
- `assets/js/hardening.js`
- `assets/js/login-protection.js`
- `assets/js/qs-core.js`
- `assets/js/settings.js`
- `assets/js/two-factor.js`
- `bin/build-release.php`
- `gracewell-security-suite-pro.php`
- `includes/class-gqs-activity-logger.php`
- `includes/class-gqs-admin.php`
- `includes/class-gqs-ajax.php`
- `includes/class-gqs-db.php`
- `includes/class-gqs-file-integrity.php`
- `includes/class-gqs-hardening.php`
- `includes/class-gqs-login-protection.php`
- `includes/class-gqs-settings.php`
- `includes/class-gqs-two-factor.php`
- `readme.txt`
- `tests/ReleaseTest.php`
- `tests/SecurityTest.php`
- `tests/UiBackendTest.php`
- `uninstall.php`

## Follow-up fixes in 1.0.0

Root layout issues were competing viewport grid placements and implicit minimum-content widths in fractional tracks. Login sections now use two independently flowing columns; child widths, grid tracks and inputs are bounded by their parent. Available admin-content width determines responsive stacking, including a folded WordPress sidebar. QR/manual key/inline verification share the existing panel design, with the methods list alongside it on desktop.

The Custom Login URL header uses the existing small switch and status badge. Saving the slug preserves enablement, enabling/disabling saves immediately, and copy feedback uses the shared clipboard helper. Secret, individual backup and Copy All actions provide temporary check feedback. Used codes are hidden and excluded from copy/download.

Removed Security Suite Pro enrollment emails, lockout alerts, scan alerts, recipient/preferences, test-mail handler, recovery-email handler, recovery method row, email policy row, notification-settings tab/card, and corresponding listeners. In-app activity notifications and WordPress's native password recovery remain.

Follow-up validation passed: 22 PHPUnit tests / 91 assertions; all plugin PHP/JavaScript syntax and whitespace checks; all seven pages in both themes at 320/375/425/768/1024/1280/1440/1920 with expanded/collapsed sidebars and visible-card parent bounds; no detected page/card overflow or runtime errors. Hidden settings tabs are excluded from geometry checks. Browser tests verified inline enrollment, secret copy/check restoration, actual Copy All clipboard contents, identical backup values after refresh, backup login, consumed-code removal and rejection, current TOTP login, remaining policy saving, retired-global-field rejection, and compact custom-route enable/disable persistence. The activation callback completed with both plugin and database version 1.0.0. A follow-up real scan checked 5,274 files with zero findings in two seconds.

Temporary browser accounts and their settings were cleaned up. Legacy hash-only backups remain usable; their original plaintext cannot be recovered, so owners must intentionally regenerate once if they want a displayable set.


## October 2 layout and Plugin Check follow-up

Login Protection metric cards now have compact three-part headings, smaller gaps and no imposed body height. Duplicate top/lower badge IDs were removed; both locked-IP and allowlist counts update from real data. File Integrity cards put the value above its label with the existing miniature graph aligned at the right. Activity Log allocates more width to details, uses compact date/time rows and two-line previews, and retains escaped full details in the row dialog. Below 650px available content width, each row becomes a labeled two-column entry rather than wrapping seven narrow columns.

Repaired reported date formatting, translator annotation, filesystem alternatives, input sanitization, private AJAX nonce verification, script module tagging, resource versioning and the missing languages directory. Replaced the offloaded animation script with a small local native-browser adapter; entrance, counter, graph, toast and modal animation calls remain functional. Development scripts are CLI-only and excluded from the release ZIP, along with tests, tool configs and caches. No option or user-meta migration was introduced in this follow-up.

Production Plugin Check: zero errors, 126 warnings. Remaining warnings concern direct/prepared database operations, intentional fresh reads, schema creation and nonce analysis in WordPress authentication/routing hooks; the rationale is recorded in SECURITY.md. The source checkout also retains development files that Plugin Check rejects for packaging. The distributable ZIP excludes them.

Validation: 22 PHPUnit tests / 91 assertions passed; PHP and JavaScript syntax checks and Git whitespace checks passed. All seven admin pages passed overflow/runtime checks in light/dark modes at 320, 375, 425, 768, 1024, 1280, 1440 and 1920px with both expanded and collapsed WordPress sidebars. Focused browser checks confirmed File Integrity labels below values, graphs on the right, and Activity Log full-details dialogs. Physical authenticator scanning and actual PHP 7.4/WordPress 5.3 executions still require manual verification.

Follow-up files: `admin/views/login-protection.php`; `assets/css/admin-compat.css`; `assets/js/activity-log.js`, `login-protection.js`, `qs-core.js`, `qs-motion.js`, `file-integrity.js`, `settings.js`, `two-factor.js`; `includes/class-gqs-admin.php`, `class-gqs-ajax.php`, `class-gqs-activity-logger.php`, `class-gqs-file-integrity.php`, `class-gqs-hardening.php`, `class-gqs-login-protection.php`, `class-gqs-settings.php`, `class-gqs-two-factor.php`; `languages/index.php`; `bin/build-release.php`; `tests/bootstrap.php`, `tests/SecurityTest.php`, `tests/ReleaseTest.php`; `uninstall.php`; `readme.txt`; `SECURITY.md`; this report.


The final Login Protection pass measured 140-148px desktop cards, with no overflow at the tested sizes. A console/resource check found only the pre-existing server favicon request (`http://localhost/favicon.ico`, HTTP 404); Security Suite Pro resources loaded and no plugin JavaScript exceptions were detected. Configure the site's favicon separately if desired. Checking the development checkout reports three packaging errors (`.phpunit.result.cache`, `phpcs.xml.dist`, `phpunit.xml.dist`); none is included in the release archive.


## Project cleanup

Removed the unreferenced `assets/css/scoped/admin-compat.css`; WordPress enqueues the maintained compatibility stylesheet at `assets/css/admin-compat.css`. Removed the generated PHPUnit result cache and Composer `vendor` directory from this checkout and Git tracking. The removed files were moved to `C:/Users/abine/AppData/Local/Temp/gqs-cleanup-20261002` for recovery. All Composer packages are development-only, and the plugin bootstrap has no Composer autoloader dependency.

Keep `composer.json`, `composer.lock`, the shared PHPUnit/PHPCS configurations, tests and release build script in Git. Run `composer install` to recreate ignored development dependencies; `composer test` and `composer phpcs` use them. The new `.gitignore` excludes dependencies, generated release/test output, local environment settings, editor files, logs and temporary files. Shared development configurations are intentionally retained; build the production ZIP with `php bin/build-release.php` rather than uploading the source checkout.


## Git branch recovery, 2 October 2026

Switching to a README-only `main` checkout and applying saved changes left modified files unresolved while removing unchanged runtime dependencies. Missing encryption code prevented WordPress bootstrap; missing styles, images and QR/hero scripts also broke pages. Restored the eleven missing runtime files from the verified 1.0.0 archive and recovered shared development manifests/configuration from `plugin-functions`. During repair, GitHub Desktop switched back to `plugin-functions` and reapplied the stash, introducing 34 add/add conflicts. Every incoming file matched the preserved verified fixes; those versions resolved the conflicts. The final repair remains on `plugin-functions`, as requested.

Recovery snapshots and the original conflicted index are in `C:/Users/abine/AppData/Local/Temp/gqs-git-repair-20261002`. The existing stash is preserved. Generated vendor/cache files and the unused stylesheet reintroduced by the checkout were removed from the project and Git tracking again. `.gitattributes` standardizes source line endings while preserving binary assets. All runtime includes, styles, scripts and images are present in Git; there are no unresolved index entries or conflict markers.

Verification after recovery: WordPress bootstraps with the plugin active; 22 PHPUnit tests / 91 assertions pass; PHP/JavaScript syntax and staged whitespace checks pass; seven admin pages pass light/dark and 320/375/425/768/1024/1280/1440/1920px checks with expanded/collapsed sidebars. Temporary browser users and settings are restored after testing. Commit changes on the development branch before switching branches. Bring the complete development branch into `main` through a reviewed merge rather than applying only a partial stash. No remote push or history rewrite is part of this repair.


## 4 October 2026 malware engine regression suite

Run with the XAMPP PHP 8.2 binary:

```sh
composer install
/Applications/XAMPP/xamppfiles/bin/php vendor/bin/phpunit -c phpunit.xml.dist
/Applications/XAMPP/xamppfiles/bin/php vendor/bin/phpcs --standard=phpcs.xml.dist
/Applications/XAMPP/xamppfiles/bin/php tests/benchmark.php
composer validate --strict
```

Tests bootstrap the actual local WordPress database. Full-scan/baseline cases use
transactions and cache cleanup; lifecycle cases use isolated table prefixes.
Sanitized `.fixture` files store behavior inside `if (false)` branches and use only
`.invalid` endpoints. Guardian tests include standalone requests without the normal
plugin, precomputed MU lists, real local WordPress requests, benign hosting/API/cache
lookalikes, ordering limitations, hash preservation, update/collision/removal,
missing/corrupt state, read-only storage and path/size/token limits. Archive tests
read entries without extraction. Never substitute operational malware.

`tests/browser-smoke.cjs` optionally uses Playwright and local Chrome. Set
`GWQSH_PLAYWRIGHT` to its module and `GWQSH_BROWSER_ACCOUNT` to a mode-0600 temporary
JSON account file with `username`, `password`, `base` and `login`. It checks frontend,
native login and all seven pages at 375px and 1280px. Create/delete the temporary
administrator locally; never commit credentials or account state. Playwright is not
a production dependency. The exact measured results are in
[the implementation report](SECURITY-UPGRADE-REPORT.md).

## File Integrity workflow regressions (4 October 2026)

`IntegrityWorkflowTest.php` exercises 1,100 real database findings at all seven page
sizes, exact IDs/LIMIT/OFFSET, filters/sorting/clamping, quarantine/full-rescan/restore,
recreation, permanent removal, MU sentinels, trusted Old/New decisions, escaped diff,
large copies, orphan/damaged evidence, symlinks and partial cleanup/deletion failures.
Run database suites sequentially because they share the local WordPress installation:

```sh
/Applications/XAMPP/xamppfiles/bin/php vendor/bin/phpunit -c phpunit.xml.dist
/Applications/XAMPP/xamppfiles/bin/php vendor/bin/phpcs --standard=phpcs.xml.dist
composer validate --strict
```

The complete real-browser suite is `tests/browser-integrity.cjs`. It requires
Playwright and local Chrome. `tests/browser-environment.php` creates temporary local
administrator/subscriber accounts and 1,100 inert findings. It saves the original
baseline/quarantine metadata and temporarily isolates the quarantine view so destructive
UI tests touch fixture copies only. The browser verifies that every exposed quarantine
record belongs to its fixture before continuing. No credentials are committed.

Example setup (choose a private existing directory for the temporary credentials):

```sh
export GWQSH_BROWSER_WORKDIR="/tmp/gwqsh-integrity-work"
export GWQSH_BROWSER_ACCOUNT="$GWQSH_BROWSER_WORKDIR/browser-account.json"
export GWQSH_PHP="/Applications/XAMPP/xamppfiles/bin/php"
export GWQSH_PLAYWRIGHT="$GWQSH_BROWSER_WORKDIR/node_modules/playwright"
export GWQSH_BROWSER_FIXTURE="$PWD/tests/browser-fixture.php"
export GWQSH_BROWSER_NONCE="$PWD/tests/browser-nonce.php"
export GWQSH_BROWSER_RESULT="$GWQSH_BROWSER_WORKDIR/browser-results.json"
"$GWQSH_PHP" tests/browser-environment.php setup
"$GWQSH_PHP" tests/browser-fixture.php old
node tests/browser-integrity.cjs
"$GWQSH_PHP" tests/browser-environment.php cleanup
```

Cleanup refuses to discard ownership metadata while fixture copies remain. If a browser
assertion fails before Clear All, log in with the temporary fixture administrator and
remove only copies whose paths contain that run's `gwqsh-browser-…` marker before running
cleanup. Original metadata is merged back without discarding unrelated newly imported
records. The nonce helper uses only the temporary subscriber's own authenticated session
and is CLI-only. Fixtures need local web/CLI write access because XAMPP's PHP worker and
CLI can run as different users.

Latest measured results and limitations are in
[the File Integrity workflow report](FILE-INTEGRITY-WORKFLOW-REPORT.md).


The File Integrity suite also verifies failed-isolation retries in a read-only folder, deduplication of recreated identical bytes, retained trusted text, removal-history persistence failures, and a 500-ID review requiring one SQL update. The browser suite checks that bulk review sends one mutation request and that a notification receives the hit-test above an open review popup. Permission checks require a non-root CLI identity so a read-only fixture directory actually prevents unlinking.
