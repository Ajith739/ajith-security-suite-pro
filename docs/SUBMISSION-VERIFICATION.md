# Security Suite Pro 1.0.0 submission verification

Canonical project: `C:/laragon/www/wordpress/wp-content/plugins/gracewell-security-suite-pro`.
Branch: `plugin-functions`. Author: Ajithkumar739. Contributor: gracewell89.
The user confirmed that the old slug was not reserved. The old directory/bootstrap/text domain were renamed; the local WordPress activation entry was updated. Original Git metadata/source recovery copy: `C:/Users/abine/AppData/Local/Temp/gwqsh-slug-recovery-20261003`. Open the canonical directory in GitHub Desktop. No remote push or history rewrite was performed.

## Prefix and data compatibility

All own PHP classes/constants/functions, AJAX actions and nonces, maintenance hooks, table names, options, transients, user metadata, frontend globals/handles and collision-sensitive CSS identifiers now use `GWQSH_`/`gwqsh_` (hyphenated identifiers use `gwqsh-`). This includes `GWQSH_Admin`, `GWQSH_Settings`, `GWQSH_Two_Factor`, `GWQSH_Login_Protection`, `GWQSH_DB`, `GWQSH_Ajax`, `GWQSH_Crypto`, `GWQSH_Activity_Logger`, `GWQSH_File_Integrity`, `GWQSH_Hardening`, bootstrap/lifecycle functions, `GWQSH_CONFIG`, `GWQSH_DATA`, `window.GWQSH`, `GWQSH_Motion`, `gwqsh_action`, `gwqsh_nonce`, and all four database tables.

Migration renames tables atomically, retains IDs/indexes/rows and stored payloads, and changes option/meta/transient keys without rewriting serialized values. Both individual and aggregate option caches and affected user metadata caches are invalidated. Existing current keys win. Conflicting populated tables fail closed instead of overwriting data. Cron hook names migrate, empty timestamps and obsolete integrity scheduling are removed, and unrelated cron jobs remain. Migration is idempotent and precedes authentication initialization.

Remaining legacy strings are deliberate migration/compatibility readers, regression fixtures or historical documentation: `GQS_DISABLE_LOGIN_URL`, `GQS_TRUSTED_PROXIES`, old stored keys/table names, `gqs1` encrypted payload markers, trusted cookies, recovery bookmarks and in-flight factor fields. They do not expose old AJAX endpoints or an authentication bypass. Existing localStorage theme/density preferences are read as fallbacks. Previously quarantined files are retained at their original private paths and covered by opt-in uninstall. WordPress's native `DISALLOW_FILE_EDIT` name remains because core requires it.

The existing original login/hardening/general/policy settings were compared with the pre-migration snapshot after tests and restored where test tooling had temporarily changed them. TOTP/backup payloads and hash algorithms remain compatible. Temporary browser users, fixture files/tables and test settings were removed/restored.

## Runtime assets, branding and packaging

Three.js r160 / 0.160.0 now loads from `assets/vendor/three/three.module.js`; its original MIT license is included. qrcode-generator 2.0.4 remains local and MIT licensed, with readable source and attribution. `THIRD-PARTY-NOTICES.txt` documents both. The native motion adapter is project code, not GSAP. Google Fonts were removed in favor of system stacks. No runtime script/font CDN requests were observed. Genuine plugin external requests are official WordPress.org checksums and checksum-verified core source downloads.

Security Suite Pro's menu position is 81; all seven existing pages, layout, icons and light/dark design are preserved. Copying 2FA values shows only a temporary tick visually; accessible feedback and useful clipboard failure notifications remain. Slug save/toggle operations cannot overwrite each other during an in-flight request. Custom login URLs and native form actions support pretty, index.php and plain permalinks; standard unauthenticated login/admin routes stay protected. Recovery, logout/lost/reset flows, AJAX/REST and authenticated admin access remain available.

The allowlist builder creates `dist/gracewell-security-suite-pro-1.0.0.zip`, handles missing ZipArchive with a clear CLI error, rejects symlinks/unexpected development files under runtime folders and finalizes through a temporary archive. The ZIP has 49 runtime/release files and excludes Git metadata, tests, Composer dependencies/configuration, build tools, reports and generated builds. All release-facing versions remain 1.0.0; dependency versions were retained.

## Verification results

- PHPUnit: **27 tests / 138 assertions passed** on local WordPress 7.1.2 with PHP CLI 8.2.12.
- PHP syntax: **29 project PHP files passed** under PHP 8.2.12 and PHP 8.4.12.
- JavaScript syntax: **11 own JavaScript files passed**; the bundled Three.js module also loaded and rendered successfully.
- PHPCS WordPress standard over every production PHP file: **0 errors / 115 warnings**. Missing documentation/formatting were corrected. Reviewed native authentication/routing and trusted identifier exceptions are narrowly annotated; no whole-file/global security suppression was added. Remaining PHPCS warnings cover live database queries/cache, callback parameters required by WordPress hook contracts, guarded local filesystem operations/error returns, encoded cryptographic payloads/SVG, existing local SQL timestamps and two parameter naming conventions. They are retained for reviewer inspection; timezone/DST behavior merits additional deployment testing.
- Static Plugin Check on the extracted production ZIP: **0 errors / 96 warnings**, detailed below and in `dist/verification/plugin-check.json`.
- Fresh activation, deactivation, preserve-data uninstall and explicit delete-data uninstall were tested in isolated database tables, including preservation of unrelated cron and 2FA state on deactivation.
- Prefix regression tests cover key/meta/table/cron migration, legacy encrypted secrets, persistent backup hashes, idempotence and single-use consumption.
- Browser: enrollment, invalid code rejection, current TOTP login, replay rejection, persistent backups, single-use rejection, regeneration, user setup restrictions, self-only subscriber status, nonce/capability rejection, administrator require/reset, and Help changelog passed.
- QR canvas decoded to the exact otpauth URI/account/issuer/TOTP configuration. Trusted-device login, HttpOnly/SameSite cookie, legacy cookie compatibility and revocation passed.
- Actual clipboard contents and tick-only feedback passed in both themes, including icon restoration and denied-clipboard failure recovery.
- Browser login routing passed for plain and index permalinks, native custom form POST, protected standard routes, authenticated admin, logout, lost/reset-password handling, AJAX/REST, legacy recovery and immediate disable. Pretty-permalink URL construction and reset-cookie-path preservation have unit coverage.
- Live scan: **5,274 actual files, 0 modified / 0 missing / 0 suspicious**, completed in 118 seconds. Real isolated fixture tests demonstrate all three states, escaped/bounded diffs, quarantine metadata, tampered-download rejection and checksum-verified restoration. No fixture findings remain in production results.
- Seven admin pages passed **224 width/theme/sidebar combinations**, including 320/375/425/768/1024/1280/1440/1920px, with no overflow or JS runtime errors. Local Three.js animation rendered; no external script/font requests were observed.
- Missing-ZipArchive packaging path returned an explanatory error rather than a PHP fatal. Git whitespace checks passed; canonical Git metadata passed fsck (only pre-existing unreachable recovery/stash objects).

## Remaining Plugin Check warnings

| Warning | Count | Review rationale |
| --- | ---: | --- |
| `WordPress.DB.DirectDatabaseQuery.DirectQuery` | 41 | Plugin-owned audit/scan/lockout tables and atomic factor consumption require direct database operations. Values use prepare() or WordPress insert/update/delete methods. |
| `WordPress.DB.DirectDatabaseQuery.NoCaching` | 32 | Authentication lockouts, replay guards and single-use consumption must read current database state; stale caches could weaken security. Settings/meta use their APIs or invalidate caches after direct migration. |
| `PluginCheck.Security.DirectDB.UnescapedDBParameter` | 22 | Analyzer flags trusted identifiers or prepared-query variables. Table names derive from WordPress prefix and fixed suffixes; migration/uninstall validate identifiers. WHERE clauses and sort directions are internally allowlisted. No request value becomes a raw SQL identifier; WP 5.3 does not support %i. |
| `WordPress.DB.DirectDatabaseQuery.SchemaChange` | 1 | Installation updates only the four owned tables through dbDelta; uninstall is opt-in and prefix-scoped. |

These warnings remain visible for human review. They do not represent unescaped request values being interpolated into SQL; no authentication or file safety check was removed to silence analysis. WordPress.org acceptance still requires its own review.

## Manual checks still needed

WordPress 5.3 with PHP 7.4 was not available for execution; minimum-version compatibility must be tested before advertising that combination as tested. Multisite/network lifecycle, other server configurations (especially Nginx uploads protection), real mobile authenticator scanning, email delivery/reset-link completion and additional timezone/DST combinations require manual deployment checks. PHP 8.4 was syntax-checked, not used for the entire browser/authentication suite. Core restore/diff tests used checksum-verified development fixtures rather than overwriting live core files.

## Files changed

- `SECURITY.md`
- `SUBMISSION-VERIFICATION.md` (removed/replaced)
- `TESTING.md`
- `THIRD-PARTY-NOTICES.txt`
- `admin/views/activity-log.php`
- `admin/views/dashboard.php`
- `admin/views/file-integrity.php`
- `admin/views/hardening.php`
- `admin/views/login-protection.php`
- `admin/views/settings.php`
- `admin/views/two-factor.php`
- `assets/css/admin-compat.css`
- `assets/css/scoped/activity-log.css`
- `assets/css/scoped/dashboard.css`
- `assets/css/scoped/file-integrity.css`
- `assets/css/scoped/hardening.css`
- `assets/css/scoped/login-protection.css`
- `assets/css/scoped/page-fixes.css`
- `assets/css/scoped/settings.css`
- `assets/css/scoped/two-factor.css`
- `assets/js/activity-log.js`
- `assets/js/dashboard.js`
- `assets/js/file-integrity.js`
- `assets/js/hardening.js`
- `assets/js/hero-birds.js`
- `assets/js/login-protection.js`
- `assets/js/qrcode.js`
- `assets/js/qs-core.js`
- `assets/js/qs-motion.js`
- `assets/js/settings.js`
- `assets/js/two-factor.js`
- `assets/vendor/three/LICENSE.txt`
- `assets/vendor/three/three.module.js`
- `bin/build-release.php`
- `gracewell-security-suite-pro.php`
- `gracewell-quiteshield.php` (removed/replaced)
- `includes/class-gqs-activity-logger.php` (removed/replaced)
- `includes/class-gqs-admin.php` (removed/replaced)
- `includes/class-gqs-ajax.php` (removed/replaced)
- `includes/class-gqs-crypto.php` (removed/replaced)
- `includes/class-gqs-db.php` (removed/replaced)
- `includes/class-gqs-file-integrity.php` (removed/replaced)
- `includes/class-gqs-hardening.php` (removed/replaced)
- `includes/class-gqs-login-protection.php` (removed/replaced)
- `includes/class-gqs-settings.php` (removed/replaced)
- `includes/class-gqs-two-factor.php` (removed/replaced)
- `includes/class-gwqsh-activity-logger.php`
- `includes/class-gwqsh-admin.php`
- `includes/class-gwqsh-ajax.php`
- `includes/class-gwqsh-crypto.php`
- `includes/class-gwqsh-db.php`
- `includes/class-gwqsh-file-integrity.php`
- `includes/class-gwqsh-hardening.php`
- `includes/class-gwqsh-login-protection.php`
- `includes/class-gwqsh-migration.php`
- `includes/class-gwqsh-settings.php`
- `includes/class-gwqsh-two-factor.php`
- `phpcs.xml.dist`
- `readme.txt`
- `tests/LifecycleTest.php`
- `tests/PrefixMigrationTest.php`
- `tests/ReleaseTest.php`
- `tests/RestoreTest.php`
- `tests/SecurityTest.php`
- `tests/UiBackendTest.php`
- `uninstall.php`
