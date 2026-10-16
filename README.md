# Gracewell Security Suite Pro

WordPress security plugin repository: https://github.com/joshua-sundar/gracewell-security-suite-pro

The production directory, bootstrap and text domain are `gracewell-security-suite-pro`; the main file is `gracewell-security-suite-pro.php`. Persistent `gwqsh_` keys, tables, cron hooks, crypto payloads and legacy prefixes remain compatible with the released Free edition and previous Pro builds.

## Install or upgrade

Back up the site, leave data removal on uninstall disabled, and deactivate Free or the previous Pro development edition. Upload the release ZIP in WordPress and activate Pro. The editions share data and must not run together. Keep the inactive old edition until you verify settings, 2FA and scans. Do not uninstall Free with data removal enabled while Pro still uses its data.

## Build

Run `php bin/build-release.php /absolute/output/directory`. The builder reads the version from the plugin header, checks it against the readme, rejects output inside the source, and packages only runtime code/assets and release documents. Development tools, tests, fixtures, Git metadata, and the old development loader are excluded.

After updating the locked WebAuthn dependency with Composer, run `node bin/bundle-webauthn.cjs` to refresh its namespace-isolated runtime. `GWQSH_COMPOSER_VENDOR_DIR` supports an external development dependency directory. Production installations do not require Composer.

## Verify

Use an isolated WordPress test installation with this plugin active. Set `GWQSH_TEST_WP_ROOT` to its absolute root; run `phpunit -c phpunit.xml.dist`. Run `phpcs --standard=phpcs.xml.dist`, PHP 8.0+ syntax checks and WordPress Plugin Check before distribution. See `docs/RELEASE.md`, `docs/UPGRADE-REPORT-2026-10.md` and `SECURITY.md` for verification results and deployment prerequisites.
