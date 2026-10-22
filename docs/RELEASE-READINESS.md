# Release readiness — 1.3.0-rc.6 (2026-10-22)

**Status: review candidate, not release-ready.** No commercial detection,
exploit-coverage, certification or parity claim is authorized by these results.

## Delivered in this revision

* Closed a **complete WAF bypass**: values of parameters named `password`, `pwd`,
  `log`, `token`, `session`, `code`, `secret`, `nonce` (and nested credential
  objects) were never inspected. Now screened for injection-class attacks without
  ever being logged. Regression: `waf-credential-keys`.
* Single-segment traversal, quoted/`LIKE` SQL tautologies, comment-obfuscated
  unions, version-comment keywords, `WAITFOR DELAY`, nested `SLEEP()`, and
  serialized objects nested in arrays are now correlated.
* New **report-first** rule `GWQSH-1017` (executable PHP in request data);
  enforcement requires `enforce_new`.
* One evidence walk per collection in `advanced()` (was two).
* First executable regression harness in the repository: 124 assertions
  (122 pass, 2 honest skips) plus a 102-file syntax lint, and
  `docs/engine-manifest.json` with a test that fails when capability claims drift
  from the code.

## Hard blockers (do not ship a customer package)

1. **Passkeys are unavailable in a clean checkout** — `includes/vendor/webauthn/`
   is gitignored and absent. Either ship the locked, namespace-scoped runtime or
   remove the passkey feature claim from the readme.
2. **Hero bird animation asset missing** — `assets/vendor/three/three.module.js`
   is gitignored; the dynamic import fails silently.
3. **No WordPress validation of any kind** in this session: activation,
   deactivation, Free→Pro migration, settings save, cron, admin UI.
4. **No restore or recovery validation** — backup/restore is advertised in the UI
   but a restore has not been proven.
5. **No compatibility run** — WooCommerce checkout, Gutenberg save, multisite,
   PHP 8.0–8.3.
6. **Toolchain absent** — PHPCS, PHPStan, Plugin Check and `composer audit` were
   not run (there is no root Composer manifest).
7. **Nine namespaced engines, eight unwired** — remove or wire them before any
   marketing text implies the extra capability.

## Documented residuals (acceptable with disclosure)

* The detector is lexical; five benign shapes are flagged on purpose
  (`docs/WAF-VALIDATION.md` §5).
* Encrypted/compressed/oversized bodies yield an explicit "incomplete coverage"
  state, not a verdict.
* No pre-WordPress firewall layer.
* Signed-feed clients require an operator-supplied trust anchor and feed; no
  service is operated from this repository.

## Verification checklist before packaging

| Step | Command / action |
| --- | --- |
| Syntax | `php tests/lint.php .` → 0 failures |
| Regression | `php tests/run-tests.php --verbose` → 0 failures |
| Assets | Confirm `includes/vendor/webauthn/src/WebAuthn.php` and `assets/vendor/three/three.module.js` exist in the archive |
| Secrets | Scan the archive for keys, tokens, `.env`, `node_modules`, `tests/.runtime` |
| Install | Activate on a disposable WordPress with the previous version installed; verify migration and settings |
| Traffic | Run the WAF in report mode against real traffic for a day; review "Firewall inspection incomplete" and false positives |
| Commerce | Complete a WooCommerce checkout and a Gutenberg post save with WAF in block mode |
| Recovery | Create a backup, stage-import, verify row counts, cutover, roll back |
| Auth | Enrol TOTP and a passkey on a staging origin; verify replay rejection |
| Deploy | Only after all of the above; keep `GWQSH_DB_VERSION` unchanged (1.6.1) |
