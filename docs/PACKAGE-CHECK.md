# Release gate — `tests/tools/package-check.php`

Automated check of defects that break a shipped build or would leak material into
a release archive. It runs as the last step of
`node tests/tools/php-wasm-runner.mjs` and writes
`docs/evidence/package-check.json`.

```bash
php tests/tools/package-check.php .
# exit 0 = pass or blocked-with-disclosure; exit 1 = fail
```

## Checks

| Check | What it proves | Current result |
| --- | --- | --- |
| Version consistency | Plugin header, `GWQSH_VERSION`, `readme.txt` stable tag and `docs/security-progress.json` agree | 4 sources agree on `1.3.0-rc.6` |
| Require integrity | Every `GWQSH_PATH . '…php'` / `__DIR__ . '…php'` target exists; optional guarded assets are classified separately | 88 PHP files scanned, **0 broken requires**, 2 guarded optional assets |
| Feature assets | Advertised features have their runtime files | `includes/vendor/webauthn/src/WebAuthn.php` **missing** (passkeys), `assets/vendor/three/three.module.js` **missing** (hero animation) — both disclosed in `docs/RELEASE-READINESS.md` |
| Secrets | Private keys, AWS/GitHub/Google/Stripe/Slack/Twilio token shapes in shipped PHP/JS/CSS/JSON | 90 files scanned, **0 findings** |
| Dev artifacts | `node_modules`, `tests/.runtime`, `tests/tmp`, `.env`, `.DS_Store` must not be in a shipping tree | none present (and ignored by git) |

## Gate semantics

* `fail` — an undisclosed defect (version drift, broken require, secret, dev
  artifact, missing-asset blocker not documented). Must be fixed.
* `blocked` — code and metadata are consistent, but a disclosed asset is missing
  so a customer package must not be produced. This is the current state.
* `pass` — safe to package.

## What this does NOT do

It does not build or inspect an actual ZIP, does not run WordPress, Plugin Check,
PHPCS/PHPStan or `composer audit`, and it cannot detect a secret that is stored in
an option or database rather than in a file. Secret patterns are shape-based and
will not catch a bespoke credential format.
