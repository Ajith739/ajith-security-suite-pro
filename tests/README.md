# Regression tests

Isolated assertions that execute **real plugin source** against a minimal
WordPress API stub (`tests/bootstrap.php`). They are not a substitute for a
WordPress integration test — see `docs/TEST-EVIDENCE.md` for the exact split.

## Run

```bash
# with a PHP binary
php tests/lint.php .
php tests/run-tests.php --verbose --json=docs/evidence/phpunit-results.json

# without a PHP binary (WASM runtime; needs `npm install php-wasm`)
node tests/tools/php-wasm-runner.mjs
```

The WASM runner mirrors every `.php`/`.json` file into the runtime, lints all PHP
sources with `token_get_all(..., TOKEN_PARSE)`, runs the suite, and writes
`docs/evidence/lint.json` and `docs/evidence/phpunit-results.json`.

## Layout

| Path | Purpose |
| --- | --- |
| `bootstrap.php` | WordPress function stubs backed by in-memory state |
| `lib/harness.php` | `gw_assert`, `gw_same`, `gw_expect_all`, `gw_expect_none`, `gw_skip` |
| `run-tests.php` | loader + summary + JSON evidence |
| `lint.php` | syntax lint without the `php` CLI |
| `cases/010-waf-corpus.php` | attack + benign request corpora |
| `cases/020-ip-trust.php` | CIDR, forwarded chain, spoof resistance |
| `cases/030-bot-shield.php` | sensitive-file probes |
| `cases/040-policy.php` | rollout/decision gates, budgets, inspection states |
| `cases/050-inspector.php` | JSON/multipart parsers and rate counters |
| `cases/060-auth-guard.php` | TOTP replay, WebAuthn ceremony checks |
| `cases/070-ssrf.php` | webhook destination validation |
| `cases/080-performance.php` | bounded-cost regression thresholds |
| `cases/090-false-positives.php` | allowed benign traffic + documented aggressive rules |
| `cases/100-integration-manifest.php` | wired/unwired engine claims must match the code |

## Rules

* Never weaken an assertion to make a change pass.
* A check that cannot run must call `gw_skip()` with a reason, never `gw_assert(..., true)`.
* Samples are hand-written regression inputs, not a statistical corpus.
