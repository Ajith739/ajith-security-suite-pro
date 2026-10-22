# Continuous security progress log

## Session 2026-10-22 — v1.3.0-rc.6

### Starting point

* Repository `Ajith739/ajith-security-suite-pro`, branch `arena/a0b93feb-...`,
  single commit `4728e6c update`, plugin version `1.3.0-rc.5`.
* `AGENTS.md`, `tests/`, `tools/` referenced by earlier documents **did not
  exist**. Several documents referenced artifacts (`docs/THIRD-PARTY-INTEGRATION-AUDIT.md`,
  `tools/dependency-audit`, `docs/evidence/integration.json` corpus claims) that
  are not in the tree.
* No PHP binary, no MySQL, no WordPress in the environment.

### Work performed (in order)

1. **Inventory** — 102 PHP files, 27k lines; mapped hooks, cron events and tables.
   Found nine `Gracewell\SecurityPro\*` engines; only `Gracewell_WAF_Inspector`
   was referenced (as a parser).
2. **Built a real test harness** because no PHP existed: `php-wasm` PHP 8.4.1
   runtime + `tests/bootstrap.php` (WordPress stubs) + `tests/lib/harness.php` +
   `tests/run-tests.php` + `tests/tools/php-wasm-runner.mjs` + `tests/lint.php`.
3. **First run** (8 assertions) exposed three real WAF gaps immediately:
   quoted SQL tautology, single-segment traversal, nested serialized object.
4. **Expanded corpus** — 40 attack-shaped and 19 benign samples, plus 7
   credential-parameter bypass cases. 11 of 11 credential cases and 9 of 9
   obfuscation cases failed before the fix.
5. **Fixed the firewall** (`includes/class-gwqsh-firewall.php`):
   * credential-scope inspection (`credential_values`) — closes a full bypass,
   * `traversal()` single-segment detection,
   * `sql_high_confidence()` tautology/comment/time-based/error-based families,
   * `xss_high_confidence()` extraction (same rules, now shared),
   * `serialized_object()` nested object detection,
   * `php_code_in_request()` + new report-first `GWQSH-1017`,
   * one evidence walk per collection instead of two in `advanced()`.
6. **Added tests** for IP/CIDR/trusted-proxy, Bot Shield probes, rollout policy,
   evidence budgets, JSON/multipart parsers, rate and credential-stuffing
   counters, TOTP replay + WebAuthn ceremony validation, SSRF validation,
   performance bounds, false-positive boundaries, and an engine-wiring manifest.
7. **Created `docs/engine-manifest.json`** and the test that enforces it, so no
   unwired class can be presented as protection.
8. **Version bump** to `1.3.0-rc.6` (header, `GWQSH_VERSION`, `readme.txt`,
   changelog). `GWQSH_DB_VERSION` unchanged — no schema change.
9. **Documentation** rewritten/added: `AGENTS.md`, this log, gap register,
   benchmark matrix, test evidence, remaining work, feature matrix, engine
   integration audit, WAF validation, release readiness, performance.

10. **Malware analyzer evidence** — wrote a synthetic corpus
    (`tests/cases/110-malware-analyzer.php`) against the real analyzer. Four
    samples scored 0: remote `include("http://…")`, obfuscated callable
    assembly, `preg_replace /e` and `create_function`. The first two are real
    current dropper patterns and were fixed with token-level rules
    (`remote_include`, `obfuscated_callable`); the latter two cannot execute on
    PHP 8+ and are recorded as documented non-detections. Analyzer `VERSION`
    bumped to force re-analysis of cached scan results.

### Measured outcome

```
Linted 103 PHP files, 0 failures
PHP 8.4.1 | 128 passed, 0 failed, 2 skipped, 130 total
```

Timing (WASM runtime, not production):

| Case | Cost |
| --- | --- |
| typical GET (5 short params) | ≈397 µs/request |
| two ~30 KB values | ≈1400 µs/request |
| 120 nested cart-like values | ≈1020 µs/request |

### Deliberately not done

* No deletion of the eight dead engine classes (owner decision required).
* No attempt to bypass the missing WebAuthn/three.js vendor assets.
* No claim of WordPress, WooCommerce, multisite, browser or production-traffic
  validation.
* No cloud service, feed publisher or key material introduced.

### Continuation pointer

Next three tasks are listed in `docs/REMAINING-WORK.md` §1.
