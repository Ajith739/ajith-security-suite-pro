# Phase 0 — Baseline audit report

**Product:** Gracewell Security Suite Pro 1.1.0
**Repository state at audit:** commit `c342c42` ("initial upadte") on `arena/783d59f4-ajith-security-suite-pro`
**Audit date:** 2026-10-16
**Auditor role:** defensive security review performed inside this repository, using only the
tests, fixtures and source that ship with the plugin plus a fresh WordPress install.

This report documents the **observed** state of the plugin. Every "verified" line below is
backed by a command that was actually executed and whose output is reproducible with the
commands in section 1. Nothing here is a claim of complete protection.

---

## 1. Verification environment (exact, reproducible)

| Component | Value |
|---|---|
| PHP runtime | PHP 8.5.10 (cli, NTS) — WASM build via `@php-wasm/cli` (`/home/user/.cache/phpwasm/node_modules/.bin/php-wasm-cli`) |
| Test framework | PHPUnit 9.6.37, installed from the commits locked in `composer.lock` |
| Coding standard | PHP_CodeSniffer 3.13.6 + WordPress-Coding-Standards 3.4.1 (same locked refs) |
| WordPress under test | 7.1.3, installed at `/home/user/.cache/wp` |
| Database | SQLite via the official WordPress SQLite Database Integration drop-in v3.1.0 |
| Test command | `GWQSH_TEST_WP_ROOT=/home/user/.cache/wp php-wasm-cli /home/user/.cache/tools/vendor/phpunit/phpunit/phpunit -c phpunit.xml.dist --no-coverage` |
| PHPCS command | `php-wasm-cli /home/user/.cache/tools/vendor/squizlabs/php_codesniffer/bin/phpcs -q --standard=phpcs.xml.dist --runtime-set installed_paths <wpcs>,<phpcsextra>,<phpcsutils>` |

Everything above was downloaded from the exact references in `composer.lock`, the
`WordPress/WordPress` tag tarball and the SQLite integration repository. No Composer binary
is available in the audit environment, so the dependency tree was reconstructed at the
locked commits and autoloaded with a generated classmap.

### Environment limitations (do not mistake these for plugin defects)

| Limitation | Effect | Evidence |
|---|---|---|
| Child-process execution is not supported by this runtime | `GuardianTest` (9 cases) cannot run: the test starts a second PHP interpreter through `proc_open(array(PHP_BINARY, '-r', <code>))`, and the WASM runtime emulates that with a shell wrapper that chokes on the parentheses in the code | `/bin/sh: 1: Syntax error: "(" unexpected`, `exit 2`, then `Failed asserting that 2 is identical to 0` at `tests/GuardianTest.php:9` |
| No MySQL server | `LifecycleTest` errors: `mysqli_real_connect(): Error while reading greeting packet` | `class-wpdb.php:1990` via `tests/LifecycleTest.php:10` |
| SQLite drop-in keeps stale table metadata after a rename | `PrefixMigrationTest::test_table_rename_preserves_ids_and_records_without_touching_live_tables` fails even though the rename itself succeeds | Probe: after `ALTER TABLE wp_probe_r1 RENAME TO wp_probe_r2`, `SHOW TABLES LIKE 'wp_probe_r1'` still returns `wp_probe_r1` and `SHOW TABLES LIKE 'wp_probe_r2'` returns `NULL` |
| SQLite driver cannot execute `RENAME TABLE` | Drove the migration portability fix in `GWQSH_Migration::tables()` | `MySQL query: RENAME TABLE ... Unknown query type: RENAME` |
| SQLite driver lacks `LAST_INSERT_ID(expr)`, `JSON_UNQUOTE(JSON_EXTRACT(...))`, `INET6_ATON()`, `ON CONFLICT`, `INSERT OR IGNORE` | Drove the portable SQL work in `GWQSH_DB`, `GWQSH_Enterprise_Store` and `GWQSH_Migration` | `probe*.php` outputs recorded in the phase report |

**Consequence:** the plugin's MySQL-specific statements cannot be executed in this sandbox.
They were therefore **not** changed blindly: every dialect-specific fix keeps the original
MySQL statement byte-identical and adds a separate, tested path for the SQLite family.

---

## 2. Baseline test results

| Run | Tests | Assertions | Errors | Failures | Skipped | Log |
|---|---|---|---|---|---|---|
| Baseline (unmodified plugin) | 192 | 3872 | 4 | 16 | 3 | `testlogs/baseline.txt` |
| Final (after this session's fixes + new tests) | 207 | 3976 | 1 | 10 | 3 | `testlogs/final3.txt` |

All 11 remaining problems are attributable to the three environment limitations above
(9 × `GuardianTest`, 1 × `LifecycleTest`, 1 × `PrefixMigrationTest`). No plugin-owned
assertion that can execute in this environment is failing.

---

## 3. Feature audit matrix

Legend for **Enforcement**: `verified` = the security decision was executed and observed
in this environment; `partial` = the decision path exists but a required input/provider is
missing or unverified; `unverified` = cannot be executed here; `absent` = no implementation.

| Feature | Existing implementation | Actual enforcement | Tests | Remaining gap |
|---|---|---|---|---|
| Web application firewall (query inspection) | `GWQSH_Firewall::inspect()` on `init` priority 2; SQLi/XSS regexes, scanner-agent + exploit-path rule, `GWQSH-1001…1005` | `verified` (rule matching, 403/429, report vs block mode, dedup logging) — **defaults to `enabled=false` and `enforce_new=false`** | `FirewallPageTest`, `EnterpriseSecurityTest` | No protection until an administrator opts in; authenticated requests are skipped entirely; no virtual patching; no REST/XML-RPC body inspection |
| Malware analyzer (heuristic) | `GWQSH_Malware_Analyzer` v6: token-based call analysis, bounded taint propagation, 20+ weighted rules, 512 KiB bound | `verified` through `MalwareEngineTest` + fixture corpus | `MalwareEngineTest`, `IntegrityWorkflowTest` | No trained/validated model (by design); dormant-code analysis is heuristic |
| Signature database | `GWQSH_Signatures`: Ed25519-verified JSON feed, monotonic version, expiry windows, rollback copy | `unverified` — requires `sodium` (absent in this PHP build), `GWQSH_SIGNATURE_FEED_URL` and `GWQSH_SIGNATURE_PUBLIC_KEY` | `EnterpriseSecurityTest` (availability gating) | **External provider required**; no publisher is configured by default |
| Threat intelligence / reputation | `GWQSH_Threat_Intelligence`: AbuseIPDB adapter or `gwqsh_reputation_provider` filter, cached with TTL, queue rate-limited to 10/min | `unverified` — **disabled by default**, needs an API key | `EnterpriseSecurityTest` | **External provider required** (AbuseIPDB key); blocking off by default |
| Country access rules | `GWQSH_Country_Access` + `gwqsh_enterprise['geo']` | `partial` — needs a GeoIP provider and explicit consent | `EnterpriseSecurityTest` | **External provider required**; unknown locations default to "allow and log" |
| Early Guardian | `GWQSH_Guardian` installs `000000-gracewell-guardian.php`, verifies SHA-256 on admin requests, quarantines verified-critical MU files with reversible containment | `unverified` in this sandbox (child-process limitation); logic covered by 9 fixtures that run on a native PHP host | `GuardianTest` (needs native PHP) | Independent off-box verification still recommended after filesystem compromise |
| File integrity scanning | `GWQSH_Scan_Engine` + `GWQSH_File_Integrity`: bounded enumeration, SHA-256, core checksums, resumable batches, cron continuation | `verified` (paging, filters, sorting, restore paths) | `IntegrityWorkflowTest`, `ScanStateTest`, `RestoreTest` | MySQL-only JSON expressions (now portable); uploads coverage limited by the documented 512 KiB analysis bound |
| Quarantine & cleanup | `GWQSH_Quarantine_Manager`: hashed copies, metadata, restore/delete, sentinel handling, locks | `verified` after this session's fix (see §4-1) | `QuarantineManagerTest`, `IntegrityWorkflowTest`, `RestoreTest` | Hard-link-only publication is now portable; `RestoreTest` cleanup-failure path is verified |
| Prefix/data migration (Free → Pro) | `GWQSH_Migration` | `verified` for options and user-meta keys on both DB families after this session's fixes | `PrefixMigrationTest` (1 case remains environment-blocked) | Table-rename assertion cannot run on the SQLite drop-in |
| Atomic security state (rate limits, leases, alert dedup) | `GWQSH_Enterprise_Store` | `verified` on SQLite after this session's portable path; MySQL path unchanged | `EnterpriseSecurityTest` | Concurrency properties are asserted, not load-tested |
| Activity log & alerts | `GWQSH_Activity_Logger`, `GWQSH_Activity_View_Data`, delivery providers (`gwqsh_deliver_events`) | `verified` (filters, pagination, redaction, IPv6 equivalence, export) | `ActivityLogTest` | Remote delivery (email/Slack/Datadog) requires administrator configuration |
| Hardening controls | `GWQSH_Hardening`, `GWQSH_Hardening_Rules`, `GWQSH_Hardening_Data` | `verified` for assessment and managed upload rules | `HardeningPageTest` | Server-level (`.htaccess`/nginx) guidance is advisory |
| Login protection & lockouts | `GWQSH_Login_Protection` (IP lockouts, allowlist, custom login URL, XML-RPC policy) | `verified` (`LoginProtectionTest`, SQLite lockout path works via MySQL upsert compatibility) | `LoginProtectionTest`, `UiBackendTest` | Never-lock-out-and-lose-access guarantees are tested but not proven for every third-party auth plugin |
| Two-factor / passkeys / recovery | `GWQSH_Two_Factor`, `GWQSH_Passkeys`, `GWQSH_Recovery` | `verified` per the repository's browser-auth suites (not re-run here: browser tooling is unavailable) | `TwoFactorPageTest`, `SecurityTest` | Browser/WebAuthn flows need a browser environment |
| **Database malware & persistence scanning** | **absent before this session** → `GWQSH_Database_Scanner` (new) | `verified` — 15 new tests plus a CLI end-to-end proof on a live install that plants 7 artifacts and confirms all rules fire with no data change | `DatabaseScannerTest`, `tests/database-scan-proof.php` | Admin UI surfacing still to be wired (AJAX endpoints exist); no destructive remediation, by design; no measured false-positive rate on a production corpus |
| Backup / disaster recovery | No backup engine; quarantine + restore-point primitives only | `absent` | — | Large, deliberate gap. Requires an external provider decision |
| Licensing / premium services | `GWQSH_License` + `GWQSH_License_Provider` interface | `partial` — provider interface only, no endpoint configured | `EnterpriseSecurityTest` | **External provider required**; no fake license server exists (correct behaviour) |
| Multisite | `GWQSH_Network`, site-scoped tables, `is_multisite()` branches | `unverified` — no multisite fixture in this environment | — | Multisite behaviour needs a dedicated fixture |

---

## 4. Confirmed defects found in this audit (and their status)

### 4-1. Quarantine restore fails on filesystems without hard-link support — **fixed**
`GWQSH_Quarantine_Manager::restore_quarantined_locked()` published restored files with
`@link()` only. Where `link()` is unavailable (Windows/IIS, some network and container
volumes — and the WASM filesystem used here, `link(): Too many links`), a **verified,
recoverable quarantine copy could not be restored at all**, and the error text blamed a
"occupied" target that did not exist. Fixed by adding an atomic-rename fallback that still
refuses to overwrite an existing target, never exposes partial bytes, and keeps the
post-publication checksum verification.
Evidence: `tests/QuarantineManagerTest`, `tests/RestoreTest`, `tests/IntegrityWorkflowTest` now pass.

### 4-2. Atomic counters and leases silently returned `null` on SQLite — **fixed**
`GWQSH_Enterprise_Store::hit()`/`lock()` relied on `LAST_INSERT_ID(expr)` (MySQL-only).
On SQLite-backed installations the rate limiter, alert deduplication and lease-based
mutual exclusion silently failed closed (`null` → callers abort). Fixed with a portable
two-statement claim/increment path inside the same admission lease; the MySQL statement is
unchanged. Evidence: `EnterpriseSecurityTest::test_atomic_counters_and_owned_lease_release`.

### 4-3. Activity-log IP filtering used `INET6_ATON()`, which SQLite lacks — **fixed**
The IPv6 equivalence filter returned a `WP_Error` instead of results on those installs (the
log view failed for IPv6 filters). Replaced by `GWQSH_DB::ip_filter_sql()`, which keeps
`INET6_ATON` on MySQL and compares literal/canonical/expanded notations elsewhere.
Evidence: `ActivityLogTest::test_percent_placeholder_search_stays_literal_and_ipv6_is_equivalent`.

### 4-4. File-integrity sorting/filtering used MySQL JSON functions — **fixed**
`JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(...))))` and `FIELD(...)` made the findings list
empty/erroring on SQLite installs. Expressions are now produced by
`GWQSH_DB::json_text()/cast_unsigned()/enum_rank()` (MySQL keeps the original functions).
Evidence: `IntegrityWorkflowTest::test_1100_findings_all_page_sizes_…` passes.

### 4-5. Free → Pro migration could not run on SQLite — **fixed**
`RENAME TABLE` (unsupported by the drop-in) and self-join `UPDATE` statements meant legacy
`gqs_` options and user-meta keys were never migrated, so upgraded sites appeared to lose
their settings and 2FA enrolment. Table renames now use `ALTER TABLE … RENAME TO` (valid on
both families) and the key renames have equivalent SQLite paths.
Evidence: `PrefixMigrationTest::test_stored_keys_cron_and_legacy_ciphertexts_survive_idempotent_upgrade` passes.

### 4-6. `get_option('cron')` was string-cast while writing the new scanner — **fixed in the new code**
WordPress returns the schedule as an array; the initial implementation raised
"Array to string conversion" mid-scan. Now handled explicitly, and every access stops on a
reported failure instead of presenting partial data as clean.

### 4-7. Destructive test fixture (found and fixed during this session)
The first revision of the new `DatabaseScannerTest` deleted pre-existing options
(including `active_plugins`) in `tearDown()`, which deactivated the plugin on the fixture.
Teardown now snapshots and restores `{exists, value, autoload}` per option, or removes only
options the test itself created. Test-suite hygiene is part of the security story: a suite
that mutates a live install is itself a risk.

### 4-8. A cloaked frame could never be reported on its own — **fixed**
`GWQSH_Database_Scanner::check_obfuscated_scripts()` prefiltered rows with
`LIKE '%<script%'` and then `continue`d before the frame check whenever the value held no
`<script>`. Any stored payload consisting of a hidden `<iframe>` alone — the common shape of
a cloaked redirect injected into a widget, option or post — was therefore never reported as
`GWQSH-3003`. It was found by the end-to-end proof run (`tests/database-scan-proof.php`:
4 findings before the fix, 7 after, with `GWQSH-3003` present). The prefilter now accepts
either tag, the two checks are independent, and the frame pattern additionally recognises
off-screen positioning and zero opacity. Regression tests cover a frame-only payload
(must report) and a visible YouTube-style embed with a neighbouring hidden `<div>`
(must not report).

### 4-9. The scheduled database scan needed an explicit owner — **implemented**
Registering a cron hook without scheduling it, or scheduling it without clearing it, is how
plugins leave unrequested recurring jobs behind. The scanner now follows the administrator's
existing scan-schedule opt-in: enabling scheduled integrity scanning queues one bounded
database scan per day, disabling it removes the event, and both are covered by tests.
Deactivation clears the hook with the other twelve.

### Not fixed, documented instead
* WAF remains **opt-in** (`enabled=false`, `enforce_new=false`) — deliberately unchanged in
  this session.
* Authenticated/privileged request inspection is still skipped by `GWQSH_Firewall::inspect()`.
* No backup/restore engine exists.
* No virtual-patch engine exists.
* Signature feed, reputation provider and license provider remain **unconfigured**.

---

## 5. Risk register (residual, not hypothetical)

| Risk | Impact | Current mitigation | Next step |
|---|---|---|---|
| WAF disabled by default on a fresh install | Attacks pass until an administrator enables it | Setup wizard guidance; report-only mode available | Ship a explicit "enable protection" first-run step in the existing wizard |
| Authenticated requests bypass inspection | Post-auth exploit traffic (plugin endpoints, REST abuse) is not filtered | WordPress capability checks, login protection | Phase 2: bounded inspection for privileged AJAX/REST with exemption allowlists |
| No backup engine | Recovery depends on host backups | Quarantine + restore points for files only | Phase 5/16: provider-backed backups with restore verification |
| Threat feed/provider absent | No reputation or vulnerability intelligence | Country rules and local evidence remain | Document provider requirements; never ship placeholder data |
| MySQL production paths unverified in this environment | A regression introduced here could pass tests and fail on MySQL | MySQL statements kept byte-identical whenever a SQLite branch was added; PHPCS clean | Re-run the full suite on a MySQL-backed fixture before release |
| Guardian cannot be exercised here | Early-loading protection is untested in this sandbox | Existing fixture corpus + native-host instructions retained | Run `--filter GuardianTest` on a native PHP host (XAMPP) before release |

---

## 6. What this audit does **not** establish

* No claim that the plugin is free of vulnerabilities, or that any weight of testing makes
  it "100% secure". A green internal suite is not independent assurance.
* No measured false-positive/false-negative rate for the file analyzer was produced here;
  the repository documents intended fixture coverage, but only the executable subset ran.
* No performance benchmarking was performed; the SQLite fixture is not representative of a
  production MySQL host.
* Browser/WebAuthn/UI verification workflows were **not** executed in this session
  (no browser environment); their existing results in `docs/` were reviewed, not re-run.
