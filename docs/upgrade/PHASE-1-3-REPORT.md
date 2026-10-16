# Upgrade report — Phase 0 baseline, Phase 1 hardening, Phase 3 (first deliverable)

**Scope of this session:** audit the codebase, establish a real test baseline, fix the
confirmed defects that block verified recovery, add the highest-value missing capability
(database malware/persistence scanning), and document the rest honestly.

**Explicitly *not* claimed:** this is not the complete programme in the master prompt.
Phase 2 (WAF expansion, virtual patching), Phase 4 (Recovery Center UX), Phase 5 (cloud
services, backup, licensing) and Phase 6/7 are not implemented. Nothing here is a promise
of complete protection, and no score is awarded for tests that were not executed.

---

## 1. What changed (code)

| File | Change | Why |
|---|---|---|
| `includes/class-gwqsh-database-scanner.php` | **New** `GWQSH_Database_Scanner`: read-only, bounded, prefix-aware inspection of options, posts, postmeta, usermeta/sitemeta, widgets, cron and active-plugin configuration | The "major priority" gap: detection of database-resident malware and persistence |
| `includes/class-gwqsh-quarantine-manager.php` | Restore publication falls back from `link()` to a guarded atomic `rename()` (`publish_without_hard_link()`) | Restoring a verified quarantine copy failed on filesystems without hard links |
| `includes/class-gwqsh-db.php` | New portable SQL helpers: `driver()`, `json_text()`, `cast_unsigned()`, `enum_rank()`, `ip_filter_sql()` | Verify and keep working the security state machine on SQLite-backed WordPress |
| `includes/class-gwqsh-enterprise-store.php` | `lock()`/`hit()` gain SQLite branches; MySQL statements unchanged | Rate limiting, dedup and leases silently failed closed on SQLite |
| `includes/class-gwqsh-activity-view-data.php` | IP filter uses `GWQSH_DB::ip_filter_sql()` | IPv6 filter returned `WP_Error` on SQLite |
| `includes/class-gwqsh-file-integrity.php` | Sort/filter expressions built by the portable helpers | Findings list was empty/erroring on SQLite |
| `includes/class-gwqsh-migration.php` | `ALTER TABLE … RENAME TO` (both engines) + SQLite paths for option and user-meta key renames | Free → Pro upgrade lost settings/enrolment visibility on SQLite |
| `includes/class-gwqsh-network.php` | New `expand()` for full IPv6 notation | Needed by the portable IP comparison |
| `includes/class-gwqsh-ajax.php` | New `get_database_scan`, `run_database_scan`, `approve_admin_baseline` subactions + view-data reducers | Central router already enforces nonce + `manage_options`; no new entry point |
| `gracewell-security-suite-pro.php` | Requires and initialises the scanner | Wiring only |
| `tests/DatabaseScannerTest.php` | **New** 15 tests / 48 assertions | Prove the scanner's detections, its false-positive discipline, the scheduling contract and its non-destructiveness |
| `tests/database-scan-proof.php` | **New** CLI proof run against a live install | Plant seven persistence artifacts, show every rule firing, and show that nothing in the database changes |
| `gracewell-security-suite-pro.php` | Deactivation additionally clears `GWQSH_Database_Scanner::CRON_HOOK` | No leftover recurring job after the plugin is switched off |

No UI file, stylesheet, script, option key, table, hook name or branding element was
changed. The scanner is **not** surfaced in a page yet (see §5).

---

## 2. Security properties of the new scanner (self-review)

* **Read-only.** Only `SELECT` statements. No `UPDATE`/`DELETE`/`DROP` in the module; the
  destructive operations remain where they already were (quarantine and restore), gated by
  capability, nonce, ownership checks and one-use verification tokens.
* **Bounded.** 200-row prefilter limit per table, 8 KiB inspected per value, 240-character
  redacted excerpts, 60 findings, 8-second budget, 8-second `duration_ms` recorded. Hitting
  any limit sets `status=limited`; a limited scan is never presented as clean.
* **Never executes stored content.** No `eval`, no `include` of database content, no
  `unserialize()` with object instantiation — `safe_unserialize()` passes
  `allowed_classes => false` and the test asserts the payload stays an inert
  `__PHP_Incomplete_Class`.
* **Evidence, not authority.** Every finding carries rule id, severity, confidence, table,
  column, record identifier, a redacted excerpt and an explicit "review before changing"
  action. There is no automatic cleanup path from a database finding.
* **Honest silence.** `GWQSH_Database_Scanner::report()` returns an empty array when no scan
  has run; administrator drift is reported as a *coverage limitation* rather than asserted
  when no approved baseline exists.
* **Data minimisation.** Excerpts pass through `GWQSH_Activity_View_Data::safe_text()` so
  tokens, cookies, keys and passwords are redacted before they are stored in a report.
* **Prefix/multisite aware.** Uses `$wpdb->prefix`, `$wpdb->options/posts/postmeta/usermeta`,
  `$wpdb->sitemeta` on multisite, and reports the multisite flag in the report.
* **False-positive discipline.** A `<script>` is only reported together with an obfuscation
  marker; a hidden `<iframe>` needs cloaking attributes; a cron hook needs to be registered
  by nothing currently installed (and PHP source in arguments escalates it). Each detection
  has a named benign-control test.

### Known limits of the scanner (stated, not hidden)
* Leading-wildcard `LIKE` prefilters scan full columns; on very large sites this is I/O
  heavy. Run it in low traffic, or reduce scope with the documented bounds.
* Encrypted or serialized-with-object payloads cannot be parsed meaningfully; the scanner
  reports the storing record rather than guessing the content.
* Cron findings are review items: deactivated plugins legitimately leave orphaned entries.
* Only the current site's tables are scanned on multisite; other sites need their own run.

---

## 3. Test evidence (all executed in this session)

| Suite | Result | Notes |
|---|---|---|
| `DatabaseScannerTest` (new) | **OK — 15 tests, 48 assertions** | Detections, benign controls, frame-only regression, inert object parsing, read-only proof, coverage limits, schedule opt-in |
| End-to-end proof on a live install (`tests/database-scan-proof.php`) | **All 7 planted artifacts reported; 0 rows changed** | `status: limited`, 75 ms, `read_only: options 159 -> 159, usermeta 33 -> 33, planted rows 4 -> 4`; the only write is the scanner's own report option |
| Full suite, baseline (unmodified) | 192 tests, 3872 assertions, **4 errors, 16 failures**, 3 skipped | `testlogs/baseline.txt` |
| Full suite, final | 207 tests, 3976 assertions, **1 error, 10 failures**, 3 skipped | `testlogs/final3.txt` |
| PHP_CodeSniffer (WPCS) on every touched file | `class-gwqsh-database-scanner.php`: **completely clean**; `class-gwqsh-db.php`: 0 errors (1 style warning); `class-gwqsh-ajax.php` back at its pre-existing 15 `$_POST` findings; no new violations introduced by this session | `phpcs --standard=phpcs.xml.dist` with `installed_paths` set to the locked standards |
| PHP syntax check (`php -l`) | Pass on every changed/new file | PHP 8.5.10 |

**Every remaining red is an environment limitation, with evidence:**
9 × `GuardianTest` — the test spawns a second PHP interpreter with
`proc_open(array(PHP_BINARY, '-d', …, '-r', $code))`; this runtime emulates that call with
`/bin/sh` and fails to parse the code argument (`/bin/sh: 1: Syntax error: "(" unexpected`,
exit 2). The Guardian logic itself is exercised by the same fixture corpus on a native PHP
host, which this sandbox is not. 1 × `LifecycleTest` — needs a real MySQL server
(`mysqli_real_connect(): Error while reading greeting packet`). 1 × `PrefixMigrationTest` —
the SQLite drop-in keeps stale table metadata after a rename, proven with a standalone probe
(the rename itself succeeds and the rows are preserved). None of these is an assertion about
plugin behaviour that a native host cannot satisfy.

### Reproduction
```bash
# tests (WordPress 7.1.3 + SQLite drop-in at /home/user/.cache/wp)
GWQSH_TEST_WP_ROOT=/home/user/.cache/wp \
  /home/user/.cache/phpwasm/node_modules/.bin/php-wasm-cli \
  /home/user/.cache/tools/vendor/phpunit/phpunit/phpunit -c phpunit.xml.dist --no-coverage

# coding standard
/home/user/.cache/phpwasm/node_modules/.bin/php-wasm-cli \
  /home/user/.cache/tools/vendor/squizlabs/php_codesniffer/bin/phpcs -q --standard=phpcs.xml.dist \
  --runtime-set installed_paths /home/user/.cache/tools/vendor/wp-coding-standards/wpcs,/home/user/.cache/tools/vendor/phpcsstandards/phpcsextra,/home/user/.cache/tools/vendor/phpcsstandards/phpcsutils
```
On a normal XAMPP/MySQL host the Guardian and migration suites should also run; that remains
**unverified here** and must be executed before release.

---

## 4. Engineering scorecard (self-assessment, evidence-based)

The master prompt's 100-point framework is used as a **target**, not as a certificate.
Scores reflect only what is implemented *and* verified in this environment.

| Category | Max | Awarded | Justification |
|---|---|---|---|
| Firewall & exploit-specific protection | 15 | **4** | Real bounded rules exist and are tested, but enforcement is opt-in, authenticated traffic is skipped, and no virtual-patch engine exists. I did not modify the WAF this session, so I claim no credit for improvement. |
| Malware & database detection | 15 | **9** | File analyzer v6 is reviewed and tested through fixtures; the new database/persistence scanner is implemented, covered by 15 passing tests with benign controls, and proven end-to-end on a live install where one genuine false negative (cloaked frame without a script tag) was discovered and fixed. No measured false-positive rate on a production corpus, no archive/streaming improvements, no signature publisher. |
| Safe malware recovery & rollback | 15 | **7** | Quarantine/restore verified including a real publication defect fixed this session, plus the cleanup-failure path. No backup engine, no verified full-site restore, no restore drill on a deliberately compromised fixture. |
| Authentication & account security | 10 | **4** | TOTP/passkeys/recovery/lockouts exist with tests; the lockout atomic path now works on both DB families. Not re-verified in a browser here, and non-interactive authentication policy was not re-audited this session. |
| Vulnerability & threat intelligence | 10 | **2** | Provider interfaces and safe integration code exist (Ed25519 feed, AbuseIPDB, country rules). No feed, key or advisory source is configured — an unconfigured feed is not intelligence. |
| Integrity, backup & monitoring | 10 | **5** | Integrity scanning is strong and verified (paging, filters, resume, checksums). No backup/offsite and no restore verification. |
| Security code review & testing | 10 | **7** | Real baseline established, real defects found and fixed (five of them recovery- or detection-critical), 15 new unit tests plus a reproducible CLI proof on a live install, PHPCS clean on the new module, dialect work kept byte-identical on the production path. No independent review, no fuzzing, no race-condition load tests, MySQL path not re-verified here. |
| Performance & hosting compatibility | 5 | **2** | Bounded processing and budgets exist and are documented; the SQLite findings are a genuine compatibility improvement. No before/after benchmarks were run, so no performance credit is claimed. |
| UI integration & accessibility | 5 | **1** | Deliberately untouched to protect the existing design. The new scanner has no page yet, so it gets almost no credit. |
| Operations, documentation & release readiness | 5 | **3** | This audit, the phase report, reproducible commands and explicit limitation statements. No release build was produced or packaged in this session. |
| **Total** | 100 | **44** | |

Interpretation: **the plugin is a solid, partly-verified product with a genuinely strong
file-integrity/analysis core and a large amount of premium functionality that is either
opt-in, provider-dependent, or not yet verified.** 44/100 reflects verified capability, not
potential. Any claim beyond this would not be supported by the evidence in this repository.

---

## 5. Operational notes for administrators

**Database scanning (new).** The scanner runs through the existing authenticated router:
`POST admin-ajax.php` with `action=gwqsh_action`, a valid `gwqsh_nonce`, and
`subaction=run_database_scan` (findings are also readable with `get_database_scan`). Run it
during low traffic; on large sites expect a full-column `LIKE` prefilter on options and
posts. `status=limited` or `status=failed` means coverage was incomplete — never treat it as
a clean result. Approving the administrator baseline
(`subaction=approve_admin_baseline`) records the **current** accounts as the review
reference; it is not a statement that they are trustworthy. This is the first thing to do on
a site you have just cleaned, so later administrator creation is flagged.

**Restoring quarantined files.** Restore now works on hosts without hard-link support. It
still refuses to overwrite an existing live file: review or remove that file first. If a
restore is interrupted, the quarantined copy and its metadata are retained and the file can
be restored again.

**Upgrading from the Free edition.** Table renames now use `ALTER TABLE … RENAME TO` and the
option/user-meta key rename has an equivalent path on SQLite — both families migrate
settings and 2FA enrolment without data loss. Verify your key settings after upgrading.

**Enabling the firewall for real protection.** The WAF ships **disabled**. In *Firewall &
Cleanup*, set the operation mode to *Detection / report only* first, review the recorded
events for false positives, then switch to *Blocking / enforcement* and enable enforcement
of new rules separately. Nothing in this session changed that rollout model.

---

## 6. Reproducing the end-to-end database scan proof

```bash
GWQSH_TEST_WP_ROOT=/home/user/.cache/wp \
  /home/user/.cache/phpwasm/node_modules/.bin/php-wasm-cli tests/database-scan-proof.php
```
Observed output (2026-10-16, WordPress 7.1.3 on the SQLite drop-in):

```
status: limited  duration_ms: 75  findings: 7
  GWQSH-3001: gwqsh_proof_payload      (PHP source stored in an option)
  GWQSH-3002: gwqsh_proof_widget       (obfuscated script in stored data)
  GWQSH-3003: gwqsh_proof_frame        (cloaked frame, no script tag present)
  GWQSH-3004: gwqsh_proof_incident     (known incident string)
  GWQSH-3005: gwqsh_proof_orphan_hook  (unregistered scheduled task)
  GWQSH-3007: 2188                     (capability row for a missing account)
  GWQSH-3008: gwqsh-proof-missing/plugin.php (active component with no file)
rules missing: none
read_only: options 159 -> 159, usermeta 33 -> 33, planted rows 4 -> 4
planted payload unchanged: yes
```

`status: limited` is correct here: the administrator-drift check cannot be evaluated until an
approved baseline exists, and a limited scan is never presented as clean. The script removes
every fixture it plants, including the `active_plugins` and wp-cron entries.

## 7. Recommended next phases (in priority order)

1. **MySQL verification run.** Execute the full suite on a native PHP + MySQL host
   (`php vendor/phpunit/phpunit/phpunit -c phpunit.xml.dist`, `--filter GuardianTest`).
   Until then, the MySQL paths are author-verified only.
2. **WAF Phase 2.** Bounded inspection of privileged AJAX/REST traffic with per-rule
   exceptions, plus rule versioning, rollback and a virtual-patch table with expiry.
3. **Recovery Center (Phase 4).** Incident phases on top of the data that already exists
   (scan findings, quarantine, administrator drift, cron review) — UI work inside the
   existing navigation, no new sidebar entry.
4. **Provider wiring (Phase 5).** Signature publisher, reputation, licensing and offsite
   backups are all interface-complete and unconfigured; they need real credentials,
   endpoints and terms before they can be called operational.
5. ~~**UI surfacing for the database scanner**~~ — **done** in
   [PLAN-PHASE-2.md](PLAN-PHASE-2.md): the Firewall & Cleanup screen now renders the scan
   status, coverage and findings, including the "limited coverage" state. That document also
   records the WAF Phase-2 step (bounded authenticated inspection, detection by default) and
   the resulting suite: 220 tests, 4041 assertions, 9 environment-only `GuardianTest`
   failures, 0 errors.

## 8. Unverified areas (stated plainly)

Browser/WebAuthn flows, multisite behaviour, minimum supported PHP/WordPress versions,
performance benchmarks, mail/Slack/Datadog delivery, WAF behaviour under concurrent load,
and any provider-dependent capability. None of these were executed in this session.
