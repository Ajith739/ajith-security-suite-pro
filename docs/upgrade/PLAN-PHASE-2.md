# Plan — Phase 2 + database-scanner UI increment

## Deliverable A — Database malware & persistence scan, surfaced in the existing UI

Constraint respected: **no new sidebar entry, no new design system.** The scanner appears as a
card inside the existing **Firewall & Cleanup** page, built only from the classes that page
already uses (`qs-card`, `qs-fw-*`, `qs-badge`, `qs-fw-table-scroll`, `qs-button`).

| Step | File | Work |
|---|---|---|
| A1 | `includes/class-gwqsh-database-view-data.php` (new) | Single source of truth for screen data: status, coverage, findings, baseline, disclaimer. Sanitizes rule/title/severity/confidence/table/column/record; passes evidence text through raw so the interface escapes it **exactly once**; caps rows. |
| A2 | `includes/class-gwqsh-ajax.php` | `database_scan_data()` delegates to the view-data class so AJAX and server-rendered data cannot drift. |
| A3 | `includes/class-gwqsh-admin.php` | `get_page_initial_data('firewall-cleanup')` gains `database` (same shape as the AJAX payload). |
| A4 | `admin/views/firewall-cleanup.php` | New card: status/coverage banner, findings table with empty state, reviewed-evidence disclaimer, buttons for scan + baseline approval. Keyboard reachable, `aria-live` feedback, no inline styles beyond the page's existing pattern. |
| A5 | `assets/js/firewall-cleanup.js` | Render the card from initial data; wire Run scan / Approve baseline through `GWQSH.ajax`; re-render on response, surface "limited coverage" and never show a clean state for a failed scan. |
| A6 | `tests/DatabaseScanPageTest.php` (new) | Page data shape, hostile titles sanitized, evidence not pre-escaped (single-escape contract), malformed findings dropped, findings capped, no internal state in the payload, capability/nonce enforcement, and baseline approval recording only current administrators. |
| A7 | `tests/jsdom-database-card.cjs` + `tests/database-page-capture.php` (new) | The real controller driven against the real rendered markup in jsdom: status rendering, empty state, run-scan re-render, limited-coverage wording, findings rendered as inert text (no injected markup), meta line, confirm-then-approve baseline. Skips cleanly when jsdom or a capture is absent. |

## Deliverable B — WAF Phase 2: bounded authenticated inspection

| Step | File | Work |
|---|---|---|
| B1 | `includes/class-gwqsh-firewall.php` | `inspect_privileged()` on a separate hook; bounded extraction (≤40 scalars, ≤8 KiB total, ≤1 KiB per value, skips sensitive keys and oversized values); rules `GWQSH-1006` (script/SQL payload in an authenticated request) and `GWQSH-1007` (traversal/inclusion in an authenticated request); **detect-only by default**; a content-writer path allowlist that is never blocked; pure `privileged_decision()` so the policy is unit-testable without terminating a request. |
| B2 | `includes/class-gwqsh-enterprise-config.php` | New `waf` fields: `privileged` (default off), `privileged_enforce` (default off), `privileged_exclusions` (new `rules` type restricted to 1006/1007). |
| B3 | `includes/class-gwqsh-enterprise-ui.php` | Schema-driven form already renders the new fields; add the honest explanatory sentence. |
| B4 | `admin/views/firewall-cleanup.php` | Correct the "authenticated requests are excluded" note to describe the two modes truthfully. |
| B5 | `tests/PrivilegedWafTest.php` (new) | Detection in admin/AJAX contexts; sensitive fields and oversized editor content never inspected; per-rule exceptions work; report-only by default; content-writer paths never blocked; exempt paths; opt-in required and anonymous requests untouched; no submitted value stored in audit details. |
| B6 | `tests/EnterpriseSecurityTest.php` | Rule inventory updated to the two new authenticated rules, with the safe default asserted (inspection off, content authoring never denied). |

## Sequencing and safety

1. Back up the fixture database and checkpoint the working tree before touching code.
2. A1–A3, then B1–B4, then JS/views, then tests, then PHPCS, then the full suite.
3. If the full suite regresses, revert that step instead of adjusting unrelated tests.

## Verified outcome

- Full suite: **220 tests, 4041 assertions, 9 failures, 4 skipped, 0 errors**. The nine failures are all
  `GuardianTest` and are environmental: they need a second PHP process, and php-wasm's `proc_open`
  ignores argv. Every other pre-existing test passes; the two new test files add 13 tests.
- PHPCS: `0 errors, 0 warnings` across the five changed PHP files (the two long-standing
  `advanced()` violations were fixed while the file was open).
- Runtime checks against the WordPress fixture: `waf` round-trips `privileged`,
  `privileged_enforce` and `privileged_exclusions`; the schema rejects exempting a public rule;
  the decision is `block` on `/wp-admin/options.php`, `detect` on `/wp-admin/post.php`, and `ignore`
  while inspection is off; the Firewall & Cleanup view renders "Never scanned" with the card present.
- The jsdom run found and fixed a real defect: evidence was escaped in the view model *and* again in
  the browser, so a stored payload rendered as `&lt;script&gt;` instead of the payload. Escaping now
  happens once, at render, and both layers assert it.

## Reproducing the evidence

```bash
# PHP suites (PHP 8.5 via php-wasm, WordPress fixture on SQLite)
GWQSH_TEST_WP_ROOT=/home/user/.cache/wp \
  .cache/phpwasm/node_modules/.bin/php-wasm-cli \
  .cache/tools/vendor/phpunit/phpunit/phpunit -c phpunit.xml.dist --no-coverage
# focused: --filter 'DatabaseScanPageTest|PrivilegedWafTest'

# Rendered-markup DOM harness for the database-scan card
php-wasm-cli tests/database-page-capture.php /tmp/gwqsh-page     # needs a loaded WP fixture
GWQSH_PAGE_DIR=/tmp/gwqsh-page NODE_PATH=<dir with jsdom> node tests/jsdom-database-card.cjs

# Coding standard
phpcs --standard=phpcs.xml.dist --runtime-set installed_paths <wpcs,phpcsextra,phpcsutils> \
  includes/class-gwqsh-database-view-data.php includes/class-gwqsh-enterprise-config.php \
  includes/class-gwqsh-enterprise-ui.php includes/class-gwqsh-firewall.php \
  admin/views/firewall-cleanup.php
```

## Explicit non-goals for this increment

Virtual patching, rule download/rollback, multisite verification, browser automation
(unavailable in this sandbox), and any change to the existing public-query behaviour of the
firewall. No enforcement is switched on by default anywhere.
