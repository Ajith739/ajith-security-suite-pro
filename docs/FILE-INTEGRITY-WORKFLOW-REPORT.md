# File Integrity and Quarantine workflow — 4 October 2026

This upgrade preserves the existing Gracewell layout, scanner, analyzer, PathGuard,
Early Guardian, upload protection, login protection and 2FA. Changes to controls,
styles and action handling are confined to File Integrity.

## Pagination cause and fix

Mutation handlers previously returned `get_scan_issues_paged()` with no filters.
The browser replaced its current rows with those default page-one, 20-row results
while retaining other pagination variables. Equal detection timestamps also lacked
an ID tie-breaker, and invalid final pages were not clamped.

Mutations now return operation results. One frontend findings state contains page,
page size, search, location, status, severity, sort, order and selected tab.
`refreshCurrentView()` supplies it to the normal `get_scan_data` endpoint after
quarantine, review, acceptance, restoration, deletion, bulk operations and scanning.
The database counts matching records, clamps the page, and selects only the requested
`LIMIT`/`OFFSET`. Sorting uses fixed SQL expressions and an ID tie-breaker. Allowed
page sizes are exactly 10, 20, 30, 50, 100, 250 and 500. Pagination includes first/last
pages and ellipses; the table describes matching findings rather than generic files.

Page size is saved in the current administrator's `gwqsh_integrity_per_page` user
meta. Filter/search/sort/page-size changes reset page one; mutations retain the
nearest valid current page. Scan completion retains page size and filters, resets
page one, clears stale selection and refreshes through the same endpoint. Fetch
response generations prevent older requests overwriting newer navigation.

The browser also exposed a scheduled-scan race: cron and AJAX could contend for the
existing scan lock and return 503. Busy scans now return pending progress, and
explicit continuation requests do not start another scan after cron has completed.

## Quarantine cause, state model and source of truth

The missing-file loop previously compared only the baseline with the live filesystem.
Quarantine removed the original and resolved its finding, leaving the baseline entry
intact. A subsequent scan therefore created a new Missing finding.

The existing `gwqsh_quarantine_metadata` option is the authoritative ownership and
provenance index. Records include artifact/finding IDs, original relative path,
component/type, full SHA-256, size, timestamp, reason, severity, score, confidence and
status. A filesystem marker or sidecar alone cannot authorize restore/delete or
suppress an absent baseline file. Canonical path comparison uses PathGuard, including
absent paths and configured root aliases. Display paths are separate from canonical
operation paths and are never used as authorization.

For non-core baseline absence, the scanner checks `absence_state()` first:

- **Missing:** absent without an owned quarantine or matching removal record.
- **Quarantined:** absent with owned quarantine provenance and an available artifact;
  remains manageable in the quarantine panel and contributes no Missing count.
- **Damaged:** owned quarantine provenance remains but evidence is unavailable;
  visible in the panel, scan coverage, and summary warning rather than silently clean.
- **Intentionally removed:** a confirmed permanent deletion keeps a path-specific
  tombstone in `gwqsh_intentional_removals`, including the artifact's historical hash
  and the baseline hash associated with removal. Findings/history remain retained.
- **Recreated:** a live file at that path is inspected normally, even while an older
  artifact or tombstone exists. No live-file malware suppression is introduced.
- **Restored/Accepted:** the historical finding records the action; subsequent live
  inspection returns to normal baseline and malware analysis.

Only exact Gracewell sentinel bytes tied to owned metadata and artifact ID are
recognized. Both the manager's sentinel and the existing Early Guardian sentinel
format are supported. Replacing either sentinel causes normal inspection again.

Official core checksum expectations remain independent. An intentionally quarantined
core file requires official restoration and an active integrity warning; permanent
removal never suppresses official core expectations. Core bootstrap protection and
self-quarantine protection remain enforced.

A shared private-storage lock serializes manager mutations and Guardian metadata
imports. Ownership and sidecar provenance are persisted before removing a live file.
Reconciliation records orphan artifact names internally in `gwqsh_quarantine_orphans`
and resolves stale non-core Missing rows for actively quarantined paths. It never
promotes arbitrary orphan files into trusted ownership.

## Selection, quarantine management and Clear All

Select All applies to the current findings page only. Its checkbox is checked for all
rows, indeterminate for some rows, and unchecked for none. Clear Selection empties IDs,
resets the checkbox and hides the bulk toolbar. Navigation, filters, scans and mutation
refreshes clear stale selections. Bulk quarantine submits eligible selected findings;
Missing, protected and already isolated states are not offered another quarantine.

The added existing-style card lists original path, component, reason/severity,
quarantine date, size, abbreviated SHA-256, state and actions. Backups are labeled
Preserved backup. Visible-page selection, Clear Selection, individual restore/delete,
Restore Selected, Delete Selected and Clear All Quarantine are wired to existing AJAX
routes. Bulk requests accept 1–500 IDs/artifacts and reject 501. Failures are per-item
and return safe details while other items continue.

Clear All requires the explicit confirmation:
“Permanently delete all quarantined copies? This cannot be undone.”
Every integrity route remains centrally protected by `manage_options` and a nonce.
Deletion derives filenames from validated artifact IDs inside private storage,
requires Gracewell-owned metadata, refuses symlink artifacts, deletes sidecars, and
retains failed records. It never follows an original path to delete a live file.

Restore verifies full SHA-256, validates the original target, stages and verifies the
complete file, and publishes exclusively so a racing existing target is not overwritten.
Only an exact owned MU sentinel may be replaced. Evidence cleanup occurs after restored
hash verification. Cleanup failures retain ownership and are reported without discarding
the verified restored live file. Files larger than 5 MB remain full copies.

## Modified Old / New decisions and diff

Review Change uses the existing modal with Trusted/Old and Current/New descriptions.
Restore Old selects actual content only when its full hash matches the trusted baseline;
it preserves and verifies the current New version, restores verified Old bytes, verifies
again, resolves the finding and logs the action. A backup reason alone cannot establish
trust. Core restore downloads and checksum-verifies the official WordPress file.

Keep New requires confirmation, an active finding, an unchanged scan-time SHA-256 and
fresh complete malware analysis. Critical, score >=80, automatic-block and unresolved
Critical findings at that path are rejected. Safe content updates the baseline and
records Accepted. Official core checks continue even after local baseline acceptance;
the confirmation warns that official restoration is preferred.

Non-core text diff uses actual hash-verified trusted content. Core diff uses a bounded,
official-checksum-verified download. Diff is escaped, limited to 512 KiB / 5,000 lines per file,
and excludes binary content. Hash/size evidence is available when text comparison is
unavailable. Old restoration is disabled when only an old hash exists.

The File Integrity modal stacking adjustment keeps its controls above the existing
sticky admin header; no other page's styles were changed.

## Files and database changes

Runtime files changed in this task:

- `admin/views/file-integrity.php`
- `assets/css/scoped/file-integrity.css`
- `assets/js/file-integrity.js`
- `includes/class-gwqsh-admin.php`
- `includes/class-gwqsh-ajax.php`
- `includes/class-gwqsh-file-integrity.php`
- `includes/class-gwqsh-path-guard.php`
- `includes/class-gwqsh-quarantine-manager.php`
- `includes/class-gwqsh-scan-engine.php`
- `includes/class-gwqsh-guardian.php`

Added tests: `IntegrityWorkflowTest.php`, `browser-integrity.cjs`,
`browser-environment.php`, `browser-fixture.php`, `browser-nonce.php`.
Updated `QuarantineManagerTest.php` to reject stale resolved IDs before creating a new
finding for a restored file. Added this report and reproducible test instructions.
Existing uncommitted project changes were preserved. The older security report received
only trailing-whitespace cleanup from this task.

No schema migration is necessary: the existing status column and resolution flag retain
history. New options/user meta initialize lazily; no old results are destroyed. Existing
uninstall prefix cleanup already covers these plugin-owned names.

## Measured validation

- **PHPUnit:** 90 tests, 1,754 assertions, passed with XAMPP PHP 8.2.
- **PHPCS/WPCS:** executed across the configured backend/views; zero errors,
  191 warnings. Remaining warnings include direct filesystem/database operations,
  documentation recommendations and intentionally fresh reads. This is not a
  warning-free WPCS run.
- **PHP lint:** 45 Gracewell PHP files checked, zero failures; Composer dependencies
  are excluded from the Gracewell lint count.
- **JavaScript syntax:** 14 asset/test files checked, zero failures.
- **Composer:** `composer validate --strict` passed.
- **Browser:** 45 real local WordPress/Chrome checks passed; zero JavaScript runtime or
  unexpected console errors. Tested 375px and 1280px widths. The browser exercised all
  page sizes, navigation, filters/search/sort, selection/indeterminate/clearing, mutation
  page retention, final-page clamping, individual/bulk restore/delete, 500 quarantines,
  501 rejection, partial bulk errors, destructive Clear All confirmation, escaped diff,
  Restore Old, Keep New, Critical rejection, completed resumable scanning, preferences,
  missing nonce rejection, and capability denial with a valid subscriber nonce.
- **Whitespace:** `git diff --check` passed.

The database regression suite uses 1,100 findings with identical detection timestamps
and checks exact IDs, complete coverage, no duplication, every supported page size,
LIMIT/OFFSET, filters, sorting, empty pages and final-page clamping. Filesystem regressions
cover full quarantine/rescan/restore/delete/recreation, MU sentinel replacement, trusted
restoration and preserved New bytes, Critical acceptance rejection, escaped content,
large copies, missing/tampered evidence, orphan reporting, symlink rejection, partial
deletion and restore-cleanup failure. Database mutations use transactions and filesystem
fixtures are cleaned up. Browser accounts, copies, fixtures and temporary findings are
removed after testing; the saved original baseline/quarantine view is restored. A subsequent real scan refreshes
statistics after the temporary fixtures are removed.

## Security review and limitations

Operation targets come from active finding IDs or owned artifact IDs, never display
paths. Traversal, wrappers, symlink segments, stale IDs, hash changes, nonce/capability
bypasses, oversized bulk requests and arbitrary SQL sort expressions are checked or
rejected. UI paths/reasons/errors are escaped. Random artifact names, complete copies,
private directory guards, Early Guardian, ZIP analysis, encrypted TOTP, hashed recovery
codes and login protection remain intact.

Trusted Old content is not synthesized from hashes: automatic non-core restoration
requires a matching retained copy. Official restoration requires reachable WordPress.org
and checksum-verified content. Existing scanner coverage/size limits still apply; incomplete
analysis cannot be accepted. Atomic exclusive quarantine restoration requires filesystem
hard-link support; failure retains evidence rather than overwriting a target. PHP storage
must be accessible to the serving PHP identity; existing inaccessible/missing evidence is
reported as damaged. Processes with independent filesystem write access remain outside
what a cooperative plugin lock can fully serialize. Browser validation covered two widths,
not every device/browser. Optional select-all-across-pages and Restore All were not added.


## File Integrity table and lifecycle follow-up (2026-10-05)

Scan Results and Quarantine management now share a full-width workspace with accessible
view buttons (including arrow/Home/End navigation). Each table keeps its own pagination;
quarantine defaults to 20 entries even when findings use 500. Table bodies are bounded to
65vh with sticky headers. Mobile rows show labelled fields, wrapped paths, all actions,
and a visible select-all control. Evidence can be expanded without making every row tall.
File Integrity assets use modification timestamps to invalidate cached CSS/JavaScript.

Finding mutations prevent repeated in-flight submissions. Under the existing storage lock,
repeated quarantine requests reuse the same owned artifact for already isolated content.
Exact owned MU blocking stubs are never quarantined as new evidence. Concurrent requests
can receive `quarantine_busy`; retrying after completion reuses the existing artifact.
Legacy unresolved findings for an owned absent/blocked path outside the official core
index are reconciled both
on page load and refresh. Permanent deletion records removal independently of evidence
metadata, resolves stale findings, and survives rescans. Recreated live files continue to
be inspected; missing official core requirements remain visible.

Text reviews now use WordPress's native diff engine to display the complete bounded file,
with old/new line numbers, escaped source, additions/removals, and totals. The 40-line
fallback is removed. Baseline lookup handles canonical aliases. Hash/size metadata wraps
fully; binary files and missing old copies receive an accurate explanation. Current text
can be inspected even when old bytes were not retained. A hash cannot reconstruct an old
file; complete old/new comparison still requires retained verified bytes (or verified
official core content). Larger files receive an explicit offline-comparison message,
rather than a truncated diff.

Regressions cover duplicate finding rows, repeated isolation, deletion/rescanning,
recreated files, owned-stub re-isolation, and insertion/deletion beyond line 1,500.
Browser verification covers both panels, independent pagination, labelled mobile rows,
keyboard switching, concurrent isolation plus safe retries, and escaped Git-style changes.


Follow-up validation: **94 PHPUnit tests / 1,789 assertions passed**; **54 browser
checks passed with zero JavaScript runtime errors**. Five additional browser checks
validated concurrent requests and safe retries, keyboard switching, actual mobile card
layout, and added/removed diff rows. Changed PHP/JavaScript syntax and `git diff --check`
passed. WordPress coding standards reported zero errors (existing filesystem/database
warnings remain). Temporary browser accounts, findings, copies, and fixture files were
removed; baseline and existing quarantine metadata were restored. A final scan refreshed
actual file counts after cleanup.


## Retry, review and popup follow-up (2026-10-05)

The reported path was `wp-content/plugins/quiteshield/tests/fixtures/malware/attack-mu-cloaking.php`, a sanitized static-analysis fixture in the inactive legacy plugin. XAMPP runs PHP as `daemon`; its directory was owned by `abinesh` with mode 0755. PHP could read and preserve the source but could not unlink it. Retrying created another backup, and deleting a backup incorrectly resolved the still-live source until the next scan rediscovered it.

The manager now reuses an owned copy only after verifying its complete SHA-256 against the current source, including failed-removal backups and identical recreated files. Failed isolation explicitly reports that the original remains active. Deleting a backup cannot resolve a live source; successful removals persist verified removal history before evidence deletion. Reconciliation fetches unresolved paths once rather than querying each artifact separately. Locked operations refresh WordPress option caches to avoid stale cross-request metadata.

For this local fixture folder, a macOS ACL grants only `daemon` directory creation and child deletion (`user:daemon allow add_file,delete_child`); POSIX mode remains 0755. Actual browser isolation, three repeated requests, deletion/rescan, and identical-source recreation all passed. The original fixture was restored byte-for-byte with its permissions and timestamps after validation. It remains intentionally present for the user's next action; its suspicious finding is legitimate while the source remains live. The fixture was never executed.

Bulk Mark as Reviewed now sends one authenticated request and performs one prepared database update for up to 500 selected IDs. It does not trust or accept the file contents. Browser completion measured 457 ms locally. Notifications sit above the review popup, wrap long messages, and remain visible longer while a popup is open. Successful mutation messages appear before the table refresh.

Git-style reviews display every changed hunk with context, line numbers and totals, plus an expandable complete-file comparison. Verified text bytes are retained separately when content is accepted or a trusted baseline is established, so deleting quarantine evidence does not destroy the trusted text. Historical hashes alone cannot recover unavailable old bytes; binary files and text above 512 KiB or 5,000 lines retain explicit comparison limits. Final-newline and line-ending differences are reported accurately.

Validation: the full PHPUnit suite passed 98 tests / 1,815 assertions; the additional permission regression passed 1 test / 16 assertions. The browser suite passed 56 checks with no JavaScript runtime errors, including a real hit-test proving the toast appears above the popup. Three additional browser checks passed against the exact reported file. Temporary accounts, fixture findings, quarantine records and baseline changes were cleaned up. PHP/JavaScript syntax checks, WordPress coding standards (zero errors; existing warnings remain), and whitespace checks passed.
