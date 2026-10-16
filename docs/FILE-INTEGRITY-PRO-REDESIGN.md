# File Integrity Pro redesign — 8 October 2026

## Scope and files

Inspected the File Integrity view, page JavaScript/CSS, Pro dashboard/header assets, Two-Factor view, admin routing/assets/data, AJAX controller, scanner, file-integrity service, malware analyzer, security runtime, path guard, quarantine manager, Guardian, database schema, settings, activity logger, existing workflow report, and relevant test suites. Dashboard, Login Protection and Two-Factor view files and their dedicated styles/scripts were not edited.

Modified:
- admin/views/file-integrity.php
- assets/js/file-integrity.js
- includes/class-gwqsh-admin.php (File Integrity assets only)
- includes/class-gwqsh-ajax.php (preserve signed page-size input for the allowlist)
- includes/class-gwqsh-file-integrity.php (summary fields)
- includes/class-gwqsh-scan-engine.php (completed scan executable-upload count; Windows-safe dependency exclusion; explicit-root fallback after partial enumeration)
- includes/class-gwqsh-quarantine-manager.php (allow 5/25 page sizes)
- tests/IntegrityWorkflowTest.php (existing pagination regression extended)
- tests/QuarantineManagerTest.php (5/25 validation and negative-size regression)
- tests/ScanStateTest.php (Windows-safe dependency exclusion regression)

Created:
- assets/css/scoped/pro-file-integrity.css
- docs/FILE-INTEGRITY-PRO-REDESIGN.md

Composer development dependencies were installed from the existing composer.lock to run the existing tests. No schema migration or new chart library was added.

## Scanner → storage → service → UI

GWQSH_Scan_Engine enumerates bounded permitted roots, classifies sources, streams SHA-256 hashing, analyzes bounded text/archives, compares official WordPress checksums and local baselines, and resumes persisted batches under a lock. Findings use gwqsh_scan_results; scan history uses gwqsh_scan_history. Chunked WordPress options hold scan progress, candidate manifests, baseline and analysis cache. Last-scan counters and gwqsh_scan_health store totals and coverage limitations.

GWQSH_File_Integrity exposes stored summaries, history, SQL-paginated findings and bounded escaped reviews. GWQSH_Admin supplies initial data and page assets. GWQSH_Ajax validates capability/nonce before serving refreshes and mutations. file-integrity.php renders the composition; file-integrity.js retains real AJAX workflows; pro-file-integrity.css applies only to data-page=file-integrity. No filesystem scan starts during page rendering.

## Design and integration

The screenshot guided the shared Pro header, active File Integrity navigation, mountain/lighthouse hero, protection card, five compact summary cards with decorative mini bars, Integrity Score gauge, adaptive history chart, Last Scan card, management tabs, filter toolbar/chips, separate severity column, compact actions/pagination, four tools, two-column tips and footer.

Counts come from stored scan data. The fifth card honestly shows the built-in heuristic/behavior analyzer and its version; there is no downloaded signature subscription, invented definition count, or invented update date. Protection does not claim scheduled full-file scans: the plugin removed that schedule, and cron only continues scans already started. Saved coverage errors are visible. Never Run and resumable Running states are represented.

Core integrity continues to use installed-version/locale WordPress checksums. WordPress supplies MD5 checksums; local baselines and evidence use SHA-256. Plugin/theme checks continue to use existing baselines and heuristic classification, without assuming premium/custom package checksums exist. Uploads continue through the existing analyzer, including executable content and archive rules. Completed scan manifests now persist a separate executable-upload count; older scans without this measurement show an em dash rather than borrowing the suspicious count.

The clean percentage is calculated once in PHP and consumed by JavaScript. The chart uses the existing SVG line-chart utility and real history, with data-dependent axes, ResizeObserver updates, points, area fill and tooltip. It does not pin an invented screenshot date.

Search, source/status/severity filters, sorting, pagination and selection retain the existing stored-result query architecture. Page sizes 5/25 were added while retaining all previous supported sizes. Search does not rescan the filesystem. Repair from Known Good Copy leads to Modified findings and the existing Review Change flow. Core replacement and bulk quarantine clearly operate on findings on the current page. Review network failures are handled; scan request failures recover the control and allow retry/resume.

Quarantine management retains real owned records, metadata, restore/delete/bulk actions and permanent-deletion confirmation. Review retains escaped bounded complete diffs and hash evidence, with trusted restoration unavailable when verified old bytes do not exist. Verified current content must still pass the existing acceptance protections.

## Security and responsive review

Central AJAX manage_options and nonce validation, finding/artifact-ID authorization, prepared SQL, fixed sort allowlists, canonical root/path checks, traversal/wrapper/null-byte rejection, symlink checks, unpredictable private artifact names, ownership metadata, SHA-256 evidence verification, storage locking, exclusive restore publication and existing destination conflict refusal remain in place. No browser-supplied path was introduced as an operation target. Scanned content remains data; the redesign does not execute it.

The new CSS is scoped to File Integrity and uses the Pro palette. Desktop has five summary cards and three analysis cards; tablet uses two columns; narrow screens stack cards. The results table keeps horizontal scrolling inside its bounded container. Shared CSS rules with legacy !important grid declarations are overridden locally. Shared Pro CSS, Two-Factor view and qs-core.js were compared against their initial contents and are unchanged.

Two code refinement passes addressed reference density/composition and legacy responsive cascade conflicts. **Live visual comparison passes were not completed**: browser connector inventory contained no browser, creating an in-app tab failed, and the Windows computer-use native pipe was unavailable. Screenshot fidelity, dynamic resize sequences, browser console and end-to-end button interaction must still be verified in a working browser.

## Validation and remaining limitations

- PHP syntax: all modified PHP/test files pass.
- JavaScript syntax: file-integrity.js passes node --check.
- Server rendering: Dashboard, Login Protection, Two-Factor and File Integrity render through real WordPress as an administrator, with no captured notices/warnings.
- Direct summary and page-size checks: centralized percentage and 5/10/25/50 SQL page sizes pass.
- WordPress coding standards on all six modified runtime PHP files: zero errors, 106 warnings, mostly existing direct filesystem/database operations. The new view has no reported violations.
- Initial full regression suite: 122 tests / 1,901 assertions, 10 errors and 8 failures. Missing quoted-example/image fixtures, unsupported symlink creation, Unix chmod/path assumptions and scanner workflow failures prevent a clean full-suite result. The scan_running render error came from a long-lived process loading the older service before the template changed; a fresh-process render test now passes. Negative page-size acceptance was fixed. Remaining failures are not claimed resolved without rerun evidence.
- Focused fresh-process rerun: 36 tests / 2,753 assertions passed, covering Dashboard, Login Protection, Two-Factor, security/rendering, UI backend and page-size validation.
- Real resumable scan completed in 3 batches (1,984 checked, 41 seconds) and the persisted executable-upload count matched its actual manifest. It reported enumeration_limit, prompting a scanner portability fix: Windows separators now normalize before dependency exclusions; incomplete parent enumeration no longer suppresses explicit plugin/theme/upload roots; canonical paths deduplicate overlapping enumerations. The guard, time/size bounds, hash/baseline and analyzer behavior are retained.
- Expanded pagination regression: 1 test / 2,575 assertions passed across 1,100 stored findings, including 5 and 25 row sizes.
- Windows-safe dependency exclusion regression: 1 test / 75 assertions passed.
- Scanner portability/workflow rerun: 5 tests / 97 assertions; the modified/missing/suspicious scanner case now passes. Four quarantine/rescan cases remain unsuccessful (2 errors, 2 failures): recreated files were not rediscovered and damaged evidence was not included in scan coverage. Incomplete enumeration was observed and may explain these failures; this is not a completed root-cause diagnosis. These are unresolved backend limitations, not passed security checks.
- Final real scan refresh: completed in 6 resumable batches, 6,130 checked files / 50 seconds. Persisted executable-upload count matches the actual scan manifest (0). WordPress option values are normalized to integer/null in the service. Coverage remains limited by enumeration_limit, content_size_limit and size_limit; these limitations are shown in the UI and set Attention Required.

Server render checks establish PHP loading, not browser layout/console correctness. Existing analyzer limits, partial archive/text coverage, checksum/network availability, baseline trust requirements, private storage permissions and hard-link support still apply. No claim of comprehensive malware detection or perfect security is made. The initial full-suite failures involving missing fixtures, Windows permissions/symlinks and trusted-current acceptance were not all rerun or resolved. Scanner and quarantine safety therefore remain qualified by the recorded failures.

## Requested scorecard

Scores are provisional code-review estimates, not measured visual/browser acceptance:

| Area | Score / 10 | Evidence limit |
|---|---:|---|
| Visual Match | Unverified | Live screenshot comparison unavailable |
| UI/UX | 8 | Structure and real controls implemented; browser interaction pending |
| Responsiveness | 8 | Scoped responsive rules; required live resize sequences pending |
| Functionality | 7 | 36 focused tests pass; four targeted scanner/quarantine cases remain unsuccessful |
| Scanner Accuracy | Unscored | Existing engine preserved; no corpus accuracy measurement |
| Quarantine Safety | 7 | Existing ID/path/hash/ownership controls preserved; rescan regressions remain |
| Security | 8 | Capability/path/crypto checks pass; coverage and filesystem regressions remain |
| Performance | 8 | Stored-data page, SQL pagination, existing batch scanner; no benchmark |
| Code Quality | 8 | Syntax/render checks and zero coding-standard errors; legacy warnings remain |

Final regression summary: Dashboard, Login Protection and Two-Factor pass server render and focused backend tests; their dedicated view/style/script files were not redesigned. Shared navigation markup is reused on File Integrity, but browser navigation/console/resize behavior has not been live-verified in this environment.
