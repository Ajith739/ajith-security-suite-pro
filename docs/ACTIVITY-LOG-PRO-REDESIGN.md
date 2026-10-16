# Activity Log Pro implementation report

Implemented in the existing Security Suite Pro plugin on 2026-10-08. The supplied Activity Log screenshot guided the layout. Counts, events, IP addresses and dates come from the existing audit table.

## Files inspected

Reviewed the supplied prompt and image, Activity Log view/script/styles, Pro File Integrity view and header, dashboard icon sprite, shared Pro CSS, admin compatibility CSS, qs-core.js, plugin bootstrap, DB schema/migrations, admin asset routing, AJAX dispatcher, settings and visitor-IP resolution, Activity Logger, Dashboard/Login data adapters, Login Protection, Two-Factor, File Integrity, scan engine, quarantine manager, Firewall, uninstall lifecycle, and relevant PHPUnit/configuration files.

## Files changed

| Modified file | Purpose |
| --- | --- |
| gracewell-security-suite-pro.php | Load/init the Activity data service; schema version 1.3.1; cancel migration work on deactivation |
| includes/class-gwqsh-db.php | Add nullable derived safe_details and composite timestamp/ID and event-name/timestamp indexes |
| includes/class-gwqsh-admin.php | Activity-only Pro CSS and script cache versions; new initial data; exclude Activity WebGL hero |
| includes/class-gwqsh-ajax.php | Protected Activity data, cleanup preview and confirmed batch actions |
| includes/class-gwqsh-activity-logger.php | Redact recognized credentials at write/read; normalize valid IPs; correct activation/deactivation names; missing WordPress lifecycle collectors; stable ordering; bounded scheduled retention cleanup |
| admin/views/activity-log.php | Pro header, illustrated hero, metrics, charts, activity table, filters, actions, tips and footer |
| assets/js/activity-log.js | Real data rendering, chart updates, applied filter state, paging, accessible row menus, detail dialog, export and confirmed cleanup |
| uninstall.php | Remove the new search-backfill scheduled hook through existing uninstall lifecycle |

| Created file | Purpose |
| --- | --- |
| includes/class-gwqsh-activity-view-data.php | Central classification, validation, queries, export, cleanup and bounded safe-search migration |
| assets/css/scoped/pro-activity-log.css | Page-scoped reference layout and responsive rules |
| tests/ActivityLogTest.php | Transactional query, privacy, permission, pagination, migration, collection and cleanup coverage |
| docs/ACTIVITY-LOG-PRO-REDESIGN.md | This report |

Completed-page view, JavaScript and CSS files were preserved. Hardening, Pro and Settings were not redesigned.

## UI, charts and table

Reused the existing Pro logo, header controls, navigation, typography tokens, icons and mountain/lighthouse illustration. Firewall & Cleanup retains a working navigation entry. Native WordPress sidebar and toolbar remain native.

Implemented five metric cards, the wide Activity Overview, Event Types donut, compact seven-column Recent Activity table, right-side Filter Logs/Quick Actions/Security Tips, and footer. Help opens the verified official [WordPress hardening documentation](https://developer.wordpress.org/advanced-administration/security/hardening/). The author website is labeled Gracewell, since there is no implemented feedback form.

Metrics report a rolling 30-day window and compare it with the preceding equivalent 30-day window. Comparisons are hidden when the preceding count is zero. Tooltips explain that count changes do not measure security risk.

The overview supports 7/30/90 site dates and uses the existing SVG chart helper, its ResizeObserver, and one reusable chart instance. A disclosure provides an accessible data table. The donut explicitly reports the last 30 days, independently of the overview selector and table filters. Integer percentages use remainder allocation to total 100%. Empty rings contain no fabricated segments.

Display groups are disjoint: known file events, Security & Login, User Actions, System Events, and an explicit Other group when needed. Login events are a defined exact-name subset; original event names and stored types are preserved. No classification relies on filenames or arbitrary description text.

Table pages contain at most ten records, sorted event_time DESC, id DESC. The server clamps requested pages after counting. View opens the loaded immutable record with site-time ISO timestamp, category, original type, event name, severity, user, IP and sanitized description. The keyboard-capable row menu offers View Details, Copy Event ID and Filter Similar Events. No individual delete/edit controls were added.

## Real collection and integrations

All integrations use the existing gwqsh_activity_log table and existing logger calls:

- Login Protection: successful/failed login, lockouts, locked authentication, XML-RPC denial, unlocks and configuration changes.
- Two-Factor: enrollment/disable/reset, backup-code use/regeneration, failed verification, trusted-device changes and policy updates where currently emitted.
- File Integrity/scanner/quarantine: completed scans, quarantine, backup preservation, restoration, repair and baseline acceptance where currently emitted.
- Firewall & Cleanup: actual firewall denials/settings and shared scanner/quarantine actions.
- WordPress: existing authentication, upgrades, roles and profiles; added missing user creation/deletion and theme activation collectors.

No duplicate authentication database or competing event collector was introduced. Unsupported passkey/security-engine events are not invented.

## Queries, filtering and migration

Apply Filters and Enter trigger the query. Typing alone does not query. Supported filters are search, category/login subset, exact similar event, stored username, IPv4/IPv6, recorded-severity availability, bounded preset periods and inclusive custom site dates. Equivalent IPv6 representations match. Invalid dates, future dates, inverted ranges, unsupported keys and custom spans beyond 366 calendar days are rejected.

The logger has no severity/source/result/actor-ID columns. Severity therefore reads Not recorded; that is the only specific severity option. Unavailable metadata is described honestly in the detail view.

Search covers event, user, IP and a sanitized description derivative. Original legacy descriptions are preserved. The additive migration fills safe_details in batches of 250, with a cursor and scheduled continuation. New logger writes populate it immediately. While migration is pending the UI explains that legacy description search is being prepared. The local migration completed and both new indexes were verified.

SQL values use placeholders; dynamic columns and sort/group expressions are fixed or whitelisted. Prepared predicates are composed without reinterpreting user percent signs as new placeholders. URL state, applied state, pagination and controls synchronize after success; generation checks discard stale responses. Failures retain the last successfully applied dataset/export state.

## Export and cleanup

Both export buttons submit to an authenticated, POST-only admin-post endpoint with its own nonce and manage_options check. Export uses the same validated filters as the table and covers the whole filtered set, not merely its current page. It streams batches of 500 with timestamp/ID keyset pagination and an initial maximum-ID snapshot. UTF-8 BOM, explicit CSV escaping, safe filename, no-cache/nosniff headers, redaction and spreadsheet formula protection are implemented. Exports above 50,000 records require narrower filters.

Clear Old Logs previews the real configured retention, site-time cutoff and eligible count. The dialog explicitly warns that deletion cannot be undone. A short-lived user-bound preview token, snapshot maximum ID, nonce, capability, explicit confirmation and repeated retention-policy/cutoff checks protect each batch. At most 1,000 expired rows are deleted per request. New, recent and post-preview records survive. Each successful manual batch creates a safe cleanup audit record outside the snapshot. Unlimited retention disables cleanup. Closing the dialog stops subsequent batches after any request already in flight.

Existing daily retention cleanup now uses site time and bounded batches, with scheduled continuation for a full batch. No retention setting is silently changed. No existing audit-lock policy was found in the storage architecture.

## Security and privacy

Protected view/data/export/cleanup paths require administrator capability. AJAX actions use the existing central nonce/capability dispatcher; export has a separate nonce. Input shapes and dates are validated; output and modal content are escaped. Credential-bearing legacy descriptions with recognized password/token/secret/cookie/authorization/TOTP/recovery/nonce/challenge/private-key fields are withheld as a whole. New logger writes use the same conservative redaction. Existing callers continue to emit descriptive events, not authentication submissions or secret user metadata. Safe search derivatives are not included in response records.

The existing trusted visitor-IP resolver remains authoritative; no unvalidated proxy header is introduced. Valid written IPs are normalized. No remote telemetry, new runtime library or package was added.

## Responsive implementation

The page uses a wide-left/narrow-right grid, five desktop metrics, three/two-column metric layouts at smaller containers, tablet card rearrangement and a single mobile column. Table overflow is confined to its scroll wrapper; floating menus are positioned inside the viewport and closed on scrolling/resizing. The donut retains a square aspect ratio; the chart reuses the shared resize observer. Focus styles, labels, native date controls, menu keyboard navigation, status announcements, disabled/loading states and reduced-motion rules are included.

Browser screenshots, console inspection and interactive resizing were **not performed**. The computer-use inventory returned no available apps or browsers. The requested 2560/1920/1600/1440/1366/1280/1024/768/430/390/375 widths and resize sequences remain unverified. No pixel-match claim is made.

## Verification actually performed

| Check | Result |
| --- | --- |
| Final combined Activity/Dashboard/Login/2FA/Firewall/UI/Security/File Integrity pagination suite | 55 tests, 2,874 assertions passed |
| Activity-specific checks | Include migration preservation/batching, safe description search, DST day boundaries, IPv6 equivalence, literal percent searches, immutable row paging, secret redaction, permissions, manual/scheduled retention batches and real collector registration |
| Actual CSV export probe | 503 filtered records across two batches; order, UTF-8, quoting, formula mitigation and redaction passed; fixtures removed |
| Actual endpoint probes | Authorized Activity response succeeded; invalid AJAX/export/cleanup nonces and unauthorized data/export/cleanup were rejected |
| PHP syntax | All changed runtime PHP files and new test file checked successfully |
| JavaScript syntax | node --check assets/js/activity-log.js passed after final JS edits |
| WordPress runtime renders | Dashboard, Login Protection, Two-Factor, File Integrity, Firewall & Cleanup and Activity Log rendered; no warnings/notices captured |
| File Integrity regression | Central score/page-size checks plus 1,100-finding pagination/filter/clamping and page-size validation passed |
| WPCS | 0 errors, 38 warnings across changed runtime PHP; warnings concern direct uncached audit queries/stream I/O and existing unused hook parameters/admin helpers |
| Schema/runtime sample | DB version 1.3.1, both composite indexes present, search migration complete; initial local snapshot 7.4 ms, ten rows and seven chart dates |

The full scanner/quarantine suite was not rerun. Previously documented scanner/fixture/Windows limitations are outside this Activity change. Tests used temporary or transactional fixtures; the CSV probe explicitly removed its records.

## Bugs corrected and remaining limits

Removed hardcoded users/event menus, current-page-only CSV, fabricated donut slivers, browser-local timestamp parsing, unstable simultaneous-event ordering, per-keystroke queries and missing stale-response handling. Corrected misleading plugin activation/deactivation event names for future records. Added safe retention cleanup rather than connecting Clear Old Logs to the legacy clear-all action.

Legacy timestamps are naive WordPress local datetimes. They are deliberately not bulk-reinterpreted as UTC, which would corrupt existing history and completed-page consumers. Exact original offsets for ambiguous historical DST hours or a subsequently changed site timezone cannot be recovered from that schema. Severity and additional structured metadata are unavailable; no values are inferred. User/IP suggestion lists are bounded to 200 distinct recent values. Large-scale 100,000-record performance, full browser interaction and visual matching remain unverified.

## Evidence-based assessment

Scores are engineering assessments, not a certification. Visual scores are provisional source-review estimates only; live rendering/resize verification could change them.

| Category | Score / 10 | Evidence and limit |
| --- | --- | --- |
| Screenshot Visual Match | 6, provisional | Required structure/assets/colors recreated; no rendered screenshot comparison |
| UI/UX | 7, provisional | Real applied filters, menus, details, export, cleanup preview and error states; browser interactions unverified |
| Typography | 7, provisional | Existing font family and reference size hierarchy used; visual inspection unavailable |
| Alignment | 7, provisional | Grid proportions and compact component spacing specified; actual pixel alignment unverified |
| Responsiveness | 6, provisional | Container layouts, confined overflow, circular donut and shared chart resize support; requested resize matrix not executed |
| Event Logging Functionality | 8 | Existing sources reused, missing lifecycle hooks tested; unsupported source metadata remains absent |
| Filtering & Export | 8 | Validation/filter tests and real multi-batch CSV/permission probes passed; frontend interactions unverified |
| Database Performance | 7 | Bounded queries/migrations/streaming and composite indexes; 7.4 ms local sample, no large-scale benchmark |
| Security | 8 | Capability/nonce/retention/redaction/formula/SQL checks passed; no independent penetration audit |
| Code Quality | 8 | Focused service and scoped assets, passing regression suite, syntax/WPCS checks; 38 warnings remain |
