# Login Protection redesign and verification

Implemented locally on 7 October 2026 against `Security Suite Pro Login Protection Dashboard (2).png`. Changes apply to Login Protection, using the real WordPress toolbar and sidebar. The completed Dashboard view, JavaScript, stylesheet, data provider, and icon definitions remain byte-for-byte unchanged.

## Files inspected

The audit covered plugin bootstrap, database setup, admin registration and asset loading, AJAX dispatch, settings/IP resolution, login protection, activity logging, Hardening/XML-RPC, Two-Factor authentication, capability/nonce gates, uninstall handling, existing tests, and the previous dashboard implementation. Principal files:

- `gracewell-security-suite-pro.php`, `includes/class-gwqsh-db.php`, `includes/class-gwqsh-admin.php`, `includes/class-gwqsh-ajax.php`.
- `includes/class-gwqsh-login-protection.php`, `includes/class-gwqsh-settings.php`, `includes/class-gwqsh-activity-logger.php`, `includes/class-gwqsh-hardening.php`, `includes/class-gwqsh-two-factor.php`.
- `admin/views/login-protection.php`, `admin/views/dashboard.php`, `admin/views/dashboard-icons.php`.
- `assets/js/login-protection.js`, `assets/js/dashboard.js`, `assets/js/qs-core.js`.
- Scoped dashboard, Pro dashboard, legacy login protection, page-fixes, and admin-compat styles; local header/logo/world-map assets.
- `tests/SecurityTest.php`, `tests/UiBackendTest.php`, `tests/DashboardDataTest.php`, `tests/LifecycleTest.php`, `tests/ReleaseTest.php`, browser test helpers, and release documentation.

## Modified, created, and removed

| Modified file | Purpose |
| --- | --- |
| `gracewell-security-suite-pro.php` | Load Login Protection view data; advance the database schema version to 1.2.0. |
| `includes/class-gwqsh-admin.php` | Supply the login snapshot, load the existing Pro component CSS plus the login-only stylesheet, omit obsolete login styles and the WebGL hero. Dashboard behavior is preserved. |
| `includes/class-gwqsh-ajax.php` | Connect real settings/access saves and snapshots; validate bounds, switches, IPs, proxy modes and slugs; report persistence failures and stale unlocks. Existing central authorization remains in place. |
| `includes/class-gwqsh-db.php` | Add nullable `first_attempt` to the existing lockout table and backfill existing rows without removing their counters or expiries. |
| `includes/class-gwqsh-login-protection.php` | Enforce repeat escalation, anchor the failure-count window, serialize counter updates, avoid extending active lockouts, support username recording and optional email alerts, preserve routing, improve IPv6 allowlist comparisons and mutation feedback. |
| `includes/class-gwqsh-activity-logger.php` | Respect the username-recording preference for failed-login audit records. |
| `includes/class-gwqsh-hardening.php` | Record real XML-RPC denials from the existing blocking rule. |
| `admin/views/login-protection.php` | Reference-based page composition and accessible native forms. |
| `assets/js/login-protection.js` | Real rendering, saves, unlocks, allowlist synchronization, responsive chart, keyboard tooltips, menus/search, copies and error recovery. |

Created:

- `includes/class-gwqsh-login-view-data.php` — one read model and score calculation.
- `assets/css/scoped/pro-login.css` — styles scoped to `.qs-pro-login-page`, with container breakpoints.
- `tests/LoginProtectionTest.php` — regression coverage for counters, expiry, escalation, alerts, actual statistics, IPv6 and proxy reporting.
- `docs/LOGIN-PROTECTION-REDESIGN.md` — this implementation report.

Removed: `assets/css/scoped/login-protection.css`, the obsolete stylesheet for the replaced page. Shared legacy styles used by other pages were retained.

## Components and real data

The page contains the established Pro navigation with Login Protection active; mountain/lighthouse hero and compact actual status panel; seven metrics; score gauge and breakdown; four-series Attack Trends; five lockout-rule rows; Protection Settings; Access Controls; synchronized trusted-IP chips; selected-IP unlocks; recent login events; geographic availability state; bottom allowlist and five tool tiles.

Data flow:

`existing options / lockout table / audit records → GWQSH_Login_View_Data → initial PHP and JSON → login-protection.js → authenticated AJAX → updated snapshots`

Settings remain in `gwqsh_login_protection`, `gwqsh_allowlist`, `gwqsh_settings`, and `gwqsh_hardening`. No new production table, REST endpoint, external service, chart package, font or JavaScript dependency was introduced.

Connected settings: engine enabled, maximum failures, count window, default duration, repeated lockouts in 24 hours, escalation duration, generic errors, username recording, administrator email on lockout, shared XML-RPC Hardening rule, custom slug/enabled, guest login/admin behavior, and trusted proxy mode. Saves are explicit and report success only after server acknowledgement.

Metrics use recorded denials in 30 days, current active lockouts, saved threshold/duration, effective XML-RPC state and the actual allowlist. Ordinary failed-password audit entries are distinct from genuinely denied requests. Chart bins use WordPress site calendar dates and offer 7/14/30 days. No comparison percentages or reference counts are fabricated.

Protection score: brute-force protection 40%, effective custom URL 20%, effective XML-RPC rule 20%, enabled valid lockout rules 20%. This is a configuration score, rather than a guarantee of site security. Country protection is unavailable and excluded from the score. PHP initial output and AJAX updates use the same calculation.

## Actions and security

Preserved `get_login_data`, `save_login_settings`, `unlock_ip`, `add_allow_ip`, `remove_allow_ip`, `save_login_slug`, and the existing toggle action; added `save_login_access`. The new interface does not expose a destructive clear-all action.

The central scalar-shape check, `gwqsh_nonce` verification, and `manage_options` requirement protect all Login Protection requests. Numeric fields have server bounds; booleans and enums are strict. SQL values are prepared. PHP and JavaScript output is escaped. Forwarded IPs require an explicitly trusted `REMOTE_ADDR`; missing or invalid headers are reported as direct detection. No automatic Cloudflare trust was added.

IPv4 and IPv6 additions are validated. Equivalent IPv6 spellings match for allowlist bypass, and existing CIDR entries retain their previous behavior. Both chip views use the same stored array. Unlocks update only the selected locked record and return a conflict if it is no longer locked.

The count window is anchored to the first failure. Its timestamp is reset on window expiry, lock expiry and manual unlock. Repeat escalation uses actual prior lockout events in 24 hours. Requests already blocked do not extend the lockout or trigger another alert. A successful password check awaiting Two-Factor authentication remains exempt from failed-attempt counting. Email defaults off and uses WordPress mail transport when enabled.

Custom login routing retains native WordPress authentication, reset and logout handlers, subdirectory/plain/index/pretty URL handling, internal AJAX/admin-post exceptions, and emergency recovery. Changing the custom URL configuration rotates its private recovery key. The displayed/copied login URL reflects the currently effective route.

## Responsive and visual review

Two desktop refinement passes adjusted the hero, metric density, gauges, rule rows, form spacing, table badges and bottom tools against the reference. Extra Save and recovery controls and truthful unavailable states make some cards taller than the supplied static image. The existing Dashboard illustration and native WordPress shell also differ from the reference artwork and shell configuration; this is not a pixel-identical result.

Verified widths: 2560, 1920, 1672, 1600, 1440, 1366, 1280, 1024, 768, 430, 390 and 375 pixels. Verified live sequences: 1920 → 390 → 1920; 1440 → 768 → 1440; 430 → 1366. Container widths account for WordPress sidebar space. Analytics, forms and tables reflow progressively; mobile controls grow, trusted IPv6 chips wrap, and wide tables scroll inside their own cards. Charts redraw from cached real data on resize, without resize-triggered AJAX.

No page-level horizontal overflow or unexpected browser errors occurred in the final Login Protection sweep. Search, notifications, account/navigation menus, native keyboard controls, focus feedback, Escape dismissal and chart keyboard tooltips were exercised. Review screenshots and machine-readable results are retained locally under `/tmp/quietshield-login-review/` without session credentials.

## Bugs fixed

- Repeat-lockout parameters were stored without enforcement.
- Failure windows drifted with each last attempt instead of using a start time.
- Active lockouts could be counted repeatedly or silently claim an unlock succeeded.
- Proxy reporting could claim a configured provider even without a valid accepted header.
- The old chart could substitute fixed weekday values when actual data was missing.
- Failed-password events could be presented as enforced blocks.
- Failed-login username recording had no real preference; email toggles were not connected to lockouts.
- Equivalent IPv6 forms could fail allowlist matching.
- The displayed login route could remain custom while custom routing was disabled.
- Both rebuilt allowlist views now stay synchronized; previously unconnected controls have real saves.

## Tests and Dashboard regression

- PHP syntax checks passed for all modified/created PHP files; JavaScript syntax check passed.
- PHPUnit: **27 tests, 123 assertions, all passed** across LoginProtectionTest, SecurityTest, UiBackendTest, DashboardDataTest and LifecycleTest.
- WordPress Coding Standards: **zero errors** in changed production PHP. Twenty-two warnings remain in existing callback signatures, legacy timestamp formatting, local asset/filesystem access and an unrelated existing database call. New view data and markup have no warnings.
- Browser actions: settings reload/persistence and engine pause/resume; invalid bounds/switches/enums, reserved slug and untrusted proxy rejection; IPv4/IPv6 add/remove and duplicate validation; synchronized chips; selected-IP unlock and stale rejection; View All/Show Less over six real isolated lockout rows; genuine nonce and subscriber capability rejection; malformed POST rejection; chart ranges/keyboard; header menus; and URL clipboard actions.
- Native HTTP/browser flows: password login through custom route, native logout, guest default-route 404 and admin restriction, lost-password form, invalid reset-key handling, a valid reset submission and authentication with its new password, public AJAX routing, real XML-RPC denial, emergency recovery and normal-login restoration after disabling custom routing.
- Simulated network failures preserved unsaved form values, kept saved metrics, re-enabled Save and recovered through Retry.
- Dashboard read-only browser regression passed with no unexpected errors or horizontal overflow; chart ranges and search still worked. The Dashboard template, stylesheet, script, data provider and shared icon file matched the original backup byte-for-byte.
- Temporary accounts, sessions, fixture lockouts and positively identified test audit rows were removed. Test settings were restored after browser scenarios. Later legitimate settings saves from the active administrator were detected and retained, along with their audit records and recovery configuration.

## Remaining limitations and assessment

Country blocking/GeoIP, shared IP reputation, separate role policies, Slack and AI threat alerts have no corresponding backend in this build. They show truthful unavailable/shared-rule states. The decorative map has no invented heat spots or country counts. Older unlogged XML-RPC requests cannot be reconstructed. Username recording annotates IP-based lockouts; it does not introduce separate per-username counters. Historical reasons may be unavailable when their audit records have expired. Email delivery depends on WordPress mail configuration; alert tests intercepted the mail call and sent no external email. The count window is a fixed window anchored to the first failure, rather than a sliding-window algorithm.

Self-assessment, bounded by the checks above:

| Area | Score / 10 |
| --- | --- |
| Visual match | 8.5 |
| UI/UX | 9 |
| Responsiveness | 9 |
| Functionality | 9 |
| Security | 9 |
| Performance | 8.5 |
| Code quality | 9 |
