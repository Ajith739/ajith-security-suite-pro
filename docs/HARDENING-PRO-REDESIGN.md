# Hardening Pro implementation report
Date: 2026-10-08. Project: gracewell-security-suite-pro.

The Hardening screen now follows the supplied screenshot's structure, uses real backend assessments, and supports explicit, scoped configuration changes. Browser visual verification remains outstanding.

## 1. Files inspected
The supplied Hardening prompt and screenshot; plugin bootstrap; Hardening, settings, admin, AJAX, security runtime, activity logger, shared score providers and file-integrity summary; existing Hardening view/script/styles; shared dashboard styles/icons/header; completed Pro views and scripts; PHPUnit configuration and existing regression tests.

## 2. Files modified
- gracewell-security-suite-pro.php: loads the two Hardening services.
- includes/class-gwqsh-hardening.php: runtime guards, capability restrictions, precise disclosure controls, assessed checks and failure recovery.
- includes/class-gwqsh-admin.php: Hardening-only assets and initial data.
- includes/class-gwqsh-ajax.php: validated, confirmed Hardening actions and verification/CSP dispatch.
- admin/views/hardening.php: redesigned screen.
- assets/js/hardening.js: backend-confirmed interactions.
- tests/UiBackendTest.php: administrator fixture and current overall-score contract for the protected Hardening provider.

## 3. Files created
- includes/class-gwqsh-hardening-data.php
- includes/class-gwqsh-hardening-rules.php
- assets/css/scoped/pro-hardening.css
- tests/HardeningPageTest.php
- docs/HARDENING-PRO-REDESIGN.md

## 4. Hardening UI redesigned
Reused the Pro header, logo, icon symbols, illustration and tokens. Added four compact metrics, six-row checklist, component ring, recommendations, four server tabs, scoped undo card and public-header preview. Navigation retains all completed routes, including Firewall & Cleanup. Active Hardening state is rendered by PHP.

Two source refinement passes were performed: initial screenshot geometry/colors/density, then table-cell alignment, component value columns, narrow-screen spacing, overflow, status descriptions and preservation of an actively edited CSP draft. These were source/layout reviews, not rendered screenshot comparisons.

## 5. Real controls
Switches represent saved intent. Status and effectiveness are separate. XML-RPC uses the authentication filter and exact request blocker; editor restrictions use WordPress capabilities; version hiding removes generator output and exact core-version values only on core asset paths; enumeration limits anonymous numeric probes and users REST routes. Named author archives, authenticated routes and unrelated REST endpoints remain available. Headers and uploads do not receive effectiveness credit merely because their toggles are on.

States include Disabled, Plugin disabled, Enabled, Verification Pending, Partially Applied, Manual Configuration Required and Failed. Requests are serialized, controls show busy state, and success is reported after the backend confirms. Errors refresh the assessment.

## 6. Hardening Score
Preserved established weights: XML-RPC 15, editor 15, version disclosure 10, enumeration 15, headers 33, uploads 12. Total 100. Only effective controls contribute. Four WordPress controls require active configuration and hook evidence. Headers require recent observed expected values. Uploads require active configuration, the exact managed block, Apache detection and recent successful HTTP sampling. A hook assessment is scoped evidence, not a guarantee against caches or another plugin.

## 7. Risk Level
Preserved thresholds: Low >=85, Medium >=60, High >=35, otherwise Critical. The UI explicitly labels this a weighted Hardening assessment; it is not an absolute judgment of all site vulnerabilities. Counts and recommendations derive from the same six rows.

## 8. Security Components
Uses the existing login, TFA, integrity, Hardening and activity providers. The circle is explicitly labeled Hardening. The provider also exposes the existing weighted overall calculation separately; it is not passed off as the ring's score. No new chart library.

## 9. Recommendations
Pending or ineffective controls sort first. Review opens the actual status, scope, compatibility note and weight. View All shows all six controls. Effective controls display current evidence rather than fabricated completion.

## 10. Apache rules
Only the trusted WordPress uploads .htaccess is automatically managed. The exact known plugin block is recognized; edited or duplicate markers cause refusal. Root configuration and foreign directives are preserved. Existing bytes, existence and hash are backed up in protected options before a write. Direct filesystem support is required; an exclusive lock, sibling temporary file, content comparison, external-edit check and atomic rename precede success. Repeated application is idempotent.

Actual local Apache fixture: ordinary text HTTP 200, .php HTTP 403, mixed-case .PHp8 HTTP 403; owned-block removal passed. The fixture and inert files were removed and existing ownership options restored. Generated root-header guidance is for manual review only.

## 11. Nginx configuration
Nginx is detected as manual configuration required. No .htaccess is written for enabling on Nginx. Guidance derives the site's paths, quotes the upload regex, warns about location ordering/header duplication, and requires nginx -t and a reload. No Nginx deployment or syntax test was available; this is guidance, not a verified active configuration.

## 12. CSP
Separate off/report-only/enforce workflow, default off. Bounded single-line policies, supported directive/source allowlists, duplicate-directive rejection and control-character rejection prevent header injection. Enforcement requires explicit confirmation and warns about integration breakage. Existing application CSP headers are preserved. CSP targets public WordPress frontend responses, excluding admin and REST. No report collector is installed; report-only diagnostics require browser developer tools. Policy validation/persistence was tested; browser integration behavior was not.

## 13. Headers Preview
Separates configured values from observed public headers and includes timestamp/expiry and upload verification result. Default headers are added only if absent in PHP's existing response headers. Server/proxy headers added later cannot be inspected by PHP; public verification provides that evidence.

Verification uses the fixed configured home URL and same-origin trusted uploads URL, with no browser-supplied URL, redirects or credentials. Each of at most three requests has a five-second timeout. Temporary probes contain plain inert text without PHP tags. Cleanup results affect assurance. Evidence lasts five minutes and is invalidated by control/CSP/site/server/rule-content changes and a new verification attempt. A per-administrator one-minute cooldown prevents repeated probing. Page rendering does not perform remote checks.

Real installed-site check: public HTTP 200; Apache/2.4.58; observed nosniff, SAMEORIGIN and strict-origin-when-cross-origin. Uploads sampling failed, so no uploads assurance was awarded; zero probe files remained. At that check, score was 88, five passing controls and Low weighted Hardening risk. This was a timestamped observation, not a permanent state.

## 14. Reset to Defaults
Requires nonce, administrator capability and confirmation. Restores five established default intents with headers off, and turns custom CSP off. Apache upload rules are managed only in the owned scope; unsupported servers remain manual. It differs from Revert All.

## 15. Undo / rollback
Revert All disables the six plugin controls and custom CSP and removes only exact owned upload directives. Previously created empty managed files can be removed when ownership metadata supports it. Unrelated bytes and host changes are preserved; when external changes make separator ownership uncertain, the separator is retained.

Previous plugin settings and CSP are backed up before grouped changes. Settings persistence precedes filesystem writes. Rule failures attempt restoration of prior plugin settings and log failure; database or filesystem failure is not reported as a guaranteed rollback. Protected last-file backup remains available for administrator recovery. There is no reliable pre-installation settings snapshot, so Revert All does not invent one or restore unknown external settings. External constants, manually deployed directives and legacy foreign blocks may continue to apply.

## 16. Security issues fixed
Removed saved-toggle-as-proof scoring, unconditional header replacement, hardcoded CSP enforcement, broad public-author blocking, overly broad asset version removal and creation/redefinition of DISALLOW_FILE_EDIT. Added strict explicit states, confirmed destructive actions, bounded policy validation, fixed-target verification, probe cleanup, owned-block collision refusal, protected backups and persistence checks. Upload scanning/filtering is explicitly distinguished from server execution denial.

WordPress references used for the hook audit:
- [xmlrpc_enabled scope](https://developer.wordpress.org/reference/hooks/xmlrpc_enabled/)
- [WordPress response headers](https://developer.wordpress.org/reference/hooks/wp_headers/)
- [Dynamic capabilities](https://developer.wordpress.org/reference/hooks/user_has_cap/)

## 17. Responsive improvements
Scoped container breakpoints at 1120, 850 and 560 pixels adjust lower-card layout, main columns, metrics and mobile stacking. Shared header navigation handles its available container width. Table scrolling is confined to its wrapper, code scrolls internally, long notes wrap, tabs use roving keyboard focus and reduced-motion settings are respected.

Requested widths 2560, 1920, 1600, 1440, 1366, 1280, 1024, 768, 430, 390 and 375: all remain visually unverified. Requested cycles 1920 ->390 ->1920, 1440 ->768 ->1440 and 430 ->1366 were not executed. CUA returned no available apps or browsers. Browser console, tab navigation, clipboard, modal focus and live resize behavior therefore remain untested.

## 18. Completed-page regressions
Dashboard, Login Protection, Two-Factor, File Integrity, Firewall & Cleanup and Activity Log views and page scripts matched their pre-change contents byte for byte: 12 files unchanged. Shared UI styles were not edited. All seven views rendered through installed WordPress with zero captured PHP warnings/notices. Shared score and file-integrity page-size checks passed.

## 19. Tests actually executed
- Focused regression selection: 66 PHPUnit tests, 2,970 assertions passed.
- Hardening-specific integration suite: 10 tests, 85 assertions passed. Covers score consistency, readonly assessment, exact/foreign byte preservation, backups, duplicate/edited blocks, locks, Nginx manual state, reset versus revert, CSP invalid input and authorization, cache keys, REST scope, mocked fixed-origin HTTP checks, cleanup, evidence invalidation, persistence rejection and recovery.
- Ten actual AJAX probes passed: authorized data, invalid nonce, unauthorized data, unsupported feature, ambiguous state, missing toggle/reset/revert/verify confirmation and CSP header injection.
- Actual public HTTP check and isolated Apache denial/rollback fixture passed as described above.
- Nine modified/created PHP code files passed php -l; Hardening JS passed node --check.
- Runtime asset registration passed: shared Pro and Hardening styles, page script, no legacy Hardening/page-fixes stylesheet collision, no hero WebGL runtime.
- Rendered structure: six switches, four ARIA tabs, no placeholder href.
- WordPress coding standards: zero errors, 19 warnings across production files. Warnings include deliberate local filesystem operations/atomic primitives, inherited callback arguments, existing database calls and benign logo encoding.
- This was the selected regression suite, not an assertion that every repository test passes. Inherited scanner fixture/Windows failures documented in earlier work were outside this change.

## 20. Remaining limitations
Rendered visual accuracy and frontend interactions require a browser review. Nginx guidance requires hosting deployment/testing. Existing uploads configuration failed actual sampling and needs manual review of its preserved host/legacy directives. The generated owned block worked in the isolated Apache fixture; that does not prove every installed handler or extension is denied. Header evidence samples one public response and expires. Existing/proxy headers are preserved, so differing policies can remain partial. Hook evidence and reversible owned changes do not guarantee universal protection or recovery from unrelated database/server failures.

## Evidence-based review scores
These are conservative implementation review scores, not pixel measurements or browser QA results.

| Area | Score /10 | Evidence and limit |
| --- | ---: | --- |
| Screenshot Accuracy | 5 | Reference structure and source refinement; no rendered comparison |
| UI/UX | 6 | Explicit states and confirmations; frontend flow untested |
| Typography | 6 | Shared tokens and compact hierarchy; no visual inspection |
| Alignment | 6 | Table/component layout corrected in source; browser pending |
| Responsiveness | 5 | Container rules and local overflow; all requested widths untested |
| Hardening Functionality | 8 | Integration/AJAX tests; actual uploads remains unverified |
| Server Configuration Safety | 8 | Owned bytes, backups, lock, atomic write, real Apache fixture; no Nginx deployment |
| Rollback Reliability | 8 | Exact removal and failure fixtures; no universal recovery guarantee |
| Security | 8 | Authorization, validation and fixed-target tests; external integration limits |
| Performance | 8 | No remote page-load checks/new chart runtime; no browser profiling |
| Code Quality | 8 | Syntax/regressions clean, WPCS zero errors; 19 warnings remain |

## Header and hero follow-up — 2026-10-08
At the user’s request, Hardening now uses the existing Settings topbar markup and shared hero, with Hardening copy and active navigation. The hero includes the existing heroBirds canvas and bundled Three.js module. Settings-specific hero layout fixes are scoped to this hero. Pro styling starts below the hero to avoid overriding the Settings header. The lower Hardening content, page script and backend controls remain unchanged. PHP rendering and bird-module registration were checked; live WebGL/browser appearance remains unverified in this session. The original no-WebGL asset check described above is superseded by this requested change.
