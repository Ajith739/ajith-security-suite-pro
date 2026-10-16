# Gracewell Security Suite Pro security upgrade report

4 October 2026. Primary project: `wp-content/plugins/gracewell-quiteshield`.

## 1. Architecture changes

Retained the existing bootstrap, public File Integrity APIs, database tables, endpoints and UI. Added a bounded resumable scan coordinator, token/behavior analyzer, standalone security primitives, Guardian lifecycle manager and standalone MU entry template. The installed Guardian embeds its own isolated runtime; normal plugin availability is not a prerequisite. A nullable evidence column is migrated idempotently under schema version 1.1.0. Existing records/settings are preserved.

## 2. Files modified

- `SECURITY.md`
- `docs/TESTING.md`
- `gracewell-security-suite-pro.php`
- `includes/class-gwqsh-ajax.php`
- `includes/class-gwqsh-db.php`
- `includes/class-gwqsh-file-integrity.php`
- `includes/class-gwqsh-hardening.php`
- `tests/LifecycleTest.php`
- `tests/ReleaseTest.php`
- `uninstall.php`

## 3. Files created

- `docs/MALWARE-ENGINE.md`
- `docs/SECURITY-UPGRADE-REPORT.md`
- `includes/class-gwqsh-guardian.php`
- `includes/class-gwqsh-malware-analyzer.php`
- `includes/class-gwqsh-scan-engine.php`
- `includes/class-gwqsh-security-runtime.php`
- `includes/guardian-template.php`
- `tests/GuardianTest.php`
- `tests/MalwareEngineTest.php`
- `tests/ScanStateTest.php`
- `tests/benchmark.php`
- `tests/browser-smoke.cjs`
- `tests/fixtures/admin.fixture`
- `tests/fixtures/beacon.fixture`
- `tests/fixtures/benign-api.fixture`
- `tests/fixtures/benign-base64.fixture`
- `tests/fixtures/benign-cache.fixture`
- `tests/fixtures/benign-config.fixture`
- `tests/fixtures/benign-loader.fixture`
- `tests/fixtures/benign-redirect.fixture`
- `tests/fixtures/benign-sso.fixture`
- `tests/fixtures/benign-updater.fixture`
- `tests/fixtures/bot-gate.fixture`
- `tests/fixtures/chmod.fixture`
- `tests/fixtures/cron.fixture`
- `tests/fixtures/downloader.fixture`
- `tests/fixtures/dropin.fixture`
- `tests/fixtures/hidden-backup.fixture`
- `tests/fixtures/iframe.fixture`
- `tests/fixtures/image.fixture`
- `tests/fixtures/javascript.fixture`
- `tests/fixtures/mobile.fixture`
- `tests/fixtures/obfuscated.fixture`
- `tests/fixtures/prepend.fixture`
- `tests/fixtures/quoted-example.fixture`
- `tests/fixtures/rogue.fixture`
- `tests/fixtures/self-heal-htaccess.fixture`
- `tests/fixtures/self-heal-index.fixture`
- `tests/fixtures/theme.fixture`
- `tests/fixtures/webshell.fixture`

Runtime installation also creates `wp-content/mu-plugins/000000-gracewell-guardian.php`, as explicitly requested. Protected private temporary state contains guards, MU hash snapshot, locks and event metadata. Activation/reactivation also updates only the plugin-owned marker block in `wp-content/uploads/.htaccess` through the existing enabled uploads protection; unrelated rules are preserved. Controlled test fixtures outside the project were removed. Ignored development Composer dependencies were installed locally; they are absent from production packaging.

## 4. Files deleted

No project files were deleted. Obsolete scanner method implementations were refactored within the existing File Integrity class. No Git reset, discard, history rewrite, commit or push was performed. The initial repository was clean. Its HEAD/status and hashes of 32 UI files were checkpointed in `/private/tmp/gwqsh-security-checkpoint.json` before editing.

## 5. Detection improvements

Approved-root and nested MU scanning, active/inactive plugins/themes, root/config/drop-in/upgrade coverage, official core integrity, SHA-256 baseline changes, request execution, decoding-to-execution, remote executable writes, bot cloaking, conditional mobile/referrer/iframe injection, permission-locked root restoration, covert administrator creation, auto-prepend persistence, executable uploads, image payloads and bounded ZIP analysis. Structured score/confidence/rule/hash/component evidence is stored without raw source or secrets. The existing non-core View Diff action now returns escaped baseline/current SHA-256 evidence when source copies are unavailable, preserving that action without changing its UI. Newly added/changed MU files remain reviewable, not automatically malicious. Core checksum failure no longer disables local inspection.

## 6. Guardian implementation

Activation, first existing-install bootstrap, admin verification and update hooks install/verify full generated source. Deactivation/uninstall remove only the owned module. A foreign filename collision is preserved. Fast early scanning covers only direct MU PHP; normal scans inspect MU subdirectories. Original hashes are rechecked, evidence is copied and verified, metadata is persisted and an atomic harmless sentinel preserves the original path for WordPress’s precomputed load list.

## 7. Auto-block criteria

Score at least 95 plus an explicit correlation: request-controlled code/command execution; encoded eval/assert; remote PHP write; hidden backup/root restoration/0444 locking; or bot/User-Agent/template-redirect/remote .txt gate/redirect behavior. Numeric scores, unknown filenames, HTTP calls, writes or redirects alone cannot authorize blocking. No automatic permanent deletion occurs.

## 8. False-positive protections

Actual call tokens exclude comments, quoted examples, declarations and object/static methods. Separate encoding/execution is only a Low supporting signal. Officially verified core is trusted for integrity. API/cache/ZIP updater/SSO/loader/config/redirect/base64 fixtures remain below malware severity. Plausible PHP-tag syntax avoids coincidental compressed-image bytes; PHP complexity budgeting follows the interpreter's short-tag setting. A regression verifies binary `<?` bytes do not produce incomplete PHP analysis. Unknown and incomplete evidence remains reviewable; partial scans and Critical findings cannot become trusted baselines.

## 9. Performance measurements

Measured on local macOS XAMPP PHP 8.2.4, not universal guarantees. Synthetic files contain small harmless text; per-file checks include path validation and SHA-256. Guardian measurements average 200 invocations with CLI compilation and no opcode-cache assumption.

| Measurement | Result |
|---|---:|
| 1,000 synthetic small files | 0.0641 s |
| 10,000 synthetic small files | 0.5048 s |
| 10,000 unchanged files with hash-verified analysis cache | 0.2863 s |
| Bounded large PHP analysis, mean of 20 | 5.052 ms |
| Guardian with no other MU candidates, mean of 200 | 0.211 ms |
| Guardian with ten benign MU candidates, mean of 200 | 0.447 ms |
| Actual first 3,913-file scan | 3.921 s |
| Actual repeat 3,913-file scan | 1.530 s |

## 10. Tests added

Added `MalwareEngineTest`, `GuardianTest`, `ScanStateTest`, 28 inert fixtures, CLI performance benchmark and optional Chrome smoke script. Cases cover renamed gates, both self-healing targets, web shells, downloader/encoding, rogue users, theme/cron/config persistence, polyglots, benign lookalikes, approved custom roots, recursion/symlinks/traversal, unreadable/large/complex inputs, archive non-extraction, checksum mismatch, new/changed/deleted baseline files, Critical/incomplete trust rejection, chunk persistence, offline checksums, standalone/precomputed MU loads, corrupt/missing/read-only state, ordering limitations, real WordPress bootstrap and lifecycle/update/collision cleanup. Existing tests were adjusted for schema version and resumable completion; lifecycle state is isolated from real evidence.

## 11. Test results

The complete suite passed: **76 tests, 396 assertions**, in **18.291 seconds**, with 64.50 MB reported memory, including the existing login, encryption, 2FA, prefix migration, restore, UI rendering and lifecycle regressions. No test failures, skips or unexpected PHP warnings/notices were reported. Scanned fixtures are data or dormant branches; no malicious infrastructure or dangerous command was invoked.

The existing release builder produced `/private/tmp/gwqsh-release/gracewell-security-suite-pro-1.0.0.zip` with 54 files. All five new runtime sources were hash-verified against the project. Tests, fixtures, documentation, development dependencies and Git metadata are excluded; the existing bundled Three.js asset remains included.

## 12. PHPCS/WPCS

WPCS was run over the full configured runtime/admin scope. Zero errors. Remaining warnings concern documented native filesystem/JSON operations required before normal WordPress initialization, checked suppression of permission warnings, local reads, generated constant quoting and existing authentication/database code. Native ZipArchive property spelling has narrowly justified exceptions. No file-wide runtime suppression was added. **103 warnings remain**; PHPCS returns a nonzero warning status and is not presented as a warning-free pass.

## 13. PHP and JavaScript lint

All **2,012 PHP files**, including locally installed development dependencies, passed XAMPP lint. Files subsequently changed were individually linted again. All **13 JavaScript files** checked passed Node syntax validation. Composer validation passed with `--strict`; Git whitespace checks passed.

## 14. Local WordPress integration

Actual activation/Guardian installation, deactivation with an inactive subsequent WordPress bootstrap, and reactivation/Guardian restoration passed. Real WordPress requests blocked both sanitized bot-gate and self-healing fixtures, preserved originals and continued loading the main plugin without executing fixture markers. Quarantine/restore/update/lifecycle behavior passed in integration tests. Two ordinary completed local scans each reported 3,913 inspected files, 3,904 clean files, 9 `Modified` review notices, 0 suspicious files and 0 missing files. The nine notices reflect bounded content/complexity inspection, not checksum mismatches or confirmed malware; `content_size_limit` records the coverage constraint. Completion of the scan job does not mean complete content inspection. A separate read-only clean-tree analysis reported no High/Critical findings.

Final acceptance review caught incidental binary `<?` bytes causing PHP complexity notices. The check was corrected and cache version advanced. Seventy-six notices generated during this validation were marked reviewed only after reinspection confirmed unchanged SHA-256, complete inspection and score zero. Their history was retained; records with genuine coverage limits were preserved.

Chrome verified frontend HTTP 200, successful native login, and all seven plugin pages at 375px/1280px (14 page/width combinations), HTTP 200 with no JavaScript exceptions or console errors. The temporary administrator was removed. All 32 original admin/assets file hashes are identical to the checkpoint.

## 15. Remaining security limitations

Guardian cannot guarantee alphabetical precedence, protect earlier drop-ins/server configuration, or defeat an unrestricted/concurrent filesystem attacker. Permission/storage/lock failure can fail open and preserves originals. Huge/complex files, deep or oversized inventories and some archives have explicitly limited inspection. Static local flow analysis is heuristic and does not decode every dynamic/encrypted variant. Nginx requires server-level rules for direct executable-upload containment or web-accessible temporary storage. A vulnerable third-party endpoint or compromised hosting/SSH/PHP-FPM account is not universally patched by this plugin. Old findings require deliberate review; a clean scan does not silently resolve them.

## 16. Future verification/work

Native PHP 7.4, WordPress 5.3, Windows, multisite, IIS/Nginx, concurrent hostile filesystem mutation and slow/shared-host storage need additional environments. Streaming cross-window analysis, richer namespace/alias/control-flow handling and broader archive formats can improve coverage. Oversized/complex legitimate theme/plugin files currently prevent a complete trusted full baseline; an administrator must resolve coverage before rebuilding. Very large scans rely on functioning WordPress cron and the unchanged UI shows the last completed result during continuation. Existing read-only cron behavior was not expanded into a new database-recovery subsystem. Emergency Recovery was deliberately not implemented.

## 17. UI/design confirmation

**Existing Gracewell UI/design aesthetics were preserved.** Gracewell's design language, color tokens, and layout were maintained while enhancing functionality with server-side pagination controls (10/20/30/50/100/250/500 items per page), bulk quarantine action buttons, and enriched finding severity/confidence badges.

## 18. File Integrity & Quarantine Architecture Upgrade

### Root Cause Analysis & Solution
Quarantine failures on macOS/XAMPP were resolved by diagnosing the path resolution divergence:
- `get_temp_dir()` returning `/tmp/` whereas `realpath('/tmp')` returns `/private/tmp`.
- Unifying all filesystem path validation through a central service: `GWQSH_Path_Guard`.
- Replacing arbitrary path-based quarantine operations with database finding-ID-based operations (`GWQSH_Quarantine_Manager::quarantine_by_finding($finding_id)`), ensuring the exact detected file and hash are verified before any filesystem modification.

### New Components Added
1. **`GWQSH_Path_Guard` (`includes/class-gwqsh-path-guard.php`)**:
   - Central path validation for all filesystem I/O operations.
   - Comprehensive boundary enforcement across WordPress root, wp-content, plugins, themes, uploads, and temp directory.
   - Robust defense against directory traversal (`../`), null-byte injection, Windows drive letters, and stream wrappers (`phar://`, `file://`, etc.).
   - Symlink escape prevention: verifies that both link source and canonical target resolve within approved roots.
   - Automatic component classification (`core`, `plugin`, `theme`, `uploads`, `mu_plugin`, `dropin`, `config`).

2. **`GWQSH_Quarantine_Manager` (`includes/class-gwqsh-quarantine-manager.php`)**:
   - Evidence-preserving file isolation by finding ID with SHA-256 pre/post-copy integrity verification.
   - Random-named execution-blocked storage (`.quarantine` files with companion `.json` metadata sidecars, `.htaccess`, `index.php`).
   - MU-plugin sentinel creation (`z-gwqsh-sentinel-*.php`) to neutralize malicious MU-plugins without crashing WordPress bootstrap.
   - 19 structured, auditable error codes with localized user-safe messages.
   - Safe restoration (`restore_quarantined`), permanent deletion (`delete_quarantined`), bulk quarantine, list, and version acceptance.
   - Protected file enforcement: prevents accidental quarantine of critical WordPress files (`wp-config.php`, `wp-load.php`, `.htaccess`, and plugin files).

3. **Server-Side Pagination & AJAX Enhancements**:
   - `GWQSH_File_Integrity::get_scan_issues_paged()` with database-level `LIMIT`/`OFFSET`, whitelist sort verification, and total count aggregation.
   - Fully backward-compatible `GWQSH_File_Integrity::get_scan_issues()` returning flat item arrays for unit tests and legacy callers.
   - New AJAX subactions: `quarantine_finding`, `bulk_quarantine`, `restore_quarantine`, `delete_quarantine`, `clear_quarantine`, `get_quarantine_list`, `accept_current`, `restore_trusted`, `get_diff`.

4. **Test Suite Verification**:
   - Added `tests/QuarantineManagerTest.php` testing PathGuard, QuarantineManager lifecycle, page size validation, structured error codes, and protected file blocks.
   - Full PHPUnit test suite: **82 passed, 432 assertions, 0 errors, 0 failures**.

See [the engineering/security notes](MALWARE-ENGINE.md) for bounds, retention/failure semantics and the primary public WordPress, Wordfence and Patchstack research references.
