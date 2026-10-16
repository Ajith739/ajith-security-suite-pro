# Two-Factor Pro redesign and verification

Completed against `security-pro-reference/Security Suite Pro Two-Factor Dashboard.png`, the supplied Two-Factor reference. Work date: 2026-10-08. Dashboard and Login Protection were preserved.

## 1. Files inspected

- `includes/class-gwqsh-two-factor.php`: enrollment, RFC 6238 TOTP, encrypted secrets, backup records, login challenges, remembered devices, mandatory setup and REST restrictions.
- `includes/class-gwqsh-ajax.php`: central nonce/capability dispatch and every Two-Factor handler.
- `includes/class-gwqsh-admin.php`, `gracewell-security-suite-pro.php`: menu permissions, screen rendering, localized data and assets.
- `admin/views/two-factor.php`, `assets/js/two-factor.js`, former `assets/css/scoped/two-factor.css`: previous UI and actions.
- `includes/class-gwqsh-crypto.php`: authenticated sodium secretbox/AES-256-GCM encryption and legacy format support.
- `includes/class-gwqsh-settings.php`, `includes/class-gwqsh-login-protection.php`: client IP resolution, custom login routes, password-stage lockouts and challenge exemptions.
- `includes/class-gwqsh-activity-logger.php`, `includes/class-gwqsh-db.php`, `includes/class-gwqsh-migration.php`, `uninstall.php`: audit records, storage, prefix migration and plugin-owned cleanup.
- Completed Dashboard/Login views, scripts, CSS, data providers and `admin/views/dashboard-icons.php`: reusable Pro components and preservation checks.
- `assets/js/qs-core.js`, `assets/js/qrcode.js`, `assets/css/admin-compat.css`: accessible dialogs, clipboard/export/AJAX utilities, local QR rendering and native admin integration.
- Existing Security, Release, UI Backend, Dashboard Data, Login Protection and Lifecycle tests.

No WebAuthn credentials, passkey verification, email factor verification or SMS factor verification implementation was found. No external verification provider was introduced.

## 2. Files modified

- `admin/views/two-factor.php`
- `assets/js/two-factor.js`
- `includes/class-gwqsh-two-factor.php`
- `includes/class-gwqsh-ajax.php`
- `includes/class-gwqsh-admin.php`
- `gracewell-security-suite-pro.php`

Admin/bootstrap changes load the new Two-Factor provider and styles, retain the existing QR dependency, apply script cache busting and omit the unnecessary WebGL hero runtime for this screen. Other screens keep their original asset paths and behavior.

## 3. Files created / removed

Created:

- `includes/class-gwqsh-two-factor-view-data.php`
- `assets/css/scoped/pro-two-factor.css`
- `tests/TwoFactorPageTest.php`
- `docs/TWO-FACTOR-REDESIGN.md`

Removed the obsolete `assets/css/scoped/two-factor.css`; its enqueue path was removed before final verification. The new screen reuses unchanged Pro tokens, illustration, logo and icon sprite. No new production vendor package was added.

## 4. Redesigned components

The Pro header with active Two-Factor navigation; identity protection hero and actual protection state; five metric cards; authenticator setup with real QR and manual key; enabled method rows; policy toggles and role dialog; recovery code grid, warning and export controls; passkey/remembered-device tabs; paginated users table with search, role/status filters and safe management dialogs; security guidance. The native WordPress menu and toolbar remain intact.

The layout independently stacks setup/recovery on the left and methods/policy/devices on the right, matching the reference hierarchy. Multiple visual comparison/refinement passes tightened card dimensions, restored tinted metric icons, corrected responsive header container names, compacted rows, and fixed mobile recovery/footer spacing.

## 5. TOTP integration

The existing SHA1, six-digit, 30-second TOTP implementation and ±1-step validation window remain. Enrollment uses an encrypted pending secret and activates only after valid code verification. Active rotation leaves the current authenticator working until the replacement is verified. Pending enrollment consumption is conditional on the stored value so a stale/concurrent verification cannot consume a different pending key.

An already-enrolled account cannot reuse the enrollment endpoint to reset its replay counter. Login and self-disable use atomic TOTP replay guards. Setup, replacement, self-disable and login code checks share an atomic account limit of ten factor attempts per five minutes. Password-stage lockouts retain their existing behavior.

## 6. QR implementation

The existing bundled MIT QR generator renders locally, with a four-module quiet zone and a matching `otpauth://totp/` URI containing site issuer, user identity, actual pending secret, SHA1, six digits and 30-second period. No secret goes to a remote QR service.

Both canvas data and the actual rendered QR pixels were decoded and compared with the provisioning URI. Displayed QR decoding passed at desktop 1492, tablet 768 and mobile 375 pixels. Current active secrets are not redisplayed after verification; a new pending key requires explicit regeneration.

## 7. Backup codes

Preserved cryptographic random generation, keyed verification hashes, authenticated encrypted display copies for the owning user, legacy hash-only handling, atomic single-use consumption and replacement of all previous codes on regeneration. Used code records lose their verification hash and display copy.

Individual copy, Copy All and text download include only the currently visible unused codes. Exports contain site, username, generation date and a security warning, with no authenticator secret, session token or cryptographic record. Regeneration is explicitly confirmed. Older code sets without a recorded generation date show “Not recorded.”

## 8. Passkeys / WebAuthn

Not implemented in the existing plugin. Counts remain zero, method rows show “Not configured,” and Add Passkey explains the unavailable registration service. No fake devices, credential records, toggles or browser WebAuthn calls were introduced. RP/origin/challenge/signature testing is therefore not applicable.

## 9. Remembered devices

Actual user-owned records are displayed without token hashes or session identifiers. A stable opaque identifier replaces fragile list indexes; deletion validates ownership and uses atomic compare-and-swap. Invalid and stale identifiers return errors rather than reporting success.

Existing records show unrecorded creation/last-use dates honestly. Newly remembered devices record creation and last use; successful trusted-cookie use updates the last-use date. Normal password verification is still required. Revocation causes another factor challenge at the next login; current WordPress sessions are unaffected unless an administrator explicitly resets the account.

## 10. Policy and enforcement

Preserved existing `require_admin`, `allow_roles` and `remember_device` settings. Added actual `allow_admin_reset`, `enforce_roles` and `required_roles` fields using the existing Two-Factor option. The admin-reset default preserves previous functionality; saved restrictions are respected.

Role selections come from `wp_roles()`, including custom/WooCommerce roles. Staff enforcement selects only registered editor/author/shop-manager roles. Server-side mandatory setup uses the stored selected roles. Unknown roles, malformed toggle values and malformed target IDs are rejected. Viewing the page does not enable any enforcement policy.

Tests restored only deliberately changed preference fields. Genuine policy changes made during review were retained rather than replacing them with an earlier snapshot.

## 11. User management

The table uses real WordPress users, initial avatars, safe method/verification/recovery information and 25-row server pagination through `WP_User_Query`. Search includes login, display name and—when the viewer is an administrator—email. Search is debounced; role and status filters work on actual data.

Site counters/status IDs are cached for at most 15 seconds and invalidated after relevant user metadata, role, user or policy changes. Metadata is primed in bounded batches when rebuilding counters; table queries fetch only a page. Cached records contain counters and IDs, never secrets, backup values or remembered-device tokens.

Low-privilege viewers receive only their own user row, setup key, backup values and devices. Administrators can require setup and inspect/revoke permitted users' remembered devices, but cannot enroll an authenticator or retrieve another user's setup/recovery secrets. Admin reset requires a permitted target, allowed policy, explicit confirmation and nonce; it clears factor/recovery/device data and destroys the target's WordPress sessions while preserving their enrollment requirement.

## 12. Security review

Reviewed authentication ownership, central CSRF nonce and capability checks, per-target authorization, scalar request shapes, strict code/role/ID validation, authenticated encryption, single-use backups, TOTP replay resistance, account rate limiting, challenge expiry/attempt limits, password-first login and token confidentiality.

Challenges now bind to the registered encrypted factor record, so reset or rotation invalidates older password-issued challenges. Privileged resets retain audit logging without secrets. The UI clears its global initial-data reference and removes secret-bearing QR/key content after verification.

Reference guidance: [WordPress nonces and authorization](https://developer.wordpress.org/apis/security/nonces/) and [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238). This is a targeted implementation review, not an independent penetration-test certification.

## 13. Responsive verification

Passed widths: 2560, 1920, 1600, 1440, 1366, 1280, 1024, 768, 430, 390 and 375; additionally compared at the reference width of 1492. Repeated resize sequences passed: 1920 → 390 → 1920; 1440 → 768 → 1440; 430 → 1366.

No document overflow or header overflow in the final checks. Tablet layouts use two columns where space permits; mobile uses one column, a larger scannable QR, wrapping backup grids and contained horizontal table scrolling. Mobile menu, Escape behavior, device-tab arrow keys, labels, focus states and dialogs were exercised.

## 14. Bugs fixed

- Inactive enrollment now has a distinct pending key; active replacement cannot silently disable the current authenticator.
- Replayable re-enrollment and unrestricted factor guesses were closed.
- Stale device indexes no longer revoke the wrong record or return false success.
- Existing role/reset controls now have actual backend behavior and validation.
- Previous unsupported/demo method states and local-only user state fallbacks were removed.
- Recovery exports now contain actual site/account/date context and only current unused values.
- Broken/missing QR or secure-storage states provide useful recovery guidance instead of a blank QR or false “connected” state.
- The new root retains both shared and page-specific container names so the established mobile header works.
- Removed the unused copied heading helper and consolidated repeated base CSS rules after visual refinement.

## 15. Dashboard regression

HTTP 200, correct active navigation, native toolbar/sidebar, no document overflow and no browser console errors. Dashboard view, CSS, JS, provider and shared icon sprite are byte-for-byte unchanged from the pre-task copies.

## 16. Login Protection regression

HTTP 200, correct active navigation, native toolbar/sidebar, no document overflow and no browser console errors. Login view, CSS, JS, provider, login service and shared settings service are byte-for-byte unchanged. The existing custom login route also completed an actual password → TOTP challenge → WordPress login sequence.

File Integrity, Hardening, Activity Log, Pro and Settings navigation destinations returned HTTP 200 and rendered the plugin app; none was redesigned.

## 17. Limitations

- Passkey, email-factor and SMS-factor registration/verification are unavailable and clearly represented as such.
- Native WordPress chrome, actual data, the established shared illustration and honest empty/unavailable states differ from the reference's populated examples; visual equivalence is close rather than pixel exact.
- Older device and backup-generation timestamps cannot be reconstructed.
- Counters have a short cache; rebuilding exact state across very large user populations was not benchmarked at production scale.
- Ten existing coding-standard warnings remain in changed legacy classes (required hook arguments, a pre-existing parameter name, local asset reads and unrelated legacy SQL). Changed/new PHP has zero coding-standard errors.
- Existing WordPress/WooCommerce `shop_order_placehold` capability notices appeared during fixture/user deletion. Final page-load checks did not introduce plugin PHP notices. Interim missing-stylesheet warnings while the page was being built were resolved once the stylesheet was created and are not present in final page checks.

## 18. Tests and cleanup

- Final integration suite: **42 tests, 230 assertions, all passed**, covering TwoFactorPageTest, SecurityTest, UiBackendTest, ReleaseTest, DashboardDataTest, LoginProtectionTest and LifecycleTest.
- Browser enrollment checks: real QR/manual key match; copy; pending regeneration; invalid code rejection; valid enrollment; active-secret concealment; ten real backups; individual/all copy; clean export; replacement set; username/role/status filters; unavailable passkey state; confirmed authenticator rotation.
- Browser policy/authorization checks: 25-row pagination and next page; actual device records; malformed/stale ID rejection; explicit active-rotation confirmation; rejection of another user's enrollment; invalid roles/toggle values; actual custom-role saving; low-privilege self-service and cross-user denial; restored test preferences; invalid nonce 403; negative target ID rejection.
- Confirmed admin reset and verified removal of sessions, pending registration, backup codes and remembered devices while retaining requirements. Saved admin-reset restrictions were also tested.
- Actual native login verified password-stage challenge, hidden password during challenge, valid TOTP completion and remembered-device creation when permitted.
- PHP syntax checks passed for all seven changed/new PHP/test files; JavaScript syntax passed; coding standards: zero errors, ten existing warnings.
- Browser regression checks for all three Pro screens and other navigation destinations passed without console errors. Deliberately invalid security requests returned expected 400/403/409 responses.
- Temporary reviewer/member accounts, sessions, custom role and their test records were removed. Genuine users and current settings were preserved. Review tools, credentials and temporary screenshots stayed outside the plugin; no fixture or dependency package was shipped.

## Assessment /10

These are engineering assessments, not independent certification or fabricated perfect scores.

| Area | Score | Basis |
| --- | ---: | --- |
| Visual match | 8.5 | Reference hierarchy, components and density; native chrome, established art and real state vary. |
| UI/UX | 9 | Confirmed changes, useful empty/error states, real controls and keyboard behavior. |
| Responsiveness | 9 | All requested widths/resize sequences; contained table scrolling and decoded mobile QR. |
| TOTP | 9 | Verified native login/enrollment/rotation, replay protection and account throttling. |
| Passkeys | 0 | WebAuthn service is not implemented; accurately shown unavailable. |
| Recovery | 9 | Actual one-use backups, invalidation, copying and safe exports; email/SMS absent. |
| Functionality | 8.5 | Implemented methods and management pass; unsupported factors remain unavailable. |
| Security | 9 | Targeted ownership, nonce, crypto, replay, throttle and reset tests; no formal external audit. |
| Performance | 8.5 | Paged queries, bounded metadata batches, short invalidated counter cache; no large-site benchmark. |
| Code quality | 9 | Scoped UI, safe provider, meaningful tests and zero standard errors; legacy warnings retained. |
