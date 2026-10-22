# Authentication validation — 2026-10-22

## Executed (13 assertions, all passing)

`tests/cases/060-auth-guard.php`, against `Gracewell\SecurityPro\Auth\Gracewell_Auth_Guard`
and the WordPress stub user-meta store:

| Assertion | Result |
| --- | --- |
| First TOTP use in a 30 s window accepted | pass |
| Same window replayed rejected | pass |
| Older window rejected | pass |
| Newer window accepted | pass |
| Replay state is per user | pass |
| WebAuthn valid assertion accepted | pass |
| Origin mismatch rejected (`https://evil.test`) | pass |
| Wrong ceremony type (`webauthn.create` for an assertion) rejected | pass |
| Challenge mismatch rejected | pass |
| Cloned-authenticator counter regression rejected | pass |
| Malformed `clientDataJSON` rejected | pass |
| Zero-counter authenticators remain usable | pass |
| Trailing-slash origin normalised | pass |

## Production path (what actually protects a site)

| Control | Implementation | Verified here? |
| --- | --- | --- |
| TOTP replay guard | `GWQSH_Two_Factor::consume_totp()` — compare-and-swap on `gwqsh_2fa_last_slice` | Logic read; **not executed** (needs `$wpdb`/user meta in a real install) |
| Passkey ceremony validation | bundled `WebAuthn` verifier via `GWQSH_Passkeys::verifier()` | **Cannot run**: `includes/vendor/webauthn/` is absent from this checkout |
| Login lockouts / escalation | `GWQSH_Login_Protection` | Not executed |
| Backup codes | hashed, one-use, HMAC-tagged | Not executed |
| Email / SMS recovery | `GWQSH_Recovery` (Twilio adapter) | Not executed; no provider credentials |
| Session / app-password containment | `GWQSH_Incident_Recovery` | Not executed |

Important: the guarded class `Gracewell_Auth_Guard` is **not wired** into the
production path (see `docs/ENGINE-INTEGRATION-AUDIT.md`). The assertion results
above demonstrate that the guard logic is correct; they are not evidence that the
plugin's login flow uses it.

## Blocking defect

`includes/vendor/webauthn/` is excluded by `.gitignore` and absent, so
`GWQSH_Passkeys::available()` is false on a clean checkout and passkey enrolment
and login are unavailable. This is a packaging blocker, not a design flaw.

## Not validated

Browser passkey registration/authentication against a real authenticator, TOTP
enrolment UI, remembered-device flow, recovery code UX, alternative WordPress
authentication entry points (XML-RPC, application passwords, WooCommerce login),
and forced-2FA-by-role enforcement.
