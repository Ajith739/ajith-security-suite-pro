=== Gracewell Security Suite Pro ===
Contributors: gracewell89
Tags: security, firewall, two factor authentication, passkeys, file integrity
Requires at least: 5.3
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.3.0-rc.5
License: GPL-2.0-or-later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

WordPress security with a query firewall, passkeys, two-factor recovery, login rate limiting, scheduled integrity scans and clear audit logs.

== Description ==

Gracewell Security Suite Pro brings everyday WordPress security operations into one responsive administration workspace. Review recorded threats, manage visitor restrictions, protect accounts, schedule file inspection and investigate changes with a readable old/new comparison.

* Login attempt windows, temporary lockouts, repeat-lockout escalation and per-role protection controls.
* Custom login URL, configurable guest access, visitor IP allowlisting and explicit trusted reverse proxy IP/CIDR configuration.
* TOTP enrollment, encrypted authenticator secrets, hashed one-use backup codes and verified remembered devices.
* WebAuthn passkeys: register, rename, remove and sign in with a verified device or security key. Requires HTTPS or localhost and a compatible browser.
* Verified account email backup codes and SMS backup through configured Twilio or an extensible provider adapter, with expiry and resend/attempt limits.
* IPv4/IPv6 manual restrictions, temporary locks, permanent bans, notes, unblock actions and persistent management history.
* Scheduled quick/full integrity scans: hourly, twice daily, daily or weekly, selectable scopes and background run-now.
* Official WordPress core checksums, local suspicious-file inspection, trusted baselines, source differences, quarantine and restoration.
* WordPress hardening, CSP configuration and server application evidence.
* Paginated audit records, site-timezone displays, cached country attribution and geographic summaries of this site's retained denials.
* Light/dark administration, accessible notifications, illustrated empty states and responsive activity records.
* Module configuration, section resets and import/export with provider credentials excluded.

The scanner reports coverage limitations and suspicious patterns; it does not guarantee detection of every compromise. Country summaries describe this installation's records, not a global live intelligence feed. Country blocking and commercial licensing/renewal infrastructure are not advertised as implemented features.

== Installation ==

1. Back up WordPress and the database. Deactivate Free or the previous Pro edition first; keep data removal on uninstall disabled while upgrading.
2. Upload the gracewell-security-suite-pro ZIP in Plugins > Add New, or copy its folder into wp-content/plugins.
3. Activate Pro. Existing settings, logs and authenticator enrollment are preserved; upgrades add IP restriction history and query indexes.
4. Review Login Protection and Hardening. Save the private custom-login recovery link before enabling a custom URL.
5. Enroll an authenticator and save one-use backup codes. Register a passkey on a secure origin if desired.
6. Configure optional backup delivery and explicitly verify each recovery destination.
7. Choose scan scopes and frequency in File Integrity. For reliable low-traffic scheduling, trigger WP-Cron from a server scheduler.

== Frequently Asked Questions ==

= Can Free and Pro run together? =
No. Pro reuses the same security data and refuses activation alongside Free or the previous development edition. Deactivate the old edition without deleting its data. Keep the inactive edition until the upgrade is verified; disable data deletion before uninstalling it.

= What if I lose my authenticator? =
Use an unused backup code, a registered passkey or an explicitly enrolled email/SMS backup. Delivered backup codes are available after password verification. An authorized administrator can reset enrollment; the reset also revokes passkeys and enrolled recovery methods. Backup code regeneration invalidates the previous set. Store your codes safely.

= Are passkeys available on HTTP? =
HTTPS is required in production; localhost supports development. Private device keys stay on the authenticator, while the plugin stores public verification keys.

= How do I recover a forgotten custom login URL? =
Use the private recovery link saved from Login Protection, or define GWQSH_DISABLE_LOGIN_URL as true in wp-config.php. Recovery access still requires authentication. Pretty, index.php and plain permalink routes are supported.

= Which proxy headers are supported? =
CF-Connecting-IP, X-Forwarded-For, X-Real-IP and True-Client-IP. Explicitly enable a mode and configure trusted proxy IPs/CIDRs. Forwarded chains are walked from the trusted edge toward the nearest untrusted client.

= Are scans scheduled? =
Yes: hourly, twice daily, daily or weekly, with quick/full inspection and selectable scopes. Disabling removes the cron event. WP-Cron depends on traffic or a server trigger and does not guarantee an exact execution time.

= Does the scanner verify every plugin/theme against its publisher? =
No. Core uses official checksums. Other files use local baseline and suspicious-pattern analysis. Quick or limited-scope scans cannot establish a complete baseline. Size and coverage limitations remain visible.

= Which hardening features require server configuration? =
Uploads execution protection manages Apache .htaccess rules. Nginx and other servers require equivalent configuration. Test security headers and CSP with your site's integrations before enforcement.

= Does it require API keys? =
Local TOTP, passkey verification, QR generation and admin scripts do not need hosted services. WordPress.org supplies core files/checksums. Optional country attribution uses ipwho.is. SMS needs a provider account; email uses the site's configured mail delivery.

= What are the tested versions? =
The upgrade was tested on the local WordPress 7.1.3 / PHP 8.0.30 installation. PHP 8.0 is the runtime minimum for the bundled WebAuthn verifier. Consult the implementation report for the actual validation scope; minimum WordPress compatibility is not a promise that every historical version was tested.

== Screenshots ==

1. Dashboard with readable activity and recorded threat sources.
2. Access Controls with trusted proxies, visitor exceptions and role controls.
3. Authenticator setup, passkey management and verified backup methods.
4. Integrity findings, color-coded source review and scheduled scans.
5. Firewall denials with site-local times and cached attribution.
6. IP restrictions with expiry, reasons and history.
7. Hardening evidence, headers and CSP.
8. Module configuration and import/export in light/dark themes.

== Changelog ==

= 1.3.0-rc.5 (development candidate, staging only) =
* Merge enhanced bounded WAF multipart, XML and REST inspection with RC4 private-file probe shield.
* Restore policy-respecting XML-RPC restrictions, hardened malware file root containment and exact-password breach checks.
* Add permission-checked Security Doctor in settings and WP-CLI.
* Additional validation is required before production deployment; no commercial threat-intelligence service is included.


= 1.2.0-rc.1 =
* Fail closed on malformed Ed25519 signatures across native and WordPress Sodium implementations.
* Add separately approved report-first SQL correlations and structured local WAF metadata.
* Include MU-plugin inventory and advisory version checks; reject malformed reputation category arrays.
* Deprecate automatic Early Guardian source replacement; publish detections for confirmed administrator quarantine.
* Add protected retained-event HTML/JSON reports and WP-CLI report/inventory commands.
* Ship engineering validation evidence and documented open release blockers.


= 1.1.1 =
* Correct core advisory identifiers and prevent report-only AJAX heuristics from shadowing enforced virtual patches.
* Add verified malware-feed rollback, anti-replay state, overlapping verification keys and explicit expiry/update health.
* Restore the locked, namespace-scoped WebAuthn runtime in clean checkouts and release packages.
* Add verified account-session and selected application-password containment in the existing Recovery Center.
* Harden bounded configuration parsing and preserve exact password and signed-package bytes.
* Live intelligence still requires a real authorized provider. No production service or independent security certification is bundled.

= 1.1.0 =
* Add WebAuthn passkeys and password-bound email/SMS backup verification.
* Add persistent IPv4/IPv6 restrictions, history, scheduled scans and module configuration.
* Fix proxy selection, forwarding trust, site-time formatting and blocked-request attribution.
* Resume directory enumeration across batches, cache enrollment coverage and add query indexes.
* Improve responsive activity, event badges, illustrations, toasts, Access Controls and diff review.
* Bundle the MIT WebAuthn verifier; raise the PHP requirement to 8.0.

= 1.0.0 =
* Initial Pro release, Free-to-Pro encryption compatibility and activation safeguards.
* Login protection, TOTP, backup codes, remembered devices and manual integrity inspection.
* Source review, restoration, quarantine, WordPress hardening and audit logs.
* Responsive administration in light and dark themes.

== Upgrade Notice ==

= 1.1.0 =
Requires PHP 8.0+. Back up first. Historical SQL dates remain site-local. Optional country lookup and email/SMS backups require explicit configuration. Existing enrollment is preserved.

== External services ==

WordPress.org: official core checksums and original replacement files during scanning/restoration. https://wordpress.org/about/privacy/

ipwho.is: optional public IP attribution, disabled by default. Only public IPs are sent, without usernames, secrets or request bodies. Results are cached and lookups run in background. https://ipwhois.io/privacy https://ipwhois.io/terms

Twilio: optional SMS backup delivery. The destination number and verification message are sent to the configured account. Tokens are encrypted locally and omitted from exports. Provider charges may apply. https://www.twilio.com/en-us/legal/privacy https://www.twilio.com/en-us/legal/tos

WordPress mail: verification messages go to the account email through the site's mail system. Configure reliable delivery before relying on this method.
