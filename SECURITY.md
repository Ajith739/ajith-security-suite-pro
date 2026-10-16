# Gracewell Security Suite Pro security notes

## Custom login recovery

Save the private recovery URL displayed in Login Protection before enabling a custom login URL. It grants temporary access to the normal WordPress login form and does not bypass a password or two-factor authentication. Changing the custom login URL rotates the recovery link. An administrator with server access can define `GWQSH_DISABLE_LOGIN_URL` as `true` in `wp-config.php` if the custom route stops working.

## Trusted proxies

By default, the plugin uses a validated `REMOTE_ADDR` and ignores forwarded headers. To trust a proxy, set `GWQSH_TRUSTED_PROXIES` in `wp-config.php` to an array of the proxy's exact IP addresses and enable proxy handling in Settings. Use only addresses controlled by your infrastructure.

## Two-factor data

TOTP secrets and unused backup-code display copies use authenticated encryption with a key derived from WordPress salts (Sodium secretbox or AES-256-GCM). Changing salts can require re-enrollment or intentional backup-code regeneration. Verification uses one-way salted HMAC-SHA256 hashes. Consumption atomically removes the hash and encrypted display copy, retaining only a used marker; regeneration replaces the entire set. Only the owning authenticated user receives displayable codes. Other-user status lists contain counts only.

Legacy plaintext backups are migrated to encrypted display copies and hashes without losing unused codes. Existing hash-only records remain valid but cannot be reconstructed; the interface explains that intentional regeneration is needed to obtain displayable values. No codes are regenerated on refresh.

2FA enforcement follows each user's verified enrollment, without a global 2FA switch or dependency on plugin master status. Required users with incomplete enrollment can access their own setup page until they verify an authenticator code. Password verification issues a five-minute, IP-bound random challenge for the second step. Security Suite Pro sends no emails; native WordPress recovery emails remain intact.

## File scanning and Early Guardian

The existing File Integrity interfaces now use a local layered analyzer, configured
WordPress roots, dedicated MU coverage, SHA-256 change evidence and bounded resumable
scans. Version 1.1.0 of the database schema adds nullable evidence without deleting
existing data. Core checksum unavailability does not disable local inspection.

A standalone early MU Guardian preserves originals and replaces only explicit
high-confidence malicious shapes with harmless stubs. Alphabetical loading cannot
guarantee precedence over filesystem attackers. Guardian installation, failure,
removal, quarantine retention, bounded coverage and false-positive policy are
specified in [the engine security documentation](docs/MALWARE-ENGINE.md).

Direct native filesystem operations are intentional for early independence and
atomic sibling replacement. Suppressed native warnings are paired with inspected
return values and failure state, keeping permission errors from breaking requests.
WPCS warnings remain visible; they are not globally suppressed. `var_export` emits
a safely quoted installation constant rather than debug output; the fixed
`error_log` message contains no exception text or source data. Native ZipArchive
property spelling has a narrowly justified coding-standard exception.

Core diffs still require a checksum-verified official baseline and bounded escaped
source. Findings store rule IDs and hashes rather than secrets or raw snippets.

## External services

Core checksum verification and core file restoration contact WordPress.org. All admin scripts, Three.js and the QR library are bundled locally. System fonts are used; opening an admin page does not load fonts or executable scripts from a third-party CDN. No plugin telemetry is sent by the new security services.


## Plugin Check review

The 1.0.0 production ZIP excludes test suites, Composer development dependencies, build tools, PHPUnit caches and configuration files. Its static Plugin Check run has no errors. Remaining warnings concern direct database queries, caching, trusted SQL identifiers and schema creation. Custom table identifiers come only from the validated WordPress prefix and fixed table suffixes; values are prepared or passed to WordPress database methods. Dynamic activity WHERE fragments and sort directions are internally allowlisted. `%i` identifier placeholders are deliberately not used because WordPress 5.3 lacks them.

Fresh lockout, replay, factor-consumption and activity queries are deliberately not cached. Schema changes are restricted to the plugin's own installation tables. AJAX dispatch checks the request nonce and capability before routing; private handlers that read POST also check their nonce. Authentication hooks use WordPress-verified credentials and unguessable expiring challenges; URL routing, author blocking and page selection do not mutate settings. Upgrade hooks run after WordPress core has authorized the operation. These analyzer warnings remain visible for reviewer inspection rather than being suppressed across whole files.

## Development-prefix migration

The canonical directory, bootstrap and text domain are `gracewell-security-suite-pro`. Pro replaces the released Free edition; the active editions cannot run simultaneously. Stored gwqsh_ keys and security payloads are retained. Free site-salt and prior Pro auth-salt ciphertext remain readable. New recovery-code hashes use the site-salt scheme; both earlier verifier formats remain valid until consumed. Keep data removal disabled before deleting the inactive Free plugin. Public declarations, AJAX/nonces, database tables, options, transients, user metadata and cron hooks use `GWQSH_`/`gwqsh_`. A one-time migration renames legacy tables and stored keys without decrypting or modifying payloads; existing current keys take precedence. Conflicting populated tables stop the upgrade rather than overwrite data. Security state is migrated before authentication hooks initialize. Legacy encrypted `gqs1` payloads, trusted-device cookies, recovery bookmarks and in-flight factor input names remain verifiable. Old AJAX actions are not exposed. Legacy `GQS_DISABLE_LOGIN_URL` and `GQS_TRUSTED_PROXIES` constants remain supported; prefer the new `GWQSH_` names. Previously quarantined files remain in their original private storage and are included in intentional uninstall cleanup.

Custom login routes follow WordPress permalink configuration: `/slug/` with pretty permalinks, `/index.php/slug/` with index permalinks, or `/?gwqsh_login=slug` with plain permalinks. The displayed/copied URL and native form action use the same route. No server rewrite configuration is changed by the plugin.
