# Enterprise configuration and recovery

New remote services are opt-in. Version remains 1.1.0; additive database schema is 1.6.0. Back up files and database before deployment.

## Controls and authorization

Settings contains reputation credentials, alert delivery, Datadog shipping, privacy, licensing, signed feeds and the optional setup checklist, inside existing cards. Login Protection contains country/reputation enforcement. Firewall contains inspection mode and additional rules. File Integrity retains its scheduler and gains signature status/update controls. Disclosures start collapsed. The checklist saves progress and links to existing configuration; it does not automatically apply policies or promise a measured two-minute setup.

New settings require the current password and a current TOTP or unused backup code when enrolled. Restores, deletion of recovery copies, baseline acceptance and settings import require a session/password/IP-bound, one-use proof valid for120seconds. WordPress nonces remain CSRF tokens, not one-use authorizations. On multisite, plugin management requires manage_network_options; owner-bound 2FA self-service remains available. Tables/options remain per-site. No network-wide licensing or policy database is invented. Actual multisite installation, new-site lifecycle and global user-factor/encryption behavior require acceptance testing before deployment.

## Recovery and enforcement

Add `define( 'GWQSH_DISABLE_ENTERPRISE', true );` before WordPress loads in wp-config.php to bypass country/reputation restrictions and the expanded WAF layer. Existing login protection, legacy IP blocks and authentication continue. Correct the policy and remove the constant. Keep a trusted administrator IP/CIDR in the existing allowlist before restrictive enforcement.

Country restrictions require the existing geolocation consent switch. Unknown locations follow the configured policy; verified administrators bypass unknown-country denial. Public login entry paths remain reachable; country enforcement follows successful password authentication. Known denied countries may still restrict administrators. VPNs, NAT and attribution errors limit accuracy.

Cloudflare headers require configured trusted peers AND verified official ranges. Select Cloudflare proxy mode and refresh ranges explicitly. Daily refresh follows configuration; ranges older than eight days are rejected. X-Forwarded-For retains its trusted-chain parser. Arbitrary forwarded headers are never authoritative.

AbuseIPDB lookup and blocking are separate opt-ins. Only public IPs are looked up in background, up to ten newly queued lookups/minute. Valid scores cache for one hour; failures for five minutes. Uncached/outage results are never fabricated or synchronously fetched during login. Valid cached scores at the configured threshold may deny access; trusted IPs take precedence. This does not provide an independently operated distributed reputation network.

The expanded WAF is WordPress-layer inspection. Additional rules start report-only. Authenticated traffic and raw JSON/XML bodies are not comprehensively inspected. Capacity/contention may make optional intelligence unavailable; authentication rate-counter failures fail closed. State is bounded at5,000 ordinary rows plus coordination leases. This cannot replace an upstream firewall or hosting-level resource controls.

## Delivery and credentials

Slack accepts only HTTPS hooks.slack.com/services webhooks. Datadog supports the US/EU HTTPS Logs intake. Email requires an existing administrator recipient and functioning wp_mail transport. Credentials use the existing encrypted storage, are nonautoloaded and excluded from exports. Blank fields keep secrets; Revoke removes them. Losing encryption keys/salts requires the existing crypto recovery procedure.

Only minimized event metadata is projected: event ID/name/category/severity/time/site hash, and optionally anonymized IP/account. Passwords, OTPs, session material, authorization headers, raw bodies and diagnostic details are excluded. Queue tests show enqueue success separately from delivery success. Review delivery audit counts and failure codes.

Workers claim up to five events, use an eight-second loop budget and five-second HTTP timeout, retry up to five times with backoff, and retain local audit evidence on failure. One in-flight request may extend the loop budget. Queue capacity is1,000; terminal records may be evicted at capacity, and new deliveries are rejected if pending work fills it. Fixed-window deduplication coalesces repeated events. A crash after remote acceptance can cause at-least-once delivery: receivers should deduplicate by site_id/event_id. Configure reliable WordPress cron on low-traffic sites. Live remote deliveries were not exercised during development.

## Signed feeds

No publisher service, private key or purported official signatures are bundled. Obtain an official HTTPS feed and provision `GWQSH_SIGNATURE_FEED_URL` plus trusted base64 Ed25519 `GWQSH_SIGNATURE_PUBLIC_KEY` in wp-config.php. Sodium is required. Enable updates in Settings. The daily WP-Cron update reads exact signed JSON bytes and base64 detached response header `X-GWQSH-Ed25519`.

Schema: integer schema=1, increasing integer version, integer created_at/expires_at UTC timestamps, signatures array. Records contain unique id (letters/digits/underscore/dot/hyphen, max64), type sha256/literal, string value, integer score40..100, scopes from Core/Plugin/Theme/Uploads. SHA256 is lowercase64hex; literal length8..256 without NUL. Feed max1MiB/2,000 entries; expiry max90days. Regex/executable entries are rejected. Reserializing JSON invalidates its signature.

Transport, signature, schema and version failures retain the last verified database. Expired signed rules stop matching; local heuristics continue. Hash exclusions suppress only signed rules. Matches provide evidence, not automatic permission to delete. Publisher rotation requires a trusted constant deployment and higher feed version. Previous verified data is retained for recovery; no unauthenticated downgrade endpoint exists. Publisher infrastructure, signing-key management, revocation and feed quality remain release dependencies.

## Provider contracts

- `gwqsh_reputation_provider`: GWQSH_Reputation_Provider::lookup(IP), returning integer score0..100 and categories from brute_force/spam/scanner/hostile, or WP_Error.
- `gwqsh_delivery_provider`: GWQSH_Delivery_Provider::deliver(minimized event), returning true/WP_Error for the selected channel.
- `gwqsh_license_provider`: GWQSH_License_Provider activate/deactivate/refresh(token, hashed site ID), returning authenticated state active/inactive/expired/renewal and integer expires_at, or WP_Error. No licensing server, entitlement policy or activation limit is assumed. Providers must implement authenticated HTTPS, anti-replay and site binding. Expiry/outages never disable protection.

Adapters are trusted installed PHP. Custom providers must enforce their own destination/credential safeguards; the bundled fixed-host HTTP policy cannot constrain arbitrary third-party PHP.

## Privacy and rollback

WordPress privacy callbacks page account-attributed audit records100at a time. Erasure anonymizes identity/IP/details while retaining event/time, scrubs queued account projections and clears last-country metadata. Authentication factors remain intact and exports never expose secrets. Remote collector retention, unattributed/IP-only records, IP-block history and scan/quarantine evidence require separate operator procedures. This is not a blanket compliance certification. IP anonymization affects newly recorded/projected logs, not the IP used for enforcement. Queue retention is1..30days; local audit retention retains existing controls.

Deactivation clears enterprise jobs and retains data. Uninstall removes data only with existing explicit deletion consent. Roll back code together with a matching database backup; do not use destructive uninstall as rollback. New tables are additive and existing options/tables are not renamed.

Protocol references checked: [WordPress nonces](https://developer.wordpress.org/apis/security/nonces/), [safe HTTP](https://developer.wordpress.org/reference/functions/wp_safe_remote_post/), [AbuseIPDB](https://docs.abuseipdb.com/#check-endpoint), [Cloudflare ranges](https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/), [Slack](https://api.slack.com/incoming-webhooks), [Datadog](https://docs.datadoghq.com/api/latest/logs/).
