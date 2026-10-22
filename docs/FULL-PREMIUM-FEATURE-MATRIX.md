# Full premium capability matrix — v1.3.0-rc.6 (2026-10-22)

Status codes:

* **TESTED** — implemented, integrated, and covered by an executed assertion in `tests/`.
* **IMPL** — implemented and reachable from a WordPress hook; not exercised in this environment.
* **PARTIAL** — works with documented limits.
* **MISSING** — not implemented.
* **EXTERNAL** — requires a third-party service, credential or human operator.
* **N/A** — not possible inside a normal PHP plugin (or deliberately out of scope).

"Not verified anywhere in this document" means exactly that; no vendor feature was
assumed to exist because a comparison screenshot showed it.

## A. Firewall and attack prevention

| Feature | Status | Location / limit |
| --- | --- | --- |
| Active web application firewall | TESTED | `GWQSH_Firewall::inspect()` on `init` prio 2; 40 attack samples blocked |
| SQL injection protection | TESTED | `sql_high_confidence()` + `extended_sql()`; lexical only |
| Reflected/stored XSS defence | PARTIAL | Request-side detection TESTED (`xss_high_confidence()`); stored XSS is not inspected by the WAF |
| Path traversal | TESTED | `traversal()` incl. single `../`, encoded, Windows |
| File inclusion | TESTED | wrapper + sensitive-path correlation |
| Suspicious upload protection | PARTIAL | filename/metadata rules TESTED via `upload_evidence()`; file *content* is not scanned by the WAF |
| REST/AJAX inspection | TESTED (parsers), PARTIAL (routing) | `inspect_rest()` + parser assertions; no live REST round trip |
| XML-RPC abuse protection | IMPL | `xmlrpc_methods`, `xmlrpc_enabled`, pingback header removal |
| Authenticated request inspection | IMPL (defaults report-only) | `rollout()` verified by assertions |
| Exploit-specific rules | TESTED | `GWQSH-1001…1021`; metadata in `includes/waf/rules.php` |
| Early-loading PHP WAF (before WP) | MISSING | Opt-in server config intentionally not modified |
| Host-level sensitive-file rules | PARTIAL | Bot Shield path rules TESTED; real `.env`/`.git` blocking is the web server's job (N/A for PHP) |
| Rate limiting | TESTED | `check_rate_limit()` counters; `waf-rate` in firewall; no concurrency test |
| Virtual patch integration | PARTIAL | firewall calls `GWQSH_Vulnerabilities::match()`; no production patch list |

## B. Bot and abusive request defence

| Feature | Status | Notes |
| --- | --- | --- |
| Brute-force login protection | IMPL | `GWQSH_Login_Protection` lockouts, escalation |
| Credential stuffing controls | TESTED (counter), IMPL (enforcement) | `check_credential_stuffing()`; in-memory counter only in this class |
| Enumeration protection | IMPL | `block_author_scan`, REST user restriction |
| Sensitive-file probe detection | TESTED | 16 probes / 20 ordinary paths |
| Bot Shield integration | TESTED | `path_rule()` plus `can_enforce()` gating |
| Temporary automatic IP holds | IMPL | `record_probe()`/`held_rule()`; requires block mode opt-in |
| IP reputation | EXTERNAL | AbuseIPDB adapter, key required |
| Manual IP blocking | IMPL | `GWQSH_IP_Blocks` |
| CIDR handling | TESTED | IPv4/IPv6, boundary and malformed cases |
| Country restrictions | IMPL | `GWQSH_Country_Access`; requires geo lookups |
| Shared-IP/NAT safety | PARTIAL | allowlist + trusted proxies TESTED; no NAT heuristics |
| Trusted reverse-proxy handling | TESTED | spoof-resistant chain walk (23 assertions) |
| Bot event analysis | PARTIAL | events recorded in the activity log; no analytics engine |

## C. Malware and integrity

| Feature | Status | Notes |
| --- | --- | --- |
| Quick / full / deep scan tiers | IMPL | `GWQSH_Scan_Engine` scopes and batching; not benchmarked |
| Scheduled scanning | IMPL | WP-Cron hooks; no reliability test |
| Core file integrity | IMPL | WordPress.org checksums |
| Plugin/theme integrity | IMPL | checksum + baseline diff |
| MU-plugin and drop-in scanning | IMPL | advisory inventory incl. MU files |
| Uploads inspection | PARTIAL | pattern-based; binary content is heuristically examined |
| Signature matching | IMPL | signed feed client; no feed configured |
| Context-aware PHP analysis | IMPL | token analysis in `GWQSH_Malware_Analyzer` |
| Known malicious hashes | IMPL | hash matching against configured feed |
| Backdoor/webshell indicators | IMPL | heuristics |
| Persistence indicators | PARTIAL | option/cron review tooling exists; not validated |
| Malicious redirects | PARTIAL | detectable via content heuristics only |
| Accurate coverage / skipped-file reporting | IMPL | coverage metadata in scan state |

## D. Vulnerability intelligence

| Feature | Status | Notes |
| --- | --- | --- |
| Core/plugin/theme vulnerability monitoring | PARTIAL | signed advisory client; no feed/trust anchor configured |
| Installed-version checks | IMPL | `vulnerabilities::inventory()` |
| Canonical product identification | IMPL | `component_id()`/provenance checks |
| CVE/advisory feeds | EXTERNAL | operator must supply a signed feed |
| Vulnerability-specific virtual patches | IMPL | scoped, data-only predicates |
| Safe automatic rule updates | IMPL | staged verify → activate → rollback |
| Revocation and rollback | IMPL | rollback/expiry logic; not exercised here |
| Outdated/abandoned component warnings | PARTIAL | version comparison; abandonment requires directory data (EXTERNAL) |

## E. Authentication

| Feature | Status | Notes |
| --- | --- | --- |
| TOTP | IMPL | `GWQSH_Two_Factor`; replay guard TESTED in isolation |
| Passkeys/WebAuthn | PARTIAL | bundled runtime **absent from this checkout**; ceremony validation TESTED |
| Backup codes | IMPL | hashed one-use codes |
| Email recovery | IMPL | `GWQSH_Recovery` |
| SMS recovery | EXTERNAL | Twilio adapter untested |
| Forced 2FA by role | IMPL | per-role policy |
| Session inventory / revocation | IMPL | `GWQSH_Incident_Recovery` |
| Application-password monitoring | IMPL | containment actions |
| Admin creation / privilege escalation alerts | IMPL | activity events `New administrator account`, `User role changed` |
| Emergency administrator recovery | IMPL | recovery centre flows |
| Enforcement across access paths | PARTIAL | XML-RPC/app-password paths documented but not tested end to end |

## F. Malware remediation

| Feature | Status | Notes |
| --- | --- | --- |
| Safe file quarantine | IMPL | `GWQSH_Quarantine_Manager` + operation token |
| Trusted-source file repair | IMPL | re-download of core/plugin files by checksum |
| Core restoration | IMPL | checksum-based |
| Plugin/theme repair | IMPL | checksum-based |
| Database malware scanning | IMPL | `GWQSH_Database_Scanner` |
| Selected database cleanup | IMPL | preview → ticket → apply → rollback |
| Suspicious option remediation | PARTIAL | dependent on operator review |
| Redirect cleanup | PARTIAL | no automated rewrite |
| Cron persistence analysis | IMPL | review tooling |
| Unauthorized administrator investigation | IMPL | recovery centre |
| Incident containment | IMPL | session/app-password revocation; Guardian detection-only |
| Post-repair verification / reinfection monitoring | PARTIAL | rescan available; no scheduled verification loop validated |

## G. Backup and disaster recovery

| Feature | Status | Notes |
| --- | --- | --- |
| Encrypted backup manifests | PARTIAL | manifest hashing; encryption depends on `GWQSH_Crypto` |
| Database backup | IMPL | chunked job with resume |
| Custom prefix / third-party tables / HPOS / multisite tables | PARTIAL | prefix-aware; HPOS and multisite table coverage not validated |
| Filesystem backup | MISSING | database only |
| Verified import / restoration | PARTIAL | staged import + row-count verification (trait) |
| Dry-run restoration | PARTIAL | verification step exists |
| Recoverable cutover / rollback | PARTIAL | design present; not executed |
| Configuration restoration | PARTIAL | settings export/import |
| Coordinated full-site recovery | MISSING | files not covered |
| Interrupted-recovery testing | MISSING | not tested |

## H. Security operations

| Feature | Status | Notes |
| --- | --- | --- |
| Audit log / firewall event log | IMPL | `gwqsh_activity_log`, site-timezone display |
| Local WordPress timestamps | IMPL | `GWQSH_Time::format()` |
| Realtime-style admin notices | PARTIAL | polled notices; no websockets (N/A) |
| Durable alert queue | IMPL | `gwqsh_delivery_queue` |
| Email alerts | IMPL (unconfigured) | not delivered in tests |
| Slack integration | IMPL (fixed destination) | host/path pinned |
| SSRF-safe webhooks | TESTED | rejection cases executed |
| Retention policies | IMPL | pruning jobs |
| Security diagnostics | IMPL | Security Doctor (settings + WP-CLI) |
| Security status / agency reports | IMPL | HTML/JSON/CSV reports |
| Multisite network administration | PARTIAL | network WAF policy code; not tested |
| License-safe product updates | PARTIAL | `Update URI` header; no licence server |
| Scheduled reporting | IMPL | cron-driven; not delivered in tests |

## I. Server and WordPress hardening

| Feature | Status | Notes |
| --- | --- | --- |
| XML-RPC controls | IMPL | reversible toggles |
| Directory listing prevention | IMPL | `.htaccess`/`web.config`/nginx guidance + writes where permitted |
| File editor restriction | IMPL | `DISALLOW_FILE_EDIT` + capability removal |
| Upload execution restrictions | IMPL | rules written to uploads dir, reversibility checked |
| Sensitive file permissions | PARTIAL | diagnostic only; host owns permissions |
| Security headers / CSP | IMPL | `send_headers`, CSP level config |
| REST permissions | IMPL | endpoint and user restriction |
| User enumeration controls | IMPL | author scan + REST |
| Debug exposure checks | IMPL | Security Doctor diagnostics |
| Reversible server recommendations | IMPL | evidence + rollback of written rules |
| PHP configuration diagnostics | IMPL | Security Doctor |

## J. Premium infrastructure

| Feature | Status | Notes |
| --- | --- | --- |
| Signed WAF rule delivery | MISSING | rules are local source data by design |
| Signed malware signatures / vulnerability feeds / virtual patches | IMPL client, EXTERNAL service | Ed25519 verification, expiry, anti-downgrade, rollback |
| IP reputation integration | EXTERNAL | AbuseIPDB adapter |
| Key rotation | EXTERNAL | operator-supplied trust anchors |
| Feed expiration / replay protection | IMPL | verified in code; not executed here (no sodium) |
| Emergency rule revocation / last-known-good rollback | IMPL | rollback path exists |
| Provider monitoring | IMPL | feed health state |
| Clear licence/subscription boundaries | PARTIAL | licence option exists, no authority |

## K. Performance and compatibility

| Feature | Status | Notes |
| --- | --- | --- |
| WAF request overhead | TESTED (in-harness) | ≈397 µs typical in WASM; no production measurement |
| Scan memory usage | MISSING | not measured |
| Background job reliability | MISSING | not measured |
| Cache correctness | PARTIAL | counters bypass object cache; no cache-plugin test |
| WooCommerce checkout compatibility | MISSING | not tested (REST body budget is coded) |
| Gutenberg save compatibility | MISSING | authored-field exclusion coded, not tested |
| REST/AJAX compatibility | PARTIAL | parsers tested, endpoints not |
| Multisite compatibility | MISSING | not tested |
| PHP version compatibility | PARTIAL | PHP 8.4 only; 8.0–8.3 untested |
| WordPress version compatibility | MISSING | no WP runtime in this environment |
| Mobile/responsive admin UI | N/A (unchanged) | preserved from the existing design; not re-verified |
| Dark mode | N/A (unchanged) | preserved; not re-verified |

## Summary counts

| Status | Count |
| --- | --- |
| TESTED | 17 |
| IMPL | 43 |
| PARTIAL | 27 |
| MISSING | 10 |
| EXTERNAL | 7 |
| N/A / preserved | 4 |
