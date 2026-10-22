# Security benchmark matrix — v1.3.0-rc.6 (2026-10-22)

Rules for reading this table: a score is only raised by *executed* evidence in
this checkout. Architectural code that is not reachable from a hook scores no
higher than the reachable replacement. 10/10 is an engineering target, not a
result.

| Dimension | Score | Executed evidence | What caps the score |
| --- | --- | --- | --- |
| WAF and exploit protection | **7.5** | 40 attack samples detected across SQLi/XSS/traversal/LFI/RCE/SSRF/object-injection; 33 benign samples allowed; policy gates verified (24 assertions) | lexical detectors only; no pre-WordPress layer; no independent exploit corpus; unknown production FP rate |
| Bot and IP defences | **6.0** | 16 sensitive-file probes detected / 20 ordinary paths allowed; hold logic; CIDR + IPv6 + forwarded-chain spoof tests (23 assertions) | no edge/DDoS protection, no live IP reputation, no country-blocking validation |
| Malware detection | **5.5** | synthetic corpus: 8/8 malicious PHP flagged, 10/10 benign PHP clean, uploads/oversize handling verified; two new token-level rules | corpus is hand-written, not representative; production false-positive rate and scan cost unmeasured |
| Vulnerability intelligence | **4.0** | signed-advisory client + scoped patch evaluation code path | no trust anchor, no feed, no CVE ingestion |
| Virtual patching | **4.0** | `match()`/`evaluate()` wired into firewall with approval gate | production patch list empty; no verified exploit-condition testing |
| Threat intelligence | **3.0** | client-side verification design documented | no publisher, no keys, no rotation/replay test in this session |
| Authentication | **6.5** | TOTP replay rejection (4), WebAuthn origin/type/challenge/counter (9) assertions | WebAuthn runtime missing from checkout; no browser flow; no SMS provider |
| File integrity | **5.0** | scheduling/baseline code reachable | not run against a live site |
| Cleanup / quarantine | **5.0** | quarantine + operation-token flow reachable | no restore round trip executed |
| Backup / recovery | **3.5** | backup engine + staged-import trait reachable | no restore/cutover/rollback test |
| Monitoring / alerting | **5.5** | durable queue + fixed-destination transport verified by inspection and SSRF tests | no live email/Slack delivery test |
| Performance | **5.5** | bounded work measured (§PERFORMANCE-BENCHMARK) | WASM timings only; no production p50/p95 |
| Compatibility | **4.0** | lint + tests on PHP 8.4.1 | no WP/WooCommerce/Gutenberg/multisite/browser run; no PHP 8.0–8.3 matrix |
| Release security | **5.5** | version/db-version discipline, unsigned assets documented, no secrets in repo | vendor assets gitignored; no PHPCS/PHPStan/Plugin Check/composer audit |

Weighted overall (equal weights across 14 dimensions): **5.2 / 10**.

## Evidence index

* `docs/evidence/phpunit-results.json` — 130 assertions, 128 passed, 0 failed, 2 skipped
* `docs/evidence/lint.json` — 102 files, 0 syntax failures
* `docs/WAF-VALIDATION.md`, `docs/TEST-EVIDENCE.md`, `docs/ENGINE-INTEGRATION-AUDIT.md`

## Score-inflation guards

* Unwired engine classes score nothing (enforced by
  `tests/cases/100-integration-manifest.php`).
* Cloud/managed services are scored as *external dependency*, never as delivered
  capability.
* Synthetic corpora are labelled synthetic everywhere they appear.
