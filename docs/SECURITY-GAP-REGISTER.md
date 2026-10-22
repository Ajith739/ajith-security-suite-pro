# Security gap register — updated 2026-10-22 (v1.3.0-rc.6)

Status vocabulary: **Fixed** (code + regression test), **Partial** (works with
limits), **Open** (not addressed), **External** (needs a third party),
**Not comparable** (not possible in a PHP plugin).

| ID | Priority | Gap | Status | Evidence |
| --- | --- | --- | --- | --- |
| WAF-1 | **P1** | Credential-named parameters (`password`, `pwd`, `log`, `token`, `session`, `code`, `secret`, `nonce`, nested credential objects) were an inspection blind spot: `?password=' OR 1=1-- -` bypassed the firewall. | **Fixed** | `tests/cases/010-waf-corpus.php` → `waf-credential-keys`; `GWQSH_Firewall::evidence()`/`collect()` now return `credential_values` screened by injection rules only, never logged |
| WAF-2 | **P1** | Single-segment path traversal (`../wp-config.php`, `%2e%2e%2f…`) not correlated. | **Fixed** | `GWQSH_Firewall::traversal()`; corpus `dot dot slash x1`, `encoded traversal` now match |
| WAF-3 | **P2** | Quoted/`LIKE` SQL tautologies, comment-obfuscated `UNION/**/SELECT`, `/*!50000UNION*/`, `WAITFOR DELAY`, nested `SLEEP()` missed. | **Fixed** | `sql_high_confidence()`; 9-sample obfuscation corpus passes |
| WAF-4 | **P2** | Serialized object nested inside serialized arrays not detected. | **Fixed** | `serialized_object()`; corpus case `php object b` |
| WAF-5 | **P2** | No rule for executable PHP in request data (webshell/dropper attempt). | **Fixed (report-first)** | New `GWQSH-1017`, `action: report`; blocking requires `enforce_new` |
| WAF-6 | **P3** | Heuristics flag some legitimate prose (`sleep(n)`, `or 1 = 1`, quoted equality, `;cat`). | **Documented** | `tests/cases/090-false-positives.php` asserts the flagging; mitigations = report mode, path exclusions, IP allowlist |
| WAF-7 | **P2** | WAF cannot inspect an encrypted/compressed body, an oversized body, or a body PHP discarded (`post_max_size`). | **Partial (honest)** | These produce `inspection_budget_exceeded` / `unsupported_request_format` / `parsing_error` states and a "Firewall inspection incomplete" audit event; no false "safe" claim |
| WAF-8 | **P2** | No request inspection at all before WordPress loads (no early-loading PHP WAF / auto_prepend_file). | **Open** | Opt-in server configuration is deliberately not modified by the plugin |
| INT-1 | **P1** | Eight namespaced engine classes are dead code; capability claims based on them would be false. | **Documented + guarded** | `docs/engine-manifest.json`, `tests/cases/100-integration-manifest.php` (fails on drift) |
| INT-2 | **P2** | Duplicate implementations of replay guard, SSRF validation, scanner, feed manager, DB remediator, DB restore. | **Open** | Deletion recommended in a dedicated cleanup change; active path documented per engine |
| AUTH-1 | **P1** | `includes/vendor/webauthn/` is gitignored and absent from this checkout, so passkeys are unavailable in a clean clone (feature gate degrades safely). | **Open (packaging)** | `GWQSH_Passkeys::available()` returns false; `docs/RELEASE-READINESS.md` blocker |
| AUTH-2 | **P2** | Passkey/TOTP browser flows not executed in this session. | **Open (test coverage)** | `docs/AUTHENTICATION-VALIDATION.md` |
| UI-1 | **P3** | `assets/vendor/three/three.module.js` is gitignored; hero bird animation degrades. | **Open (packaging)** | `assets/js/hero-birds.js` dynamic import is guarded |
| SCAN-1 | **P2** | Malware engine not benchmarked against a **representative** corpus; production false-positive rate and scan cost unknown. | **Partial** | `tests/cases/110-malware-analyzer.php`: 8/8 hand-written malicious flagged, 10/10 benign clean (synthetic only) |
| SCAN-3 | **P2** | Remote PHP include (`include("http://…")`) scored 0 despite being a dropper pattern. | **Fixed** | `remote_include` token-level rule; corpus case `remote include` |
| SCAN-4 | **P2** | Obfuscated callable assembly (`$f = "sys"."tem"; $f($_POST)`) scored 0. | **Fixed** | `obfuscated_callable` rule limited to dangerous resolved names |
| SCAN-2 | **P2** | Namespaced `Gracewell_Malware_Scanner` duplicate unused. | **Open** | See INT-1 |
| VULN-1 | **P2** | No operator trust anchor / signed advisory feed; virtual patches are data-only and unused in production until configured. | **External** | `docs/VULNERABILITY-PATCHING.md`, `docs/THREAT-INTELLIGENCE.md` |
| VULN-2 | **P2** | No vendor CVE/advisory ingestion pipeline; core checksum integrity relies on WordPress.org. | **External** | Same |
| REC-1 | **P1** | Full-site disaster recovery (filesystem + cutover + rollback) not validated end-to-end. | **Open** | `docs/RECOVERY-VALIDATION.md` |
| OPS-1 | **P2** | No live test of email/Slack delivery, scheduled reports, or multisite network policy. | **External/Open** | `docs/REPORTING.md` |
| SEC-1 | **P3** | `GWQSH_Settings::forwarded_ip()` computes an unused `$peers` array. | **Open (cosmetic)** | Cleanup candidate |
| SEC-2 | **P3** | No PHPCS/PHPStan/Plugin Check run (toolchain and Composer manifest absent). | **Open** | `docs/RELEASE-READINESS.md` |

## Regression rule

Each **Fixed** row must keep a matching assertion in `tests/`. Deleting or
weakening a test to make a change pass is prohibited by `AGENTS.md` §2.2.
