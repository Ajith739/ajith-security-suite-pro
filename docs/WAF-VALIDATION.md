# WAF validation — v1.3.0-rc.6 (2026-10-22)

Scope: the **active** request-inspection path only —
`GWQSH_Firewall::init()` → `inspect()` (init prio 2) / `inspect_rest()`
(`rest_pre_dispatch`) → `match()`, `advanced()`, `normalized_request()`,
`GWQSH_Bot_Shield`, `GWQSH_Vulnerabilities::match()` → `decision()` →
`status_header` + `GWQSH_UI::error` or report-only audit.

## 1. What was executed

`node tests/tools/php-wasm-runner.mjs` on PHP 8.4.1 (WASM). Full results in
`docs/evidence/phpunit-results.json`.

| Corpus | Samples | Result |
| --- | --- | --- |
| SQL injection (tautology, union, information_schema, time/error/file, hex, char()) | 12 | 12 detected |
| SQL obfuscation (quoted/`LIKE` tautology, `UNION/**/SELECT`, `/*!50000UNION*/`, `WAITFOR DELAY`, nested `SLEEP`) | 9 | 9 detected |
| XSS (script, event handlers, `javascript:`, `srcdoc`, `animate onbegin`, uppercase handlers) | 14 | 14 detected |
| Path traversal (double, single, encoded, Windows, `....//`) | 5 | 5 detected |
| File inclusion (`php://`, `expect://`, `data://`, `/etc/passwd`, `/proc/self/environ`) | 5 | 5 detected |
| Command injection (`;cat`, `| id`, backtick, `$(…)`) | 4 | 4 detected |
| SSRF (169.254.169.254, localhost, 10/8, 127.0.0.1, gopher, GCP metadata) | 6 | 6 detected |
| PHP object injection (top-level and nested in arrays) | 2 | 2 detected |
| Credential-named parameters carrying attacks | 7 | 7 detected |
| **Benign traffic** (search text, quotes, URLs, JSON, HTML markup, versions, emails, CSS, Windows path, base64, admin URLs) | 19 | 19 allowed |
| Additional benign set (Gutenberg markup, WC cart JSON, serialized arrays, contract prose, price comparisons, emoji, plugin paths) | 14 | 14 allowed |

These are hand-written regression samples, **not** a statistically
representative exploit corpus, and they are not a Wordfence comparison.

## 2. Behaviour changes in this release

| Change | Why | Rollout control |
| --- | --- | --- |
| Credential-named values are inspected for injection | They were a complete bypass (`?password=' OR 1=1-- -` passed) | Same legacy blocking family as other values; no new setting |
| Single `../` segment flagged | Common traversal payload missed by the two-segment rule | Existing `traversal` toggle + WAF mode |
| Tautology / comment / time-based / error-based SQL families | Common evasion shapes missed | Legacy blocking family (`sql_high_confidence`) |
| Nested serialized objects flagged | Nested payloads missed | Existing generic rule family (`GWQSH-1009`, needs `enforce_new` to block) |
| `GWQSH-1017` executable PHP in request data | No rule existed | **Report-first**; blocking requires `enforce_new` |
| One evidence walk instead of two in `advanced()` | Reduced per-request CPU | None needed |

## 3. Policy semantics (unchanged and re-verified)

* Report/block precedence: a report-only match never shadows a blocking match
  (`waf-policy` assertions).
* `enforce_new` gates every generic rule; `GWQSH-1006` additionally needs
  `enforce_sql_extended` (24 assertions).
* Authenticated inspection defaults to `report`.
* Emergency recovery mode and WAF `disabled` short-circuit both entry points.
* Coverage gaps are reported as states (`inspection_budget_exceeded`,
  `parsing_error`, `unsupported_request_format`, `partially_inspected`) and emit
  a deduplicated "Firewall inspection incomplete" audit event — never a silent
  "clean" verdict.

## 4. Honest limitations

1. No inspection before WordPress loads; `auto_prepend_file`/server rules are
   deliberately not modified.
2. Encrypted, compressed or over-budget bodies are reported as partial coverage,
   not inspected.
3. The detector is lexical. It is not a SQL/HTML parser and cannot prove intent.
4. Five benign-looking shapes are flagged on purpose (§5).
5. No production traffic test: false-positive rates on real WooCommerce,
   Gutenberg and custom REST traffic remain unknown.
6. No independent pentest, OWASP ZAP or WPScan run; no claim of vendor parity.

## 5. Known aggressive detections

`sleep(n)` in prose, `or 1 = 1` in prose, quoted equality in prose, `<?php`
pasted into a form (report-only), `;cat /etc/...` in prose. Mitigations: report
mode, exact path exclusions, IP allowlist, approval gates.
