# Performance benchmark — 2026-10-22

## Method

`tests/cases/080-performance.php` times the real evaluation path
(`GWQSH_Firewall::match()` + `GWQSH_Firewall::advanced()`) inside a **PHP 8.4.1
WebAssembly runtime on a shared sandbox CPU**. WASM is materially slower than
PHP-FPM with opcache, so the numbers are useful for *relative regression
tracking* and for spotting algorithmic blow-ups — they are **not** production
latency and no p50/p95 claim is made.

## Measured (in-harness)

| Case | Work per request | Time |
| --- | --- | --- |
| Typical anonymous GET | 5 short parameters, one evidence walk each for `match()`/`advanced()` | ≈397 µs |
| Worst-case budgeted values | two values ≈15 KB each (truncated to 2048 bytes by the evidence bound) | ≈1400 µs |
| Nested cart-like payload | 120 nested values under a WooCommerce REST path | ≈1020 µs |

Threat bounds enforced in code (not just measured):

* evidence: 128 nodes, 16 KiB total, 2048 bytes per value, depth 8, 10 ms deadline;
* multipart parser: 1 MiB body cap, 128 parts, 8 KiB headers, 70-byte boundary;
* REST JSON: endpoint-specific caps (16 KiB anonymous → 1 MiB authenticated editor);
* regexes: bounded quantifiers, `(*LIMIT_MATCH)`/`(*LIMIT_DEPTH)` on the extended
  SQL matcher, values truncated to 2048 bytes before matching.

## Regression thresholds in the suite

| Assertion | Threshold |
| --- | --- |
| typical request | < 8000 µs |
| two ~30 KB values | < 200000 µs |
| 120 nested values | < 60000 µs |

Thresholds are deliberately loose for WASM; they exist to catch order-of-magnitude
regressions (e.g. accidental nested-loop re-walking of evidence).

## Not measured

* production p50/p95 latency, TTFB impact, opcache/JIT effects;
* memory ceilings for scans and backup jobs;
* concurrency (parallel requests, counter contention on `gwqsh_security_state`);
* database query counts per request (`GWQSH_Enterprise_Store::hit()` performs an
  atomic UPDATE plus occasional admission SELECTs — this is the main DB cost per
  evaluated request and was not profiled).
