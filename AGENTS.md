# AGENTS.md — authoritative working rules for Gracewell Security Suite Pro

This file is authoritative for any human or automated contributor. If a request
conflicts with this file, this file wins and the conflict must be reported.

## 1. Repository identity

| Item | Value (verified in this checkout) |
| --- | --- |
| Plugin | Gracewell Security Suite Pro |
| Main file | `gracewell-security-suite-pro.php` |
| Version | `1.3.0-rc.6` (`GWQSH_VERSION`, plugin header, `readme.txt` stable tag) |
| Database version | `1.6.1` (`GWQSH_DB_VERSION`, unchanged) |
| PHP | 8.0+ required; tested here on 8.4.1 (WASM) only |
| WordPress | 5.3+ required; no runtime WP test was executed in this session |
| Prefix | `GWQSH_` classes, `gwqsh_` options/tables/meta |
| Namespaced code | `Gracewell\SecurityPro\*` under `includes/{waf,scanner,auth,alerts,intelligence,vulnerabilities,cleanup,recovery}/` |
| Licence | GPL-2.0-or-later |

There is no `Free` plugin inside this repository. Do not create one, and do not
edit distribution metadata that belongs to it.

## 2. Safety rules

1. Never delete, rename or move the repository root or `.git`.
2. Never remove a security control to make a test pass.
3. Never claim a capability that is not reachable from a WordPress hook. The
   integration manifest `docs/engine-manifest.json` is machine-enforced by
   `tests/cases/100-integration-manifest.php`.
4. Never persist secrets, raw request payloads, passwords, TOTP seeds or full
   credential material in logs, options or evidence files.
5. Never introduce a network destination that a visitor can choose. Outbound
   calls go through `GWQSH_Secure_HTTP` with a fixed host/path.
6. Never fabricate test results, benchmark numbers, vendor comparisons,
   certification, or operator involvement.
7. No cloud WAF, managed cleanup or threat-intelligence network may be described
   as operating. This repository ships local engines plus *optional* signed-feed
   clients whose trust anchors must be supplied by the site operator.
8. Preserve the UI: dashboard, hero, navigation, footer, bird animation,
   typography, colours, dark mode, responsive layout, spot illustrations and the
   bottom-right notifications are not to be redesigned. The File Integrity
   scheduling popup stays as-is.
9. Preserve Free-to-Pro migration and existing user records. Schema changes
   require an explicit migration and a version bump of `GWQSH_DB_VERSION`.

## 3. Change protocol

1. Read this file, `docs/ENGINE-INTEGRATION-AUDIT.md` and
   `docs/CONTINUOUS-SECURITY-PROGRESS.md`.
2. Reproduce or add a failing regression test before changing behaviour
   (`tests/cases/*.php`).
3. Make the smallest coherent change inside the existing architecture. Reuse
   `GWQSH_*` services; do not add a parallel engine, table, cron worker or hook.
4. Run `node tests/tools/php-wasm-runner.mjs` (or
   `php tests/run-tests.php --verbose` when a PHP binary exists) and keep
   `docs/evidence/*.json` in sync.
5. Update the documents listed in section 5 with real results only.
6. Commit in logical increments. Never push to `main`; open a pull request from
   the working branch.

## 4. Testing contract

| Command | Purpose |
| --- | --- |
| `php tests/lint.php .` | Token-parser syntax lint of every PHP file |
| `php tests/run-tests.php --verbose` | 130 isolated assertions against real plugin source |
| `node tests/tools/php-wasm-runner.mjs` | Same, inside a WASM PHP runtime when no PHP binary exists |

Skipped checks must stay recorded as skipped. Anything requiring a real
WordPress install, browser, DNS, sodium or a provider account is listed as
**not run**, never as passed.

## 5. Documentation set

Maintained: `docs/security-progress.json`, `docs/SECURITY-GAP-REGISTER.md`,
`docs/CONTINUOUS-SECURITY-PROGRESS.md`, `docs/SECURITY-BENCHMARK-MATRIX.md`,
`docs/TEST-EVIDENCE.md`, `docs/REMAINING-WORK.md`, `docs/WORDFENCE-HEAD-TO-HEAD.md`,
`docs/FULL-PREMIUM-FEATURE-MATRIX.md`, `docs/ENGINE-INTEGRATION-AUDIT.md`,
`docs/WAF-VALIDATION.md`, `docs/MALWARE-SCANNER-VALIDATION.md`,
`docs/THREAT-INTELLIGENCE.md`, `docs/VULNERABILITY-PATCHING.md`,
`docs/RECOVERY-VALIDATION.md`, `docs/AUTHENTICATION-VALIDATION.md`,
`docs/PERFORMANCE-BENCHMARK.md`, `docs/RELEASE-READINESS.md`.

## 6. Authoritative scorecard (evidence-based, 2026-10-22)

Scores are capped by what was executed **in this checkout**. "Not verified" is a
legitimate score component, and 10/10 is an aspiration, not a claim.

| Dimension | Score | Basis |
| --- | --- | --- |
| WAF request inspection (local) | 7.5/10 | Bounded parsers for GET/POST/JSON/multipart/XML/REST; 40-sample attack corpus detected, 19-sample benign corpus allowed; no independent exploit corpus or production traffic measurement |
| Bot / abusive-request defence | 6.0/10 | Sensitive-file probes, holds, rate limiting and CIDR/trusted-proxy tests pass; no edge/DDoS protection, no live IP reputation |
| Malware detection | 5.5/10 | Synthetic corpus: 8/8 malicious PHP flagged, 10/10 benign clean, uploads/oversize states verified; representative corpus and production false-positive rate still unknown |
| Vulnerability intelligence / virtual patching | 4.0/10 | Signed-advisory client and scoped patch evaluation exist; no operator trust anchor, no vendor feed, no verified exploit corpus |
| Authentication | 6.5/10 | TOTP replay guards and WebAuthn ceremony validation are tested in isolation; bundled WebAuthn runtime is missing from this checkout, so passkeys are unavailable here |
| File integrity / cleanup | 5.0/10 | Scheduled scans, quarantine and baseline tooling exist; not exercised against live WordPress in this session |
| Backup / recovery | 3.5/10 | Backup engine plus staged import trait exist; full restore not validated end-to-end |
| Security operations (logs, alerts) | 5.5/10 | Audit log, durable queue and fixed-destination delivery; no live provider test, no scheduled-report validation |
| Hardening | 6.0/10 | Reversible settings with real hooks; server-level effects depend on the host |
| Premium infrastructure | 3.0/10 | Signed-feed client code only; no publisher, keys, rotation or monitoring operated here |
| Performance | 5.5/10 | Bounded work (sub-millisecond typical in-harness); no production p50/p95 latency measurement |
| Compatibility | 4.0/10 | PHP 8.4 WASM lint/tests only; no WooCommerce, Gutenberg, multisite or browser run |
| Release security | 5.5/10 | Version/db-version discipline, provenance docs, no secrets in repo; vendor assets missing from version control |

Overall earned score for this checkout: **5.2/10** — a bounded, tested local
security suite with honest gaps, not a Wordfence-Premium equivalent.

## 7. Open blockers (must stay visible in release notes)

1. `includes/vendor/webauthn/` and `assets/vendor/three/` are excluded by
   `.gitignore`; passkeys and the hero animation therefore degrade in a clean
   checkout. Release packaging must ship them.
2. No WordPress integration run, WooCommerce checkout test, multisite test,
   browser passkey test or production latency measurement exists in this
   session's evidence.
3. No production threat-intelligence publisher, trusted public key, provider
   credential or licence authority is configured.
4. Full-site disaster recovery and broad database remediation remain unvalidated.
5. Nine namespaced engine classes exist; eight are unwired duplicates of active
   `GWQSH_*` services (see the integration audit).
