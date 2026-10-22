# Engine integration audit — 2026-10-22 (v1.3.0-rc.6)

Method: for each engine class, trace *UI → settings → capability check → input
validation → runtime hook → security decision → enforcement → audit log →
recovery*, then verify the class is referenced from production code. `UNWIRED`
below means no WordPress hook can reach the class; it therefore contributes **no**
runtime protection and must not be counted as a feature.

Machine enforcement: `tests/cases/100-integration-manifest.php` fails if a class
recorded as unwired becomes referenced, or if a class recorded as wired is not
referenced. Manifest: `docs/engine-manifest.json`.

## 1. Result matrix

| Engine class | Entry point in production | Hook | State |
| --- | --- | --- | --- |
| `GWQSH_Firewall` | `inspect()`, `inspect_rest()` | `init` (prio 2), `rest_pre_dispatch`, `xmlrpc_*`, `template_redirect` | **Active** |
| `GWQSH_Bot_Shield` | `path_rule()`/`record_probe()`/`held_rule()` from `GWQSH_Firewall::inspect()` | inherited | **Active** (block mode only) |
| `GWQSH_Enterprise_Store` | `hit()/get()/put()` counters and holds | used by firewall, login, geo | **Active** |
| `GWQSH_Login_Protection` | `authenticate`/`wp_login_failed` guards, allowlist, lockouts | authentication hooks | **Active** |
| `GWQSH_Two_Factor` | login interception, TOTP CAS replay guard, trusted devices | `authenticate`, `wp_login` | **Active** |
| `GWQSH_Passkeys` | enrolment/assertion handlers | `wp_ajax_*`, `login_form` | **Active only when the bundled WebAuthn runtime is present** |
| `GWQSH_Scan_Engine` + `GWQSH_Malware_Analyzer` | scheduled/manual scans, results table | WP-Cron + AJAX | **Active** |
| `GWQSH_File_Integrity` | scheduling, baselines, summaries | `init`, cron | **Active** |
| `GWQSH_Quarantine_Manager` | quarantine/restore with operation token | AJAX + admin | **Active** |
| `GWQSH_Vulnerabilities` | `match()` from firewall, `inspect_rest()`, inventory | `init`, cron `gwqsh_refresh_advisories` | **Active** (feed must be operator-approved) |
| `GWQSH_Signatures` | signed malware signature feed | `init`, cron | **Active client, no feed configured** |
| `GWQSH_Alert_Service` | durable queue + `gwqsh_deliver_alerts` | cron | **Active** (channels off by default) |
| `GWQSH_Secure_HTTP` | fixed-destination transport | called by alert/reputation/feeds | **Active** |
| `GWQSH_Backup_Engine` | database backup jobs | AJAX + cron | **Active** (file restore unvalidated) |
| `GWQSH_Hardening`/`GWQSH_Hardening_Rules` | reversible settings + hooks | `init`, `wp_headers`, filesystem | **Active** |
| `GWQSH_Guardian` | early MU guard file | `install()` on activation | **Detection only** (auto-replace deprecated) |
| `Gracewell\SecurityPro\WAF\Gracewell_WAF_Inspector` | bounded parser used by `GWQSH_Firewall` | inherited | **Active as parser only** |
| `Gracewell\SecurityPro\Auth\Gracewell_Auth_Guard` | — | — | **UNWIRED** (duplicate of `GWQSH_Two_Factor` CAS guard) |
| `Gracewell\SecurityPro\Alerts\Gracewell_SSRF_Safe_Dispatcher` | — | — | **UNWIRED** (duplicate of stricter `GWQSH_Secure_HTTP`) |
| `Gracewell\SecurityPro\Scanner\Gracewell_Malware_Scanner` | — | — | **UNWIRED** (duplicate of `GWQSH_Malware_Analyzer`) |
| `Gracewell\SecurityPro\Vulnerabilities\Gracewell_Virtual_Patch_Engine` | — | — | **UNWIRED** (duplicate of `GWQSH_Vulnerabilities`) |
| `Gracewell\SecurityPro\Intelligence\Gracewell_Signed_Feed_Verifier` | — | — | **UNWIRED** (duplicate of `GWQSH_Crypto::verify_ed25519` path) |
| `Gracewell\SecurityPro\Intelligence\Gracewell_Threat_Feed_Manager` | — | — | **UNWIRED** (duplicate of `GWQSH_Signatures`/`GWQSH_Vulnerabilities` staging) |
| `Gracewell\SecurityPro\Cleanup\Gracewell_DB_Malware_Remediator` | — | — | **UNWIRED** (duplicate of `GWQSH_Database_Remediation`) |
| `Gracewell\SecurityPro\Recovery\Gracewell_Safe_DB_Restore` | — | — | **UNWIRED** (duplicate of `GWQSH_Backup_Engine` + restore trait) |

Grep evidence (production files only, engine files excluded):

```
Gracewell_WAF_Inspector            => includes/class-gwqsh-firewall.php
Gracewell_Malware_Scanner          => UNWIRED
Gracewell_Virtual_Patch_Engine     => UNWIRED
Gracewell_Threat_Feed_Manager      => UNWIRED
Gracewell_Signed_Feed_Verifier     => UNWIRED
Gracewell_Auth_Guard               => UNWIRED
Gracewell_SSRF_Safe_Dispatcher     => UNWIRED
Gracewell_DB_Malware_Remediator    => UNWIRED
Gracewell_Safe_DB_Restore          => UNWIRED
```

## 2. Findings

| ID | Severity | Finding | Disposition |
| --- | --- | --- | --- |
| INT-1 | High (reporting integrity) | Eight namespaced "enterprise" engines are dead code. Any capability claim based on them is false. | Recorded in the manifest, guarded by a test, documented here. Deletion deferred: removing files needs an explicit owner decision because they are referenced by `THIRD-PARTY-NOTICES.md` review notes. |
| INT-2 | Medium | Duplicate replay/SSRF/scanner logic risks divergence over time (a fix in one copy does not reach the active path). | Active path documented per engine; test suite pins the active behaviour. Recommendation: delete the eight duplicates in a dedicated cleanup change. |
| INT-3 | Medium | `GWQSH_Firewall` evaluates the same request through `match()`, `advanced()` and `normalized_request()`, walking the evidence tree up to three times. | Reduced to one walk per collection in `advanced()` this session; the remaining extra pass is intrinsic to the review-first design and is bounded (16 KiB/128 nodes). |
| INT-4 | Low | `GWQSH_Settings::forwarded_ip()` computes `$peers` and never uses it. | Left in place (harmless); note for the next cleanup. |
| INT-5 | Info | Guardian source replacement is deprecated; only detection publishes findings. | Documented as detection-only; no auto-repair claim. |

## 3. What this audit does not prove

* That active engines behave correctly inside a real WordPress install — no WP
  runtime test ran in this session.
* That provider integrations (AbuseIPDB, Slack, Datadog, signed feeds) work; they
  are opt-in and unconfigured.
* That the UI exposes every setting reached by these hooks; UI wiring was read,
  not clicked through.
