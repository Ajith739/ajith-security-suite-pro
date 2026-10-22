# Head-to-head positioning vs Wordfence (Free / Premium)

## Read this first

* No reproducible head-to-head test was run. Nothing in this document should be
  quoted as proof that Gracewell is better, equal or worse in independent testing.
* Vendor capabilities below are **public, widely documented product facts**, not
  results verified in this session. Treat them as claims to be re-checked against
  current vendor documentation before publication.
* Gracewell scores come from `docs/SECURITY-BENCHMARK-MATRIX.md` and are limited
  to what was executed in this checkout.
* Wordfence Premium is a commercial service with a threat-intelligence network,
  managed WAF rules and a support organisation. Gracewell is a local plugin. The
  comparison is therefore asymmetric by construction.

## Dimension-by-dimension

| Dimension | Gracewell (earned here) | Wordfence Free (public docs) | Wordfence Premium (public docs) | Honest verdict |
| --- | --- | --- | --- | --- |
| Local request inspection | 7.5 — 40 sample corpus, bounded parsers, policy gates | Signature/firewall rules in the plugin, extended WAF delayed-rule model | Same engine plus immediate premium rule updates | Gracewell is comparable in *mechanism* for a small reviewed rule set; far smaller coverage. No parity claim. |
| Rule/threat intelligence network | 3.0 — client only, no feed | Vendor-maintained feed including delayed rules | Real-time vendor feed, IP reputation network, threat intel team | **Wordfence clearly ahead.** Uncontestable without an operated service. |
| Managed WAF / edge DDoS | Not offered (N/A in a plugin) | Not offered in-plugin (server-level hardening only) | Optional cloud WAF/DDoS products | Wordfence ahead where the customer buys the service; both are local for the plugin layer. |
| Malware scanning | 5.0 — engine reachable, unbenchmarked | Signature + heuristic scanning with vendor signature updates | Same plus immediate signature updates | **Wordfence ahead** on signature breadth and measured operational history. |
| Vulnerability data | 4.0 — signed-client design, no feed | Vendor vulnerability database with alerts | Adds immediate virtual patching from that database | **Wordfence ahead**; Gracewell cannot match without a licensed feed. |
| Two-factor / passkeys | 6.5 — TOTP + WebAuthn code, runtime asset missing in checkout | TOTP (and premium options) | Extended authentication options | Roughly comparable in scope; **Gracewell currently ships broken in a clean clone** (missing vendor asset), so it cannot be rated ahead. |
| Login protection / lockouts | IMPL, CIDR/proxy logic tested | Yes | Yes | Comparable mechanism; no scale test on either side. |
| File integrity / repair | 5.0 — checksums + quarantine | Core/plugin/theme comparison, repair | Same | Comparable mechanism. Gracewell's quarantine/restore round trip was not executed. |
| Audit logging & alerting | 5.5 — durable queue, fixed destinations | Live traffic log, email alerts | Plus alerting/reporting extensions | Comparable locally; delivery untested here. |
| Backup / recovery | 3.5 — database only, unvalidated | Not a backup product | Not a backup product | Neither is a backup product; Gracewell's partial coverage must not be marketed as one. |
| Data residency / self-hosting | Local-only by default | Local plugin, vendor telemetry/feeds | Same | Gracewell's local-only default is a genuine differentiator for privacy-sensitive sites. |
| Support / SLA / certification | None | Community | Commercial | **Wordfence ahead**; no certification or SLA exists for Gracewell. |

## What would be required to claim superiority

1. An operated, signed intelligence service with a publisher, key rotation,
   revocation and monitoring — not a client library.
2. An independently selected exploit/malware corpus (not written by us) with
   published detection and false-positive rates for both products.
3. Production latency and load measurements on identical hosts.
4. An independent penetration test and a published methodology.
5. Vendor documentation review at a dated snapshot for every compared row.

Until then the correct statement is: *Gracewell is a local, auditable WordPress
security suite with a tested request-inspection core and clearly documented gaps;
it is not a Wordfence Premium equivalent.*
