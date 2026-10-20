# Release readiness: 1.2.0-rc.1

Status: review candidate; the full premium-parity objective is not complete. No commercial detection, exploit-coverage or certification claim is authorized by these results.

Implemented: fail-closed Ed25519 verification across native Sodium and WordPress fallback; malformed reputation response validation; modular WAF metadata and separately approved SQL correlations; MU-plugin advisory inventory/version gating; native editor hardening constant; administrator-confirmed Guardian containment policy; protected HTML/JSON reports over the existing activity store; read-only WP-CLI report/inventory commands; reproducible packaging and regression evidence.

Release blockers:

- Representative real malware and exploit corpora, independent false-positive review, OWASP ZAP/WPScan and penetration testing have not run. Synthetic results are regression evidence only.
- No production signed malware/advisory publisher, provider credentials, authorized Patchstack/NVD mapping pipeline, VirusTotal integration, verified license authority or Twilio adapter was supplied. Existing AbuseIPDB code requires opt-in/key; it was not live-tested.
- General proposed-edit database malware cleanup/diff/rollback, full-site disaster recovery, network-level containment and general reinfection scheduling are not delivered here. Existing file quarantine/restore and limited contextual database baseline rollback remain available.
- Browser passkey enrollment/login, WooCommerce checkout, comprehensive UI screenshots, multiple PHP/WP versions, multisite runtime tests, concurrency stress and load/TTFB benchmarks remain outstanding.
- Plugin Check retains five baseline errors and now reports 57 warnings (baseline: 43). Its process exit code does not establish readiness. See SECURITY-AUDIT.md.
- No independent audit or certification took place. Do not invent an audit firm, report, score or approval.

Deployment checklist: verify artifact SHA-256; restore-test the private SQL/plugin backup in a disposable environment; review Guardian deprecation; review this source diff; validate real traffic in report mode; test authentication/checkout and recovery; review CSP using the existing hardening controls; validate each external service and data-sharing policy. Keep new SQL enforcement off until that site's compatibility review is approved. No schema version is changed and no legacy records are removed by this upgrade.
