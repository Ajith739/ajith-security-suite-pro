# Remaining work — v1.3.0-rc.6

## 1. Next three tasks (highest value first)

1. **Restore the locked vendor runtimes and gate releases on them.**
   `includes/vendor/webauthn/**` and `assets/vendor/three/three.module.js` are
   excluded by `.gitignore` and absent, so passkeys are unavailable and the hero
   animation degrades in a clean checkout. Add a packaging verification step that
   fails when either asset is missing from the release archive.
2. **Run the suite inside a disposable WordPress install.**
   Activation/deactivation, Free→Pro migration, settings persistence, a real WAF
   block on a front-end request, quarantine → restore round trip, database backup
   → staged import. This harness cannot prove any of that.
3. **Resolve the duplicate engines.**
   Either delete the eight unwired `Gracewell\SecurityPro\*` classes or wire the
   ones that add capability (there is none today — every one duplicates a live
   `GWQSH_*` service). The manifest test keeps the documentation honest either
   way; deletion removes maintenance risk.

## 2. Security work still open

| Area | Task |
| --- | --- |
| WAF | Pre-WordPress opt-in layer (documented, never auto-applied); compressed-body handling policy; production FP measurement on WooCommerce/Gutenberg/REST |
| Detection | Expand the corpus with independently sourced payloads (licensed for reuse); add regression samples for multipart filenames, XML-RPC multicall and JWT-shaped bodies |
| Auth | Browser passkey enrolment/login; TOTP UI flow; application-password inventory review; emergency admin recovery drill |
| Malware | Representative benign/malicious corpus benchmark; coverage accounting per scope; resumability under memory cap |
| Cleanup | End-to-end quarantine/repair/rollback with diff preview and rescan |
| Recovery | Full-site restore, cutover and rollback in a disposable environment, including custom prefixes, HPOS and multisite tables |
| Alerts | Live email/Slack delivery, retry/backoff behaviour, retention pruning |
| Hardening | Verify each reversible setting's actual server effect; document host responsibilities |
| Ops | WP-CLI report parity, scheduled agency reports, multisite policy inheritance |

## 2b. Completed since the previous checkpoint

* Settings validation, XML-RPC policy, advisory range boundaries and release
  metadata now have executed assertions (76 added).
* Release gate (`tests/tools/package-check.php`) covers version drift, require
  targets, secrets and dev artifacts; it correctly reports `blocked` because of
  the two missing vendor assets.

## 3. Toolchain still missing

PHPCS (WordPress ruleset), PHPStan (level ≥5), Plugin Check, `composer audit`
(no root manifest exists), secret scanning, JS syntax/lint for `assets/js`, and a
PHP 8.0/8.1/8.2/8.3 matrix. None of these ran; do not report them as passing.

## 4. External dependencies (cannot be completed inside the plugin)

* Signed threat-intelligence publisher, trusted public keys, rotation, revocation
  monitoring and replay protection exercised against a live service.
* Managed WAF/edge DDoS protection, malware clean-up crews, IP reputation
  network, CVE ingestion (NVD/Patchstack) and licensed rule feeds.
* SMS recovery provider credentials (Twilio adapter exists, untested).
* Slack/Datadog endpoints for live delivery tests.
