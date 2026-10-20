# Threat intelligence

Existing malware/advisory feeds are data-only Ed25519 packages: bounded download → exact-byte verification → strict schema/time/trust checks → serialized activation → health/audit state. Private signing keys never belong in this plugin. Malware packages support bounded SHA-256 and literal signatures, not downloaded PHP, regex or YARA execution. Advisory packages carry explicit component identity, version ranges and narrowly scoped predicates. Production feed URLs/trust must be configured independently by the operator.

The new common verify_ed25519 guard catches Throwable from native Sodium or WordPress's Sodium compatibility layer. A valid-length signature with a noncanonical scalar previously threw in the available XAMPP fallback. Both feed services now return a verification error and retain their last verified state.

Regression checks cover valid signing, changed message bytes, replay, expiry, rejected regex entries, stale rollback requests, signed rollback, retained high-water version after rollback, revoked local trust, transport failure and corrupted HTTP signatures. Test keys are generated in memory and never persisted. A rollback re-verifies previous bytes with current trust and validity windows. Failure preserves current data; it does not authorize an expired or revoked package.

Health reports last attempt, installed version, verification and expiry times. Existing admin feed controls remain in their existing sections. AbuseIPDB has a bounded opt-in adapter and encrypted API key storage; nested category values now fail validation. Live provider quotas, results and commercial feed operation were not tested. VirusTotal, NVD and Patchstack ingestion pipelines are outstanding. Unsigned upstream data must be reviewed/versioned/signed by an authorized publisher before local activation; no provider is fabricated.

Reproduce declared bundled-package advisory screening with `composer audit --working-dir=tools/dependency-audit --locked`. No runtime Composer installation is required. This metadata does not verify that vendored source is byte-identical to upstream.
