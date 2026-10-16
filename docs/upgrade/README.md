# Security upgrade documents (October 2026)

Read these in order:

1. **[PHASE-0-AUDIT.md](PHASE-0-AUDIT.md)** — reproducible baseline of the plugin as it
   stood, the feature-by-feature audit matrix, the confirmed defects with evidence, the
   residual risk register, and an explicit statement of what testing does *not* establish.
2. **[PHASE-1-3-REPORT.md](PHASE-1-3-REPORT.md)** — every code change made in this session,
   the security self-review of the new database scanner, the test results (baseline vs
   final), the evidence-based 100-point scorecard (44/100), administrator operating notes
   and the recommended next phases.

3. **[PLAN-PHASE-2.md](PLAN-PHASE-2.md)** — the increment that followed: the database-scan
   card in the Firewall & Cleanup screen and bounded inspection of authenticated request
   payloads. Contains the verified outcome, including the double-escaping defect the jsdom
   harness caught.

Related existing documents: `../MALWARE-ENGINE.md` (file analysis engine and budgets),
`../enterprise/ARCHITECTURE.md`, `../enterprise/OPERATIONS.md`, `../TESTING.md`
(historical verification notes), `../../SECURITY.md`.

**Honesty rules used throughout:** a feature is only described as verified when a command in
this repository produced the evidence; provider-dependent capabilities are marked as
requiring configuration; skipped or environment-blocked tests are named, never silently
counted as passing.
