# Priority-ranked security gaps

| Priority | Finding | Status / evidence |
| --- | --- | --- |
| P1 | Noncanonical Ed25519 signature can throw through WP Sodium fallback and crash update jobs | Fixed by GWQSH_Crypto::verify_ed25519; corrupt-signature regression for both feed services |
| P1 | Early Guardian automatically replaces suspected MU files without per-operation administrator confirmation | Automatic replacement deprecated; detection publishes review findings. Legacy quarantine imports/restores retained |
| P1 | New SQL rule could inherit an old generic enforcement setting | Separate enforce_sql_extended approval defaults false; reporting cannot shadow an existing enforceable traversal rule |
| P2 | MU-plugin advisory coverage omitted from inventory and fresh version gating | Added distinct mu-plugin:filename.php identity, bounded filename grammar and current-header reads |
| P2 | Nested provider categories could trigger array conversion warnings | Reject non-string/oversized category arrays before set comparison |
| P2 | No shipped repeatable validation corpus | Guarded disposable-database suite and synthetic JSON fixtures added |
| P2 | No complete published retained-event report | Existing filters/redaction reused for aggregates, zero-filled trends and capped event detail; severity/status omissions disclosed |
| P2 | No production intelligence publisher or verified exploit corpus | Open: operator-supplied signing trust, source licensing, ingestion and testing required |
| P2 | Arbitrary database malware cleanup and full disaster recovery | Open: reviewed proposals, original-byte evidence, serialized-data safety and verified rollback required |
| P2 | Browser/multisite/load/independent testing | Open; no percentage guarantees |
| P3 | Plugin Check distribution/compatibility findings | Five pre-existing errors documented; 57 warnings need reviewer disposition |

WordPress admin_init is not a deprecated hook. Existing admin-only installation work remains there. File paths use canonical roots and symlink checks; sanitize_file_name alone would not prevent traversal. Fixed SQL identifiers remain fixed; values are prepared. No arbitrary SQL identifiers from the pasted examples are used.
