# Recovery validation and rollback

The integration suite creates an inert upload file and a real finding with its full SHA-256. Changing that file after the finding causes isolation to fail. Restoring the expected bytes allows actual quarantine, and restoring the quarantined artifact recovers exactly those bytes. Traversal, stream wrappers and a symlink escape are rejected. This validates one controlled round trip, not a zero-data-loss service guarantee or an entire disaster recovery system.

Early Guardian automatic replacement is deprecated in this candidate to satisfy per-operation administrator-confirmed cleanup. The generated module records a bounded review_required signal and leaves the MU source unchanged. Admin ingestion revalidates the current file's path/hash and detection before publishing it through existing File Integrity findings. The health sidecar retains the latest signal, not a complete forensic timeline; full scans provide broader findings. Detection alone cannot stop that MU file from loading. Existing manually confirmed quarantine/sentinel replacement and legacy quarantine import/restore remain available.

File workflow: inspect finding and diff → confirm isolation in the existing UI → the existing manager preserves/hash-verifies original bytes and ownership metadata before changing the live file → inspect quarantine → confirm restore with existing recent authorization. Keep filesystem access to the private quarantine directory and original site/plugin encryption material. Never delete retained evidence as part of upgrade.

Upgrade rollback: place the site into a controlled maintenance window using your normal host procedure; retain the current working copy; restore the backed-up plugin directory; restore its backed-up owned MU Guardian file if the previous behavior is intentionally desired. No schema change is introduced here. Restore the full SQL snapshot only when data rollback is intentionally needed, in an isolated restore test first; importing it into a working site overwrites later writes. Preserve original salts and private evidence storage. The pre-upgrade backup manifest supplies checksums. No blanket TRUNCATE/reinsert script is provided.

Whole-site restore drills, checksum-verified external package repair under failure, concurrency stress, reinfection scheduling and commercial loss metrics remain outstanding.

---

## Status at v1.3.0-rc.6 (2026-10-22)

Nothing in this file was executed in the current session. Environment: no MySQL,
no WordPress, so no backup was created, staged, imported, cut over or rolled back.
The recovery code paths (`GWQSH_Backup_Engine`, `includes/trait-gwqsh-database-restore.php`,
staged-table verification) were read, not run.

Consequences for scoring and claims:

* backup/restore capability is scored **3.5/10** (`docs/SECURITY-BENCHMARK-MATRIX.md`);
* filesystem backup, coordinated full-site recovery and interrupted-recovery
  testing are recorded as **missing** in `docs/FULL-PREMIUM-FEATURE-MATRIX.md` §G;
* no "guaranteed recovery" wording is permitted anywhere in the product or
  marketing material.

To validate: create a database backup, verify the manifest hash, stage-import
into disposable tables, compare row counts, perform the cutover, then roll back,
and finally repeat with an interrupted mid-import process.
