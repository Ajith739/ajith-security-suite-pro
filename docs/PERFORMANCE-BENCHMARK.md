# Measured performance scope

See evidence/integration.json for measured whole-corpus WAF/analyzer runtime, total suite time and PHP peak allocation on a fresh WordPress 6.8.3/XAMPP PHP 8.2.4 site. These are single-process regression timings, not request latency/TTFB, frontend browser timing, throughput or results for 10000–50000 files. The full process peak includes WordPress and all test setup; it is not a scanner-only allocation. The requested 50MB absolute request budget is not established.

Existing file/database scans use bounded resumable work, stored cursors and owned leases. Reports perform one grouped aggregate and a 200-row detail query over existing indexed timestamps; calendar trends are at most 366 days. Counts cover the retained date window and can still be expensive on large logs. No global PHP memory_limit is lowered, because that can crash unrelated WordPress work.

Outstanding: repeatable baseline-vs-candidate TTFB, 100k-row scans, 50k-file scans, object-cache configurations, storage failure, peak concurrent workers and multisite scaling. No unmeasured percentage improvement is claimed.
