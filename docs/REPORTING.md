# Retained-event security reports

Activity Log → Security Report downloads self-contained HTML using the currently applied activity filters. Existing CSV export is retained. The report contains retained matching totals by existing category, zero-filled calendar trends and at most 200 recent details, with shared credential redaction. Weekly buckets start Monday; the end date is inclusive in the site's timezone. Trailing averages include zero days and use up to seven available calendar days, not seven event rows. Historical severity/status are not fabricated.

Authenticated POST admin-post.php action=gwqsh_security_report requires a gwqsh_security_report nonce in _wpnonce; format is html or json. Shared activity filters include days, start/end, event, category, user, IP and search. The protected AJAX action gwqsh_action/subaction=security_report uses the existing gwqsh_nonce and administrative dispatch. There is no public endpoint.

Read-only command examples (select a real administrator):

```sh
wp gracewell report --user=1 --days=30 --format=json > /private/report.json
wp gracewell report --user=1 --start=2026-10-01 --end=2026-10-19 --interval=week --format=html > /private/report.html
wp gracewell inventory --user=1
```

Use your browser's print-to-PDF if needed; native TCPDF/PDF generation is not bundled or claimed. Retained history can be incomplete due to existing retention, and concurrent deletions can change data during the multi-query report. A maximum event ID excludes new inserts but is not a transactional snapshot.
