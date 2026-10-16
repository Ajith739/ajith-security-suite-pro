// Database-scan card: renders against the real admin markup and drives the real controller.
//
// Requires jsdom plus a capture produced by tests/database-page-capture.php:
//   GWQSH_JSDOM=jsdom GWQSH_PAGE_DIR=<dir with page.html + data.json> node tests/jsdom-database-card.cjs
// Without them this exits with SKIP (non-zero only on a real failure), so it never blocks
// a checkout that has no WordPress runtime.
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert/strict');

const dir = process.env.GWQSH_PAGE_DIR;
let JSDOM;
try {
  ({ JSDOM } = require(process.env.GWQSH_JSDOM || 'jsdom'));
} catch (error) {
  console.log('SKIP - jsdom is not installed (' + error.code + ')');
  process.exit(0);
}
if (!dir || !fs.existsSync(path.join(dir, 'page.html')) || !fs.existsSync(path.join(dir, 'data.json'))) {
  console.log('SKIP - no captured page; run tests/database-page-capture.php first and set GWQSH_PAGE_DIR');
  process.exit(0);
}

const html = fs.readFileSync(path.join(dir, 'page.html'), 'utf8');
const payload = JSON.parse(fs.readFileSync(path.join(dir, 'data.json'), 'utf8'));
const controller = fs.readFileSync(path.join(__dirname, '..', 'assets/js/firewall-cleanup.js'), 'utf8');
(async () => {
const checks = [];
  const dom = new JSDOM(html, { runScripts: 'outside-only', pretendToBeVisual: true, url: 'https://example.invalid/wp-admin/admin.php?page=gracewell-security-suite-pro-firewall-cleanup' });
  const { window } = dom;

  const calls = [];
  const hostile = '<script>alert(1)</script><?php system($_GET["c"]); ?>';

  window.GWQSH = {
    esc: (value) =>
      String(value).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m])),
    toast: () => {},
    modal: () => {},
    confirm: (title, text, okLabel, fn) => { calls.push(['confirm', title]); if (fn) fn(); },
    ajax: async (subaction, data) => {
      calls.push(['ajax', subaction, data]);
      if (subaction === 'run_database_scan') {
        return {
          success: true,
          data: {
            scanned: true,
            baseline: 2,
            status_label: 'Limited coverage',
            coverage: 'Coverage was incomplete for: Administrator accounts vs approved baseline. Treat the result as partial, not as proof that the database is clean.',
            driver: 'sqlite',
            disclaimer: 'Database findings are evidence for review. Nothing is deleted or modified automatically.',
            report: {
              status: 'limited',
              duration_ms: 75,
              checks: { administrator_drift: { label: 'Administrator accounts vs approved baseline', rows: 2, limited: true } },
              findings: [
                { rule: 'GWQSH-3001', title: 'PHP code stored in site data', severity: 'Critical', confidence: 'High', table: 'wp_options', column: 'option_value', record: 'gwqsh_e2e_payload', excerpt: hostile, detail: 'Stored value contains a PHP open tag.', action: 'Review before changing anything.' },
              ],
            },
          },
        };
      }
      if (subaction === 'approve_admin_baseline') {
        return { success: true, data: { scanned: true, baseline: 3, status_label: 'Limited coverage', coverage: 'coverage', driver: 'sqlite', disclaimer: 'disclaimer', report: { status: 'limited', findings: [], checks: {} } } };
      }
      return { success: false, data: { message: 'unsupported in harness' } };
    },
  };
  window.GWQSH_PAGES = { 'file-integrity': 'page=file-integrity' };
  window.GWQSH_DATA = payload;
  window.GWQSH_PREFS = {};
  window.localStorage.clear();
  window.requestAnimationFrame = (fn) => fn();
  window.cancelAnimationFrame = () => {};

  window.eval(controller);
  checks.push('controller executed against the real rendered markup without throwing');

  const doc = window.document;
  const status = doc.querySelector('#qs-db-status');
  assert.equal(status.textContent.trim(), 'Never scanned', 'stored state renders as never scanned');
  checks.push('initial status renders from server data: ' + status.textContent.trim());

  assert.match(doc.querySelector('#qs-db-rows').textContent, /No database scan has been run yet/);
  checks.push('empty state explains that no scan has run');

  await doc.querySelector('#qs-db-run').click();
  await new Promise((resolve) => setTimeout(resolve, 10));

  assert.ok(calls.some((call) => call[0] === 'ajax' && call[1] === 'run_database_scan'), 'the card calls the run subaction');
  assert.equal(doc.querySelector('#qs-db-status').textContent.trim(), 'Limited coverage');
  checks.push('run_database_scan response re-renders the status badge');

  assert.match(doc.querySelector('#qs-db-coverage').textContent, /partial, not as proof/);
  checks.push('limited coverage is described as partial coverage');

  const rows = doc.querySelectorAll('#qs-db-rows tr');
  assert.equal(rows.length, 1);
  assert.match(rows[0].textContent, /GWQSH-3001/);
  assert.match(rows[0].textContent, /wp_options\.option_value/);
  assert.match(rows[0].textContent, /gwqsh_e2e_payload/);
  assert.equal(doc.querySelectorAll('#qs-db-rows script').length, 0, 'no script element may be created from stored evidence');
  assert.match(rows[0].textContent, /<script>alert\(1\)<\/script>/, 'the payload is shown as inert text');
  checks.push('findings render escaped evidence with no injected markup');

  assert.match(doc.querySelector('#qs-db-meta').textContent, /1 finding\(s\).*driver: sqlite.*limited checks: 1.*approved administrators: 2/);
  checks.push('meta line reports findings, driver, limited checks and baseline size');

  await doc.querySelector('#qs-db-baseline').click();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.ok(calls.some((call) => call[0] === 'confirm'), 'baseline approval asks for confirmation first');
  assert.ok(calls.some((call) => call[0] === 'ajax' && call[1] === 'approve_admin_baseline'), 'confirmation performs the approval');
  assert.match(doc.querySelector('#qs-db-meta').textContent, /approved administrators: 3/);
  checks.push('baseline approval is confirmed before it runs and refreshes the payload');

  assert.equal(doc.querySelectorAll('#qs-fw-log-rows tr').length > 0, true, 'the rest of the page still rendered');
  checks.push('existing firewall sections still render beside the new card');

  console.log(checks.map((line) => 'ok - ' + line).join('\n'));
  console.log(`\njsdom checks passed: ${checks.length}`);

})().catch((error) => { console.error('FAILED: ' + error.message); process.exit(1); });
