// Real local WordPress integration. Temporary fixture/account paths are supplied by the runner.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { chromium } = require(process.env.GWQSH_PLAYWRIGHT || 'playwright');
(async () => {
  const account = JSON.parse(fs.readFileSync(process.env.GWQSH_BROWSER_ACCOUNT, 'utf8'));
  const browser = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
  const page = await browser.newPage();
  const errors = [], checks = [];
  page.on('pageerror', e => errors.push(e.message));
  page.on('console', m => { if (m.type() === 'error' && !/favicon|status of (400|403|404|409)/.test(m.text())) errors.push(m.text()); });
  const check = (name, condition) => { assert.ok(condition, name); checks.push(name); console.log('PASS ' + name); };
  const refresh = async action => {
    const response = page.waitForResponse(r => r.url().includes('admin-ajax.php') && (r.request().postData() || '').includes('get_scan_data'), {timeout:120000});
    await action(); await response; await page.waitForTimeout(120);
  };
  const ajax = (op, params = {}) => page.evaluate(async ({ op, params }) => GWQSH.ajax(op, params), { op, params });
  const fixture = mode => {
    const r = spawnSync(process.env.GWQSH_PHP, [process.env.GWQSH_BROWSER_FIXTURE, mode], { encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
  };
  const close = async () => { const dialog = page.locator('.modal-bg').last(); await dialog.locator('[data-x]').click(); await page.waitForTimeout(200); };
  const confirm = async label => { await page.locator('.modal-f').last().getByRole('button', { name: label, exact: true }).click(); await page.waitForTimeout(700); };
  try {
    fixture('old');
    await page.goto(account.login);
    await page.locator('#user_login').fill(account.username); await page.locator('#user_pass').fill(account.password);
    await Promise.all([page.waitForURL('**/wp-admin/**'), page.locator('#wp-submit').click()]);
    const url = new URL('wp-admin/admin.php?page=gracewell-quietshield-file-integrity', account.base).href;
    await page.goto(url); await page.waitForTimeout(500);
    const initialQuarantine = await ajax('get_quarantine_list');
    check('quarantine contains fixture records only', Object.values(initialQuarantine.data.quarantine).every(item => (item.original || '').includes(account.marker)));
    await refresh(() => page.locator('#fSearch').fill(account.marker));
    for (const size of [10,20,30,50,100,250,500]) {
      await refresh(() => page.locator('#pageSize').selectOption(String(size)));
      check(`page size ${size}`, await page.locator('#fBody tr[data-id]').count() === size);
    }
    await refresh(() => page.locator('#pageSize').selectOption('20'));
    await refresh(() => page.locator('#fPager [data-p="3"]').click());
    check('page number navigation', (await page.locator('#fInfo').textContent()).startsWith('Showing 41–60'));
    await page.locator('#fBody .checkbox').first().check();
    check('partial selection is indeterminate', await page.locator('#checkAll').evaluate(e => e.indeterminate));
    await page.locator('#checkAll').check();
    check('select all current page only', await page.locator('#fBody .checkbox:checked').count() === 20);
    await page.locator('#bulkClear').click();
    check('clear selection clears header and toolbar', await page.locator('#checkAll').evaluate(e => !e.checked && !e.indeterminate) && await page.locator('#bulk').evaluate(e => e.classList.contains('hide')));
    await page.locator('#fBody .checkbox').first().check(); await page.locator('#bulkQuar').click();
    await refresh(() => confirm('Quarantine Selected'));
    check('mutation stays on page 3 at size 20', await page.locator('#pageSize').inputValue() === '20' && (await page.locator('#fInfo').textContent()).startsWith('Showing 41–60'));
    await page.locator('#showQuarantine').click();
    check('only quarantine panel visible', await page.locator('#quarantine').isVisible() && !(await page.locator('#results').isVisible()));
    check('quarantine list visible', await page.locator('#qBody tr[data-artifact]').count() >= 1);
    await page.locator('#qSelectAll').check();
    check('quarantine select all', await page.locator('#qBody .checkbox:checked').count() >= 1);
    await page.locator('#qClearSelection').click();
    check('quarantine clear selection', await page.locator('#qSelectAll').evaluate(e => !e.checked && !e.indeterminate));
    await page.locator('#qBody [data-q="restore_quarantine"]').first().click(); await refresh(() => confirm('Restore'));
    check('single restore updates quarantine', await page.locator('#qBody tr[data-artifact]').count() === 0);
    await page.locator('#showResults').click();
    const restoreIds = await page.locator('#fBody tr[data-id]').evaluateAll(rows => rows.slice(0, 2).map(r => r.dataset.id));
    await ajax('bulk_quarantine', {finding_ids: restoreIds.join(',')});
    await refresh(() => page.locator('#fSearch').fill(account.marker + ' '));
    await page.locator('#showQuarantine').click();
    await page.locator('#qSelectAll').check(); await page.locator('#qRestoreSelected').click(); await refresh(() => confirm('Restore Selected'));
    check('bulk restore updates quarantine immediately', await page.locator('#qBody tr[data-artifact]').count() === 0);
    await page.locator('#showResults').click();
    await refresh(() => page.locator('#fLoc').selectOption('Theme')); check('location filters', await page.locator('#fBody tr[data-id]').count() === 0);
    await refresh(() => page.locator('#fLoc').selectOption('Plugin'));
    await refresh(() => page.locator('#fSeverity').selectOption('Low')); check('severity filter reset page', (await page.locator('#fInfo').textContent()).startsWith('Showing 1–20'));
    await refresh(() => page.locator('#fSeverity').selectOption(''));
    await refresh(() => page.locator('#fSort').selectOption('path')); await refresh(() => page.locator('#fOrder').selectOption('ASC'));
    const paths = await page.locator('#fBody td.path').allTextContents(); check('server path sort', JSON.stringify(paths) === JSON.stringify([...paths].sort()));
    check('normal UI paths hide internal labels', paths.every(p => !p.includes('/@')));
    await refresh(() => page.locator('#fSearch').fill('review.php'));
    await page.locator('#fBody [data-more]').click(); await page.locator('.modal-f').last().getByRole('button', {name:'Quarantine',exact:true}).click(); await page.waitForTimeout(700);
    fixture('new');
    await refresh(() => page.locator('#fSearch').fill('review.php '));
    await page.locator('#fBody [data-do]').click();
    await page.locator('.modal-f').last().getByRole('button', {name:'Restore Old / Trusted Version',exact:true}).waitFor();
    await page.evaluate(() => GWQSH.toast('Visible action error test', 'err'));
    await page.waitForTimeout(400);
    check('error notification is above an open dialog', await page.locator('.toasts .toast.err').last().evaluate(e => { const r=e.getBoundingClientRect(); return e.contains(document.elementFromPoint(r.x+r.width/2,r.y+r.height/2)); }));
    await page.evaluate(() => document.querySelectorAll('.toast').forEach(e=>e.remove()));
    check('review includes Git line numbers', await page.locator('.git-diff .old-ln').count() > 0 && await page.locator('.git-diff .new-ln').count() > 0);
    check('review shows escaped diff', await page.locator('.modal-b').last().textContent().then(s => s.includes('<script>alert(1)</script>')) && await page.locator('.modal-b').last().locator('script').count() === 0);
    await refresh(() => page.locator('.modal-f').last().getByRole('button', {name:'Restore Old / Trusted Version',exact:true}).click());
    check('Restore Old restores trusted bytes', fs.readFileSync(account.root + '/review.php','utf8').includes('Trusted old version'));
    fixture('new'); await refresh(() => page.locator('#fSearch').fill('review.php'));
    await page.locator('#fBody [data-do]').click(); await page.waitForTimeout(250);
    await page.locator('.modal-f').last().getByRole('button', {name:'Keep New / Accept Current',exact:true}).click();
    await refresh(() => confirm('Keep New / Accept Current'));
    // Close the retained review dialog after its nested confirmation.
    if (await page.locator('.modal-bg').count()) await close();
    check('Keep New resolves safe finding', await page.locator('#fBody tr[data-id]').count() === 0);
    fixture('critical'); await refresh(() => page.locator('#fSearch').fill('review.php '));
    await page.locator('#fBody [data-do]').click(); await page.waitForTimeout(250);
    check('critical Keep New disabled', await page.locator('.modal-f').last().getByRole('button',{name:'Keep New / Accept Current',exact:true}).isDisabled());
    await close();
    await refresh(() => page.locator('#fSearch').fill(account.marker));
    // Real endpoint boundaries and independent per-item errors.
    const valid = Number(await page.locator('#fBody tr[data-id]').first().getAttribute('data-id'));
    let result = await ajax('bulk_quarantine',{finding_ids: Array(501).fill(valid).join(',')}); check('501 rejected', !result.success);
    result = await ajax('bulk_quarantine',{finding_ids:[valid,2147483647].join(',')}); check('bulk partial failure reports safe errors', result.success && result.data.results.quarantined === 1 && result.data.results.failed === 1 && result.data.results.errors.length === 1);
    await refresh(() => page.locator('#fSearch').fill(account.marker + ' '));
    await page.locator('#showQuarantine').click();
    await page.locator('#qBody [data-q="delete_quarantine"]').first().click(); await refresh(() => confirm('Delete Permanently'));
    check('single permanent deletion updates UI', await page.locator('#qBody tr[data-artifact]').count() >= 1);
    await page.locator('#qSelectAll').check(); await page.locator('#qDeleteSelected').click(); await refresh(() => confirm('Delete Selected'));
    check('bulk permanent delete removes copies', await page.locator('#qBody tr[data-artifact]').count() === 0);
    result = await ajax('bulk_restore_quarantine', {artifacts: Array(501).fill('a'.repeat(32)).join(',')}); check('501 bulk restores rejected', !result.success);
    result = await ajax('bulk_delete_quarantine', {artifacts: Array(501).fill('a'.repeat(32)).join(',')}); check('501 bulk deletes rejected', !result.success);
    // 500 valid findings in a single request, then clear every owned test copy.
    result = await ajax('get_scan_data',{search:account.marker,per_page:500});
    const ids = result.data.issues.filter(x => x.can_quarantine).map(x => x.id);
    check('500 fixtures available', ids.length === 500);
    result = await ajax('bulk_quarantine',{finding_ids:ids.join(',')}); check('500 bulk quarantine', result.success && result.data.results.quarantined === 500 && result.data.results.failed === 0);
    await page.locator('#showResults').click();
    await refresh(() => page.locator('#fSearch').fill(account.marker));
    await page.locator('#showQuarantine').click();
    check('quarantine page size independent', await page.locator('#qBody tr[data-artifact]').count() === 20);
    const clearCandidates = await ajax('get_quarantine_list');
    check('clear all contains fixture copies only', Object.values(clearCandidates.data.quarantine).every(item => item.original.includes(account.marker)));
    await page.locator('#qClearAll').click();
    check('clear all destructive confirmation', (await page.locator('.modal-b').last().textContent()).includes('This cannot be undone'));
    await refresh(() => confirm('Clear All Quarantine'));
    check('Clear All Quarantine empties UI', await page.locator('#qBody tr[data-artifact]').count() === 0);
    await page.locator('#showResults').click();
    // Mutation on the final page clamps to the nearest remaining page.
    await refresh(() => page.locator('#pageSize').selectOption('100'));
    let last = Math.max(...await page.locator('#fPager [data-p]').evaluateAll(buttons => buttons.map(b => Number(b.dataset.p))));
    if (last > 1) {
      await refresh(() => page.locator('#fPager [data-p="' + last + '"]').click());
      await page.locator('#checkAll').check();
      let reviewRequests=0; const countReview = req => { if ((req.postData()||'').includes('bulk_mark_reviewed')) reviewRequests++; }; page.on('request', countReview);
      const reviewStart=Date.now(); await refresh(() => page.locator('#bulkIgnore').click()); page.off('request',countReview);
      check('bulk review sends one mutation request', reviewRequests === 1); console.log('Bulk review elapsed: '+(Date.now()-reviewStart)+'ms');
      check('invalid final page clamps to previous page', await page.locator('#fPager [aria-current="page"]').textContent() === String(last - 1));
    }
    await refresh(() => page.locator('#runScan').click());
    check('resumable scan completes', (await page.locator('#scanPill').textContent()) === 'Completed');
    check('scan preserves page-size preference', await page.locator('#pageSize').inputValue() === '100');
    await page.reload(); await page.waitForTimeout(400);
    check('administrator page-size preference persists', await page.locator('#pageSize').inputValue() === '100');
    // Missing nonce and nonadministrator requests cannot dispatch mutations.
    const noNonce = await page.evaluate(async () => (await fetch(GWQSH_CONFIG.ajax_url,{method:'POST',body:new URLSearchParams({action:'gwqsh_action',subaction:'clear_all_quarantine'})})).status);
    check('nonce enforcement', noNonce === 403);
    const reader = await browser.newContext(); const readerPage = await reader.newPage();
    await readerPage.goto(account.login); await readerPage.locator('#user_login').fill(account.subscriber); await readerPage.locator('#user_pass').fill(account.password);
    await Promise.all([readerPage.waitForURL('**/wp-admin/**'), readerPage.locator('#wp-submit').click()]);
    const cookie = (await reader.cookies()).find(c => c.name.startsWith('wordpress_logged_in_'));
    const nonceResult = spawnSync(process.env.GWQSH_PHP, [process.env.GWQSH_BROWSER_NONCE], {input:cookie.value,encoding:'utf8'});
    assert.equal(nonceResult.status,0,nonceResult.stderr);
    const denial = await readerPage.evaluate(async ({url,nonce}) => {
      const response = await fetch(url,{method:'POST',body:new URLSearchParams({action:'gwqsh_action',subaction:'clear_all_quarantine',nonce})});
      return {status:response.status,json:await response.json()};
    }, {url:new URL('wp-admin/admin-ajax.php',account.base).href,nonce:nonceResult.stdout.trim()});
    console.log('Reader permission response: ' + JSON.stringify(denial));
    check('capability enforcement with valid reader nonce', denial.status === 403 && denial.json.data.message === 'Permission denied.');
    await reader.close();
    for (const width of [375,1280]) {
      await page.setViewportSize({width,height:900}); await page.waitForTimeout(250);
      await page.locator('#showQuarantine').click();
      if (width === 375) check('mobile quarantine select all visible', await page.locator('#qSelectAll').isVisible());
      check(`quarantine responsive width ${width}`, await page.locator('#gracewell-quietshield-app').evaluate(e => e.scrollWidth <= e.clientWidth + 2));
      await page.locator('#showResults').click();
      if (width === 375) {
        check('mobile findings select all visible', await page.locator('#checkAll').isVisible());
        check('mobile finding rows fit the viewport', await page.locator('#fBody tr[data-id]').evaluateAll(rows => rows.every(e => e.clientWidth < 375 && e.scrollWidth <= e.clientWidth + 2 && [...e.cells].slice(1).every(c => c.clientWidth >= 100))));
      }
      check(`responsive width ${width}`, await page.locator('#gracewell-quietshield-app').evaluate(e => e.scrollWidth <= e.clientWidth + 2));
    }
    console.log('Browser errors: ' + JSON.stringify(errors));
    check('no JS runtime errors', errors.length === 0);
    fs.writeFileSync(process.env.GWQSH_BROWSER_RESULT, JSON.stringify({checks,errors},null,2));
    console.log(JSON.stringify({passed:checks.length,checks,errors},null,2));
  } finally { await browser.close(); }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });
