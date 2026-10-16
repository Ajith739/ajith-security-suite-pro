// Optional local Chrome smoke test. Credentials are supplied by a temporary local account.
const fs = require('node:fs');
const { chromium } = require(process.env.GWQSH_PLAYWRIGHT || 'playwright');
(async () => {
  const account = JSON.parse(fs.readFileSync(process.env.GWQSH_BROWSER_ACCOUNT, 'utf8'));
  const browser = await chromium.launch({ executablePath: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', err => errors.push(err.stack));
  page.on('response', response => { if (response.status() >= 400 && response.url().includes('/plugins/gracewell-quiteshield-pro/')) errors.push(response.status() + ' ' + response.url()); });
  const front = await page.goto(account.base);
  await page.goto(account.login);
  await page.locator('#user_login').fill(account.username);
  await page.locator('#user_pass').fill(account.password);
  await Promise.all([page.waitForURL('**/wp-admin/**'), page.locator('#wp-submit').click()]);
  const slugs = ['gracewell-quietshield', 'gracewell-quietshield-login', 'gracewell-quietshield-two-factor', 'gracewell-quietshield-file-integrity', 'gracewell-quietshield-firewall-cleanup', 'gracewell-quietshield-hardening', 'gracewell-quietshield-activity-log', 'gracewell-quietshield-settings'];
  const results = [];
  for (const width of [375, 1280]) {
    await page.setViewportSize({ width, height: 900 });
    for (const slug of slugs) {
      const response = await page.goto(new URL(`wp-admin/admin.php?page=${slug}`, account.base).href);
      await page.locator('#gracewell-quietshield-app').waitFor();
      await page.waitForTimeout(200);
      results.push({ page: slug, width, status: response.status(), app: await page.locator('#gracewell-quietshield-app').count() });
    }
  }
  await browser.close();
  console.log(JSON.stringify({ frontend: front.status(), login: true, admin: results, javascriptErrors: errors }, null, 2));
  if (front.status() !== 200 || errors.length || results.some(r => r.status !== 200 || r.app !== 1)) process.exitCode = 1;
})().catch(error => { console.error(error.message); process.exitCode = 1; });
