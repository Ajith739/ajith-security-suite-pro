const fs=require('node:fs'),assert=require('node:assert/strict');
const {chromium}=require(process.env.GWQSH_PLAYWRIGHT || 'playwright');
(async()=>{
 const dir=process.env.GWQSH_UPGRADE_TEST_DIR,account=JSON.parse(fs.readFileSync(dir+'/account.json','utf8'));
 const browser=await chromium.launch({executablePath:'C:/Program Files/Google/Chrome/Application/chrome.exe',headless:true});
 const context=await browser.newContext({reducedMotion:'reduce',timezoneId:'America/New_York'});const page=await context.newPage();
 const errors=[],results=[];page.on('pageerror',e=>errors.push(e.message));page.on('response',r=>{if(r.status()>=400 && /\/plugins\/gracewell-security-suite-pro\/assets\//.test(r.url()))errors.push(r.status()+' '+r.url());});
 page.on('response',async r=>{if(/admin-ajax\.php/.test(r.url()) && /passkey_/.test(r.request().postData()||'')){try{const body=await r.json();if(!body.success)console.error('Passkey endpoint:',body.data?.message||'Request rejected');}catch{}}});
 try{
  await page.goto(account.login);await page.locator('#user_login').fill(account.username);await page.locator('#user_pass').fill(account.password);await Promise.all([page.waitForURL('**/wp-admin/**'),page.locator('#wp-submit').click()]);
  const go=async suffix=>{await page.goto(new URL('wp-admin/admin.php?page=gracewell-security-suite-pro'+suffix,account.base).href);await page.locator('#gracewell-security-suite-pro-app').waitFor();assert.equal(await page.locator('#gracewell-security-suite-pro-app').getAttribute('data-page'),suffix==='-login'?'login-protection':suffix.slice(1)||'dashboard');};
  for(const suffix of process.env.GWQSH_AUTH_ONLY?['-two-factor']:['','-login','-two-factor','-file-integrity','-firewall-cleanup','-hardening','-activity-log','-settings']){
   await go(suffix);assert.equal(await page.locator('#mainNav .nav-link').count(),7);
   for(const theme of ['light','dark']){
    await page.evaluate(t=>{GWQSH.store.set('gwqsh-theme',t);GWQSH.applyPrefs();},theme);
    for(const width of [375,768,1280]){
     await page.setViewportSize({width,height:900});await page.waitForTimeout(100);
     const measure=await page.evaluate(()=>({width:innerWidth,scroll:document.documentElement.scrollWidth,hero:document.querySelector('.hero-pro-card')?.getBoundingClientRect().toJSON()}));
     results.push({page:suffix || 'dashboard',theme,...measure});assert(measure.scroll<=width+3,JSON.stringify(results.at(-1)));
    }
   }
   assert.equal(await page.locator('script[src*="three.module"]').count(),0);
   const warnings=await page.locator('body').innerText();assert(!/PHP (?:Warning|Notice|Fatal)|Parse error|Warning: Undefined|Fatal error:/.test(warnings));
  }
  await page.setViewportSize({width:1280,height:900});await go('-login');
  await page.locator('#gwqsh-ip-form [name=ip]').fill('198.51.100.218');await page.locator('#gwqsh-ip-form [name=reason]').fill('Browser fixture restriction');await page.locator('#gwqsh-ip-form button[type=submit]').click();
  await page.locator('[data-manual-unblock="198.51.100.218"]').first().waitFor();await page.locator('[data-manual-unblock="198.51.100.218"]').first().click();await page.locator('.modal-f button').last().click();await page.waitForFunction(()=>!document.querySelector('[data-manual-unblock="198.51.100.218"]'));
  await page.evaluate(()=>GWQSH.toast('Toast verification','success'));assert(await page.locator('.toasts .gwqsh-toast-close').last().isVisible());await page.locator('.toasts .gwqsh-toast-close').last().click();
  const nonceFailure=await page.evaluate(async()=>{const r=await fetch(GWQSH_CONFIG.ajax_url,{method:'POST',body:new URLSearchParams({action:'gwqsh_action',subaction:'ip_block_save',nonce:'invalid',ip:'198.51.100.219'})});return r.status;});assert.equal(nonceFailure,403);
  await go('-two-factor');
  const cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  await page.evaluate(()=>{window.testToastMessages=[];new MutationObserver(()=>{document.querySelectorAll('.toasts .toast').forEach(t=>{if(!window.testToastMessages.includes(t.innerText))window.testToastMessages.push(t.innerText);});}).observe(document.querySelector('#gracewell-security-suite-pro-app'),{childList:true,subtree:true});});
  await page.locator('#qs-tf-add-passkey').click();await page.locator('#gwqsh-passkey-name').fill('Browser test passkey');await page.locator('#gwqsh-passkey-password').fill(account.password);await page.locator('.modal-f button').last().click();
  try{await page.locator('[data-passkey-rename]').first().waitFor({timeout:20000});}catch(error){console.error('UI diagnostics:',errors,await page.evaluate(()=>window.testToastMessages));throw error;}
  await page.locator('[data-passkey-rename]').first().click();await page.locator('#gwqsh-new-passkey-name').fill('Renamed browser passkey');await page.locator('#gwqsh-manage-passkey-password').fill(account.password);await page.locator('.modal-f button').last().click();await page.getByText('Renamed browser passkey',{exact:true}).waitFor();
  await page.evaluate(()=>fetch(GWQSH_CONFIG.logout_url));await page.goto(account.login);
  await page.locator('#user_login').fill(account.username);await page.getByRole('button',{name:'Sign in with a passkey',exact:true}).click();await page.waitForURL('**/wp-admin/**',{timeout:20000});
  await go('-two-factor');await page.locator('#qs-tf-passkey-tab').click();await page.locator('[data-passkey-remove]').first().click();await page.locator('#gwqsh-manage-passkey-password').fill(account.password);await page.locator('.modal-f button').last().click();await page.waitForFunction(()=>!document.querySelector('[data-passkey-remove]'));
  await go('');await page.setViewportSize({width:375,height:900});await page.screenshot({path:dir+'/dashboard-mobile.png',fullPage:true});
  await go('-login');await page.setViewportSize({width:1280,height:900});await page.screenshot({path:dir+'/access-desktop.png',fullPage:true});
  assert.deepEqual(errors,[]);
  fs.writeFileSync(dir+'/browser-results.json',JSON.stringify({results,errors,checks:['8 pages x 2 themes x 3 widths','manual block and unblock','invalid nonce rejected','accessible dismissible toast','WebAuthn registration, rename, passwordless login and removal']},null,2));
  console.log('PASS: 48 responsive page/theme checks, IP management, nonce security, toasts and browser WebAuthn lifecycle.');
 }finally{await browser.close();}
})().catch(e=>{console.error(e);process.exit(1);});
