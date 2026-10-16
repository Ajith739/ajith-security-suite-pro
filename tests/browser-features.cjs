// Real UI workflows against a disposable WordPress site; never prints credentials.
const fs=require('node:fs'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const {chromium}=require(process.env.GWQSH_PLAYWRIGHT||'playwright');
const jsQR=require(process.env.GWQSH_QR_DECODER||'jsqr');
(async()=>{
 const a=JSON.parse(fs.readFileSync(process.env.GWQSH_BROWSER_ACCOUNT,'utf8'));
 const b=await chromium.launch({executablePath:process.env.GWQSH_CHROME||'/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 const checks=[],errors=[];
 try{
 const context=await b.newContext({viewport:{width:1280,height:900}}),p=await context.newPage();
 p.on('pageerror',e=>errors.push(e.stack));
 const go=async suffix=>{await p.goto(a.base+'wp-admin/admin.php?page=gracewell-quietshield'+suffix);await p.waitForFunction(()=>!!window.GWQSH);};
 const login=async page=>{await page.goto(a.login);await page.locator('#user_login').fill(a.username);await page.locator('#user_pass').fill(a.password);await page.locator('#wp-submit').click();};
 const confirm=async name=>{await p.locator('.modal-f').last().getByRole('button',{name,exact:true}).click();};
 await login(p);await go('-firewall-cleanup');
 await p.locator('#qs-fw-enabled').check();await p.locator('#qs-fw-settings [type="submit"]').click();await p.waitForFunction(()=>document.querySelector('#qs-fw-feedback').textContent==='Firewall settings saved.');
 await p.reload();assert(await p.locator('#qs-fw-enabled').isChecked());
 const publicContext=await b.newContext();const probe=await publicContext.request.get(a.base+'?probe='+encodeURIComponent("' OR 1=1 --"));assert.equal(probe.status(),403);
 assert.equal((await context.request.get(a.base+'wp-admin/admin.php?page=gracewell-quietshield&probe='+encodeURIComponent("' OR 1=1 --"))).status(),200);
 await publicContext.close();checks.push('Firewall actual form save/reload, anonymous SQL probe denial and authenticated bypass');
 await go('-hardening');await p.locator('[data-info]').first().click();assert(await p.locator('.modal-bg').isVisible());await p.locator('.modal-bg [data-x]').click();
 await p.locator('[data-toggle="version"]').click();await confirm('Disable');await p.waitForFunction(()=>!document.querySelector('.modal-bg'));await p.reload();assert.equal(await p.locator('[data-toggle="version"]').getAttribute('aria-checked'),'false');
 await p.locator('[data-toggle="version"]').click();await confirm('Enable');await p.waitForFunction(()=>!document.querySelector('.modal-bg'));await p.reload();assert.equal(await p.locator('[data-toggle="version"]').getAttribute('aria-checked'),'true');
 for(const tab of ['nginx','csp','tips','apache']){await p.locator('[data-tab="'+tab+'"]').click();assert(await p.locator('#panel-'+tab).isVisible());}
 checks.push('Hardening information dialog, confirmed toggle saves and reload, four tabs');
 await go('-settings#importexport');assert(await p.locator('#importexport').isVisible());
 await p.locator('#importFile').setInputFiles({name:'audit-preferences.json',mimeType:'application/json',buffer:Buffer.from(JSON.stringify({settings:{retention:'45',theme:'dark'}}))});
 await p.waitForFunction(()=>document.querySelector('.toast')?.textContent.includes('settings imported'));await p.reload();await p.locator('#t-general').click();assert.equal(await p.locator('#retention').inputValue(),'45');
 await p.locator('#t-tools').click();const download=await Promise.all([p.waitForEvent('download'),p.locator('#exportS').click()]);const saved=JSON.parse(fs.readFileSync(await download[0].path(),'utf8'));assert.equal(saved.settings.retention,'45');
 await p.locator('#resetS').click();await confirm('Reset Defaults');await p.waitForFunction(()=>!document.querySelector('.modal-bg'));await p.reload();await p.locator('#t-general').click();assert.equal(await p.locator('#retention').inputValue(),'30');
 checks.push('Settings import with custom retention, real JSON download, confirmed reset and reload');
 await go('-two-factor');await p.locator('#qs-tf-regenerate').click();await confirm('Regenerate');await p.waitForFunction(()=>document.querySelector('#qs-tf-qr canvas'));
 const qr=await p.locator('#qs-tf-qr canvas').evaluate(c=>({width:c.width,height:c.height,pixels:[...c.getContext('2d').getImageData(0,0,c.width,c.height).data],uri:c.parentElement.dataset.uri}));
 const decoded=jsQR(Uint8ClampedArray.from(qr.pixels),qr.width,qr.height);assert(decoded);assert.equal(decoded.data,qr.uri);
 const secret=await p.locator('#qs-tf-secret').innerText();let bits='';for(const c of secret.replace(/\s/g,''))bits+='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(c).toString(2).padStart(5,'0');
 const key=Buffer.from(bits.match(/.{8}/g).map(v=>parseInt(v,2)));
 const totp=()=>{const counter=Buffer.alloc(8);counter.writeBigUInt64BE(BigInt(Math.floor(Date.now()/30000)));const h=crypto.createHmac('sha1',key).update(counter).digest(),o=h[19]&15;return ((h.readUInt32BE(o)&0x7fffffff)%1000000).toString().padStart(6,'0');};
 const current=totp(),invalid=current==='000000'?'999999':'000000';
 await p.locator('#qs-tf-code').fill(invalid);await p.locator('#qs-tf-verify').click();await p.waitForFunction(()=>document.querySelector('#qs-tf-feedback').dataset.error==='true');assert(await p.locator('#qs-tf-verify').isVisible());
 await p.locator('#qs-tf-code').fill(totp());await p.locator('#qs-tf-verify').click();await p.waitForFunction(()=>document.querySelector('#qs-tf-disable') && !document.querySelector('#qs-tf-disable').hidden);
 await p.locator('#qs-tf-backup-regenerate').click();await confirm('Regenerate Codes');await p.waitForFunction(()=>document.querySelectorAll('#qs-tf-codes li').length===10);
 const codes=await p.locator('#qs-tf-codes code').allTextContents();await p.reload();assert.deepEqual(await p.locator('#qs-tf-codes code').allTextContents(),codes);
 const challengeContext=await b.newContext(),challenge=await challengeContext.newPage();await login(challenge);await challenge.locator('#gwqsh_2fa_code').waitFor();await challenge.locator('#gwqsh_2fa_code').fill(codes[0]);await challenge.locator('#wp-submit').click();await challenge.waitForURL('**/wp-admin/**');await challengeContext.close();
 await p.reload();assert.equal(await p.locator('#qs-tf-codes li').count(),9);
 await p.locator('#qs-tf-disable').click();await p.locator('#qs-disable-code').fill(codes[1]);await confirm('Disable 2FA');await p.waitForFunction(()=>document.querySelector('#qs-tf-disable').hidden);
 checks.push('QR decoded against provisioning URI; invalid enrollment rejected; valid TOTP enrollment; backup generation/reload, password challenge and one-use recovery login; credential-verified disable');
 await go('-activity-log');await p.locator('#logSearch').fill('2FA');await p.locator('#activityFilters [type="submit"]').click();await p.waitForFunction(()=>document.querySelector('#activityBody [data-view]'));
 await p.locator('#activityBody [data-view]').first().click();assert(await p.locator('.modal-bg').isVisible());await p.locator('.modal-bg [data-x]').click();
 const exportDownload=await Promise.all([p.waitForEvent('download'),p.locator('[data-export]').first().click()]);const csv=fs.readFileSync(await exportDownload[0].path(),'utf8');assert(csv.includes('2FA'));checks.push('Activity search, full-details dialog and actual CSV export');
 console.log(JSON.stringify({checks,javascriptErrors:errors},null,2));assert.deepEqual(errors,[]);
 }finally{await b.close();}
})().catch(e=>{console.error(e.stack);process.exitCode=1;});
