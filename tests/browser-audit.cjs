// Run only against a disposable WordPress installation with temporary accounts.
const fs = require('node:fs');
const assert = require('node:assert/strict');
const { chromium } = require(process.env.GWQSH_PLAYWRIGHT || 'playwright');
let activeBrowser;
(async () => {
 const account=JSON.parse(fs.readFileSync(process.env.GWQSH_BROWSER_ACCOUNT,'utf8'));
 const browser=await chromium.launch({executablePath:process.env.GWQSH_CHROME || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',headless:true});
 activeBrowser=browser;
 const context=await browser.newContext({reducedMotion:'reduce'});
 const page=await context.newPage(), errors=[], layouts=[], surfaces=[], checks=[];
 page.setDefaultTimeout(20000);
 page.on('pageerror',e=>errors.push(e.stack));
 page.on('response',r=>{if(r.status()>=400 && r.url().includes('/plugins/gracewell-quiteshield-pro/'))errors.push(`${r.status()} ${r.url()}`);});
 await page.goto(account.login);await page.locator('#user_login').fill(account.username);await page.locator('#user_pass').fill(account.password);
 await Promise.all([page.waitForURL('**/wp-admin/**'),page.locator('#wp-submit').click()]);
 const suffixes=['','-login','-two-factor','-file-integrity','-firewall-cleanup','-hardening','-activity-log','-settings'];
 const widths=[320,360,375,390,425,576,768,900,1024,1180,1280,1440,1500,1920];
 const go=async suffix=>{await page.goto(new URL(`wp-admin/admin.php?page=gracewell-quietshield${suffix}`,account.base).href);await page.locator('#gracewell-quietshield-app').waitFor();};
    const measure=()=>page.evaluate(()=>{
     const w=document.documentElement.clientWidth;
     const overflow=[...document.querySelectorAll('#gracewell-quietshield-app *')].filter(el=>{
      const r=el.getBoundingClientRect(),s=getComputedStyle(el);
      let scrollParent=el.parentElement;
      while(scrollParent && scrollParent.id!=='gracewell-quietshield-app'){ if (['auto','scroll'].includes(getComputedStyle(scrollParent).overflowX)) return false; scrollParent=scrollParent.parentElement; }
      return r.width>0 && r.height>0 && s.visibility!=='hidden' && r.right>w+2 && !el.closest('svg,.table-scroll,.qs-fw-table-scroll,.hd-table-scroll,.al-table-scroll,.tabs-scroll');
     }).slice(0,12).map(el=>({tag:el.tagName,cls:el.className,id:el.id,right:Math.round(el.getBoundingClientRect().right)}));
     return {page:document.querySelector('#gracewell-quietshield-app').dataset.page,theme:document.documentElement.dataset.theme,width:innerWidth,scroll:document.documentElement.scrollWidth,overflow};
    });
 for(const suffix of suffixes){
  await go(suffix);
  assert.equal(await page.locator('#mainNav .nav-link').count(),7);
  assert.equal(await page.locator('.topbar .pro-link').count(),0);
  assert.equal(await page.locator('#mainNav a[href*="firewall-cleanup"]').count(),1);
  assert.equal(await page.locator('#mainNav [aria-current="page"]').count(),suffix==='-settings'?0:1);
  for(const theme of ['light','dark']){
   await page.evaluate(t=>{GWQSH.store.set('gwqsh-theme',t);GWQSH.applyPrefs();document.dispatchEvent(new CustomEvent('gwqsh:theme'));},theme);
   for(const width of widths){
    await page.setViewportSize({width,height:900});await page.waitForTimeout(65);
layouts.push(await measure());
    if(width===1280){
     await page.evaluate(()=>document.body.classList.add("folded"));await page.waitForTimeout(100);
     layouts.push({...await measure(),sidebar:"folded"});
     await page.evaluate(()=>document.body.classList.remove("folded"));
    }
   }
   if(theme==='dark'){
    if(process.env.GWQSH_SCREENSHOTS && !['-two-factor'].includes(suffix)){
     fs.mkdirSync(process.env.GWQSH_SCREENSHOTS,{recursive:true});
     for(const width of [375,1280]){await page.setViewportSize({width,height:900});await page.screenshot({path:process.env.GWQSH_SCREENSHOTS+'/'+(suffix||'dashboard')+'-'+width+'.png',fullPage:true});}
    }
    surfaces.push({page:suffix,lightSurfaces:await page.evaluate(()=>[...document.querySelectorAll('#gracewell-quietshield-app *')].filter(el=>{
     const r=el.getBoundingClientRect(),s=getComputedStyle(el),c=s.backgroundColor.match(/[\d.]+/g);
     return r.width*r.height>1500 && r.width>50 && r.height>25 && c && c.length>=3 && Math.min(...c.slice(0,3).map(Number))>190 && (c.length<4||Number(c[3])>.8) && !el.closest('.hero,.qs-tf-qr') && !el.matches('.switch,.qs-tf-switch span');
    }).map(el=>({cls:el.className,id:el.id,bg:getComputedStyle(el).backgroundColor,color:getComputedStyle(el).color}))) });
   }
  }
  // Viewports equivalent to a 1280px window at 125%, 150%, and 200% zoom.
  for(const zoom of [1.25,1.5,2]){
   await page.setViewportSize({width:Math.round(1280/zoom),height:Math.round(900/zoom)});
   layouts.push({...await measure(),zoomEquivalent:zoom});
  }
  await page.setViewportSize({width:375,height:900});
  await page.evaluate(()=>GWQSH.modal({title:'Layout verification',body:'<p>Theme and responsive dialog check.</p><input aria-label="Test input" value="Readable input">'}));
  const modal=page.locator('.modal-bg .modal');
  assert(await modal.evaluate(el=>{const r=el.getBoundingClientRect();return r.left>=0 && r.right<=innerWidth+2 && r.top>=0 && r.bottom<=innerHeight+2;}));
  assert(await modal.evaluate(el=>{const c=getComputedStyle(el).backgroundColor.match(/\d+/g);return c && Math.max(...c.slice(0,3).map(Number))<190;}));
  assert(await modal.locator('input').evaluate(el=>{const c=getComputedStyle(el).backgroundColor.match(/\d+/g);return c && Math.max(...c.slice(0,3).map(Number))<190;}));
  await page.locator('.modal-bg [data-x]').click();await page.waitForFunction(()=>!document.querySelector('.modal-bg'));
  await page.locator('[data-menu="user"]').click();assert(await page.locator('#menu-user').evaluate(el=>{const r=el.getBoundingClientRect();return r.left>=0 && r.right<=innerWidth+2;}));await page.locator('[data-menu="user"]').click();
  await page.locator('#burger').click();assert.equal(await page.locator('#burger').getAttribute('aria-expanded'),'true');
  assert(await page.locator('#mainNav a[href*="firewall-cleanup"]').isVisible());await page.keyboard.press('Escape');
  assert.equal(await page.locator('#burger').getAttribute('aria-expanded'),'false');
 }
 if(process.env.GWQSH_LAYOUT_RESULTS)fs.writeFileSync(process.env.GWQSH_LAYOUT_RESULTS,JSON.stringify({layouts,surfaces,errors},null,2));
 checks.push('Eight pages, seven navigation links, active states, mobile menu and Escape');
 await go('-settings');await page.setViewportSize({width:1280,height:900});
 await page.locator('.seg-btn[data-tab="appearance"]').click();assert(await page.locator('#theme').isVisible());
 await page.locator('#theme').selectOption('system');await page.waitForFunction(()=>localStorage.getItem('gwqsh-theme')==='system');
 await page.emulateMedia({colorScheme:'dark'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='dark');
 await page.emulateMedia({colorScheme:'light'});await page.waitForFunction(()=>document.documentElement.dataset.theme==='light');
 await page.locator('#theme').selectOption('dark');await page.waitForFunction(()=>localStorage.getItem('gwqsh-theme')==='dark');
 await page.locator('[data-menu="user"]').click();await page.locator('#themeToggle').click();assert.equal(await page.locator('#theme').inputValue(),'light');
 await go('');assert.equal(await page.evaluate(()=>document.documentElement.dataset.theme),'light');await page.reload();assert.equal(await page.evaluate(()=>document.documentElement.dataset.theme),'light');
 await go('-settings');await page.locator('.seg-btn[data-tab="advanced"]').click();assert(await page.locator('#advanced').isVisible());
 await page.locator('.seg-btn[data-tab="general"]').click();
 await Promise.all([
  page.waitForResponse(r=>r.url().includes('admin-ajax.php') && (r.request().postData()||'').includes('{"retention":"90"}')),
  (async()=>{await page.locator('#retention').selectOption('30');await page.locator('#retention').selectOption('7');await page.locator('#retention').selectOption('90');})()
 ]);
 await page.waitForFunction(()=>document.querySelector('#retention').value==='90');
 await page.reload();assert.equal(await page.locator('#retention').inputValue(),'90');
 await page.route('**/admin-ajax.php',route=>route.abort());await page.locator('#retention').selectOption('30');await page.waitForFunction(()=>document.querySelector('.toast.err'));
 assert.equal(await page.locator('#retention').inputValue(),'90');await page.unroute('**/admin-ajax.php');
 checks.push('Settings panels, saved retention reload, failed request rollback, System media changes, header/theme selector synchronization and navigation persistence');
 const request=async(action,data={},nonce)=>page.evaluate(async({action,data,nonce})=>{
  const body=new URLSearchParams({action:'gwqsh_action',subaction:action,nonce:nonce===undefined?GWQSH_CONFIG.nonce:nonce,...data});
  const r=await fetch(GWQSH_CONFIG.ajax_url,{method:'POST',body});return {status:r.status,json:await r.json()};
 },{action,data,nonce});
 assert.equal((await request('save_settings',{settings:JSON.stringify({theme:'dark'})},'invalid')).status,403);
 assert.equal((await request('save_settings',{settings:JSON.stringify({theme:['dark']})})).status,400);
 assert.equal((await request('save_settings',{settings:JSON.stringify({retention:-1})})).status,400);
 for(const action of ['get_dashboard_data','get_login_data','get_2fa_data','get_scan_data','get_firewall_data','get_hardening_data','activity_data'])assert.equal((await request(action)).json.success,true,action);
 checks.push('Seven real data endpoints, invalid nonce and invalid settings rejected');
 await go('-login');const max=page.locator('[name="max_attempts"]');await max.selectOption('10');
 await page.locator('#qs-login-settings-form [type="submit"]').click();await page.waitForFunction(()=>document.querySelector('#qs-login-feedback')?.textContent.includes('Protection settings saved'));
 await page.reload();assert.equal(await max.inputValue(),'10');
 checks.push('Login Protection actual form save and reload');
 await go('-activity-log');await page.locator('#activityFilters').evaluate(form=>form.requestSubmit());await page.waitForFunction(()=>!document.querySelector('#activityFilters [type="submit"]').disabled);
 checks.push('Activity filter form executes without errors');
 const readerContext=await browser.newContext(),reader=await readerContext.newPage();await reader.goto(account.login);await reader.locator('#user_login').fill(account.subscriber);await reader.locator('#user_pass').fill(account.password);
 await Promise.all([reader.waitForURL('**/wp-admin/**'),reader.locator('#wp-submit').click()]);
 await reader.goto(new URL('wp-admin/admin.php?page=gracewell-quietshield-two-factor',account.base).href);await reader.locator('#gracewell-quietshield-app').waitFor();
 const forbidden=await reader.evaluate(async()=>{const body=new URLSearchParams({action:'gwqsh_action',subaction:'save_settings',nonce:GWQSH_CONFIG.nonce,settings:'{"theme":"dark"}'});const r=await fetch(GWQSH_CONFIG.ajax_url,{method:'POST',body});return r.status;});assert.equal(forbidden,403);
 const denied=await reader.goto(new URL('wp-admin/admin.php?page=gracewell-quietshield-settings',account.base).href);assert.equal(denied.status(),403);
 checks.push('Subscriber own 2FA page allowed; Settings page and mutation denied');
 await browser.close();
 const failures=layouts.filter(r=>r.scroll>r.width+2 || r.overflow.length);
 console.log(JSON.stringify({checks,layoutCases:layouts.length,layoutFailures:failures,darkSurfaces:surfaces,javascriptErrors:errors},null,2));
 if(failures.length || surfaces.some(s=>s.lightSurfaces.length) || errors.length)process.exitCode=1;
})().catch(async e=>{console.error(e.stack);process.exitCode=1;await activeBrowser?.close();});
