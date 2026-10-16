/* Real Two-Factor enrollment, recovery and policy controls, scoped to this screen. */
(() => {
    'use strict';
    const root = document.querySelector('.qs-pro-two-factor');
    if (!root || !window.GWQSH) return;
    const $ = s => root.querySelector(s) || document.querySelector(s), $$ = s => [...root.querySelectorAll(s)];
    const { esc, ajax, modal, confirm, toast, copy, download } = window.GWQSH;
    const icon = name => `<svg class="qs-icon" aria-hidden="true"><use href="#i-${esc(name)}"/></svg>`;
    let data = window.GWQSH_DATA || {}, busy = false, tab = 'passkeys', request = 0, searchTimer;
    window.GWQSH_DATA = {}; // Keep enrollment secrets in this screen's short-lived state only.
    function feedback(message, error = false) {
        if (message) toast(message, error ? 'err' : 'ok');
    }
    function filters() { return {search:$('#qs-tf-user-search').value.trim(),role:$('#qs-tf-user-role').value,status:$('#qs-tf-user-status').value,page:data.user_page || 1}; }
    async function refresh(extra = {}) {
        const id = ++request;
        const result = await ajax('get_2fa_data', {...filters(),...extra});
        if (id !== request) return;
        if (!result.success) { feedback(result.data?.message || 'Unable to refresh two-factor data. Reload the page to try again.', true); return false; }
        data = result.data; render(); return true;
    }
    async function mutate(action, payload, message) {
        if (busy) { toast('Wait for the current change to finish.', 'info'); return false; }
        busy = true; root.setAttribute('aria-busy','true');
        const controls = $$('[data-policy],#qs-tf-verify,#qs-tf-regenerate,#qs-tf-backup-regenerate');
        const disabled = controls.map(button => button.disabled);
        controls.forEach(button => {button.disabled = true;});
        try {
            const result = await ajax(action, payload);
            if (!result.success) { feedback(result.data?.message || 'Unable to save this change.', true); return false; }
            await refresh(); feedback(message); return true;
        } finally {
            busy = false; root.removeAttribute('aria-busy');
            controls.forEach((button,index) => {button.disabled = disabled[index];});
            syncSetup(); syncPolicy();
        }
    }
    function metric(key,value,badge,description) {
        const el = $(`[data-tf-metric="${key}"]`);
        if (!el) return;
        const strong = el.querySelector('strong');
        if (strong) strong.textContent = value;
        if (badge !== undefined) {
            const pill = el.querySelector('.qs-badge');
            if (pill) { pill.textContent = badge; pill.hidden = !badge; }
        }
        if (description) {
            const p = el.querySelector('p');
            if (p) p.textContent = description;
        }
    }
    function syncSetup() {
        const pending = !!data.secret, active = !!data.is_enabled;
        const secEl = $('#qs-tf-secret');
        if (secEl) secEl.textContent = pending ? data.secret.match(/.{1,4}/g).join(' ') : data.effective_enabled ? 'Authenticator connected' : 'No setup key available';
        const copySec = $('#qs-tf-copy-secret');
        if (copySec) copySec.disabled = !pending;
        const codeEl = $('#qs-tf-code');
        if (codeEl) { codeEl.hidden = !pending; codeEl.required = pending; }
        const codeLbl = $('[for="qs-tf-code"]');
        if (codeLbl) codeLbl.hidden = !pending;
        const verifyBtn = $('#qs-tf-verify');
        if (verifyBtn) {
            verifyBtn.hidden = !pending;
            verifyBtn.innerHTML = (active ? 'Verify Replacement' : 'Verify & Enable 2FA') + icon('arrow');
            verifyBtn.disabled = busy || !pending;
        }
        const bupRegen = $('#qs-tf-backup-regenerate');
        if (bupRegen) bupRegen.disabled = busy || !active;
        const disBtn = $('#qs-tf-disable');
        if (disBtn) disBtn.hidden = !active;
        const stEl = $('#qs-tf-setup-status');
        if (stEl) stEl.textContent = active ? (pending ? 'Your current authenticator remains active until this replacement is verified.' : data.effective_enabled ? 'Your authenticator is active. Regenerate to connect a new device.' : 'Your stored authenticator needs attention. Regenerate and verify a replacement.') : '2FA is activated only after successful code verification.';
        const qr = $('#qs-tf-qr');
        if (!qr) return;
        if (qr.dataset.uri === data.qr_uri) return;
        qr.dataset.uri = data.qr_uri || ''; qr.replaceChildren();
        if (!pending) {qr.innerHTML = data.effective_enabled ? `<p>${icon('shield-check')}<br>Authenticator connected<br>Verified and active</p>` : '<p>Secure setup is unavailable. Regenerate your QR code to retry.</p>';return;}
        try {
            if (!window.gwqshQR) throw new Error('Unavailable');
            window.gwqshQR(qr,data.qr_uri,{size:320,dark:'#090b52'});
            qr.querySelector('canvas')?.setAttribute('aria-label','Scan to enroll your own authenticator');
        } catch {qr.textContent = 'QR generation unavailable. Enter the setup key manually.';}
    }
    $('#qs-tf-copy-secret').addEventListener('click',event => {if (data.secret) copy(data.secret,'Setup key copied',event.currentTarget,{iconOnly:true});});
    $('#qs-tf-enroll').addEventListener('submit',async event => {
        event.preventDefault();
        const code = $('#qs-tf-code').value.trim();
        if (!/^\d{6}$/.test(code)) {feedback('Enter the six-digit code from your authenticator.',true);return;}
        const button = $('#qs-tf-verify');button.textContent = 'Verifying…';
        const ok = await mutate(data.is_enabled ? 'confirm_2fa_secret' : 'enable_user_2fa',{code},data.is_enabled ? 'Replacement authenticator verified. Remembered devices were revoked.' : 'Two-factor authentication enabled. Generate and save your backup codes.');
        if (ok) $('#qs-tf-code').value = '';
    });
    $('#qs-tf-regenerate').addEventListener('click',() => confirm('Regenerate your QR code?',data.is_enabled ? 'Your current authenticator stays active until the replacement is verified. The previous pending key stops working. Verification will revoke remembered devices.' : 'The previous unverified setup key will stop working. Scan the new QR code and verify it to enable 2FA.','Regenerate',() => mutate('generate_2fa_secret',{confirmed:1},'New setup key generated. Scan it and verify a code.')));
    $('#qs-tf-help').addEventListener('click',() => modal({title:'Authenticator setup guide',body:'<ol><li>Open Google Authenticator, Authy, 1Password, or another TOTP app.</li><li>Scan your QR code or enter your setup key manually.</li><li>Enter the six-digit code shown in the app, then verify.</li><li>Generate backup codes and store them safely.</li></ol><p>Codes use SHA1, six digits, and a 30-second period. Keep your device clock synchronized. Never share your setup key.</p>'}));
    $('#qs-tf-disable').addEventListener('click',() => modal({title:'Disable your two-factor authentication?',body:'<p>This removes your authenticator, backup codes, and remembered devices. A required account cannot disable 2FA.</p><label for="qs-disable-code">Current authenticator or unused backup code</label><input class="field" id="qs-disable-code" autocomplete="one-time-code">',actions:[{label:'Cancel'},{label:'Disable 2FA',cls:'btn-danger',fn:bg => mutate('disable_own_2fa',{code:bg.querySelector('#qs-disable-code').value.trim()},'Your two-factor authentication was disabled.')}]}));

    function visibleCodes() {return (data.backup_codes || []).filter(record => !record.used && record.code).map(record => record.code);}
    function syncBackup() {
        const codes = visibleCodes();
        $('#qs-tf-codes').innerHTML = codes.map((code,index) => `<li><code>${esc(code)}</code><button class="qs-tf-copy" type="button" data-code-index="${index}" aria-label="Copy backup code ${index+1}">${icon('tf-copy')}</button></li>`).join('');
        $('#qs-tf-backup-empty').hidden = !!codes.length;
        $('#qs-tf-backup-empty').textContent = data.backup_remaining ? 'Your older hashed codes remain valid but cannot be displayed. Regenerate intentionally to save a new set.' : data.is_enabled ? 'No unused backup codes. Generate a set and save it somewhere safe.' : 'Verify your authenticator first, then generate your one-time recovery codes.';
        $('#qs-tf-copy-all').disabled = !codes.length;$('#qs-tf-download').disabled = !codes.length;
    }
    $('#qs-tf-codes').addEventListener('click',event => {const button = event.target.closest('[data-code-index]');if (button) copy(visibleCodes()[Number(button.dataset.codeIndex)],'Backup code copied',button,{iconOnly:true});});
    $('#qs-tf-copy-all').addEventListener('click',event => copy(visibleCodes().join('\n'),'Backup codes copied',event.currentTarget,{iconOnly:true}));
    $('#qs-tf-download').addEventListener('click',() => {
        const codes = visibleCodes();if (!codes.length) return;
        download('quietshield-backup-codes.txt',`Security Suite Pro Backup Codes\nSite: ${data.site}\nUsername: ${data.username}\nGeneration date: ${data.backup_generated}\n\n${codes.join('\n')}\n\nEach code can only be used once. Keep these codes in a secure password manager or offline location. Regenerating codes invalidates this set.\n`,'text/plain');
        toast('Backup codes downloaded.');
    });
    $('#qs-tf-backup-regenerate').addEventListener('click',() => confirm('Regenerate backup codes?','All current unused codes stop working immediately. Save the new codes in a password manager or offline location.','Regenerate Codes',() => mutate('generate_backup_codes',{},'New backup codes generated. Save them securely.')));

    const unsupported = feature => window.GWQSH.manageMethod?.(feature === 'Passkey' ? 'passkeys' : feature === 'Email backup' ? 'email' : 'sms');
    function syncMethods() {
        const methods = [
            ['app','tf-phone','Authenticator App (TOTP)','Use Google Authenticator, Authy, etc.',data.effective_enabled?'Enabled':'Set up'],
            ['passkeys','shield-check','Passkeys (WebAuthn)','Use a device fingerprint or security key.',data.recovery?.passkeys?.length?'Enabled':'Set up'],
            ['backup','tf-key','Backup Codes',`${data.backup_remaining} one-time codes remaining.`,data.backup_remaining?'Enabled':'Set up'],
            ['email','mail','Email Backup','Receive verification codes via email.',data.recovery?.email?'Enabled':'Set up'],
            ['sms','tf-device','SMS Backup','Receive verification codes via SMS.',data.recovery?.sms?'Enabled':'Set up'],
            ['devices','tf-device','Trusted Devices','Remember devices for 30 days.',data.settings.remember_device?'Managed':'Off']
        ];
        $('#qs-tf-method-rows').innerHTML = methods.map(([key,symbol,title,help,status]) => `<button class="qs-tf-method-row" data-method="${key}" type="button"><span class="qs-tf-row-icon">${icon(symbol)}</span><span><b>${esc(title)}</b><small>${esc(help)}</small></span><span class="qs-badge ${['Enabled','Managed'].includes(status)?'qs-good':status==='Not configured'?'':'qs-warning'}">${esc(status)}</span><i aria-hidden="true">›</i></button>`).join('');
    }
    $('#qs-tf-method-rows').addEventListener('click',event => {
        const key = event.target.closest('[data-method]')?.dataset.method;
        if (key==='app') {$('#qs-tf-setup').scrollIntoView({behavior:'smooth',block:'center'});$('#qs-tf-code').hidden ? $('#qs-tf-regenerate').focus() : $('#qs-tf-code').focus();}
        if (key==='backup') {$('#qs-tf-backup').scrollIntoView({behavior:'smooth',block:'center'});$('#qs-tf-backup-regenerate').focus();}
        if (key==='devices') devicesModal();
        if (['passkeys','email','sms'].includes(key)) unsupported({passkeys:'Passkey',email:'Email backup',sms:'SMS backup'}[key]);
    });
    $('#qs-tf-manage-methods').addEventListener('click',() => window.GWQSH.manageMethod?.('all'));
    $('#qs-tf-add-passkey').addEventListener('click',() => unsupported('Passkey'));
    const staffRoles = () => ['editor','author','shop_manager'].filter(role => data.roles[role]);
    function syncPolicy() {
        $$('[data-policy]').forEach(input => {
            input.checked = input.dataset.policy==='staff' ? data.settings.enforce_roles && staffRoles().length>0 && staffRoles().every(role => data.settings.required_roles.includes(role)) : !!data.settings[input.dataset.policy];
            input.disabled = busy || !data.can_manage;
        });
    }
    $$('[data-policy]').forEach(input => input.addEventListener('change',() => {
        const key = input.dataset.policy, checked = input.checked;
        syncPolicy();
        let payload = {[key]:checked?1:0};
        if (key==='staff') {
            const roles = new Set(data.settings.required_roles);staffRoles().forEach(role => checked ? roles.add(role) : roles.delete(role));
            payload = {required_roles:JSON.stringify([...roles]),...(checked?{enforce_roles:1}:{})};
        }
        confirm('Save two-factor policy?',`This will ${checked?'enable':'disable'} “${esc(input.getAttribute('aria-label'))}”. Required users must enroll their own authenticator before accessing other site features.`,'Save Policy',() => mutate('save_2fa_settings',payload,'Two-factor policy saved.'));
    }));
    $('#qs-tf-roles').addEventListener('click',() => {
        if (!data.can_manage) return;
        modal({title:'Manage role enforcement',body:'<p>Select actual site roles. Enforced roles must complete enrollment; existing authenticators remain active.</p>'+Object.entries(data.roles).map(([key,name],index) => `<p><label for="qs-role-${index}"><input id="qs-role-${index}" type="checkbox" value="${esc(key)}" data-role ${data.settings.required_roles.includes(key)?'checked':''}> ${esc(name)}</label></p>`).join('')+`<p><label><input type="checkbox" id="qs-role-enforce" ${data.settings.enforce_roles?'checked':''}> Enforce selected roles</label></p><p><label><input type="checkbox" id="qs-role-optional" ${data.settings.allow_roles?'checked':''}> Allow optional enrollment for other roles</label></p>`,actions:[{label:'Cancel'},{label:'Save Role Settings',cls:'btn-primary',fn:bg => mutate('save_2fa_settings',{required_roles:JSON.stringify([...bg.querySelectorAll('[data-role]:checked')].map(input => input.value)),enforce_roles:bg.querySelector('#qs-role-enforce').checked?1:0,allow_roles:bg.querySelector('#qs-role-optional').checked?1:0},'Role enforcement settings saved.')} ]});
    });

    function deviceRows(devices) {
        return devices.length ? devices.map(device => `<div class="qs-tf-device-row"><span class="qs-tf-row-icon">${icon('tf-device')}</span><div><b>${esc(device.label)}</b><small>Added ${esc(device.created)} · Expires ${esc(device.expires)}</small></div><span class="qs-badge qs-good">Trusted</span><div><small>Last used</small><small>${esc(device.last_used)}</small></div><button class="qs-small-button qs-tf-remove" type="button" data-device-id="${esc(device.id)}">Remove</button></div>`).join('') : '<p class="qs-tf-empty">No trusted devices. After a successful 2FA login, choose “Trust this device for 30 days” if site policy permits.</p>';
    }
    function syncDevices() {
        $('#qs-tf-trusted-tab').textContent = `Trusted Devices (${data.devices.length})`;
        const list = $('#qs-tf-device-list');
        list.setAttribute('aria-labelledby',tab==='trusted'?'qs-tf-trusted-tab':'qs-tf-passkey-tab');
        list.innerHTML = tab==='trusted' ? deviceRows(data.devices) : (window.GWQSH.passkeyRows ? window.GWQSH.passkeyRows(data.recovery?.passkeys || []) : window.GWQSH.emptyState('No registered passkeys','Register a passkey to sign in with your device.','setup'));
        $$('[data-device-tab]').forEach(button => {const active = tab===button.dataset.deviceTab;button.setAttribute('aria-selected',String(active));button.tabIndex = active?0:-1;});
    }
    $$('[data-device-tab]').forEach(button => {
        button.addEventListener('click',() => {tab=button.dataset.deviceTab;syncDevices();});
        button.addEventListener('keydown',event => {if (['ArrowLeft','ArrowRight','Home','End'].includes(event.key)) {event.preventDefault();tab = event.key==='Home'?'passkeys':event.key==='End'?'trusted':tab==='passkeys'?'trusted':'passkeys';syncDevices();$(`[data-device-tab="${tab}"]`).focus();}});
    });
    function revoke(button,userId) {
        confirm('Revoke remembered device?','This device will need an authenticator or unused backup code on its next login. Its current WordPress session is unaffected.','Revoke Device',() => mutate('remove_trusted_device',{device_id:button.dataset.deviceId,...(userId?{user_id:userId}:{})},'Remembered device revoked.'),true);
    }
    $('#qs-tf-device-list').addEventListener('click',event => {const b=event.target.closest('[data-device-id]');if (b) revoke(b);});
    async function devicesModal(userId) {
        const result = await ajax('get_user_2fa_devices',userId?{user_id:userId}:{});
        if (!result.success) {feedback(result.data?.message || 'Unable to load devices.',true);return;}
        modal({title:'Manage remembered devices',wide:true,body:deviceRows(result.data.devices),onOpen:bg => {
            bg.querySelectorAll('[data-device-id]').forEach(button => button.addEventListener('click',async () => {
                // Keep the owning dialog open so the explicit confirmation remains reviewable.
                button.disabled=true;
                const ok = await mutate('remove_trusted_device',{device_id:button.dataset.deviceId,...(userId?{user_id:userId}:{})},'Remembered device revoked.');
                if (ok) {button.closest('.qs-tf-device-row').remove();} else button.disabled=false;
            }));
        }});
    }
    $('#qs-tf-all-devices').addEventListener('click',() => devicesModal());
    function syncUsers() {
        $('#qs-tf-user-rows').innerHTML = data.users.length ? data.users.map(u => `<tr><td><span class="qs-tf-user"><span class="qs-tf-user-avatar ${u.me?'me':''}">${esc((u.name||u.u)[0].toUpperCase())}</span>${esc(u.u)}</span></td><td><span class="qs-tf-user-role">${esc(u.role)}</span></td><td><span class="qs-tf-user-status qs-tf-${u.st.toLowerCase()}">${esc(u.st)}</span>${u.required?'<small><br>Setup required</small>':''}</td><td>${esc(u.m)}</td><td>${esc(u.a)}</td><td>${u.backup_remaining?`Backup codes (${u.backup_remaining})`:'—'}</td><td><button class="qs-small-button" data-user-id="${u.id}" type="button">${u.st==='Enabled'?'Manage':u.me?'Enable':'Manage'}</button></td></tr>`).join('') : '<tr><td colspan="7">No users match these filters.</td></tr>';
        $('#qs-tf-user-count').textContent = `${data.user_total} users · Page ${data.user_page} of ${data.user_pages}`;
        $('#qs-tf-user-prev').disabled = data.user_page<=1;$('#qs-tf-user-next').disabled = data.user_page>=data.user_pages;
    }
    $('#qs-tf-user-rows').addEventListener('click',event => {
        const button=event.target.closest('[data-user-id]');if (!button) return;
        const u=data.users.find(user=>user.id===Number(button.dataset.userId));if (!u) return;
        if (u.me && !u.enrolled) {$('#qs-tf-setup').scrollIntoView({behavior:'smooth',block:'center'});$('#qs-tf-code').focus();return;}
        const actions=[{label:'Close'}];
        if (u.me) actions.push({label:'Manage your devices',fn:()=>{setTimeout(()=>devicesModal(),0);}});
        if (!u.me && u.can_edit) {
            actions.push({label:u.individual_required?'Remove individual requirement':'Require setup',cls:'btn-outline',fn:()=>mutate('require_user_2fa',{user_id:u.id,required:u.individual_required?0:1},'User enrollment requirement saved.')});
            actions.push({label:'Manage devices',cls:'btn-outline',fn:()=>{setTimeout(()=>devicesModal(u.id),0);}});
            if (data.settings.allow_admin_reset && u.enrolled) actions.push({label:'Reset 2FA…',cls:'btn-danger',fn:()=>{setTimeout(()=>confirm(`Reset 2FA for ${esc(u.u)}?`,'This removes the authenticator, passkeys, email/SMS recovery, backup codes and remembered devices, and signs this user out. Their role and individual enrollment requirement remain in effect.','Reset 2FA',()=>mutate('reset_user_2fa',{user_id:u.id,confirmed:1},'User two-factor authentication reset.'),true),0);}});
        }
        modal({title:`Manage 2FA for ${esc(u.u)}`,body:`<p>Role: ${esc(u.role)}<br>Status: ${esc(u.st)}<br>Method: ${esc(u.m)}<br>Last verified: ${esc(u.a)}<br>Recovery: ${u.backup_remaining} unused backup codes<br>Remembered devices: ${u.device_count}</p><p>${u.me?'Manage your own authenticator in the setup card.':'Users must enroll their own authenticator. Administrators cannot see another user’s secret or backup codes.'}</p>`,actions});
    });
    $('#qs-tf-user-search').addEventListener('input',() => {clearTimeout(searchTimer);searchTimer=setTimeout(()=>refresh({page:1}),300);});
    ['#qs-tf-user-role','#qs-tf-user-status'].forEach(selector=>$(selector).addEventListener('change',()=>refresh({page:1})));
    $('#qs-tf-user-prev').addEventListener('click',()=>refresh({page:data.user_page-1}));
    $('#qs-tf-user-next').addEventListener('click',()=>refresh({page:data.user_page+1}));
    function render() {
        const state=data.protection;
        if ($('#qs-tf-protection-title')) $('#qs-tf-protection-title').textContent = `2FA Protection ${state==='Protected'?'Active':state==='Partial'?'Partially Configured':'Disabled'}`;
        if ($('#qs-tf-protection-badge')) $('#qs-tf-protection-badge').textContent=state;
        if ($('#qs-tf-protection-badge')) $('#qs-tf-protection-badge').className='qs-badge '+(state==='Protected'?'qs-good':'qs-warning');
        if ($('#qs-tf-protection-description')) $('#qs-tf-protection-description').textContent=state==='Protected'?`Your ${data.can_manage?'site':'account'} is protected with two-factor authentication.`:'Complete enrollment and review role policies to protect your site.';
        metric('coverage',`${data.counts?.enabled ?? 0} / ${data.counts?.total ?? 0} users`,`${data.percent ?? 0}%`);
        metric('trusted',`${data.counts?.devices ?? 0} devices`,data.settings?.remember_device?'Active':'Off');
        metric('recovery',`${data.backup_remaining ?? 0} backup codes`,data.backup_remaining?'Ready':'Set up');
        metric('verification',data.last_label || 'Never','',data.last_date || 'No verification recorded');
        syncSetup();syncBackup();syncMethods();syncPolicy();syncDevices();syncUsers();
        document.dispatchEvent(new CustomEvent('gwqsh:factor-state',{detail:data.recovery}));
    }
    render();

    const deliveryBtn = document.getElementById('qs-open-delivery-modal');
    if (deliveryBtn) {
        deliveryBtn.addEventListener('click', () => {
            const tpl = document.getElementById('qs-tpl-delivery-settings');
            if (!tpl) return;
            const content = tpl.content.cloneNode(true);
            const div = document.createElement('div');
            div.appendChild(content);
            modal({
                title: 'Passkey & Backup Delivery Settings',
                wide: true,
                body: div.innerHTML,
                onOpen: bg => {
                    const form = bg.querySelector('form.qs-integrations-form');
                    if (form) {
                        form.addEventListener('submit', async e => {
                            e.preventDefault();
                            const submitBtn = form.querySelector('button[type="submit"]');
                            if (submitBtn) submitBtn.disabled = true;
                            const settings = {};
                            form.querySelectorAll('[name]').forEach(input => {
                                settings[input.name] = input.dataset.fieldType === 'bool' ? (input.value === '1') : input.value;
                            });
                            try {
                                const res = await ajax('config_save', { section: 'integrations', settings });
                                if (res.success) {
                                    toast('Passkey & backup delivery settings saved.', 'ok');
                                } else {
                                    toast(res.data?.message || 'Unable to save delivery settings.', 'err');
                                }
                            } catch {
                                toast('Error saving delivery settings.', 'err');
                            } finally {
                                if (submitBtn) submitBtn.disabled = false;
                            }
                        });
                    }
                }
            });
        });
    }
})();
