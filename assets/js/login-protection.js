/* Login Protection: server snapshots, scoped controls and responsive charts. */
(() => {
    'use strict';
    const root = document.querySelector('#gracewell-security-suite-pro-app[data-page="login-protection"]');
    if (!root || !window.GWQSH) return;
    const $ = s => root.querySelector(s);
    const $$ = s => [...root.querySelectorAll(s)];
    const esc = window.GWQSH.esc;
    let data = window.GWQSH_DATA || {};
    let requestId = 0, activePoint = null, allLocks = false, mutating = false;
    const format = n => Number(n || 0).toLocaleString();
    const date = window.GWQSH.date;
    $('#qs-login-chart').innerHTML = '<div class="qs-chart-tooltip" role="status" aria-live="polite" hidden></div>';
    const series = [['blocked','Blocked Attempts','#ff273d'],['failed','Failed Logins','#ffa800'],['successful','Successful Logins','#0755ff']];
    function drawChart() {
        const chart = $('#qs-login-chart');
        const tip = chart.querySelector('.qs-chart-tooltip');
        chart.querySelector('svg')?.remove();
        tip.hidden = true;
        chart.onpointermove = chart.onpointerleave = chart.onblur = chart.onkeydown = null;
        const d = data.chart;
        if (!d || d.error || !d.labels?.length) return;
        const width = chart.clientWidth;
        const height = chart.clientHeight;
        if (width < 50) return;
        const count = d.labels.length;
        const topValue = Math.max(4, ...series.flatMap(([key]) => d[key] || []));
        const step = Math.max(1, Math.ceil(topValue / 4));
        const max = step * 4;
        const pad = { left:Math.max(30, String(max).length * 6 + 10), right:15, top:9, bottom:24 };
        const x = i => pad.left + i / Math.max(1, count - 1) * (width - pad.left - pad.right);
        const y = v => pad.top + (1 - v / max) * (height - pad.top - pad.bottom);
        const path = values => values.map((v,i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(v).toFixed(2)}`).join(' ');
        let markup = '<defs><linearGradient id="qs-login-chart-fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#ff273d" stop-opacity=".23"/><stop offset="1" stop-color="#ff273d" stop-opacity=".01"/></linearGradient></defs>';
        for (let i = 0; i <= 4; i++) markup += `<line x1="${pad.left}" x2="${width-pad.right}" y1="${y(i*step)}" y2="${y(i*step)}" stroke="#e7eef9"/><text x="${pad.left-9}" y="${y(i*step)+3}" text-anchor="end">${i*step}</text>`;
        const interval = Math.max(1, Math.ceil(count / Math.max(2, Math.floor(width / 60))));
        d.labels.forEach((label,i) => {
            markup += `<line x1="${x(i)}" x2="${x(i)}" y1="${pad.top}" y2="${height-pad.bottom}" stroke="#edf2fb"/>`;
            if (i === count-1 || (i % interval === 0 && (i === 0 || x(count-1)-x(i) >= 48))) markup += `<text x="${x(i)}" y="${height-4}" text-anchor="${i===0 ? 'start' : i===count-1 ? 'end' : 'middle'}">${esc(label)}</text>`;
        });
        const blocked = d.blocked || Array(count).fill(0);
        markup += `<path d="${path(blocked)} L${x(count-1)},${y(0)} L${x(0)},${y(0)} Z" fill="url(#qs-login-chart-fill)"/>`;
        series.forEach(([key,,color]) => {
            const values = d[key] || Array(count).fill(0);
            markup += `<path d="${path(values)}" fill="none" stroke="${color}" stroke-width="1.7" stroke-linejoin="round"/>`;
            if (count <= 14) values.forEach((v,i) => { markup += `<circle cx="${x(i)}" cy="${y(v)}" r="3" fill="${color}" stroke="white" stroke-width="1"/>`; });
        });
        chart.insertAdjacentHTML('afterbegin', `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Recorded security activity over ${count} days">${markup}</svg>`);
        const show = i => {
            activePoint = i;
            tip.innerHTML = `<b>${esc(d.labels[i])}</b>` + series.map(([key,label,color]) => `<span><i style="display:inline-block;width:6px;height:6px;border-radius:50%;background:${color};margin-right:5px"></i>${esc(label)}: <b>${format(d[key]?.[i])}</b></span>`).join('');
            tip.hidden = false;
            tip.style.left = `${Math.max(0, Math.min(width - tip.offsetWidth, x(i) + 8))}px`;
            tip.style.top = '0px';
        };
        chart.onpointermove = event => { const rect = chart.getBoundingClientRect(); show(Math.max(0,Math.min(count-1,Math.round((event.clientX-rect.left-pad.left)/(width-pad.left-pad.right)*(count-1))))); };
        chart.onpointerleave = () => { tip.hidden = true; };
        chart.onblur = () => { tip.hidden = true; };
        chart.onkeydown = event => {
            if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') { event.preventDefault(); show(Math.max(0, Math.min(count-1, (activePoint ?? 0) + (event.key === 'ArrowRight' ? 1 : -1)))); }
        };
    }
    function badge(el, enabled, yes = 'Enabled', no = 'Disabled') {
        el.textContent = enabled ? yes : no;
        el.classList.toggle('qs-good', !!enabled);
        el.classList.toggle('qs-warning', !enabled);
    }
    function update() {
        const s = data.settings;
        if (!s) return;
        $('#qs-login-error').hidden = !data.data_error;
        const metrics = {blocked:format(data.blocked_30d),locked:format(data.locked_ips.length),failures:`${s.max_attempts} in ${s.time_window} min`,duration:`${s.lockout_duration} min`,xmlrpc:data.xmlrpc ? 'Enabled' : 'Disabled',trusted:format(data.allow_ips.length)};
        Object.entries(metrics).forEach(([key,value]) => { const metric = $(`[data-login-metric="${key}"] strong`); if (metric) metric.textContent = value; });
        const statuses = {engine:[data.engine_active ? 'Active':'Paused',data.engine_active],custom:[data.custom_active ? 'Enabled':'Disabled',data.custom_active],proxy:[data.proxy_name,data.proxy_effective]};
        Object.entries(statuses).forEach(([key,[label,on]]) => {
            $(`[data-status-label="${key}"]`).textContent = label;
            badge($(`[data-status-badge="${key}"]`),on,'Active',key==='proxy' ? 'Direct':'Inactive');
            $(`[data-status-label="${key}"]`).closest('div').querySelector('use').setAttribute('href',on ? '#i-check':'#i-alert');
        });
        const score = Number(data.protection_score);
        $('#qs-login-score-value').textContent = score;
        $('#qs-login-ring').setAttribute('stroke-dashoffset',483.805*(1-score/100));
        $('#qs-login-gauge').setAttribute('aria-label',`Login protection score ${score} out of 100`);
        $('.qs-login-score').dataset.scoreLevel = score>=85 ? 'good' : score>=50 ? 'review' : 'weak';
        $('#qs-login-score-status').textContent = score>=85 ? 'Excellent':score>=50 ? 'Review':'Needs attention';
        $('#qs-login-headline').textContent = score>=85 ? 'Your login protection is strong!':'Strengthen your login protection';
        $$('[data-login-score]').forEach(el => {
            const val = data.score_components[el.dataset.loginScore];
            el.textContent = val===null ? 'N/A':val;
            el.closest('li').querySelector('use').setAttribute('href',val ? '#i-check':'#i-alert');
            el.closest('li').querySelector('.qs-login-score-check').classList.toggle('qs-is-inactive', !val);
        });
        const rules = {threshold:[`${s.max_attempts} failed login attempts in ${s.time_window} minutes`,`Lock IP for ${s.lockout_duration} minutes`,data.engine_active],repeat:[`${s.repeat_lockouts} lockouts in 24 hours`,`Trigger a ${s.repeat_duration}-hour lockout`,data.engine_active],generic:['Show generic login errors','Prevents username disclosure in error messages',s.generic_errors],proxy:['Proxy & IP detection','Only explicitly trusted proxy headers are accepted',data.proxy_effective],track:['Track by IP and username','Record usernames alongside failed-login IPs',s.track_username]};
        Object.entries(rules).forEach(([key,[title,note,on]]) => {
            const el=$(`[data-login-rule="${key}"]`);
            el.querySelector('b').textContent=title; el.querySelector('small').textContent=note;
            badge(el.querySelector('.qs-badge'),on,'Enabled',key==='proxy' ? 'Direct IP':'Disabled');
        });
        const empty = (cols,text) => `<tr><td colspan="${cols}" class="qs-empty">${esc(text)}</td></tr>`;
        const locks = allLocks ? data.locked_ips : data.locked_ips.slice(0,5);
        $('#qs-locked-body').innerHTML = locks.length ? locks.map(e => `<tr><td title="${esc(e.ip)}">${esc(e.ip)}</td><td>${esc(e.username)}</td><td>${format(e.attempts)}</td><td title="${esc(e.until)}">${esc(date(e.until))}</td><td title="${esc(e.reason)}">${esc(e.reason)}</td><td><button type="button" class="qs-small-button" data-unlock-ip="${esc(e.ip)}" aria-label="Unlock ${esc(e.ip)}">Unlock</button></td></tr>`).join('') : empty(6,'No IP addresses are currently locked');
        $('#qs-all-lockouts').textContent = allLocks ? 'Show Less':'View All →';
        $('#qs-all-lockouts').disabled = data.locked_ips.length<=5;
        $('#qs-all-lockouts').setAttribute('aria-expanded',String(allLocks));
        const results = {'Login successful':['Success','qs-good'],'Login attempt blocked':['Failed','qs-danger'],'IP locked out':['Locked','qs-danger'],'IP unlocked':['Unlocked','qs-good'],'Login blocked by lockout':['Blocked','qs-danger'],'XML-RPC access blocked':['Blocked','qs-danger'],'XML-RPC login blocked':['Blocked','qs-danger'],'IP allowlisted':['Allowlisted','qs-good'],'IP allowlist updated':['Updated','qs-blue-badge']};
        $('#qs-login-event-body').innerHTML = data.events.length ? data.events.map(e => {const [label,tone]=results[e.event_name] || ['Recorded','qs-blue-badge'];return `<tr><td>${esc(date(e.event_time))}</td><td title="${esc(e.details)}" class="qs-event-${tone}">${esc(e.event_name)}</td><td title="${esc(e.ip_address)}">${esc(e.ip_address)}</td><td>${esc(e.user_login || '—')}</td><td><span class="qs-badge ${tone}">${label}</span></td></tr>`;}).join('') : empty(5,'No login events recorded in the last 30 days');
        $$('[data-allowlist]').forEach(el => { el.innerHTML = data.allow_ips.length ? data.allow_ips.map(ip=>`<span class="qs-login-chip"><span>${esc(ip)}</span><button type="button" data-remove-ip="${esc(ip)}" aria-label="Remove trusted IP ${esc(ip)}">×</button></span>`).join('') : '<span class="qs-login-chart-note">No trusted IP addresses configured.</span>'; });
        $('#qs-configured-url').textContent = data.login_url;
        const notification=$('#menu-notif');
        if (notification) {
            notification.querySelectorAll('.menu-item').forEach(e=>e.remove());
            const recent = data.events.map(e=>`<div class="menu-item"><span><b>${esc(e.event_name)}</b><small>${esc(e.ip_address)}</small></span></div>`).join('') || '<div class="menu-item">No recent login events.</div>';
            notification.querySelector('.menu-head').insertAdjacentHTML('afterend',recent);
        }
        drawChart();
        const total=series.reduce((sum,[key])=>sum+(data.chart?.[key]||[]).reduce((a,b)=>a+b,0),0);
        $('#qs-login-chart-empty').textContent = data.chart?.error ? 'Unable to load attack trends. Retry loading statistics.' : total ? 'Counts reflect recorded login activity for the selected period.' : 'No login events recorded for this period. Counts reflect recorded activity only.';
    }
    function feedback(message,error=false) {
        if(message) window.GWQSH.toast(message,error?'err':'ok');
        window.GWQSH.toast(message,error ? 'err':'ok');
    }
    async function refresh() {
        const id=++requestId;
        $('#qs-login-chart').setAttribute('aria-busy','true');
        try {
            const response=await window.GWQSH.ajax('get_login_data',{days:$('#qs-login-chart-range').value});
            if(id!==requestId) return;
            if(!response.success) throw new Error(response.data?.message || 'Unable to load login statistics.');
            data=response.data;activePoint=null;update();
        } catch(error) {if(id===requestId) {$('#qs-login-error').hidden=false;feedback(error.message,true);}}
        finally {if(id===requestId) $('#qs-login-chart').removeAttribute('aria-busy');}
    }
    async function mutate(action,values,button,onSuccess,message) {
        if(mutating) {feedback('A change is being saved. Please wait before saving another change.',true);return;}
        mutating=true;++requestId;
        const original=button?.textContent;
        if(button) {button.disabled=true;button.textContent='Saving…';button.setAttribute('aria-busy','true');}
        try {
            const response=await window.GWQSH.ajax(action,values);
            if(!response.success) throw new Error(response.data?.message || 'This change could not be saved.');
            if(response.data?.data) {
                data=response.data.data;
                // Preserve the selected period while fetching its real series after the mutation.
                if(Number($('#qs-login-chart-range').value)!==data.chart.days) await refresh();
            }
            if(onSuccess) await onSuccess(response.data);
            update();feedback(message);
        } catch(error) {feedback(error.message,true);}
        finally {mutating=false;if(button) {button.disabled=false;button.textContent=original;button.removeAttribute('aria-busy');}}
    }
    $('#qs-login-settings-form').addEventListener('submit',event=>{
        event.preventDefault();const form=event.currentTarget; const values={};
        ['max_attempts','time_window','lockout_duration','repeat_lockouts','repeat_duration'].forEach(key=>{values[key]=form.elements[key].value;});
        ['enabled','generic_errors','track_username','email_lockout','xmlrpc'].forEach(key=>{values[key]=form.elements[key].checked ? '1':'0';});
        mutate('save_login_settings',values,form.querySelector('[type="submit"]'),null,'Protection settings saved.');
    });
    $('#qs-login-access-form').addEventListener('submit',event=>{
        event.preventDefault();const form=event.currentTarget;const values=Object.fromEntries(new FormData(form).entries());
        values.custom_enabled=form.elements.custom_enabled.checked ? '1':'0';
        values.role_protection=JSON.stringify(Object.fromEntries([...root.querySelectorAll('[data-role-protection]')].map(input=>[input.dataset.roleProtection,input.checked])));
        mutate('save_login_access',values,form.querySelector('[type="submit"]'),null,'Access settings saved. Keep your updated recovery URL private.');
    });
    const customToggle = $('#qs-login-access-form').elements.custom_enabled;
    customToggle.addEventListener('change', () => {
        $('[data-custom-url-state]').textContent = customToggle.checked ? 'Enabled' : 'Disabled';
    });
    $('.qs-login-add-ip').addEventListener('submit',event=>{
        event.preventDefault();const form=event.currentTarget;
        mutate('add_allow_ip',{ip:form.elements.ip.value.trim()},form.querySelector('[type="submit"]'),response=>{data.allow_ips=response.allow_ips;form.reset();},'Trusted IP added.');
    });
    root.addEventListener('click',event=>{
        const remove=event.target.closest('[data-remove-ip]');
        if(remove) mutate('remove_allow_ip',{ip:remove.dataset.removeIp},remove,response=>{data.allow_ips=response.allow_ips;},'Trusted IP removed.');
        const unlock=event.target.closest('[data-unlock-ip]');
        if(unlock) mutate('unlock_ip',{ip:unlock.dataset.unlockIp},unlock,refresh,'IP unlocked.');
    });
    $('#qs-all-lockouts').addEventListener('click',()=>{allLocks=!allLocks;update();});
    $('#qs-add-ip-focus').addEventListener('click',()=>{$('#qs-new-trusted-ip').scrollIntoView({behavior:window.GWQSH.reduced ? 'auto':'smooth',block:'center'});$('#qs-new-trusted-ip').focus({preventScroll:true});});
    $('#qs-login-chart-range').addEventListener('change',refresh);
    $('#qs-login-retry').addEventListener('click',refresh);
    const copy=async(value,message)=>{if(await window.GWQSH.copy(value,message,null,{silent:true})) feedback(message);else feedback('Clipboard unavailable. Please enable clipboard access and try again.',true);};
    $('#qs-copy-login-url')?.addEventListener('click',()=>copy(data.login_url,'Login URL copied.'));
    $('#qs-copy-recovery')?.addEventListener('click',()=>copy(data.recovery_url,'Private recovery URL copied.'));

    $('#btn-login-recovery-modal')?.addEventListener('click', () => {
        const tpl = document.getElementById('tpl-login-recovery');
        if (!tpl) return;
        const clone = tpl.content.cloneNode(true);
        const div = document.createElement('div');
        div.appendChild(clone);
        window.GWQSH.modal({
            title: 'Login URL & Emergency Recovery',
            wide: false,
            body: div.innerHTML,
            onOpen: bg => {
                bg.querySelector('#qs-copy-login-url')?.addEventListener('click', () => copy(data.login_url, 'Login URL copied.'));
                bg.querySelector('#qs-copy-recovery')?.addEventListener('click', () => copy(data.recovery_url, 'Private recovery URL copied.'));
            }
        });
    });

    $('#btn-country-restrictions-modal')?.addEventListener('click', () => {
        const tpl = document.getElementById('tpl-country-restrictions');
        if (!tpl) return;
        const clone = tpl.content.cloneNode(true);
        const div = document.createElement('div');
        div.appendChild(clone);
        const details = div.querySelector('details');
        if (details) details.open = true;
        window.GWQSH.modal({
            title: 'Country Restrictions',
            wide: true,
            body: div.innerHTML,
            onOpen: bg => {
                const d = bg.querySelector('details');
                if (d) d.open = true;
            }
        });
    });

    $('#btn-ip-reputation-modal')?.addEventListener('click', () => {
        const tpl = document.getElementById('tpl-ip-reputation');
        if (!tpl) return;
        const clone = tpl.content.cloneNode(true);
        const div = document.createElement('div');
        div.appendChild(clone);
        const details = div.querySelector('details');
        if (details) details.open = true;
        window.GWQSH.modal({
            title: 'IP Reputation',
            wide: true,
            body: div.innerHTML,
            onOpen: bg => {
                const d = bg.querySelector('details');
                if (d) d.open = true;
            }
        });
    });
    let lastWidth=0, lastHeight=0;
    new ResizeObserver(entries=>{
        const width=entries[0].contentRect.width;
        const height=entries[0].contentRect.height;
        if(Math.abs(width-lastWidth)<1 && Math.abs(height-lastHeight)<1) return;
        lastWidth=width;lastHeight=height;
        requestAnimationFrame(drawChart);
    }).observe($('#qs-login-chart'));
    update();
})();
