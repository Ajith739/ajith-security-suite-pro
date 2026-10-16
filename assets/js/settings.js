/* ============================================================
   Gracewell Security Suite Pro â€” Settings page logic
   Depends on: qs-core.js (loaded before this, both deferred)
   ============================================================ */

document.addEventListener('DOMContentLoaded', function () {
    const { $, $$, toast, modal, confirm, esc, fmt } = GWQSH;
    const D = window.GWQSH_DATA || {};

    /* ---------- persisted settings (localStorage + backend) ---------- */
    const KEY = 'gwqsh-settings';

    const DEF = {
        status: true, autoupdate: true, retention: '30', language: 'en_US', timezone: 'Asia/Kolkata',
        telemetry: false, notice: true, proxy: false, https: true,
        theme: 'light', compact: false, anim: true, tips: true,
        debug: false, proxyheader: 'xff', uninstall: false
    };

    let S = Object.assign({}, DEF, D.settings || {});
    document.addEventListener('gwqsh:settings-saved',event=>{Object.assign(S,event.detail || {});paint();});

    // cross-page prefs
    S.theme = GWQSH.store.get('gwqsh-theme', S.theme);
    S.compact = GWQSH.store.get('gwqsh-density', S.compact ? 'compact' : 'comfortable') === 'compact';
    S.anim = GWQSH.store.get('gwqsh-anim', S.anim ? '1' : '0') === '1';
    S.tips = GWQSH.store.get('gwqsh-tips', S.tips ? '1' : '0') === '1';

    const LABEL = {
        geo_enabled: 'Public IP country lookup', status: 'Plugin status', autoupdate: 'Automatic updates', retention: 'Data retention',
        language: 'Plugin language', timezone: 'Timezone', telemetry: 'Telemetry',
        notice: 'Admin notice for critical issues', proxy: 'IP detection via proxy',
        https: 'HTTPS for plugin pages',
        theme: 'Color scheme', compact: 'Compact layout', anim: 'Animated charts',
        tips: 'Security tips', debug: 'Debug logging', proxyheader: 'Proxy header',
        uninstall: 'Delete data on uninstall'
    };

    function paint() {
        $$('[data-key]').forEach(el => {
            const k = el.dataset.key;
            if (el.classList.contains('switch')) GWQSH.setSwitch(el, !!S[k]);
            else el.value = S[k];
        });
        if ($('#proxyheader')) $('#proxyheader').disabled = !S.proxy;
        const updates = $('[data-key="autoupdate"]');
        if (updates && D.can_manage_updates === false) {
            updates.disabled = true;
            updates.title = 'Plugin updates require WordPress update permissions; network updates require network administration.';
            if (updates.closest('.set-row')?.querySelector('.txt small')) {
                updates.closest('.set-row').querySelector('.txt small').textContent = updates.title;
            }
        }
        const unavailable = {telemetry:'No telemetry service is configured.', language:'The interface follows WordPress; plugin translations are unavailable.', timezone:'Logs and cron use the WordPress site timezone.', https:'HTTPS is managed by WordPress and the web server.', debug:'A separate plugin debug logger is unavailable.'};
        Object.entries(unavailable).forEach(([key, reason]) => {
            const control = $('[data-key="' + key + '"]');
            if (control) {
                control.disabled = true; control.title = reason;
                if (control.classList.contains('switch')) GWQSH.setSwitch(control, false);
                const siteValue = key === 'language' ? D.site_locale : key === 'timezone' ? D.site_timezone : '';
                if (siteValue && control.options) {
                    if (![...control.options].some(o => o.value === siteValue)) control.add(new Option(siteValue, siteValue));
                    control.value = siteValue;
                }
                const row = control.closest('.set-row');
                if (row) {
                    const sm = row.querySelector('.txt small');
                    if (sm) sm.textContent = reason;
                    const badge = row.querySelector('.switch-pill');
                    if (badge) { badge.textContent = 'Unavailable'; badge.className = 'pill switch-pill p-gray'; }
                }
            }
        });
        if (!$('#retention').querySelector('option[value="' + S.retention + '"]')) $('#retention').add(new Option(S.retention === '0' ? 'Unlimited' : S.retention + ' days', S.retention));
        $('#retention').value = S.retention;
    }

    let saveQueue = Promise.resolve();
    document.addEventListener('gwqsh:theme', () => { S.theme = GWQSH.store.get('gwqsh-theme', S.theme); paint(); });
    async function persist(settings = S) {
        const res = await GWQSH.ajax('save_settings', { settings });
        if (!res.success) { toast(res.data?.message || 'Could not save settings', 'err'); return false; }
        applySaved(res.data.settings);

        // Save to WordPress database
        return true;
    }

    function applySaved(saved) {
        S = saved;
        GWQSH.store.set(KEY, JSON.stringify(S));
        GWQSH.store.set('gwqsh-theme', S.theme);
        GWQSH.store.set('gwqsh-density', S.compact ? 'compact' : 'comfortable');
        GWQSH.store.set('gwqsh-anim', S.anim ? '1' : '0');
        GWQSH.store.set('gwqsh-tips', S.tips ? '1' : '0');
        const before = document.documentElement.dataset.theme;
        GWQSH.applyPrefs();
        document.dispatchEvent(new CustomEvent('gwqsh:theme'));
        if (before !== document.documentElement.dataset.theme && GWQSH.rebuildHero) GWQSH.rebuildHero();

    }

    function save(k, v) {
        const task = () => saveOne(k, v);
        saveQueue = saveQueue.then(task, task);
        return saveQueue;
    }
    async function saveOne(k, v) {
        const prev = S[k];
        S[k] = v;
        if (!await persist({ [k]: v })) { S[k] = prev; paint(); return false; }
        paint();
        const txt = typeof v === 'boolean' ? LABEL[k] + (v ? ' enabled' : ' disabled') : LABEL[k] + ' saved';
        toast(txt, 'ok', {
            label: 'Undo',
            fn: async () => {
                await save(k, prev);
            }
        });
    }

    paint();

    document.addEventListener('gwqsh:toggle', e => {
        const k = e.target.dataset.key;
        if (!k) return;

        if (k === 'geo_enabled' && e.detail.on) {
            GWQSH.setSwitch(e.target, false);
            confirm('Enable public IP country lookup?', 'Public IPs from recorded security events will be sent to ipwho.is for country attribution.', 'Enable lookup', () => save('geo_enabled', true));
            return;
        }

        if (k === 'status' && !e.detail.on) {
            GWQSH.setSwitch(e.target, true);
            confirm('Turn off Security Suite Pro?',
                'Login and firewall protections will stop until you turn it back on. Enrolled users will still need their two-factor credentials.',
                'Turn off', () => save('status', false), true);
            return;
        }

        if (k === 'uninstall' && e.detail.on) {
            GWQSH.setSwitch(e.target, false);
            confirm('Delete data on uninstall?',
                'If you delete the plugin, every setting, log and scan result is removed and can\u2019t be recovered.',
                'Turn on', () => save('uninstall', true), true);
            return;
        }

        save(k, e.detail.on);
    });

    $$('select[data-key]').forEach(el => el.addEventListener('change', () => save(el.dataset.key, el.value)));

    /* ---------- tabs (optional in 10-card dashboard layout) ---------- */
    const OVERVIEW = ['general', 'security'];

    function showTab(t, focus) {
        if (!$('.tabs-scroll')) return;
        $$('.tabs-scroll .seg-btn').forEach(b => {
            const selected = b.dataset.tab === t;
            b.setAttribute('aria-selected', String(selected));
            b.tabIndex = selected ? 0 : -1;
        });
        const shown = t === 'general' ? OVERVIEW : [t];
        $$('.s-card').forEach(c => {
            c.classList.toggle('hide', !shown.includes(c.dataset.tab));
        });
        $('#panels')?.classList.toggle('single', shown.length === 1);
        $('#panels')?.setAttribute('aria-labelledby', 't-' + t);
        if (GWQSH.animOn()) GWQSH_Motion.from($$('.s-card:not(.hide)'), { y: 10, opacity: 0, duration: .35, stagger: .05, ease: 'power2.out', clearProps: 'all' });
        if (focus) history.replaceState(null, '', '#' + t);
    }

    $('.tabs-scroll')?.addEventListener('click', e => {
        const b = e.target.closest('.seg-btn');
        if (b) showTab(b.dataset.tab, true);
    });

    $('.tabs-scroll')?.addEventListener('keydown', e => {
        if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
        e.preventDefault();
        const bs = $$('.tabs-scroll .seg-btn');
        const i = bs.findIndex(b => b.getAttribute('aria-selected') === 'true');
        const n = e.key === 'Home' ? bs[0] : e.key === 'End' ? bs[bs.length - 1] : bs[(i + (e.key === 'ArrowRight' ? 1 : -1) + bs.length) % bs.length];
        n.focus();
        n.scrollIntoView({ block: 'nearest', inline: 'nearest' });
        showTab(n.dataset.tab, true);
    });

    if ($('.tabs-scroll')) {
        const h = location.hash.slice(1);
        showTab(['security', 'appearance', 'advanced', 'tools'].includes(h) ? h : 'general');
        if (h === 'importexport') { showTab('tools'); setTimeout(() => $('#importexport')?.scrollIntoView({ behavior: 'smooth' }), 300); }
    }

    /* ---------- import / export / reset ---------- */
    $('#exportS')?.addEventListener('click', async () => {
        const result=await GWQSH.ajax('config_export');if(!result.success){toast(result.data?.message || 'Export failed.','err');return;}
        GWQSH.download('gracewell-security-suite-pro-config.json',JSON.stringify(result.data,null,2),'application/json');toast('Configuration exported');
    });

    $('#importS')?.addEventListener('click', () => $('#importFile')?.click());

    $('#importFile')?.addEventListener('change', e => {
        const f = e.target.files[0];
        if (!f) return;
        if (f.size > 1048576) { toast('Settings imports must be smaller than 1 MB.', 'err'); e.target.value = ''; return; }
        const rd = new FileReader();
        rd.onload = () => {
            const task = async () => {
            const previous = Object.assign({}, S);
            try {
                const j = JSON.parse(rd.result);
                if(j.format===2 && j.sections){const imported=await GWQSH.ajax('config_import',{payload:j});if(!imported.success)throw new Error(imported.data?.message || 'Import failed.');toast('Configuration imported');location.reload();return;}
                const inc = j.settings || j;
                const known = Object.keys(DEF).filter(k => k in inc);
                if (!known.length) throw 0;
                known.forEach(k => { if (typeof DEF[k] === 'boolean' && typeof inc[k] !== 'boolean') throw new Error('Invalid switch value'); S[k] = typeof DEF[k] === 'boolean' ? inc[k] : String(inc[k]); });
                if (!await persist()) { S = previous; paint(); return; }
                paint();
                toast(known.length + ' settings imported from ' + f.name);
            } catch (err) {
                S = previous; paint();
                toast('That file isn\u2019t a Security Suite Pro settings export. Choose the .json file from \u201cExport Settings\u201d.', 'err');
            }
            e.target.value = '';
            };
            saveQueue = saveQueue.then(task, task);
        };
        rd.readAsText(f);
    });

    $('#resetS').addEventListener('click', () => confirm('Reset general settings?', 'Restore default plugin preferences, color scheme, retention and automatic update selection.', 'Reset Defaults', () => {
        const task = async () => {
            const result = await GWQSH.ajax('reset_settings');
            if (!result.success) { toast(result.data?.message || 'Could not reset settings', 'err'); return false; }
            applySaved(result.data.settings); paint(); toast('General settings reset'); return true;
        };
        saveQueue = saveQueue.then(task, task);
        return saveQueue;
    }, true));

    /* ---------- tools ---------- */
    $('#rebuild').addEventListener('click', () =>
        confirm('Open the integrity scanner?',
            'Use File Integrity to run a scan and review its findings before trusting an inspected baseline.',
            'Open File Integrity',
            async () => {
                window.location.href = window.GWQSH_PAGES['file-integrity'];
            }));

    $('#clearLogs').addEventListener('click', () =>
        confirm('Clear all activity logs?',
            'All stored activity events will be permanently deleted. Export them first if you need a copy.',
            'Clear logs',
            async () => {
                if (window.GWQSH && GWQSH.ajax) {
                    const savedResponse = await GWQSH.ajax('clear_activity_logs');
                    if (!savedResponse.success) { toast(savedResponse.data?.message || 'Could not complete this action', 'err'); return false; }
                }
                toast('Activity logs cleared', 'warn');
            },
            true));
});
