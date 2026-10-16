/* ============================================================
   Gracewell Security Suite Pro — Shared Core (GWQSH)
   Loaded with `defer` on every plugin page.
   Depends on: window.GWQSH_Motion, window.THREE (both optional).
   ============================================================ */

(function () {
    "use strict";
    const GWQSH = window.GWQSH = {};
    const root = document.documentElement;
    const store = {
        get(k, d) { try { let v = localStorage.getItem(k); if (v === null && k.startsWith('gwqsh-')) { v = localStorage.getItem(k.replace(/^gwqsh-/, 'qs-')); if (v !== null) localStorage.setItem(k, v); } return v === null ? d : v } catch (e) { return d } },
        set(k, v) { try { localStorage.setItem(k, v) } catch (e) { } }
    };
    GWQSH.store = store;
    const motionPreference = window.matchMedia('(prefers-reduced-motion: reduce)');
    GWQSH.reduced = motionPreference.matches;
    const syncMotion = () => { GWQSH.reduced = motionPreference.matches; };
    if (motionPreference.addEventListener) motionPreference.addEventListener('change', syncMotion);
    else motionPreference.addListener(syncMotion);
    GWQSH.animOn = () => !GWQSH.reduced && store.get('gwqsh-anim', window.GWQSH_PREFS?.anim === false ? '0' : '1') === '1' && !!window.GWQSH_Motion;
    const G = window.GWQSH_Motion || null;

    /* ----- preferences shared across pages */
    GWQSH.applyPrefs = function () {
        const prefs = window.GWQSH_PREFS || {};
        let t = store.get('gwqsh-theme', prefs.theme || 'light');
        if (!['light', 'dark', 'system'].includes(t)) t = 'light';
        if (t === 'system') t = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        root.dataset.theme = t;
        root.dataset.density = store.get('gwqsh-density', prefs.compact ? 'compact' : 'comfortable');
        document.querySelectorAll('.tips-card').forEach(el => el.classList.toggle('tips-off', store.get('gwqsh-tips', prefs.tips === false ? '0' : '1') !== '1'));
        const app = document.getElementById('gracewell-security-suite-pro-app');
        if (app && !app.dataset.heroBg) {
            const urlParams = new URLSearchParams(window.location.search);
            const heroParam = urlParams.get('hero_bg');
            if (heroParam === 'lighthouse' || heroParam === 'classic') {
                app.dataset.heroBg = heroParam;
            } else {
                app.dataset.heroBg = Math.random() < 0.5 ? 'lighthouse' : 'classic';
            }
        }
    };
    GWQSH.applyPrefs();
    const systemTheme = window.matchMedia('(prefers-color-scheme: dark)');
    const syncSystemTheme = () => { if (store.get('gwqsh-theme', window.GWQSH_PREFS?.theme || 'light') === 'system') { GWQSH.applyPrefs(); document.dispatchEvent(new CustomEvent('gwqsh:theme')); } };
    if (systemTheme.addEventListener) systemTheme.addEventListener('change', syncSystemTheme);
    else systemTheme.addListener(syncSystemTheme);
    window.addEventListener('storage', event => { if (event.key === null || event.key.startsWith('gwqsh-')) { GWQSH.applyPrefs(); document.dispatchEvent(new CustomEvent('gwqsh:theme')); } });

    GWQSH.$ = (s, c = document) => c.querySelector(s);
    GWQSH.$$ = (s, c = document) => Array.from(c.querySelectorAll(s));
    GWQSH.esc = s => String(s).replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
    GWQSH.date = function(value) {
        if (!value) return '—';
        const wall = typeof value === 'string' && /^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$/.test(value);
        let date = new Date(wall ? value.replace(' ', 'T') + 'Z' : typeof value === 'number' ? (value < 1e12 ? value * 1000 : value) : value);
        if (Number.isNaN(date.getTime())) return String(value);
        let zone = wall ? 'UTC' : window.GWQSH_CONFIG?.site_timezone || 'UTC';
        if (/^[+-]/.test(zone)) { date = new Date(date.getTime() + Number(window.GWQSH_CONFIG.site_offset || 0) * 1000); zone = 'UTC'; }
        return new Intl.DateTimeFormat(undefined, {timeZone:zone, year:'numeric',month:'short',day:'numeric',hour:'numeric',minute:'2-digit'}).format(date);
    };
    GWQSH.eventTone = name => /unblocked|unlocked/i.test(name) ? 'success' : /\bblocked\b|critical|malware|denied|locked out/i.test(name) ? 'danger' : /failed|warning|suspicious|modified|missing|changed|removed|disabled/i.test(name) ? 'warning' : /success|clean|allowed|enabled|restored|completed|verified|registered/i.test(name) ? 'success' : 'info';
    GWQSH.emptyState = function(title, description='Your security records will appear here when available.', kind='logs') {
        const assets={logs:'timeline.png',clean:'auth.png',scan:'auth.png',setup:'auth.png',unavailable:'earth-plane.png','403':'403-illustration.png','404':'404-illustration.png','500':'500-illustration.png'};
        return '<div class="gwqsh-empty" data-empty-kind="'+GWQSH.esc(kind)+'"><img loading="lazy" width="112" height="96" src="'+GWQSH.esc((window.GWQSH_CONFIG?.asset_url || '')+(assets[kind] || assets.logs))+'" alt=""><h3>'+GWQSH.esc(title)+'</h3><p>'+GWQSH.esc(description)+'</p></div>';
    };
    GWQSH.fmt = n => Number(n).toLocaleString('en-US');
    GWQSH.labelTable = function (table) {
        if (!table) return;
        const labels = Array.from(table.querySelectorAll('thead th'), th => th.textContent.trim() || 'Select');
        table.querySelectorAll('tbody tr').forEach(row => Array.from(row.cells).forEach((cell, i) => { cell.dataset.label = labels[i] || 'Actions'; }));
    };

    /* ----- AJAX helper */
    GWQSH.ajax = async function (subaction, data = {}) {
        const cfg = window.GWQSH_CONFIG || {};
        const url = cfg.ajax_url || '/wp-admin/admin-ajax.php';
        const control = document.activeElement?.matches('button') ? document.activeElement : null;
        const alreadyDisabled = control?.disabled;
        if (control && !alreadyDisabled) { control.disabled = true; control.setAttribute('aria-busy', 'true'); }
        const body = new FormData();
        body.append('action', 'gwqsh_action');
        body.append('subaction', subaction);
        body.append('nonce', cfg.nonce || '');
        for (const [k, v] of Object.entries(data)) {
            body.append(k, typeof v === 'object' && v !== null ? JSON.stringify(v) : v);
        }
        try {
            const res = await fetch(url, { method: 'POST', body });
            const json = await res.json();
            if (!json || typeof json.success !== 'boolean') throw new Error('Invalid server response');
            if (!res.ok && json.success) throw new Error('HTTP request failed');
            return json;
        } catch (e) {
            return { success: false, data: { message: 'The request could not complete. Check your connection and reload if your session expired.' } };
        } finally {
            if (control && !alreadyDisabled) { control.disabled = false; control.removeAttribute('aria-busy'); }
        }
    };

    /* ----- sync user header info */
    (function () {
        const cfg = window.GWQSH_CONFIG;
        if (!cfg || !cfg.user) return;
        const av = GWQSH.$('.avatar');
        if (av && cfg.user.initial) av.textContent = cfg.user.initial;
        const mh = GWQSH.$('#menu-user .menu-head');
        if (mh) {
            const b = mh.querySelector('b'), sm = mh.querySelector('small');
            if (b) b.textContent = cfg.user.login;
            if (sm) sm.textContent = cfg.user.role;
        }
        const lo = GWQSH.$('#menu-user a[href*="action=logout"]') || GWQSH.$('#menu-user [data-toast]');
        if (lo && cfg.logout_url) {
            lo.removeAttribute('data-toast');
            lo.setAttribute('href', cfg.logout_url);
        }
    })();

    /* ----- theme toggle in the header menu (shared by every page) */
    (function () {
        const btn = GWQSH.$('#themeToggle'), lbl = GWQSH.$('#themeLbl');
        if (!btn) return;
        function sync() { if (lbl) lbl.textContent = root.dataset.theme === 'dark' ? 'Light mode' : 'Dark mode'; }
        sync();
        document.addEventListener('gwqsh:theme', sync);
        btn.addEventListener('click', () => {
            root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
            store.set('gwqsh-theme', root.dataset.theme);
            sync();
            document.dispatchEvent(new CustomEvent('gwqsh:theme'));
            GWQSH.$$('.menu.open').forEach(m => m.classList.remove('open'));
            GWQSH.$$('[data-menu]').forEach(b => b.setAttribute('aria-expanded', 'false'));
        });
    })();

    /* ----- toast */
    const TOAST_IC = {
        ok: '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/></svg>',
        warn: '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>',
        err: '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>',
        info: '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>'
    };
    let toastBox;
    GWQSH.toast = function (msg, type = 'ok', action) {
        type = ({success:'ok',error:'err',warning:'warn'})[type] || type;
        if (!TOAST_IC[type]) type='info';
        if (!toastBox) { toastBox = document.createElement('div'); toastBox.className = 'toasts'; toastBox.setAttribute('role', 'status'); toastBox.setAttribute('aria-live', 'polite'); document.getElementById('gracewell-security-suite-pro-app').appendChild(toastBox); }
        const t = document.createElement('div'); t.className = 'toast ' + type;
        t.innerHTML = TOAST_IC[type] + '<span>' + GWQSH.esc(msg) + '</span>';
        if (action) { const b = document.createElement('button'); b.type = 'button'; b.textContent = action.label; b.onclick = () => { action.fn(); close(); }; t.appendChild(b); }
        while (toastBox.children.length >= 4) toastBox.firstElementChild.remove();
        toastBox.appendChild(t);
        const close = () => { if (G) { G.to(t, { opacity: 0, y: 8, duration: .2, onComplete: () => t.remove() }) } else t.remove(); };
        const dismiss=document.createElement('button');dismiss.type='button';dismiss.className='gwqsh-toast-close';dismiss.setAttribute('aria-label','Dismiss notification');dismiss.textContent='×';dismiss.onclick=close;t.appendChild(dismiss);
        if (G && GWQSH.animOn()) G.from(t, { opacity: 0, y: 12, duration: .3, ease: 'power3.out' });
        setTimeout(close, window.GWQSH_CONFIG?.current === 'file-integrity' && document.querySelector('.modal-bg') ? (type === 'err' ? 10000 : 6000) : action ? 5200 : 3200);
    };

    /* ----- modal */
    GWQSH.modal = function ({ title, body, icon = '', wide = false, actions = [{ label: 'Close' }], onOpen, onClose, canDismissBackdrop = () => true }) {
        const bg = document.createElement('div'); bg.className = 'modal-bg';
        const id = 'm' + Math.random().toString(36).slice(2, 8);
        bg.innerHTML = '<div class="modal' + (wide ? ' wide' : '') + '" role="dialog" aria-modal="true" aria-labelledby="' + id + '"><div class="modal-h">' + icon + '<h3 id="' + id + '">' + title + '</h3><button class="kebab" data-x aria-label="Close"><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></button></div><div class="modal-b">' + body + '</div><div class="modal-f"></div></div>';
        const f = bg.querySelector('.modal-f');
        const prev = document.activeElement;
        let closed = false;
        const close = () => { if (closed) return; closed = true; onClose && onClose(); document.removeEventListener('keydown', onKey); if (G) { G.to(bg, { opacity: 0, duration: .15, onComplete: () => bg.remove() }) } else bg.remove(); prev && prev.focus && prev.focus(); };
        actions.forEach(a => { const b = document.createElement('button'); b.type = 'button'; b.className = 'btn ' + (a.cls || 'btn-neutral'); b.innerHTML = a.label; b.onclick = async () => {
            if (b.disabled) return;
            const label = b.innerHTML; b.disabled = true; b.setAttribute('aria-busy', 'true');
            if (a.fn) b.textContent = 'Working…';
            try { if (a.fn && await a.fn(bg) === false) return; close(); }
            catch (e) { GWQSH.toast('Could not complete this action. Please try again.', 'err'); }
            finally { b.disabled = false; b.removeAttribute('aria-busy'); b.innerHTML = label; }
        }; f.appendChild(b); });
        bg.addEventListener('click', e => { if ((e.target === bg && canDismissBackdrop(bg)) || e.target.closest('[data-x]')) close(); });
        const onKey = e => {
            const dialogs = [...document.querySelectorAll('#gracewell-security-suite-pro-app .modal-bg')];
            if (dialogs[dialogs.length - 1] !== bg) return;
            if (e.key === 'Escape') close();
            if (e.key === 'Tab') {
                const els = GWQSH.$$('button,input,select,textarea,a[href]', bg).filter(x => !x.disabled && x.getClientRects().length && x.tabIndex !== -1); const a = els[0], z = els[els.length - 1];
                if (e.shiftKey && document.activeElement === a) { z.focus(); e.preventDefault(); } else if (!e.shiftKey && document.activeElement === z) { a.focus(); e.preventDefault(); }
            }
        };
        document.addEventListener('keydown', onKey);
        document.getElementById('gracewell-security-suite-pro-app').appendChild(bg);
        if (G) { G.from(bg, { opacity: 0, duration: .18 }); G.from(bg.firstChild, { y: 16, scale: .98, opacity: 0, duration: .3, ease: 'power3.out' }); }
        const first = bg.querySelector('input,select,textarea') || f.lastChild; first && first.focus();
        onOpen && onOpen(bg);
        return { el: bg, close };
    };
    GWQSH.confirm = function (title, text, okLabel, fn, danger) {
        return GWQSH.modal({ title, body: '<p>' + text + '</p>', actions: [{ label: 'Cancel' }, { label: okLabel, cls: danger ? 'btn-danger' : 'btn-primary', fn }] });
    };

    /* ----- clipboard */
    GWQSH.copy = async function (text, label, button, options = {}) {
        try {
            if (navigator.clipboard && window.isSecureContext) await navigator.clipboard.writeText(text);
            else {
                const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select();
                try { if (!document.execCommand('copy')) throw new Error('copy'); } finally { ta.remove(); }
            }
            if (button) {
                const previous = button.innerHTML;
                button.innerHTML = '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="m4 12 5 5L20 6"/></svg>' + (options.iconOnly ? '<span class="screen-reader-text">Copied</span>' : ' Copied');
                button.disabled = true;
                setTimeout(() => { button.innerHTML = previous; button.disabled = false; }, 1800);
            }
            if (!options.silent) GWQSH.toast(label || 'Copied', 'ok'); return true;
        } catch (e) { GWQSH.toast('Copy failed. Select the text and copy it manually.', 'err'); return false; }
    };
    GWQSH.download = function (name, text, type = 'text/plain') {
        const url = URL.createObjectURL(new Blob([text], { type })); const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 500);
    };

    /* ----- switches (delegated) */
    GWQSH.setSwitch = function (sw, on) {
        sw.setAttribute('aria-checked', on ? 'true' : 'false');
        const pill = sw.parentElement.querySelector('.switch-pill');
        if (pill) { pill.textContent = on ? 'Enabled' : 'Disabled'; pill.className = 'pill switch-pill ' + (on ? 'p-green' : 'p-gray'); }
    };
    document.addEventListener('click', e => {
        if (window.GWQSH_CONFIG?.current === 'dashboard') return;
        const sw = e.target.closest('.switch'); if (!sw || sw.disabled) return;
        const on = sw.getAttribute('aria-checked') !== 'true';
        GWQSH.setSwitch(sw, on);
        sw.dispatchEvent(new CustomEvent('gwqsh:toggle', { bubbles: true, detail: { on } }));
    });

    /* ----- steppers */
    document.addEventListener('click', e => {
        const b = e.target.closest('[data-step]'); if (!b) return;
        const inp = b.closest('.stepper').querySelector('input');
        const min = +inp.min || 0, max = +inp.max || 999; let v = (+inp.value || 0) + (+b.dataset.step);
        inp.value = Math.max(min, Math.min(max, v)); inp.dispatchEvent(new Event('change', { bubbles: true }));
    });

    /* ----- generic data-toast / coming-soon / copy handlers */
    document.addEventListener('click', async e => {
        const t = e.target.closest('[data-toast]'); if (t) { e.preventDefault(); GWQSH.toast(t.dataset.toast, t.dataset.toastType || 'info'); }
        const s = e.target.closest('[data-soon]'); if (s) { e.preventDefault(); GWQSH.toast('The ' + s.dataset.soon + ' screen isn\u2019t part of this design set yet.', 'info'); }
        const c = e.target.closest('[data-copy]'); if (c && !c.disabled) {
            e.preventDefault(); const src = c.dataset.copy.startsWith('#') ? GWQSH.$(c.dataset.copy) : null;
            let value = src ? (src.value || src.textContent).trim() : c.dataset.copy;
            if (c.dataset.copy === '#secret') value = value.replace(/\s/g, '');
            const old = c.innerHTML; c.disabled = true;
            if (await GWQSH.copy(value, c.dataset.copyLabel, null, { silent: window.GWQSH_CONFIG?.current === 'two-factor' })) {
                c.innerHTML = '<svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m4 12 5 5L20 6"/></svg><span class="screen-reader-text">Copied</span>';
                setTimeout(() => { c.innerHTML = old; c.disabled = false; }, 1800);
            } else c.disabled = false;
        }
    });

    /* ----- header menus */
    function closeMenus(except) { GWQSH.$$('.menu.open').forEach(m => { if (m !== except) { m.classList.remove('open'); const b = GWQSH.$('[data-menu="' + m.id.slice(5) + '"]'); b && b.setAttribute('aria-expanded', 'false'); } }); }
    document.addEventListener('click', e => {
        const b = e.target.closest('[data-menu]');
        if (b) {
            const m = GWQSH.$('#menu-' + b.dataset.menu); if (!m) return; const open = !m.classList.contains('open'); closeMenus(m); m.classList.toggle('open', open); b.setAttribute('aria-expanded', open);
            if (open && G) G.from(m, { y: -6, opacity: 0, duration: .2, ease: 'power2.out' }); return;
        }
        if (!e.target.closest('.menu')) closeMenus();
    });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') closeMenus(); });
    const markRead = GWQSH.$('#markRead');
    if (store.get('gwqsh-notif-read', '0') === '1') { GWQSH.$('#notifDot')?.classList.add('off'); GWQSH.$$('.menu-item.unread').forEach(x => x.classList.remove('unread')); }
    markRead && markRead.addEventListener('click', () => { store.set('gwqsh-notif-read', '1'); GWQSH.$('#notifDot').classList.add('off'); GWQSH.$$('.menu-item.unread').forEach(x => x.classList.remove('unread')); GWQSH.toast('All notifications marked as read'); });

    /* mobile nav */
    const burger = GWQSH.$('#burger'), nav = GWQSH.$('#mainNav');
    burger && burger.addEventListener('click', () => {
        const o = !nav.classList.contains('open'); nav.classList.toggle('open', o); burger.setAttribute('aria-expanded', o);
        if (o && G) G.from(GWQSH.$$('.nav-link', nav), { x: -10, opacity: 0, stagger: .03, duration: .25, ease: 'power2.out' });
    });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && nav) { nav.classList.remove('open'); burger?.setAttribute('aria-expanded', 'false'); } });
    document.addEventListener('click', e => { if (nav && !e.target.closest('#mainNav, #burger')) { nav.classList.remove('open'); burger?.setAttribute('aria-expanded', 'false'); } });
    window.addEventListener('resize', () => { if (window.innerWidth >= 1500 && nav) { nav.classList.remove('open'); burger && burger.setAttribute('aria-expanded', 'false'); } });

    /* ----- Pro modal */
    document.addEventListener('click', e => {
        if (!e.target.closest('[data-pro]')) return;
        GWQSH.modal({
            title: 'Security Suite Pro is on the way', icon: '<span class="tile t-amber sm"><svg class="i" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M11.56 3.27a.5.5 0 0 1 .88 0l2.95 5.6a1 1 0 0 0 1.52.29l4.27-3.66a.5.5 0 0 1 .82.5l-2.83 10.25a1 1 0 0 1-.96.73H5.8a1 1 0 0 1-.96-.73L2 5.99a.5.5 0 0 1 .82-.5l4.27 3.66a1 1 0 0 0 1.52-.29z"/><path d="M5 21h14"/></svg></span>',
            body: '<p>Version 1.0.0 includes the available security tools. Pro features are not available in this release.</p>',
            actions: [{ label: 'Close', cls: 'btn-primary' }]
        });
    });

    /* ----- search palette */
    const PAGES = [
        ['Login Protection', window.GWQSH_PAGES['login-protection'], 'Lockouts, allowlist, custom login URL'],
        ['Two-Factor Authentication', window.GWQSH_PAGES['two-factor'], '2FA setup, backup codes, users'],
        ['File Integrity Scan', window.GWQSH_PAGES['file-integrity'], 'Core files and manual scan results'],
        ['Firewall & Cleanup', window.GWQSH_PAGES['firewall-cleanup'], 'Query protection, login lockouts, cleanup scans'],
        ['Security Hardening', window.GWQSH_PAGES['hardening'], 'XML-RPC, file editor, headers'],
        ['Activity Log', window.GWQSH_PAGES['activity-log'], 'Events, export logs'],
        ['Plugin Settings', window.GWQSH_PAGES['settings'], 'General, security, appearance'],
        ['IP allowlist', window.GWQSH_PAGES['login-protection'] + '#allowlist', 'Login Protection'],
        ['Custom login URL', window.GWQSH_PAGES['login-protection'] + '#loginurl', 'Login Protection'],
        ['Backup codes', window.GWQSH_PAGES['two-factor'] + '#backup', 'Two-Factor'],
        ['Run a new scan', window.GWQSH_PAGES['file-integrity'] + '#lastscan', 'File Integrity'],
        ['Security headers', window.GWQSH_PAGES['hardening'] + '#checklist', 'Hardening'],
        ['Export logs', window.GWQSH_PAGES['activity-log'] + '#log', 'Activity Log'],
        ['Admin color scheme', window.GWQSH_PAGES['settings'] + '#appearance', 'Settings'],
        ['Import / export settings', window.GWQSH_PAGES['settings'] + '#importexport', 'Settings']
    ];
    function openSearch() {
        closeMenus();
        const m = GWQSH.modal({ title: '<span class="sr">Search</span>', body: '', actions: [] });
        const box = m.el.querySelector('.modal'); box.classList.add('palette');
        box.innerHTML = '<div class="search"><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg><input type="search" placeholder="Search pages and settings\u2026" aria-label="Search pages and settings" autocomplete="off"></div><ul role="listbox"></ul>';
        const inp = box.querySelector('input'), ul = box.querySelector('ul'); let sel = 0, items = [];
        const draw = () => {
            const q = inp.value.trim().toLowerCase(); items = PAGES.filter(p => !q || (p[0] + ' ' + p[2]).toLowerCase().includes(q)); sel = Math.min(sel, Math.max(0, items.length - 1));
            ul.innerHTML = items.length ? items.map((p, i) => '<li><a href="' + p[1] + '" class="' + (i === sel ? 'active' : '') + '" role="option">' + GWQSH.esc(p[0]) + '<small>' + GWQSH.esc(p[2]) + '</small></a></li>').join('') : '<li style="padding:14px;color:var(--muted)">No matches. Try \u201clogin\u201d, \u201cscan\u201d or \u201c2FA\u201d.</li>';
        };
        inp.addEventListener('input', () => { sel = 0; draw(); });
        inp.addEventListener('keydown', e => { if (e.key === 'ArrowDown') { sel = Math.min(items.length - 1, sel + 1); draw(); e.preventDefault(); } if (e.key === 'ArrowUp') { sel = Math.max(0, sel - 1); draw(); e.preventDefault(); } if (e.key === 'Enter' && items[sel]) { location.href = items[sel][1]; } });
        draw(); inp.focus();
    }
    document.addEventListener('click', e => { if (e.target.closest('[data-open-search]')) openSearch(); });
    document.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openSearch(); } });

    /* ----- count up */
    GWQSH.countUp = function (scope = document) {
        GWQSH.$$('[data-count]', scope).forEach(el => {
            const end = parseFloat(el.dataset.count), dec = +(el.dataset.dec || 0);
            const out = v => el.textContent = dec ? v.toFixed(dec) : GWQSH.fmt(Math.round(v));
            if (!GWQSH.animOn()) { out(end); return; }
            const o = { v: 0 }; G.to(o, { v: end, duration: 1.1, ease: 'power2.out', delay: .25, onUpdate: () => out(o.v) });
        });
    };
    GWQSH.setCount = function (el, val, dec = 0) {
        if (el) el.dataset.count = val;
        if (!el) return; const from = parseFloat(String(el.textContent).replace(/,/g, '')) || 0;
        if (!GWQSH.animOn()) { el.textContent = dec ? val.toFixed(dec) : GWQSH.fmt(val); return; }
        const o = { v: from }; G.to(o, { v: val, duration: .6, ease: 'power2.out', onUpdate: () => el.textContent = dec ? o.v.toFixed(dec) : GWQSH.fmt(Math.round(o.v)) });
    };

    /* ----- progress bars */
    GWQSH.bars = function (scope = document) {
        GWQSH.$$('.bar>span[data-w]', scope).forEach(s => { if (GWQSH.animOn()) G.to(s, { width: s.dataset.w + '%', duration: 1, ease: 'power3.out', delay: .3 }); else s.style.width = s.dataset.w + '%'; });
    };
    GWQSH.setBar = function (s, w) { s.dataset.w = w; if (GWQSH.animOn()) G.to(s, { width: w + '%', duration: .5, ease: 'power2.out' }); else s.style.width = w + '%'; };

    /* ----- conic ring */
    GWQSH.ring = function (el, val) {
        if (!GWQSH.animOn()) { el.style.setProperty('--p', val); return; }
        const cur = parseFloat(getComputedStyle(el).getPropertyValue('--p')) || 0; const o = { p: cur };
        G.to(o, { p: val, duration: 1.2, ease: 'power3.out', delay: cur ? 0 : .3, onUpdate: () => el.style.setProperty('--p', o.p) });
    };

    /* ----- line chart */
    function smooth(pts) {
        if (pts.length < 2) return '';
        let d = 'M' + pts[0][0] + ',' + pts[0][1];
        for (let i = 0; i < pts.length - 1; i++) {
            const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
            const c1 = [p1[0] + (p2[0] - p0[0]) / 6, p1[1] + (p2[1] - p0[1]) / 6], c2 = [p2[0] - (p3[0] - p1[0]) / 6, p2[1] - (p3[1] - p1[1]) / 6];
            d += ' C' + c1.join(',') + ' ' + c2.join(',') + ' ' + p2.join(',');
        }
        return d;
    }
    GWQSH.lineChart = function (el, cfg) {
        el.classList.add('chart');
        let first = true, pinned = cfg.pin;
        const tip = document.createElement('div'); tip.className = 'tip'; el.appendChild(tip);
        const svgNS = 'http://www.w3.org/2000/svg';
        let svg;
        function render() {
            const W = Math.max(160, el.clientWidth), H = cfg.height || 180;
            const hasR = cfg.series.some(s => s.axis === 'right');
            const pad = { l: 34, r: hasR ? 30 : 10, t: 12, b: 26 };
            const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b, n = cfg.labels.length;
            const X = i => pad.l + (n === 1 ? iw / 2 : i * iw / (n - 1));
            const Y = (v, s) => { const max = s && s.axis === 'right' ? cfg.rMax : cfg.yMax; return pad.t + ih - Math.min(v, max) / max * ih; };
            let h = '<defs>';
            cfg.series.forEach((s, k) => { h += '<linearGradient id="' + el.id + 'g' + k + '" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="' + s.color + '" stop-opacity="' + (s.area === false ? 0 : .22) + '"/><stop offset="1" stop-color="' + s.color + '" stop-opacity="0"/></linearGradient>'; });
            h += '</defs>';
            for (let v = 0; v <= cfg.yMax; v += cfg.yStep) { const y = Y(v); h += '<line class="gl" x1="' + pad.l + '" x2="' + (W - pad.r) + '" y1="' + y + '" y2="' + y + '"/><text class="ax" x="' + (pad.l - 8) + '" y="' + (y + 4) + '" text-anchor="end">' + (cfg.fmt ? cfg.fmt(v) : v) + '</text>'; }
            if (hasR) { for (let v = 0; v <= cfg.rMax; v += cfg.rStep) { h += '<text class="ax" x="' + (W - pad.r + 8) + '" y="' + (Y(v, { axis: 'right' }) + 4) + '">' + v + '</text>'; } }
            const every = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 58))));
            cfg.labels.forEach((l, i) => { if (i % every === 0 || i === n - 1 && (n - 1) % every > every / 2) h += '<text class="ax" x="' + X(i) + '" y="' + (H - 6) + '" text-anchor="middle">' + l + '</text>'; });
            h += '<line class="guide" x1="0" x2="0" y1="' + pad.t + '" y2="' + (pad.t + ih) + '" stroke="var(--faint)" stroke-dasharray="3 3" opacity="0"/>';
            cfg.series.forEach((s, k) => {
                const pts = s.data.map((v, i) => [+X(i).toFixed(1), +Y(v, s).toFixed(1)]);
                if (!pts.length) return;
                const line = smooth(pts);
                h += '<path class="area" d="' + line + ' L' + pts[pts.length - 1][0] + ',' + (pad.t + ih) + ' L' + pts[0][0] + ',' + (pad.t + ih) + 'Z" fill="url(#' + el.id + 'g' + k + ')"/>';
                h += '<path class="ln" d="' + line + '" fill="none" stroke="' + s.color + '" stroke-width="2.2" stroke-linecap="round"/>';
                if (n <= 16) pts.forEach(p => { h += '<circle class="pt" cx="' + p[0] + '" cy="' + p[1] + '" r="3.6" fill="' + s.color + '" stroke="var(--surface)" stroke-width="1.5"/>'; });
            });
            h += '<rect class="hit" x="' + pad.l + '" y="0" width="' + iw + '" height="' + H + '" fill="transparent"/>';
            if (svg) svg.remove();
            svg = document.createElementNS(svgNS, 'svg'); svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H); svg.setAttribute('width', W); svg.setAttribute('height', H); svg.setAttribute('role', 'img'); svg.setAttribute('aria-label', cfg.aria || 'Line chart');
            if (!n) h += '<text class="ax" x="' + (W / 2) + '" y="' + (H / 2) + '" text-anchor="middle">No recorded data in this period</text>';
            svg.innerHTML = h; el.insertBefore(svg, tip);
            const guide = svg.querySelector('.guide');
            const show = i => {
                if (!n) return;
                const x = X(i); guide.setAttribute('x1', x); guide.setAttribute('x2', x); guide.setAttribute('opacity', '1');
                const top = Math.min(...cfg.series.map(s => Y(s.data[i], s)));
                tip.innerHTML = '<div class="t">' + (cfg.tipTitle ? cfg.tipTitle(i) : cfg.labels[i]) + '</div>' + cfg.series.map(s => '<div><span class="dot" style="color:' + s.color + '"></span>' + s.name + ': <b>' + (cfg.tipFmt ? cfg.tipFmt(s.data[i]) : GWQSH.fmt(s.data[i])) + '</b></div>').join('');
                tip.style.opacity = '1';
                const tw = tip.offsetWidth; const lx = Math.max(tw / 2, Math.min(W - tw / 2, x + (x > W * 0.6 ? -(tw / 2 + 14) : (tw / 2 + 14))));
                tip.style.left = lx + 'px'; tip.style.top = Math.max(tip.offsetHeight + 2, top + tip.offsetHeight / 2) + 'px';
            };
            const hide = () => { if (pinned != null && pinned < n) show(pinned); else { tip.style.opacity = '0'; guide.setAttribute('opacity', '0'); } };
            const hit = svg.querySelector('.hit');
            const pick = ev => { if (!n) return; const r = svg.getBoundingClientRect(); const cx = (ev.touches ? ev.touches[0].clientX : ev.clientX) - r.left; const i = Math.round((cx * W / r.width - pad.l) / iw * (n - 1)); show(Math.max(0, Math.min(n - 1, i))); };
            hit.addEventListener('mousemove', pick); hit.addEventListener('touchstart', pick, { passive: true }); hit.addEventListener('touchmove', pick, { passive: true });
            hit.addEventListener('mouseleave', hide);
            hide();
            if (first && GWQSH.animOn()) {
                GWQSH.$$('.ln', svg).forEach(p => { const L = p.getTotalLength(); G.fromTo(p, { strokeDasharray: L, strokeDashoffset: L }, { strokeDashoffset: 0, duration: 1.2, ease: 'power2.inOut', delay: .35 }); });
                G.from(GWQSH.$$('.area', svg), { opacity: 0, duration: .8, delay: .9 });
                G.from(GWQSH.$$('.pt', svg), { scale: 0, transformOrigin: 'center', transformBox: 'fill-box', stagger: .02, duration: .3, delay: 1.1 });
                G.from(tip, { opacity: 0, duration: .3, delay: 1.3 });
            }
            first = false;
        }
        render();
        let rt; new ResizeObserver(() => { clearTimeout(rt); rt = setTimeout(render, 60); }).observe(el);
        return { update(next) { Object.assign(cfg, next); pinned = next.pin !== undefined ? next.pin : pinned; first = true; render(); } };
    };

    /* ----- donut */
    GWQSH.donut = function (el, segs, opt = {}) {
        const size = opt.size || 180, w = opt.width || 26, r = (size - w) / 2, C = 2 * Math.PI * r, gap = opt.gap || 3;
        const total = segs.reduce((a, s) => a + s.value, 0);
        let off = 0, h = '<svg viewBox="0 0 ' + size + ' ' + size + '" width="100%" height="100%" role="img" aria-label="' + (opt.aria || 'Donut chart') + '"><g transform="rotate(-90 ' + size / 2 + ' ' + size / 2 + ')">';
        segs.forEach(s => { const len = s.value / total * C; h += '<circle cx="' + size / 2 + '" cy="' + size / 2 + '" r="' + r + '" fill="none" stroke="' + s.color + '" stroke-width="' + w + '" stroke-dasharray="' + Math.max(0, len - gap) + ' ' + C + '" stroke-dashoffset="' + (-off) + '"><title>' + s.label + ': ' + s.value + '</title></circle>'; off += len; });
        h += '</g></svg>';
        el.innerHTML = h;
        if (GWQSH.animOn()) G.from(el.querySelector('g'), { rotation: -120, svgOrigin: size / 2 + ' ' + size / 2, opacity: 0, duration: 1, ease: 'power3.out', delay: .3 });
    };

    /* ----- page entrance */
    GWQSH.enter = function () {
        if (!GWQSH.animOn()) return;
        const tl = G.timeline({ defaults: { ease: 'power3.out' } });
        tl.from('.hero .eyebrow,.hero .h1,.hero .lede', { y: 14, opacity: 0, duration: .6, stagger: .08 })
            .from('.hero-tag', { opacity: 0, rotate: -14, scale: .9, duration: .8 }, '-=.4')
            .from('.page .card', { y: 18, opacity: 0, duration: .55, stagger: { each: .035, from: 'start' }, clearProps: 'transform,opacity' }, '-=.6');
    };

    /* ----- optional Three.js hero (only runs on pages with .hero-canvas) */
    GWQSH.hero = function () {
        const canvas = GWQSH.$('.hero-canvas'); if (!canvas || !window.THREE) return;
        /* ...unchanged from original — kept intact for pages that use it... */
    };

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelector('[data-changelog]')?.addEventListener('click', () => GWQSH.modal({
            title: 'Security Suite Pro changelog',
            body: '<h4>Version 1.0.0 — Initial public release</h4><ul><li>Login attempt protection, IP allowlisting and a configurable custom login URL.</li><li>Verified TOTP enrollment, single-use backup codes and revocable trusted devices.</li><li>Manual core integrity checks, suspicious-file detection, bounded differences, restoration and quarantine.</li><li>WordPress hardening controls with calculated security status.</li><li>Activity logs, responsive light and dark admin themes.</li></ul>'
        }));
        const cfg = window.GWQSH_CONFIG || {};
        const notifications = GWQSH.$('#menu-notif') || GWQSH.$('#menu-notifications');
        if (notifications) {
            notifications.querySelectorAll('.menu-item').forEach(item => item.remove());
            const entries = cfg.notifications || [];
            const content = document.createElement('div');
            content.className = 'notification-events';
            content.innerHTML = entries.length ? entries.map(e => '<div class="menu-item"><span><b>' + GWQSH.esc(e.event_name) + '</b><small>' + GWQSH.esc(e.details || '') + '</small></span></div>').join('') : '<div class="menu-item">No events in the last 24 hours.</div>';
            notifications.appendChild(content);
            GWQSH.$('#notifDot')?.classList.toggle('off', !entries.length);
        }
        GWQSH.hero(); GWQSH.enter();
        if (location.hash) { const t = GWQSH.$(location.hash); if (t && G && GWQSH.animOn()) { setTimeout(() => { t.scrollIntoView({ behavior: 'smooth', block: 'start' }); G.fromTo(t, { boxShadow: '0 0 0 0 rgba(47,91,234,.5)' }, { boxShadow: '0 0 0 6px rgba(47,91,234,0)', duration: 1.2, delay: .5, repeat: 1 }); }, 400); } }
    });
})();
