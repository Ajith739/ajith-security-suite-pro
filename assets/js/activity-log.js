/* Security Suite Pro Activity Log: real audit data, applied filters and bounded workflows. */
'use strict';
document.addEventListener('DOMContentLoaded', () => {
    const { $, $$, esc, fmt, toast, modal } = GWQSH;
    const root = $('.qs-pro-activity');
    if (!root) return;
    const groups = { Security: ['Security & Login', '#ff384b', 'red'], User: ['User Actions', '#316dff', 'blue'], File: ['File Changes', '#ff9f00', 'orange'], System: ['System Events', '#00c888', 'green'], Other: ['Other Events', '#9a9faf', 'blue'] };
    const keys = ['search', 'category', 'event', 'user', 'ip', 'severity', 'days', 'start', 'end'];
    const form = $('#activityFilters'), status = $('#alStatus');
    let snapshot = window.GWQSH_DATA || {}, applied = { days: '30' }, page = 1, generation = 0, loading = false, chart, activeMenu, menuTrigger;
    function controls(value) {
        keys.forEach(k => { const c = form.elements.namedItem(k); if (!c) return; if (k === 'user' && value[k] && !Array.from(c.options).some(o => o.value === value[k])) c.add(new Option(value[k], value[k])); c.value = value[k] || (k === 'days' ? '30' : ''); });
        $('#similarLabel').hidden = !value.event; $('#similarLabel').textContent = value.event ? 'Exact event: ' + value.event : '';
    }
    function readControls() { const f = {}; keys.forEach(k => f[k] = String(form.elements.namedItem(k)?.value || '')); return f; }
    function urlState(f, p) {
        const url = new URL(location.href);
        keys.forEach(k => { url.searchParams.delete('al_' + k); if (f[k] && !(k === 'days' && String(f[k]) === '30')) url.searchParams.set('al_' + k, f[k]); });
        url.searchParams.delete('al_page'); if (p > 1) url.searchParams.set('al_page', p);
        // Replace legacy deep-link filters with the canonical applied state.
        url.searchParams.delete('type'); url.searchParams.delete('user');
        history.replaceState(null, '', url);
    }
    function message(text, error = false) { status.textContent = text; status.dataset.error = String(error); }
    function showTable() {
        closeMenu();
        const rows = snapshot.items || [];
        $('#activityBody').innerHTML = rows.length ? rows.map(r => {
            const g = groups[r.category] || groups.Other, color = r.badge === 'Login' ? 'blue' : g[2];
            return '<tr><td><time datetime="' + esc(r.timestamp) + '">' + esc(r.display_time) + '</time></td><td title="' + esc(r.event_name) + '"><span class="al-dot" style="background:' + g[1] + '"></span>' + esc(r.event_name) + '</td><td title="' + esc(r.user_login) + '">' + esc(r.user_login) + '</td><td title="' + esc(r.ip_address) + '">' + esc(r.ip_address) + '</td><td title="' + esc(r.details) + '">' + esc(r.details) + '</td><td><span class="al-badge al-' + color + '">' + esc(r.badge) + '</span></td><td><div class="al-row-actions"><button class="al-button" type="button" data-view="' + r.id + '">View</button><button class="al-kebab" type="button" data-more="' + r.id + '" aria-label="Actions for event ' + r.id + '" aria-haspopup="menu" aria-expanded="false">···</button></div></td></tr>';
        }).join('') : '<tr><td colspan="7" style="padding:30px;text-align:center">' + (keys.some(k => k !== 'days' && applied[k]) ? 'No events match your filters.' : 'No activity recorded yet.') + '</td></tr>';
        page = snapshot.page || 1;
        const total = snapshot.total || 0, pages = snapshot.pages || 1;
        $('#activityInfo').textContent = total ? 'Showing ' + fmt((page - 1) * 10 + 1) + '–' + fmt(Math.min(page * 10, total)) + ' of ' + fmt(total) + ' events' : '0 events';
        const numbers = [...new Set([1, ...Array.from({ length: 5 }, (_, i) => page - 2 + i).filter(n => n > 1 && n < pages), pages])].sort((a, b) => a - b);
        let html = '<button type="button" data-page="' + (page - 1) + '" aria-label="Previous page" ' + (page === 1 ? 'disabled' : '') + '>‹</button>';
        numbers.forEach((n, i) => { if (i && n - numbers[i - 1] > 1) html += '<span aria-hidden="true">…</span>'; html += '<button type="button" data-page="' + n + '" ' + (n === page ? 'aria-current="page"' : '') + '>' + n + '</button>'; });
        $('#activityPager').innerHTML = html + '<button type="button" data-page="' + (page + 1) + '" aria-label="Next page" ' + (page === pages ? 'disabled' : '') + '>›</button>';
    }
    function overview() {
        if (!snapshot.counts || !snapshot.chart) return;
        const counts = snapshot.counts, prev = snapshot.previous || {}, total = Object.values(counts).reduce((a, b) => a + Number(b), 0);
        $$('[data-metric]').forEach(el => {
            const key = el.dataset.metric, value = key === 'all' ? total : counts[key] || 0, before = key === 'all' ? Object.values(prev).reduce((a, b) => a + Number(b), 0) : prev[key] || 0;
            el.textContent = fmt(value);
            const t = root.querySelector('[data-trend="' + key + '"]'); t.hidden = !before;
            if (before) { const delta = Math.round((value - before) / before * 100); t.textContent = (delta > 0 ? '↑ ' : delta < 0 ? '↓ ' : '') + Math.abs(delta) + '%'; t.dataset.direction = delta < 0 ? 'down' : 'up'; t.title = 'Count change compared with the preceding 30 days; this does not measure risk.'; }
        });
        const relevant = Object.entries(groups).filter(([k]) => k !== 'Other' || counts.Other || snapshot.chart.series.Other.some(Boolean));
        $('#donutTotal').textContent = fmt(total);
        if (total) GWQSH.donut($('#activityDonut'), relevant.filter(([k]) => counts[k] > 0).map(([k, g]) => ({ label: g[0], color: g[1], value: counts[k] })), { size: 160, width: 24, gap: 2, aria: 'Recorded event distribution over the last 30 days' });
        else $('#activityDonut').innerHTML = '<svg viewBox="0 0 160 160" role="img" aria-label="No activity recorded yet"><circle cx="80" cy="80" r="68" fill="none" stroke="#e8eef8" stroke-width="24"/></svg>';
        const percentages = relevant.map(([k]) => { const exact = total ? (counts[k] || 0) / total * 100 : 0; return { key: k, value: Math.floor(exact), fraction: exact % 1 }; });
        let left = total ? 100 - percentages.reduce((sum, p) => sum + p.value, 0) : 0;
        [...percentages].sort((a, b) => b.fraction - a.fraction).forEach(p => { if (left > 0) { p.value++; left--; } });
        const pct = Object.fromEntries(percentages.map(p => [p.key, p.value]));
        $('#donutLegend').innerHTML = relevant.map(([k, g]) => '<li><span class="al-dot" style="background:' + g[1] + '"></span><span>' + g[0] + '</span><b>' + pct[k] + '%</b><span>(' + fmt(counts[k] || 0) + ')</span></li>').join('');
        const order = ['User', 'Security', 'File', 'System', ...(relevant.some(([k]) => k === 'Other') ? ['Other'] : [])];
        const series = order.map(k => ({ name: groups[k][0], color: groups[k][1], data: snapshot.chart.series[k] }));
        $('#chartLegend').innerHTML = series.map(s => '<span><span class="al-dot" style="background:' + s.color + '"></span>' + s.name + '</span>').join('');
        const max = Math.max(1, ...series.flatMap(s => s.data)), step = Math.max(1, Math.ceil(max / 4)), yMax = step * 4;
        const cfg = { labels: snapshot.chart.labels, series, height: 151, yStep: step, yMax, pin: null, aria: 'Recorded events by site day; exact values are in the chart data table', tipTitle: i => esc(snapshot.chart.dates[i]), fmt: fmt };
        if (chart) chart.update(cfg); else chart = GWQSH.lineChart($('#activityChart'), cfg);
        $('#chartData').innerHTML = '<table class="al-table"><caption>Events by site date</caption><thead><tr><th>Date</th>' + order.map(k => '<th>' + groups[k][0] + '</th>').join('') + '</tr></thead><tbody>' + snapshot.chart.dates.map((date, i) => '<tr><td>' + esc(date) + '</td>' + order.map(k => '<td>' + fmt(snapshot.chart.series[k][i]) + '</td>').join('') + '</tr>').join('') + '</tbody></table>';
        if (snapshot.options) {
            const sel = $('#eventUser'), current = sel.value; sel.innerHTML = '<option value="">All Users</option>';
            snapshot.options.user_login.forEach(u => { if (u) sel.add(new Option(u, u)); });
            if (current && !Array.from(sel.options).some(o => o.value === current)) sel.add(new Option(current, current)); sel.value = current;
            $('#eventIps').innerHTML = snapshot.options.ip_address.filter(ip => !['—', ''].includes(ip)).map(ip => '<option value="' + esc(ip) + '"></option>').join('');
        }
    }
    async function load(filters = applied, nextPage = 1, withOverview = false) {
        const ticket = ++generation; loading = true; message('Loading activity…'); $('#log').setAttribute('aria-busy', 'true');
        const res = await GWQSH.ajax('activity_data', { ...filters, page_num: nextPage, overview: withOverview ? '1' : '0', chart_days: $('#chartRange').value });
        if (ticket !== generation) return false;
        loading = false; $('#log').removeAttribute('aria-busy');
        if (!res.success) { message(res.data?.message || 'Could not load activity records.', true); return false; }
        snapshot = { ...snapshot, ...res.data }; applied = { ...filters }; page = res.data.page;
        message(snapshot.search_ready === false ? 'Safe description search is being prepared for older records. Event, user and IP search is available.' : ''); controls(applied); showTable(); if (withOverview) overview(); urlState(applied, page); return true;
    }
    form.addEventListener('submit', e => { e.preventDefault(); if (!form.reportValidity()) return; const f = readControls(); if ((f.start || f.end) && (!f.start || !f.end || f.start > f.end)) { message('Enter both dates with start no later than end.', true); return; } load(f); });
    $('#filterDays').addEventListener('change', () => { $('#startDate').value = ''; $('#endDate').value = ''; });
    $('#resetFilters').addEventListener('click', () => { const f = { days: '30' }; controls(f); load(f); });
    $('#chartRange').addEventListener('change', () => load(applied, page, true));
    $('#activityPager').addEventListener('click', e => { const b = e.target.closest('[data-page]'); if (b && !b.disabled) load(applied, Number(b.dataset.page)); });
    $$('[data-filter-category]').forEach(b => b.addEventListener('click', () => { const f = { days: '30', category: b.dataset.filterCategory }; controls(f); load(f); }));
    $('#roleChanges').addEventListener('click', () => { const f = { days: '30', event: 'User role changed' }; controls(f); load(f); });
    function detail(id) {
        const r = snapshot.items?.find(r => r.id === Number(id)); if (!r) return;
        const fields = { 'Event ID': r.id, Timestamp: r.timestamp, Category: r.badge, 'Original type': r.event_type, Event: r.event_name, Severity: r.severity, User: r.user_login, 'IP address': r.ip_address, Description: r.details };
        modal({ title: 'Event #' + r.id, wide: true, body: '<dl class="al-detail">' + Object.entries(fields).map(([k, v]) => '<dt>' + esc(k) + '</dt><dd>' + esc(String(v || 'Not recorded')) + '</dd>').join('') + '</dl><p>Times use the WordPress site timezone. Additional source/result metadata was not recorded by the existing logger.</p>' });
    }
    function closeMenu(restore = false) { if (!activeMenu) return; activeMenu.remove(); activeMenu = null; menuTrigger?.setAttribute('aria-expanded', 'false'); if (restore) menuTrigger?.focus(); }
    function openMenu(button) {
        if (menuTrigger === button && activeMenu) { closeMenu(true); return; }
        closeMenu(); menuTrigger = button; const id = button.dataset.more;
        activeMenu = document.createElement('div'); activeMenu.className = 'al-row-menu'; activeMenu.setAttribute('role', 'menu');
        activeMenu.innerHTML = '<button role="menuitem" type="button" data-action="view">View Details</button><button role="menuitem" type="button" data-action="copy">Copy Event ID</button><button role="menuitem" type="button" data-action="similar">Filter Similar Events</button>';
        const palette = getComputedStyle(root); ['--qs-navy', '--qs-border', '--qs-bg'].forEach(token => activeMenu.style.setProperty(token, palette.getPropertyValue(token)));
        document.getElementById('gracewell-security-suite-pro-app').appendChild(activeMenu); button.setAttribute('aria-expanded', 'true');
        const rect = button.getBoundingClientRect(); activeMenu.style.left = Math.max(8, Math.min(innerWidth - activeMenu.offsetWidth - 8, rect.right - activeMenu.offsetWidth)) + 'px'; activeMenu.style.top = Math.max(8, Math.min(innerHeight - activeMenu.offsetHeight - 8, rect.bottom + 4)) + 'px';
        activeMenu.querySelector('button').focus();
        activeMenu.addEventListener('click', async e => { const a = e.target.closest('[data-action]'); if (!a) return; const row = snapshot.items.find(r => r.id === Number(id)); closeMenu(true); if (!row) return;
            if (a.dataset.action === 'view') detail(id);
            if (a.dataset.action === 'copy') { try { await GWQSH.copy(String(id), 'Event ID copied.'); } catch { toast('Could not copy event ID.', 'err'); } }
            if (a.dataset.action === 'similar') { const f = { ...applied, event: row.event_name }; controls(f); load(f); }
        });
        activeMenu.addEventListener('keydown', e => { const buttons = [...activeMenu.querySelectorAll('button')], index = buttons.indexOf(document.activeElement); if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) { e.preventDefault(); buttons[e.key === 'Home' ? 0 : e.key === 'End' ? buttons.length - 1 : (index + (e.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length].focus(); } if (e.key === 'Tab') closeMenu(); });
    }
    $('#activityBody').addEventListener('click', e => { const v = e.target.closest('[data-view]'), m = e.target.closest('[data-more]'); if (v) detail(v.dataset.view); if (m) openMenu(m); });
    document.addEventListener('click', e => { if (!e.target.closest('.al-row-menu,[data-more]')) closeMenu(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') { closeMenu(true); } });
    window.addEventListener('resize', () => closeMenu()); window.addEventListener('scroll', () => closeMenu(), true);
    $$('[data-export]').forEach(b => b.addEventListener('click', () => {
        if (loading) { toast('Wait for the activity query to finish.', 'err'); return; }
        if ((snapshot.total || 0) > 50000) { toast('Narrow filters to at most 50,000 events before exporting.', 'err'); return; }
        const exportForm = $('#activityExport'); exportForm.querySelectorAll('[data-filter]').forEach(el => el.remove());
        keys.forEach(k => { const input = document.createElement('input'); input.type = 'hidden'; input.name = k; input.value = applied[k] || (k === 'days' ? '30' : ''); input.dataset.filter = ''; exportForm.appendChild(input); });
        exportForm.submit();
    }));
    let cleaning = false;
    $('#clearOldLogs').addEventListener('click', async () => {
        if (cleaning) return;
        const preview = await GWQSH.ajax('activity_cleanup_preview');
        if (!preview.success) { toast(preview.data?.message || 'Could not preview cleanup.', 'err'); return; }
        const p = preview.data;
        if (!p.count) { toast('No records are older than the configured retention cutoff.'); return; }
        modal({ title: 'Clear expired activity logs?', body: '<p>Retention: <b>' + esc(String(p.days)) + ' days</b>.</p><p>Delete <b>' + fmt(p.count) + '</b> records older than <b>' + esc(p.cutoff) + ' (' + esc(p.timezone) + ')</b>.</p><p>This deletion cannot be undone. Recent records are retained. Your retention policy will remain ' + esc(String(p.days)) + ' days.</p><p role="status" id="cleanupProgress"></p>', actions: [{ label: 'Cancel' }, { label: 'Delete expired records', cls: 'btn-danger', fn: async bg => {
            if (cleaning) return false; cleaning = true; let removed = 0;
            try {
                let remaining = p.count;
                while (remaining > 0) {
                    if (!bg.isConnected) { toast('Cleanup stopped. ' + fmt(removed) + ' records removed.'); await load(applied, page, true); return; }
                    const res = await GWQSH.ajax('activity_cleanup', { token: p.token, confirmed: '1' });
                    if (!res.success) { bg.querySelector('#cleanupProgress').textContent = (res.data?.message || 'Cleanup failed.') + ' ' + fmt(removed) + ' records removed so far.'; return false; }
                    removed += res.data.deleted; remaining = res.data.remaining;
                    bg.querySelector('#cleanupProgress').textContent = fmt(removed) + ' removed; ' + fmt(remaining) + ' remaining.';
                    if (!res.data.deleted && remaining) { bg.querySelector('#cleanupProgress').textContent = 'Cleanup stopped because no progress was made.'; return false; }
                }
                toast(fmt(removed) + ' expired records removed.'); await load(applied, page, true);
            } finally { cleaning = false; }
        } }] });
    });
    const params = new URLSearchParams(location.search), initial = { days: '30' };
    keys.forEach(k => { if (params.has('al_' + k)) initial[k] = params.get('al_' + k); });
    if (params.has('type')) initial.category = ({ security: 'Security', user: 'User', users: 'User', plugin: 'System', system: 'System', login: 'Login', file: 'File' })[params.get('type').toLowerCase()] || '';
    if (params.has('user')) initial.user = params.get('user');
    applied = initial; controls(initial);
    if (snapshot.items && snapshot.chart) { showTable(); overview(); if (snapshot.search_ready === false) message('Safe description search is being prepared for older records. Event, user and IP search is available.'); }
    if (keys.some(k => params.has('al_' + k)) || params.has('type') || params.has('user') || params.has('al_page')) load(initial, Number(params.get('al_page')) || 1);
    else if (!snapshot.items) message('Activity records could not be loaded. Reload to try again.', true);
});
