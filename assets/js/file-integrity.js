/* ============================================================
   Gracewell Security Suite Pro — File Integrity page logic
   Depends on: qs-core.js (loaded before this, both deferred)
   ============================================================ */

document.addEventListener('DOMContentLoaded', function () {
    const { $, $$, toast, modal, confirm, esc, fmt } = GWQSH;
    const D = window.GWQSH_DATA || {};


    /* ---------- data ---------- */
    let files = (D.issues || []).map(r => ({ ...r, path: r.display_path || r.path, id: Number(r.id) }));
    $('#kvFiles').textContent = fmt(Number(D.summary?.total || 0));
    $('#kvDur').textContent = Number(D.summary?.duration || 0) + ' seconds';
    $('#lastDate').textContent = D.summary?.last_date || 'Never';
    const state = {
        page: 1, perPage: Number(D.per_page) || 20, total: Number(D.total) || 0,
        pages: Number(D.pages) || 1, search: '', type: '', status: '', severity: '',
        sort: 'date', order: 'DESC', tab: ''
    };
    let sel = new Set();
    let TOTAL = D.summary?.total ?? 0;
    let quarantine = D.quarantine || {};
    let qPage = 1, qPerPage = 20, qSel = new Set();
    const pendingActions = new Set();
    function switchTable(view) {
        const isResults = view === 'results';
        $('#results').hidden = !isResults; $('#quarantine').hidden = isResults;
        $('#showResults').setAttribute('aria-selected', String(isResults));
        $('#showQuarantine').setAttribute('aria-selected', String(!isResults));
        $('#showResults').tabIndex = isResults ? 0 : -1;
        $('#showQuarantine').tabIndex = isResults ? -1 : 0;
    }
    $('#showResults').addEventListener('click', () => switchTable('results'));
    $('#showQuarantine').addEventListener('click', () => switchTable('quarantine'));
    $('.integrity-switch').addEventListener('keydown', e => {
        if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
        e.preventDefault();
        const view = e.key === 'Home' ? 'results' : e.key === 'End' ? 'quarantine' : $('#results').hidden ? 'results' : 'quarantine';
        switchTable(view); $(view === 'results' ? '#showResults' : '#showQuarantine').focus();
    });
    switchTable('results');

    const fmtDate = GWQSH.date;

    const pill = { Modified: 'p-amber', Missing: 'p-red', Suspicious: 'p-red' };
    const action = { Modified: 'Review Change', Missing: 'Review Missing File', Suspicious: 'Quarantine' };

    const severityPill = {
        Critical: 'p-red',
        High: 'p-red',
        Medium: 'p-amber',
        Low: 'p-blue',
        Informational: 'p-green'
    };

    function counts() {
        return { Modified: Number(D.summary?.modified || 0), Missing: Number(D.summary?.missing || 0), Suspicious: Number(D.summary?.suspicious || 0) };
    }

    function refreshSummary() {
        const scopes = D.summary?.scope_counts || {};
        const protection = D.summary?.protection || 'Monitoring';
        if ($('#fiProtectionBadge')) $('#fiProtectionBadge').textContent = protection;
        if ($('#fiProtectionBadge')) $('#fiProtectionBadge').className = 'pill ' + (protection === 'Attention Required' ? 'p-amber' : protection === 'Disabled' ? 'p-gray' : 'p-green');
        if ($('#fiProtectionTitle')) $('#fiProtectionTitle').textContent = protection === 'Disabled' ? 'Integrity Protection Disabled' : protection === 'Attention Required' ? 'Integrity Review Required' : 'Integrity Monitoring';
        const descText = protection === 'Disabled' ? 'Plugin protection is disabled. Review your security settings.' : protection === 'Attention Required' ? (D.summary?.coverage?.length ? 'Scan coverage is limited. Review the coverage notes and saved findings below.' : 'Saved scan findings need review. Inspect changes and suspicious files below.') : 'Ready for on-demand and scheduled integrity scans.';
        if ($('#fiProtectionDescription')) $('#fiProtectionDescription').innerHTML = '<span class="fi-dot"></span> ' + descText;
        $('#engineChecked').textContent = D.summary?.last_date || 'Not scanned yet';
        $('#scanPill').textContent = D.summary?.scan_running ? 'Running' : D.summary?.last_date ? 'Completed' : 'Never Run';
        $('#runScan').firstChild.textContent = D.summary?.scan_running ? 'Resume Scan ' : 'Run New Scan ';
        const heroRun = $('#heroRunScan');
        if (heroRun && heroRun.firstChild) {
            heroRun.firstChild.textContent = D.summary?.scan_running ? 'Resume Scan ' : 'Run Integrity Scan ';
        }
        $('#scanPill').className = 'pill ' + (D.summary?.scan_running ? 'p-blue' : D.summary?.last_date ? 'p-green' : 'p-gray');
        $$('.stats .stat:not(.fi-engine) .stat-head .pill').forEach((el, i) => {
            const b = D.summary?.breakdown || {};
            const n = [{ a: 'core-mod', b: 'core-miss' }, { a: 'pl-mod', b: 'pl-sus' }, { a: 'th-mod', b: 'th-sus' }, { a: 'up-sus' }][i];
            const alerts = Number(b[n.a] || 0) + Number(b[n.b] || 0);
            el.textContent = !TOTAL ? 'Not scanned' : alerts ? alerts + ' alerts' : 'Checked';
            el.className = 'pill ' + (alerts ? 'p-amber' : 'p-green');
        });
        $$('.stats .stat [data-count]').forEach((el, i) => GWQSH.setCount(el, [Number(D.summary?.breakdown?.['core-ok'] || 0) + Number(D.summary?.breakdown?.['core-mod'] || 0) + Number(D.summary?.breakdown?.['core-miss'] || 0), Number(scopes.Plugin || 0), Number(scopes.Theme || 0), Number(scopes.Uploads || 0)][i]));
        const c = counts(), issues = c.Modified + c.Missing + c.Suspicious, clean = Number(D.summary?.clean || 0);

        $$('[data-n]').forEach(el => el.textContent = el.dataset.n === 'all' ? issues : (c[el.dataset.n] || 0));

        GWQSH.setCount($('#nClean'), clean);
        $('#nMod').textContent = c.Modified;
        $('#nMiss').textContent = c.Missing;
        $('#nSus').textContent = c.Suspicious;

        const pct = Number(D.summary?.clean_percent || 0);
        GWQSH.ring($('#cleanRing'), pct);
        GWQSH.setCount($('#cleanPct'), pct, 1);

        $('#sumP').textContent = !TOTAL ? 'No file scan has run yet.' : issues
            ? 'We checked ' + fmt(TOTAL) + ' files and found ' + issues + ' item' + (issues === 1 ? '' : 's') + ' that need attention.'
            : 'We scanned ' + fmt(TOTAL) + ' files and found nothing that needs attention.';
        $('#sumHead').textContent = !TOTAL ? 'Run your first file scan' : issues ? 'Your site needs a look' : 'Your site looks good!';

        if (D.summary?.coverage?.length) {
            $('#sumHead').textContent = 'Verification incomplete';
            $('#sumP').textContent += ' Coverage limited: ' + D.summary.coverage.map(v => v.replaceAll('_', ' ')).join(', ') + '.';
            const omitted = Number(D.summary?.uninspected || 0);
            if (omitted) $('#sumP').textContent += ' ' + fmt(omitted) + ' files were not inspected and are excluded from the clean count.';
            if (D.summary?.omitted_files?.length) $('#sumP').textContent += ' Omitted files (up to 100): ' + D.summary.omitted_files.map(v => v.path + ' (' + v.reason.replaceAll('_', ' ') + ')').join('; ') + '.';
        }
        if (D.summary?.quarantine_damaged) {
            $('#sumHead').textContent = 'Quarantine evidence needs review';
            $('#sumP').textContent = D.summary.quarantine_damaged + ' quarantine records have damaged or missing evidence. Review Quarantine management.';
        }

        const by = (t, s) => Number(D.summary?.breakdown?.[({ Core: { Modified: 'core-mod', Missing: 'core-miss' }, Plugin: { Modified: 'pl-mod', Suspicious: 'pl-sus' }, Theme: { Modified: 'th-mod', Suspicious: 'th-sus' }, Uploads: { Suspicious: 'up-sus' } })[t]?.[s]] || 0);
        const set = (k, v) => { const el = $('[data-k="' + k + '"]'); el && (el.textContent = fmt(v)); };
        set('core-mod', by('Core', 'Modified'));
        set('core-miss', by('Core', 'Missing'));
        set('core-ok', D.summary?.breakdown?.['core-ok'] ?? 0);
        set('pl-mod', by('Plugin', 'Modified'));
        set('pl-sus', by('Plugin', 'Suspicious'));
        set('pl-ok', D.summary?.breakdown?.['pl-ok'] ?? 0);
        set('th-mod', by('Theme', 'Modified'));
        set('th-sus', by('Theme', 'Suspicious'));
        set('th-ok', D.summary?.breakdown?.['th-ok'] ?? 0);
        set('up-sus', by('Uploads', 'Suspicious'));
        $('[data-k="up-php"]').textContent = D.summary?.breakdown?.['up-php'] == null ? '—' : fmt(D.summary.breakdown['up-php']);
        set('up-ok', D.summary?.breakdown?.['up-ok'] ?? 0);
    }

    /* ---- Server-side data fetcher ---- */
    let fetchGeneration = 0;
    async function refreshCurrentView(resetPage = false) {
        if (resetPage) state.page = 1;
        sel.clear();
        $('#checkAll').checked = false; $('#checkAll').indeterminate = false;
        $$('#fBody .checkbox').forEach(box => { box.checked = false; });
        $('#bulk').classList.add('hide');
        const generation = ++fetchGeneration;
        try {
            const res = await GWQSH.ajax('get_scan_data', {
                page_num: state.page, per_page: state.perPage, search: state.search,
                type: state.type, status: state.status, severity: state.severity,
                sort: state.sort, order: state.order
            });
            if (generation !== fetchGeneration) return;
            if (!res.success) { toast(res.data?.message || 'Unable to refresh findings.', 'err'); return; }
            const result = res.data;
            D.summary = result.summary;
            D.history = result.history || D.history;
            TOTAL = Number(D.summary?.total || 0);
            files = (result.issues || []).map(r => ({ ...r, path: r.display_path || r.path, id: Number(r.id) }));
            state.page = Number(result.page);
            state.pages = Number(result.pages);
            state.total = Number(result.total);
            state.perPage = Number(result.per_page);
            quarantine = result.quarantine || {};
            qSel.clear();
            draw(); drawQuarantine(); refreshSummary();
        } catch (error) {
            toast('Unable to refresh findings. Please retry.', 'err');
        }
    }

    function draw() {
        const slice = files;

        function formatPath(p) {
            const parts = p.split('/');
            const file = parts.pop();
            const dir = parts.join('/') + (parts.length ? '/' : '');
            return '<span class="path-wrap" title="' + esc(p) + '"><span class="path-dir">' + esc(dir) + '</span><strong class="path-file">' + esc(file) + '</strong></span>';
        }

        function severityBadge(f) {
            if (!f.severity) return '';
            const cls = severityPill[f.severity] || 'p-blue';
            return '<span class="pill p-sm ' + cls + '" title="Score: ' + f.score + ', Confidence: ' + esc(f.confidence || 'Unknown') + '">' + esc(f.severity) + '</span>';
        }

        $('#fBody').innerHTML = slice.length
            ? slice.map(f => '<tr data-id="' + f.id + '">' +
                '<td><input type="checkbox" class="checkbox" aria-label="Select ' + esc(f.path) + '"' + (sel.has(f.id) ? ' checked' : '') + '></td>' +
                '<td class="path">' + formatPath(f.path) + '</td>' +
                '<td>' + esc(({mu_plugin: 'MU Plugin', config: 'Root / Config', dropin: 'Drop-in'})[f.component] || f.type) + '</td>' +
                '<td><span class="pill p-status ' + (pill[f.st] || 'p-amber') + '">' + esc(f.st) + '</span></td>' +
                '<td>' + severityBadge(f) + '</td>' +
                '<td>' + fmtDate(f.date) + '</td>' +
                '<td style="text-align:center"><button class="btn ' + (f.st === 'Suspicious' && f.can_quarantine ? 'btn-danger' : 'btn-outline') + ' btn-sm" data-do="' + esc(f.st) + '" type="button" style="min-width:92px">' + (f.st === 'Suspicious' && !f.can_quarantine ? 'View Details' : (action[f.st] || 'Review')) + '</button></td>' +
                '<td><button class="kebab" data-more aria-label="More actions for ' + esc(f.path) + '" type="button"><svg class="i" viewBox="0 0 24 24" fill="currentColor"><circle cx="5" cy="12" r="1.8"/><circle cx="12" cy="12" r="1.8"/><circle cx="19" cy="12" r="1.8"/></svg></button></td></tr>').join('')
            : '<tr class="empty-row"><td colspan="8">' + (state.total ? 'No files match these filters.' : 'All clear. Nothing needs attention right now.') + '</td></tr>';

        GWQSH.labelTable($('#fBody').closest('table'));

        // Info text.
        if (state.total > 0) {
            const start = (state.page - 1) * state.perPage + 1;
            const end = Math.min(state.page * state.perPage, state.total);
            $('#fInfo').textContent = 'Showing ' + start + '–' + end + ' of ' + state.total + (state.search || state.type || state.status || state.severity ? ' matching findings' : ' findings');
        } else {
            $('#fInfo').textContent = '';
        }

        // Pagination.
        let p = '<button type="button" data-p="' + (state.page - 1) + '" aria-label="Previous page"' + (state.page === 1 ? ' disabled' : '') + '><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="m15 18-6-6 6-6"/></svg></button>';
        const pages = [...new Set([1, state.pages, state.page - 2, state.page - 1, state.page, state.page + 1, state.page + 2])].filter(i => i >= 1 && i <= state.pages).sort((a, b) => a - b);
        pages.forEach((i, index) => {
            if (index && i - pages[index - 1] > 1) p += '<span aria-hidden="true">…</span>';
            p += '<button type="button" data-p="' + i + '"' + (i === state.page ? ' aria-current="page"' : '') + '>' + i + '</button>';
        });
        p += '<button type="button" data-p="' + (state.page + 1) + '" aria-label="Next page"' + (state.page === state.pages ? ' disabled' : '') + '><svg class="i" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="m9 18 6-6-6-6"/></svg></button>';
        $('#fPager').innerHTML = state.pages > 1 ? p : '';

        $('#checkAll').checked = slice.length > 0 && slice.every(f => sel.has(f.id));
        $('#checkAll').indeterminate = slice.some(f => sel.has(f.id)) && !slice.every(f => sel.has(f.id));
        $('#bulk').classList.toggle('hide', !sel.size);
        $('#bulkN').textContent = sel.size + ' selected';
    }

    async function doFindingAction(id, operation, message, type = 'ok') {
        const key = operation + ':' + id;
        if (pendingActions.has(key)) return false;
        pendingActions.add(key);
        try {
            const res = await GWQSH.ajax(operation, { finding_id: id });
            if (!res.success) { toast(res.data?.message || 'Action failed.', 'err'); await refreshCurrentView(); return false; }
            toast(message, type);
            await refreshCurrentView();
            return true;
        } finally { pendingActions.delete(key); }
    }

    async function removeFiles(ids, message, type = 'ok', operation = 'mark_reviewed') {
        if (operation === 'mark_reviewed') {
            const key = 'review:' + [...ids].sort((a,b) => a-b).join(',');
            if (pendingActions.has(key)) return false;
            pendingActions.add(key);
            try {
                const res = await GWQSH.ajax('bulk_mark_reviewed', {finding_ids: ids.join(',')});
                if (!res.success) { toast(res.data?.message || 'Review failed.', 'err'); return false; }
                toast(res.data.results.reviewed + ' findings reviewed' + (res.data.results.skipped ? '; ' + res.data.results.skipped + ' already reviewed or unavailable' : ''), type);
                await refreshCurrentView();
                return true;
            } finally { pendingActions.delete(key); }
        }
        let ok = 0; const errors = [];
        for (const id of ids) {
            const res = await GWQSH.ajax(operation === 'restore_file' ? 'restore_trusted' : operation, { finding_id: id });
            if (res.success) ok++; else errors.push(res.data?.message || 'Action failed.');
        }
        await refreshCurrentView();
        toast(errors.length ? ok + ' completed, ' + errors.length + ' failed: ' + errors.join('; ') : message, errors.length ? 'warn' : type);
        return !errors.length;
    }

    function acceptCurrent(f) {
        confirm('Keep New / Accept Current?', esc(f.path) + ' will become the trusted baseline.' + (f.type === 'Core' ? ' This modifies your local baseline for an official core file. Official checksum checks will continue; restoring the official version is preferred.' : ''), 'Keep New / Accept Current',
            () => doFindingAction(f.id, 'accept_current', 'Current version accepted as trusted'));
        return false;
    }

    async function reviewChange(f) {
        let res;
        try { res = await GWQSH.ajax('get_diff', { finding_id: f.id }); } catch (error) { toast('Unable to load the file review. Retry shortly.', 'err'); return; }
        if (!res.success) { toast(res.data?.message || 'Review unavailable.', 'err'); return; }
        const review = res.data;
        const actions = [{ label: 'Close' }];
        actions.push({ label: f.type === 'Core' ? 'Restore Official Version' : 'Restore Old / Trusted Version', cls: 'btn-primary',
            fn: () => doFindingAction(f.id, 'restore_trusted', 'Trusted version restored; current version preserved') });
        actions.push({ label: 'Keep New / Accept Current', cls: 'btn-neutral', fn: () => acceptCurrent(f) });
        if (f.can_quarantine) actions.push({ label: 'Quarantine', cls: 'btn-danger', fn: () => doFindingAction(f.id, 'quarantine_finding', 'File quarantined', 'warn') });
        modal({ title: 'Review Change: ' + esc(f.path.split('/').pop()), wide: true,
            body: '<p class="muted">' + esc(f.path) + '</p><h4>Trusted / Old Version → Current / New Version</h4>' + review.diff +
                (!review.can_accept ? '<p class="muted">Resolve or quarantine this malware finding before updating the trusted baseline.</p>' : ''),
            actions, onOpen: bg => {
                const buttons = bg.querySelectorAll('.modal-f button');
                buttons[1].disabled = !review.can_restore;
                buttons[2].disabled = !review.can_accept;
            }
        });
    }

    $('#fBody').addEventListener('click', async e => {
        const tr = e.target.closest('tr[data-id]');
        const f = tr && files.find(x => x.id === Number(tr.dataset.id));
        if (!f) return;
        if (e.target.matches('.checkbox')) { e.target.checked ? sel.add(f.id) : sel.delete(f.id); draw(); return; }
        if (e.target.closest('[data-do]')) {
            if (f.st === 'Modified') return reviewChange(f);
            if (f.st === 'Suspicious' && !f.can_quarantine) { modal({ title: 'Finding Details', body: '<p>' + esc(f.path) + '</p><p>' + esc(f.det) + '</p>', actions: [{ label: 'Close' }] }); return; }
            if (f.st === 'Suspicious' && f.can_quarantine) {
                confirm('Quarantine this file?', esc(f.path) + ' will be isolated by Gracewell.', 'Quarantine', () => doFindingAction(f.id, 'quarantine_finding', 'File quarantined', 'warn'), true);
            } else if (f.st === 'Missing') {
                modal({ title: 'Review Missing File', body: '<p>' + esc(f.path) + '</p><p>' + esc(f.det) + '</p>', actions: [
                    { label: 'Close' }, { label: 'Mark as reviewed', fn: () => doFindingAction(f.id, 'mark_reviewed', 'Finding reviewed') },
                    ...(f.type === 'Core' ? [{ label: 'Restore Official Version', cls: 'btn-primary', fn: () => doFindingAction(f.id, 'restore_trusted', 'Official version restored') }] : [])
                ] });
            }
        }
        if (e.target.closest('[data-more]')) {
            const actions = [{ label: 'Copy path', fn: () => GWQSH.copy(f.path, 'File path copied') }];
            if (f.st === 'Modified') actions.push({ label: 'Review Change', fn: () => { reviewChange(f); return true; } });
            if (f.can_quarantine) actions.push({ label: 'Quarantine', cls: 'btn-danger', fn: () => doFindingAction(f.id, 'quarantine_finding', 'File quarantined', 'warn') });
            actions.push({ label: 'Mark as reviewed', fn: () => doFindingAction(f.id, 'mark_reviewed', 'Finding reviewed') });
            modal({ title: esc(f.path.split('/').pop()), body: '<p class="path">' + esc(f.path) + '</p><p>' + esc(f.type) + ' · ' + esc(f.st) + '</p><p>' + esc(f.det) + '</p>', actions });
        }
    });

    $('#checkAll').addEventListener('change', e => { files.forEach(f => e.target.checked ? sel.add(f.id) : sel.delete(f.id)); draw(); });
    $('#bulkClear').addEventListener('click', () => { sel.clear(); draw(); });
    $('#bulkIgnore').addEventListener('click', () => removeFiles([...sel], 'Selected findings reviewed'));
    async function bulkQuarantine(ids) {
        const res = await GWQSH.ajax('bulk_quarantine', { finding_ids: ids.join(',') });
        await refreshCurrentView();
        if (!res.success) { toast(res.data?.message || 'Bulk action failed.', 'err'); return false; }
        const result = res.data.results;
        toast(result.quarantined + ' quarantined, ' + result.failed + ' failed' + (result.errors?.length ? ': ' + result.errors.map(x => x.message).join('; ') : ''), result.failed ? 'warn' : 'ok');
        return true;
    }
    $('#bulkQuar').addEventListener('click', () => {
        const ids = files.filter(f => sel.has(f.id) && f.can_quarantine).map(f => f.id);
        if (!ids.length) { toast('No selected findings are eligible for quarantine.', 'info'); return; }
        confirm('Quarantine ' + ids.length + ' selected findings?', 'Eligible selected findings on this page will be isolated.', 'Quarantine Selected', () => bulkQuarantine(ids), true);
    });

    $('#pageSize').value = state.perPage;
    $('#pageSize').addEventListener('change', e => { state.perPage = Number(e.target.value); refreshCurrentView(true); });
    $('#fPager').addEventListener('click', e => {
        const b = e.target.closest('[data-p]');
        if (!b || b.disabled) return;
        state.page = Number(b.dataset.p); refreshCurrentView();
    });
    let filterTimeout;
    const filterMap = { fSearch: 'search', fLoc: 'type', fStat: 'status', fSeverity: 'severity', fSort: 'sort', fOrder: 'order' };
    Object.entries(filterMap).forEach(([id, key]) => $('#' + id).addEventListener('input', e => {
        state[key] = e.target.value.trim();
        if (key === 'status') { state.tab = ''; $$('#fTabs .seg-btn').forEach(b => b.setAttribute('aria-selected', b.dataset.t === '')); }
        clearTimeout(filterTimeout); filterTimeout = setTimeout(() => refreshCurrentView(true), key === 'search' ? 300 : 0);
    }));
    $('#fTabs').addEventListener('click', e => {
        const b = e.target.closest('.seg-btn'); if (!b) return;
        $$('#fTabs .seg-btn').forEach(x => x.setAttribute('aria-selected', x === b));
        state.tab = state.status = b.dataset.t; $('#fStat').value = state.status; refreshCurrentView(true);
    });
    $('#sortDate').addEventListener('click', e => {
        state.sort = 'date'; state.order = state.order === 'ASC' ? 'DESC' : 'ASC';
        $('#fSort').value = state.sort; $('#fOrder').value = state.order;
        e.currentTarget.querySelector('.i').style.transform = state.order === 'ASC' ? 'rotate(180deg)' : '';
        refreshCurrentView(true);
    });

    function drawQuarantine() {
        const entries = Object.values(quarantine);
        const pages = Math.max(1, Math.ceil(entries.length / qPerPage));
        qPage = Math.min(qPage, pages);
        const visible = entries.slice((qPage - 1) * qPerPage, qPage * qPerPage);
        $('#qBody').innerHTML = visible.length ? visible.map(item => '<tr data-artifact="' + esc(item.file) + '"><td><input class="checkbox" type="checkbox" aria-label="Select ' + esc(item.display_path) + '"' + (qSel.has(item.file) ? ' checked' : '') + '></td><td class="path">' + esc(item.display_path) + '</td><td>' + esc(item.component || item.file_type || 'MU Plugin') + '</td><td>' + esc(({scan_quarantine: 'Scan isolation', restore_backup: 'Restoration backup', 'restore backup': 'Restoration backup'})[item.reason] || item.reason || 'Guardian isolation') + ' · ' + esc(item.severity || '') + '</td><td>' + fmtDate(Number(item.time) * 1000) + '</td><td title="' + esc(item.hash) + '">' + fmt(Number(item.size || 0)) + ' bytes<br>' + esc((item.hash || '').slice(0, 16)) + '…</td><td><span class="pill p-amber">' + esc(item.status) + '</span></td><td><button class="btn btn-outline btn-sm" type="button" data-q="restore_quarantine"' + (!item.present ? ' disabled' : '') + '>Restore</button> <button class="btn btn-danger btn-sm" type="button" data-q="delete_quarantine" aria-label="Delete quarantined copy permanently">Delete</button></td></tr>').join('') : '<tr><td colspan="8">Quarantine is empty.</td></tr>';
        GWQSH.labelTable($('#qBody').closest('table'));
        $('#qSelectAll').checked = visible.length > 0 && visible.every(x => qSel.has(x.file));
        $('#qSelectAll').indeterminate = visible.some(x => qSel.has(x.file)) && !$('#qSelectAll').checked;
        $('#qBulk').classList.toggle('hide', !qSel.size); $('#qSelected').textContent = qSel.size + ' selected';
        $('#qClearAll').disabled = !entries.length;
        $('#qCount').textContent = entries.length;
        $('#qInfo').textContent = entries.length ? 'Showing ' + ((qPage - 1) * qPerPage + 1) + '–' + Math.min(qPage * qPerPage, entries.length) + ' of ' + entries.length + ' copies' : 'Quarantine is empty';
        $('#qPager').innerHTML = pages > 1 ? '<button type="button" data-qp="' + (qPage - 1) + '"' + (qPage === 1 ? ' disabled' : '') + '>Previous</button><span>' + qPage + ' / ' + pages + '</span><button type="button" data-qp="' + (qPage + 1) + '"' + (qPage === pages ? ' disabled' : '') + '>Next</button>' : '';
    }
    async function quarantineAction(operation, params) {
        const key = operation + ':' + JSON.stringify(params);
        if (pendingActions.has(key)) return false;
        pendingActions.add(key);
        try {
            const res = await GWQSH.ajax(operation, params);
            await refreshCurrentView();
            if (!res.success) { toast(res.data?.message || 'Quarantine action failed.', 'err'); return false; }
            const result = res.data.results;
            toast(result ? (result.restored ?? result.deleted ?? 0) + ' completed, ' + result.failed + ' failed' + (result.errors?.length ? ': ' + result.errors.map(x => x.message).join('; ') : '') : 'Quarantine updated.', result?.failed ? 'warn' : 'ok');
            return true;
        } finally { pendingActions.delete(key); }
    }
    $('#qBody').addEventListener('click', e => {
        const row = e.target.closest('[data-artifact]'); if (!row) return;
        const name = row.dataset.artifact;
        if (e.target.matches('.checkbox')) { e.target.checked ? qSel.add(name) : qSel.delete(name); drawQuarantine(); return; }
        const button = e.target.closest('[data-q]'); if (!button) return;
        const deleting = button.dataset.q === 'delete_quarantine';
        confirm(deleting ? 'Delete quarantined copy permanently?' : 'Restore quarantined file?', deleting ? 'This cannot be undone. Live files will remain untouched.' : 'The file will return to its original path and be evaluated on the next scan. Existing files are never overwritten.', deleting ? 'Delete Permanently' : 'Restore', () => quarantineAction(button.dataset.q, { artifact: name }), deleting);
    });
    $('#qSelectAll').addEventListener('change', e => { Object.values(quarantine).slice((qPage - 1) * qPerPage, qPage * qPerPage).forEach(x => e.target.checked ? qSel.add(x.file) : qSel.delete(x.file)); drawQuarantine(); });
    $('#qClearSelection').addEventListener('click', () => { qSel.clear(); drawQuarantine(); });
    $('#qPager').addEventListener('click', e => { const b = e.target.closest('[data-qp]'); if (b && !b.disabled) { qPage = Number(b.dataset.qp); qSel.clear(); drawQuarantine(); } });
    $('#qRestoreSelected').addEventListener('click', () => confirm('Restore Selected?', 'Existing live files will be skipped. Restored content will be inspected on the next scan.', 'Restore Selected', () => quarantineAction('bulk_restore_quarantine', { artifacts: [...qSel].join(',') })));
    $('#qDeleteSelected').addEventListener('click', () => confirm('Delete Selected permanently?', 'This cannot be undone.', 'Delete Selected', () => quarantineAction('bulk_delete_quarantine', { artifacts: [...qSel].join(',') }), true));
    $('#qClearAll').addEventListener('click', () => confirm('Clear All Quarantine?', 'Permanently delete all quarantined copies? This cannot be undone.', 'Clear All Quarantine', () => quarantineAction('clear_all_quarantine', {}), true));

    $('#qPageSize').addEventListener('change', e => { qPerPage = Number(e.target.value); qPage = 1; qSel.clear(); drawQuarantine(); });

    /* ---------- tools ---------- */
    $('#toolRepair').addEventListener('click', async () => {
        state.status = 'Modified'; state.tab = 'Modified'; state.page = 1;
        $('#fStat').value = 'Modified';
        $$('#fTabs [data-t]').forEach(b => b.setAttribute('aria-selected', String(b.dataset.t === 'Modified')));
        switchTable('results'); await refreshCurrentView(true);
        $('#results').scrollIntoView({ behavior: 'smooth', block: 'start' });
        toast('Choose Review Change to inspect and restore a verified trusted copy.', 'info');
    });
    $('#toolReplace').addEventListener('click', () => {
        const ids = files.filter(f => f.type === 'Core' && f.st === 'Modified').map(f => f.id);
        if (!ids.length) { toast('No modified core findings on this page. Use the Core / Modified filters to find them.', 'info'); return; }
        confirm('Replace ' + ids.length + ' modified core files on this page?',
            'Security Suite Pro downloads clean copies from WordPress.org and overwrites the modified files. A backup is kept in quarantine.',
            'Replace files',
            async () => {
                return removeFiles(ids, ids.length + ' core files replaced with clean copies', 'ok', 'restore_file');
            });
    });

    $('#toolQuar').addEventListener('click', () => {
        const ids = files.filter(f => f.st === 'Suspicious' && f.can_quarantine).map(f => f.id);
        if (!ids.length) { toast('No eligible suspicious findings on this page.', 'info'); return; }
        confirm('Quarantine suspicious findings on this page?', ids.length + ' findings will be isolated.', 'Quarantine', () => bulkQuarantine(ids), true);
    });

    $('#tipsMore').addEventListener('click', e => {
        const open = e.currentTarget.getAttribute('aria-expanded') !== 'true';
        e.currentTarget.setAttribute('aria-expanded', open);
        e.currentTarget.firstChild.textContent = open ? 'Show less ' : 'View All ';
        $$('#tipList .extra').forEach(x => x.classList.toggle('hide', !open));
        if (open && GWQSH.animOn()) GWQSH_Motion.from('#tipList .extra', { opacity: 0, y: -6, stagger: .05, duration: .3 });
    });

    /* ---------- chart ---------- */
    function data(days) {
        const L = [], T = [], C = [], M = [], S = [];
        const cutoff = Date.now() - days * 864e5;
        const history = (D.history || []).filter(row => new Date(row.scan_date.replace(' ', 'T') + 'Z').getTime() + Number(window.GWQSH_CONFIG.site_offset || 0) * -1000 >= cutoff).reverse();
        for (const row of history) {
            const d = new Date(row.scan_date.replace(' ', 'T') + 'Z');
            L.push(d.toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric' }));
            T.push(d.toLocaleDateString('en-US', { timeZone: 'UTC', month: 'short', day: 'numeric', year: 'numeric' }));
            C.push(Number(row.clean_files));
            M.push(Number(row.modified_files));
            S.push(Number(row.suspicious_files));
        }
        return { L, T, C, M, S };
    }

    function chartScale(d) {
        const max = Math.max(1, ...d.C), rMax = Math.max(1, ...d.M, ...d.S);
        const step = Math.max(1, Math.ceil(max / 3)), rStep = Math.max(1, Math.ceil(rMax / 3));
        return { yMax: step * 3, yStep: step, rMax: rStep * 3, rStep };
    }
    let d = data(7);
    const ser = d => [
        { name: 'Clean', color: '#22C55E', data: d.C },
        { name: 'Modified', color: '#F59E0B', data: d.M, axis: 'right', area: false },
        { name: 'Suspicious', color: '#EF4444', data: d.S, axis: 'right', area: false }
    ];

    const chart = GWQSH.lineChart($('#scanChart'), {
        height: 176, labels: d.L,
        ...chartScale(d),
        fmt: v => v >= 1000 ? +(v / 1000).toFixed(1) + 'K' : v,
        pin: null, tipTitle: i => d.T[i],
        aria: 'Clean, modified and suspicious files per scan',
        series: ser(d)
    });

    $('#actRange').addEventListener('change', e => {
        d = data(+e.target.value);
        chart.update({ labels: d.L, pin: null, ...chartScale(d), series: ser(d) });
    });

    /* ---------- manual scan ---------- */
    $('#runScan').addEventListener('click', async e => {
        const b = e.currentTarget, h = b.innerHTML;
        b.disabled = true;
        b.textContent = 'Scanning…';

        const pill = $('#scanPill');
        pill.className = 'pill p-blue';
        pill.textContent = 'Running';

        $('#scanProg').classList.remove('hide');
        const bar = $('#scanBar');
        bar.closest('.bar').hidden = true;
        bar.style.width = '0%';

        bar.style.width = '100%';
        bar.style.opacity = '.35';
        let elapsed = 0;
        $('#scanTxt').textContent = 'Scanning files…';
        const iv = setInterval(() => { $('#scanTxt').textContent = 'Scanning files… ' + (++elapsed) + ' seconds elapsed'; }, 1000);

        let scanRes = null;
        if (window.GWQSH && GWQSH.ajax) {
            try { scanRes = await GWQSH.ajax('run_scan'); } catch (error) { scanRes = { success: false, data: { message: 'Unable to start scan. Retry shortly.' } }; }
        }

        clearInterval(iv);
        bar.style.width = '100%';

        if (!scanRes || !scanRes.success) {
            b.disabled = false;
            b.innerHTML = h;
            pill.className = 'pill p-red';
            pill.textContent = 'Scan failed';
            $('#scanProg').classList.add('hide');
            toast(scanRes?.data?.message || 'Scan could not complete.', 'warn');
            return;
        }

        try {
        while (scanRes.data?.result?.pending) {
            $('#scanTxt').textContent = 'Continuing scan…';
            await new Promise(resolve => setTimeout(resolve, 1000));
            scanRes = await GWQSH.ajax('run_scan', { resume: 1 });
            if (!scanRes.success) break;
        }
        } catch (error) { scanRes = { success: false, data: { message: 'Scan connection interrupted. Retry to resume the saved scan.' } }; }
        b.disabled = false; b.innerHTML = h;
        pill.className = scanRes.success ? 'pill p-green' : 'pill p-red';
        pill.textContent = scanRes.success ? 'Completed' : 'Scan failed';
        $('#scanProg').classList.add('hide');
        await refreshCurrentView(true);
        $('#lastDate').textContent = D.summary?.last_date || 'Never';
        $('#kvDur').textContent = Number(D.summary?.duration || 0) + ' seconds';
        $('#kvFiles').textContent = fmt(TOTAL);
        d = data(Number($('#actRange').value)); chart.update({ labels: d.L, ...chartScale(d), series: ser(d), pin: null });
        toast(scanRes.success ? 'Scan complete. ' + state.total + ' findings need attention.' : scanRes.data?.message || 'Scan failed.', scanRes.success ? 'ok' : 'err');
    });

    $('#heroRunScan')?.addEventListener('click', () => {
        const runBtn = $('#runScan');
        if (runBtn) {
            runBtn.scrollIntoView({ behavior: 'smooth', block: 'center' });
            runBtn.click();
        }
    });

    /* ---------- Schedule Scan Modal (Phase 7) ---------- */
    $('#qs-schedule-scan-btn')?.addEventListener('click', async () => {
        const trigger = $('#qs-schedule-scan-btn');
        if (trigger.disabled) return;
        trigger.disabled = true;
        let schedule;
        try {
            const dataRes = await GWQSH.ajax('scan_schedule_data');
            if (!dataRes?.success || !dataRes.data?.settings) throw new Error(dataRes?.data?.message || 'Unable to load the saved schedule.');
            schedule = dataRes.data.settings;
            D.schedule = dataRes.data;
        } catch (error) {
            toast(error.message || 'Unable to load the saved schedule.', 'err');
            return;
        } finally { trigger.disabled = false; }

        const initialFreq = ({weekly:'gwqsh_weekly',monthly:'gwqsh_monthly'})[schedule.frequency] || schedule.frequency;
        const initialTime = schedule.time || '02:00';

        const bodyHtml = `
            <form id="qs-sched-form" class="qs-sched-modal-form" onsubmit="return false;">
                <div class="qs-sched-group">
                    <label class="qs-sched-label" for="qs-sched-freq">
                        <b>Frequency</b>
                        <span>How often scheduled scanning runs</span>
                    </label>
                    <select id="qs-sched-freq" class="field qs-select qs-sched-select">
                        <option value="disabled" ${!schedule.enabled ? 'selected' : ''}>Disabled</option>
                        ${['hourly','twicedaily','gwqsh_custom'].includes(initialFreq) ? `<option value="${esc(initialFreq)}" ${schedule.enabled ? 'selected' : ''}>${esc(D.schedule.frequency_label)}</option>` : ''}
                        <option value="daily" ${schedule.enabled && initialFreq === 'daily' ? 'selected' : ''}>Daily</option>
                        <option value="gwqsh_weekly" ${schedule.enabled && initialFreq === 'gwqsh_weekly' ? 'selected' : ''}>Weekly</option>
                        <option value="gwqsh_monthly" ${schedule.enabled && initialFreq === 'gwqsh_monthly' ? 'selected' : ''}>Monthly</option>
                    </select>
                </div>
                <div class="qs-sched-group">
                    <label class="qs-sched-label" for="qs-sched-time">
                        <b>Time</b>
                        <span>WordPress timezone: ${esc(window.GWQSH_CONFIG.site_timezone)}</span>
                    </label>
                    <div class="qs-time-input-wrap">
                        <svg class="i qs-time-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <circle cx="12" cy="12" r="10" />
                            <polyline points="12 6 12 12 16 14" />
                        </svg>
                        <input type="time" id="qs-sched-time" class="field qs-time-field" value="${esc(initialTime)}" required>
                    </div>
                </div>
            </form>
        `;

        trigger.focus();
        modal({
            title: 'Schedule automatic scans',
            canDismissBackdrop: bg => !bg.dataset.dirty && !bg.querySelector('[aria-busy=true]'),
            onOpen: bg => { bg.classList.add('qs-schedule-dialog'); bg.querySelector('form').addEventListener('input', () => { bg.dataset.dirty = '1'; }); bg.querySelector('form').addEventListener('change', () => { bg.dataset.dirty = '1'; }); },
            body: bodyHtml,
            actions: [
                { label: 'Cancel' },
                {
                    label: 'Save schedule',
                    cls: 'btn-primary',
                    fn: async (bg) => {
                        if (!bg.querySelector('form').reportValidity()) return false;
                        const freq = bg.querySelector('#qs-sched-freq')?.value || 'daily';
                        const time = bg.querySelector('#qs-sched-time')?.value || '02:00';

                        try {
                            const res = await GWQSH.ajax('scan_schedule_save', {
                                settings: JSON.stringify({
                                    ...schedule,
                                    enabled: freq !== 'disabled',
                                    frequency: freq === 'disabled' ? initialFreq : freq,
                                    time: time
                                })
                            });

                            if (res && res.success) {
                                D.schedule = res.data;
                                const nextDisplay = $('#qs-next-scan-display');
                                if (nextDisplay) {
                                    nextDisplay.textContent = res.data?.next || 'Scheduled';
                                }
                                toast(res.data.settings.enabled ? 'Scan schedule saved successfully.' : 'Scheduled scans disabled.', 'ok');
                                return true;
                            } else {
                                toast(res?.data?.message || 'Failed to save schedule.', 'err');
                                return false;
                            }
                        } catch (err) {
                            toast(err?.message || 'Error saving schedule.', 'err');
                            return false;
                        }
                    }
                }
            ]
        });
    });

    $('#toolSignatures')?.addEventListener('click', () => {
        const tpl = document.getElementById('tpl-signatures');
        if (!tpl) return;
        const clone = tpl.content.cloneNode(true);
        const div = document.createElement('div');
        div.appendChild(clone);
        const details = div.querySelector('details');
        if (details) details.open = true;
        GWQSH.modal({
            title: 'Signed Malware Signature Updates',
            wide: true,
            body: div.innerHTML,
            onOpen: bg => {
                const d = bg.querySelector('details');
                if (d) d.open = true;
            }
        });
    });

    draw();
    drawQuarantine();
    refreshSummary();
    refreshCurrentView();
});
