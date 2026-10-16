/* Security Suite Pro Hardening: server-assessed state, explicit changes only. */
document.addEventListener('DOMContentLoaded', function () {
    const app = document.querySelector('.qs-pro-hardening');
    if (!app || !window.GWQSH) return;
    const { esc, toast, modal, confirm } = GWQSH;
    const $ = s => app.querySelector(s);
    const $$ = s => Array.from(app.querySelectorAll(s));
    let data = window.GWQSH_DATA || {}, busy = false, all = false;
    const text = (s, value) => { const el = $(s); if (el) el.textContent = value; };
    function render() {
        if (!data.rows) return;
        text('#scoreN', data.score); text('#ringN', data.score);
        text('#enabledN', data.passed); text('#enabledBadge', data.passed + ' / 6');
        text('#pendingN', data.pending); text('#pendingBadge', data.pending + ' pending');
        text('#riskN', data.level); text('#riskBadge', data.level);
        $('#riskBadge').className = 'hd-pill ' + (data.level === 'Low' ? 'hd-green' : 'hd-orange');
        $('#scoreBar').style.width = data.score + '%';
        $('#scoreBar').parentElement.setAttribute('aria-valuenow', data.score);
        $('#scoreArc').style.strokeDasharray = '427.26';
        $('#scoreArc').style.strokeDashoffset = 427.26 * (1 - data.score / 100);
        $('#scoreRing svg').setAttribute('aria-label', 'Hardening score ' + data.score + ' out of 100');
        text('#serverLabel', data.server);
        text('#scoreMsg', data.score >= 85 ? 'Most weighted hardening protections pass.' : 'Review disabled or unverified protections.');
        text('#enabledMsg', data.passed === 6 ? 'All six controls have current evidence.' : 'Controls with current application evidence.');
        text('#pendingMsg', data.pending ? 'Disabled or unverified controls need review.' : 'Nothing left to do in this checklist.');
        Object.entries(data.rows).forEach(([key, row]) => {
            const button = $('[data-toggle="' + key + '"]');
            button.setAttribute('aria-checked', String(row.configured));
            button.setAttribute('aria-describedby', 'status-' + key);
            const status = $('[data-control-status="' + key + '"]');
            status.id = 'status-' + key; status.textContent = row.status;
            status.className = 'hd-pill ' + (row.effective ? 'hd-green' : row.status === 'Failed' ? 'hd-red' : 'hd-orange');
        });
        const components = data.components || {};
        $('#componentScores').innerHTML = [['login', 'Login Protection'], ['tfa', 'Two-Factor Auth'], ['file', 'File Integrity'], ['hardening', 'Hardening'], ['activity', 'Activity Log']].map(([key, name]) => '<div><dt>' + name + '</dt><dd>' + esc(String(components[key] ?? 0)) + '</dd></div>').join('');
        const entries = Object.entries(data.rows).sort((a, b) => Number(a[1].effective) - Number(b[1].effective));
        $('#recommendationList').innerHTML = (all ? entries : entries.slice(0, 4)).map(([key, row]) => '<div class="hd-rec"><span class="hd-rec-icon ' + (row.effective ? 'hd-green' : 'hd-orange') + '" aria-hidden="true">' + (row.effective ? '✓' : '!') + '</span><div><b>' + esc(row.name) + '</b><small>' + esc(row.effective ? 'Current evidence passes.' : row.status) + '</small></div><button class="hd-link" type="button" data-info="' + key + '">' + (row.effective ? 'Done' : 'Review') + '</button></div>').join('');
        text('#recAll', all ? 'Show Fewer Recommendations ↑' : 'View All Recommendations →');
        text('#apacheCode', data.apache); text('#nginxCode', data.nginx);
        $('#cspMode').value = data.csp.mode; $('#cspPolicy').value = data.csp.policy;
        const expected = Object.entries(data.expected_headers || {}).map(([k, v]) => k + ': ' + v);
        const observed = Object.entries(data.evidence?.headers || {}).map(([k, v]) => k + ': ' + (v || '(absent)'));
        text('#headersPreview', 'Configured values\n' + (expected.join('\n') || 'Security headers are disabled.') + '\n\nLast observed public response\n' + (observed.join('\n') || 'Not verified.'));
        text('#verificationNote', data.evidence?.checked ? 'Checked ' + data.evidence.checked + '. Evidence expires after five minutes. ' + data.evidence.upload_note : 'Public headers and uploads denial are unverified. Verify after server or cache changes.');
    }
    async function change(action, values = {}) {
        if (busy) return false;
        busy = true; app.setAttribute('aria-busy', 'true');
        const buttons = $$('[data-toggle], #resetDef, #revertAll, #verifyHardening, #cspForm button');
        buttons.forEach(b => b.disabled = true);
        $('#hardeningStatus').dataset.error = 'false'; text('#hardeningStatus', 'Working…');
        try {
            const result = await GWQSH.ajax(action, { ...values, confirmed: 1 });
            if (!result.success) throw new Error(result.data?.message || 'The change could not be completed.');
            data = result.data; render(); text('#hardeningStatus', 'Saved. Assessment refreshed from the server.');
            toast('Assessment updated', 'ok'); return true;
        } catch (error) {
            const refreshed = await GWQSH.ajax('get_hardening_data');
            if (refreshed.success) { data = refreshed.data; render(); }
            $('#hardeningStatus').dataset.error = 'true'; text('#hardeningStatus', error.message); toast(error.message, 'err'); return false;
        } finally { busy = false; app.removeAttribute('aria-busy'); buttons.forEach(b => b.disabled = false); }
    }
    function details(key) {
        const row = data.rows[key];
        modal({ title: esc(row.name), body: '<p><b>' + esc(row.status) + '</b></p><p>' + esc(row.note) + '</p><p>Saved intent: ' + (row.configured ? 'on' : 'off') + '. Assessment weight: ' + row.weight + ' points.</p>' });
    }
    app.addEventListener('click', e => {
        const info = e.target.closest('[data-info]'); if (info) details(info.dataset.info);
        const toggle = e.target.closest('[data-toggle]');
        if (toggle && !busy) {
            const key = toggle.dataset.toggle, row = data.rows[key], on = !row.configured;
            confirm((on ? 'Enable ' : 'Disable ') + esc(row.name) + '?', esc(row.note) + (key === 'uploads' ? ' Only the exact owned uploads .htaccess block may be changed, with a protected backup. Other server rules remain.' : ' This changes the plugin option and WordPress runtime enforcement.'), on ? 'Enable' : 'Disable', () => change('toggle_hardening', { feature: key, on: on ? 1 : 0 }), !on);
        }
        const copy = e.target.closest('[data-copy-code]');
        if (copy) copyText(data[copy.dataset.copyCode]);
    });
    async function copyText(value) {
        try {
            if (!navigator.clipboard?.writeText) throw new Error('Clipboard access unavailable.');
            await navigator.clipboard.writeText(value); toast('Copied', 'ok');
        } catch (_) {
            modal({ title: 'Copy configuration', body: '<p>Clipboard access is unavailable. Select this text and copy it manually.</p><pre class="code-block">' + esc(value) + '</pre>' });
        }
    }
    $('#recAll').addEventListener('click', () => { all = !all; render(); });
    $('#reviewRecommendations')?.addEventListener('click', () => { all = true; render(); $('#recommendations').scrollIntoView({ block: 'start' }); $('#recAll').focus(); });
    $$('[data-details]').forEach(b => b.addEventListener('click', () => modal({ title: 'Hardening assessment', body: '<p>Score: ' + data.score + ' / 100. ' + data.passed + ' of six controls pass. The ring shows this Hardening assessment.</p><p>XML-RPC 15, editor 15, version disclosure 10, enumeration 15, headers 33, uploads 12 points. Saved intent alone does not establish server protection. Shared module components remain separate.</p>' })));
    $('#resetDef').addEventListener('click', () => confirm('Reset hardening to defaults?', 'Enable XML-RPC blocking, editor restriction, version hiding, enumeration restriction and uploads protection. Disable security headers and custom CSP. On Apache this may add the owned uploads block after backup; other server directives and wp-config.php remain intact.', 'Reset to Defaults', () => change('reset_hardening')));
    $('#revertAll').addEventListener('click', () => confirm('Revert all hardening changes?', 'Disable all six plugin controls and custom CSP. Remove only the exact owned uploads block after backup. Manually installed rules, other plugins and wp-config.php constants may continue to restrict access. Edited or duplicate managed blocks require manual review.', 'Revert All Changes', () => change('revert_hardening'), true));
    $('#verifyHardening').addEventListener('click', () => confirm('Verify this site?', 'Request a fixed public page and, when uploads are writable and on the same origin, briefly create inert .txt and .php probe files containing no PHP code. Check media delivery and HTTP denial, then remove the probes. Up to three five-second requests; no credentials are sent.', 'Verify Now', () => change('verify_hardening')));
    $('#cspForm').addEventListener('submit', e => {
        e.preventDefault();
        const values = { mode: $('#cspMode').value, policy: $('#cspPolicy').value };
        confirm('Save Content Security Policy?', values.mode === 'enforce' ? 'Enforcement can break scripts, styles and integrations. Confirm that you tested this policy in report-only mode. Public frontend only; existing CSP headers are preserved.' : 'Save this policy for public frontend responses. Report-only mode produces browser diagnostics without blocking resources. Existing CSP headers are preserved.', 'Save Policy', () => change('save_hardening_csp', values), values.mode === 'enforce');
    });
    $('#copyCsp').addEventListener('click', () => copyText('Content-Security-Policy-Report-Only: ' + $('#cspPolicy').value));
    const tabs = $$('[data-tab]');
    function selectTab(tab) {
        tabs.forEach(t => { const selected = t === tab; t.setAttribute('aria-selected', String(selected)); t.tabIndex = selected ? 0 : -1; $('#panel-' + t.dataset.tab).hidden = !selected; });
    }
    tabs.forEach((tab, i) => {
        tab.addEventListener('click', () => selectTab(tab));
        tab.addEventListener('keydown', e => {
            let next;
            if (e.key === 'ArrowRight') next = (i + 1) % tabs.length;
            if (e.key === 'ArrowLeft') next = (i + tabs.length - 1) % tabs.length;
            if (e.key === 'Home') next = 0; if (e.key === 'End') next = tabs.length - 1;
            if (next !== undefined) { e.preventDefault(); selectTab(tabs[next]); tabs[next].focus(); }
        });
    });
    render();
    // Evidence expiry is reflected without starting an HTTP verification.
    setInterval(async () => { if (busy || $('#cspForm').contains(document.activeElement) || document.querySelector('.modal-bg') || !data.evidence?.checked) return; const result = await GWQSH.ajax('get_hardening_data'); if (result.success) { data = result.data; render(); } }, 60000);
});
