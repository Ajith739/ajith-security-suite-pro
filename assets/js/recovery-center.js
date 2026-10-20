/* Incident investigation inside the existing File Integrity visual system. */
(() => {
    'use strict';
    const ui = window.GWQSH;
    const trigger = document.getElementById('toolRecoveryCenter');
    if (!ui || !trigger) return;
    const esc = value => ui.esc(String(value ?? ''));
    const request = async (action, data = {}) => {
        const result = await ui.ajax(action, data);
        if (!result?.success) throw new Error(result?.data?.message || 'Unable to load investigation evidence.');
        return result.data;
    };
    trigger.addEventListener('click', async () => {
        trigger.disabled = true;
        try {
            let snapshot = await request('recovery_center_status');
            let busy = false;
            let dialog;
            const draw = () => {
                const db = snapshot.database || {};
                const running = db.state === 'running';
                const records = (db.findings || []).map(record => '<li><b>' + esc(record.table) + ' #' + esc(record.id) + '</b> · ' + esc(record.field) + '<ul>' + Object.entries(record.rules).map(([id, description]) => '<li>' + esc(id) + ': ' + esc(description) + '</li>').join('') + '</ul><small>Inspected-byte SHA-256: ' + esc(record.sample_sha256) + (record.partial ? ' (partial content)' : '') + '</small></li>').join('');
                const omissions = (db.omitted || []).map(record => '<li>' + esc(record.table) + ' #' + esc(record.id) + ': ' + esc(record.reason) + '</li>').join('');
                dialog.el.querySelector('.modal-b').innerHTML =
                    '<p><strong>' + esc(snapshot.state) + '</strong>. Review the evidence and preserve verified backups before remediation.</p>' +
                    '<h4>1. Identify the incident</h4><p>Review saved file findings, account membership, recent events and database evidence.</p>' +
                    '<p>Database inspection: <b>' + esc(db.state || 'not run') + '</b>; ' + esc(db.read || 0) + ' records read, ' + esc(db.inspected || 0) + ' inspected, ' + esc(db.finding_count || 0) + ' review findings, ' + esc(db.omitted_count || 0) + ' exclusions or partial records.</p>' +
                    '<p role="status" data-recovery-status></p><div class="qs-enterprise-actions"><button type="button" class="btn btn-primary btn-sm" data-recovery="scan">' + (running ? 'Continue database scan' : 'Start database scan') + '</button>' + (running ? '<button type="button" class="btn btn-outline btn-sm" data-recovery="cancel">Cancel database scan</button>' : '') + '<button type="button" class="btn btn-outline btn-sm" data-recovery="refresh">Refresh evidence</button><button type="button" class="btn btn-outline btn-sm" data-recovery="export">Export investigation</button></div>' +
                    '<details><summary>Database evidence requiring review (' + esc((db.findings || []).length) + ' shown)</summary>' + (records ? '<ul>' + records + '</ul>' : '<p>No saved database evidence. A missing, failed or incomplete scan does not establish absence of compromise.</p>') + '</details>' +
                    '<details><summary>Inspection coverage and exclusions</summary><ul>' + (snapshot.limitations || []).concat(db.coverage || []).map(note => '<li>' + esc(note) + '</li>').join('') + '</ul><p>Exclusion counts: ' + esc(JSON.stringify(db.omission_reasons || {})) + '</p><ul>' + omissions + '</ul><p>Current source index: ' + esc(db.source ?? 'not started') + '; last record ID: ' + esc(db.cursor || 0) + '. Background continuation requires functioning WP-Cron.</p></details>' +
                    '<details><summary>Administrator membership (review authorization)</summary><ul>' + (snapshot.accounts || []).map(account => '<li>#' + esc(account.ID) + ' ' + esc(account.user_login) + ' <button type="button" class="btn btn-outline btn-sm" data-recovery="account" data-user-id="' + esc(account.ID) + '">Review sessions &amp; credentials</button></li>').join('') + '</ul></details>' +
                    '<h4>2. Contain confirmed threats</h4><p>Use the existing IP controls and file quarantine after reviewing evidence. Preserve administrator access. Review compromised sessions and application passwords in WordPress user profiles.</p>' +
                    '<h4>3. Recover trusted content</h4><p>Review file findings and use existing verified core restore or trusted-copy recovery. Database changes require an independently verified backup, exact-record review and confirmation. This workflow does not modify database content.</p>' +
                    '<button type="button" class="btn btn-outline btn-sm" data-recovery="files">Review existing file findings</button>' +
                    '<h4>4. Validate recovery</h4><p>Run fresh file and database inspections. Review administrators, cron persistence, component vulnerabilities, permissions and the entry point. A zero-finding scan alone does not verify recovery.</p>' +
                    '<h4>5. Monitor for reinfection</h4><p>Keep scheduled file scans and security alerts configured. Review new administrators, recurring files and unexpected configuration changes.</p>' +
                    '<details><summary>Recent security timeline</summary><ul>' + (snapshot.timeline || []).map(event => '<li>' + esc(ui.date(event.event_time)) + ': ' + esc(event.event_name) + '</li>').join('') + '</ul></details>';
            };
            dialog = ui.modal({ title: 'Security Recovery Center', body: '', wide: true, onClose: () => queueMicrotask(() => trigger.focus()), actions: [{ label: 'Close' }] });
            draw();
            dialog.el.addEventListener('click', async event => {
                const button = event.target.closest('[data-recovery]');
                if (!button || busy) return;
                const action = button.dataset.recovery;
                if (action === 'files') { dialog.close(); document.getElementById('showResults')?.click(); return; }
                if (action === 'account') {
                    button.disabled = true;
                    try {
                        const account = await request('recovery_account_security', { user_id: button.dataset.userId });
                        const body = '<p>' + esc(account.scope) + '</p><p>' + esc(account.session_count) + ' active sessions; ' + esc(account.application_password_count) + ' application credentials. Showing at most ' + esc(account.display_limit) + ' of each.</p><ul>' + account.sessions.map(session => '<li>Login: ' + esc(session.login ? ui.date(new Date(session.login * 1000).toISOString()) : 'Unknown') + '; expires: ' + esc(ui.date(new Date(session.expires * 1000).toISOString())) + '; device: ' + esc(session.device) + '</li>').join('') + '</ul><p>Revoking your own sessions preserves this browser session. Other accounts lose all current WordPress sessions. Rotate compromised passwords and review other authentication methods separately.</p><label>Type REVOKE ' + esc(account.user_id) + ' to confirm the selected action<input data-containment-confirm autocomplete="off"></label><p><button type="button" class="btn btn-outline btn-sm" data-contain-kind="sessions">Revoke sessions</button></p><ul>' + account.application_passwords.map(credential => '<li>' + esc(credential.name) + ' <button type="button" class="btn btn-outline btn-sm" data-contain-kind="application_password" data-uuid="' + esc(credential.uuid) + '">Revoke this credential</button></li>').join('') + '</ul>';
                        const accountDialog = ui.modal({ title: 'Account #' + account.user_id + ' security', body, actions: [{ label: 'Close' }] });
                        accountDialog.el.addEventListener('click', async click => {
                            const control = click.target.closest('[data-contain-kind]');
                            if (!control || accountDialog.el.dataset.busy) return;
                            accountDialog.el.dataset.busy = '1'; control.disabled = true;
                            try {
                                await request(control.dataset.containKind === 'sessions' ? 'recovery_revoke_sessions' : 'recovery_revoke_application_password', { user_id: account.user_id, uuid: control.dataset.uuid || '', confirmed: accountDialog.el.querySelector('[data-containment-confirm]').value });
                                ui.toast('Selected account access revoked. Review fresh evidence and rotate compromised credentials.', 'ok'); accountDialog.close();
                            } catch (error) { ui.toast(error.message, 'err'); }
                            finally { delete accountDialog.el.dataset.busy; control.disabled = false; }
                        });
                    } catch (error) { ui.toast(error.message, 'err'); }
                    finally { button.disabled = false; }
                    return;
                }
                if (action === 'export') {
                    const url = URL.createObjectURL(new Blob([JSON.stringify(snapshot, null, 2)], { type: 'application/json' }));
                    const link = document.createElement('a'); link.href = url; link.download = 'gracewell-investigation.json'; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); return;
                }
                busy = true;
                dialog.el.querySelectorAll('[data-recovery]').forEach(element => { element.disabled = true; });
                try {
                    const db = snapshot.database || {};
                    if (action === 'scan') await request(db.state === 'running' ? 'database_scan_continue' : 'database_scan_start', { job_id: db.id || '' });
                    if (action === 'cancel') await request('database_scan_cancel', { job_id: db.id || '' });
                    snapshot = await request('recovery_center_status'); draw();
                    ui.toast(action === 'scan' ? 'Database inspection updated. Review progress and coverage.' : action === 'cancel' ? 'Database inspection cancelled.' : 'Investigation evidence refreshed.', 'ok');
                } catch (error) {
                    dialog.el.querySelector('[data-recovery-status]').textContent = error.message;
                    ui.toast(error.message, 'err');
                } finally {
                    busy = false; dialog.el.querySelectorAll('[data-recovery]').forEach(element => { element.disabled = false; });
                }
            });
        } catch (error) { ui.toast(error.message, 'err'); }
        finally { trigger.disabled = false; }
    });
})();
