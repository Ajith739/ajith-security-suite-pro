/* Security Suite Pro command center: real snapshots, responsive SVG, interactive threat map & hardening controls. */
(() => {
    'use strict';
    const root = document.querySelector('.qs-pro-dashboard');
    if (!root || !window.GWQSH) return;
    const $ = s => (root && root.querySelector(s)) || document.querySelector(s);
    const $$ = s => [...((root && root.querySelectorAll(s)) || document.querySelectorAll(s))];
    const esc = window.GWQSH.esc;
    let data = window.GWQSH_DATA || {};
    let requestId = 0;
    let activePoint = null;
    const format = n => Number(n || 0).toLocaleString();
    const scanDate = value => {
        const match = String(value || '').match(/^(\d{4})-(\d{2})-(\d{2}) (\d{2}):(\d{2})/);
        if (!match) return value || '—';
        const [, year, month, day, hour, minute] = match;
        const months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
        return `${months[Number(month) - 1]} ${Number(day)}, ${year}, ${String(Number(hour) % 12 || 12).padStart(2, '0')}:${minute} ${Number(hour) >= 12 ? 'PM' : 'AM'}`;
    };
    const date = window.GWQSH.date;

    /* Security Activity chart (Responsive SVG) */
    const series = [
        ['blocked', 'Blocked requests', '#0755ff'],
        ['login', 'Login attempts', '#00c888'],
        ['files', 'File changes', '#ff9f00'],
        ['malware', 'Suspicious detections', '#ff2039']
    ];

    function drawChart() {
        const chart = $('#activityChart');
        const tip = $('#chartTip');
        if (!chart) return;
        chart.querySelector('svg')?.remove();
        if (tip) tip.hidden = true;
        const d = data.chart_data;
        if (!d || d.error || !d.labels?.length) return;
        const width = chart.clientWidth;
        const height = chart.clientHeight;
        if (width < 50) return;
        const pad = { left: 30, right: 15, top: 9, bottom: 22 };
        const count = d.labels.length;
        const topValue = Math.max(4, ...series.flatMap(([key]) => d[key] || []));
        const step = Math.max(1, Math.ceil(topValue / 4));
        const max = step * 4;
        const x = i => pad.left + i / Math.max(1, count - 1) * (width - pad.left - pad.right);
        const y = v => pad.top + (1 - v / max) * (height - pad.top - pad.bottom);
        const path = values => values.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(2)},${y(v).toFixed(2)}`).join(' ');
        let markup = '<defs><linearGradient id="qs-chart-fill" x1="0" y1="0" x2="0" y2="1"><stop stop-color="#0755ff" stop-opacity=".23"/><stop offset="1" stop-color="#0755ff" stop-opacity=".01"/></linearGradient></defs>';
        for (let i = 0; i <= 4; i++) markup += `<line x1="${pad.left}" x2="${width - pad.right}" y1="${y(i * step)}" y2="${y(i * step)}" stroke="#e7eef9"/><text x="${pad.left - 9}" y="${y(i * step) + 3}" text-anchor="end">${i * step}</text>`;
        const interval = Math.max(1, Math.ceil(count / Math.max(2, Math.floor(width / 60))));
        d.labels.forEach((label, i) => {
            markup += `<line x1="${x(i)}" x2="${x(i)}" y1="${pad.top}" y2="${height - pad.bottom}" stroke="#edf2fb"/>`;
            if (i % interval === 0 || i === count - 1) markup += `<text x="${x(i)}" y="${height - 4}" text-anchor="${i === 0 ? 'start' : i === count - 1 ? 'end' : 'middle'}">${esc(label)}</text>`;
        });
        const blocked = d.blocked || Array(count).fill(0);
        markup += `<path d="${path(blocked)} L${x(count - 1)},${y(0)} L${x(0)},${y(0)} Z" fill="url(#qs-chart-fill)"/>`;
        series.forEach(([key,, color]) => {
            const values = d[key] || Array(count).fill(0);
            markup += `<path d="${path(values)}" fill="none" stroke="${color}" stroke-width="1.7" stroke-linejoin="round"/>`;
            if (count <= 14) values.forEach((v, i) => { markup += `<circle cx="${x(i)}" cy="${y(v)}" r="3" fill="${color}" stroke="white" stroke-width="1"/>`; });
        });
        chart.insertAdjacentHTML('afterbegin', `<svg viewBox="0 0 ${width} ${height}" role="img" aria-label="Recorded security activity over ${count} days">${markup}</svg>`);
        const show = i => {
            activePoint = i;
            if (!tip) return;
            tip.innerHTML = `<b>${esc(d.labels[i])}</b>` + series.map(([key, label, color]) => `<span><i style="display:inline-block;width:6px;height:6px;border-radius:50%;background:${color};margin-right:5px"></i>${esc(label)}: <b>${format(d[key]?.[i])}</b></span>`).join('');
            tip.hidden = false;
            tip.style.left = `${Math.max(0, Math.min(width - tip.offsetWidth, x(i) + 8))}px`;
            tip.style.top = '0px';
        };
        chart.onpointermove = event => { const rect = chart.getBoundingClientRect(); show(Math.max(0, Math.min(count - 1, Math.round((event.clientX - rect.left - pad.left) / (width - pad.left - pad.right) * (count - 1))))); };
        chart.onpointerleave = () => { if (tip) tip.hidden = true; };
        chart.onblur = () => { if (tip) tip.hidden = true; };
        chart.onkeydown = event => {
            if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') { event.preventDefault(); show(Math.max(0, Math.min(count - 1, (activePoint ?? 0) + (event.key === 'ArrowRight' ? 1 : -1)))); }
        };
    }

    /* Global Threat Sources (Dotted World Map + Concentric Radar Pulses matching Image 3) */
    function renderThreatMap(geoList) {
        const wrap = $('#qsThreatMapWrap');
        if (!wrap) return;

        const list = Array.isArray(geoList) ? geoList : [];

        let tooltip = wrap.querySelector('.qs-geo-tooltip');
        if (!tooltip) {
            tooltip = document.createElement('div');
            tooltip.className = 'qs-geo-tooltip';
            tooltip.hidden = true;
            wrap.appendChild(tooltip);
        }

        // Dotted continent paths (viewBox 0 0 440 160)
        let svgMarkup = `
            <defs>
                <pattern id="qsThreatDots" width="4" height="4" patternUnits="userSpaceOnUse">
                    <circle cx="1" cy="1" r=".8" fill="#93c5fd" opacity="0.85"/>
                </pattern>
            </defs>
            <g fill="url(#qsThreatDots)">
                <path d="M20 34 42 23 57 24 63 14 93 12 103 20 134 18 151 29 147 42 131 43 119 58 108 63 105 78 89 81 85 94 72 89 66 78 48 72 44 59 31 57 26 47 15 46Z"/>
                <path d="m87 89 15 4 8 13 17 8 12 1 4 13 14 4 5 19-12 11-5 22-12 15-10-10-2-20-13-15-4-17-10-7Z" transform="translate(0 -21)"/>
                <path d="m151 12 26-8 19 5-2 15-18 11-14-3Z"/>
                <path d="m194 35 15-10 17 3 13-6 17 8 6 15-10 8-21-1-4 12-19 4-10-13-14-3Z"/>
                <path d="m204 66 25-5 25 10 7 21-11 17-7 20-11 16-12-3-4-15-12-12-10-23Z"/>
                <path d="m253 26 21-9 20 6 23-10 24 3 22-6 16 7 25 5 11 13-19 13-23 2-7 15-19 6-8 17-13-6-12-1-3 13-13 1-13-22-12-5-4-15-12-2Z"/>
                <path d="m295 80 10 5 7 20-9 7-8-11-9-8Z"/>
                <path d="m330 89 13 3 8 16 16 6 3 7-17 2-16-10-7-14Z"/>
                <path d="m365 116 22-3 16 10 5 15-13 11-23-4-15-10Z"/>
                <path d="m393 64 4-8 5 4-1 12-7 7-4-6Z"/>
                <path d="m253 128 5 2 1 14-5 7-4-7Z"/>
                <path d="m413 143 5-5 5 2-4 11-6 3Z"/>
            </g>
        `;

        // Render animated concentric radar hotspots for each country
        list.forEach(geo => {
            if (!geo.coords || !Array.isArray(geo.coords)) return;
            const [cx, cy] = geo.coords;
            const color = geo.color || '#ef4444';
            svgMarkup += `
                <g class="qs-pulse-group" tabindex="0" role="img" aria-label="${esc(geo.country)}: ${esc(geo.attacks)} recorded blocked requests" data-country="${esc(geo.code)}" data-name="${esc(geo.country)}" data-percent="${esc(geo.percent)}" data-attacks="${esc(geo.attacks || 0)}" data-threat="${esc(geo.threat || 'Threat')}" data-cx="${cx}" data-cy="${cy}">
                    <circle class="qs-pulse-ring-1" cx="${cx}" cy="${cy}" r="14" fill="${color}" opacity="0.30"/>
                    <circle class="qs-pulse-ring-2" cx="${cx}" cy="${cy}" r="22" fill="${color}" opacity="0.15"/>
                    <circle class="qs-pulse-dot" cx="${cx}" cy="${cy}" r="3.8" fill="${color}" stroke="#ffffff" stroke-width="1.2"/>
                    <circle class="qs-pulse-hit" cx="${cx}" cy="${cy}" r="16" fill="transparent"/>
                </g>
            `;
        });

        wrap.innerHTML = `<svg class="qs-threat-map-svg" viewBox="0 0 440 160" role="img" aria-label="Global threat source distribution map">${svgMarkup}</svg>`;
        wrap.appendChild(tooltip);

        // Interactive mouseover for radar pulses
        const svg = wrap.querySelector('svg');
        const showTip = (group) => {
            const country = group.dataset.name;
            const percent = group.dataset.percent;
            const attacks = group.dataset.attacks;
            const threat = group.dataset.threat;
            const cx = Number(group.dataset.cx);
            const cy = Number(group.dataset.cy);
            const rect = svg.getBoundingClientRect();
            const posX = (cx / 440) * rect.width;
            const posY = (cy / 160) * rect.height;

            tooltip.innerHTML = `<strong>${esc(country)}</strong> · <b>${esc(percent)}%</b><br><small style="color:#94a3b8">${format(attacks)} recorded blocks · ${esc(threat)}</small>`;
            tooltip.hidden = false;
            tooltip.style.left = `${posX}px`;
            tooltip.style.top = `${Math.max(10, posY - 10)}px`;

            // Highlight corresponding country row in list
            const code = group.dataset.country;
            $$('.qs-geo-row').forEach(row => {
                row.classList.toggle('is-hovered', row.dataset.country === code);
            });
        };

        const hideTip = () => {
            tooltip.hidden = true;
            $$('.qs-geo-row').forEach(row => row.classList.remove('is-hovered'));
        };

        wrap.querySelectorAll('.qs-pulse-group').forEach(group => {
            group.addEventListener('mouseenter', () => showTip(group));
            group.addEventListener('focus', () => showTip(group));
            group.addEventListener('blur', hideTip);
            group.addEventListener('mouseleave', hideTip);
        });
    }

    /* Render country breakdown list */
    function renderThreatCountryList(geoList) {
        const container = $('#qsThreatCountryList');
        if (!container) return;

        const list = Array.isArray(geoList) && geoList.length ? geoList : (data.geography || []);
        const subtitle = $('#qsGeoSubtitle');
        if (subtitle) subtitle.textContent = list.length ? `${format(list.reduce((n, g) => n + Number(g.attacks || 0), 0))} total blocked requests from ${list.length} countries` : 'Recorded security event distribution';
        if (!list.length) {
            container.innerHTML = `<div class="qs-geo-empty"><img src="${esc((window.GWQSH_CONFIG?.asset_url || '') + 'earth-plane.png')}" alt="" width="80" height="80" class="qs-geo-empty-img" /><h4>No attributed threat sources</h4><p>Enable public IP country lookup in Settings. This widget uses recorded denials from this site.</p></div>`;
            return;
        }

        container.innerHTML = `
            <table class="qs-geo-table">
                <thead>
                    <tr>
                        <th scope="col" class="qs-geo-col-num">#</th>
                        <th scope="col" class="qs-geo-col-country-th">COUNTRY</th>
                        <th scope="col" class="qs-geo-col-threats-th">THREATS</th>
                        <th scope="col" class="qs-geo-col-share-th">SHARE %</th>
                    </tr>
                </thead>
                <tbody>
                    ${list.slice(0, 8).map((geo, idx) => `
                        <tr class="qs-geo-row" data-country="${esc(geo.code)}">
                            <td class="qs-geo-td-num">${idx + 1}</td>
                            <td class="qs-geo-td-country">
                                <img class="qs-geo-flag" src="${esc(geo.flag || '')}" alt="" width="20" height="14" />
                                <span class="qs-geo-name">${esc(geo.country)}</span>
                            </td>
                            <td class="qs-geo-td-threats">
                                <div class="qs-geo-progress-track">
                                    <div class="qs-geo-progress-fill" style="width: ${esc(geo.percent)}%; background-color: ${esc(geo.color)};"></div>
                                </div>
                                <span class="qs-geo-threat-count">${format(geo.attacks || 0)}</span>
                            </td>
                            <td class="qs-geo-td-share">${esc(geo.percent)}%</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;

        // Link hover events on country rows to map pulse markers
        container.querySelectorAll('.qs-geo-row').forEach(row => {
            const code = row.dataset.country;
            row.addEventListener('mouseenter', () => {
                const group = $(`#qsThreatMapWrap .qs-pulse-group[data-country="${code}"]`);
                if (group) {
                    group.classList.add('is-highlighted');
                    const tooltip = $('#qsThreatMapWrap .qs-geo-tooltip');
                    const svg = $('#qsThreatMapWrap svg');
                    if (tooltip && svg) {
                        const cx = Number(group.dataset.cx);
                        const cy = Number(group.dataset.cy);
                        const rect = svg.getBoundingClientRect();
                        tooltip.innerHTML = `<strong>${esc(group.dataset.name)}</strong> · <b>${esc(group.dataset.percent)}%</b><br><small style="color:#94a3b8">${format(group.dataset.attacks)} recorded blocks</small>`;
                        tooltip.hidden = false;
                        tooltip.style.left = `${(cx / 440) * rect.width}px`;
                        tooltip.style.top = `${Math.max(10, (cy / 160) * rect.height - 10)}px`;
                    }
                }
            });
            row.addEventListener('mouseleave', () => {
                $$('#qsThreatMapWrap .qs-pulse-group').forEach(g => g.classList.remove('is-highlighted'));
                const tooltip = $('#qsThreatMapWrap .qs-geo-tooltip');
                if (tooltip) tooltip.hidden = true;
            });
        });
    }

    function updateDashboard() {
        const summary = data.scan_summary || {};
        const issues = Number(summary.modified || 0) + Number(summary.missing || 0) + Number(summary.suspicious || 0);
        const scanned = !!summary.last_date;
        const metrics = {
            blocked: [format(data.threats_blocked), '', 'Retained lockouts and denials'],
            users: [`${data.users_2fa} / ${data.users_total}`, data.users_total ? Math.round(data.users_2fa / data.users_total * 100) + '%' : 'No users', '2FA enabled users'],
            integrity: [format(issues), issues ? 'Needs review' : scanned ? 'No issues' : 'Not scanned', scanned ? 'Last scan: ' + summary.last_date.split(', ').slice(0, 2).join(', ') : 'No scan completed yet'],
            shields: [`${data.active_shields} / ${data.shields_total}`, data.active_shields === data.shields_total ? 'Active' : 'Review', 'Protection modules configured'],
            schedule: [data.schedule, '', data.next_scan ? 'Next scan: ' + data.next_scan : 'Manual scans available'],
            malware: [format(summary.suspicious), summary.suspicious ? 'Review' : scanned ? 'No flags' : 'Not scanned', 'Suspicious files flagged by scanner']
        };
        Object.entries(metrics).forEach(([key, [value, badge, note]]) => {
            const element = $(`[data-metric="${key}"]`);
            if (!element) return;
            element.querySelector('strong').textContent = value;
            const badgeElement = element.querySelector('.qs-badge');
            if (badgeElement) {
                badgeElement.textContent = badge;
                badgeElement.hidden = !badge;
            }
            element.querySelector('p').textContent = note;
        });
        const score = Number(data.security_score || 0);
        const status = score >= 85 ? 'Excellent' : score >= 70 ? 'Good' : 'Needs attention';
        const scoreVal = $('#qs-score-value');
        if (scoreVal) scoreVal.textContent = score;
        const scoreStatus = $('#qs-score-status');
        if (scoreStatus) scoreStatus.textContent = status;
        const scoreRing = $('#qs-score-ring');
        if (scoreRing) scoreRing.setAttribute('stroke-dashoffset', 483.805 * (1 - score / 100));
        const gauge = $('.qs-gauge');
        if (gauge) gauge.setAttribute('aria-label', `Security score ${score} out of 100: ${status}`);
        const headline = $('#qs-score-headline');
        if (headline) headline.textContent = score >= 85 ? 'Your site is very well protected!' : 'Your site needs attention';
        $$('[data-score]').forEach(el => { el.textContent = data.score_components?.[el.dataset.score] || 0; });
        const hCount = $('#qs-hardening-count');
        if (hCount) hCount.textContent = `${data.hardening_on} / 6 Completed`;
        $$('[data-hardening]').forEach(el => {
            const enabled = !!data.hardening?.[el.dataset.hardening];
            el.classList.toggle('is-on', enabled);
            el.setAttribute('aria-pressed', String(enabled));
            const labelEl = el.nextElementSibling;
            if (labelEl) el.setAttribute('aria-label', `${labelEl.textContent}: ${enabled ? 'Enabled' : 'Disabled'}`);
        });
        const empty = (cols, message) => `<tr><td class="qs-empty" colspan="${cols}">${esc(message)}</td></tr>`;
        const recBody = $('#qs-recent-body');
        const toneMap = { success: 'green', danger: 'red', warning: 'orange', info: 'blue' };
        if (recBody) recBody.innerHTML = data.recent_activity?.length ? data.recent_activity.map(e => {
            const tone = toneMap[window.GWQSH.eventTone(e.event_name)] || 'blue';
            return `<tr><td class="qs-td-time">${esc(date(e.event_time))}</td><td class="qs-td-event"><span class="qs-event-cell"><i class="qs-status-dot qs-dot-${tone}"></i><span class="qs-event-name qs-text-${tone}">${esc(e.event_name)}</span></span></td><td class="qs-td-ip">${esc(e.ip_address || '—')}</td><td class="qs-td-detail"><span class="qs-detail" title="${esc(e.details)}">${esc(e.details)}</span></td></tr>`;
        }).join('') : empty(4, 'No recent activity recorded');
        const threatBody = $('#qs-threat-body');
        if (threatBody) threatBody.innerHTML = data.live_threats?.length ? data.live_threats.map(e => `<tr><td>${esc(date(e.event_time))}</td><td class="qs-danger-text">${esc(e.event_name)}</td><td>${esc(e.ip_address)}</td><td><span class="qs-badge qs-blue-badge">Blocked</span></td></tr>`).join('') : empty(4, 'No recent threats detected');
        const qTitle = $('.qs-quarantine h2');
        if (qTitle) qTitle.textContent = `Quarantine (${summary.quarantined || 0} files)`;
        const qBody = $('#qs-quarantine-body');
        if (qBody) qBody.innerHTML = data.quarantine?.length ? data.quarantine.map(e => `<tr><td title="${esc(e.display_path)}">${esc(String(e.display_path).split('/').pop())}</td><td>${esc(e.status)}</td><td>${esc(date(e.time))}</td></tr>`).join('') : empty(3, 'No quarantined files');
        const scanHist = $('#qs-scan-history');
        if (scanHist) scanHist.innerHTML = data.scan_history?.length ? data.scan_history.map(scan => {
            const count = Number(scan.modified_files) + Number(scan.missing_files) + Number(scan.suspicious_files);
            return `<tr><td><span class="qs-scan-shield"><svg class="qs-icon" aria-hidden="true"><use href="#i-shield-check"/></svg></span></td><td><a href="${esc(window.GWQSH_PAGES['file-integrity'])}">Full File Scan</a></td><td>${format(count)} findings · ${format(scan.total_files)} files</td><td><time datetime="${esc(String(scan.scan_date || '').replace(' ', 'T'))}">${esc(scanDate(scan.scan_date))}</time></td><td><span class="qs-badge ${count ? 'qs-danger' : 'qs-good'}">${count ? 'Review' : 'No issues'}</span></td></tr>`;
        }).join('') : empty(5, 'No scans completed yet');
        const updated = $('#qs-updated');
        if (updated) updated.textContent = `Updated at ${data.updated}`;

        drawChart();
        renderThreatMap(data.geography);
        renderThreatCountryList(data.geography);
    }

    async function refresh() {
        const id = ++requestId;
        $('#activityChart')?.setAttribute('aria-busy', 'true');
        const overviewDays = $('#qs-geo-range')?.value || $('#qs-overview-range')?.value || 30;
        const result = await window.GWQSH.ajax('get_dashboard_data', {
            days: $('#chartRange')?.value || 7,
            overview_days: overviewDays
        });
        if (id !== requestId) return false;
        $('#activityChart')?.removeAttribute('aria-busy');
        if (!result.success || result.data?.data_error || result.data?.chart_data?.error) {
            const err = $('#qs-load-error');
            if (err) err.hidden = false;
            return false;
        }
        data = result.data;
        const err = $('#qs-load-error');
        if (err) err.hidden = true;
        activePoint = null;
        updateDashboard();
        return true;
    }

    // Chart & overview event listeners
    $('#chartRange')?.addEventListener('change', refresh);
    $('#qs-overview-range')?.addEventListener('change', refresh);
    $('#qs-retry')?.addEventListener('click', refresh);

    // Threat map period selector (30 Days, 14 Days, 7 Days)
    $('#qs-geo-range')?.addEventListener('change', async event => {
        const days = event.target.value;
        const wrap = $('#qsThreatMapWrap');
        if (wrap) wrap.setAttribute('aria-busy', 'true');
        const res = await window.GWQSH.ajax('get_dashboard_data', {
            days: $('#chartRange')?.value || 7,
            overview_days: days
        });
        if (wrap) wrap.removeAttribute('aria-busy');
        if (res.success && res.data) {
            data = res.data;
            renderThreatMap(data.geography);
            renderThreatCountryList(data.geography);
        }
    });

    // Serialize each hardening change and confirm disabling an enforced protection.
    const checklist = $('.qs-checklist');
    let hardeningBusy = false;
    checklist?.addEventListener('click', event => {
        const li = event.target.closest('li'), toggle = li?.querySelector('[data-hardening]');
        if (!toggle || hardeningBusy) return;
        const currentlyOn = toggle.classList.contains('is-on');
        const label = li.querySelector('b')?.textContent || toggle.dataset.hardening;
        const apply = async () => {
            if (hardeningBusy) return false;
            hardeningBusy = true;
            toggle.setAttribute('aria-busy', 'true');
            try {
                const res = await GWQSH.ajax('toggle_hardening', { feature: toggle.dataset.hardening, on: currentlyOn ? '0' : '1', confirmed: '1' });
                if (!res.success) { GWQSH.toast(res.data?.message || 'Could not update hardening control', 'err'); return false; }
                await refresh();
                GWQSH.toast(label + ' setting saved. Review enforced status in Hardening.', 'ok');
                return true;
            } finally { hardeningBusy = false; toggle.removeAttribute('aria-busy'); }
        };
        if (currentlyOn) GWQSH.confirm('Disable ' + label + '?', 'This reduces the configured protection. Review compatibility in Hardening before changing it.', 'Disable', apply, true);
        else apply();
    });

    // Quick Action: Real-time Malware Scan button
    $('#qsActionMalwareScan')?.addEventListener('click', () => {
        const btn = $('#runScanBtn');
        if (btn) {
            btn.click();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }
    });

    let resizeFrame;
    const chartEl = $('#activityChart');
    if (chartEl) {
        const observer = new ResizeObserver(() => {
            cancelAnimationFrame(resizeFrame);
            resizeFrame = requestAnimationFrame(() => {
                drawChart();
                renderThreatMap(data.geography);
            });
        });
        observer.observe(chartEl);
    }

    // Initial render
    drawChart();
    renderThreatMap(data.geography);
    renderThreatCountryList(data.geography);

    // Scan button handler
    $('#runScanBtn')?.addEventListener('click', async event => {
        const button = event.currentTarget;
        if (button.disabled) return;
        const label = button.innerHTML;
        const status = $('#qs-scan-status');
        button.disabled = true; button.setAttribute('aria-busy', 'true'); button.textContent = 'Scanning…';
        if (status) status.textContent = 'Inspecting files with the existing security scanner…';
        try {
            let result = await window.GWQSH.ajax('run_scan');
            while (result.success && result.data?.result?.pending) {
                const processed = result.data.result.total;
                if (status) status.textContent = processed ? `Scan in progress · ${format(processed)} files inspected` : 'Scan in progress · continuing file inspection…';
                await new Promise(resolve => setTimeout(resolve, 1000));
                result = await window.GWQSH.ajax('run_scan', { resume: 1 });
            }
            if (!result.success) throw new Error(result.data?.message || 'Scan could not complete. Open File Integrity to review or resume.');
            const summary = result.data.summary || {};
            const findings = Number(summary.modified || 0) + Number(summary.missing || 0) + Number(summary.suspicious || 0);
            if (status) {
                status.textContent = `Scan completed · ${format(summary.total)} files inspected · ${format(findings)} findings to review.`;
                if (result.data.result?.coverage?.length) status.textContent += ` ${result.data.result.coverage.length} scan coverage limitations; review File Integrity.`;
            }
            await refresh();
        } catch (error) {
            if (status) status.textContent = error.message;
            window.GWQSH.toast(error.message, 'err');
        } finally {
            button.disabled = false; button.removeAttribute('aria-busy'); button.innerHTML = label;
        }
    });
})();
