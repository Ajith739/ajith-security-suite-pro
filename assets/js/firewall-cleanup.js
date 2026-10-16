/* Scoped Firewall & Cleanup controller; scanner and file actions share existing services. */
(() => {
  "use strict";
  const root = document.querySelector(".qs-pro-firewall-cleanup");
  if (!root || !window.GWQSH) return;
  const $ = (s) => root.querySelector(s),
    $$ = (s) => [...root.querySelectorAll(s)];
  const { ajax, esc, modal, confirm, toast } = window.GWQSH;
  let data = window.GWQSH_DATA || {},
    scanning = false,
    disposed = false,
    dirty = false,
    logsExpanded = false,
    scanError = "";
  window.GWQSH_DATA = {};
  const feedback = (message, error = false) => {
    if (message) toast(message, error ? 'err' : 'info');
  };
  function render(syncSettings = false) {
    $("#qs-fw-ip-records").innerHTML =
      "<p><b>Active temporary blocks</b></p>" +
      (data.lockouts.length
        ? '<div class="qs-fw-table-scroll"><table><thead><tr><th scope="col">IP</th><th scope="col">Attempts</th><th scope="col">Expires</th><th scope="col">Action</th></tr></thead><tbody>' +
          data.lockouts
            .map(
              (row) =>
                `<tr><td>${esc(row.ip)}</td><td>${Number(row.attempts)}</td><td>${esc(row.until)}</td><td><button type="button" class="qs-small-button" data-unlock="${esc(row.ip)}">Unlock</button></td></tr>`,
            )
            .join("") +
          "</tbody></table></div>"
        : "<p>No active login lockouts.</p>") +
      "<p><b>Trusted IP exceptions</b></p><p>" +
      (data.allowlist.length
        ? data.allowlist.map((ip) => esc(ip)).join(" · ")
        : "No trusted IP exceptions configured.") +
      "</p><small>Preview: up to 25 lockouts and 50 exceptions. Manage the full list in Login Protection.</small>";

    $$("[data-metric]").forEach((node) => {
      node.textContent = Number(
        data[node.dataset.metric] || 0,
      ).toLocaleString();
    });
    $$("[data-result]").forEach((node) => {
      node.textContent = Number(
        data.results[node.dataset.result] || 0,
      ).toLocaleString();
    });
    const active = data.active && data.settings.enabled;
    for (const id of ["#qs-fw-status", "#qs-fw-master-label"]) {
      $(id).textContent = active
        ? "Active"
        : data.active
          ? "Off"
          : "Plugin off";
      $(id).className = "qs-badge " + (active ? "qs-good" : "qs-fw-neutral");
    }
    if (syncSettings && !dirty) {
      $("#qs-fw-enabled").checked = data.settings.enabled;
      $$("[data-rule]").forEach((input) => {
        input.checked =
          input.dataset.rule === "login"
            ? data.login.enabled
            : data.settings[input.dataset.rule];
      });
    }
    $("#qs-fw-rate-description").textContent =
      `${data.login.max_attempts} failed attempts within ${data.login.time_window} minutes trigger a ${data.login.lockout_duration}-minute login lockout. Trusted IPs are excluded.`;
    const progress = data.progress,
      percent = progress
        ? Math.min(
            99,
            Math.floor((progress.offset / Math.max(1, progress.total)) * 100),
          )
        : 0;
    const completed = !!data.summary.last_date,
      findings =
        data.results.malware + data.results.suspicious + data.results.unknown;
    $("#qs-fw-ring").style.setProperty(
      "--progress",
      `${progress ? percent : completed ? 100 : 0}%`,
    );
    $("#qs-fw-ring").setAttribute(
      "aria-valuenow",
      String(progress ? percent : completed ? 100 : 0),
    );
    $("#qs-fw-percent").textContent =
      `${progress ? percent : completed ? 100 : 0}%`;
    $("#qs-fw-phase").textContent = progress
      ? `Scanning ${progress.phase} files`
      : scanning
        ? "Preparing scan…"
        : completed
          ? "Last scan finished"
          : "Ready to scan";
    $("#qs-fw-start").disabled = scanning;
    $("#qs-fw-start").textContent = scanning
      ? "Scanning…"
      : progress
        ? "Resume Scan"
        : "Start Scan";
    let state = "neutral",
      title = "No completed scan",
      description = "Run a scan to inspect your site.";
    if (scanError) {
      state = "warning";
      title = "Scan failed";
      description = scanError;
    } else if (progress || scanning) {
      title = "Scan in progress";
      description =
        "Counts show outstanding findings and the last completed inspection.";
    } else if (completed && data.health.length) {
      state = "warning";
      title = "Scan incomplete";
      description = `${data.health.length} coverage limitations and ${findings.toLocaleString()} unresolved findings require review. See the full report.`;
    } else if (completed && findings) {
      state = "warning";
      title = "Findings require review";
      description = `${findings.toLocaleString()} unresolved findings. Inspect evidence before cleanup.`;
    } else if (completed) {
      state = "clean";
      title = "No outstanding findings";
      description =
        "The completed scan reported no unresolved threats or integrity issues within its coverage.";
    }
    $("#qs-fw-result-banner").dataset.state = state;
    $("#qs-fw-result-title").textContent = title;
    $("#qs-fw-result-description").textContent = description;
    $("#qs-fw-last").textContent = completed
      ? `Last scan: ${data.summary.last_date}`
      : "Never scanned";
    $("#qs-fw-log-rows").innerHTML = data.events.length
      ? data.events
          .map(
            (row) =>
              `<tr><td>${esc(row.time_label || window.GWQSH.date(row.event_time))}</td><td>${esc(row.ip_address)}</td><td>${esc(row.country || 'Lookup unavailable')}</td><td>${esc(row.rule)}</td><td>${esc(row.path)}</td><td><span class="qs-badge qs-danger">Blocked</span></td></tr>`,
          )
          .join("")
      : '<tr><td colspan="6">No blocked requests recorded yet.</td></tr>';
    $("#qs-fw-pagination").hidden = !logsExpanded;
    $("#qs-fw-page").textContent = `Page ${data.page} of ${data.pages}`;
    $("#qs-fw-prev").disabled = data.page <= 1;
    $("#qs-fw-next").disabled = data.page >= data.pages;
  }
  async function refresh(page = data.page || 1) {
    const response = await ajax("get_firewall_data", { page_num: page });
    if (disposed) return false;
    if (!response.success) {
      feedback(
        response.data?.message ||
          "Unable to load firewall statistics. Reload to retry.",
        true,
      );
      return false;
    }
    data = response.data;
    render();
    return true;
  }
  $("#qs-fw-settings").addEventListener("change", () => {
    dirty = true;
    feedback("Unsaved changes. Save to apply them.");
  });
  $("#qs-fw-enabled").addEventListener("change", () => {
    dirty = true;
    feedback("Unsaved changes. Save to apply them.");
  });
  async function save(confirmed = false) {
    const button = $("#qs-fw-save"),
      payload = {
        enabled: $("#qs-fw-enabled").checked ? "1" : "0",
        confirmed: confirmed ? "1" : "0",
      };
    $$("[data-rule]").forEach((input) => {
      payload[input.dataset.rule] = input.checked ? "1" : "0";
    });
    if (
      ((data.settings.enabled && payload.enabled === "0") ||
        (data.login.enabled && payload.login === "0")) &&
      !confirmed
    ) {
      confirm(
        "Disable security protection?",
        "The protections you switched off will stop when saved. Review your selected query and login settings before continuing.",
        "Disable and save",
        () => save(true),
        true,
      );
      return;
    }
    button.disabled = true;
    button.textContent = "Saving…";
    const inputs = $$("[data-rule],#qs-fw-enabled");
    inputs.forEach((input) => {
      input.disabled = true;
    });
    try {
      const response = await ajax("save_firewall_settings", payload);
      if (!response.success) {
        feedback(
          response.data?.message || "Unable to save firewall settings.",
          true,
        );
        return;
      }
      data = response.data;
      dirty = false;
      render(true);
      feedback("Firewall settings saved.");
      
    } finally {
      button.disabled = false;
      button.textContent = "Save Firewall Settings →";
      inputs.forEach((input) => {
        input.disabled = false;
      });
    }
  }
  $("#qs-fw-settings").addEventListener("submit", (event) => {
    event.preventDefault();
    save();
  });
  const tabs = $$("[role=tab]");
  function tabSelect(tab) {
    tabs.forEach((button) => {
      const active = button === tab;
      button.setAttribute("aria-selected", String(active));
      button.tabIndex = active ? 0 : -1;
      $("#" + button.getAttribute("aria-controls")).hidden = !active;
    });
  }
  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => tabSelect(tab));
    tab.addEventListener("keydown", (event) => {
      let next;
      if (event.key === "ArrowRight") next = (index + 1) % tabs.length;
      if (event.key === "ArrowLeft")
        next = (index + tabs.length - 1) % tabs.length;
      if (event.key === "Home") next = 0;
      if (event.key === "End") next = tabs.length - 1;
      if (next !== undefined) {
        event.preventDefault();
        tabSelect(tabs[next]);
        tabs[next].focus();
      }
    });
  });
  async function scan() {
    if (scanning) return;
    scanError = "";
    scanning = true;
    feedback("Preparing scan…");
    render();
    let resume = !!data.progress;
    try {
      while (!disposed) {
        const response = await ajax("run_scan", { resume: resume ? "1" : "0" });
        if (disposed) return;
        if (!response.success) {
          scanError =
            response.data?.message || "Unable to start scan. Try again.";
          feedback(scanError, true);
          return;
        }
        await refresh();
        if (!response.data.result.pending) {
          feedback(
            "Scan finished. Review results and coverage in the full report.",
          );
          break;
        }
        resume = true;
        await new Promise((resolve) => setTimeout(resolve, 1200));
      }
    } finally {
      scanning = false;
      if (!disposed) render();
    }
  }
  $("#qs-fw-start").addEventListener("click", scan);
  window.addEventListener("pagehide", () => {
    disposed = true;
  });
  $("#qs-fw-view-all").addEventListener("click", () => {
    logsExpanded = true;
    render();
    $("#qs-fw-next").focus();
  });
  $("#qs-fw-prev").addEventListener("click", () => refresh(data.page - 1));
  $("#qs-fw-next").addEventListener("click", () => refresh(data.page + 1));
  $("#qs-fw-ip-records").addEventListener("click", (event) => {
    const button = event.target.closest("[data-unlock]");
    if (!button) return;
    confirm(
      "Unlock this IP?",
      "Restore authentication access for " + esc(button.dataset.unlock) + ".",
      "Unlock",
      async () => {
        const response = await ajax("unlock_ip", { ip: button.dataset.unlock });
        if (!response.success) {
          feedback(response.data?.message || "Unable to unlock this IP.", true);
          return false;
        }
        await refresh();
        feedback("Selected IP unlocked.");
      },
    );
  });
  const integrity = window.GWQSH_PAGES["file-integrity"];
  $$("[data-tool]").forEach((button) =>
    button.addEventListener("click", () => {
      if (button.dataset.tool === "rescan") {
        scan();
        $("#qs-fw-start").scrollIntoView({ block: "center", behavior: "auto" });
        return;
      }
      const descriptions = {
        quarantine:
          "Quarantine uses validated finding IDs, preserves hashed evidence and checks whether the original changed. Manage active findings and quarantine records in File Integrity.",
        malware:
          "Critical heuristic findings need review before removal. The existing quarantine action preserves evidence first. Suspicious files are never deleted automatically from this screen.",
        restore:
          "Restore uses official WordPress core checksums or a retained, verified trusted copy. Quarantined malware is not treated as a clean backup.",
      };
      modal({
        title: button.querySelector("b").textContent,
        body: `<p>${esc(descriptions[button.dataset.tool])}</p><p>${data.quarantine_count ? `${Number(data.quarantine_count)} preserved evidence records.` : "No quarantined files."}</p><a class="btn primary" href="${esc(integrity)}">Open File Integrity management →</a>`,
        actions: [{ label: "Close" }],
      });
    }),
  );
  $("#btn-waf-modal")?.addEventListener("click", () => {
    const tpl = document.getElementById("tpl-waf");
    if (!tpl) return;
    const clone = tpl.content.cloneNode(true);
    const div = document.createElement("div");
    div.appendChild(clone);
    const details = div.querySelector("details");
    if (details) details.open = true;
    modal({
      title: "Firewall Mode & Additional Rules",
      wide: true,
      body: div.innerHTML,
      onOpen: (bg) => {
        const d = bg.querySelector("details");
        if (d) d.open = true;
      },
    });
  });
  render(true);
})();
