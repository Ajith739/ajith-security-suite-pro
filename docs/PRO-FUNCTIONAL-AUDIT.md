# Pro page / feature / handler audit

All UI requests use POST `gwqsh_action` with `subaction`, the `gwqsh_nonce` nonce and central capability checks. Only explicitly allowlisted 2FA self-service actions allow `read`; other actions require `manage_options`.

| Page | Backend services / storage | Literal frontend actions | Missing handlers |
|---|---|---|---|
| dashboard | Dashboard_Data; options, users, scan and activity tables | `get_dashboard_data`, `run_scan`, `toggle_hardening` | None |
| login-protection | Login_View_Data / Login_Protection; options, allowlist, lockouts | `add_allow_ip`, `get_login_data`, `remove_allow_ip`, `save_login_access`, `save_login_settings`, `unlock_ip` | None |
| two-factor | Two_Factor_View_Data / Two_Factor / Crypto; encrypted user metadata, policy options | `disable_own_2fa`, `generate_2fa_secret`, `generate_backup_codes`, `get_2fa_data`, `get_user_2fa_devices`, `remove_trusted_device`, `require_user_2fa`, `reset_user_2fa`, `save_2fa_settings` | None |
| file-integrity | File_Integrity / Scan_Engine / Quarantine_Manager / Path_Guard; findings/history tables and protected files | `bulk_mark_reviewed`, `bulk_quarantine`, `get_diff`, `get_scan_data`, `run_scan` | None |
| firewall-cleanup | Firewall / Login_Protection / Scan_Engine; rule options, logs and scan state | `get_firewall_data`, `run_scan`, `save_firewall_settings`, `unlock_ip` | None |
| hardening | Hardening_Data / Hardening_Rules / Hardening; options and managed upload rules | `get_hardening_data` | None |
| activity-log | Activity_View_Data / Activity_Logger; indexed activity table | `activity_cleanup`, `activity_cleanup_preview`, `activity_data` | None |
| settings | Settings; validated WordPress options | `clear_activity_logs`, `reset_settings`, `save_settings` | None |

Variable-dispatched actions (file operations, hardening and policy mutation) must also be exercised through regression tests. Static action matching does not establish working functionality.

## Confirmed initial findings

- File Integrity and Activity Log scripts still bind `.qs-header`, `#qs-search`, `#qs-nav-toggle` and `#qs-nav`, but their templates now render `.topbar`, `#mainNav` and `#burger`. Null dereferences stop page initialization.
- Header navigation is copied across templates, omits Firewall & Cleanup and still contains a Pro item.
- Settings always hides Appearance and Advanced panels and offers no tabs to reveal them.
- Theme bootstrap does not resolve System or use database defaults; shared preference code lacks system-change and storage synchronization.
- Pro page styles define their own light tokens and hardcoded surfaces without corresponding dark styles.
- Settings baseline action reports a completed scan despite calling the baseline-trust handler.
- Settings sends whole snapshots concurrently, allowing delayed responses to overwrite newer edits.

## Final flow checks

The shared navigation and `qs-core.js` own header events on all eight pages. Page handlers consume the real service snapshots supplied by Admin, dispatch through the central authenticated AJAX router, validate inputs, and render only successful backend results. Activity export uses its separately authorized admin endpoint. TOTP challenges use the WordPress authentication pipeline rather than an admin-page simulation.

| Interaction family | Request / enforcement | Durable result / verification |
|---|---|---|
| Login rules, access URL, allowlists, unlock | Login AJAX actions → Login_Protection / Security_Runtime | Options, attempt/lockout tables; LoginProtectionTest and UiBackendTest; browser save/reload |
| 2FA QR, enrollment, backups, disable, user policy | generate/confirm_2fa_secret, generate_backup_codes, disable_own_2fa; policy/self-service checks | Encrypted user metadata and policy options; QR decoded, real TOTP verified, password challenge and backup-code consumption tested |
| Scan and findings | run_scan / get_scan_data → bounded Scan_Engine / File_Integrity | Persisted progress, history, findings, trusted baseline; real resumable scan and scan-state regressions |
| Review, diff, accept, quarantine, restore, delete | Finding/artifact IDs → Path_Guard / Quarantine_Manager with storage locks | Validated paths, hashes, protected evidence and managed sentinels; 1,100-file browser fixture and filesystem regression tests |
| Firewall settings, statistics and tabs | save/get_firewall_data → existing Firewall service | Rule options and retained denial events; real anonymous SQL request rejected; authenticated admin bypass checked |
| Hardening switches and assessment | toggle_hardening / reset/verify/CSP actions → Hardening_Rules/Data | Options, runtime enforcement, owned upload rules with recovery; effective-state and server-probe tests |
| Activity search, filters, pagination, export, retention cleanup | activity_data / cleanup actions / admin export endpoint → Activity_View_Data/Logger | Real indexed activity records; SQL filtering/pagination tests, browser details/CSV; failed clear returns an error |
| Settings autosave, import, reset | Serialized partial save_settings / reset_settings → Settings normalization | Verified WordPress options and native auto_update_plugins; browser import/export/reset, rapid edits and network-failure rollback |

Unsupported facilities are explicitly identified in the UI. No geolocation provider, periodic integrity schedule, general HTTP rate limiter, custom WAF editor or permanent site-wide IP-ban service was added. An explicit trust-baseline action remains separate from manual scanning.
