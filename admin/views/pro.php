<?php
/**
 * Installation details and locally available documentation.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
?>
<div class="wrap qs-pro-information">
<h1>Security Suite Pro</h1>
<p>Version <?php echo esc_html( GWQSH_VERSION ); ?> · <?php echo GWQSH_Settings::is_active() ? 'Security enabled' : 'Security paused'; ?></p>
<p>This installation provides login protection, TOTP two-factor authentication, file integrity and suspicious-file scanning, quarantine, security hardening, an early security guardian, and activity logs.</p>
<h2>License & feature availability</h2>
<p>No license-verification service is implemented in this build. An active paid license, renewal date, or premium support entitlement cannot be verified.</p>
<p>Scheduled scans, geographic country blocking, custom WAF rules, and email security reports are not available in this build. Built-in WAF rules can be configured through Firewall &amp; Cleanup. Manual scans and scan history are available through File Integrity. IP lockouts and emergency login recovery are available through Login Protection.</p>
<p><a class="button button-primary" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro' ) ); ?>">Open Dashboard</a> <a class="button" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro-settings' ) ); ?>">Plugin Settings</a> <a class="button" href="https://gracewell.in/" target="_blank" rel="noopener noreferrer">Contact the Developer</a></p>
<h2 id="qs-documentation">Documentation</h2>
<dl>
<dt>Run a security scan</dt><dd>Choose Run Security Scan on the dashboard. Security Suite Pro uses bounded backend requests to inspect files. The dashboard reports actual completion and findings. Open File Integrity for coverage details, differences, review, verified restoration, and quarantine management. A scan with no findings does not guarantee that the site is free of malware.</dd>
<dt>Enable two-factor authentication</dt><dd>Open Two-Factor, enroll your authenticator, verify a code, and store backup codes safely. Only users with effective enrollment are counted as protected on the dashboard.</dd>
<dt>Configure security hardening</dt><dd>Open Hardening to change individual controls. Dashboard indicators only report the effective status and do not change settings.</dd>
<dt>Review and export events</dt><dd>Open Activity Log to filter actual audit records and export logs. Threats Blocked counts recorded IP lockout events for the selected overview period, not every failed login. The chart’s malware series counts suspicious scan findings requiring review; file series counts retained modified or missing findings by their latest detection date.</dd>
<dt>Free → Pro upgrades</dt><dd>Free and Pro share existing settings and database tables. Activate only one edition at a time to avoid duplicate PHP declarations. Switching editions must retain existing options and security records.</dd>
<dt>Security score</dt><dd>The weighted score reflects login protection (20%), effective 2FA enrollment (25%), file integrity (15%), effective hardening controls (25%), and scheduled activity-log maintenance (15%). It is a configuration indicator, not a security guarantee.</dd>
</dl>
</div>
