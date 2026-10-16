<?php
/**
 * Firewall & Cleanup, using shared security services.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
$gwqsh_view_d       = GWQSH_Firewall::data();
$gwqsh_view_db      = GWQSH_Database_View_Data::get();
$gwqsh_view_user    = wp_get_current_user();
$gwqsh_u_name       = ( $gwqsh_view_user && $gwqsh_view_user->exists() ) ? ( $gwqsh_view_user->display_name ? $gwqsh_view_user->display_name : $gwqsh_view_user->user_login ) : 'Admin';
$gwqsh_u_initial    = strtoupper( substr( $gwqsh_u_name, 0, 1 ) );
$gwqsh_u_role       = ! empty( $gwqsh_view_user->roles[0] ) ? ucfirst( $gwqsh_view_user->roles[0] ) : 'Administrator';
$gwqsh_view_icon    = static function ( $gwqsh_view_name ) {
	return '<svg class="qs-icon" aria-hidden="true"><use href="#i-' . esc_attr( $gwqsh_view_name ) . '"/></svg>';
};
$gwqsh_view_url     = static function ( $gwqsh_view_page ) {
	$gwqsh_view_suffix = array(
		'dashboard'        => '',
		'login'            => '-login',
		'two-factor'       => '-two-factor',
		'file-integrity'   => '-file-integrity',
		'hardening'        => '-hardening',
		'activity-log'     => '-activity-log',
		'firewall-cleanup' => '-firewall-cleanup',
		'settings'         => '-settings',
		'pro'              => '-pro',
	);
	return admin_url( 'admin.php?page=gracewell-security-suite-pro' . $gwqsh_view_suffix[ $gwqsh_view_page ] );
};
$gwqsh_view_section = static function ( $gwqsh_view_title, $gwqsh_view_symbol, $gwqsh_view_subtitle = '' ) use ( $gwqsh_view_icon ) {
	echo '<div class="qs-card-head"><span class="qs-tile">' . $gwqsh_view_icon( $gwqsh_view_symbol ) . '</span><div><h2>' . esc_html( $gwqsh_view_title ) . '</h2>' . ( $gwqsh_view_subtitle ? '<p>' . esc_html( $gwqsh_view_subtitle ) . '</p>' : '' ) . '</div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Helper escapes every variable; only trusted SVG markup is emitted.
};
require GWQSH_PATH . 'admin/views/dashboard-icons.php';
?>
<a class="skip" href="#main">Skip to content</a>

<header class="topbar">
<div class="topbar-in">
	<a class="brand" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro' ) ); ?>" aria-label="Security Suite Pro home">
	<img class="logo-mark" src="<?php echo esc_url( GWQSH_URL . 'assets/img/quietshield.svg' ); ?>" alt="" width="40" height="44">
	<span class="brand-txt"><b><span>Security Suite Pro</span><svg class="i qs-title-crown" aria-hidden="true"><use href="#i-crown" /></svg></b><small>A Safer WordPress, A Quieter
		Tomorrow</small></span>
	</a>

	<?php require GWQSH_PATH . 'admin/views/navigation.php'; ?>



	<div class="top-actions">

	<div class="menu-wrap">
		<button class="icon-btn" data-menu="notif" type="button" aria-haspopup="true" aria-expanded="false"
		aria-label="Notifications">
		<svg class="i">
			<use href="#i-bell" />
		</svg><span class="dot-badge <?php echo empty( $gwqsh_view_d['events'] ) ? 'off' : ''; ?>" id="notifDot"><?php echo esc_html( count( $gwqsh_view_d['events'] ) ); ?></span>
		</button>
		<div class="menu menu-notif" id="menu-notif" role="menu">
		<div class="menu-head"><b>Notifications</b><button class="link-btn" id="markRead" type="button">Mark all as
			read</button></div>
		<?php if ( empty( $gwqsh_view_d['events'] ) ) : ?>
		<div class="menu-item">No recent threats detected.</div>
		<?php else : ?>
			<?php foreach ( $gwqsh_view_d['events'] as $gwqsh_view_event ) : ?>
			<div class="menu-item"><span><b><?php echo esc_html( $gwqsh_view_event['event_name'] ); ?></b><small><?php echo esc_html( $gwqsh_view_event['ip_address'] . ( ! empty( $gwqsh_view_event['details'] ) ? ' · ' . $gwqsh_view_event['details'] : '' ) ); ?></small></span></div>
			<?php endforeach; ?>
		<?php endif; ?>
		</div>
	</div>

	<div class="menu-wrap help-wrap">
		<button class="icon-btn" data-menu="help" type="button" aria-haspopup="true" aria-expanded="false"
		aria-label="Help"><svg class="i">
			<use href="#i-help" />
		</svg></button>
		<div class="menu" id="menu-help" role="menu"><button class="menu-item" role="menuitem" type="button" data-changelog>Changelog · Version 1.0.0</button>
		<a role="menuitem" class="menu-item" href="https://wordpress.org/support/" target="_blank"
			rel="noopener"><svg class="i">
			<use href="#i-book" />
			</svg><span>Documentation</span></a>
		<a role="menuitem" class="menu-item" href="https://wordpress.org/support/forums/" target="_blank"
			rel="noopener"><svg class="i">
			<use href="#i-help" />
			</svg><span>Get support</span></a>
		</div>
	</div>

	<span class="vsep" aria-hidden="true"></span>

	<div class="menu-wrap">
		<button class="avatar-btn" data-menu="user" type="button" aria-haspopup="true" aria-expanded="false"
		aria-label="Account menu"><span class="avatar"><?php echo esc_html( $gwqsh_u_initial ); ?></span></button>
		<div class="menu" id="menu-user" role="menu">
		<div class="menu-head"><b><?php echo esc_html( $gwqsh_u_name ); ?></b><small><?php echo esc_html( $gwqsh_u_role ); ?></small></div>
		<a role="menuitem" class="menu-item" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro-settings' ) ); ?>"><svg class="i">
			<use href="#i-gear" />
			</svg><span>Plugin settings</span></a>
		<button role="menuitem" class="menu-item" id="themeToggle" type="button"><svg class="i">
			<use href="#i-moon" />
			</svg><span id="themeLbl">Dark mode</span></button>
		<a role="menuitem" class="menu-item" href="<?php echo esc_url( wp_logout_url() ); ?>"><svg class="i">
			<use href="#i-logout" />
			</svg><span>Log out</span></a>
		</div>
	</div>

	<button class="icon-btn burger" id="burger" type="button" aria-label="Open menu" aria-expanded="false"
		aria-controls="mainNav"><svg class="i">
		<use href="#i-menu" />
		</svg></button>
	</div>
</div>
</header>

<main id="main">
<section class="hero" aria-labelledby="heroTitle">
	<canvas class="hero-birds" id="heroBirds" aria-hidden="true"></canvas>
	<div class="wrap hero-in">
		<div class="hero-content">
			<p class="eyebrow">Firewall &amp; Cleanup</p>
			<h1 class="h1" id="heroTitle">Firewall &amp; <span class="hl">Cleanup</span></h1>
			<p class="lede">Block malicious traffic, detect and remove threats from your WordPress site. Advanced protection with WAF rules and one-click cleanup tools.</p>
		</div>
	</div>
</section>

<div class="qs-pro-dashboard qs-pro-firewall-cleanup">
<div class="qs-content"><p id="qs-fw-feedback" role="status" aria-live="polite"></p>
<section class="qs-overview qs-fw-overview" aria-labelledby="qs-fw-overview-title">

	<div class="qs-metrics qs-fw-metrics">
	<?php foreach ( array( array( 'shield-check', 'Firewall Status', 'blocked', 'Retained denial events', 'green' ), array( 'bug', 'Malware Detections', 'month', 'Critical findings this month', 'red' ), array( 'file', 'Cleaned Files', 'cleaned', 'Resolved removal records', 'cyan' ), array( 'globe', 'Blocked Countries', 'countries', 'GeoIP provider unavailable', 'blue' ), array( 'report', 'Quarantine', 'quarantine_count', 'Preserved evidence records', 'purple' ) ) as $gwqsh_view_metric ) : ?>
		<div class="qs-metric qs-metric-<?php echo esc_attr( $gwqsh_view_metric[4] ); ?>">
			<div class="qs-stack-icon">
				<span class="qs-stack-square" aria-hidden="true"></span>
				<span class="qs-stack-circle" aria-hidden="true">
					<?php echo $gwqsh_view_icon( $gwqsh_view_metric[0] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</span>
			</div>
			<div class="qs-metric-body">
				<h4 class="qs-metric-heading">
					<strong data-metric="<?php echo esc_attr( $gwqsh_view_metric[2] ); ?>"><?php echo esc_html( number_format_i18n( $gwqsh_view_d[ $gwqsh_view_metric[2] ] ?? 0 ) ); ?></strong>
					<span class="qs-metric-title"><?php echo esc_html( $gwqsh_view_metric[1] ); ?></span>
					<?php if ( 'blocked' === $gwqsh_view_metric[2] ) : ?>
					<span class="qs-badge qs-badge-good" id="qs-fw-status">Active</span>
					<?php endif; ?>
				</h4>
				<p class="qs-metric-desc"><?php echo esc_html( $gwqsh_view_metric[3] ); ?></p>
			</div>
		</div>
	<?php endforeach; ?>
	</div>
	<hr class="qs-overview-divider" />
</section>
<div class="qs-fw-primary-grid">
<section class="qs-card qs-fw-waf"><?php $gwqsh_view_section( 'Web Application Firewall (WAF)', 'shield-check', 'Block malicious query patterns and exploit probes.' ); ?><label class="qs-fw-master"><span id="qs-fw-master-label" class="qs-badge"></span><span class="qs-fw-switch"><input type="checkbox" id="qs-fw-enabled" aria-label="Enable public query firewall"><span></span></span></label>
<div class="qs-fw-tabs" role="tablist" aria-label="Firewall settings">
<?php
foreach ( array(
	'rules'     => 'Firewall Rules',
	'ips'       => 'IP Blocking',
	'countries' => 'Country Blocking',
	'rate'      => 'Rate Limiting',
	'custom'    => 'Custom Rules',
) as $gwqsh_view_key => $gwqsh_view_label ) :
	?>
	<button type="button" role="tab" id="qs-fw-tab-<?php echo esc_attr( $gwqsh_view_key ); ?>" aria-controls="qs-fw-panel-<?php echo esc_attr( $gwqsh_view_key ); ?>" aria-selected="<?php echo 'rules' === $gwqsh_view_key ? 'true' : 'false'; ?>" tabindex="<?php echo 'rules' === $gwqsh_view_key ? '0' : '-1'; ?>"><?php echo esc_html( $gwqsh_view_label ); ?></button><?php endforeach; ?></div>
<form id="qs-fw-settings">
<div role="tabpanel" id="qs-fw-panel-rules" aria-labelledby="qs-fw-tab-rules">
<?php foreach ( array( array( 'sql', 'Block SQL Injection', 'Detect correlated SQL probes in public query inputs.', 'report' ), array( 'xss', 'Block XSS Attempts', 'Detect script and event-handler query payloads.', 'file' ), array( 'bots', 'Block Bad Bots', 'Correlate scanner agents with sensitive exploit paths.', 'bug' ), array( 'login', 'Protect wp-login.php', 'Shared Login Protection lockout setting.', 'lock' ), array( 'agents', 'Block Suspicious User Agents', 'Uses the Bad Bots correlation; no standalone agent blocking.', 'users' ), array( 'rate', 'Enable Rate Limiting', 'General request rate limiting is unavailable.', 'calendar' ) ) as $gwqsh_view_rule ) : ?>
<label class="qs-fw-rule"><span class="qs-tile">
	<?php
	echo $gwqsh_view_icon( $gwqsh_view_rule[3] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Trusted SVG helper with escaped symbol names.
	?>
</span><span><b>
	<?php
	echo esc_html( $gwqsh_view_rule[1] );
	?>
</b><small>
	<?php
	echo esc_html( $gwqsh_view_rule[2] );
	?>
</small></span>
	<?php
	if ( in_array( $gwqsh_view_rule[0], array( 'agents', 'rate' ), true ) ) :
		?>
	<span class="qs-badge qs-fw-neutral"><?php echo 'agents' === $gwqsh_view_rule[0] ? 'Shared rule' : 'Unavailable'; ?></span>
		<?php
else :
	?>
	<span class="qs-fw-switch"><input type="checkbox" data-rule="<?php echo esc_attr( $gwqsh_view_rule[0] ); ?>" aria-label="<?php echo esc_attr( $gwqsh_view_rule[1] ); ?>"><span></span></span><?php endif; ?></label>
<?php endforeach; ?><p class="qs-fw-note">Opt-in protection inspects public URL query values. Authenticated payload inspection is a separate switch under Firewall mode &amp; additional rules, detects by default, and never denies content-authoring requests. Uploaded file bodies, credentials and session material are never inspected. This is not a comprehensive WAF.</p>
</div>
<div role="tabpanel" id="qs-fw-panel-ips" aria-labelledby="qs-fw-tab-ips" hidden><h3>Active login lockouts &amp; trusted IPs</h3><div id="qs-fw-ip-records"></div><p>Temporary authentication blocks, expiration, unlock actions and IPv4/IPv6/CIDR allowlist exceptions use Login Protection.</p><a class="qs-button" href="<?php echo esc_url( $gwqsh_view_url( 'login' ) ); ?>">Manage real IP rules →</a><p>Permanent site-wide IP bans are unavailable.</p></div>
<div role="tabpanel" id="qs-fw-panel-countries" aria-labelledby="qs-fw-tab-countries" hidden><h3>Country blocking is unavailable</h3><p>No trusted local GeoIP database or provider is configured. No country rules are enforced, and visitor-controlled country headers are ignored.</p></div>
<div role="tabpanel" id="qs-fw-panel-rate" aria-labelledby="qs-fw-tab-rate" hidden><h3>Authentication attempt limits</h3><p id="qs-fw-rate-description"></p><a class="qs-button" href="<?php echo esc_url( $gwqsh_view_url( 'login' ) ); ?>">Configure login limits →</a><p>General HTTP, API and probe rate limits are unavailable.</p></div>
<div class="qs-fw-actions-row" style="display:flex;align-items:center;gap:12px;margin-top:16px;flex-wrap:wrap;">
	<button type="submit" class="qs-button qs-fw-save" id="qs-fw-save">Save Firewall Settings
	<?php
	echo $gwqsh_view_icon( 'arrow' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Trusted SVG helper with escaped symbol names.
	?>
	</button>
	<button type="button" class="qs-button qs-btn-outline" id="btn-waf-modal"><svg class="i" style="width:14px;height:14px;margin-right:5px;"><use href="#i-gear"/></svg>Firewall mode &amp; additional rules</button>
</div>
</form>
</section>
<div class="qs-fw-right"><section class="qs-card qs-fw-scan"><?php $gwqsh_view_section( 'Malware Scan & Cleanup', 'search', 'Scan your website for malware, suspicious files and security threats.' ); ?><div class="qs-fw-scan-controls"><label class="screen-reader-text" for="qs-fw-mode">Scan type</label><select class="qs-select" id="qs-fw-mode"><option value="full">Full Scan</option></select><button type="button" class="qs-button qs-primary" id="qs-fw-start">Start Scan</button></div><div class="qs-fw-scan-body"><div class="qs-fw-ring" id="qs-fw-ring" role="progressbar" aria-label="File scan progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><div><strong id="qs-fw-percent">0%</strong><p id="qs-fw-phase">Ready to scan</p></div></div><ul class="qs-fw-checklist">
<?php
foreach ( array( 'Scan core files', 'Scan plugins', 'Scan themes', 'Scan uploads folder', 'Check for suspicious code', 'Detect local behavior signatures' ) as $gwqsh_view_label ) :
	?>
	<li>
	<?php
	echo $gwqsh_view_icon( 'check' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Trusted SVG helper with escaped symbol names.
	?>
	<span>
	<?php
	echo esc_html( $gwqsh_view_label );
	?>
</span></li><?php endforeach; ?></ul></div><p class="qs-fw-note" id="qs-fw-scan-note">Local signatures and heuristics; findings require review. Coverage limits are reported.</p></section>
<section class="qs-card qs-fw-results"><?php $gwqsh_view_section( 'Scan Results', 'bug' ); ?><a class="qs-fw-heading-link" href="<?php echo esc_url( $gwqsh_view_url( 'file-integrity' ) ); ?>">View Full Report →</a><div class="qs-fw-result-grid">
<?php
foreach ( array(
	'malware'    => 'Malware Files',
	'suspicious' => 'Suspicious Files',
	'unknown'    => 'Unknown Files',
	'clean'      => 'Clean Files',
) as $gwqsh_view_key => $gwqsh_view_label ) :
	?>
	<div><span class="qs-tile">
	<?php
	echo $gwqsh_view_icon( 'malware' === $gwqsh_view_key ? 'shield-check' : ( 'suspicious' === $gwqsh_view_key ? 'alert' : 'file' ) ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Trusted SVG helper with escaped symbol names.
	?>
	</span><strong data-result="<?php echo esc_attr( $gwqsh_view_key ); ?>">0</strong><small>
	<?php
	echo esc_html( $gwqsh_view_label );
	?>
</small></div><?php endforeach; ?></div><div id="qs-fw-result-banner" role="status"><span class="qs-tile">
<?php
echo $gwqsh_view_icon( 'alert' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Trusted SVG helper with escaped symbol names.
?>
</span><div><b id="qs-fw-result-title">No completed scan</b><p id="qs-fw-result-description">Run a scan to inspect your site.</p></div><small id="qs-fw-last"></small></div><p class="qs-fw-note">Malware = Critical heuristic findings. Unknown = unresolved integrity changes or missing files. Counts include outstanding findings.</p></section></div></div>
<div class="qs-fw-bottom-grid"><section class="qs-card qs-fw-requests"><?php $gwqsh_view_section( 'Recent Blocked Requests', 'shield-check' ); ?><button type="button" class="qs-fw-heading-link" id="qs-fw-view-all">View All →</button><div class="qs-fw-table-scroll" tabindex="0" role="region" aria-label="Blocked requests"><table><thead><tr>
<?php
foreach ( array( 'Time', 'IP Address', 'Country', 'Threat Type', 'URL', 'Action' ) as $gwqsh_view_label ) :
	?>
	<th scope="col"><?php echo esc_html( $gwqsh_view_label ); ?></th><?php endforeach; ?></tr></thead><tbody id="qs-fw-log-rows"><tr><td colspan="6">Loading recent requests…</td></tr></tbody></table></div><div class="qs-fw-pagination" id="qs-fw-pagination" hidden><button type="button" class="qs-small-button" id="qs-fw-prev">← Previous</button><span id="qs-fw-page"></span><button type="button" class="qs-small-button" id="qs-fw-next">Next →</button></div><p class="qs-fw-note">Retained denials only; ordinary failed passwords are excluded. Query firewall logs are deduplicated per visitor/rule/minute. Country attribution is unavailable.</p></section>
<section class="qs-card qs-fw-cleanup"><?php $gwqsh_view_section( 'Cleanup Tools', 'gear' ); ?>
<?php
foreach ( array( array( 'quarantine', 'Quarantine Files', 'Review findings and preserve evidence safely.', 'file' ), array( 'malware', 'Remove Malware', 'Review Critical findings; quarantine before removal.', 'bug' ), array( 'restore', 'Restore Clean Files', 'Restore from official core or a verified trusted copy.', 'refresh' ), array( 'rescan', 'Re-scan After Cleanup', 'Run the shared scanner to verify your site.', 'search' ) ) as $gwqsh_view_tool ) :
	?>
	<button type="button" class="qs-fw-tool" data-tool="<?php echo esc_attr( $gwqsh_view_tool[0] ); ?>"><span class="qs-tile">
	<?php
	echo $gwqsh_view_icon( $gwqsh_view_tool[3] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Trusted SVG helper with escaped symbol names.
	?>
</span><span><b>
	<?php
	echo esc_html( $gwqsh_view_tool[1] );
	?>
</b><small>
	<?php
	echo esc_html( $gwqsh_view_tool[2] );
	?>
</small></span><span aria-hidden="true">›</span></button><?php endforeach; ?></section><section class="qs-card qs-fw-database"><?php $gwqsh_view_section( 'Database Scan', 'gear', 'Malware and persistence stored in options, posts, widgets, scheduled tasks and accounts.' ); ?><div class="qs-fw-scan-controls"><span class="qs-badge qs-fw-neutral" id="qs-db-status"><?php echo esc_html( $gwqsh_view_db['status_label'] ); ?></span><button type="button" class="qs-button qs-primary" id="qs-db-run">Run Database Scan</button><button type="button" class="qs-button qs-btn-outline" id="qs-db-baseline">Approve Administrator Baseline</button></div><p id="qs-db-feedback" role="status" aria-live="polite"></p><p class="qs-fw-note" id="qs-db-coverage"></p><p class="qs-fw-note" id="qs-db-meta"></p><div class="qs-fw-table-scroll" tabindex="0" role="region" aria-label="Database scan findings"><table><thead><tr><th scope="col">Rule</th><th scope="col">Severity</th><th scope="col">Stored in</th><th scope="col">Record</th><th scope="col">Evidence</th></tr></thead><tbody id="qs-db-rows"></tbody></table></div><p class="qs-fw-note" id="qs-db-disclaimer">Database findings are evidence for review. Nothing is deleted or modified automatically.</p></section></div>
</div>
<template id="tpl-waf">
	<div class="qs-modal-enterprise-content">
		<?php GWQSH_Enterprise_UI::render( 'waf' ); ?>
	</div>
</template>
</main></div>
