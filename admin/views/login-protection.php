<?php
/**
 * Pro login protection command center.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
$gwqsh_view_d        = GWQSH_Admin::get_page_initial_data( 'login-protection' );
$gwqsh_view_user     = wp_get_current_user();
$gwqsh_u_name        = ( $gwqsh_view_user && $gwqsh_view_user->exists() ) ? ( $gwqsh_view_user->display_name ? $gwqsh_view_user->display_name : $gwqsh_view_user->user_login ) : 'Admin';
$gwqsh_u_initial     = strtoupper( substr( $gwqsh_u_name, 0, 1 ) );
$gwqsh_u_role        = ! empty( $gwqsh_view_user->roles[0] ) ? ucfirst( $gwqsh_view_user->roles[0] ) : 'Administrator';
$gwqsh_view_icon     = static function ( $gwqsh_view_name ) {
	return '<svg class="qs-icon" aria-hidden="true"><use href="#i-' . esc_attr( $gwqsh_view_name ) . '"/></svg>';
};
$gwqsh_view_url      = static function ( $gwqsh_view_page ) {
	$gwqsh_view_slugs = array(
		'dashboard'      => '',
		'login'          => '-login',
		'two-factor'     => '-two-factor',
		'file-integrity' => '-file-integrity',
		'hardening'      => '-hardening',
		'activity-log'   => '-activity-log',
		'pro'            => '-pro',
		'settings'       => '-settings',
	);
	return admin_url( 'admin.php?page=gracewell-security-suite-pro' . $gwqsh_view_slugs[ $gwqsh_view_page ] );
};
$gwqsh_view_head     = static function ( $gwqsh_view_title, $gwqsh_view_symbol, $gwqsh_view_page = '', $gwqsh_view_action = 'View All', $gwqsh_view_extra = '' ) use ( $gwqsh_view_icon, $gwqsh_view_url ) {
	echo '<div class="qs-card-head"><span class="qs-tile">' . $gwqsh_view_icon( $gwqsh_view_symbol ) . '</span><h2>' . esc_html( $gwqsh_view_title ) . '</h2>' . $gwqsh_view_extra; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Icon helper escapes symbol; extra is trusted markup generated below.
	if ( $gwqsh_view_page ) {
		echo '<a class="qs-small-button" href="' . esc_url( $gwqsh_view_url( $gwqsh_view_page ) ) . '">' . esc_html( $gwqsh_view_action ) . $gwqsh_view_icon( 'arrow' ) . '</a>'; } // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped icon helper.
	echo '</div>';
};
$gwqsh_view_settings = $gwqsh_view_d['settings'];
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
		<p class="eyebrow">Login Protection</p>
		<h1 class="h1" id="heroTitle">Login <span class="hl">Protection</span></h1>
		<p class="lede">Stop brute-force attacks, secure wp-login.php and XML-RPC, and control access with smarter protection rules.</p>
		<div class="hero-actions">
			<a class="btn btn-primary" href="#qs-protection-settings"><span>Configure Protection</span><svg class="i"><use href="#i-arrow" /></svg></a>
			<a class="btn btn-neutral" href="#qs-login-events"><svg class="i"><use href="#i-report" /></svg><span>View Login Activity</span></a>
		</div>
	</div>
	<div class="qs-login-status-panel" role="group" aria-label="Current login protection status">
	<?php
	foreach ( array( array( 'Protection Engine', $gwqsh_view_d['engine_active'] ? 'Active' : 'Paused', $gwqsh_view_d['engine_active'], 'engine' ), array( 'Custom Login URL', $gwqsh_view_d['custom_active'] ? 'Enabled' : 'Disabled', $gwqsh_view_d['custom_active'], 'custom' ), array( 'Proxy Detection', $gwqsh_view_d['proxy_name'], $gwqsh_view_d['proxy_effective'], 'proxy' ) ) as $gwqsh_view_row ) :
		?>
		<div><span class="qs-status-check"><?php echo $gwqsh_view_icon( $gwqsh_view_row[2] ? 'check' : 'alert' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span><span><?php echo esc_html( $gwqsh_view_row[0] ); ?> <b data-status-label="<?php echo esc_attr( $gwqsh_view_row[3] ); ?>"><?php echo esc_html( $gwqsh_view_row[1] ); ?></b></span><span class="qs-badge <?php echo $gwqsh_view_row[2] ? 'qs-good' : 'qs-warning'; ?>" data-status-badge="<?php echo esc_attr( $gwqsh_view_row[3] ); ?>"><?php echo $gwqsh_view_row[2] ? 'Active' : ( 'proxy' === $gwqsh_view_row[3] ? 'Direct' : 'Inactive' ); ?></span></div><?php endforeach; ?>
	</div>
	</div>
</section>

<div class="qs-pro-dashboard qs-pro-login-page">
<div class="qs-content qs-login-content">
<div id="qs-login-error" class="qs-load-error" role="alert"
<?php
if ( ! $gwqsh_view_d['data_error'] ) {
	echo 'hidden'; }
?>
>Unable to load login security statistics. <button id="qs-login-retry" type="button">Retry</button></div>
<div id="qs-login-feedback" class="qs-login-feedback" role="status" aria-live="polite"></div>
<section class="qs-overview qs-login-overview" aria-labelledby="qs-login-overview-title">

	<div class="qs-metrics qs-login-metrics">
	<?php
	$gwqsh_view_metrics = array(
		array( 'shield-check', 'Blocked Login Attacks', number_format_i18n( $gwqsh_view_d['blocked_30d'] ), 'Denied requests recorded in 30 days', 'red', 'blocked' ),
		array( 'lock', 'Active Lockouts', count( $gwqsh_view_d['locked_ips'] ), 'IPs are currently locked out', 'red', 'locked' ),
		array( 'gear', 'Max Failures Rule', $gwqsh_view_settings['max_attempts'] . ' in ' . $gwqsh_view_settings['time_window'] . ' min', 'Before temporary lockout', 'blue', 'failures' ),
		array( 'refresh', 'Lockout Duration', $gwqsh_view_settings['lockout_duration'] . ' min', 'Default lockout time', 'purple', 'duration' ),
		array( 'users', 'Trusted IPs', count( $gwqsh_view_d['allow_ips'] ), 'IP addresses allowlisted', 'cyan', 'trusted' ),
	);
	foreach ( $gwqsh_view_metrics as $gwqsh_view_metric ) :
		$gwqsh_view_color_tone = $gwqsh_view_metric[4];
		?>
		<div class="qs-metric qs-metric-<?php echo esc_attr( $gwqsh_view_color_tone ); ?>" data-login-metric="<?php echo esc_attr( $gwqsh_view_metric[5] ); ?>">
			<div class="qs-stack-icon">
				<span class="qs-stack-square" aria-hidden="true"></span>
				<span class="qs-stack-circle" aria-hidden="true">
					<?php echo $gwqsh_view_icon( $gwqsh_view_metric[0] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
				</span>
			</div>
			<div class="qs-metric-body">
				<h4 class="qs-metric-heading">
					<strong><?php echo esc_html( $gwqsh_view_metric[2] ); ?></strong>
					<span class="qs-metric-title"><?php echo esc_html( $gwqsh_view_metric[1] ); ?></span>
				</h4>
				<p class="qs-metric-desc"><?php echo esc_html( $gwqsh_view_metric[3] ); ?></p>
			</div>
		</div>
	<?php endforeach; ?>
	</div>
	<hr class="qs-overview-divider" />
</section>
<div class="qs-login-analytics">
	<section class="qs-card qs-login-score" data-score-level="<?php echo $gwqsh_view_d['protection_score'] >= 85 ? 'good' : ( $gwqsh_view_d['protection_score'] >= 50 ? 'review' : 'weak' ); ?>"><?php $gwqsh_view_head( 'Protection Status', 'shield-check', '', '', '<a class="qs-small-button" href="#qs-protection-settings">View Details ' . $gwqsh_view_icon( 'arrow' ) . '</a>' ); ?><div class="qs-score-body"><div class="qs-gauge" id="qs-login-gauge" role="img" aria-label="<?php echo esc_attr( 'Login protection score ' . $gwqsh_view_d['protection_score'] . ' out of 100' ); ?>"><svg viewBox="0 0 180 180" aria-hidden="true"><defs><linearGradient id="qs-login-gradient"><stop stop-color="var(--qs-score-start)"/><stop offset="1" stop-color="var(--qs-score-color)"/></linearGradient></defs><circle class="qs-gauge-track" cx="90" cy="90" r="77"/><circle id="qs-login-ring" cx="90" cy="90" r="77" stroke="url(#qs-login-gradient)" stroke-dasharray="483.805" stroke-dashoffset="<?php echo esc_attr( 483.805 * ( 1 - $gwqsh_view_d['protection_score'] / 100 ) ); ?>"/></svg><div><strong id="qs-login-score-value"><?php echo esc_html( $gwqsh_view_d['protection_score'] ); ?></strong><span>/ 100</span><b id="qs-login-score-status"><?php echo $gwqsh_view_d['protection_score'] >= 85 ? 'Excellent' : ( $gwqsh_view_d['protection_score'] >= 50 ? 'Review' : 'Needs attention' ); ?></b></div></div><div class="qs-score-details"><h3 id="qs-login-headline"><?php echo $gwqsh_view_d['protection_score'] >= 85 ? 'Your login protection is strong!' : 'Strengthen your login protection'; ?></h3><p>Based on your enabled login rules, custom URL and XML-RPC protection.</p><ul>
	<?php
	foreach ( array(
		'brute'  => 'Brute-Force Protection',
		'custom' => 'Custom Login URL',
		'xmlrpc' => 'XML-RPC Protection',
		'rules'  => 'IP Lockout Rules',
	) as $gwqsh_view_key => $gwqsh_view_name ) :
		?>
	<li><span class="qs-login-score-check <?php echo $gwqsh_view_d['score_components'][ $gwqsh_view_key ] ? '' : 'qs-is-inactive'; ?>"><?php echo $gwqsh_view_icon( $gwqsh_view_d['score_components'][ $gwqsh_view_key ] ? 'check' : 'alert' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span><span><?php echo esc_html( $gwqsh_view_name ); ?></span><b data-login-score="<?php echo esc_attr( $gwqsh_view_key ); ?>"><?php echo null === $gwqsh_view_d['score_components'][ $gwqsh_view_key ] ? 'N/A' : esc_html( $gwqsh_view_d['score_components'][ $gwqsh_view_key ] ); ?></b></li><?php endforeach; ?></ul></div></div></section>
	<section class="qs-card qs-login-trends"><?php $gwqsh_view_head( 'Login Attempt Trends', 'bars', '', '', '<label class="screen-reader-text" for="qs-login-chart-range">Attack trends period</label><select class="qs-select" id="qs-login-chart-range"><option value="7">Last 7 Days</option><option value="14">Last 14 Days</option><option value="30">Last 30 Days</option></select>' ); ?><div class="qs-legend"><span><i class="qs-series-dot qs-login-red"></i>Blocked Attempts</span><span><i class="qs-series-dot qs-login-orange"></i>Failed Logins</span><span><i class="qs-series-dot qs-login-blue"></i>Successful Logins</span></div><div id="qs-login-chart" class="qs-login-chart" tabindex="0" aria-label="Attack trends. Arrow keys explore daily counts."></div><p class="qs-login-chart-note" id="qs-login-chart-empty">Counts reflect recorded login activity for the selected period.</p></section>
	<section class="qs-card qs-login-rules"><?php $gwqsh_view_head( 'Lockout Rules', 'gear', '', '', '<a class="qs-small-button" href="#qs-protection-settings">Manage Rules ' . $gwqsh_view_icon( 'arrow' ) . '</a>' ); ?><ul class="qs-login-rule-list">
	<?php
	foreach ( array( array( 'lock', $gwqsh_view_settings['max_attempts'] . ' failed login attempts in ' . $gwqsh_view_settings['time_window'] . ' minutes', 'Lock IP for ' . $gwqsh_view_settings['lockout_duration'] . ' minutes', $gwqsh_view_d['engine_active'], 'threshold' ), array( 'refresh', $gwqsh_view_settings['repeat_lockouts'] . ' lockouts in 24 hours', 'Trigger a ' . $gwqsh_view_settings['repeat_duration'] . '-hour lockout', $gwqsh_view_d['engine_active'], 'repeat' ), array( 'file', 'Show generic login errors', 'Prevents username disclosure in error messages', $gwqsh_view_settings['generic_errors'], 'generic' ), array( 'shield-check', 'Proxy & IP detection', 'Only explicitly trusted proxy headers are accepted', $gwqsh_view_d['proxy_effective'], 'proxy' ), array( 'users', 'Track by IP and username', 'Record usernames alongside failed-login IPs', $gwqsh_view_settings['track_username'], 'track' ) ) as $gwqsh_view_rule ) :
		?>
		<li data-login-rule="<?php echo esc_attr( $gwqsh_view_rule[4] ); ?>"><span class="qs-tile"><?php echo $gwqsh_view_icon( $gwqsh_view_rule[0] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span><div><b><?php echo esc_html( $gwqsh_view_rule[1] ); ?></b><small><?php echo esc_html( $gwqsh_view_rule[2] ); ?></small></div><span class="qs-badge <?php echo $gwqsh_view_rule[3] ? 'qs-good' : 'qs-warning'; ?>"><?php echo $gwqsh_view_rule[3] ? 'Enabled' : ( 'proxy' === $gwqsh_view_rule[4] ? 'Direct IP' : 'Disabled' ); ?></span></li><?php endforeach; ?>
	</ul></section>
</div>
<div class="qs-login-forms">
	<section class="qs-card qs-protection-settings" id="qs-protection-settings"><?php $gwqsh_view_head( 'Protection Settings', 'gear' ); ?><p class="qs-login-subtitle">Configure how Security Suite Pro handles failed login attempts and lockouts.</p>
	<form id="qs-login-settings-form"><div class="qs-login-settings-grid">
	<?php
	foreach ( array( array( 'max_attempts', 'Failed attempts threshold', array( 1, 3, 5, 10, 15, 20 ), 'Number of failed login attempts before lockout.', ' attempts' ), array( 'time_window', 'Time window', array( 1, 5, 10, 15, 30, 60 ), 'Time period to count failed attempts.', ' minutes' ), array( 'lockout_duration', 'Lockout duration', array( 5, 15, 30, 60, 120, 1440 ), 'How long to block the IP after reaching threshold.', ' minutes' ), array( 'repeat_lockouts', 'Repeat lockouts in 24h', array( 1, 2, 3, 4, 5, 10 ), 'Repeated lockouts before escalation within 24 hours.', ' lockouts' ) ) as $gwqsh_view_field ) :
		$gwqsh_view_values = $gwqsh_view_field[2];
		if ( ! in_array( (int) $gwqsh_view_settings[ $gwqsh_view_field[0] ], $gwqsh_view_values, true ) ) {
			$gwqsh_view_values[] = (int) $gwqsh_view_settings[ $gwqsh_view_field[0] ];
			sort( $gwqsh_view_values ); }
		?>
		<label class="qs-login-field" for="qs-<?php echo esc_attr( $gwqsh_view_field[0] ); ?>"><b><?php echo esc_html( $gwqsh_view_field[1] ); ?></b><select id="qs-<?php echo esc_attr( $gwqsh_view_field[0] ); ?>" name="<?php echo esc_attr( $gwqsh_view_field[0] ); ?>" class="qs-select">
		<?php
		foreach ( $gwqsh_view_values as $gwqsh_view_value ) :
			?>
	<option value="<?php echo esc_attr( $gwqsh_view_value ); ?>" <?php selected( $gwqsh_view_value, $gwqsh_view_settings[ $gwqsh_view_field[0] ] ); ?>><?php echo esc_html( $gwqsh_view_value . $gwqsh_view_field[4] ); ?></option><?php endforeach; ?></select><small><?php echo esc_html( $gwqsh_view_field[3] ); ?></small></label><?php endforeach; ?>
	</div><div class="qs-login-toggle-grid">
	<?php
	foreach ( array(
		'generic_errors' => array( 'Generic login error messages', 'Show the same message for login failures.', $gwqsh_view_settings['generic_errors'] ),
		'track_username' => array( 'Track by IP and username', 'Include usernames in failed-login audit records.', $gwqsh_view_settings['track_username'] ),
		'xmlrpc'         => array( 'Protect XML-RPC logins', 'Uses the shared Hardening rule to deny XML-RPC.', $gwqsh_view_d['xmlrpc_configured'] ),
		'email_lockout'  => array( 'Email alert on lockout', 'Email the site administrator when an IP is locked.', $gwqsh_view_settings['email_lockout'] ),
	) as $gwqsh_view_key => $gwqsh_view_toggle ) :
		?>
	<label class="qs-login-toggle"><input type="checkbox" name="<?php echo esc_attr( $gwqsh_view_key ); ?>" <?php checked( $gwqsh_view_toggle[2] ); ?>><span class="qs-toggle-track" aria-hidden="true"></span><span><b><?php echo esc_html( $gwqsh_view_toggle[0] ); ?></b><small><?php echo esc_html( $gwqsh_view_toggle[1] ); ?></small></span></label><?php endforeach; ?></div><div class="qs-login-save-row"><label class="qs-login-toggle"><input name="enabled" type="checkbox" <?php checked( $gwqsh_view_settings['enabled'] ); ?>><span class="qs-toggle-track" aria-hidden="true"></span><span><b>Protection engine enabled</b></span></label><details class="qs-login-escalation"><summary>Escalated lockout</summary><label class="qs-login-field" for="qs-repeat_duration"><b>Duration after repeat lockouts</b><select id="qs-repeat_duration" class="qs-select" name="repeat_duration">
	<?php
	$gwqsh_view_repeat_values = array( 1, 6, 12, 24, 48, 72 );
	if ( ! in_array( (int) $gwqsh_view_settings['repeat_duration'], $gwqsh_view_repeat_values, true ) ) {
		$gwqsh_view_repeat_values[] = (int) $gwqsh_view_settings['repeat_duration'];
		sort( $gwqsh_view_repeat_values );
	}
	foreach ( $gwqsh_view_repeat_values as $gwqsh_view_repeat_value ) :
		?>
<option value="<?php echo esc_attr( $gwqsh_view_repeat_value ); ?>" <?php selected( $gwqsh_view_repeat_value, $gwqsh_view_settings['repeat_duration'] ); ?>><?php echo esc_html( $gwqsh_view_repeat_value . ' hours' ); ?></option><?php endforeach; ?></select><small>Longer lockout after repeated offenses.</small></label></details><button class="qs-small-button" type="submit">Save Protection</button></div></form>
		<div class="qs-protection-extra-actions" style="margin-top:16px;padding-top:14px;border-top:1px solid var(--line,#e2e8f0);display:flex;flex-wrap:wrap;gap:10px;align-items:center;">
			<button type="button" class="qs-button qs-btn-outline" id="btn-login-recovery-modal"><?php echo $gwqsh_view_icon( 'lock' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Login URL &amp; emergency recovery</button>
			<button type="button" class="qs-button qs-btn-outline" id="btn-country-restrictions-modal"><?php echo $gwqsh_view_icon( 'globe' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Country restrictions</button>
			<button type="button" class="qs-button qs-btn-outline" id="btn-ip-reputation-modal"><?php echo $gwqsh_view_icon( 'shield-check' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>IP reputation</button>
		</div>
	</section>
	<section class="qs-card qs-login-access" id="qs-login-access"><?php $gwqsh_view_head( 'Access Controls', 'lock' ); ?><p class="qs-login-subtitle">Control how users access your login areas and manage trust settings.</p><div class="qs-login-access-columns"><form id="qs-login-access-form">
	<div class="qs-login-field qs-login-url-field"><label for="qs-login-slug"><b>Custom Login URL</b></label><div class="qs-login-url-row"><input class="qs-login-input" id="qs-login-slug" name="slug" type="text" value="<?php echo esc_attr( $gwqsh_view_settings['custom_slug'] ); ?>" pattern="[a-z0-9][a-z0-9-]{2,39}" minlength="3" maxlength="40" required><label class="qs-login-toggle qs-custom-toggle"><input name="custom_enabled" type="checkbox" <?php checked( $gwqsh_view_settings['custom_slug_enabled'] ); ?> aria-label="Enable custom login URL"><span class="qs-toggle-track" aria-hidden="true"></span><span><b data-custom-url-state><?php echo $gwqsh_view_settings['custom_slug_enabled'] ? 'Enabled' : 'Disabled'; ?></b></span></label></div><small>Protect your login page with a custom URL.</small></div>
	<label class="qs-login-field" for="qs-guest-login"><b>Guest access to wp-login.php</b><select class="qs-select" id="qs-guest-login" name="guest_login_behavior"><option value="home" <?php selected( $gwqsh_view_settings['guest_login_behavior'], 'home' ); ?>>Redirect to homepage</option><option value="404" <?php selected( $gwqsh_view_settings['guest_login_behavior'], '404' ); ?>>404 - Not Found</option></select><small>Applies when the custom login URL is enabled.</small></label>
	<label class="qs-login-field" for="qs-guest-admin"><b>Guest access to wp-admin</b><select class="qs-select" id="qs-guest-admin" name="guest_admin_behavior"><option value="home" <?php selected( $gwqsh_view_settings['guest_admin_behavior'], 'home' ); ?>>Redirect to homepage</option><option value="login" <?php selected( $gwqsh_view_settings['guest_admin_behavior'], 'login' ); ?>>Restricted (Login Required)</option></select><small>Protects admin access; preserves AJAX and admin-post.</small></label><button class="qs-small-button" type="submit">Save Access</button>
	</form><div class="qs-login-trust-column" id="qs-trusted-ips">
	<label class="qs-login-field" for="qs-proxy-mode"><b>Proxy IP detection</b><select class="qs-select" id="qs-proxy-mode" form="qs-login-access-form" name="proxy_mode">
	<?php
	foreach ( array(
		'remote'     => 'Direct visitor IP',
		'xff'        => 'X-Forwarded-For',
		'cf'         => 'Cloudflare',
		'xreal'      => 'X-Real-IP',
		'trueclient' => 'True-Client-IP',
	) as $gwqsh_view_key => $gwqsh_view_name ) :
		?>
																																															<option value="<?php echo esc_attr( $gwqsh_view_key ); ?>" <?php selected( $gwqsh_view_key, $gwqsh_view_d['proxy_mode'] ); ?> ><?php echo esc_html( $gwqsh_view_name ); ?></option><?php endforeach; ?></select><small>Only headers from trusted proxy addresses are accepted.</small></label><label class="qs-login-field" for="qs-trusted-proxies"><b>Trusted proxy IPs / CIDRs</b><textarea class="qs-login-input" id="qs-trusted-proxies" name="trusted_proxies" form="qs-login-access-form" rows="3" placeholder="10.0.0.10 or 10.0.0.0/24"><?php echo esc_textarea( GWQSH_Settings::get( 'trusted_proxies', '' ) ); ?></textarea><small>Enter the reverse proxy addresses, one per line. These are separate from trusted visitor IPs.</small></label>
	<div class="qs-login-allow-title"><b>IP Allowlist (Trusted IPs)</b><button class="qs-text-button" id="qs-add-ip-focus" type="button">Manage <?php echo $gwqsh_view_icon( 'arrow' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></button></div><div class="qs-login-chips" data-allowlist></div><form class="qs-login-add-ip"><label class="screen-reader-text" for="qs-new-trusted-ip">Add trusted IP address</label><input id="qs-new-trusted-ip" class="qs-login-input" type="text" name="ip" placeholder="Add trusted IP address…" required><button class="qs-button qs-primary" type="submit">Add</button></form>
	<div class="qs-login-roles"><b>Per-role protection rules</b><div>
	<?php
	foreach ( $gwqsh_view_d['roles'] as $gwqsh_view_login_role ) :
		?>
		<span><b><?php echo esc_html( $gwqsh_view_login_role['name'] ); ?></b><input type="checkbox" class="gwqsh-role-toggle" data-role-protection="<?php echo esc_attr( $gwqsh_view_login_role['key'] ); ?>" aria-label="<?php echo esc_attr( $gwqsh_view_login_role['name'] . ' login protection' ); ?>" <?php checked( $gwqsh_view_settings['role_protection'][ $gwqsh_view_login_role['key'] ] ?? true ); ?>></span><?php endforeach; ?></div><small>Enable login rate limiting by role. Unknown accounts are always protected. Save Access to apply changes.</small></div>
	</div></div>
</section>
</div>
<div class="qs-login-tables">
	<section class="qs-card qs-login-locked" id="qs-locked-ips"><?php $gwqsh_view_head( 'Currently Locked IPs', 'lock', '', '', '<button class="qs-small-button" id="qs-all-lockouts" type="button">View All ' . $gwqsh_view_icon( 'arrow' ) . '</button>' ); ?><div class="qs-table-scroll" role="region" tabindex="0" aria-label="Scrollable login records"><table class="qs-table"><thead><tr><th scope="col">IP Address</th><th scope="col">Username</th><th scope="col">Attempts</th><th scope="col">Locked Until</th><th scope="col">Reason</th><th scope="col">Action</th></tr></thead><tbody id="qs-locked-body"><tr><td colspan="6" class="qs-empty">Loading lockout records…</td></tr></tbody></table></div></section>
	<section class="qs-card qs-login-events" id="qs-login-events"><?php $gwqsh_view_head( 'Recent Login Events', 'file', 'activity-log' ); ?><div class="qs-table-scroll" role="region" tabindex="0" aria-label="Scrollable login records"><table class="qs-table"><thead><tr><th scope="col">Time</th><th scope="col">Event Type</th><th scope="col">IP Address</th><th scope="col">Username</th><th scope="col">Result</th></tr></thead><tbody id="qs-login-event-body"><tr><td colspan="5" class="qs-empty">Loading login events…</td></tr></tbody></table></div></section>
</div>

<div class="qs-login-bottom">
	<?php $gwqsh_view_history = GWQSH_IP_Blocks::history(); ?>
	<section class="qs-card qs-card-ip-history" id="qs-ip-blocks-panel">
		<div class="qs-card-head">
			<span class="qs-tile qs-tile-blue"><svg class="i"><use href="#i-shield-check" /></svg></span>
			<div class="qs-card-head-txt">
				<h2>IP Blocks &amp; History</h2>
				<p class="qs-card-subtitle">Manage manual IP restrictions and view block audit records.</p>
			</div>
		</div>
		<form id="gwqsh-ip-form" class="qs-ip-action-row">
			<div class="qs-ip-field-group">
				<label class="screen-reader-text" for="qs-ip-address-input">IP address</label>
				<input type="text" id="qs-ip-address-input" name="ip" class="qs-login-input" placeholder="Enter IPv4 or IPv6 address…" required />
			</div>
			<div class="qs-ip-field-group">
				<label class="screen-reader-text" for="qs-ip-duration-select">Block duration</label>
				<select id="qs-ip-duration-select" name="minutes" class="qs-select">
					<option value="0">Permanent</option>
					<option value="15">15 minutes</option>
					<option value="60">1 hour</option>
					<option value="1440">24 hours</option>
					<option value="10080">7 days</option>
					<option value="43200">30 days</option>
				</select>
			</div>
			<div class="qs-ip-field-group qs-ip-reason-group">
				<label class="screen-reader-text" for="qs-ip-reason-input">Reason</label>
				<input type="text" id="qs-ip-reason-input" name="reason" class="qs-login-input" placeholder="Reason or reference note…" />
			</div>
			<button type="submit" class="qs-button qs-primary" id="qs-ip-block-btn">Block IP</button>
		</form>
		<div class="qs-table-scroll" role="region" tabindex="0" aria-label="IP Block History">
			<div id="gwqsh-ip-history">
				<?php if ( empty( $gwqsh_view_history['items'] ) ) : ?>
					<table class="qs-table qs-table-ip-history">
						<thead>
							<tr>
								<th scope="col" style="width: 140px;">IP ADDRESS</th>
								<th scope="col" style="width: 150px;">BLOCKED UNTIL</th>
								<th scope="col" style="width: 110px;">DURATION</th>
								<th scope="col">REASON</th>
								<th scope="col" style="width: 140px;">ADDED</th>
								<th scope="col" style="width: 100px;">ADDED BY</th>
								<th scope="col" style="width: 100px; text-align: right;">ACTION</th>
							</tr>
						</thead>
						<tbody>
							<tr><td colspan="7" class="qs-empty">No manual IP blocks recorded</td></tr>
						</tbody>
					</table>
				<?php else : ?>
					<table class="qs-table qs-table-ip-history">
						<thead>
							<tr>
								<th scope="col" style="width: 140px;">IP ADDRESS</th>
								<th scope="col" style="width: 150px;">BLOCKED UNTIL</th>
								<th scope="col" style="width: 110px;">DURATION</th>
								<th scope="col">REASON</th>
								<th scope="col" style="width: 140px;">ADDED</th>
								<th scope="col" style="width: 100px;">ADDED BY</th>
								<th scope="col" style="width: 100px; text-align: right;">ACTION</th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ( $gwqsh_view_history['items'] as $gwqsh_ip_item ) : ?>
							<tr>
								<td class="qs-td-ip"><b><?php echo esc_html( $gwqsh_ip_item['ip_address'] ); ?></b></td>
								<td><?php echo esc_html( $gwqsh_ip_item['expires'] ); ?></td>
								<td><?php echo esc_html( $gwqsh_ip_item['duration'] ?? 'Permanent' ); ?></td>
								<td><?php echo esc_html( $gwqsh_ip_item['reason'] ? $gwqsh_ip_item['reason'] : '—' ); ?></td>
								<td><span class="qs-td-time"><?php echo esc_html( $gwqsh_ip_item['created'] ); ?></span></td>
								<td><span class="qs-badge qs-blue-badge"><?php echo esc_html( $gwqsh_ip_item['added_by'] ?? 'admin' ); ?></span></td>
								<td style="text-align: right;">
									<?php if ( 'Blocked' === $gwqsh_ip_item['status'] ) : ?>
										<button type="button" class="qs-button qs-btn-danger-outline sm" data-manual-unblock="<?php echo esc_attr( $gwqsh_ip_item['ip_address'] ); ?>" aria-label="Unblock <?php echo esc_attr( $gwqsh_ip_item['ip_address'] ); ?>">Unblock</button>
									<?php else : ?>
										<span class="qs-badge qs-badge-neutral"><?php echo esc_html( $gwqsh_ip_item['status'] ); ?></span>
									<?php endif; ?>
								</td>
							</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				<?php endif; ?>
			</div>
		</div>
		<div class="qs-history-pagination">
			<button type="button" class="qs-small-button" data-ip-page="prev" <?php echo ( $gwqsh_view_history['page'] <= 1 ) ? 'disabled' : ''; ?>>Previous</button>
			<span id="gwqsh-ip-page">Page <?php echo esc_html( $gwqsh_view_history['page'] ); ?> of <?php echo esc_html( $gwqsh_view_history['pages'] ); ?></span>
			<button type="button" class="qs-small-button" data-ip-page="next" <?php echo ( $gwqsh_view_history['page'] >= $gwqsh_view_history['pages'] ) ? 'disabled' : ''; ?>>Next</button>
		</div>
	</section>
</div>

</div>
</div>
</main>

<template id="tpl-login-recovery">
	<div class="qs-modal-recovery-content" style="padding:4px 0;">
		<p style="margin:0 0 12px 0;font-size:13px;color:var(--muted,#64748b);">Your active login address and confidential emergency bypass endpoint.</p>
		<div style="background:var(--subtle,#f8fafc);border:1px solid var(--line,#e2e8f0);border-radius:8px;padding:14px;margin-bottom:14px;">
			<label style="font-size:11px;font-weight:700;text-transform:uppercase;color:var(--muted,#64748b);display:block;margin-bottom:6px;letter-spacing:0.5px;">Custom Login URL</label>
			<code id="qs-configured-url" style="display:block;font-size:13px;word-break:break-all;margin-bottom:12px;background:#fff;padding:8px 10px;border-radius:6px;border:1px solid var(--line,#e2e8f0);"><?php echo esc_html( $gwqsh_view_d['login_url'] ); ?></code>
			<div style="display:flex;gap:10px;flex-wrap:wrap;">
				<button class="qs-small-button" id="qs-copy-login-url" type="button"><?php echo $gwqsh_view_icon( 'file' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Copy login URL</button>
				<button class="qs-small-button" id="qs-copy-recovery" type="button"><?php echo $gwqsh_view_icon( 'shield-check' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Copy private recovery URL</button>
			</div>
		</div>
		<small style="display:block;font-size:12px;color:var(--muted,#64748b);line-height:1.4;">Keep the recovery URL private. Password reset and logout remain available even when the custom login URL is enabled.</small>
	</div>
</template>

<template id="tpl-country-restrictions">
	<div class="qs-modal-enterprise-content">
		<?php GWQSH_Enterprise_UI::render( 'geo' ); ?>
	</div>
</template>

<template id="tpl-ip-reputation">
	<div class="qs-modal-enterprise-content">
		<?php GWQSH_Enterprise_UI::render( 'reputation', 'login' ); ?>
	</div>
</template>
