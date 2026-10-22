<?php
/**
 * Settings administration view (10-Card Dashboard matching reference).
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
$gwqsh_data      = GWQSH_Admin::get_page_initial_data( 'settings' );
$gwqsh_current_u = wp_get_current_user();
$gwqsh_u_name    = ( $gwqsh_current_u && $gwqsh_current_u->exists() ) ? ( $gwqsh_current_u->display_name ? $gwqsh_current_u->display_name : $gwqsh_current_u->user_login ) : 'Admin';
$gwqsh_u_initial = strtoupper( substr( $gwqsh_u_name, 0, 1 ) );
$gwqsh_u_role    = ! empty( $gwqsh_current_u->roles[0] ) ? ucfirst( $gwqsh_current_u->roles[0] ) : 'Administrator';

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
		</svg><span class="dot-badge off" id="notifDot">0</span>
		</button>
		<div class="menu menu-notif" id="menu-notif" role="menu">
		<div class="menu-head"><b>Notifications</b><button class="link-btn" id="markRead" type="button">Mark all as
			read</button></div>
		<div class="menu-item">No unread security notifications.</div>
		</div>
	</div>

	<div class="menu-wrap help-wrap">
		<button class="icon-btn" data-menu="help" type="button" aria-haspopup="true" aria-expanded="false"
		aria-label="Help"><svg class="i">
			<use href="#i-help" />
		</svg></button>
		<div class="menu" id="menu-help" role="menu"><button class="menu-item" role="menuitem" type="button" data-changelog>Changelog · Version <?php echo esc_html( GWQSH_VERSION ); ?></button>
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
		<p class="eyebrow">General Settings</p>
		<h1 class="h1" id="heroTitle">Plugin <span class="hl">Settings</span></h1>
		<p class="lede">Configure global security preferences, notifications, and maintenance tools.</p>
	</div>
	</div>
</section>

<div class="wrap page qs-settings-page">
	<div class="qs-settings-grid-10">

		<!-- 1. Site Information -->
		<section class="card qs-card qs-set-card" id="qs-set-site-info">
			<div class="card-head">
				<span class="tile t-blue"><svg class="i" viewBox="0 0 24 24"><use href="#i-globe" /></svg></span>
				<div class="ttl">
					<h2>Site Information</h2>
					<p>WordPress core and environment details.</p>
				</div>
			</div>
			<dl class="info-list qs-info-table">
				<div><dt>Site Name</dt><dd><?php echo esc_html( get_bloginfo( 'name' ) ); ?></dd></div>
				<div><dt>Site URL</dt><dd><?php echo esc_html( home_url( '/' ) ); ?></dd></div>
				<div><dt>WordPress Version</dt><dd>v<?php echo esc_html( get_bloginfo( 'version' ) ); ?></dd></div>
				<div><dt>PHP Version</dt><dd>v<?php echo esc_html( PHP_VERSION ); ?></dd></div>
				<div><dt>Site Timezone</dt><dd><?php echo esc_html( wp_timezone_string() ); ?></dd></div>
				<div><dt>Web Server</dt><dd><?php echo esc_html( explode( ' ', sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ?? 'Apache' ) ) )[0] ); ?></dd></div>
			</dl>
		</section>

		<!-- 2. Security Settings -->
		<section class="card qs-card qs-set-card" id="qs-set-security">
			<div class="card-head">
				<span class="tile t-green"><svg class="i"><use href="#i-shield-check" /></svg></span>
				<div class="ttl">
					<h2>Security Settings</h2>
					<p>Configure global protection preferences.</p>
				</div>
			</div>
			<div class="divide"><div class="set-row"><div class="txt"><b id="l-notice">Show admin notices for critical findings</b><small>Show saved scan warnings elsewhere in WordPress.</small></div><div class="switch-set ctl auto"><button type="button" class="switch" role="switch" data-key="notice" aria-checked="false" aria-labelledby="l-notice"></button></div></div><div class="set-row"><div class="txt"><b id="l-geo_enabled">Public IP country lookup</b><small>Resolve recorded public IPs with ipwho.is. This sends those IPs to the provider.</small></div><div class="switch-set ctl auto"><button type="button" class="switch" role="switch" data-key="geo_enabled" aria-checked="false" aria-labelledby="l-geo_enabled"></button></div></div>
				<div class="set-row">
					<div class="txt">
						<b id="l-status">Plugin protection status</b>
						<small>Enable or disable Security Suite Pro enforcement.</small>
					</div>
					<div class="switch-set ctl auto">
						<button class="switch" role="switch" data-key="status" aria-checked="true" aria-labelledby="l-status"></button>
						<span class="pill switch-pill p-green">Enabled</span>
					</div>
				</div>
				<div class="set-row">
					<div class="txt">
						<b id="l-proxy">Allow IP detection via proxy</b>
						<small>Accept X-Forwarded-For headers from trusted reverse proxies.</small>
					</div>
					<div class="switch-set ctl auto">
						<button class="switch" role="switch" data-key="proxy" aria-checked="false" aria-labelledby="l-proxy"></button>
						<span class="pill switch-pill p-gray">Disabled</span>
					</div>
				</div>
				<div class="set-row">
					<div class="txt">
						<b>Admin IP Allowlist Bypass</b>
						<small>Configure visitor allowlists that bypass firewall rules.</small>
					</div>
					<a class="btn btn-outline btn-sm ctl auto" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro-login#qs-trusted-ips' ) ); ?>">Manage IPs</a>
				</div>
			</div>
		
<?php GWQSH_Enterprise_UI::render( 'reputation' ); ?>
</section>

		<!-- 3. Plugin Information -->
		<section class="card qs-card qs-set-card" id="qs-set-plugin-info">
			<div class="card-head">
				<span class="tile t-purple"><svg class="i"><use href="#i-crown" /></svg></span>
				<div class="ttl">
					<h2>Plugin Information</h2>
					<p>Version, license status, and system health.</p>
				</div>
			</div>
			<dl class="info-list qs-info-table">
				<div><dt>Plugin Version</dt><dd>v<?php echo esc_html( GWQSH_VERSION ); ?> (Pro)</dd></div>
				<div><dt>License Status</dt><dd><span class="qs-badge"><?php echo esc_html( ucfirst( GWQSH_License::status()['state'] ) ); ?></span></dd></div>
				<div><dt>Last Updated</dt><dd><?php echo esc_html( wp_date( 'M j, Y', filemtime( GWQSH_PLUGIN_FILE ) ) ); ?></dd></div>
				<div>
					<dt>Total Scans Run</dt>
					<dd>
					<?php
					global $wpdb;
					// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
					echo esc_html( number_format_i18n( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}gwqsh_scan_history" ) ) );
					?>
					</dd>
				</div>
				<div>
					<dt>Security Score</dt>
					<dd><a href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro' ) ); ?>" class="score-link"><i class="dot c-green"></i><?php echo esc_html( GWQSH_Admin::score_from_components( GWQSH_Admin::get_score_components() ) ); ?> / 100</a></dd>
				</div>
			</dl>
		
<?php GWQSH_Enterprise_UI::render( 'license' ); ?>
</section>

		<!-- 4. Dashboard & UI Settings -->
		<section class="card qs-card qs-set-card" id="qs-set-dashboard-ui">
			<div class="card-head">
				<span class="tile t-blue"><svg class="i"><use href="#i-gear" /></svg></span>
				<div class="ttl">
					<h2>Dashboard &amp; UI Settings</h2>
					<p>Customize the visual interface and preferences.</p>
				</div>
			</div>
			<div class="divide">
				<div class="set-row wrap-sm">
					<label class="txt" for="theme">
						<b>Admin page color scheme</b>
						<small>Choose your preferred interface theme.</small>
					</label>
					<div class="ctl wide">
						<select class="field field-sm qs-select" id="theme" data-key="theme">
							<option value="light" selected>Light (Default)</option>
							<option value="dark">Dark Mode</option>
							<option value="system">Match System</option>
						</select>
					</div>
				</div>
				<div class="set-row">
					<div class="txt">
						<b id="l-compact">Use compact density</b>
						<small>Tighter card spacing and smaller table padding.</small>
					</div>
					<div class="switch-set ctl auto">
						<button class="switch" role="switch" data-key="compact" aria-checked="false" aria-labelledby="l-compact"></button>
						<span class="pill switch-pill p-gray">Disabled</span>
					</div>
				</div>
				<div class="set-row">
					<div class="txt">
						<b id="l-anim">Animated charts &amp; radar</b>
						<small>Enable smooth data visualizations.</small>
					</div>
					<div class="switch-set ctl auto">
						<button class="switch" role="switch" data-key="anim" aria-checked="true" aria-labelledby="l-anim"></button>
						<span class="pill switch-pill p-green">Enabled</span>
					</div>
				</div>
				<div class="set-row">
					<div class="txt">
						<b id="l-tips">Display security recommendations</b>
						<small>Show contextual advice cards across views.</small>
					</div>
					<div class="switch-set ctl auto">
						<button class="switch" role="switch" data-key="tips" aria-checked="true" aria-labelledby="l-tips"></button>
						<span class="pill switch-pill p-green">Enabled</span>
					</div>
				</div>
			</div>
		</section>

		<!-- 5. Email Notifications -->
		<section class="card qs-card qs-set-card" id="qs-set-email-notifications">
			<div class="card-head">
				<span class="tile t-amber"><svg class="i"><use href="#i-bell" /></svg></span>
				<div class="ttl">
					<h2>Email Notifications</h2>
					<p>Alert delivery and administrator recipient.</p>
				</div>
			</div>
<dl class="qs-info-table"><div><dt>Recipient</dt><dd><?php echo esc_html( get_option( 'admin_email' ) ); ?></dd></div><div><dt>Login lockout alerts</dt><dd><?php echo GWQSH_Login_Protection::get_settings()['email_lockout'] ? 'Enabled' : 'Disabled'; ?></dd></div><div><dt>Delivery</dt><dd>Immediate, via WordPress mail</dd></div></dl><p class="qs-settings-note">Email alerts follow the saved Login Protection policy. Delivery depends on the site's mail configuration.</p><a class="btn btn-outline btn-sm" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro-login#qs-login-settings' ) ); ?>">Manage email alerts &rarr;</a>
		
<?php GWQSH_Enterprise_UI::render( 'alerts' ); ?>
</section>

		<!-- 6. Notification Types -->
		<section class="card qs-card qs-set-card" id="qs-set-notification-types">
			<div class="card-head">
				<span class="tile t-purple"><svg class="i"><use href="#i-list" /></svg></span>
				<div class="ttl">
					<h2>Notification Types</h2>
					<p>Select which event categories trigger alerts.</p>
				</div>
			</div>
<dl class="qs-info-table"><div><dt>Brute-force lockouts</dt><dd>Email, when enabled</dd></div><div><dt>File changes &amp; suspicious code</dt><dd>Activity Log &amp; scan findings</dd></div><div><dt>Critical finding notices</dt><dd>Controlled in Security Settings</dd></div></dl><p class="qs-settings-note">Email digests and separate file-change email subscriptions are unavailable in this version.</p><a class="btn btn-outline btn-sm" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro-activity-log' ) ); ?>">View recorded events &rarr;</a>
		
<?php GWQSH_Enterprise_UI::render( 'shipping' ); ?>
</section>

		<!-- 7. Data & Retention -->
		<section class="card qs-card qs-set-card" id="qs-set-retention">
			<div class="card-head">
				<span class="tile t-blue"><svg class="i"><use href="#i-file" /></svg></span>
				<div class="ttl">
					<h2>Data &amp; Retention</h2>
					<p>Activity logs and database storage policies.</p>
				</div>
			</div>
			<div class="divide">
				<div class="set-row wrap-sm">
					<label class="txt" for="retention">
						<b>Activity log retention period</b>
						<small>Automatically prune older activity event records.</small>
					</label>
					<div class="ctl wide">
						<select class="field field-sm qs-select" id="retention" data-key="retention">
							<option value="7">7 days</option>
							<option value="30" selected>30 days</option>
							<option value="90">90 days</option>
							<option value="365">1 year</option>
						</select>
					</div>
				</div>
				<div class="set-row">
					<div class="txt">
						<b id="l-uninstall">Delete data on uninstall</b>
						<small>Permanently drop tables and options when plugin is deleted.</small>
					</div>
					<div class="switch-set ctl auto">
						<button class="switch" role="switch" data-key="uninstall" aria-checked="false" aria-labelledby="l-uninstall"></button>
						<span class="pill switch-pill p-gray">Disabled</span>
					</div>
				</div>
			</div>
		
<?php GWQSH_Enterprise_UI::render( 'privacy' ); ?>
</section>

		<!-- 8. Import & Export -->
		<section class="card qs-card qs-set-card" id="qs-set-import-export">
			<div class="card-head">
				<span class="tile t-green"><svg class="i"><use href="#i-refresh" /></svg></span>
				<div class="ttl">
					<h2>Import &amp; Export</h2>
					<p>Backup or transfer plugin configuration.</p>
				</div>
			</div>
			<div class="divide">
				<div class="set-row">
					<div class="txt">
						<b>Configuration portability</b>
						<small>Export all active rules to JSON or import into another WordPress site.</small>
					</div>
					<div class="ctl gwqsh-config-actions">
						<button class="btn btn-primary btn-sm" type="button" id="exportS">Export JSON</button>
						<button class="btn btn-outline btn-sm" type="button" id="importS">Import JSON</button>
						<input type="file" id="importFile" accept="application/json,.json" hidden>
					</div>
				</div>
			</div>
		</section>

		<!-- 9. Reset & Tools -->
		<section class="card qs-card qs-set-card" id="qs-set-tools">
			<div class="card-head">
				<span class="tile t-amber"><svg class="i"><use href="#i-gear" /></svg></span>
				<div class="ttl">
					<h2>Reset &amp; Tools</h2>
					<p>Maintenance utilities and database cleanup.</p>
				</div>
			</div>
			<div class="divide">
				<div class="set-row">
					<div class="txt">
						<b>Run file integrity scan</b>
						<small>Trigger an immediate check against the core checksum baseline.</small>
					</div>
					<button class="btn btn-outline btn-sm" id="rebuild" type="button">Scan Now</button>
				</div>
				<div class="set-row">
					<div class="txt">
						<b>Clear activity logs</b>
						<small>Purge all stored security events and denial history.</small>
					</div>
					<button class="btn btn-danger btn-sm" id="clearLogs" type="button">Clear Logs</button>
				</div>
				<div class="set-row">
					<div class="txt">
						<b>Reset plugin defaults</b>
						<small>Restore default configuration values safely.</small>
					</div>
					<button class="btn btn-outline btn-sm" id="resetS" type="button">Reset Defaults</button>
				</div>
			</div>
		
<?php GWQSH_Enterprise_UI::render( 'signatures' ); ?>
<?php GWQSH_Enterprise_UI::render( 'advisories' ); ?>
<?php GWQSH_Enterprise_UI::wizard(); ?>
</section>

		<!-- 10. Security Tips -->
		<section class="card qs-card qs-set-card" id="qs-set-tips">
			<div class="card-head">
				<span class="tile t-blue"><svg class="i"><use href="#i-help" /></svg></span>
				<div class="ttl">
					<h2>Security Tips</h2>
					<p>Recommended best practices for WordPress hardening.</p>
				</div>
			</div>
			<div class="qs-tips-list">
				<div class="qs-tip-item">
					<span class="qs-tip-bullet">1</span>
					<div>
						<b>Enforce Two-Factor Authentication</b>
						<p>Require 2FA for all administrator and editor roles to stop credential stuffing.</p>
					</div>
				</div>
				<div class="qs-tip-item">
					<span class="qs-tip-bullet">2</span>
					<div>
						<b>Keep Automated Scans Scheduled</b>
						<p>Enable scheduled integrity scans to detect core or plugin modifications quickly.</p>
					</div>
				</div>
				<div class="qs-tip-item">
					<span class="qs-tip-bullet">3</span>
					<div>
						<b>Disable XML-RPC If Not Used</b>
						<p>Denying XML-RPC stops high-volume brute-force attempts on wp-login endpoints.</p>
					</div>
				</div>
				<div class="qs-tip-item">
					<span class="qs-tip-bullet">4</span>
					<div>
						<b>Maintain Regular Offsite Backups</b>
						<p>Ensure regular database and file backups are archived before major updates.</p>
					</div>
				</div>
			</div>
		</section>

		<?php GWQSH_Security_Doctor::render(); ?>
	</div>
</div>
</main>
