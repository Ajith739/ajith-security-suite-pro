<?php
/**
 * Pro Two-Factor identity protection.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
$gwqsh_view_d        = GWQSH_Admin::get_page_initial_data( 'two-factor' );
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
$gwqsh_view_settings = $gwqsh_view_d['settings'];
$gwqsh_view_section  = static function ( $gwqsh_view_title, $gwqsh_view_symbol, $gwqsh_view_subtitle = '' ) use ( $gwqsh_view_icon ) {
	echo '<div class="qs-card-head"><span class="qs-tile">' . $gwqsh_view_icon( $gwqsh_view_symbol ) . '</span><div><h2>' . esc_html( $gwqsh_view_title ) . '</h2>' . ( $gwqsh_view_subtitle ? '<p>' . esc_html( $gwqsh_view_subtitle ) . '</p>' : '' ) . '</div></div>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaped helper markup.
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

<svg width="0" height="0" aria-hidden="true" class="qs-tf-sprite"><symbol id="i-tf-phone" viewBox="0 0 24 24"><rect x="6" y="2" width="12" height="20" rx="2"/><path d="M11 18h2"/></symbol><symbol id="i-tf-key" viewBox="0 0 24 24"><circle cx="8" cy="15" r="5"/><path d="m12 11 9-9m-5 5 3 3m-1-5 3 3"/></symbol><symbol id="i-tf-copy" viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/></symbol><symbol id="i-tf-device" viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/></symbol><symbol id="i-tf-clock" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 6v6l4 2"/></symbol><symbol id="i-tf-download" viewBox="0 0 24 24"><path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/></symbol></svg>

<main id="main">
<section class="hero" aria-labelledby="heroTitle">
	<canvas class="hero-birds" id="heroBirds" aria-hidden="true"></canvas>
	<div class="wrap hero-in">
	<div class="hero-content">
		<p class="eyebrow">Identity Protection</p>
		<h1 class="h1" id="heroTitle">Two-Factor <span class="hl">Authentication</span></h1>
		<p class="lede">Stronger WordPress login security with app-based verification, passkeys, trusted devices, and recovery options.</p>
	</div>
	</div>
	<div class="wrap qs-tf-hero-metrics-wrap">
		<section class="qs-overview qs-tf-overview" aria-labelledby="qs-tf-overview-title">
			<div class="qs-metrics qs-tf-metrics">
			<?php
			$gwqsh_active_methods = array( 'TOTP', 'Backup Codes' );
			if ( ! empty( $gwqsh_view_d['recovery']['passkeys'] ) || ! empty( $gwqsh_view_settings['enable_passkeys'] ) ) {
				$gwqsh_active_methods[] = 'Passkey';
			}
			if ( ! empty( $gwqsh_view_d['recovery']['email'] ) || ! empty( $gwqsh_view_settings['enable_email'] ) ) {
				$gwqsh_active_methods[] = 'Email';
			}
			if ( ! empty( $gwqsh_view_d['recovery']['sms'] ) || ! empty( $gwqsh_view_settings['enable_sms'] ) ) {
				$gwqsh_active_methods[] = 'SMS';
			}
			$gwqsh_view_metrics   = array(
				array( 'users', '2FA Coverage', $gwqsh_view_d['counts']['enabled'] . ' / ' . $gwqsh_view_d['counts']['total'] . ' users', $gwqsh_view_d['percent'] . '%', 'Users with 2FA enabled', 'coverage', 'blue' ),
				array( 'gear', 'Active Methods', implode( ', ', $gwqsh_active_methods ), '', count( $gwqsh_active_methods ) . ' of 5 methods supported', 'methods', 'purple' ),
				array( 'tf-phone', 'Trusted Devices', $gwqsh_view_d['counts']['devices'] . ' devices', $gwqsh_view_settings['remember_device'] ? 'Active' : 'Off', 'Remembered across users', 'trusted', 'cyan' ),
				array( 'shield-check', 'Recovery Ready', $gwqsh_view_d['backup_remaining'] . ' backup codes', $gwqsh_view_d['backup_remaining'] ? 'Ready' : 'Set up', 'Your unused recovery codes', 'recovery', 'green' ),
				array( 'tf-clock', 'Last Verification', $gwqsh_view_d['last_label'], '', $gwqsh_view_d['last_date'], 'verification', 'yellow' ),
			);
			foreach ( $gwqsh_view_metrics as $gwqsh_view_metric ) :
				$gwqsh_view_has_badge = ! empty( $gwqsh_view_metric[3] );
				?>
				<div class="qs-metric qs-metric-<?php echo esc_attr( $gwqsh_view_metric[6] ); ?>" data-tf-metric="<?php echo esc_attr( $gwqsh_view_metric[5] ); ?>" style="background:#ffffff;border:1px solid rgba(226,232,240,0.9);border-radius:12px;box-shadow:0 1px 3px rgba(15,23,42,0.04),0 2px 6px rgba(15,23,42,0.02);padding:12px 14px;box-sizing:border-box;display:flex;align-items:center;gap:12px;">
					<div class="qs-stack-icon qs-metric-icon-wrap" style="width:38px;height:38px;min-width:38px;min-height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;flex-shrink:0;">
						<span class="qs-stack-circle" aria-hidden="true" style="width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;">
							<?php echo $gwqsh_view_icon( $gwqsh_view_metric[0] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
						</span>
					</div>
					<div class="qs-metric-body" style="display:flex;flex-direction:column;justify-content:center;min-width:0;flex:1;gap:3px;">
						<strong class="qs-metric-value" style="font-size:14px;font-weight:700;color:#0f172a;line-height:1.2;display:block;"><?php echo esc_html( $gwqsh_view_metric[2] ); ?></strong>
						<div class="qs-metric-title-row" style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;line-height:1.2;">
							<span class="qs-metric-title" style="font-size:13px;font-weight:600;color:#334155;line-height:1.2;"><?php echo esc_html( $gwqsh_view_metric[1] ); ?></span>
							<span class="qs-badge <?php echo in_array( strtolower( $gwqsh_view_metric[3] ), array( 'off', 'disabled' ), true ) ? 'qs-badge-off' : 'qs-badge-good'; ?>" <?php echo $gwqsh_view_has_badge ? '' : 'hidden'; ?> style="font-size:11px;padding:2px 7px;border-radius:999px;"><?php echo esc_html( $gwqsh_view_metric[3] ); ?></span>
						</div>
						<p class="qs-metric-desc" style="font-size:11.5px;color:#64748b;margin:0;line-height:1.25;"><?php echo esc_html( $gwqsh_view_metric[4] ); ?></p>
					</div>
				</div>
			<?php endforeach; ?>
			</div>
		</section>
	</div>
</section>

<div class="qs-pro-dashboard qs-pro-two-factor">
<div class="qs-content qs-tf-content">
<div id="qs-tf-feedback" role="status" aria-live="polite"></div>

<div class="qs-tf-dashboard-grid qs-tf-three-columns">
	<!-- MAIN LEFT AREA: Col 1 & Col 2 on top, Users Table below -->
	<div class="qs-tf-main-area">
		<div class="qs-tf-top-cols">
			<!-- LEFT COLUMN: Authenticator Setup & Backup Codes -->
			<div class="qs-tf-column qs-tf-col-left">
				<section class="qs-card qs-tf-setup" id="qs-tf-setup">
					<?php $gwqsh_view_section( 'Authenticator Setup', 'users', 'Scan the QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.)' ); ?>
					<button class="qs-tf-heading-action qs-tf-link" type="button" id="qs-tf-help"><?php echo $gwqsh_view_icon( 'book' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Help Guide</button>
					<div class="qs-tf-setup-grid">
						<div class="qs-tf-qr-column">
							<div id="qs-tf-qr" class="qs-tf-qr" role="img" aria-label="Your authenticator enrollment QR code">Preparing your authenticator…</div>
							<button class="qs-tf-link" type="button" id="qs-tf-regenerate"><?php echo $gwqsh_view_icon( 'refresh' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Regenerate QR Code</button>
						</div>
						<form id="qs-tf-enroll" class="qs-tf-enroll">
							<label for="qs-tf-secret">Or enter the key manually</label>
							<div class="qs-tf-keybox">
								<code id="qs-tf-secret"></code>
								<button class="qs-tf-copy" type="button" id="qs-tf-copy-secret" aria-label="Copy your authenticator setup key"><?php echo $gwqsh_view_icon( 'tf-copy' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></button>
							</div>
							<label class="qs-tf-code-label" for="qs-tf-code">Authentication code</label>
							<input id="qs-tf-code" class="qs-tf-input" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="Enter 6-digit code" required>
							<button class="qs-button qs-primary" type="submit" id="qs-tf-verify">Verify Replacement <?php echo $gwqsh_view_icon( 'arrow' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></button>
							<p id="qs-tf-setup-status" aria-live="polite">Your current authenticator remains active until this replacement is verified.</p>
							<button class="qs-tf-link qs-tf-disable" id="qs-tf-disable" type="button" hidden>Disable your 2FA</button>
						</form>
					</div>
				</section>

				<section class="qs-card qs-tf-backup" id="qs-tf-backup">
					<?php $gwqsh_view_section( 'Backup Codes', 'tf-key', "Use these one-time codes if you can't access your authenticator app." ); ?>
					<button class="qs-small-button qs-tf-heading-action" id="qs-tf-backup-regenerate" type="button"><?php echo $gwqsh_view_icon( 'refresh' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Regenerate Codes</button>
					<ul id="qs-tf-codes" class="qs-tf-codes" aria-label="Your unused backup codes"></ul>
					<p id="qs-tf-backup-empty" class="qs-tf-empty"></p>
					<div class="qs-tf-backup-footer">
						<div class="qs-tf-warning">
							<?php echo $gwqsh_view_icon( 'alert' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
							<div>
								<b>Keep these codes in a secure place.</b>
								<p>Each code can only be used once. Store them safely in a password manager or offline location.</p>
							</div>
						</div>
						<div class="qs-tf-backup-actions">
							<button class="qs-small-button" id="qs-tf-copy-all" type="button"><?php echo $gwqsh_view_icon( 'tf-copy' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Copy All</button>
							<button class="qs-small-button" id="qs-tf-download" type="button"><?php echo $gwqsh_view_icon( 'tf-download' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Download .txt</button>
						</div>
					</div>
				</section>
			</div>

			<!-- CENTER COLUMN: Your Verification Methods & Enabled Methods -->
			<div class="qs-tf-column qs-tf-col-center">
				<section class="qs-card qs-tf-your-methods" id="gwqsh-factor-status">
					<div class="qs-card-head">
						<span class="qs-tile qs-tile-blue"><?php echo $gwqsh_view_icon( 'list' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
						<div>
							<h2>Your verification methods</h2>
						</div>
						<button class="qs-tf-heading-action qs-tf-link" id="qs-tf-manage-methods" type="button">Manage Methods →</button>
					</div>
					<div class="gwqsh-methods">
						<div class="qs-method-card">
							<div class="qs-method-head">
								<span class="qs-method-icon qs-method-icon-green"><?php echo $gwqsh_view_icon( 'tf-phone' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
								<span class="qs-badge <?php echo $gwqsh_view_d['effective_enabled'] ? 'qs-good' : 'qs-warning'; ?>"><?php echo $gwqsh_view_d['effective_enabled'] ? 'Enabled' : 'Set up'; ?></span>
							</div>
							<b>TOTP</b>
							<button class="qs-button qs-btn-outline sm" type="button" data-open-method="app">Manage</button>
						</div>
						<div class="qs-method-card">
							<div class="qs-method-head">
								<span class="qs-method-icon qs-method-icon-purple"><?php echo $gwqsh_view_icon( 'users' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
								<span class="qs-badge <?php echo ! empty( $gwqsh_view_d['recovery']['passkeys'] ) ? 'qs-good' : ''; ?>"><?php echo ! empty( $gwqsh_view_d['recovery']['passkeys'] ) ? 'Enabled' : 'Not enabled'; ?></span>
							</div>
							<b>Passkey</b>
							<button class="qs-button qs-btn-outline sm" type="button" data-open-method="passkeys">Manage</button>
						</div>
						<div class="qs-method-card">
							<div class="qs-method-head">
								<span class="qs-method-icon qs-method-icon-blue"><?php echo $gwqsh_view_icon( 'mail' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
								<span class="qs-badge <?php echo ! empty( $gwqsh_view_d['recovery']['email'] ) ? 'qs-good' : ''; ?>"><?php echo ! empty( $gwqsh_view_d['recovery']['email'] ) ? 'Enabled' : 'Not enabled'; ?></span>
							</div>
							<b>Email backup</b>
							<button class="qs-button qs-btn-outline sm" type="button" data-open-method="email">Manage</button>
						</div>
						<div class="qs-method-card">
							<div class="qs-method-head">
								<span class="qs-method-icon qs-method-icon-indigo"><?php echo $gwqsh_view_icon( 'tf-device' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
								<span class="qs-badge <?php echo ! empty( $gwqsh_view_d['recovery']['sms'] ) ? 'qs-good' : ''; ?>"><?php echo ! empty( $gwqsh_view_d['recovery']['sms'] ) ? 'Enabled' : 'Not enabled'; ?></span>
							</div>
							<b>SMS backup</b>
							<button class="qs-button qs-btn-outline sm" type="button" data-open-method="sms">Manage</button>
						</div>
					</div>

					<div class="qs-tf-sub-section">
						<div class="qs-tf-sub-head">
							<span class="qs-tile-sm"><?php echo $gwqsh_view_icon( 'list' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
							<h3>Enabled Methods</h3>
						</div>
						<div id="qs-tf-method-rows"></div>
					</div>
				</section>
			</div>
		</div>

		<!-- BOTTOM OF MAIN AREA: Users & 2FA Status -->
		<div class="qs-tf-bottom-full">
			<section class="qs-card qs-tf-users" id="qs-tf-users">
				<?php $gwqsh_view_section( $gwqsh_view_d['can_manage'] ? 'Users & 2FA Status' : 'Your 2FA Status', 'users', $gwqsh_view_d['can_manage'] ? 'Manage two-factor authentication for all users on your site.' : 'Manage your authenticator and recovery options.' ); ?>
				<div class="qs-tf-user-filters">
					<label class="screen-reader-text" for="qs-tf-user-search">Search users</label>
					<input id="qs-tf-user-search" class="qs-tf-input" type="search" placeholder="Search users…">
					<label class="screen-reader-text" for="qs-tf-user-role">Filter by role</label>
					<select class="qs-select" id="qs-tf-user-role">
						<option value="">All Roles</option>
						<?php foreach ( $gwqsh_view_d['roles'] as $gwqsh_view_key => $gwqsh_view_role_label ) : ?>
							<option value="<?php echo esc_attr( $gwqsh_view_key ); ?>"><?php echo esc_html( $gwqsh_view_role_label ); ?></option>
						<?php endforeach; ?>
					</select>
					<label class="screen-reader-text" for="qs-tf-user-status">Filter by 2FA status</label>
					<select class="qs-select" id="qs-tf-user-status">
						<option value="">All Status</option>
						<option>Enabled</option>
						<option>Pending</option>
						<option>Disabled</option>
					</select>
				</div>
				<div class="qs-tf-table-scroll" tabindex="0" role="region" aria-label="Two-factor users table">
					<table class="qs-tf-table">
						<thead>
							<tr>
								<th scope="col">User</th>
								<th scope="col">Role</th>
								<th scope="col">2FA Status</th>
								<th scope="col">Method</th>
								<th scope="col">Last Activity</th>
								<th scope="col">Recovery</th>
								<th scope="col">Actions</th>
							</tr>
						</thead>
						<tbody id="qs-tf-user-rows"></tbody>
					</table>
				</div>
				<div class="qs-tf-pagination">
					<span id="qs-tf-user-count" aria-live="polite"></span>
					<button class="qs-small-button" id="qs-tf-user-prev" type="button">← Previous</button>
					<button class="qs-small-button" id="qs-tf-user-next" type="button">Next →</button>
				</div>
			</section>
		</div>
	</div>

	<!-- RIGHT SIDEBAR: Policy & Enforcement, Passkeys & Trusted Devices, Security Guidance -->
	<aside class="qs-tf-column qs-tf-col-right">
		<section class="qs-card qs-tf-policy" id="qs-tf-policy">
			<?php $gwqsh_view_section( 'Policy & Enforcement', 'shield-check' ); ?>
			<?php
			$gwqsh_view_policies = array(
				array( 'require_admin', 'Require 2FA for administrators', 'Force 2FA for all admin users.', 'tf-phone' ),
				array( 'staff', 'Require 2FA for editors & shop managers', 'Apply to editors, authors and shop managers.', 'users' ),
				array( 'remember_device', 'Remember trusted device (30 days)', 'Reduce friction on trusted devices.', 'tf-phone' ),
				array( 'allow_admin_reset', 'Allow admin reset for users', 'Administrators can reset 2FA for users.', 'users' ),
				array( 'enforce_roles', 'Per-role enforcement', 'Configure 2FA requirements by user role.', 'tf-phone' ),
			);
			foreach ( $gwqsh_view_policies as $gwqsh_view_policy ) :
				?>
			<label class="qs-tf-policy-row"><span class="qs-tf-row-icon"><?php echo $gwqsh_view_icon( $gwqsh_view_policy[3] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span><span><b><?php echo esc_html( $gwqsh_view_policy[1] ); ?></b><small><?php echo esc_html( $gwqsh_view_policy[2] ); ?></small></span><span class="qs-tf-switch"><input type="checkbox" data-policy="<?php echo esc_attr( $gwqsh_view_policy[0] ); ?>" <?php disabled( ! $gwqsh_view_d['can_manage'] ); ?> aria-label="<?php echo esc_attr( $gwqsh_view_policy[1] ); ?>"><span aria-hidden="true"></span></span></label>
			<?php endforeach; ?>
			<button class="qs-small-button qs-tf-role-button" id="qs-tf-roles" type="button" <?php disabled( ! $gwqsh_view_d['can_manage'] ); ?>><?php echo $gwqsh_view_icon( 'gear' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Manage Role Settings →</button>
			<?php if ( ! $gwqsh_view_d['can_manage'] ) : ?>
				<p class="qs-tf-policy-note">Your administrator manages these site policies.</p>
			<?php endif; ?>
		</section>

		<section class="qs-card qs-tf-devices" id="qs-tf-devices">
			<?php $gwqsh_view_section( 'Passkeys & Trusted Devices', 'tf-phone' ); ?>
			<div class="qs-tf-tabs" role="tablist" aria-label="Your registered devices">
				<button id="qs-tf-passkey-tab" type="button" role="tab" aria-selected="true" aria-controls="qs-tf-device-list" data-device-tab="passkeys">Passkeys (0)</button>
				<button id="qs-tf-trusted-tab" type="button" role="tab" aria-selected="false" aria-controls="qs-tf-device-list" data-device-tab="trusted" tabindex="-1">Trusted Devices (<?php echo count( $gwqsh_view_d['devices'] ); ?>)</button>
			</div>
			<div id="qs-tf-device-list" role="tabpanel" aria-labelledby="qs-tf-passkey-tab"></div>
			<div class="qs-tf-device-actions">
				<button class="qs-small-button qs-primary" id="qs-tf-add-passkey" type="button">+ Add Passkey</button>
				<button class="qs-small-button" id="qs-tf-all-devices" type="button"><?php echo $gwqsh_view_icon( 'gear' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Manage All Devices</button>
				<?php if ( current_user_can( GWQSH_Admin::management_capability() ) ) : ?>
				<button class="qs-small-button" id="qs-open-delivery-modal" type="button"><?php echo $gwqsh_view_icon( 'gear' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>Passkey &amp; Backup Delivery</button>
				<?php endif; ?>
			</div>
		</section>

		<section class="qs-card qs-tf-guidance" id="qs-tf-guidance">
			<?php $gwqsh_view_section( 'Security Guidance', 'help' ); ?>
			<?php foreach ( array( array( 'tf-key', 'Use an authenticator app', 'Google Authenticator, Authy, or 1Password add a second sign-in factor.' ), array( 'file', 'Store your backup codes safely', 'Keep them in a password manager or offline location.' ), array( 'shield-check', 'Passkeys for faster secure sign-in', 'Passkey registration is not configured in this version.' ), array( 'alert', 'Enforce 2FA for admins and staff', 'Require 2FA for administrators, editors, and shop managers.' ) ) as $gwqsh_view_tip ) : ?>
			<div class="qs-tf-guidance-row">
				<span class="qs-tf-row-icon"><?php echo $gwqsh_view_icon( $gwqsh_view_tip[0] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?></span>
				<div>
					<b><?php echo esc_html( $gwqsh_view_tip[1] ); ?></b>
					<p><?php echo esc_html( $gwqsh_view_tip[2] ); ?></p>
				</div>
			</div>
			<?php endforeach; ?>
			<blockquote>“Strong authentication today prevents tomorrow's breaches.”<small>— Security Suite Pro</small></blockquote>
		</section>

		<?php if ( current_user_can( GWQSH_Admin::management_capability() ) ) : ?>
		<template id="qs-tpl-delivery-settings">
			<form data-config-section="integrations" class="qs-integrations-form">
				<p style="margin:0 0 16px 0;font-size:13px;color:var(--muted,#64748b);">Configure passkey WebAuthn authentication and optional Twilio SMS backup delivery settings.</p>
				<div class="gwqsh-form-grid" style="display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;">
					<?php $gwqsh_integration_values = GWQSH_Customization::values( 'integrations' ); foreach ( GWQSH_Customization::schema()['integrations']['fields'] as $gwqsh_field => $gwqsh_spec ) : ?>
					<label style="display:flex;flex-direction:column;gap:5px;font-size:12px;font-weight:600;color:var(--navy,#0f1b4d);"><?php echo esc_html( $gwqsh_spec[0] ); ?>
					<?php if ( 'bool' === $gwqsh_spec[1] ) : ?>
						<select name="<?php echo esc_attr( $gwqsh_field ); ?>" data-field-type="bool" class="qs-select">
							<option value="0" <?php selected( empty( $gwqsh_integration_values[ $gwqsh_field ] ) ); ?>>Disabled</option>
							<option value="1" <?php selected( ! empty( $gwqsh_integration_values[ $gwqsh_field ] ) ); ?>>Enabled</option>
						</select>
					<?php else : ?>
						<input class="qs-login-input" type="<?php echo esc_attr( $gwqsh_spec[1] ); ?>" name="<?php echo esc_attr( $gwqsh_field ); ?>" value="<?php echo esc_attr( 'password' === $gwqsh_spec[1] ? '' : ( $gwqsh_integration_values[ $gwqsh_field ] ?? '' ) ); ?>" autocomplete="<?php echo 'password' === $gwqsh_spec[1] ? 'new-password' : 'off'; ?>" style="width:100%;box-sizing:border-box;">
					<?php endif; ?>
					</label>
					<?php endforeach; ?>
				</div>
				<div class="qs-integrations-actions" style="margin-top:20px;display:flex;justify-content:flex-end;gap:10px;">
					<button class="qs-button qs-primary" type="submit">Save delivery settings</button>
				</div>
			</form>
		</template>
		<?php endif; ?>
	</aside>
</div>

</div>
</main>
