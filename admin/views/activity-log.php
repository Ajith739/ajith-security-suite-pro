<?php
/** Activity Log Pro administration screen.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
if ( ! current_user_can( 'manage_options' ) ) {
	return;
}
$gwqsh_data  = GWQSH_Admin::get_page_initial_data( 'activity-log' );
$gwqsh_error = is_wp_error( $gwqsh_data ) ? $gwqsh_data->get_error_message() : '';
if ( $gwqsh_error ) {
	$gwqsh_data = array(
		'items'    => array(),
		'counts'   => array(),
		'previous' => array(),
	);
}
$gwqsh_current_u = wp_get_current_user();
$gwqsh_u_name    = ( $gwqsh_current_u && $gwqsh_current_u->exists() ) ? ( $gwqsh_current_u->display_name ? $gwqsh_current_u->display_name : $gwqsh_current_u->user_login ) : 'Admin';
$gwqsh_u_initial = strtoupper( substr( $gwqsh_u_name, 0, 1 ) );
$gwqsh_u_role    = ! empty( $gwqsh_current_u->roles[0] ) ? ucfirst( $gwqsh_current_u->roles[0] ) : 'Administrator';
$gwqsh_icon      = static function ( $gwqsh_view_name ) {

	return '<svg class="qs-icon" aria-hidden="true"><use href="#i-' . esc_attr( $gwqsh_view_name ) . '"/></svg>';
};
$gwqsh_url       = static function ( $gwqsh_view_page ) {

	$gwqsh_view_slugs = array(
		'dashboard'        => '',
		'login'            => '-login',
		'two-factor'       => '-two-factor',
		'file-integrity'   => '-file-integrity',
		'firewall-cleanup' => '-firewall-cleanup',
		'hardening'        => '-hardening',
		'activity-log'     => '-activity-log',
		'pro'              => '-pro',
		'settings'         => '-settings',
	);
	return admin_url( 'admin.php?page=gracewell-security-suite-pro' . $gwqsh_view_slugs[ $gwqsh_view_page ] );
};
$gwqsh_events    = array_slice( $gwqsh_data['items'], 0, 3 );
require GWQSH_PATH . 'admin/views/dashboard-icons.php';
?>
<a class="skip" href="#main">Skip to content</a>

<header class="topbar">
	<div class="topbar-in">
		<a class="brand" href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro' ) ); ?>" aria-label="Security Suite Pro home">
			<img class="logo-mark" src="<?php echo esc_url( GWQSH_URL . 'assets/img/quietshield.svg' ); ?>" alt="" width="40" height="44">
			<span class="brand-txt"><b><span>Security Suite Pro</span><svg class="i qs-title-crown" aria-hidden="true">
						<use href="#i-crown" />
					</svg></b><small>A Safer WordPress, A Quieter
					Tomorrow</small></span>
		</a>

		<?php require GWQSH_PATH . 'admin/views/navigation.php'; ?>



		<div class="top-actions">

			<div class="menu-wrap">
				<button class="icon-btn" data-menu="notif" type="button" aria-haspopup="true" aria-expanded="false"
					aria-label="Notifications">
					<svg class="i">
						<use href="#i-bell" />
					</svg><span class="dot-badge <?php echo empty( $gwqsh_events ) ? 'off' : ''; ?>" id="notifDot"><?php echo esc_html( count( $gwqsh_events ) ); ?></span>
				</button>
				<div class="menu menu-notif" id="menu-notif" role="menu">
					<div class="menu-head"><b>Notifications</b><button class="link-btn" id="markRead" type="button">Mark all as
							read</button></div>
					<?php
					if ( empty( $gwqsh_events ) ) :
						?>
						<div class="menu-item">No recent activity recorded.</div>
						<?php
					else :
						?>
						<?php
						foreach ( $gwqsh_events as $gwqsh_view_event ) :
							?>
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
				<p class="eyebrow">Security Activity Log</p>
				<h1 class="h1" id="heroTitle">Activity <span class="hl">Log</span></h1>
				<p class="lede">Keep track of important security events on your WordPress site. Monitor logins, changes, scans and other activities.</p>
			</div>
		</div>
	</section>

	<div class="qs-pro-dashboard qs-pro-activity">
		<div class="al-content">
			<section class="qs-overview al-overview" aria-labelledby="qs-al-overview-title">

				<div class="qs-metrics al-metrics">
					<?php
					$gwqsh_view_metrics = array(
						array( 'all', 'Total Events', 'list', 'blue', 'Last 30 days' ),
						array( 'Security', 'Security Events', 'shield-check', 'red', 'Logins, blocks and security actions' ),
						array( 'User', 'User Actions', 'users', 'cyan', 'Profiles and role changes' ),
						array( 'File', 'File Changes', 'file', 'purple', 'Scans, quarantine and restoration' ),
						array( 'System', 'System Events', 'gear', 'green', 'Plugin, theme and core updates' ),
					);
					foreach ( $gwqsh_view_metrics as $gwqsh_view_metric ) :
						$gwqsh_view_count = 'all' === $gwqsh_view_metric[0] ? array_sum( $gwqsh_data['counts'] ) : ( $gwqsh_data['counts'][ $gwqsh_view_metric[0] ] ?? 0 );
						?>
						<div class="qs-metric qs-metric-<?php echo esc_attr( $gwqsh_view_metric[3] ); ?>">
							<div class="qs-stack-icon">
								<span class="qs-stack-square" aria-hidden="true"></span>
								<span class="qs-stack-circle" aria-hidden="true">
									<?php
									echo $gwqsh_icon( $gwqsh_view_metric[2] ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
									?>
								</span>
							</div>
							<div class="qs-metric-body">
								<h4 class="qs-metric-heading">
									<strong><b data-metric="<?php echo esc_attr( $gwqsh_view_metric[0] ); ?>"><?php echo esc_html( number_format_i18n( $gwqsh_view_count ) ); ?></b></strong>
									<span class="qs-metric-title"><?php echo esc_html( $gwqsh_view_metric[1] ); ?></span>
									<span class="qs-badge qs-badge-good" data-trend="<?php echo esc_attr( $gwqsh_view_metric[0] ); ?>" hidden></span>
								</h4>
								<p class="qs-metric-desc"><?php echo esc_html( $gwqsh_view_metric[4] ); ?></p>
							</div>
						</div>
						<?php endforeach; ?>
				</div>
				<hr class="qs-overview-divider" />
			</section>
			<div class="al-grid">
				<div class="al-left">
					<section class="al-card al-overview">
						<div class="al-card-head"><span class="al-icon al-blue">
						<?php
						echo $gwqsh_icon( 'activity' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
						</span>
							<div>
								<h2>Activity Overview</h2>
								<p>Recorded events by site date.</p>
							</div><select id="chartRange" aria-label="Chart period">
								<option value="7">Last 7 days</option>
								<option value="30">Last 30 days</option>
								<option value="90">Last 90 days</option>
							</select>
						</div>
						<div class="al-chart-legend" id="chartLegend"></div>
						<div id="activityChart" class="al-chart"></div>
						<details class="al-chart-data">
							<summary>View chart data</summary>
							<div class="al-table-scroll" id="chartData"></div>
						</details>
					</section>
					<section class="al-card al-recent" id="log">
						<div class="al-card-head"><span class="al-icon al-blue">
						<?php
						echo $gwqsh_icon( 'list' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
						</span>
							<div>
								<h2>Recent Activity</h2>
								<p>Latest recorded events · <?php echo esc_html( wp_timezone_string() ); ?></p>
							</div><button class="al-button" type="button" data-export>↓ &nbsp; Export Logs</button>
						</div>
						<div class="al-status" id="alStatus" role="status" aria-live="polite"><?php echo esc_html( $gwqsh_error ); ?></div>
						<div class="al-table-scroll">
							<table class="al-table">
								<caption class="sr">Security activity records, newest first</caption>
								<thead>
									<tr>
										<th scope="col">Time</th>
										<th scope="col">Event</th>
										<th scope="col">User</th>
										<th scope="col">IP Address</th>
										<th scope="col">Details</th>
										<th scope="col">Type</th>
										<th scope="col">Actions</th>
									</tr>
								</thead>
								<tbody id="activityBody">
									<tr>
										<td colspan="7">Loading activity records…</td>
									</tr>
								</tbody>
							</table>
						</div>
						<div class="al-table-footer"><span id="activityInfo"></span>
							<nav id="activityPager" aria-label="Activity pages"></nav>
						</div>
					</section>
				</div>
				<aside class="al-right" aria-label="Activity controls">
					<section class="al-card al-types">
						<div class="al-card-head"><span class="al-icon al-blue">
						<?php
						echo $gwqsh_icon( 'shield-check' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
						</span>
							<div>
								<h2>Event Types</h2>
								<p>Last 30 days</p>
							</div>
						</div>
						<div class="al-type-body">
							<div class="al-ring">
								<div id="activityDonut"></div>
								<div class="al-ring-center"><b id="donutTotal">0</b><span>Events</span></div>
							</div>
							<ul id="donutLegend"></ul>
						</div>
					</section>
					<section class="al-card al-filters">
						<div class="al-card-head"><span class="al-icon al-blue">
						<?php
						echo $gwqsh_icon( 'search' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
						</span>
							<h2>Filter Logs</h2><button type="button" class="al-button al-reset" id="resetFilters">↻ Reset</button>
						</div>
						<form id="activityFilters"><label class="sr" for="logSearch">Search event, description, user or IP</label><input id="logSearch" name="search" type="search" maxlength="200" placeholder="Search logs…">
							<div class="al-filter-grid"><label class="sr" for="eventCategory">Event type</label><select name="category" id="eventCategory">
									<option value="">All Event Types</option>
									<option value="Login">Login Events</option>
									<?php
									foreach ( GWQSH_Activity_View_Data::GROUPS as $gwqsh_view_key => $gwqsh_view_label ) :
										?>
										<option value="<?php echo esc_attr( $gwqsh_view_key ); ?>"><?php echo esc_html( $gwqsh_view_label ); ?></option><?php endforeach; ?>
								</select><label class="sr" for="eventUser">User</label><select name="user" id="eventUser">
									<option value="">All Users</option>
								</select><label class="sr" for="eventIp">IP address (type or select)</label><input name="ip" id="eventIp" list="eventIps" placeholder="All IP Addresses" maxlength="45"><datalist id="eventIps"></datalist><label class="sr" for="eventSeverity">Severity</label><select name="severity" id="eventSeverity">
									<option value="">All Severities</option>
									<option value="unrecorded">Not recorded</option>
								</select><label class="sr" for="filterDays">Date period</label><select name="days" id="filterDays">
									<option value="1">Today</option>
									<option value="7">Last 7 Days</option>
									<option value="30" selected>Last 30 Days</option>
									<option value="90">Last 90 Days</option>
									<option value="365">Last 365 Days</option>
								</select><span class="al-date-help">Custom dates override period</span>
								<div class="al-date-range" style="display: flex; justify-content: flex-end; gap:10px;">
									<label class="al-date-label">Start date<input type="date" name="start" id="startDate" max="<?php echo esc_attr( current_datetime()->format( 'Y-m-d' ) ); ?>"></label>
									<label class="al-date-label">End date<input type="date" name="end" id="endDate" max="<?php echo esc_attr( current_datetime()->format( 'Y-m-d' ) ); ?>"></label>
								</div>
							</div><input name="event" id="similarEvent" type="hidden">
							<p id="similarLabel" hidden></p><button class="al-button al-primary" type="submit">Apply Filters &nbsp; →</button>
						</form>
					</section>
					<section class="al-card al-quick">
						<div class="al-card-head"><span class="al-icon al-blue">
						<?php
						echo $gwqsh_icon( 'gear' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
						</span>
							<h2>Quick Actions</h2>
						</div>
						<div class="al-quick-grid"><button type="button" class="al-button" data-export>▤ &nbsp; Export to CSV</button><button type="button" class="al-button" data-security-report>▤ &nbsp; Security Report</button><button type="button" class="al-button al-danger" id="clearOldLogs">▥ &nbsp; Clear Old Logs</button><button type="button" class="al-button al-purple-button" data-filter-category="Login">⇥ &nbsp; View Login Logs</button><button type="button" class="al-button al-orange-button" data-filter-category="File">▤ &nbsp; View File Changes</button></div>
					</section>
					<section class="al-card al-tips">
						<div class="al-card-head"><span class="al-icon al-green">
						<?php
						echo $gwqsh_icon( 'help' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
						</span>
							<h2>Security Tips</h2><a href="https://developer.wordpress.org/advanced-administration/security/hardening/" target="_blank" rel="noopener">View All →</a>
						</div><a class="al-tip" href="<?php echo esc_url( $gwqsh_url( 'login' ) ); ?>"><span class="al-icon al-red">
						<?php
						echo $gwqsh_icon( 'shield-check' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
						?>
																																</span><span><b>Review suspicious login attempts</b><small>Check for repeated failed login attempts.</small></span></a><a class="al-tip" href="<?php echo esc_url( $gwqsh_url( 'file-integrity' ) ); ?>"><span class="al-icon al-purple">
																																<?php
																																echo $gwqsh_icon( 'file' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
																																?>
																																																																																										</span><span><b>Monitor file changes regularly</b><small>Look for unexpected file modifications.</small></span></a><button class="al-tip" type="button" id="roleChanges"><span class="al-icon al-green">
																																																																																										<?php
																																																																																										echo $gwqsh_icon( 'users' ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
																																																																																										?>
																																																																																										</span><span><b>Keep an eye on user role changes</b><small>Review recorded user role updates.</small></span></button>
					</section>
				</aside>
			</div>
			<noscript>
				<p>Enable JavaScript to load, filter and export activity records.</p>
			</noscript>
		</div>
</main>
<form id="activityExport" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" hidden><input type="hidden" name="action" value="gwqsh_activity_export"><?php wp_nonce_field( 'gwqsh_activity_export' ); ?></form>
<div class="toasts" id="toasts" aria-live="polite"></div>
</div>

<form id="securityReportExport" method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" hidden><input type="hidden" name="action" value="gwqsh_security_report"><?php wp_nonce_field( 'gwqsh_security_report' ); ?></form>
