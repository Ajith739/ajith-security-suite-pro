<?php

/**
 * Pro security command center.
 *
 * @package GracewellSecuritySuitePro
 */

defined('ABSPATH') || exit;
$gwqsh_view_d               = GWQSH_Admin::get_page_initial_data('dashboard');
$gwqsh_view_user            = wp_get_current_user();
$gwqsh_u_name    = ($gwqsh_view_user && $gwqsh_view_user->exists()) ? ($gwqsh_view_user->display_name ? $gwqsh_view_user->display_name : $gwqsh_view_user->user_login) : 'Admin';
$gwqsh_u_initial = strtoupper(substr($gwqsh_u_name, 0, 1));
$gwqsh_u_role    = ! empty($gwqsh_view_user->roles[0]) ? ucfirst($gwqsh_view_user->roles[0]) : 'Administrator';
$gwqsh_view_icon            = static function ($gwqsh_view_name) {
	return '<svg class="qs-icon" aria-hidden="true"><use href="#i-' . esc_attr($gwqsh_view_name) . '"/></svg>';
};
$gwqsh_view_url             = static function ($gwqsh_view_page) {
	$gwqsh_view_slugs = array(
		'dashboard'        => '',
		'login'            => '-login',
		'login-protection' => '-login',
		'firewall-cleanup' => '-firewall-cleanup',
		'two-factor'       => '-two-factor',
		'file-integrity'   => '-file-integrity',
		'hardening'        => '-hardening',
		'activity-log'     => '-activity-log',
		'settings'         => '-settings',
	);
	return admin_url('admin.php?page=gracewell-security-suite-pro' . ($gwqsh_view_slugs[$gwqsh_view_page] ?? ''));
};
$gwqsh_view_head            = static function ($gwqsh_view_title, $gwqsh_view_symbol, $gwqsh_view_page = '', $gwqsh_view_action = 'View All', $gwqsh_view_extra = '') use ($gwqsh_view_icon, $gwqsh_view_url) {
	echo '<div class="qs-card-head"><span class="qs-tile">' . $gwqsh_view_icon($gwqsh_view_symbol) . '</span><h2>' . esc_html($gwqsh_view_title) . '</h2>' . $gwqsh_view_extra; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	if ($gwqsh_view_page) {
		echo '<a class="qs-small-button" href="' . esc_url($gwqsh_view_url($gwqsh_view_page)) . '">' . esc_html($gwqsh_view_action) . $gwqsh_view_icon('arrow') . '</a>';
	} // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
	echo '</div>';
};
$gwqsh_view_issues          = $gwqsh_view_d['scan_summary']['modified'] + $gwqsh_view_d['scan_summary']['missing'] + $gwqsh_view_d['scan_summary']['suspicious'];
$gwqsh_view_scanned         = ! empty($gwqsh_view_d['scan_summary']['last_date']);
$gwqsh_view_score           = $gwqsh_view_d['security_score'];
$gwqsh_view_score_status    = $gwqsh_view_score >= 85 ? 'Excellent' : ($gwqsh_view_score >= 70 ? 'Good' : 'Needs attention');
require GWQSH_PATH . 'admin/views/dashboard-icons.php';
?>
<a class="skip" href="#main">Skip to content</a>

<header class="topbar">
	<div class="topbar-in">
		<a class="brand" href="<?php echo esc_url(admin_url('admin.php?page=gracewell-security-suite-pro')); ?>" aria-label="Security Suite Pro home">
			<img class="logo-mark" src="<?php echo esc_url(GWQSH_URL . 'assets/img/quietshield.svg'); ?>" alt="" width="40" height="44">
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
					</svg><span class="dot-badge <?php echo empty($gwqsh_view_d['live_threats']) ? 'off' : ''; ?>" id="notifDot"><?php echo esc_html(count($gwqsh_view_d['live_threats'])); ?></span>
				</button>
				<div class="menu menu-notif" id="menu-notif" role="menu">
					<div class="menu-head"><b>Notifications</b><button class="link-btn" id="markRead" type="button">Mark all as
							read</button></div>
					<?php if (empty($gwqsh_view_d['live_threats'])) : ?>
						<div class="menu-item">No recent threats detected.</div>
					<?php else : ?>
						<?php foreach ($gwqsh_view_d['live_threats'] as $gwqsh_view_event) : ?>
							<div class="menu-item"><span><b><?php echo esc_html($gwqsh_view_event['event_name']); ?></b><small><?php echo esc_html($gwqsh_view_event['ip_address'] . (! empty($gwqsh_view_event['details']) ? ' · ' . $gwqsh_view_event['details'] : '')); ?></small></span></div>
						<?php endforeach; ?>
					<?php endif; ?>
				</div>
			</div>

			<div class="menu-wrap help-wrap">
				<button class="icon-btn" data-menu="help" type="button" aria-haspopup="true" aria-expanded="false"
					aria-label="Help"><svg class="i">
						<use href="#i-help" />
					</svg></button>
				<div class="menu" id="menu-help" role="menu"><button class="menu-item" role="menuitem" type="button" data-changelog>Changelog · Version <?php echo esc_html(GWQSH_VERSION); ?></button>
					<a role="menuitem" class="menu-item" href="https://developer.wordpress.org/advanced-administration/security/hardening/" target="_blank"
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
					aria-label="Account menu"><span class="avatar"><?php echo esc_html($gwqsh_u_initial); ?></span></button>
				<div class="menu" id="menu-user" role="menu">
					<div class="menu-head"><b><?php echo esc_html($gwqsh_u_name); ?></b><small><?php echo esc_html($gwqsh_u_role); ?></small></div>
					<a role="menuitem" class="menu-item" href="<?php echo esc_url(admin_url('admin.php?page=gracewell-security-suite-pro-settings')); ?>"><svg class="i">
							<use href="#i-gear" />
						</svg><span>Plugin settings</span></a>
					<button role="menuitem" class="menu-item" id="themeToggle" type="button"><svg class="i">
							<use href="#i-moon" />
						</svg><span id="themeLbl">Dark mode</span></button>
					<a role="menuitem" class="menu-item" href="<?php echo esc_url(wp_logout_url()); ?>"><svg class="i">
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
				<p class="eyebrow">SECURITY DASHBOARD</p>
				<h1 class="h1" id="heroTitle">Your WordPress site is <span class="hl">protected</span></h1>
				<p class="lede">Lightweight. Powerful security. No bloat.</p>
				<div class="hero-actions">
					<button class="btn btn-primary" id="runScanBtn" type="button"><span>Run New Scan</span> <svg class="i">
							<use href="#i-arrow" />
						</svg></button>
					<a class="btn btn-neutral" href="<?php echo esc_url($gwqsh_view_url('file-integrity')); ?>"><svg class="i">
							<use href="#i-report" />
						</svg><span>View Reports</span></a>
				</div>
				<p id="qs-scan-status" class="qs-scan-status" role="status" aria-live="polite"></p>
			</div>
			<div class="hero-pro-card">
				<div class="hero-pro-body">
					<span class="tile t-amber sm hero-pro-icon"><svg class="i fill">
							<use href="#i-crown" />
						</svg></span>
					<div class="hero-pro-info">
						<div class="hero-pro-head">
							<h3>Security Suite Pro</h3>
						</div>
						<p>Configure your protection, recovery methods and scheduled scans.</p>
					</div>
				</div>
				<a class="btn hero-pro-btn" href="<?php echo esc_url($gwqsh_view_url('settings')); ?>"><span>Configure Protection</span> <svg class="i">
						<use href="#i-arrow" />
					</svg></a>
			</div>
		</div>
	</section>

	<div class="qs-pro-dashboard">
		<div class="qs-content">
			<div class="qs-load-error" id="qs-load-error" role="alert"
				<?php
				if (! $gwqsh_view_d['data_error'] && ! $gwqsh_view_d['chart_data']['error']) {
					echo 'hidden';
				}
				?>>Unable to load security statistics. <button type="button" id="qs-retry">Retry</button></div>

			<section class="qs-overview" aria-labelledby="qs-overview-title">
				<div class="qs-metrics">
					<?php
					$gwqsh_view_metrics = array(
						array('shield-check', 'Threats Blocked', number_format_i18n($gwqsh_view_d['threats_blocked']), 'Retained lockouts and denials', '', 'red', 'blocked'),
						array('users', 'Protected Users', $gwqsh_view_d['users_2fa'] . ' / ' . $gwqsh_view_d['users_total'], '2FA enabled users', $gwqsh_view_d['users_total'] ? round($gwqsh_view_d['users_2fa'] / $gwqsh_view_d['users_total'] * 100) . '%' : 'No users', 'blue', 'users'),
						array('file', 'File Integrity', number_format_i18n($gwqsh_view_issues), $gwqsh_view_scanned ? 'Last scan: ' . explode(', ', $gwqsh_view_d['scan_summary']['last_date'])[0] . ', ' . explode(', ', $gwqsh_view_d['scan_summary']['last_date'])[1] : 'No scan completed yet', $gwqsh_view_issues ? 'Needs review' : ($gwqsh_view_scanned ? 'No issues' : 'Not scanned'), 'yellow', 'integrity'),
						array('shield-check', 'Active Shields', $gwqsh_view_d['active_shields'] . ' / ' . $gwqsh_view_d['shields_total'], 'Protection modules configured', $gwqsh_view_d['active_shields'] === $gwqsh_view_d['shields_total'] ? 'Active' : 'Review', 'green', 'shields'),
						array('calendar', 'Scheduled Scans', $gwqsh_view_d['schedule'], $gwqsh_view_d['next_scan'] ? 'Next scan in ' . $gwqsh_view_d['next_scan'] : 'Manual scans available', '', 'cyan', 'schedule'),
						array('bug', 'Malware Detections', number_format_i18n($gwqsh_view_d['scan_summary']['suspicious']), 'Suspicious files flagged by scanner', $gwqsh_view_d['scan_summary']['suspicious'] ? 'Review' : ($gwqsh_view_scanned ? 'No flags' : 'Not scanned'), 'red', 'malware'),
					);
					foreach ($gwqsh_view_metrics as $gwqsh_view_metric) :
						$gwqsh_view_color_tone = $gwqsh_view_metric[5];
						$gwqsh_view_has_badge  = ! empty($gwqsh_view_metric[4]);
						$gwqsh_view_is_warning = in_array($gwqsh_view_metric[6], array('integrity', 'malware'), true);
					?>
						<div class="qs-metric qs-metric-<?php echo esc_attr($gwqsh_view_color_tone); ?>" data-metric="<?php echo esc_attr($gwqsh_view_metric[6]); ?>">
							<div class="qs-stack-icon">
								<span class="qs-stack-square" aria-hidden="true"></span>
								<span class="qs-stack-circle" aria-hidden="true">
									<?php echo $gwqsh_view_icon($gwqsh_view_metric[0]); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
									?>
								</span>
							</div>
							<div class="qs-metric-body">
								<h4 class="qs-metric-heading">
									<strong><?php echo esc_html($gwqsh_view_metric[2]); ?></strong>
									<span class="qs-metric-title"><?php echo esc_html($gwqsh_view_metric[1]); ?></span>
									<span class="qs-badge <?php echo $gwqsh_view_is_warning ? 'qs-badge-warning' : 'qs-badge-good'; ?>" <?php echo $gwqsh_view_has_badge ? '' : 'hidden'; ?>><?php echo esc_html($gwqsh_view_metric[4]); ?></span>
								</h4>
								<p class="qs-metric-desc"><?php echo esc_html($gwqsh_view_metric[3]); ?></p>
							</div>
						</div>
					<?php endforeach; ?>
				</div>
			</section>

			<!-- MAIN DASHBOARD GRID MATCHING EXACT REFERENCE LAYOUT -->
			<div class="qs-dashboard-grid-v2">

				<!-- ROW 1: TOP ANALYTICS ROW (3 CARDS) -->
				<div class="qs-grid-row qs-row-analytics">

					<!-- 1. Security Score -->
					<section class="qs-card qs-card-score" id="qsScoreCard">
						<div class="qs-card-head">
							<span class="qs-tile qs-tile-blue"><?php echo $gwqsh_view_icon('shield-check'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																?></span>
							<h2>Security Score</h2>
							
						</div>
						<div class="qs-score-body">
							<div class="qs-gauge" role="img" aria-label="<?php echo esc_attr('Security score ' . $gwqsh_view_score . ' out of 100: ' . $gwqsh_view_score_status); ?>">
								<svg viewBox="0 0 180 180" aria-hidden="true">
									<defs>
										<linearGradient id="qs-score-gradient" x1="0" y1="0" x2="1" y2="1">
											<stop stop-color="#10b981" />
											<stop offset=".5" stop-color="#00ca98" />
											<stop offset="1" stop-color="#06b6d4" />
										</linearGradient>
									</defs>
									<circle class="qs-gauge-track" cx="90" cy="90" r="77" />
									<circle id="qs-score-ring" cx="90" cy="90" r="77" stroke="url(#qs-score-gradient)" stroke-dasharray="483.805" stroke-dashoffset="<?php echo esc_attr(483.805 * (1 - $gwqsh_view_score / 100)); ?>" />
								</svg>
								<div class="qs-gauge-center">
									<strong id="qs-score-value"><?php echo esc_html($gwqsh_view_score); ?></strong>
									<span class="qs-score-max">/100</span>
									<b id="qs-score-status"><?php echo esc_html($gwqsh_view_score_status); ?></b>
								</div>
							</div>
							<div class="qs-score-details">
								<h3 id="qs-score-headline"><?php echo $gwqsh_view_score >= 85 ? 'Your site is well protected!' : 'Your site needs attention'; ?></h3>
								<p class="qs-score-subtext">Review your settings and scan results to improve protection.</p>
								<ul class="qs-score-breakdown">
									<?php
									$score_items = array(
										'login'     => array('Login Protection', 'green'),
										'tfa'       => array('Two-Factor Auth', 'red'),
										'file'      => array('File Integrity', 'green'),
										'hardening' => array('Hardening', 'orange'),
										'activity'  => array('Activity Log', 'blue'),
									);
									foreach ($score_items as $gwqsh_view_key => $gwqsh_view_cfg) :
										$score_val = $gwqsh_view_d['score_components'][$gwqsh_view_key] ?? 0;
									?>
										<li>
											<i class="qs-series-dot qs-dot-<?php echo esc_attr($gwqsh_view_cfg[1]); ?>"></i>
											<span class="qs-score-label"><?php echo esc_html($gwqsh_view_cfg[0]); ?></span>
											<b class="qs-score-num" data-score="<?php echo esc_attr($gwqsh_view_key); ?>"><?php echo esc_html($score_val); ?></b>
										</li>
									<?php endforeach; ?>
								</ul>
							</div>
						</div>
					</section>

					<!-- 2. Security Activity -->
					<section class="qs-card qs-card-activity" id="qsActivityCard">
						<div class="qs-card-head">
							<span class="qs-tile qs-tile-blue"><?php echo $gwqsh_view_icon('bars'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																?></span>
							<h2>Security Activity</h2>
							<div class="qs-select-wrap">
								<label class="screen-reader-text" for="chartRange">Activity timeframe</label>
								<select class="qs-select qs-chart-select" id="chartRange">
									<option value="7" selected>Last 7 Days</option>
									<option value="14">Last 14 Days</option>
									<option value="30">Last 30 Days</option>
								</select>
							</div>
						</div>
						<div class="qs-card-inner">
							<div class="qs-legend">
								<span><i class="qs-series-dot qs-dot-blue"></i>Blocked Requests</span>
								<span><i class="qs-series-dot qs-dot-green"></i>Login Attempts</span>
								<span><i class="qs-series-dot qs-dot-red"></i>Risk Changes</span>
								<span title="Suspicious detections require review"><i class="qs-series-dot qs-dot-amber"></i>Malware Detections</span>
							</div>
							<div id="activityChart" class="qs-chart" tabindex="0" aria-label="Security activity chart. Use arrow keys to explore dates.">
								<div id="chartTip" class="qs-chart-tooltip" hidden></div>
							</div>
							<p class="qs-chart-note">Volume varies to show recent detections vs. threats trend for selected timeframe.</p>
						</div>
					</section>

					<!-- 3. Threat Sources by Country -->
					<section class="qs-card qs-card-geography" id="qsGeographyCard">
						<div class="qs-card-head">
							<span class="qs-tile qs-tile-blue"><svg class="i" viewBox="0 0 24 24">
									<use href="#i-globe" />
								</svg></span>
							<div class="qs-card-head-txt">
								<h2>Threat Sources by Country</h2>
								<p class="qs-card-subtitle" id="qsGeoSubtitle">
									<?php
									$geo_list = ! empty($gwqsh_view_d['geography']) ? $gwqsh_view_d['geography'] : array();
									$geo_total_blocks = array_sum(array_column($geo_list, 'attacks'));
									if (count($geo_list) > 0) {
										echo esc_html(number_format_i18n($geo_total_blocks) . ' total blocked requests from ' . count($geo_list) . ' countries');
									} else {
										echo 'Recorded security event distribution';
									}
									?>
								</p>
							</div>
							<div class="qs-geo-controls">
								<div class="qs-select-wrap">
									<label class="screen-reader-text" for="qs-geo-range">Threat period</label>
									<select id="qs-geo-range" class="qs-select qs-geo-select">
										<option value="30" selected>30 Days</option>
										<option value="14">14 Days</option>
										<option value="7">7 Days</option>
									</select>
								</div>
							</div>
						</div>
						<div class="qs-geo-body">
							<div class="qs-geo-legend-bar" title="Share of attributed blocked requests: High =20%, Medium =10%, Low &lt;10%. These describe recorded volume, not country risk.">
								<span><i class="qs-geo-dot qs-geo-dot-high"></i>High</span>
								<span><i class="qs-geo-dot qs-geo-dot-medium"></i>Medium</span>
								<span><i class="qs-geo-dot qs-geo-dot-low"></i>Low</span>
							</div>
							<div class="qs-threat-map-wrap" id="qsThreatMapWrap">
								<div class="qs-threat-map-loading" id="qsThreatMapLoading">Loading global threat map…</div>
							</div>
							<div class="qs-threat-country-list" id="qsThreatCountryList">
								<?php if (empty($geo_list)) : ?>
									<div class="qs-geo-empty">
										<img src="<?php echo esc_url(GWQSH_URL . 'assets/img/spot-illustrations/earth-plane.png'); ?>" alt="" width="80" height="80" class="qs-geo-empty-img" />
										<h4>No attributed threat sources</h4>
										<p>Enable public IP country lookup in Settings. This widget uses recorded denials from this site.</p>
									</div>
								<?php else : ?>
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
											<?php
											$geo_index = 1;
											foreach (array_slice($geo_list, 0, 8) as $gwqsh_view_geo) :
											?>
												<tr class="qs-geo-row" data-country="<?php echo esc_attr($gwqsh_view_geo['code']); ?>">
													<td class="qs-geo-td-num"><?php echo esc_html($geo_index++); ?></td>
													<td class="qs-geo-td-country">
														<img class="qs-geo-flag" src="<?php echo esc_url($gwqsh_view_geo['flag']); ?>" alt="" width="20" height="14" />
														<span class="qs-geo-name"><?php echo esc_html($gwqsh_view_geo['country']); ?></span>
													</td>
													<td class="qs-geo-td-threats">
														<div class="qs-geo-progress-track">
															<div class="qs-geo-progress-fill" style="width: <?php echo esc_attr($gwqsh_view_geo['percent']); ?>%; background-color: <?php echo esc_attr($gwqsh_view_geo['color']); ?>;"></div>
														</div>
														<strong class="qs-geo-count"><?php echo esc_html(number_format_i18n($gwqsh_view_geo['attacks'])); ?></strong>
													</td>
													<td class="qs-geo-td-share"><?php echo esc_html($gwqsh_view_geo['percent']); ?>%</td>
												</tr>
											<?php endforeach; ?>
										</tbody>
									</table>
								<?php endif; ?>
							</div>
						</div>
					</section>

				</div>

				<!-- ROW 2: RECENT ACTIVITY & THREAT FEED (2 CARDS) -->
				<div class="qs-grid-row qs-row-events">

					<!-- Recent Activity (Wide Table with Semantic Status Dots) -->
					<section class="qs-card qs-card-recent" id="qsRecentCard">
						<?php $gwqsh_view_head('Recent Activity', 'list', 'activity-log'); ?>
						<div class="qs-table-scroll">
							<table class="qs-table qs-table-recent">
								<thead>
									<tr>
										<th scope="col" style="width: 140px;">TIME</th>
										<th scope="col" style="width: 220px;">EVENT</th>
										<th scope="col" style="width: 130px;">IP ADDRESS</th>
										<th scope="col">DETAILS</th>
									</tr>
								</thead>
								<tbody id="qs-recent-body">
									<?php
									if (empty($gwqsh_view_d['recent_activity'])) :
									?>
										<tr>
											<td colspan="4" class="qs-empty">No recent activity recorded</td>
										</tr>
										<?php
									else :
										foreach ($gwqsh_view_d['recent_activity'] as $gwqsh_view_event) :
											$ev_name = $gwqsh_view_event['event_name'];
											$dot_class = 'blue';
											if (preg_match('/(completed|success|verified|clean|active)/i', $ev_name)) {
												$dot_class = 'green';
											} elseif (preg_match('/(blocked|lockout|locked|threat|denied|malware|suspicious)/i', $ev_name)) {
												$dot_class = 'red';
											} elseif (preg_match('/(warning|failed|attempt|modified|missing)/i', $ev_name)) {
												$dot_class = 'orange';
											}
										?>
											<tr>
												<td class="qs-td-time"><?php echo esc_html(mysql2date('M j, h:i A', $gwqsh_view_event['event_time'])); ?></td>
												<td class="qs-td-event">
													<span class="qs-event-cell">
														<i class="qs-status-dot qs-dot-<?php echo esc_attr($dot_class); ?>"></i>
														<span class="qs-event-name qs-text-<?php echo esc_attr($dot_class); ?>"><?php echo esc_html($ev_name); ?></span>
													</span>
												</td>
												<td class="qs-td-ip"><?php echo esc_html($gwqsh_view_event['ip_address'] ? $gwqsh_view_event['ip_address'] : '—'); ?></td>
												<td class="qs-td-detail">
													<span class="qs-detail" title="<?php echo esc_attr($gwqsh_view_event['details']); ?>"><?php echo esc_html($gwqsh_view_event['details']); ?></span>
												</td>
											</tr>
									<?php
										endforeach;
									endif;
									?>
								</tbody>
							</table>
						</div>
					</section>

					<!-- Recent Threat Feed -->
					<section class="qs-card qs-card-threats" id="qsThreatsCard">
						<?php $gwqsh_view_head('Recent Threat Feed', 'alert', 'activity-log', 'View All', '<span class="qs-badge qs-danger">Recorded</span>'); ?>
						<div class="qs-table-scroll">
							<table class="qs-table qs-table-threats">
								<thead>
									<tr>
										<th scope="col" style="width: 100px;">TIME</th>
										<th scope="col">THREAT</th>
										<th scope="col" style="width: 120px;">IP ADDRESS</th>
										<th scope="col" style="width: 90px;">ACTION</th>
									</tr>
								</thead>
								<tbody id="qs-threat-body">
									<?php
									if (empty($gwqsh_view_d['live_threats'])) :
									?>
										<tr>
											<td colspan="4" class="qs-empty-feed-cell">
												<div class="qs-feed-empty-state" style="display: flex; flex-direction: column; flex-wrap: nowrap; align-items: center;">
													<img src="<?php echo esc_url(GWQSH_URL . 'assets/img/spot-illustrations/34.png'); ?>" alt="" width="96" height="96" class="qs-spot-empty" />
													<h4>No recent threats detected</h4>
													<p>Records appear here after relevant activity is recorded.</p>
												</div>
											</td>
										</tr>
										<?php
									else :
										foreach ($gwqsh_view_d['live_threats'] as $gwqsh_view_threat) :
										?>
											<tr>
												<td class="qs-td-time"><?php echo esc_html(mysql2date('h:i A', $gwqsh_view_threat['event_time'])); ?></td>
												<td class="qs-danger-text"><b><?php echo esc_html($gwqsh_view_threat['event_name']); ?></b></td>
												<td class="qs-td-ip"><?php echo esc_html($gwqsh_view_threat['ip_address']); ?></td>
												<td><span class="qs-badge qs-blue-badge">Blocked</span></td>
											</tr>
									<?php
										endforeach;
									endif;
									?>
								</tbody>
							</table>
						</div>
						<div class="qs-card-foot-note">
							<small class="qs-feed-note">Recorded security events refresh to update.</small>
						</div>
					</section>

				</div>

				<!-- ROW 3: HARDENING CHECKLIST & QUARANTINE (2 CARDS) -->
				<div class="qs-grid-row qs-row-security">

					<!-- Hardening Checklist -->
					<section class="qs-card qs-card-hardening" id="qsHardeningCard">
						<?php $gwqsh_view_head('Hardening Checklist', 'shield-check', 'hardening', 'View All', '<span id="qs-hardening-count" class="qs-badge qs-good">' . esc_html($gwqsh_view_d['hardening_on']) . ' / 6 Completed</span>'); ?>
						<ul class="qs-checklist">
							<?php
							$hardening_rules = array(
								'xmlrpc'  => array('Disable XML-RPC', 'Blocks brute force attacks'),
								'editor'  => array('Disable file editor', 'Prevents theme and plugin edits'),
								'version' => array('Hide WordPress version', 'Removes generator meta tags'),
								'enum'    => array('Block user enumeration', 'Blocks username discovery'),
								'headers' => array('Security headers', 'Adds security response headers'),
								'uploads' => array('Block PHP file uploads', 'Restricts PHP execution in uploads'),
							);
							foreach ($hardening_rules as $gwqsh_view_key => $gwqsh_view_check) :
								$is_on = ! empty($gwqsh_view_d['hardening'][$gwqsh_view_key]);
							?>
								<li>
									<button type="button" class="qs-toggle-status <?php echo $is_on ? 'is-on' : ''; ?>" data-hardening="<?php echo esc_attr($gwqsh_view_key); ?>" aria-pressed="<?php echo $is_on ? 'true' : 'false'; ?>" aria-label="<?php echo esc_attr($gwqsh_view_check[0] . ': ' . ($is_on ? 'Enabled' : 'Disabled')); ?>"></button>
									<div class="qs-checklist-body">
										<b><?php echo esc_html($gwqsh_view_check[0]); ?></b>
										<small><?php echo esc_html($gwqsh_view_check[1]); ?></small>
									</div>
								</li>
							<?php endforeach; ?>
						</ul>
					</section>

					<!-- Quarantine -->
					<section class="qs-card qs-card-quarantine" id="qsQuarantineCard">
						<?php $gwqsh_view_head('Quarantine (' . (int) $gwqsh_view_d['scan_summary']['quarantined'] . ' Files)', 'lock', 'file-integrity', 'Manage'); ?>
						<div class="qs-table-scroll">
							<table class="qs-table qs-table-quarantine">
								<thead>
									<tr>
										<th scope="col">File Name</th>
										<th scope="col" style="width: 120px;">Status</th>
										<th scope="col" style="width: 120px;">Date</th>
									</tr>
								</thead>
								<tbody id="qs-quarantine-body">
									<?php
									if (empty($gwqsh_view_d['quarantine'])) :
									?>
										<tr>
											<td colspan="3" class="qs-empty-feed-cell">
												<div class="qs-feed-empty-state">
													<img src="<?php echo esc_url(GWQSH_URL . 'assets/img/spot-illustrations/40.png'); ?>" alt="" width="96" height="96" class="qs-spot-empty" />
													<h4>No quarantined files</h4>
													<p>Records appear here after relevant activity is recorded.</p>
												</div>
											</td>
										</tr>
										<?php
									else :
										foreach ($gwqsh_view_d['quarantine'] as $gwqsh_view_record) :
										?>
											<tr>
												<td title="<?php echo esc_attr($gwqsh_view_record['display_path']); ?>"><b><?php echo esc_html(basename($gwqsh_view_record['display_path'])); ?></b></td>
												<td><span class="qs-badge qs-warning"><?php echo esc_html($gwqsh_view_record['status']); ?></span></td>
												<td><?php echo esc_html(! empty($gwqsh_view_record['time']) ? wp_date('M j, Y', (int) $gwqsh_view_record['time']) : '—'); ?></td>
											</tr>
									<?php
										endforeach;
									endif;
									?>
								</tbody>
							</table>
						</div>
					</section>

				</div>

				<!-- ROW 4: RECENT SCAN RESULTS & PRO FEATURES (2 CARDS) -->
				<div class="qs-grid-row qs-row-bottom">

					<!-- Recent Scan Results -->
					<section class="qs-card qs-card-scans" id="qsScansCard">
						<?php $gwqsh_view_head('Recent Scan Results', 'file', 'file-integrity'); ?>
						<div class="qs-table-scroll qs-scan-table-scroll" tabindex="0" role="region" aria-label="Recent scan results">
							<table class="qs-table qs-scan-table">
								<thead>
									<tr>
										<th scope="col" style="width: 40px;" aria-label="Scan icon"></th>
										<th scope="col">SCAN TYPE</th>
										<th scope="col">FINDINGS</th>
										<th scope="col">DATE</th>
										<th scope="col" style="width: 100px;">STATUS</th>
									</tr>
								</thead>
								<tbody id="qs-scan-history">
									<?php if (empty($gwqsh_view_d['scan_history'])) : ?>
										<tr>
											<td colspan="5" class="qs-empty">No scans completed yet</td>
										</tr>
									<?php else : ?>
										<?php
										foreach ($gwqsh_view_d['scan_history'] as $gwqsh_view_scan) :
											$gwqsh_view_count = (int) $gwqsh_view_scan['modified_files'] + (int) $gwqsh_view_scan['missing_files'] + (int) $gwqsh_view_scan['suspicious_files'];
										?>
											<tr>
												<td><span class="qs-scan-file-icon"><?php echo $gwqsh_view_icon('file'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																					?></span></td>
												<td><a class="qs-scan-link" href="<?php echo esc_url($gwqsh_view_url('file-integrity')); ?>"><b>Full File Scan</b></a></td>
												<td class="qs-td-findings"><?php echo esc_html(number_format_i18n($gwqsh_view_count) . ' findings · ' . number_format_i18n($gwqsh_view_scan['total_files']) . ' files'); ?></td>
												<td><time datetime="<?php echo esc_attr(str_replace(' ', 'T', $gwqsh_view_scan['scan_date'])); ?>"><?php echo esc_html(mysql2date('M j, Y, h:i A', $gwqsh_view_scan['scan_date'])); ?></time></td>
												<td><span class="qs-badge <?php echo $gwqsh_view_count ? 'qs-danger' : 'qs-badge-no-issues'; ?>"><?php echo $gwqsh_view_count ? 'Review' : 'No Issues'; ?></span></td>
											</tr>
										<?php endforeach; ?>
									<?php endif; ?>
								</tbody>
							</table>
						</div>
					</section>

					<!-- Pro Features & Quick Actions (2x4 Grid with Crown Header) -->
					<section class="qs-card qs-card-pro-tools" id="qs-pro-tools">
						<div class="qs-card-head">
							<span class="qs-tile qs-tile-amber"><svg class="i fill" viewBox="0 0 24 24">
									<use href="#i-crown" />
								</svg></span>
							<h2>Pro Features &amp; Quick Actions</h2>
						</div>
						<div class="qs-action-grid-v2">
							<button type="button" class="qs-action-tile qs-tile-green" id="qsActionMalwareScan" title="Scan WordPress files in real-time">
								<span class="qs-tile-icon-box qs-icon-box-green"><svg class="i">
										<use href="#i-bug" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Real-time</strong>
									<span>Malware Scan</span>
								</div>
							</button>
							<a href="<?php echo esc_url($gwqsh_view_url('file-integrity')); ?>" class="qs-action-tile qs-tile-purple" title="Review scan history">
								<span class="qs-tile-icon-box qs-icon-box-purple"><svg class="i">
										<use href="#i-file" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Scan</strong>
									<span>History</span>
								</div>
							</a>
							<a href="<?php echo esc_url($gwqsh_view_url('firewall-cleanup')); ?>" class="qs-action-tile qs-tile-blue" title="Tune firewall rules">
								<span class="qs-tile-icon-box qs-icon-box-blue"><svg class="i">
										<use href="#i-shield-check" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>WAF Tuning</strong>
									<span>&amp; Rules</span>
								</div>
							</a>
							<a href="<?php echo esc_url($gwqsh_view_url('firewall-cleanup')); ?>" class="qs-action-tile qs-tile-cyan" title="Country blocking is unavailable">
								<span class="qs-tile-icon-box qs-icon-box-cyan"><svg class="i">
										<use href="#i-globe" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Country</strong>
									<span>Blocking Unavailable</span>
								</div>
							</a>
							<a href="<?php echo esc_url($gwqsh_view_url('activity-log')); ?>" class="qs-action-tile qs-tile-purple" title="Review activity logs and reports">
								<span class="qs-tile-icon-box qs-icon-box-purple"><svg class="i">
										<use href="#i-list" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Activity</strong>
									<span>&amp; Reports</span>
								</div>
							</a>
							<a href="<?php echo esc_url($gwqsh_view_url('two-factor')); ?>" class="qs-action-tile qs-tile-green" title="Configure role-based 2FA">
								<span class="qs-tile-icon-box qs-icon-box-green"><svg class="i">
										<use href="#i-users" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Role-based</strong>
									<span>2FA</span>
								</div>
							</a>
							<a href="<?php echo esc_url($gwqsh_view_url('login-protection') . '#emergency'); ?>" class="qs-action-tile qs-tile-orange" title="Emergency lockout recovery">
								<span class="qs-tile-icon-box qs-icon-box-orange"><svg class="i">
										<use href="#i-refresh" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Emergency</strong>
									<span>Recovery</span>
								</div>
							</a>
							<a href="<?php echo esc_url(admin_url('admin-post.php?action=gwqsh_export_activity_log&nonce=' . wp_create_nonce('gwqsh_export_logs'))); ?>" class="qs-action-tile qs-tile-blue" id="qsActionExportLogs" title="Download certified security audit trail">
								<span class="qs-tile-icon-box qs-icon-box-blue"><svg class="i">
										<use href="#i-report" />
									</svg></span>
								<div class="qs-tile-label-box">
									<strong>Export</strong>
									<span>Audit Logs</span>
								</div>
							</a>
						</div>
					</section>

				</div>

			</div>
		</div>
	</div>
</main>