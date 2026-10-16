<?php

/** Hardening Pro administration screen.
 *
 * @package GracewellSecuritySuitePro
 */

defined('ABSPATH') || exit;
if (! current_user_can('manage_options')) {
	return;
}
$gwqsh_data      = GWQSH_Admin::get_page_initial_data('hardening');
$gwqsh_current_u = wp_get_current_user();
$gwqsh_u_name    = $gwqsh_current_u->display_name ? $gwqsh_current_u->display_name : $gwqsh_current_u->user_login;
$gwqsh_u_initial = strtoupper(substr($gwqsh_u_name, 0, 1));
$gwqsh_u_role    = ! empty($gwqsh_current_u->roles[0]) ? ucfirst($gwqsh_current_u->roles[0]) : 'Administrator';

$gwqsh_icon = static function ($gwqsh_view_name) {
	return '<svg class="qs-icon" aria-hidden="true"><use href="#i-' . esc_attr($gwqsh_view_name) . '"/></svg>';
};
?>

<?php require GWQSH_PATH . 'admin/views/dashboard-icons.php'; ?>
<a class="skip" href="#main">Skip to content</a>
<header class="topbar">
	<div class="topbar-in">
		<a class="brand" href="<?php echo esc_url(admin_url('admin.php?page=gracewell-security-suite-pro')); ?>" aria-label="Security Suite Pro home">
			<img class="logo-mark" src="<?php echo esc_url(GWQSH_URL . 'assets/img/quietshield.svg'); ?>" alt="" width="40" height="44">
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
					</svg><span class="dot-badge" id="notifDot">1</span>
				</button>
				<div class="menu menu-notif" id="menu-notif" role="menu">
					<div class="menu-head"><b>Notifications</b><button class="link-btn" id="markRead" type="button">Mark all as
							read</button></div>
					<div class="menu-item">Loading recent events…</div>

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
	<section class="hero hd-settings-hero" aria-labelledby="heroTitle">
		<canvas class="hero-birds" id="heroBirds" aria-hidden="true"></canvas>
		<div class="wrap hero-in">
			<div class="hero-content">
				<p class="eyebrow">WordPress Hardening</p>
				<h1 class="h1" id="heroTitle">WordPress <span class="hl">Hardening</span></h1>
				<p class="lede">Strengthen your WordPress site security with recommended hardening measures. Lock down common attack vectors and apply best practices to keep your site safe and resilient.</p>
			</div>
		</div>
	</section>
	<div class="qs-pro-dashboard qs-pro-hardening">
		<div class="hd-content">
			<section class="qs-overview hd-overview" aria-labelledby="qs-hd-overview-title">

				<div class="qs-metrics hd-stats">
					<!-- 1. Hardening Score -->
					<div class="qs-metric qs-metric-green">
						<div class="qs-stack-icon">
							<span class="qs-stack-square" aria-hidden="true"></span>
							<span class="qs-stack-circle" aria-hidden="true">
								<?php echo $gwqsh_icon('shield-check'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
								?>
							</span>
						</div>
						<div class="qs-metric-body">
							<h4 class="qs-metric-heading">
								<strong><span id="scoreN"><?php echo esc_html($gwqsh_data['score']); ?></span> / 100</strong>
								<span class="qs-metric-title">Hardening Score</span>
							</h4>
							<p class="qs-metric-desc" id="scoreMsg">Assessment of these six hardening controls.</p>
							<div class="hd-progress" role="progressbar" aria-label="Hardening score" aria-valuemin="0" aria-valuemax="100" aria-valuenow="<?php echo esc_attr($gwqsh_data['score']); ?>" style="display:none;"><span id="scoreBar"></span></div>
						</div>
					</div>

					<!-- 2. Enabled Settings -->
					<div class="qs-metric qs-metric-blue">
						<div class="qs-stack-icon">
							<span class="qs-stack-square" aria-hidden="true"></span>
							<span class="qs-stack-circle" aria-hidden="true">
								<?php echo $gwqsh_icon('gear'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
								?>
							</span>
						</div>
						<div class="qs-metric-body">
							<h4 class="qs-metric-heading">
								<strong><span id="enabledN"><?php echo esc_html($gwqsh_data['passed']); ?></span> / 6</strong>
								<span class="qs-metric-title">Enabled Settings</span>
								<span class="qs-badge qs-badge-good hd-pill hd-green" id="enabledBadge"><?php echo esc_html($gwqsh_data['passed'] . ' / 6'); ?></span>
							</h4>
							<p class="qs-metric-desc" id="enabledMsg">Controls with current application evidence.</p>
						</div>
					</div>

					<!-- 3. Pending Actions -->
					<div class="qs-metric qs-metric-yellow">
						<div class="qs-stack-icon">
							<span class="qs-stack-square" aria-hidden="true"></span>
							<span class="qs-stack-circle" aria-hidden="true">
								<?php echo $gwqsh_icon('bell'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
								?>
							</span>
						</div>
						<div class="qs-metric-body">
							<h4 class="qs-metric-heading">
								<strong><span id="pendingN"><?php echo esc_html($gwqsh_data['pending']); ?></span></strong>
								<span class="qs-metric-title">Pending Actions</span>
								<span class="qs-badge qs-badge-warning hd-pill hd-orange" id="pendingBadge"><?php echo esc_html($gwqsh_data['pending'] . ' pending'); ?></span>
							</h4>
							<p class="qs-metric-desc" id="pendingMsg">Disabled or unverified controls need review.</p>
						</div>
					</div>

					<!-- 4. Risk Level -->
					<div class="qs-metric qs-metric-purple">
						<div class="qs-stack-icon">
							<span class="qs-stack-square" aria-hidden="true"></span>
							<span class="qs-stack-circle" aria-hidden="true">
								<?php echo $gwqsh_icon('lock'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
								?>
							</span>
						</div>
						<div class="qs-metric-body">
							<h4 class="qs-metric-heading">
								<strong><span id="riskN"><?php echo esc_html($gwqsh_data['level']); ?></span></strong>
								<span class="qs-metric-title">Risk Level</span>
								<span class="qs-badge hd-pill <?php echo 'Low' === $gwqsh_data['level'] ? 'qs-badge-good hd-green' : 'qs-badge-warning hd-orange'; ?>" id="riskBadge"><?php echo esc_html($gwqsh_data['level']); ?></span>
							</h4>
							<p class="qs-metric-desc">Weighted hardening assessment</p>
						</div>
					</div>
				</div>
				<hr class="qs-overview-divider" />
			</section>
			<p id="hardeningStatus" class="hd-status" role="status" aria-live="polite"></p>
			<div class="hd-grid">
				<div class="hd-left">
					<section class="hd-card hd-checklist" id="hardeningChecklist">
						<div class="hd-head"><span class="hd-icon hd-purple"><?php echo $gwqsh_icon('gear'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																				?></span>
							<div>
								<h2>Hardening Checklist</h2>
								<p>Enable security features to protect your site. Review compatibility before changing an option.</p>
							</div><button type="button" class="hd-button" id="resetDef">↶ &nbsp; Reset to Defaults</button>
						</div>
						<div class="hd-table-scroll">
							<table class="hd-table">
								
								<thead>
									<tr>
										<th scope="col">Setting</th>
										<th scope="col">Description</th>
										<th scope="col">Status</th>
										<th scope="col">Action</th>
									</tr>
								</thead>
								<tbody id="checkBody">
									<?php
									$gwqsh_descriptions = array(
										'xmlrpc'  => array('orange', 'shield-check', 'Restricts XML-RPC authentication and requests.'),
										'editor'  => array('red', 'file', 'Blocks theme and plugin file editing from admin.'),
										'version' => array('purple', 'globe', 'Removes generator output and exact core version query values.'),
										'enum'    => array('blue', 'users', 'Restricts anonymous numeric author and users REST probes.'),
										'headers' => array('orange', 'shield-check', 'Adds nosniff, SAMEORIGIN and Referrer-Policy when absent.'),
										'uploads' => array('red', 'file', 'Uses owned server rules; execution blocking requires verification.'),
									);
									foreach ($gwqsh_data['rows'] as $gwqsh_view_key => $gwqsh_view_row) :
										$gwqsh_view_d = $gwqsh_descriptions[$gwqsh_view_key];
									?>
										<tr data-key="<?php echo esc_attr($gwqsh_view_key); ?>">
											<td><span class="hd-icon hd-<?php echo esc_attr($gwqsh_view_d[0]); ?>"><?php echo $gwqsh_icon($gwqsh_view_d[1]); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																														?></span><b><?php echo esc_html($gwqsh_view_row['name']); ?></b></td>
											<td><?php echo esc_html($gwqsh_view_d[2]); ?></td>
											<td><span class="hd-pill" data-control-status="<?php echo esc_attr($gwqsh_view_key); ?>"><?php echo esc_html($gwqsh_view_row['status']); ?></span><button class="hd-info" type="button" data-info="<?php echo esc_attr($gwqsh_view_key); ?>" aria-label="Details for <?php echo esc_attr($gwqsh_view_row['name']); ?>">ⓘ</button></td>
											<td><button class="hd-toggle" type="button" role="switch" aria-label="<?php echo esc_attr($gwqsh_view_row['name']); ?>" aria-checked="<?php echo $gwqsh_view_row['configured'] ? 'true' : 'false'; ?>" data-toggle="<?php echo esc_attr($gwqsh_view_key); ?>"><span></span></button></td>
										</tr>
									<?php endforeach; ?>
								</tbody>
							</table>
						</div>
						<p class="hd-note">Toggles show saved intent; status and score reflect application evidence. Server detection: <b id="serverLabel"></b>.</p>
					</section>
					<div class="hd-lower">
						<section class="hd-card hd-server">
							<div class="hd-head"><span class="hd-icon hd-purple"><?php echo $gwqsh_icon('grid'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																					?></span>
								<div>
									<h2>Server Configuration &amp; Advanced Hardening</h2>
									<p>Review server guidance before deployment.</p>
								</div>
							</div>
							<div class="hd-tabs" role="tablist" aria-label="Server configuration"><button role="tab" id="tab-apache" aria-controls="panel-apache" aria-selected="true" tabindex="0" type="button" data-tab="apache">Apache Rules</button><button role="tab" id="tab-nginx" aria-controls="panel-nginx" aria-selected="false" tabindex="-1" type="button" data-tab="nginx">Nginx Configuration</button><button role="tab" id="tab-csp" aria-controls="panel-csp" aria-selected="false" tabindex="-1" type="button" data-tab="csp">Custom CSP</button><button role="tab" id="tab-tips" aria-controls="panel-tips" aria-selected="false" tabindex="-1" type="button" data-tab="tips">Advanced Tips</button></div>
							<div id="panel-apache" role="tabpanel" aria-labelledby="tab-apache" class="hd-tab-panel">
								<h3>Apache .htaccess Rules</h3>
								<p>Generated guidance, not deployed to the site root. Only owned uploads rules can be managed automatically on Apache; backups precede writes.</p>
								<div class="hd-code-box"><button class="hd-button hd-copy" type="button" data-copy-code="apache">▣ Copy</button>
									<pre><code id="apacheCode"></code></pre>
								</div>
							</div>
							<div id="panel-nginx" role="tabpanel" aria-labelledby="tab-nginx" hidden class="hd-tab-panel">
								<h3>Nginx Configuration</h3>
								<p>Manual configuration required. Review PHP location ordering and existing headers, run nginx -t, then reload. WordPress does not deploy these rules.</p>
								<div class="hd-code-box"><button class="hd-button hd-copy" type="button" data-copy-code="nginx">▣ Copy</button>
									<pre><code id="nginxCode"></code></pre>
								</div>
							</div>
							<div id="panel-csp" role="tabpanel" aria-labelledby="tab-csp" hidden class="hd-tab-panel">
								<h3>Custom Content Security Policy</h3>
								<p>Applies to public WordPress frontend responses only. Start in report-only mode and test integrations in browser developer tools. Existing CSP headers are preserved.</p>
								<form id="cspForm"><label for="cspMode">Policy mode</label><select id="cspMode">
										<option value="off">Disabled</option>
										<option value="report">Report-only testing</option>
										<option value="enforce">Enforce after testing</option>
									</select><label for="cspPolicy">Single-line policy (up to 2,048 bytes)</label><textarea id="cspPolicy" maxlength="2048" rows="3" placeholder="default-src 'self'; img-src 'self' https: data:"></textarea>
									<p>Supported: default-src, script-src, style-src, img-src, connect-src, font-src and frame-ancestors. No reporting endpoint is installed; inspect browser CSP messages.</p><button class="hd-button hd-primary" type="submit">Save Policy</button><button class="hd-button" type="button" id="copyCsp">Copy Report-Only Header</button>
								</form>
							</div>
							<div id="panel-tips" role="tabpanel" aria-labelledby="tab-tips" hidden class="hd-tab-panel">
								<h3>Advanced Tips</h3>
								<ul>
									<li>Keep WordPress, themes and plugins updated; remove unused extensions.</li>
									<li>Use HTTPS and verify the public response after proxy or cache changes.</li>
									<li>Protect wp-config.php through hosting configuration; never expose backup files.</li>
									<li>Use the least file permissions your hosting requires. Avoid blanket 777 permissions.</li>
									<li>Back up configuration and test server syntax before a reload.</li>
									<li>Verify ordinary media delivery as well as executable-file denial.</li>
								</ul><a href="https://developer.wordpress.org/advanced-administration/security/hardening/" target="_blank" rel="noopener">WordPress hardening documentation →</a>
							</div>
						</section>
						<section class="hd-card hd-undo">
							<div class="hd-head"><span class="hd-icon hd-blue"><?php echo $gwqsh_icon('refresh'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																				?></span>
								<div>
									<h2>Undo Changes</h2>
									<p>Revert changes owned by Security Suite Pro.</p>
								</div>
							</div>
							<div class="hd-info-panel"><b>Safe and scoped</b>
								<p>Only the exact managed uploads block and plugin hardening options are changed. Unrelated directives and external wp-config.php constants remain intact.</p>
							</div>
							<div class="hd-danger-panel">
								<h3>Revert All Hardening Changes</h3>
								<p>Disable the six controls and custom CSP; remove owned uploads rules. External or manually installed server rules may continue to apply.</p><button class="hd-button hd-danger" type="button" id="revertAll">Revert All Changes</button>
							</div>
						</section>
					</div>
				</div>
				<aside class="hd-right">
					<section class="hd-card hd-components">
						<div class="hd-head"><span class="hd-icon hd-blue"><?php echo $gwqsh_icon('activity'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																			?></span>
							<h2>Security Components</h2>
						</div>
						<div class="hd-component-body">
							<div class="hd-ring" id="scoreRing"><svg viewBox="0 0 160 160" role="img" aria-label="Hardening score">
									<circle cx="80" cy="80" r="68" fill="none" stroke="#e9efff" stroke-width="23" />
									<circle id="scoreArc" cx="80" cy="80" r="68" fill="none" stroke="currentColor" stroke-width="23" transform="rotate(-90 80 80)" />
								</svg>
								<div><b id="ringN"></b><span>/ 100</span><small>Hardening</small></div>
							</div>
							<dl id="componentScores"></dl>
						</div>
						<p class="hd-note">Circle: Hardening only. Component values use shared module providers.</p>
					</section>
					<section class="hd-card hd-recommendations" id="recommendations">
						<div class="hd-head"><span class="hd-icon hd-orange"><?php echo $gwqsh_icon('help'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																				?></span>
							<div>
								<h2>Recommended Actions</h2>
								<p>Review disabled or unverified controls.</p>
							</div>
						</div>
						<div id="recommendationList"></div><button type="button" class="hd-link hd-all" id="recAll">View All Recommendations →</button>
					</section>
					<section class="hd-card hd-headers">
						<div class="hd-head"><span class="hd-icon hd-green"><?php echo $gwqsh_icon('shield-check'); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped 
																			?></span>
							<div>
								<h2>Security Headers Preview</h2>
								<p>Configured values and the last public response.</p>
							</div>
						</div>
						<pre id="headersPreview"></pre>
						<p class="hd-note" id="verificationNote">Public headers are unverified.</p><button class="hd-button" type="button" id="verifyHardening">Verify Public Response &amp; Uploads</button>
					</section>
				</aside>
			</div>
		</div>
		<div class="toasts" id="toasts" aria-live="polite"></div>
	</div>
</main>