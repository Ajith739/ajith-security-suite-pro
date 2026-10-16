<?php
/**
 * Plugin Name: Gracewell Security Suite Pro
 * Plugin URI: https://github.com/joshua-sundar/gracewell-security-suite-pro
 * Update URI: https://github.com/joshua-sundar/gracewell-security-suite-pro
 * Description: WordPress firewall, passkeys and two-factor recovery, login protection, scheduled file integrity scans, IP restrictions and security audit logs.
 * Version: 1.1.0
 * Author: gracewell89
 * Author URI: https://gracewell.in/
 * Contributors: gracewell89
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: gracewell-security-suite-pro
 * Domain Path: /languages
 * Requires at least: 5.3
 * Requires PHP: 8.0
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

require_once __DIR__ . '/includes/class-gwqsh-pro-compatibility.php';
if ( GWQSH_Pro_Compatibility::conflicts( __FILE__ ) || defined( 'GWQSH_PLUGIN_FILE' ) ) {
	add_action( 'admin_notices', array( 'GWQSH_Pro_Compatibility', 'notice' ) );
	add_action( 'network_admin_notices', array( 'GWQSH_Pro_Compatibility', 'notice' ) );
	register_activation_hook( __FILE__, array( 'GWQSH_Pro_Compatibility', 'activation_error' ) );
	return;
}

define( 'GWQSH_PATH', plugin_dir_path( __FILE__ ) );
define( 'GWQSH_URL', plugin_dir_url( __FILE__ ) );
define( 'GWQSH_VERSION', '1.1.0' );
define( 'GWQSH_DB_VERSION', '1.6.0' );
define( 'GWQSH_PLUGIN_FILE', __FILE__ );
define( 'GWQSH_PLUGIN_DIR', GWQSH_PATH );
define( 'GWQSH_PLUGIN_URL', GWQSH_URL );
define( 'GWQSH_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );

// Legacy emergency constants remain supported during the development-prefix transition.
if ( ! defined( 'GWQSH_DISABLE_LOGIN_URL' ) && defined( 'GQS_DISABLE_LOGIN_URL' ) ) {
	define( 'GWQSH_DISABLE_LOGIN_URL', GQS_DISABLE_LOGIN_URL ); }
if ( ! defined( 'GWQSH_TRUSTED_PROXIES' ) && defined( 'GQS_TRUSTED_PROXIES' ) ) {
	define( 'GWQSH_TRUSTED_PROXIES', GQS_TRUSTED_PROXIES ); }

// Load backend modules.
require_once GWQSH_PATH . 'includes/interface-gwqsh-delivery-provider.php';
require_once GWQSH_PATH . 'includes/interface-gwqsh-reputation-provider.php';
require_once GWQSH_PATH . 'includes/interface-gwqsh-license-provider.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-country-access.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-setup-wizard.php';

require_once GWQSH_PATH . 'includes/class-gwqsh-enterprise-store.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-secure-http.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-enterprise-config.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-privacy.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-events.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-threat-intelligence.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-signatures.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-license.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-enterprise-ui.php';

require_once GWQSH_PATH . 'includes/class-gwqsh-time.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-passkeys.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-recovery.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-customization.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-ui.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-ip-blocks.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-scheduler.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-network.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-migration.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-db.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-crypto.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-settings.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-activity-logger.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-activity-view-data.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-login-protection.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-two-factor.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-two-factor-view-data.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-hardening.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-hardening-rules.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-hardening-data.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-security-runtime.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-path-guard.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-guardian.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-malware-analyzer.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-database-scanner.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-scan-engine.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-file-integrity.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-quarantine-manager.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-ajax.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-admin.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-firewall.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-dashboard-data.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-database-view-data.php';
require_once GWQSH_PATH . 'includes/class-gwqsh-login-view-data.php';

// Activation and Deactivation lifecycle hooks.
register_activation_hook( __FILE__, 'gwqsh_pro_activate_plugin' );
register_deactivation_hook( __FILE__, 'gwqsh_pro_deactivate_plugin' );
/**
 * Gwqsh activate plugin.
 */
function gwqsh_pro_activate_plugin() {
	GWQSH_Migration::run();
	GWQSH_Crypto::prepare_upgrade();
	GWQSH_DB::create_tables();
	GWQSH_Login_Protection::get_allowlist();
	GWQSH_Guardian::install();
	GWQSH_Hardening::sync_uploads_protection( GWQSH_Settings::is_active() && GWQSH_Hardening::is_enabled( 'uploads' ) );
}
/**
 * Gwqsh deactivate plugin.
 */
function gwqsh_pro_deactivate_plugin() {
	foreach ( array( 'gwqsh_deliver_events', 'gwqsh_reputation_lookup', 'gwqsh_update_signatures', 'gwqsh_refresh_cloudflare_ranges' ) as $hook ) {
		wp_clear_scheduled_hook( $hook ); }
	GWQSH_Guardian::remove();
	wp_clear_scheduled_hook( 'gwqsh_continue_integrity_scan' );
	wp_clear_scheduled_hook( 'gwqsh_scheduled_integrity_scan' );
	wp_clear_scheduled_hook( 'gwqsh_run_integrity_now' );
	wp_clear_scheduled_hook( 'gwqsh_geo_lookup' );
	wp_clear_scheduled_hook( 'gwqsh_auth_cleanup' );
	wp_clear_scheduled_hook( 'gwqsh_daily_log_cleanup' );
	wp_clear_scheduled_hook( 'gwqsh_activity_search_backfill' );
	wp_clear_scheduled_hook( 'gwqsh_cleanup_lockouts' );
	wp_clear_scheduled_hook( GWQSH_Database_Scanner::CRON_HOOK );
	GWQSH_Hardening::sync_uploads_protection( false );
}

// Bootstrap all modules.
/**
 * Gwqsh bootstrap.
 */
function gwqsh_pro_bootstrap() {
	GWQSH_Migration::run();
	GWQSH_Crypto::prepare_upgrade();
	GWQSH_Settings::migrate_removed_features();
	add_action( 'admin_notices', array( 'GWQSH_Settings', 'critical_notice' ) );
	GWQSH_DB::init();
	GWQSH_Privacy::init();
	GWQSH_Events::init();
	GWQSH_Threat_Intelligence::init();
	GWQSH_Country_Access::init();
	GWQSH_Signatures::init();
	GWQSH_Enterprise_UI::init();
	GWQSH_Network::init();
	GWQSH_IP_Blocks::init();
	GWQSH_Activity_Logger::init();
	GWQSH_Activity_View_Data::init();
	GWQSH_Login_Protection::init();
	GWQSH_Two_Factor::init();
	GWQSH_Passkeys::init();
	GWQSH_Recovery::init();
	GWQSH_Customization::init();
	GWQSH_Hardening::init();
	GWQSH_File_Integrity::init();
	GWQSH_Scheduler::init();
	GWQSH_Guardian::init();
	GWQSH_Database_Scanner::init();
	GWQSH_Firewall::init();
	GWQSH_Ajax::init();
	GWQSH_Admin::init();
}
add_action( 'plugins_loaded', 'gwqsh_pro_bootstrap' );
