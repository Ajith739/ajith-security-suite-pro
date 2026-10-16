<?php
/**
 * Prevent two editions from loading the same security engine and shared data.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Edition compatibility checks run before any shared GWQSH declarations. */
final class GWQSH_Pro_Compatibility {

	/**
	 * Find active editions other than the plugin file currently being loaded.
	 *
	 * @param string $plugin_file Current bootstrap or uninstall file.
	 * @return array Active conflicting plugin basenames.
	 */
	public static function conflicts( $plugin_file ) {
		$current = dirname( plugin_basename( $plugin_file ) );
		$active  = array_merge( (array) get_option( 'active_plugins', array() ), array_keys( (array) get_site_option( 'active_sitewide_plugins', array() ) ) );
		$known   = array(
			'gracewell-security-suite/gracewell-security-suite.php',
			'gracewell-security-suite-pro/gracewell-security-suite-pro.php',
			'gracewell-quiteshield-pro/gracewell-quietshield.php',
			'gracewell-quietshield/gracewell-quietshield.php',
		);
		return array_values(
			array_filter(
				array_unique( $active ),
				static function ( $basename ) use ( $current, $known ) {
					return dirname( $basename ) !== $current && in_array( $basename, $known, true );
				}
			)
		);
	}

	/** Show a conflict without disabling the edition already protecting the site. */
	public static function notice() {
		if ( ! current_user_can( 'activate_plugins' ) ) {
			return;
		}
		echo '<div class="notice notice-error"><p>' . esc_html__( 'Gracewell Security Suite Pro cannot load alongside another Gracewell Security Suite edition. Deactivate the Free or previous development edition, then activate Pro. Existing security data will be preserved.', 'gracewell-security-suite-pro' ) . '</p></div>';
	}

	/** Refuse activation before any shared class or constant can be redeclared. */
	public static function activation_error() {
		wp_die( esc_html__( 'Deactivate the Free or previous development edition of Gracewell Security Suite before activating Pro. Do not delete its data: Pro uses your existing settings, security logs, and 2FA enrollment.', 'gracewell-security-suite-pro' ), esc_html__( 'Gracewell edition conflict', 'gracewell-security-suite-pro' ), array( 'back_link' => true ) );
	}
}
