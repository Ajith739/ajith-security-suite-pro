<?php
/**
 * Settings repository and options manager for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Settings implementation.
 */
final class GWQSH_Settings {
	/**
	 * Migrate removed features.
	 */
	public static function migrate_removed_features() {
		if ( get_option( 'gwqsh_per_user_2fa_migration' ) ) {
			return; }
		// Readers whitelist supported settings and ignore retired global switches.
		// Keep original options and legacy metadata intact for operator rollback;
		// recovery uses only separately verified destinations, never this legacy data.
		update_option( 'gwqsh_per_user_2fa_migration', 1, false );
	}

	private const OPTION_KEY = 'gwqsh_settings';
	/**
	 * Get defaults.
	 */
	public static function get_defaults() {
		return array(
			'status'          => true,
			'autoupdate'      => true,
			'retention'       => '30',
			'language'        => 'en_US',
			'timezone'        => wp_timezone_string(),
			'telemetry'       => false,
			'notice'          => true,
			'proxy'           => false,
			'https'           => true,
			'theme'           => 'light',
			'compact'         => false,
			'anim'            => true,
			'tips'            => true,
			'debug'           => false,
			'proxyheader'     => 'xff',
			'trusted_proxies' => '',
			'geo_enabled'     => false,
			'scan_budget'     => '3',
			'hero_animation'  => true,
			'uninstall'       => false,
		);
	}
	/**
	 * Get all.
	 */
	public static function get_all() {
		$saved = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		$all               = array_intersect_key( wp_parse_args( $saved, self::get_defaults() ), self::get_defaults() );
		$all['autoupdate'] = in_array( GWQSH_PLUGIN_BASENAME, (array) get_site_option( 'auto_update_plugins', array() ), true );
		return $all;
	}
	/**
	 * Get.
	 *
	 * @param mixed $key Key.
	 * @param mixed $default Default.
	 */
	public static function get( $key, $default = null ) {
		$all = self::get_all();
		if ( array_key_exists( $key, $all ) ) {
			return $all[ $key ];
		}
		return $default;
	}
	/** Whether this viewer may change WordPress's update selection. */
	public static function can_manage_updates() {
		return current_user_can( 'update_plugins' ) && ( ! is_multisite() || current_user_can( 'manage_network_plugins' ) );
	}
	/**
	 * Set.
	 *
	 * @param mixed $key Key.
	 * @param mixed $value Value.
	 */
	public static function set( $key, $value ) {
		$all         = self::get_all();
		$all[ $key ] = $value;
		return update_option( self::OPTION_KEY, $all );
	}
	/**
	 * Normalize known preferences without writing.
	 *
	 * @param array $settings Settings.
	 */
	public static function normalize( array $settings ) {
		$current  = self::get_all();
		$defaults = self::get_defaults();

		foreach ( $defaults as $k => $def_val ) {
			if ( isset( $settings[ $k ] ) ) {
				if ( ! is_scalar( $settings[ $k ] ) ) {
					continue; }
				if ( is_bool( $def_val ) ) {
					$current[ $k ] = filter_var( $settings[ $k ], FILTER_VALIDATE_BOOLEAN );
				} else {
					$current[ $k ] = sanitize_text_field( $settings[ $k ] );
				}
			}
		}
		$current['retention']   = (string) min( 3650, max( 0, absint( $current['retention'] ) ) );
		$current['theme']       = in_array( $current['theme'], array( 'light', 'dark', 'system' ), true ) ? $current['theme'] : 'light';
		$current['proxyheader'] = in_array( $current['proxyheader'], array( 'xff', 'cf', 'xreal', 'trueclient' ), true ) ? $current['proxyheader'] : 'xff';

		$current['scan_budget']     = (string) min( 8, max( 1, absint( $current['scan_budget'] ) ) );
		$ranges                     = preg_split( '/[\s,]+/', $current['trusted_proxies'], -1, PREG_SPLIT_NO_EMPTY );
		$current['trusted_proxies'] = implode(
			"\n",
			array_slice(
				array_filter(
					$ranges,
					static function ( $range ) {
						return GWQSH_Network::matches( explode( '/', $range )[0], $range );
					}
				),
				0,
				100
			)
		);
		return $current;
	}
	/**
	 * Persist validated preferences and WordPress's native update selection.
	 *
	 * @param array $settings Changed fields.
	 * @return bool Whether the plugin option changed.
	 */
	public static function update_all( array $settings ) {
		$current = self::normalize( $settings );
		if ( array_key_exists( 'autoupdate', $settings ) ) {
			$plugins = (array) get_site_option( 'auto_update_plugins', array() );
			$plugins = array_values( array_diff( $plugins, array( GWQSH_PLUGIN_BASENAME ) ) );
			if ( $current['autoupdate'] ) {
				$plugins[] = GWQSH_PLUGIN_BASENAME;
			}
			update_site_option( 'auto_update_plugins', $plugins );
		}
		return update_option( self::OPTION_KEY, $current );
	}

	/** Display actual saved findings to administrators when notices are enabled. */
	public static function critical_notice() {
		if ( ! current_user_can( 'manage_options' ) || ! self::get( 'notice', true ) || GWQSH_Admin::current_page() ) {
			return;
		}
		$summary = GWQSH_File_Integrity::get_summary();
		if ( empty( $summary['suspicious'] ) && empty( $summary['missing'] ) ) {
			return;
		}
		echo '<div class="notice notice-warning"><p><a href="' . esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro-file-integrity' ) ) . '">' . esc_html__( 'Security Suite Pro: saved file findings need review. Open File Integrity.', 'gracewell-security-suite-pro' ) . '</a></p></div>';
	}

	/**
	 * Reset defaults.
	 */
	public static function reset_defaults() {
		return self::update_all( self::get_defaults() );
	}
	/**
	 * Get client ip.
	 */
	public static function get_client_ip() {
		$remote = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) {
			return ''; }
		$remote    = GWQSH_Network::canonical( $remote );
		$trusted   = GWQSH_Network::trusted();
		$use_proxy = (bool) self::get( 'proxy', false ) && GWQSH_Network::trusted_ip( $remote, $trusted );
		$header    = self::get( 'proxyheader', 'xff' );

		$ip = '';
		if ( $use_proxy ) {
			if ( 'cf' === $header && GWQSH_Country_Access::cloudflare_peer( $remote ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && is_string( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$ip = sanitize_text_field( filter_var( trim( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ), FILTER_VALIDATE_IP ) );
			} elseif ( 'xreal' === $header && ! empty( $_SERVER['HTTP_X_REAL_IP'] ) && is_string( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$ip = sanitize_text_field( filter_var( trim( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) ), FILTER_VALIDATE_IP ) );
			} elseif ( 'trueclient' === $header && ! empty( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) && is_string( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) {
				$ip = sanitize_text_field( filter_var( trim( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ), FILTER_VALIDATE_IP ) );
			} elseif ( 'xff' === $header && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && is_string( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$ip = self::forwarded_ip( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ), $trusted ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- forwarded_ip bounds and validates every IP before use.
			}
		}

		if ( empty( $ip ) ) {
			$ip = $remote;
		}

		// Validate IP.
		if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return GWQSH_Network::canonical( $ip );
		}

		return $remote;
	}
	/**
	 * Walk an appended forwarding chain from the trusted edge to the nearest visitor.
	 * Client-supplied entries to the left of that visitor cannot choose the lockout IP.
	 *
	 * @param string $header Untrusted X-Forwarded-For value.
	 * @param array  $trusted Explicit trusted proxy addresses.
	 * @return string Valid visitor address, or empty on malformed/excessive evidence.
	 */
	public static function forwarded_ip( $header, array $trusted ) {
		if ( ! is_string( $header ) || strlen( $header ) > 4096 ) {
			return '';
		}
		$parts = explode( ',', $header );
		if ( count( $parts ) > 32 ) {
			return '';
		}
		$peers = array();
		foreach ( $trusted as $peer ) {
			if ( is_string( $peer ) && filter_var( $peer, FILTER_VALIDATE_IP ) ) {
				$peers[] = inet_pton( $peer );
			}
		}
		foreach ( array_reverse( $parts ) as $part ) {
			$ip = trim( $part );
			if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
				return '';
			}
			if ( ! GWQSH_Network::trusted_ip( $ip, $trusted ) ) {
				return $ip;
			}
		}
		return '';
	}

	/**
	 * Is active.
	 */
	public static function is_active() {
		return (bool) self::get( 'status', true );
	}
}
