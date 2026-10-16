<?php
/**
 * Real login protection and brute force defense for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Login Protection implementation.
 */
final class GWQSH_Login_Protection {
	/** Unknown accounts remain protected; exemptions require explicit role configuration. */
	public static function protects_account( $username ) {
		$user = is_email( $username ) ? get_user_by( 'email', $username ) : get_user_by( 'login', $username );
		if ( ! $user || ! $user->roles ) { return true; }
		$rules = self::get_settings()['role_protection'];
		foreach ( $user->roles as $role ) { if ( ! array_key_exists( $role, $rules ) || $rules[$role] ) { return true; } }
		return false;
	}

	private const OPTION_KEY    = 'gwqsh_login_protection';
	private const ALLOWLIST_KEY = 'gwqsh_allowlist';
	/**
	 * Get defaults.
	 */
	public static function get_defaults() {
		return array(
			'enabled'              => true,
			'max_attempts'         => 5,
			'time_window'          => 15, // minutes.
			'lockout_duration'     => 30, // minutes.
			'repeat_lockouts'      => 4,  // times in 24h.
			'repeat_duration'      => 24, // hours.
			'custom_slug'          => 'secure-login',
			'custom_slug_enabled'  => false,
			'generic_errors'       => true,
			'track_username'       => true,
			'email_lockout'        => false,
			'guest_login_behavior' => 'home',
			'guest_admin_behavior' => 'home',
			'role_protection'      => array(),
		);
	}
	/**
	 * Get settings.
	 */
	public static function get_settings() {
		$saved = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return wp_parse_args( $saved, self::get_defaults() );
	}
	/**
	 * Update settings.
	 *
	 * @param array $new_settings New settings.
	 */
	public static function update_settings( array $new_settings ) {
		if ( isset( $new_settings['custom_slug'] ) && ! self::valid_slug( $new_settings['custom_slug'] ) ) {
			return false; }
		$current  = self::get_settings();
		$defaults = self::get_defaults();

		foreach ( $defaults as $k => $def ) {
			if ( isset( $new_settings[ $k ] ) ) {
				if ( 'role_protection' === $k ) {
					if ( ! is_array( $new_settings[$k] ) ) { continue; }
					$current[$k] = array();
					foreach ( $new_settings[$k] as $role => $state ) { if ( isset( wp_roles()->roles[$role] ) && is_bool( $state ) ) { $current[$k][$role] = $state; } }
				} elseif ( is_bool( $def ) ) {
					$current[ $k ] = filter_var( $new_settings[ $k ], FILTER_VALIDATE_BOOLEAN );
				} elseif ( is_numeric( $def ) ) {
					$current[ $k ] = absint( $new_settings[ $k ] );
				} else {
					$current[ $k ] = sanitize_text_field( $new_settings[ $k ] );
				}
			}
		}

		return update_option( self::OPTION_KEY, $current );
	}
	/**
	 * Valid slug.
	 *
	 * @param mixed $slug Slug.
	 */
	public static function valid_slug( $slug ) {
		if ( ! is_string( $slug ) || ! preg_match( '/^[a-z0-9][a-z0-9-]{2,39}$/D', $slug ) ||
			in_array( $slug, array( 'wp-admin', 'wp-login', 'wp-login-php', 'wp-json', 'wp-content', 'wp-includes', 'wp-cron', 'xmlrpc', 'index', 'admin', 'login', 'logout', 'register', 'feed', 'robots', 'favicon' ), true ) ) {
			return false; }
		return ! get_page_by_path( $slug );
	}
	/**
	 * Reset defaults.
	 */
	public static function reset_defaults() {
		return update_option( self::OPTION_KEY, self::get_defaults() );
	}
	/**
	 * Get allowlist.
	 */
	public static function get_allowlist() {
		$ips = get_option( self::ALLOWLIST_KEY, null );
		if ( null === $ips || ! is_array( $ips ) ) {
			$ips = array();
			update_option( self::ALLOWLIST_KEY, $ips );
		}
		return array_values( array_unique( $ips ) );
	}
	/**
	 * Is ip allowlisted.
	 *
	 * @param mixed $ip Ip.
	 */
	public static function is_ip_allowlisted( $ip ) {
		$allowlist = self::get_allowlist();
		if ( in_array( $ip, $allowlist, true ) ) {
			return true;
		}

		// Support CIDR subnet matching (e.g. 192.168.1.0/24).
		foreach ( $allowlist as $allowed ) {
			if ( filter_var( $allowed, FILTER_VALIDATE_IP ) && filter_var( $ip, FILTER_VALIDATE_IP ) && inet_pton( $allowed ) === inet_pton( $ip ) ) {
				return true; }
			if ( false !== strpos( $allowed, '/' ) && self::cidr_match( $ip, $allowed ) ) {
				return true;
			}
		}

		return false;
	}
	/**
	 * Cidr match.
	 *
	 * @param mixed $ip Ip.
	 * @param mixed $cidr Cidr.
	 */
	private static function cidr_match( $ip, $cidr ) {
		$parts = explode( '/', $cidr, 2 );
		if ( 2 !== count( $parts ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) || ! filter_var( $parts[0], FILTER_VALIDATE_IP ) ) {
			return false; }
		$address = inet_pton( $ip );
		$subnet  = inet_pton( $parts[0] );
		if ( strlen( $address ) !== strlen( $subnet ) || ! ctype_digit( $parts[1] ) ) {
			return false; }
		$bits = (int) $parts[1];
		if ( $bits < 0 || $bits > strlen( $address ) * 8 ) {
			return false; }
		$address_length = strlen( $address );
		for ( $i = 0; $i < $address_length; $i++ ) {
			$mask = $bits >= 8 ? 255 : ( $bits <= 0 ? 0 : ( 255 << ( 8 - $bits ) ) & 255 );
			if ( ( ord( $address[ $i ] ) & $mask ) !== ( ord( $subnet[ $i ] ) & $mask ) ) {
				return false; }
			$bits -= 8;
		}
		return true;
	}
	/**
	 * Add to allowlist.
	 *
	 * @param mixed $ip Ip.
	 */
	public static function add_to_allowlist( $ip ) {
		$ip = trim( $ip );
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) && ! ( false !== strpos( $ip, '/' ) && self::cidr_match( explode( '/', $ip )[0], $ip ) ) ) {
			return false; }
		$list = self::get_allowlist();
		if ( ! in_array( $ip, $list, true ) ) {
			$list[] = $ip;
			update_option( self::ALLOWLIST_KEY, $list );
			if ( ! in_array( $ip, self::get_allowlist(), true ) ) {
				return false; }
			GWQSH_Activity_Logger::log( 'IP allowlisted', "IP {$ip} added to allowlist", 'Security' );
			return true;
		}
		return false;
	}
	/**
	 * Remove from allowlist.
	 *
	 * @param mixed $ip Ip.
	 */
	public static function remove_from_allowlist( $ip ) {
		$list = self::get_allowlist();
		$idx  = array_search( $ip, $list, true );
		if ( false !== $idx ) {
			unset( $list[ $idx ] );
			update_option( self::ALLOWLIST_KEY, array_values( $list ) );
			if ( in_array( $ip, self::get_allowlist(), true ) ) {
				return false; }
			GWQSH_Activity_Logger::log( 'IP allowlist updated', "IP {$ip} removed from allowlist", 'Security' );
			return true;
		}
		return false;
	}
	/**
	 * Clear allowlist.
	 */
	public static function clear_allowlist() {
		update_option( self::ALLOWLIST_KEY, array() );
		GWQSH_Activity_Logger::log( 'IP allowlist cleared', 'Allowlist cleared', 'Security' );
		return true;
	}
	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'gwqsh_cleanup_lockouts', array( __CLASS__, 'cleanup_lockouts' ) );
		if ( ! wp_next_scheduled( 'gwqsh_cleanup_lockouts' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'gwqsh_cleanup_lockouts' ); }
		add_filter( 'authenticate', array( __CLASS__, 'check_lockout_before_auth' ), 20, 3 );
		add_action( 'wp_login_failed', array( __CLASS__, 'record_failed_attempt' ), 10, 2 );
		add_action( 'wp_login', array( __CLASS__, 'on_successful_login' ), 10, 2 );
		add_filter( 'login_errors', array( __CLASS__, 'filter_login_errors' ), 10, 1 );
		add_action( 'wp_loaded', array( __CLASS__, 'handle_custom_login_url' ), PHP_INT_MAX );
		add_filter( 'site_url', array( __CLASS__, 'filter_login_url' ), 10, 4 );
		add_filter( 'network_site_url', array( __CLASS__, 'filter_login_url' ), 10, 3 );
	}
	/**
	 * Cleanup lockouts.
	 */
	public static function cleanup_lockouts() {
		global $wpdb;
		$table  = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		$cutoff = current_datetime()->modify( '-2 days' )->format( 'Y-m-d H:i:s' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table identifier from the WordPress prefix; all dynamic values use prepare(). WordPress 5.3 has no %i placeholder.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$table} WHERE last_attempt < %s AND (locked_until IS NULL OR locked_until < %s)", $cutoff, current_time( 'mysql' ) ) );
	}
	/**
	 * Check lockout before auth.
	 *
	 * @param mixed $user User.
	 * @param mixed $username Username.
	 * @param mixed $password Password.
	 */
	public static function check_lockout_before_auth( $user, $username, $password ) {
		if ( ! self::protects_account( $username ) ) { return $user; }
		if ( empty( $username ) && empty( $password ) ) {
			return $user;
		}

		$settings = self::get_settings();
		if ( empty( $settings['enabled'] ) || ! GWQSH_Settings::is_active() ) {
			return $user;
		}

		$ip = GWQSH_Settings::get_client_ip();
		if ( '' === $ip ) {
			return $user; }
		if ( self::is_ip_allowlisted( $ip ) ) {
			return $user;
		}

		if ( self::is_locked( $ip ) ) {
			GWQSH_Activity_Logger::log( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ? 'XML-RPC login blocked' : 'Login blocked by lockout', 'Authentication denied for an actively locked IP.', 'Security', ! empty( $settings['track_username'] ) && $username ? $username : '—', $ip );
			$lock_info = self::get_ip_lock_info( $ip );
			$rem       = self::get_remaining_lockout_text( $lock_info );
			return new WP_Error(
				'gwqsh_locked_out',
				sprintf(
					'<strong>%s:</strong> %s',
					esc_html__( 'ACCESS LOCKED', 'gracewell-security-suite-pro' ),
					/* translators: %s: remaining lockout duration. */
					sprintf( esc_html__( 'Too many failed login attempts from your IP. Access locked for %s.', 'gracewell-security-suite-pro' ), $rem )
				)
			);
		}

		return $user;
	}
	/**
	 * Record failed attempt.
	 *
	 * @param mixed $username Username.
	 * @param mixed $error Error.
	 */
	public static function record_failed_attempt( $username, $error = null ) {
		if ( ! self::protects_account( $username ) ) { return; }
		// A successful password check followed by a second-factor challenge is not a failure.
		if ( ( is_wp_error( $error ) && in_array( 'gwqsh_2fa_required', $error->get_error_codes(), true ) ) ||
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only authentication/routing hook; WordPress authenticates credentials, and no setting is changed by this input.
			( null === $error && ! empty( $GLOBALS['gwqsh_2fa_prompt'] ) && empty( $_POST['gwqsh_2fa_code'] ) ) ) {
			return; }
		$settings = self::get_settings();
		if ( empty( $settings['enabled'] ) || ! GWQSH_Settings::is_active() ) {
			return;
		}

		$ip = GWQSH_Settings::get_client_ip();
		if ( '' === $ip ) {
			return; }
		if ( self::is_ip_allowlisted( $ip ) ) {
			return;
		}

		// Already locked requests must not extend the expiry or create repeat-lockout events.
		if ( self::is_locked( $ip ) ) {
			return; }
		global $wpdb;
		$table  = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		$now    = current_time( 'mysql' );
		$cutoff = current_datetime()->modify( '-' . max( 1, absint( $settings['time_window'] ) ) . ' minutes' )->format( 'Y-m-d H:i:s' );
		// Atomic counter update preserves the existing per-IP limit under concurrent failures.
		// phpcs:disable WordPress.DB -- Prepared atomic security counter; fixed plugin-owned table identifier.
		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (ip_address, failed_attempts, first_attempt, last_attempt, is_locked) VALUES (%s, 1, %s, %s, 0)
			ON DUPLICATE KEY UPDATE failed_attempts = IF((locked_until IS NOT NULL AND locked_until <= %s) OR (is_locked = 0 AND (first_attempt IS NULL OR first_attempt <= %s)), 1, failed_attempts + 1), first_attempt = IF((locked_until IS NOT NULL AND locked_until <= %s) OR (is_locked = 0 AND (first_attempt IS NULL OR first_attempt <= %s)), %s, first_attempt), last_attempt = %s, is_locked = IF(locked_until IS NOT NULL AND locked_until <= %s, 0, is_locked), locked_until = IF(locked_until IS NOT NULL AND locked_until <= %s, NULL, locked_until)",
				$ip,
				$now,
				$now,
				$now,
				$cutoff,
				$now,
				$cutoff,
				$now,
				$now,
				$now,
				$now
			)
		);
		// phpcs:enable WordPress.DB
		$row = self::get_ip_lock_info( $ip );
		if ( ! $row || (int) $row['is_locked'] || (int) $row['failed_attempts'] < max( 1, absint( $settings['max_attempts'] ) ) ) {
			return; }
		$events    = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$since     = current_datetime()->modify( '-24 hours' )->format( 'Y-m-d H:i:s' );
		$prior     = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$events} WHERE event_name = %s AND ip_address = %s AND event_time >= %s", 'IP locked out', $ip, $since ) ); // phpcs:ignore WordPress.DB -- Prepared event and IP filters.
		$escalated = $prior + 1 >= max( 1, absint( $settings['repeat_lockouts'] ) );
		$minutes   = $escalated ? max( 1, absint( $settings['repeat_duration'] ) ) * 60 : max( 1, absint( $settings['lockout_duration'] ) );
		$until     = current_datetime()->modify( '+' . $minutes . ' minutes' )->format( 'Y-m-d H:i:s' );
		$won       = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET is_locked = 1, locked_until = %s WHERE ip_address = %s AND is_locked = 0", $until, $ip ) ); // phpcs:ignore WordPress.DB -- Only the winning request logs/emails a lockout.
		if ( 1 !== $won ) {
			return; }
		$logged_user = ! empty( $settings['track_username'] ) && $username ? $username : '—';
		GWQSH_Activity_Logger::log( 'IP locked out', sprintf( '%d failed attempts. Locked for %d minutes.%s', $row['failed_attempts'], $minutes, $escalated ? ' Repeat-lockout escalation.' : '' ), 'Security', $logged_user, $ip );
		if ( ! empty( $settings['email_lockout'] ) ) {
			$sent = wp_mail( get_option( 'admin_email' ), 'Security Suite Pro: login IP locked out', sprintf( 'Security Suite Pro locked IP %s until %s after %d failed attempts. Review Login Protection in WordPress admin.', $ip, $until, $row['failed_attempts'] ) );
			if ( ! $sent ) {
				GWQSH_Activity_Logger::log( 'Lockout alert failed', 'The site mail transport could not send the administrator lockout alert.', 'System' ); }
		}
	}
	/**
	 * On successful login.
	 *
	 * @param mixed $user_login User login.
	 * @param mixed $user User.
	 */
	public static function on_successful_login( $user_login, $user ) {
		if ( ! self::protects_account( $user_login ) ) { return; }
		$ip = GWQSH_Settings::get_client_ip();
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$wpdb->delete( $table, array( 'ip_address' => $ip ) );
	}
	/**
	 * Filter login errors.
	 *
	 * @param mixed $error Error.
	 */
	public static function filter_login_errors( $error ) {
		$settings = self::get_settings();
		if ( ! empty( $settings['generic_errors'] ) && ! empty( $error ) ) {
			// Keep locked out notice intact if locked.
			if ( false !== strpos( $error, 'gwqsh_locked_out' ) || false !== strpos( $error, 'ACCESS LOCKED' ) || false !== strpos( $error, 'Two-Factor Authentication Required' ) || false !== strpos( $error, '2FA code' ) ) {
				return $error;
			}
			return '<strong>' . esc_html__( 'Error:', 'gracewell-security-suite-pro' ) . '</strong> ' . esc_html__( 'Invalid username or password.', 'gracewell-security-suite-pro' );
		}
		return $error;
	}
	/**
	 * Handle custom login url.
	 */
	public static function handle_custom_login_url() {
		if ( defined( 'GWQSH_DISABLE_LOGIN_URL' ) && GWQSH_DISABLE_LOGIN_URL ) {
			return;
		}
		$settings = self::get_settings();
		if ( ! GWQSH_Settings::is_active() || empty( $settings['custom_slug_enabled'] ) || ! self::valid_slug( $settings['custom_slug'] ) ) {
			return;
		}
		if ( wp_doing_ajax() || ( defined( 'DOING_CRON' ) && DOING_CRON ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return; }

		$slug          = trim( $settings['custom_slug'] );
		$request_uri   = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		$path          = wp_parse_url( $request_uri, PHP_URL_PATH );
		$path          = trim( (string) $path, '/' );
		$custom_path   = trim( (string) wp_parse_url( self::custom_login_url( $slug ), PHP_URL_PATH ), '/' );
		$legacy_path   = trim( (string) wp_parse_url( home_url( '/' . $slug . '/' ), PHP_URL_PATH ), '/' );
		$default_path  = trim( (string) wp_parse_url( get_option( 'siteurl' ) . '/wp-login.php', PHP_URL_PATH ), '/' );
		$admin_path    = trim( (string) wp_parse_url( get_option( 'siteurl' ) . '/wp-admin', PHP_URL_PATH ), '/' );
		$is_admin_path = $path === $admin_path || 0 === strpos( $path, $admin_path . '/' );
		$internal      = in_array( $path, array( $admin_path . '/admin-ajax.php', $admin_path . '/admin-post.php' ), true );
		if ( $is_admin_path && ! $internal && ! is_user_logged_in() ) {
			wp_safe_redirect( 'login' === $settings['guest_admin_behavior'] ? wp_login_url( admin_url() ) : home_url( '/' ) );
			exit;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only authentication/routing hook; WordPress authenticates credentials, and no setting is changed by this input.
		if ( isset( $_GET['gwqsh_recover'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only authentication/routing hook; WordPress authenticates credentials, and no setting is changed by this input.
			$given = sanitize_text_field( wp_unslash( $_GET['gwqsh_recover'] ) );
			if ( hash_equals( self::recovery_key(), $given ) ) {
				set_transient( 'gwqsh_recovery_' . hash( 'sha256', GWQSH_Settings::get_client_ip() ), 1, 15 * MINUTE_IN_SECONDS );
				wp_safe_redirect( site_url( 'wp-login.php' ) );
				exit;
			}
		}

		// Serve the real WordPress login at the exact custom path, including POSTs.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Public login-route selection only; native authentication still verifies credentials and factors.
		$requested_slug = isset( $_GET['gwqsh_login'] ) && is_string( $_GET['gwqsh_login'] ) ? sanitize_text_field( wp_unslash( $_GET['gwqsh_login'] ) ) : '';
		$query_route    = ! get_option( 'permalink_structure' ) && $requested_slug === $slug && trim( (string) wp_parse_url( home_url( '/' ), PHP_URL_PATH ), '/' ) === $path;
		if ( ( get_option( 'permalink_structure' ) && $path === $custom_path ) || $path === $legacy_path || $query_route ) {
			global $pagenow, $error, $action, $interim_login, $user_login, $redirect_to;
			// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Custom login dispatch must identify the native wp-login.php context before loading its unchanged authentication handler.
			$pagenow = 'wp-login.php';
			require ABSPATH . 'wp-login.php';
			exit;
		}

		// If direct wp-login.php accessed without token.
		if ( $path === $default_path && ! is_user_logged_in() ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only authentication/routing hook; WordPress authenticates credentials, and no setting is changed by this input.
			$login_action = isset( $_REQUEST['action'] ) ? sanitize_key( wp_unslash( $_REQUEST['action'] ) ) : 'login';
			// Let WordPress validate reset keys, logout nonces and internal confirmation requests.
			if ( in_array( $login_action, array( 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'confirm_admin_email', 'confirmaction', 'postpass', 'checkemail' ), true ) ) {
				return; }
			$recovery = get_transient( 'gwqsh_recovery_' . hash( 'sha256', GWQSH_Settings::get_client_ip() ) );
			if ( ! $recovery ) {
				if ( '404' === $settings['guest_login_behavior'] ) {
					GWQSH_UI::error( 404, 'Page not found', 'The requested login page is not available.' ); }
				// Preserve the original redirect-home behavior by default.
				wp_safe_redirect( home_url( '/' ) );
				exit;
			}
		}
	}
	/**
	 * Return a login route that also works with plain WordPress permalinks.
	 *
	 * @param string $slug Validated custom slug, or an empty string for the saved slug.
	 * @return string Custom login URL.
	 */
	public static function custom_login_url( $slug = '' ) {
		if ( '' === $slug ) {
			$slug = self::get_settings()['custom_slug'];
		}
		return self::custom_login_base() . $slug . ( get_option( 'permalink_structure' ) ? '/' : '' );
	}
	/**
	 * Return the custom login prefix for plain, index and pretty permalinks.
	 *
	 * @return string Login route prefix.
	 */
	public static function custom_login_base() {
		$structure = (string) get_option( 'permalink_structure' );
		if ( '' === $structure ) {
			return home_url( '/' ) . '?gwqsh_login=';
		}
		return home_url( 0 === strpos( $structure, '/index.php/' ) ? '/index.php/' : '/' );
	}
	/**
	 * Filter login url.
	 *
	 * @param mixed $url Url.
	 * @param mixed $path Path.
	 * @param mixed $scheme Scheme.
	 * @param mixed $blog_id Blog id.
	 */
	public static function filter_login_url( $url, $path = '', $scheme = null, $blog_id = null ) {
		if ( defined( 'GWQSH_DISABLE_LOGIN_URL' ) && GWQSH_DISABLE_LOGIN_URL ) {
			return $url; }
		$settings = self::get_settings();
		if ( ! GWQSH_Settings::is_active() || empty( $settings['custom_slug_enabled'] ) || ! self::valid_slug( $settings['custom_slug'] ) ) {
			return $url; }
		$login_url = self::custom_login_url( $settings['custom_slug'] );
		$query     = array();
		parse_str( (string) wp_parse_url( $url, PHP_URL_QUERY ), $query );
		// Reset cookies are scoped to the requested path; keep recovery form actions on that path.
		if ( isset( $query['action'] ) && is_string( $query['action'] ) && in_array( $query['action'], array( 'logout', 'lostpassword', 'retrievepassword', 'resetpass', 'rp', 'confirm_admin_email', 'confirmaction', 'postpass', 'checkemail' ), true ) ) {
			$request_path = isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] ) ? wp_parse_url( esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ), PHP_URL_PATH ) : '';
			$custom_path  = wp_parse_url( $login_url, PHP_URL_PATH );
			$legacy_url   = home_url( '/' . $settings['custom_slug'] . '/' );
			$legacy_path  = wp_parse_url( $legacy_url, PHP_URL_PATH );
			if ( ! in_array( $query['action'], array( 'resetpass', 'rp' ), true ) || ! in_array( rtrim( (string) $request_path, '/' ), array( rtrim( (string) $custom_path, '/' ), rtrim( (string) $legacy_path, '/' ) ), true ) ) {
				return $url; }
			if ( rtrim( (string) $request_path, '/' ) === rtrim( (string) $legacy_path, '/' ) ) {
				$login_url = $legacy_url;
			}
		}
		$default = get_option( 'siteurl' ) . '/wp-login.php';
		if ( 0 === strpos( $url, $default ) && in_array( substr( $url, strlen( $default ), 1 ), array( '', '?' ), true ) ) {
			$suffix = substr( $url, strlen( $default ) );
			if ( false !== strpos( $login_url, '?' ) && 0 === strpos( $suffix, '?' ) ) {
				$suffix = '&' . substr( $suffix, 1 );
			}
			return $login_url . $suffix;
		}
		return $url;
	}
	/**
	 * Recovery key.
	 */
	public static function recovery_key() {
		$seed = get_option( 'gwqsh_recovery_seed', '' );
		if ( ! is_string( $seed ) || ! preg_match( '/^[a-f0-9]{64}$/', $seed ) ) {
			$seed = bin2hex( random_bytes( 32 ) );
			update_option( 'gwqsh_recovery_seed', $seed, false );
		}
		return hash_hmac( 'sha256', $seed, wp_salt( 'auth' ) );
	}
	/**
	 * Recovery url.
	 */
	public static function recovery_url() {
		return add_query_arg( 'gwqsh_recover', self::recovery_key(), home_url( '/' ) );
	}
	/**
	 * Rotate recovery key.
	 */
	public static function rotate_recovery_key() {
		update_option( 'gwqsh_recovery_seed', bin2hex( random_bytes( 32 ) ), false );
		return self::recovery_url();
	}
	/**
	 * Is locked.
	 *
	 * @param mixed $ip Ip.
	 */
	public static function is_locked( $ip ) {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		$now   = current_time( 'mysql' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$locked = $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed plugin-owned table identifier from the WordPress prefix; all dynamic values use prepare(). WordPress 5.3 has no %i placeholder.
				"SELECT id FROM {$table} WHERE ip_address = %s AND is_locked = 1 AND locked_until > %s",
				$ip,
				$now
			)
		);

		return ! empty( $locked );
	}
	/**
	 * Get ip lock info.
	 *
	 * @param mixed $ip Ip.
	 */
	public static function get_ip_lock_info( $ip ) {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table identifier from the WordPress prefix; all dynamic values use prepare(). WordPress 5.3 has no %i placeholder.
		return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE ip_address = %s", $ip ), ARRAY_A );
	}
	/**
	 * Get remaining lockout text.
	 *
	 * @param mixed $row Row.
	 */
	public static function get_remaining_lockout_text( $row ) {
		if ( ! $row || empty( $row['locked_until'] ) ) {
			return '30 minutes';
		}
		$rem_sec = max( 0, GWQSH_Time::timestamp( $row['locked_until'] ) - time() );
		if ( $rem_sec > 3600 ) {
			return round( $rem_sec / 3600 ) . ' hours';
		} elseif ( $rem_sec > 60 ) {
			return round( $rem_sec / 60 ) . ' minutes';
		}
		return $rem_sec . ' seconds';
	}
	/**
	 * Get currently locked ips.
	 */
	public static function get_currently_locked_ips() {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		$now   = current_time( 'mysql' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT ip_address, failed_attempts, locked_until FROM {$table} WHERE is_locked = 1 AND locked_until > %s ORDER BY locked_until DESC", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Validated or fixed plugin-owned identifier; dynamic values are prepared, and WordPress 5.3 has no identifier placeholder.
				$now
			),
			ARRAY_A
		);

		$out = array();
		if ( $rows ) {
			foreach ( $rows as $r ) {
				$rem_sec   = max( 0, GWQSH_Time::timestamp( $r['locked_until'] ) - time() );
				$rem_text  = $rem_sec > 3600 ? round( $rem_sec / 3600 ) . ' hours' : ( round( $rem_sec / 60 ) . ' minutes' );
				$until_fmt = GWQSH_Time::format( $r['locked_until'], 'M d, g:i A' );
				$out[]     = array(
					'ip'        => $r['ip_address'],
					'attempts'  => (int) $r['failed_attempts'],
					'until'     => $until_fmt,
					'remaining' => $rem_text,
				);
			}
		}
		return $out;
	}
	/**
	 * Unlock ip.
	 *
	 * @param mixed $ip Ip.
	 */
	public static function unlock_ip( $ip ) {
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return false; }
		global $wpdb;
		$table   = esc_sql( $wpdb->prefix . 'gwqsh_lockouts' );
		$updated = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET is_locked = 0, failed_attempts = 0, first_attempt = NULL, locked_until = NULL WHERE ip_address = %s AND is_locked = 1", $ip ) ); // phpcs:ignore WordPress.DB -- Prepared IP; selected record only.
		if ( 1 !== $updated ) {
			return false; }
		GWQSH_Activity_Logger::log( 'IP unlocked', "Manual unlock for IP {$ip}", 'Security', null, $ip );
		return true;
	}
	/**
	 * Get failed attempts 24h.
	 */
	public static function get_failed_attempts_24h() {
		global $wpdb;
		$table  = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$cutoff = current_datetime()->modify( '-24 hours' )->format( 'Y-m-d H:i:s' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
		return (int) $wpdb->get_var(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed plugin-owned table identifier from the WordPress prefix; all dynamic values use prepare(). WordPress 5.3 has no %i placeholder.
				"SELECT COUNT(*) FROM {$table} WHERE event_name = 'Login attempt blocked' AND event_time >= %s",
				$cutoff
			)
		);
	}
	/**
	 * Get activity chart data.
	 *
	 * @param mixed $days Days.
	 */
	public static function get_activity_chart_data( $days = 7 ) {
		global $wpdb;
		$table  = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$days   = absint( $days );
		$cutoff = current_datetime()->modify( '-' . absint( $days ) . ' days' )->format( 'Y-m-d 00:00:00' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT DATE(event_time) as d, event_name, COUNT(*) as c FROM {$table} WHERE event_time >= %s AND event_name IN ('Login successful', 'Login attempt blocked') GROUP BY DATE(event_time), event_name", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Validated or fixed plugin-owned identifier; dynamic values are prepared, and WordPress 5.3 has no identifier placeholder.
				$cutoff
			),
			ARRAY_A
		);

		$date_map = array();
		for ( $i = $days - 1; $i >= 0; $i-- ) {
			$dt              = current_datetime()->modify( '-' . absint( $i ) . ' days' )->format( 'Y-m-d' );
			$lbl             = current_datetime()->modify( '-' . absint( $i ) . ' days' )->format( 'M j' );
			$date_map[ $dt ] = array(
				'label'   => $lbl,
				'success' => 0,
				'blocked' => 0,
			);
		}

		if ( $rows ) {
			foreach ( $rows as $r ) {
				$dt = $r['d'];
				if ( isset( $date_map[ $dt ] ) ) {
					if ( 'Login successful' === $r['event_name'] ) {
						$date_map[ $dt ]['success'] += (int) $r['c'];
					} else {
						$date_map[ $dt ]['blocked'] += (int) $r['c'];
					}
				}
			}
		}

		$labels     = array();
		$successful = array();
		$blocked    = array();

		foreach ( $date_map as $item ) {
			$labels[]     = $item['label'];
			$successful[] = $item['success'];
			$blocked[]    = $item['blocked'];
		}

		return array(
			'labels'     => $labels,
			'successful' => $successful,
			'blocked'    => $blocked,
		);
	}
}
