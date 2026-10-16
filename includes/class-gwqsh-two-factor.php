<?php
/**
 * Real Two-Factor Authentication (TOTP RFC 6238) for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Two Factor implementation.
 */
final class GWQSH_Two_Factor {
	/** Enrollment coverage without decrypting every account's secret on each page. */
	public static function coverage_counts() {
		$cached = get_transient( 'gwqsh_tf_coverage' );
		if ( is_array( $cached ) ) {
			return $cached; }
		global $wpdb;
		$row    = $wpdb->get_row( "SELECT COUNT(*) AS total, SUM(EXISTS(SELECT 1 FROM {$wpdb->usermeta} e WHERE e.user_id=u.ID AND e.meta_key='gwqsh_2fa_enabled' AND e.meta_value='1') AND EXISTS(SELECT 1 FROM {$wpdb->usermeta} s WHERE s.user_id=u.ID AND s.meta_key='gwqsh_2fa_secret' AND s.meta_value<>'')) AS enabled FROM {$wpdb->users} u", ARRAY_A );
		$result = array(
			'total'   => (int) ( $row['total'] ?? 0 ),
			'enabled' => (int) ( $row['enabled'] ?? 0 ),
		);
		set_transient( 'gwqsh_tf_coverage', $result, 30 );
		return $result;
	}

	private const B32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
	/**
	 * Init.
	 */
	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'resume_challenge' ), 19, 3 );
		add_filter( 'authenticate', array( __CLASS__, 'intercept_2fa_login' ), 50, 3 );
		add_action( 'login_form', array( __CLASS__, 'add_2fa_login_field' ) );
		foreach ( array( 'added_user_meta', 'updated_user_meta', 'deleted_user_meta' ) as $hook ) {
			add_action( $hook, array( 'GWQSH_Two_Factor_View_Data', 'metadata_changed' ), 10, 3 ); }
		foreach ( array( 'user_register', 'deleted_user', 'set_user_role', 'update_option_gwqsh_two_factor_settings' ) as $hook ) {
			add_action( $hook, array( 'GWQSH_Two_Factor_View_Data', 'invalidate' ) ); }
		add_action( 'template_redirect', array( __CLASS__, 'restrict_incomplete_setup' ), 0 );
		add_action( 'admin_init', array( __CLASS__, 'restrict_incomplete_setup' ), 0 );
		add_action( 'wp_authenticate_application_password_errors', array( __CLASS__, 'application_password_policy' ), 10, 4 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'restrict_rest' ), 10, 3 );
	}
	/** Noninteractive credentials cannot silently bypass a required or enrolled factor. */
	public static function application_password_policy( $error, $user, $item, $password ) {
		if ( $user instanceof WP_User && ( self::required( $user->ID ) || self::effective_enabled( $user->ID ) ) ) {
			$error->add( 'gwqsh_app_password_restricted', 'Application passwords are restricted for accounts protected by two-factor authentication.' );
		}
	}
	/**
	 * Get settings.
	 */
	public static function get_settings() {
		return array_intersect_key(
			wp_parse_args(
				(array) get_option( 'gwqsh_two_factor_settings', array() ),
				array(
					'require_admin'     => false,
					'allow_roles'       => true,
					'remember_device'   => true,
					'allow_admin_reset' => true,
					'enforce_roles'     => false,
					'required_roles'    => array(),
				)
			),
			array_flip( array( 'require_admin', 'allow_roles', 'remember_device', 'allow_admin_reset', 'enforce_roles', 'required_roles' ) )
		);
	}
	/**
	 * Required.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function required( $user_id ) {
		$policy = self::get_settings();
		$user   = get_userdata( $user_id );
		if ( ! $user ) {
			return false; }
		return ( get_user_meta( $user_id, 'gwqsh_2fa_required', true ) ||
			( ! empty( $policy['require_admin'] ) && user_can( $user_id, 'manage_options' ) ) ||
			( ! empty( $policy['enforce_roles'] ) && array_intersect( (array) $policy['required_roles'], $user->roles ) ) );
	}
	/**
	 * Effective enabled.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function effective_enabled( $user_id ) {
		return self::is_user_2fa_enabled( $user_id );
	}
	/**
	 * Needs setup.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function needs_setup( $user_id ) {
		return $user_id && self::required( $user_id ) && ! self::is_user_2fa_enabled( $user_id );
	}
	/**
	 * Restrict incomplete setup.
	 */
	public static function restrict_incomplete_setup() {
		if ( ! self::needs_setup( get_current_user_id() ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
			return; }
		if ( wp_doing_ajax() ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Authentication/setup routing hook; password-issued expiring challenge validates factor requests, and AJAX dispatch verifies its nonce separately.
			$action = isset( $_POST['action'] ) ? sanitize_key( wp_unslash( $_POST['action'] ) ) : '';
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Authentication/setup routing hook; password-issued expiring challenge validates factor requests, and AJAX dispatch verifies its nonce separately.
			$sub = isset( $_POST['subaction'] ) ? sanitize_key( wp_unslash( $_POST['subaction'] ) ) : '';
			if ( 'gwqsh_action' === $action && in_array( $sub, self::self_service_actions(), true ) ) {
				return; }
			wp_send_json_error( array( 'message' => 'Complete your required 2FA setup first.' ), 403 );
		}
		if ( 'two-factor' === GWQSH_Admin::current_page() ) {
			return; }
		wp_safe_redirect( admin_url( 'admin.php?page=gracewell-security-suite-pro-two-factor' ) );
		exit;
	}
	/**
	 * Restrict rest.
	 *
	 * @param mixed $result Result.
	 * @param mixed $server Server.
	 * @param mixed $request Request.
	 */
	public static function restrict_rest( $result, $server, $request ) {
		return self::needs_setup( get_current_user_id() ) ? new WP_Error( 'gwqsh_setup_required', 'Complete your required 2FA setup first.', array( 'status' => 403 ) ) : $result;
	}
	/**
	 * Self service actions.
	 */
	public static function self_service_actions() {
		return array( 'passkey_list', 'passkey_create_options', 'passkey_create_verify', 'passkey_rename', 'passkey_remove', 'recovery_data', 'recovery_setup_send', 'recovery_setup_verify', 'recovery_remove', 'get_2fa_data', 'generate_2fa_secret', 'confirm_2fa_secret', 'enable_user_2fa', 'disable_own_2fa', 'generate_backup_codes', 'remove_trusted_device', 'get_user_2fa_devices' );
	}

	/*
	-------------------------------------------------------------
		Base32 & RFC 6238 TOTP implementation
		-------------------------------------------------------------
	 */
	/**
	 * Generate secret.
	 *
	 * @param mixed $length Length.
	 */
	public static function generate_secret( $length = 32 ) {
		$secret = '';
		$chars  = self::B32_CHARS;
		$max    = strlen( $chars ) - 1;
		for ( $i = 0; $i < $length; $i++ ) {
			$secret .= $chars[ random_int( 0, $max ) ];
		}
		return $secret;
	}
	/**
	 * Base32 decode.
	 *
	 * @param mixed $b32 B32.
	 */
	public static function base32_decode( $b32 ) {
		$b32       = strtoupper( trim( $b32 ) );
		$chars     = self::B32_CHARS;
		$buffer    = 0;
		$bits_left = 0;
		$output    = '';

		for ( $i = 0, $len = strlen( $b32 ); $i < $len; $i++ ) {
			$val = strpos( $chars, $b32[ $i ] );
			if ( false === $val ) {
				continue;
			}
			$buffer     = ( $buffer << 5 ) | $val;
			$bits_left += 5;
			if ( $bits_left >= 8 ) {
				$bits_left -= 8;
				$output    .= chr( ( $buffer >> $bits_left ) & 0xFF );
			}
		}

		return $output;
	}
	/**
	 * Calculate totp.
	 *
	 * @param mixed $secret Secret.
	 * @param mixed $time_slice Time slice.
	 */
	public static function calculate_totp( $secret, $time_slice = null ) {
		if ( null === $time_slice ) {
			$time_slice = floor( time() / 30 );
		}

		$secret_bin = self::base32_decode( $secret );
		$time_bin   = pack( 'N*', 0 ) . pack( 'N*', $time_slice );
		$hmac       = hash_hmac( 'sha1', $time_bin, $secret_bin, true );

		$offset    = ord( $hmac[ strlen( $hmac ) - 1 ] ) & 0x0F;
		$hash_part = substr( $hmac, $offset, 4 );

		$value = unpack( 'N', $hash_part );
		$value = $value[1] & 0x7FFFFFFF;

		return str_pad( (string) ( $value % 1000000 ), 6, '0', STR_PAD_LEFT );
	}
	/**
	 * Verify totp.
	 *
	 * @param mixed $secret Secret.
	 * @param mixed $code Code.
	 * @param mixed $discrepancy Discrepancy.
	 */
	public static function verify_totp( $secret, $code, $discrepancy = 1 ) {
		if ( ! is_string( $secret ) || ! preg_match( '/^[A-Z2-7]{16,}$/D', $secret ) ) {
			return false; }
		$code = trim( (string) $code );
		if ( 6 !== strlen( $code ) || ! ctype_digit( $code ) ) {
			return false;
		}

		$current_slice = floor( time() / 30 );
		for ( $i = -$discrepancy; $i <= $discrepancy; $i++ ) {
			$expected = self::calculate_totp( $secret, $current_slice + $i );
			if ( hash_equals( $expected, $code ) ) {
				return true;
			}
		}

		return false;
	}
	/**
	 * Get totp uri.
	 *
	 * @param mixed $username Username.
	 * @param mixed $secret Secret.
	 */
	public static function get_totp_uri( $username, $secret ) {
		$issuer = get_bloginfo( 'name' );
		if ( empty( $issuer ) ) {
			$issuer = 'Gracewell Security Suite Pro';
		}
		return sprintf(
			'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
			rawurlencode( $issuer ),
			rawurlencode( $username ),
			$secret,
			rawurlencode( $issuer )
		);
	}

	/*
	-------------------------------------------------------------
		Backup Codes
		-------------------------------------------------------------
	 */
	/**
	 * Generate backup codes.
	 *
	 * @param mixed $count Count.
	 */
	public static function generate_backup_codes( $count = 10 ) {
		$alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
		$codes    = array();
		for ( $i = 0; $i < $count; $i++ ) {
			$part1 = '';
			$part2 = '';
			for ( $j = 0; $j < 4; $j++ ) {
				$part1 .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
				$part2 .= $alphabet[ random_int( 0, strlen( $alphabet ) - 1 ) ];
			}
			$codes[] = $part1 . '-' . $part2;
		}
		return $codes;
	}
	/**
	 * Get user backup codes.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function get_user_backup_codes( $user_id ) {
		$codes = self::get_stored_backup_codes( $user_id );
		return array_map(
			static function ( $record ) use ( $user_id ) {

				$out = array( 'used' => ! empty( $record['used'] ) );
				if ( empty( $record['used'] ) && get_current_user_id() === (int) $user_id && ! empty( $record['display'] ) ) {
					$code = GWQSH_Crypto::decrypt( $record['display'] );
					if ( $code ) {
						$out['code'] = $code; }
				}
				return $out;
			},
			$codes
		);
	}
	/**
	 * Get stored backup codes.
	 *
	 * @param mixed $user_id User id.
	 */
	private static function get_stored_backup_codes( $user_id ) {
		$codes = get_user_meta( $user_id, 'gwqsh_backup_codes', true );
		if ( ! is_array( $codes ) ) {
			return array();
		}
		$migrated = false;
		foreach ( $codes as &$record ) {
			if ( is_array( $record ) && ! empty( $record['used'] ) && ( isset( $record['hash'] ) || isset( $record['display'] ) || isset( $record['code'] ) ) ) {
				unset( $record['hash'], $record['display'], $record['code'] );
				$migrated = true;
			}
			if ( is_array( $record ) && ! empty( $record['code'] ) && empty( $record['hash'] ) ) {
				$record['hash'] = 'sha256-site:' . hash_hmac( 'sha256', strtoupper( trim( $record['code'] ) ), GWQSH_Crypto::get_site_salt() );
				if ( empty( $record['used'] ) ) {
					$record['display'] = GWQSH_Crypto::encrypt( strtoupper( trim( $record['code'] ) ) ); }
				unset( $record['code'] );
				$migrated = true;
			}
			if ( ! is_array( $record ) || ( empty( $record['used'] ) && empty( $record['hash'] ) ) ) {
				return array(); }
		}
		unset( $record );
		if ( $migrated ) {
			update_user_meta( $user_id, 'gwqsh_backup_codes', $codes ); }
		return $codes;
	}
	/**
	 * Save user backup codes.
	 *
	 * @param mixed $user_id User id.
	 * @param array $codes Codes.
	 */
	public static function save_user_backup_codes( $user_id, array $codes ) {
		// Verification hashes and authenticated encrypted display copies share one atomic record.
		$records = array();
		foreach ( $codes as $c ) {
			$encrypted = GWQSH_Crypto::encrypt( $c );
			if ( false === $encrypted ) {
				return false; }
			$records[] = array(
				'display' => $encrypted,
				'hash'    => 'sha256-site:' . hash_hmac( 'sha256', strtoupper( trim( $c ) ), GWQSH_Crypto::get_site_salt() ),
				'used'    => false,
			);
		}
		if ( false === update_user_meta( $user_id, 'gwqsh_backup_codes', $records ) ) {
			return false; }
		return array_map(
			static function ( $code ) {
				return array(
					'code' => $code,
					'used' => false,
				);
			},
			$codes
		);
	}
	/**
	 * Verify and burn backup code.
	 *
	 * @param mixed $user_id User id.
	 * @param mixed $code Code.
	 */
	public static function verify_and_burn_backup_code( $user_id, $code ) {
		$records = self::get_stored_backup_codes( $user_id );
		if ( empty( $records ) ) {
			return false;
		}

		$code = strtoupper( trim( $code ) );
		foreach ( $records as $idx => $rec ) {
			$matches = ! empty( $rec['hash'] ) && self::matches_backup_hash( $rec['hash'], $code );
			if ( empty( $rec['used'] ) && $matches ) {
				$previous                = $records;
				$records[ $idx ]['used'] = true;
				unset( $records[ $idx ]['hash'], $records[ $idx ]['display'] );
				if ( ! self::compare_and_swap_meta( $user_id, 'gwqsh_backup_codes', $previous, $records ) ) {
					return false; }
				GWQSH_Activity_Logger::log( 'Backup code used', 'Single-use 2FA backup code used for login', 'Security', get_userdata( $user_id )->user_login );
				return true;
			}
		}

		return false;
	}

	/**
	 * Read released Free and legacy Pro recovery verifiers without rewriting them.
	 *
	 * @param string $hash Stored verifier.
	 * @param string $code Normalized recovery code.
	 * @return bool Whether the verifier matches.
	 */
	private static function matches_backup_hash( $hash, $code ) {
		if ( 0 === strpos( $hash, 'sha256-site:' ) || 0 === strpos( $hash, 'sha256:' ) ) {
			$tag = 0 === strpos( $hash, 'sha256-site:' ) ? 'sha256-site:' : 'sha256:';
			try {
				if ( hash_equals( $hash, $tag . hash_hmac( 'sha256', $code, GWQSH_Crypto::get_site_salt() ) ) ) {
					return true;
				}
			} catch ( Throwable $error ) {
				// A missing Free key must not authorize a site-salt verifier.
				if ( 'sha256-site:' === $tag ) {
					return false;
				}
			}
			return 'sha256:' === $tag && hash_equals( $hash, 'sha256:' . hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ) );
		}
		return wp_check_password( $code, $hash );
	}

	/**
	 * Atomic consumption prevents concurrent requests from reusing the same factor.
	 *
	 * @param mixed $user_id User id.
	 * @param mixed $key Key.
	 * @param mixed $old Old.
	 * @param mixed $new New.
	 */
	public static function compare_and_swap_meta( $user_id, $key, $old, $new ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Atomic compare-and-swap on usermeta requires direct query; cache invalidated immediately below.
		$changed = $wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->usermeta} SET meta_value = %s WHERE user_id = %d AND meta_key = %s AND meta_value = %s",
				maybe_serialize( $new ),
				$user_id,
				$key,
				maybe_serialize( $old )
			)
		);
		wp_cache_delete( $user_id, 'user_meta' );
		if ( 1 === $changed && 'gwqsh_trusted_devices' === $key ) {
			GWQSH_Two_Factor_View_Data::invalidate(); }
		return 1 === $changed;
	}

	/*
	-------------------------------------------------------------
		User 2FA State Management
		-------------------------------------------------------------
	 */
	/**
	 * Is user 2fa enabled.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function is_user_2fa_enabled( $user_id ) {
		return (bool) get_user_meta( $user_id, 'gwqsh_2fa_enabled', true );
	}
	/**
	 * Get user secret.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function get_user_secret( $user_id ) {
		$stored = get_user_meta( $user_id, 'gwqsh_2fa_secret', true );
		if ( is_string( $stored ) && preg_match( '/^(?:gwqsh1|gqs1):/', $stored ) ) {
			return GWQSH_Crypto::decrypt( $stored );
		}
		if ( is_string( $stored ) && preg_match( '/^[A-Z2-7]{16,}$/', $stored ) ) {
			return self::save_user_secret( $user_id, $stored ) ? $stored : false;
		}
		return false;
	}
	/**
	 * Save user secret.
	 *
	 * @param mixed $user_id User id.
	 * @param mixed $secret Secret.
	 */
	public static function save_user_secret( $user_id, $secret ) {
		if ( ! is_string( $secret ) || ! preg_match( '/^[A-Z2-7]{16,}$/', $secret ) ) {
			return false;
		}
		$encrypted = GWQSH_Crypto::encrypt( $secret );
		return false !== $encrypted && false !== update_user_meta( $user_id, 'gwqsh_2fa_secret', $encrypted );
	}
	/**
	 * Get setup secret.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function get_setup_secret( $user_id ) {
		$pending = self::get_pending_secret( $user_id );
		if ( self::is_user_2fa_enabled( $user_id ) ) {
			return $pending;
		}
		if ( $pending ) {
			return $pending; }
		$secret    = self::get_user_secret( $user_id );
		$secret    = $secret ? $secret : self::generate_secret();
		$encrypted = GWQSH_Crypto::encrypt( $secret );
		if ( false === $encrypted || false === update_user_meta( $user_id, 'gwqsh_2fa_pending_secret', $encrypted ) ) {
			return false; }
		update_user_meta( $user_id, 'gwqsh_2fa_pending_created', time() );
		return $secret;
	}
	/** Read a pending enrollment without creating a key during verification.
	 *
	 * @param int $user_id Account identifier.
	 * @return string|false Unexpired pending secret.
	 */
	public static function get_pending_secret( $user_id ) {
		$stored = get_user_meta( $user_id, 'gwqsh_2fa_pending_secret', true );
		if ( ! $stored ) {
			return false; }
		$created = (int) get_user_meta( $user_id, 'gwqsh_2fa_pending_created', true );
		if ( $created && $created < time() - 1800 ) {
			delete_user_meta( $user_id, 'gwqsh_2fa_pending_secret', $stored );
			delete_user_meta( $user_id, 'gwqsh_2fa_pending_created', $created );
			return false;
		}
		if ( ! $created ) {
			update_user_meta( $user_id, 'gwqsh_2fa_pending_created', time() ); }
		return GWQSH_Crypto::decrypt( $stored );
	}
	/**
	 * Get provisioning secret.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function get_provisioning_secret( $user_id ) {
		if ( self::is_user_2fa_enabled( $user_id ) ) {
			return self::get_setup_secret( $user_id );
		}
		return self::get_setup_secret( $user_id );
	}
	/**
	 * Enable user 2fa.
	 *
	 * @param mixed $user_id User id.
	 * @param mixed $secret Secret.
	 */
	public static function enable_user_2fa( $user_id, $secret = null ) {
		if ( empty( $secret ) ) {
			$secret = self::get_user_secret( $user_id );
		}
		if ( ! $secret || ! self::save_user_secret( $user_id, $secret ) ) {
			return false;
		}
		update_user_meta( $user_id, 'gwqsh_2fa_enabled', 1 );
		delete_user_meta( $user_id, 'gwqsh_2fa_pending_secret' );
		delete_user_meta( $user_id, 'gwqsh_2fa_pending_created' );
		update_user_meta( $user_id, 'gwqsh_2fa_last_verified', current_time( 'mysql' ) );
		add_user_meta( $user_id, 'gwqsh_2fa_last_slice', 0, true );

		$u = get_userdata( $user_id );
		GWQSH_Activity_Logger::log( '2FA enabled', 'Two-Factor Authentication activated', 'Security', $u ? $u->user_login : 'User' );
		return true;
	}
	/**
	 * Reset user 2fa.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function reset_user_2fa( $user_id ) {
		delete_user_meta( $user_id, 'gwqsh_2fa_enabled' );
		delete_user_meta( $user_id, 'gwqsh_2fa_secret' );
		delete_user_meta( $user_id, 'gwqsh_2fa_pending_secret' );
		delete_user_meta( $user_id, 'gwqsh_2fa_pending_created' );
		delete_user_meta( $user_id, 'gwqsh_backup_codes' );
		delete_user_meta( $user_id, 'gwqsh_backup_generated' );
		delete_user_meta( $user_id, 'gwqsh_trusted_devices' );
		delete_user_meta( $user_id, 'gwqsh_2fa_last_slice' );
		delete_user_meta( $user_id, 'gwqsh_2fa_last_verified' );
		foreach ( array( 'gwqsh_passkeys', 'gwqsh_recovery_email_verified', 'gwqsh_recovery_phone_verified', 'gwqsh_recovery_setup', 'gwqsh_recovery_login', 'gwqsh_recovery_setup_email', 'gwqsh_recovery_setup_sms', 'gwqsh_recovery_login_email', 'gwqsh_recovery_login_sms' ) as $key ) {
			delete_user_meta( $user_id, $key ); }

		$u = get_userdata( $user_id );
		GWQSH_Activity_Logger::log( '2FA disabled', get_current_user_id() === (int) $user_id ? 'Two-Factor Authentication disabled by account owner' : 'Two-Factor Authentication reset by administrator', 'Security', $u ? $u->user_login : 'User' );
		return true;
	}
	/**
	 * Get all users 2fa list.
	 */
	public static function get_all_users_2fa_list() {
		$users      = current_user_can( 'manage_options' ) ? get_users() : array( wp_get_current_user() );
		$out        = array();
		$current_id = get_current_user_id();

		foreach ( $users as $u ) {
			$enabled  = self::is_user_2fa_enabled( $u->ID );
			$complete = $enabled && (bool) self::get_user_secret( $u->ID );
			$last     = get_user_meta( $u->ID, 'gwqsh_2fa_last_verified', true );
			$last_fmt = ! empty( $last ) ? GWQSH_Time::format( $last ) : '—';
			$roles    = ! empty( $u->roles ) ? array_map( 'ucfirst', $u->roles ) : array( 'Subscriber' );

			$out[] = array(
				'id'               => $u->ID,
				'u'                => $u->user_login,
				'role'             => implode( ', ', $roles ),
				'st'               => $complete ? ( 'Enabled' ) : ( $enabled || get_user_meta( $u->ID, 'gwqsh_2fa_secret', true ) || self::required( $u->ID ) ? 'Setup incomplete' : 'Disabled' ),
				'enrolled'         => $enabled,
				'required'         => (bool) self::required( $u->ID ),
				'backup_remaining' => count(
					array_filter(
						self::get_user_backup_codes( $u->ID ),
						static function ( $r ) {
							return empty( $r['used'] ); }
					)
				),
				'm'                => $enabled ? 'Authenticator App' : '—',
				'a'                => $last_fmt,
				'me'               => $u->ID === $current_id ? 1 : 0,
			);
		}

		return $out;
	}
	/**
	 * Get trusted devices.
	 *
	 * @param mixed $user_id User id.
	 */
	public static function get_trusted_devices( $user_id ) {
		$records = get_user_meta( $user_id, 'gwqsh_trusted_devices', true );
		$out     = array();
		foreach ( (array) $records as $device ) {
			if ( ! is_array( $device ) || empty( $device['token_hash'] ) || empty( $device['expires'] ) || $device['expires'] <= time() ) {
				continue; }
			$out[] = array(
				'id'        => hash_hmac( 'sha256', $device['token_hash'], wp_salt( 'nonce' ) ),
				'label'     => $device['label'] ?? 'Browser',
				'expires'   => wp_date( 'M j, Y', $device['expires'] ),
				'created'   => ! empty( $device['created'] ) ? wp_date( 'M j, Y, h:i A', $device['created'] ) : 'Not recorded',
				'last_used' => ! empty( $device['last_used'] ) ? wp_date( 'M j, Y, h:i A', $device['last_used'] ) : 'Not recorded',
			);
		}
		return $out;
	}
	/**
	 * Revoke a stable, opaque device ID owned by this user.
	 *
	 * @param int    $user_id Owner.
	 * @param string $id Opaque device ID.
	 */
	public static function remove_trusted_device( $user_id, $id ) {
		$old = get_user_meta( $user_id, 'gwqsh_trusted_devices', true );
		if ( ! is_array( $old ) || ! preg_match( '/^[a-f0-9]{64}$/D', (string) $id ) ) {
			return false; }
		foreach ( $old as $index => $device ) {
			if ( ! empty( $device['token_hash'] ) && hash_equals( hash_hmac( 'sha256', $device['token_hash'], wp_salt( 'nonce' ) ), $id ) ) {
				$new = $old;
				unset( $new[ $index ] );
				if ( ! self::compare_and_swap_meta( $user_id, 'gwqsh_trusted_devices', $old, array_values( $new ) ) ) {
					return false; }
				GWQSH_Activity_Logger::log( 'Trusted device revoked', 'A remembered device was revoked', 'Security', get_userdata( $user_id )->user_login );
				return true;
			}
		}
		return false;
	}
	/**
	 * Reserve one of ten factor attempts per five-minute account window atomically.
	 *
	 * @param int $user_id Account.
	 */
	public static function reserve_factor_attempt( $user_id ) {
		for ( $try = 0; $try < 3; ++$try ) {
			$old = get_user_meta( $user_id, 'gwqsh_2fa_attempts', true );
			$new = is_array( $old ) && ! empty( $old['until'] ) && $old['until'] > time() ? $old : array(
				'until' => time() + 300,
				'count' => 0,
			);
			if ( $new['count'] >= 10 ) {
				return false; }
			++$new['count'];
			if ( '' === $old ? add_user_meta( $user_id, 'gwqsh_2fa_attempts', $new, true ) : self::compare_and_swap_meta( $user_id, 'gwqsh_2fa_attempts', $old, $new ) ) {
				return true; }
			wp_cache_delete( $user_id, 'user_meta' );
		}
		return false;
	}

	/*
	-------------------------------------------------------------
		Login Interception & Verification
		-------------------------------------------------------------
	 */
	/**
	 * Add 2fa login field.
	 */
	public static function add_2fa_login_field() {
		if ( empty( $GLOBALS['gwqsh_2fa_prompt'] ) ) {
			return; }
		$challenge = isset( $GLOBALS['gwqsh_2fa_challenge'] ) ? $GLOBALS['gwqsh_2fa_challenge'] : '';
		?>
		<?php
		if ( $challenge ) :
			?>
			<input type="hidden" name="gwqsh_2fa_challenge" value="<?php echo esc_attr( $challenge ); ?>"><?php endif; ?>
		<p class="gwqsh-2fa-wrap">
			<label for="gwqsh_2fa_code"><?php esc_html_e( '2FA Code / Backup Code (if enabled)', 'gracewell-security-suite-pro' ); ?><br />
			<input type="text" name="gwqsh_2fa_code" id="gwqsh_2fa_code" class="input" value="" size="20" placeholder="6-digit code or backup code" autocomplete="one-time-code" /></label>
			<?php
			if ( ! empty( self::get_settings()['remember_device'] ) ) :
				?>
				<label><input type="checkbox" name="gwqsh_trust_device" value="1" /> <?php esc_html_e( 'Trust this device for 30 days', 'gracewell-security-suite-pro' ); ?></label><?php endif; ?>
		</p>

		<script>document.getElementById('user_login').value=
		<?php
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Display only, sanitized and JSON escaped; native WordPress password authentication issued the challenge.
		echo wp_json_encode( isset( $_POST['log'] ) ? sanitize_text_field( wp_unslash( $_POST['log'] ) ) : '', JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT );
		?>
		;
		<?php
		if ( $challenge ) :
			?>
			document.getElementById('user_login').readOnly=true;var pw=document.getElementById('user_pass');if(pw){pw.required=false;pw.removeAttribute('name');pw.closest('.user-pass-wrap').hidden=true;}<?php endif; ?>document.getElementById('gwqsh_2fa_code').focus();</script>
		<?php
	}

	/**
	 * Resume only a short-lived, unguessable challenge issued after password verification.
	 *
	 * @param mixed $user User.
	 * @param mixed $username Username.
	 * @param mixed $password Password.
	 */
	public static function resume_challenge( $user, $username, $password ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Authentication/setup routing hook; password-issued expiring challenge validates factor requests, and AJAX dispatch verifies its nonce separately.
		if ( empty( $_POST['gwqsh_2fa_challenge'] ) ) {
			return $user; }
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Authentication/setup routing hook; password-issued expiring challenge validates factor requests, and AJAX dispatch verifies its nonce separately.
		$token = sanitize_text_field( wp_unslash( $_POST['gwqsh_2fa_challenge'] ) );
		if ( ! preg_match( '/^[a-f0-9]{64}$/D', $token ) ) {
			return new WP_Error( 'gwqsh_challenge_invalid', 'The 2FA session has expired. Sign in with your password again.' ); }
		$key  = 'gwqsh_2fa_challenge_' . hash( 'sha256', $token );
		$data = get_transient( $key );
		if ( ! is_array( $data ) || empty( $data['user_id'] ) || $data['expires'] <= time() || $data['attempts'] >= 5 || ! hash_equals( $data['ip'], hash( 'sha256', GWQSH_Settings::get_client_ip() ) ) ) {
			delete_transient( $key );
			return new WP_Error( 'gwqsh_challenge_invalid', 'The 2FA session has expired. Sign in with your password again.' );
		}
		// Disabling 2FA invalidates pending challenges instead of turning one into a password substitute.
		if ( ! self::effective_enabled( $data['user_id'] ) || empty( $data['factor'] ) || ! hash_equals( $data['factor'], hash( 'sha256', (string) get_user_meta( $data['user_id'], 'gwqsh_2fa_secret', true ) ) ) ) {
			delete_transient( $key );
			return new WP_Error( 'gwqsh_challenge_invalid', 'Authentication settings changed. Sign in with your password again.' ); }
		++$data['attempts'];
		set_transient( $key, $data, max( 1, $data['expires'] - time() ) );
		$GLOBALS['gwqsh_2fa_challenge'] = $token;
		$resolved_user                  = get_userdata( $data['user_id'] );
		return $resolved_user ? $resolved_user : new WP_Error( 'gwqsh_challenge_invalid', 'Account unavailable.' );
	}
	/**
	 * Finish challenge.
	 */
	private static function finish_challenge() {
		if ( ! empty( $GLOBALS['gwqsh_2fa_challenge'] ) ) {
			delete_transient( 'gwqsh_2fa_challenge_' . hash( 'sha256', $GLOBALS['gwqsh_2fa_challenge'] ) );
		}
	}
	/**
	 * Intercept 2fa login.
	 *
	 * @param mixed $user User.
	 * @param mixed $username Username.
	 * @param mixed $password Password.
	 */
	public static function intercept_2fa_login( $user, $username, $password ) {
		if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) ) {
			return $user;
		}

		if ( ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || ( defined( 'REST_REQUEST' ) && REST_REQUEST ) ) && ( self::required( $user->ID ) || self::effective_enabled( $user->ID ) ) ) {
			return new WP_Error( 'gwqsh_noninteractive_restricted', 'Use an explicitly supported interactive two-factor sign-in.' ); }
		if ( ( $GLOBALS['gwqsh_passkey_verified'] ?? 0 ) === $user->ID ) {
			return $user; }
		if ( ! self::effective_enabled( $user->ID ) ) {
			return $user;
		}
		$GLOBALS['gwqsh_2fa_prompt'] = true;

		if ( self::trusted_device_valid( $user->ID ) ) {
			self::finish_challenge();
			return $user; }

		$code = isset( $_POST['gwqsh_2fa_code'] ) ? sanitize_text_field( wp_unslash( $_POST['gwqsh_2fa_code'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Missing

		if ( empty( $code ) ) {
			if ( empty( $GLOBALS['gwqsh_2fa_challenge'] ) && ! empty( $password ) ) {
				$token = bin2hex( random_bytes( 32 ) );
				set_transient(
					'gwqsh_2fa_challenge_' . hash( 'sha256', $token ),
					array(
						'user_id'  => $user->ID,
						'factor'   => hash( 'sha256', (string) get_user_meta( $user->ID, 'gwqsh_2fa_secret', true ) ),
						'expires'  => time() + 300,
						'attempts' => 0,
						'ip'       => hash( 'sha256', GWQSH_Settings::get_client_ip() ),
					),
					300
				);
				$GLOBALS['gwqsh_2fa_challenge'] = $token;
			}
			return new WP_Error(
				'gwqsh_2fa_required',
				'<strong>' . esc_html__( 'Two-Factor Authentication Required:', 'gracewell-security-suite-pro' ) . '</strong> ' .
				esc_html__( 'Please enter the 6-digit code from your authenticator app (or a backup code) to log in.', 'gracewell-security-suite-pro' )
			);
		}

		if ( ! self::reserve_factor_attempt( $user->ID ) ) {
			return new WP_Error( 'gwqsh_2fa_rate_limited', 'Too many verification attempts. Try again in five minutes.' ); }
		$secret = self::get_user_secret( $user->ID );
		$slice  = self::matching_totp_slice( $secret, $code );
		add_user_meta( $user->ID, 'gwqsh_2fa_last_slice', 0, true );
		$previous_slice = get_user_meta( $user->ID, 'gwqsh_2fa_last_slice', true );
		$last_slice     = (int) $previous_slice;
		if ( false !== $slice && $slice > $last_slice ) {
			if ( ! self::compare_and_swap_meta( $user->ID, 'gwqsh_2fa_last_slice', $previous_slice, $slice ) ) {
				return new WP_Error( 'gwqsh_2fa_reused', 'This 2FA code has already been used. Wait for the next code.' ); }
			update_user_meta( $user->ID, 'gwqsh_2fa_last_verified', current_time( 'mysql' ) );
			self::maybe_trust_device( $user->ID );
			self::finish_challenge();
			return $user;
		}

		// Email/SMS recovery is bound to the password-issued login challenge.
		$recovery_token = $GLOBALS['gwqsh_2fa_challenge'] ?? '';
		if ( $recovery_token && GWQSH_Recovery::verify( $user->ID, $code, 'login', hash( 'sha256', $recovery_token ) ) ) {
			update_user_meta( $user->ID, 'gwqsh_2fa_last_verified', current_time( 'mysql' ) );
			self::finish_challenge();
			GWQSH_Activity_Logger::log( 'Recovery login verified', 'A one-time delivered backup code was verified.', 'Security', $user->user_login );
			return $user;
		}
		// Try backup codes.
		if ( self::verify_and_burn_backup_code( $user->ID, $code ) ) {
			update_user_meta( $user->ID, 'gwqsh_2fa_last_verified', current_time( 'mysql' ) );
			self::maybe_trust_device( $user->ID );
			self::finish_challenge();
			return $user;
		}

		GWQSH_Activity_Logger::log( '2FA verification failed', 'Invalid 2FA code entered during login', 'Security', $user->user_login );

		return new WP_Error(
			'gwqsh_2fa_invalid',
			'<strong>' . esc_html__( 'Error:', 'gracewell-security-suite-pro' ) . '</strong> ' .
			esc_html__( 'The 2FA code is invalid or has expired. Please try again.', 'gracewell-security-suite-pro' )
		);
	}
	/**
	 * Matching totp slice.
	 *
	 * @param mixed $secret Secret.
	 * @param mixed $code Code.
	 */
	public static function matching_totp_slice( $secret, $code ) {
		if ( ! is_string( $secret ) || ! preg_match( '/^[A-Z2-7]{16,}$/D', $secret ) || ! preg_match( '/^\d{6}$/D', (string) $code ) ) {
			return false;
		}
		$current = (int) floor( time() / 30 );
		for ( $slice = $current - 1; $slice <= $current + 1; $slice++ ) {
			if ( hash_equals( self::calculate_totp( $secret, $slice ), (string) $code ) ) {
				return $slice;
			}
		}
		return false;
	}
	/**
	 * Consume a current authenticator code with the same replay guard as login.
	 *
	 * @param int    $user_id Account.
	 * @param string $code Submitted factor.
	 */
	public static function consume_totp( $user_id, $code ) {
		$slice = self::matching_totp_slice( self::get_user_secret( $user_id ), $code );
		add_user_meta( $user_id, 'gwqsh_2fa_last_slice', 0, true );
		$old = get_user_meta( $user_id, 'gwqsh_2fa_last_slice', true );
		return false !== $slice && $slice > (int) $old && self::compare_and_swap_meta( $user_id, 'gwqsh_2fa_last_slice', $old, $slice );
	}
	/**
	 * Trusted device valid.
	 *
	 * @param mixed $user_id User id.
	 */
	private static function trusted_device_valid( $user_id ) {
		if ( empty( self::get_settings()['remember_device'] ) ) {
			return false; }
		$cookie = isset( $_COOKIE['gwqsh_trusted_device'] ) ? (string) sanitize_text_field( wp_unslash( $_COOKIE['gwqsh_trusted_device'] ) ) : '';
		if ( ! preg_match( '/^[a-f0-9]{64}$/D', $cookie ) ) {
			return false; }
		$hash    = hash( 'sha256', $cookie );
		$devices = get_user_meta( $user_id, 'gwqsh_trusted_devices', true );
		if ( ! is_array( $devices ) ) {
			return false; }
		foreach ( $devices as $index => $device ) {
			if ( isset( $device['token_hash'], $device['expires'] ) && $device['expires'] > time() && hash_equals( $device['token_hash'], $hash ) ) {
				$old                            = $devices;
				$devices[ $index ]['last_used'] = time();
				self::compare_and_swap_meta( $user_id, 'gwqsh_trusted_devices', $old, $devices );
				return true; }
		}
		return false;
	}
	/**
	 * Maybe trust device.
	 *
	 * @param mixed $user_id User id.
	 */
	private static function maybe_trust_device( $user_id ) {
		if ( empty( self::get_settings()['remember_device'] ) ) {
			return; }
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Authentication/setup routing hook; password-issued expiring challenge validates factor requests, and AJAX dispatch verifies its nonce separately.
		if ( empty( $_POST['gwqsh_trust_device'] ) || headers_sent() ) {
			return; }
		$token   = bin2hex( random_bytes( 32 ) );
		$expires = time() + 30 * DAY_IN_SECONDS;
		$devices = get_user_meta( $user_id, 'gwqsh_trusted_devices', true );
		if ( ! is_array( $devices ) ) {
			$devices = array(); }
		$devices   = array_values(
			array_filter(
				$devices,
				static function ( $device ) {
					return is_array( $device ) && ! empty( $device['token_hash'] ) && ! empty( $device['expires'] ) && $device['expires'] > time();
				}
			)
		);
		$label     = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 80 ) : 'Browser';
		$devices[] = array(
			'token_hash' => hash( 'sha256', $token ),
			'expires'    => $expires,
			'label'      => $label,
			'created'    => time(),
			'last_used'  => time(),
		);
		update_user_meta( $user_id, 'gwqsh_trusted_devices', array_slice( $devices, -10 ) );
		setcookie(
			'gwqsh_trusted_device',
			$token,
			array(
				'expires'  => $expires,
				'path'     => COOKIEPATH ? COOKIEPATH : '/',
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			)
		);
		GWQSH_Activity_Logger::log( 'Trusted device added', 'A device was trusted for 30 days', 'Security' );
	}
}
