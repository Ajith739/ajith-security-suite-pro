<?php
/**
 * Authentication anomaly detection and protection hardening.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * Login anomaly detection, factor reset protection, OTP replay prevention,
 * application password auditing, and suspicious admin creation alerts.
 */
final class GWQSH_Auth_Hardening {

	/** Register hardening hooks. */
	public static function init() {
		// Monitor administrator creation.
		add_action( 'user_register', array( __CLASS__, 'monitor_user_creation' ), 10, 2 );
		add_action( 'set_user_role', array( __CLASS__, 'monitor_role_change' ), 10, 3 );

		// OTP replay prevention.
		add_filter( 'gwqsh_totp_verify', array( __CLASS__, 'prevent_otp_replay' ), 10, 3 );

		// Application password creation monitoring.
		add_action( 'wp_create_application_password', array( __CLASS__, 'monitor_app_password_creation' ), 10, 4 );

		// Factor reset protection.
		add_action( 'profile_update', array( __CLASS__, 'monitor_profile_update' ), 10, 3 );

		// Login anomaly hooks.
		add_action( 'wp_login', array( __CLASS__, 'analyze_login' ), 10, 2 );
		add_action( 'wp_login_failed', array( __CLASS__, 'track_failed_login' ), 10, 2 );

		// Wordfence-grade leaked password protection (HaveIBeenPwned k-anonymity).
		add_filter( 'wp_authenticate_user', array( __CLASS__, 'check_leaked_password' ), 20, 2 );
		add_action( 'user_profile_update_errors', array( __CLASS__, 'check_leaked_password_on_profile_update' ), 10, 3 );
		add_action( 'validate_password_reset', array( __CLASS__, 'check_leaked_password_on_reset' ), 10, 2 );
	}

	/** Detect suspicious admin user creation.
	 *
	 * @param int   $user_id  New user ID.
	 * @param array $userdata User data array.
	 */
	public static function monitor_user_creation( $user_id, $userdata = array() ) {
		$user = get_userdata( $user_id );
		if ( ! $user ) {
			return;
		}

		$is_admin = in_array( 'administrator', $user->roles, true );
		$context  = array(
			'user_id'    => $user_id,
			'username'   => $user->user_login,
			'email'      => $user->user_email,
			'roles'      => $user->roles,
			'created_by' => get_current_user_id(),
		);

		// Flag unattended admin creation (no active session = likely automated).
		if ( $is_admin && ! get_current_user_id() ) {
			$context['suspicious'] = true;
			$context['reason']     = 'Administrator created without an active session';
			GWQSH_Activity_Logger::log(
				'Suspicious administrator creation',
				wp_json_encode( $context ),
				'Security'
			);
			GWQSH_Alert_Service::dispatch( 'admin', 'Critical', 'Suspicious administrator account created without an active session: ' . $user->user_login );
			return;
		}

		if ( $is_admin ) {
			GWQSH_Activity_Logger::log(
				'Administrator account created',
				wp_json_encode( $context ),
				'Security'
			);
			GWQSH_Alert_Service::dispatch( 'admin', 'High', 'New administrator account created: ' . $user->user_login . ' by user #' . get_current_user_id() );
		}
	}

	/** Monitor role escalation to administrator.
	 *
	 * @param int    $user_id  User ID.
	 * @param string $role     New role.
	 * @param array  $old_roles Previous roles.
	 */
	public static function monitor_role_change( $user_id, $role, $old_roles ) {
		if ( 'administrator' !== $role || in_array( 'administrator', $old_roles, true ) ) {
			return;
		}

		$user    = get_userdata( $user_id );
		$context = array(
			'user_id'    => $user_id,
			'username'   => $user ? $user->user_login : 'unknown',
			'old_roles'  => $old_roles,
			'new_role'   => $role,
			'changed_by' => get_current_user_id(),
		);

		GWQSH_Activity_Logger::log(
			'Role escalated to administrator',
			wp_json_encode( $context ),
			'Security'
		);

		// No active admin session performing the change = suspicious.
		if ( ! get_current_user_id() || ! current_user_can( 'promote_users' ) ) {
			$context['suspicious'] = true;
			GWQSH_Alert_Service::dispatch( 'role', 'Critical', 'Role escalation to administrator without authorization: user #' . $user_id );
		} else {
			GWQSH_Alert_Service::dispatch( 'role', 'High', 'User #' . $user_id . ' promoted to administrator by user #' . get_current_user_id() );
		}
	}

	/** Prevent TOTP code replay by tracking recently used codes.
	 *
	 * @param bool   $valid     Whether the code was valid.
	 * @param int    $user_id   User ID.
	 * @param string $code      The OTP code.
	 * @return bool Modified validity.
	 */
	public static function prevent_otp_replay( $valid, $user_id, $code ) {
		if ( ! $valid ) {
			return $valid;
		}

		// Use the authoritative per-user atomic slice consumer; no second replay store.
		return GWQSH_Two_Factor::consume_totp( $user_id, $code );
	}

	/** Monitor application password creation for audit trail.
	 *
	 * @param int    $user_id  User ID.
	 * @param array  $new_item New application password item.
	 * @param string $new_password The unhashed generated application password (not logged).
	 * @param array  $args     Request arguments.
	 */
	public static function monitor_app_password_creation( $user_id, $new_item, $new_password, $args ) {
		$context = array(
			'user_id'    => $user_id,
			'app_name'   => sanitize_text_field( substr( $new_item['name'] ?? '', 0, 100 ) ),
			'uuid'       => $new_item['uuid'] ?? '',
			'created_by' => get_current_user_id(),
			'method'     => isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'unknown',
		);

		GWQSH_Activity_Logger::log(
			'Application password created',
			wp_json_encode( $context ),
			'Security'
		);

		// Alert if created for an admin account.
		$user = get_userdata( $user_id );
		if ( $user && in_array( 'administrator', $user->roles, true ) ) {
			GWQSH_Alert_Service::dispatch( 'admin', 'Medium', 'Application password created for administrator: ' . $user->user_login );
		}
	}

	/** Monitor profile updates for security-relevant changes.
	 *
	 * @param int     $user_id       User ID.
	 * @param WP_User $old_user_data Previous user data.
	 * @param array   $userdata      Updated user data.
	 */
	public static function monitor_profile_update( $user_id, $old_user_data, $userdata = array() ) {
		// Detect email change for admin accounts.
		if ( is_array( $userdata ) && isset( $userdata['user_email'] ) && $old_user_data->user_email !== $userdata['user_email'] ) {
			if ( in_array( 'administrator', $old_user_data->roles, true ) ) {
				GWQSH_Activity_Logger::log(
					'Administrator email changed',
					'User #' . $user_id . ' email changed from ' . $old_user_data->user_email . ' to ' . ( $userdata['user_email'] ?? 'unknown' ),
					'Security'
				);
				GWQSH_Alert_Service::dispatch( 'admin', 'High', 'Administrator email changed for user #' . $user_id );
			}
		}

		// Detect password change for admin accounts.
		if ( is_array( $userdata ) && ! empty( $userdata['user_pass'] ) ) {
			if ( in_array( 'administrator', $old_user_data->roles, true ) ) {
				GWQSH_Activity_Logger::log(
					'Administrator password changed',
					'User #' . $user_id . ' password updated.',
					'Security'
				);
			}
		}
	}

	/** Analyze a successful login for anomalies.
	 *
	 * @param string  $user_login Username.
	 * @param WP_User $user       User object.
	 */
	public static function analyze_login( $user_login, $user ) {
		$ip       = GWQSH_Settings::get_client_ip();
		$agent    = isset( $_SERVER['HTTP_USER_AGENT'] ) ? substr( sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ), 0, 256 ) : '';
		$is_admin = in_array( 'administrator', $user->roles, true );

		$context = array(
			'user_id'  => $user->ID,
			'username' => $user_login,
			'ip'       => GWQSH_Privacy::ip( $ip ),
			'admin'    => $is_admin,
		);

		// Track login for anomaly baseline.
		$history_key = 'login-history-' . $user->ID;
		$history     = GWQSH_Enterprise_Store::get( 'auth-hardening', $history_key );
		$logins      = is_array( $history ) ? $history : array();

		$current = array(
			'time'  => time(),
			'ip'    => hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) ),
			'agent' => substr( $agent, 0, 100 ),
		);

		// Check for new IP login (never seen for this user).
		$known_ips = array_column( $logins, 'ip' );
		if ( ! in_array( $current['ip'], $known_ips, true ) && count( $known_ips ) > 0 && $is_admin ) {
			$context['anomaly'] = 'new_ip';
			GWQSH_Activity_Logger::log(
				'Administrator login from new IP',
				wp_json_encode( $context ),
				'Security'
			);
			GWQSH_Alert_Service::dispatch( 'login', 'Medium', 'Administrator ' . $user_login . ' logged in from a new IP address.' );
		}

		// Store login in bounded history (last 20 logins per user).
		$logins[] = $current;
		$logins   = array_slice( $logins, -20 );
		GWQSH_Enterprise_Store::put( 'auth-hardening', $history_key, $logins, 30 * DAY_IN_SECONDS );
	}

	/** Track failed login attempts for credential stuffing detection.
	 *
	 * @param string   $username  Attempted username.
	 * @param WP_Error $error     Login error.
	 */
	public static function track_failed_login( $username, $error = null ) {
		$ip  = GWQSH_Settings::get_client_ip();
		$key = 'failed-logins-' . $ip;

		$count = GWQSH_Enterprise_Store::hit( 'auth-hardening', $key, 300 );

		// Track every attempt, retaining at most 20 distinct-name hashes per IP window.
		$usernames_key = 'failed-usernames-' . hash_hmac( 'sha256', $ip, wp_salt( 'auth' ) );
		$tried         = GWQSH_Enterprise_Store::get( 'auth-hardening', $usernames_key );
		$usernames     = is_array( $tried ) ? $tried : array();
		$name_hash     = hash_hmac( 'sha256', strtolower( substr( $username, 0, 60 ) ), wp_salt( 'auth' ) );
		$usernames[]   = $name_hash;
		$usernames     = array_slice( array_values( array_unique( $usernames ) ), -20 );
		$unique        = count( $usernames );
		GWQSH_Enterprise_Store::put( 'auth-hardening', $usernames_key, $usernames, 300 );
		if ( null !== $count && $count >= 10 ) {
			if ( $unique >= 5 && 1 === GWQSH_Enterprise_Store::hit( 'auth-hardening', 'stuffing-alert-' . $ip, 600 ) ) {
				GWQSH_Activity_Logger::log(
					'Credential stuffing detected',
					$count . ' failed attempts from IP ' . GWQSH_Privacy::ip( $ip ) . ' using ' . $unique . ' unique usernames in 5 minutes.',
					'Security'
				);
				GWQSH_Alert_Service::dispatch( 'lockout', 'High', 'Credential stuffing detected from IP ' . GWQSH_Privacy::ip( $ip ) . ': ' . $count . ' failures with ' . $unique . ' unique usernames.' );
			}
		}
	}

	/** Get a security audit of application passwords for all admin accounts.
	 *
	 * @return array|WP_Error Audit results.
	 */
	public static function audit_application_passwords() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		if ( ! class_exists( 'WP_Application_Passwords' ) ) {
			return array(
				'available' => false,
				'message'   => 'Application passwords are not available in this WordPress version.',
			);
		}

		$admins = get_users(
			array(
				'role'   => 'administrator',
				'number' => 100,
				'fields' => array( 'ID', 'user_login' ),
			)
		);

		$results = array();
		foreach ( $admins as $admin ) {
			if ( ! current_user_can( 'list_app_passwords', $admin->ID ) ) {
				continue;
			}
			$passwords = WP_Application_Passwords::get_user_application_passwords( $admin->ID );
			if ( empty( $passwords ) ) {
				continue;
			}
			$account = array(
				'user_id'   => $admin->ID,
				'username'  => $admin->user_login,
				'passwords' => array(),
			);
			foreach ( array_slice( $passwords, 0, 20 ) as $pw ) {
				$age    = time() - ( $pw['created'] ?? 0 );
				$stale  = $age > 180 * DAY_IN_SECONDS; // Over 6 months old.
				$unused = empty( $pw['last_used'] ) || ( time() - $pw['last_used'] ) > 90 * DAY_IN_SECONDS;

				$account['passwords'][] = array(
					'uuid'      => $pw['uuid'],
					'name'      => sanitize_text_field( substr( $pw['name'], 0, 100 ) ),
					'created'   => $pw['created'],
					'last_used' => $pw['last_used'] ?? 0,
					'age_days'  => (int) ( $age / DAY_IN_SECONDS ),
					'stale'     => $stale,
					'unused'    => $unused,
					'risk'      => $stale && $unused ? 'High' : ( $stale || $unused ? 'Medium' : 'Low' ),
				);
			}
			$results[] = $account;
		}

		return array(
			'available' => true,
			'accounts'  => $results,
			'total'     => count( $results ),
		);
	}

	/** Match a complete 35-character SHA-1 suffix, never a substring of another line.
	 * The padded response contains dummy records that must not be confused with
	 * positive breach counts. This pure function is regression-tested offline.
	 *
	 * @param string $body K-anonymity API response body.
	 * @param string $suffix Uppercase SHA-1 suffix.
	 */
	public static function breached_suffix_in_response( $body, $suffix ) {
		if ( ! is_string( $body ) || ! is_string( $suffix ) || ! preg_match( '/^[A-F0-9]{35}$/D', $suffix ) ) {
			return false;
		}
		foreach ( explode( "\n", $body ) as $line ) {
			$parts = explode( ':', trim( $line ), 2 );
			if ( count( $parts ) !== 2 || strlen( $parts[0] ) !== 35 || ! ctype_xdigit( $parts[0] ) ) {
				continue;
			}
			if ( hash_equals( $suffix, strtoupper( $parts[0] ) ) ) {
				return ctype_digit( $parts[1] ) && (int) $parts[1] > 0;
			}
		}
		return false;
	}

	/** Check if a password is compromised using HaveIBeenPwned k-anonymity API.
	 * Zero cleartext password bytes leave the server; only the first 5 characters of the SHA1 hash are sent.
	 *
	 * @param string $password Cleartext password to check.
	 * @return bool True if compromised in a known breach.
	 */
	public static function is_password_leaked( $password ) {
		if ( ! is_string( $password ) || '' === $password || strlen( $password ) > 256 ) {
			return false;
		}
		$sha1      = strtoupper( sha1( $password ) );
		$cache_key = 'gwqsh_pwned_' . md5( $sha1 );
		$cached    = get_transient( $cache_key );
		if ( false !== $cached ) {
			return (bool) $cached;
		}
		$prefix   = substr( $sha1, 0, 5 );
		$suffix   = substr( $sha1, 5 );
		$response = wp_safe_remote_get(
			'https://api.pwnedpasswords.com/range/' . $prefix,
			array(
				'timeout'             => 2,
				'redirection'         => 0,
				'sslverify'           => true,
				'limit_response_size' => 524288,
				'headers'             => array( 'Add-Padding' => 'true' ),
				'user-agent'          => 'Gracewell-Security-Suite-Pro/' . ( defined( 'GWQSH_VERSION' ) ? GWQSH_VERSION : '1.3' ),
			)
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			// Fail-open on network error/timeout so users are not blocked by external API issues.
			return false;
		}
		$body      = wp_remote_retrieve_body( $response );
		// A truncated response is not a reliable negative finding.
		if ( ! is_string( $body ) || strlen( $body ) >= 524288 ) {
			return false;
		}
		$is_leaked = self::breached_suffix_in_response( $body, $suffix );
		set_transient( $cache_key, $is_leaked ? 1 : 0, $is_leaked ? DAY_IN_SECONDS : HOUR_IN_SECONDS );
		return $is_leaked;
	}

	/** Inspect password at login time for data breach exposure.
	 *
	 * @param WP_User|WP_Error $user Authenticating user object or prior error.
	 * @param string           $password Submitted password.
	 * @return WP_User|WP_Error Unmodified user or error if blocking is enabled.
	 */
	public static function check_leaked_password( $user, $password ) {
		if ( is_wp_error( $user ) || ! ( $user instanceof WP_User ) || ! is_string( $password ) || '' === $password ) {
			return $user;
		}
		$is_privileged = array_intersect( array( 'administrator', 'editor', 'author' ), (array) $user->roles );
		if ( ! $is_privileged && ! apply_filters( 'gwqsh_check_all_passwords_leaked', false ) ) {
			return $user;
		}
		if ( self::is_password_leaked( $password ) ) {
			GWQSH_Activity_Logger::log(
				'Leaked password detected',
				sprintf( 'User "%s" authenticated with a password compromised in public data breaches.', $user->user_login ),
				'High',
				'—',
				GWQSH_Settings::get_client_ip()
			);
			GWQSH_Events::enqueue(
				'email',
				array(
					'event_id'          => 'leaked-pwd-' . $user->ID . '-' . time(),
					'delivery_identity' => 'leaked-pwd-' . $user->ID,
					'event'             => 'Compromised Password in Data Breach',
					'category'          => 'critical',
					'severity'          => 'High',
					'user'              => $user->user_login,
					'ip'                => GWQSH_Settings::get_client_ip(),
					'timestamp'         => gmdate( 'c' ),
					'message'           => sprintf( 'Account "%s" successfully authenticated using a password that has appeared in public credential breaches. Immediate password change is recommended.', $user->user_login ),
				)
			);
			if ( apply_filters( 'gwqsh_enforce_leaked_password_reset', false ) ) {
				return new WP_Error(
					'leaked_password',
					'<strong>SECURITY ALERT:</strong> The password you entered has been found in an online data breach. For your site\'s security, please reset your password.'
				);
			}
		}
		return $user;
	}

	/** Prevent setting a known breached password during profile update.
	 *
	 * @param WP_Error $errors Errors.
	 * @param bool     $update Update state.
	 * @param stdClass $user   User object.
	 */
	public static function check_leaked_password_on_profile_update( $errors, $update, $user ) {
		if ( isset( $_POST['pass1'] ) && is_string( $_POST['pass1'] ) && '' !== $_POST['pass1'] ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$pw = wp_unslash( $_POST['pass1'] ); // Preserve the exact secret; sanitization changes the password being checked.
			if ( self::is_password_leaked( $pw ) ) {
				$errors->add( 'leaked_password', 'The password you entered has appeared in public credential breaches. Choose a unique password.' );
			}
		}
	}

	/** Prevent setting a known breached password during password reset.
	 *
	 * @param WP_Error $errors Errors.
	 * @param WP_User  $user   User object.
	 */
	public static function check_leaked_password_on_reset( $errors, $user ) {
		if ( isset( $_POST['pass1'] ) && is_string( $_POST['pass1'] ) && '' !== $_POST['pass1'] ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing
			$pw = wp_unslash( $_POST['pass1'] ); // Preserve the exact secret; sanitization changes the password being checked.
			if ( self::is_password_leaked( $pw ) ) {
				$errors->add( 'leaked_password', 'The new password you chose has appeared in public credential breaches. Choose a stronger, unique password.' );
			}
		}
	}
}
