<?php
/**
 * WebAuthn enrollment and login using the bundled lbuchs verifier.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Passkeys service. */
final class GWQSH_Passkeys {
	/** Create indexed, non-autoloaded, expiring authentication challenge storage. */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = $wpdb->prefix . 'gwqsh_auth_challenges';
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
 token_hash char(64) NOT NULL,
 payload text NOT NULL,
 expires_at bigint(20) unsigned NOT NULL,
 PRIMARY KEY  (token_hash),
 KEY expires_at (expires_at)
) {$charset};"
		);
	}
	/**
	 * Normalize a user-visible credential name.
	 *
	 * @param string $value Submitted label.
	 * @return string
	 */
	private static function name( $value ) {
		$value = substr( sanitize_text_field( $value ), 0, 80 );
		return $value ? $value : 'Passkey';
	}
	/** Register the service hooks. */
	public static function init() {
		add_action( 'wp_ajax_gwqsh_passkey_login', array( __CLASS__, 'login_ajax' ) );
		add_action( 'wp_ajax_nopriv_gwqsh_passkey_login', array( __CLASS__, 'login_ajax' ) );
		add_filter( 'authenticate', array( __CLASS__, 'resume' ), 19, 1 );
		add_action( 'login_enqueue_scripts', array( __CLASS__, 'assets' ) );
	}
	/** Enqueue the native WordPress login integration. */
	public static function assets() {
		wp_enqueue_script( 'gwqsh-passkey-login', GWQSH_URL . 'assets/js/passkey-login.js', array(), (string) filemtime( GWQSH_PATH . 'assets/js/passkey-login.js' ), true );
		wp_add_inline_script(
			'gwqsh-passkey-login',
			'window.GWQSH_LOGIN=' . wp_json_encode(
				array(
					'url'      => admin_url( 'admin-ajax.php' ),
					'nonce'    => wp_create_nonce( 'gwqsh_login_factor' ),
					'passkeys' => self::available(),
				)
			) . ';',
			'before'
		);
	}
	/** Check the secure origin, provider policy and bundled runtime. */
	public static function available() {
		return GWQSH_Recovery::settings()['passkeys'] && extension_loaded( 'openssl' ) && function_exists( 'mb_strlen' ) && ( 'https' === wp_parse_url( home_url(), PHP_URL_SCHEME ) || 'localhost' === wp_parse_url( home_url(), PHP_URL_HOST ) ) && is_file( GWQSH_PATH . 'includes/vendor/webauthn/src/WebAuthn.php' );
	}
	/**
	 * Create the maintained WebAuthn verifier for this relying party.
	 *
	 * @throws RuntimeException When the secure origin or runtime is unavailable.
	 */
	private static function verifier() {
		if ( ! self::available() ) {
			throw new RuntimeException( 'Passkeys require HTTPS (or localhost) and the WebAuthn runtime.' ); }
		require_once GWQSH_PATH . 'includes/vendor/webauthn/src/WebAuthn.php';
		return new \GracewellSecuritySuitePro\Vendor\WebAuthn\WebAuthn( get_bloginfo( 'name' ), wp_parse_url( home_url(), PHP_URL_HOST ), array( 'none' ), true );
	}
	/**
	 * Read credential verification keys owned by one user.
	 *
	 * @param mixed $user_id user id value.
	 */
	public static function records( $user_id ) {
		$records = get_user_meta( $user_id, 'gwqsh_passkeys', true );
		return is_array( $records ) ? $records : array(); }
	/**
	 * Return display-only credential metadata for the owning user.
	 *
	 * @param mixed $user_id user id value.
	 */
	public static function listing( $user_id ) {
		$out = array();
		foreach ( self::records( $user_id ) as $id => $row ) {
			$out[] = array(
				'id'        => $id,
				'name'      => $row['name'],
				'created'   => GWQSH_Time::format( (int) $row['created'] ),
				'last_used' => ! empty( $row['last_used'] ) ? GWQSH_Time::format( (int) $row['last_used'] ) : 'Never',
			); }
		return $out;
	}
	/**
	 * Encode binary WebAuthn wire data as base64url.
	 *
	 * @param mixed $binary binary value.
	 */
	public static function b64( $binary ) {
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- Binary WebAuthn wire encoding or provider Basic authentication, never executable content.
		return rtrim( strtr( base64_encode( $binary ), '+/', '-_' ), '=' ); }
	/**
	 * Validate and decode bounded base64url WebAuthn wire data.
	 *
	 * @param mixed $value value value.
	 * @throws RuntimeException When validation or challenge persistence fails.
	 */
	public static function decode( $value ) {
		if ( ! is_string( $value ) || strlen( $value ) > 131072 || ! preg_match( '/^[A-Za-z0-9_-]+$/D', $value ) ) {
			throw new RuntimeException( 'Invalid credential data.' ); }
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- Binary WebAuthn wire encoding or provider Basic authentication, never executable content.
		$decoded = base64_decode( strtr( $value, '-_', '+/' ), true );
		if ( false === $decoded ) {
			throw new RuntimeException( 'Invalid credential data.' ); }
		return $decoded;
	}
	/**
	 * Validate the exact configured origin and reject cross-origin assertions.
	 *
	 * @param mixed $encoded encoded value.
	 * @throws RuntimeException When validation or challenge persistence fails.
	 */
	private static function origin( $encoded ) {
		$binary   = self::decode( $encoded );
		$data     = json_decode( $binary, true );
		$url      = wp_parse_url( home_url() );
		$expected = $url['scheme'] . '://' . $url['host'] . ( isset( $url['port'] ) ? ':' . $url['port'] : '' );
		if ( ! is_array( $data ) || ( $data['origin'] ?? '' ) !== $expected || ! empty( $data['crossOrigin'] ) ) {
			throw new RuntimeException( 'Credential origin mismatch.' ); }
		return $binary;
	}
	/**
	 * Persist a non-autoloaded one-use challenge.
	 *
	 * @param array $data Challenge data.
	 * @param int   $ttl Lifetime in seconds.
	 * @throws RuntimeException When storage fails.
	 */
	public static function issue( array $data, $ttl = 300 ) {
		global $wpdb;
		$token           = bin2hex( random_bytes( 32 ) );
		$data['expires'] = time() + $ttl;
		$data['ip']      = hash( 'sha256', GWQSH_Settings::get_client_ip() );
		// phpcs:ignore WordPress.DB -- Indexed bounded expiry cleanup; no request-selected table or SQL.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_auth_challenges WHERE expires_at < %d LIMIT 200", time() ) );
		// phpcs:ignore WordPress.DB -- Plugin-owned ephemeral records; generated hashes and encoded payload are escaped by wpdb.
		if ( ! $wpdb->insert(
			$wpdb->prefix . 'gwqsh_auth_challenges',
			array(
				'token_hash' => hash( 'sha256', $token ),
				'payload'    => wp_json_encode( $data ),
				'expires_at' => $data['expires'],
			)
		) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.SchemaChange -- This is a user-facing error string, not a SQL schema operation.
			throw new RuntimeException( 'Unable to create authentication challenge.' ); }
		return $token;
	}
	/**
	 * Atomically consume a matching unexpired authentication challenge.
	 *
	 * @param mixed $token token value.
	 * @param mixed $purpose purpose value.
	 * @throws RuntimeException When validation or challenge persistence fails.
	 */
	public static function consume( $token, $purpose ) {
		global $wpdb;
		if ( ! is_string( $token ) || ! preg_match( '/^[a-f0-9]{64}$/D', $token ) ) {
			throw new RuntimeException( 'Authentication session expired.' ); }
		$hash = hash( 'sha256', $token );
		// phpcs:ignore WordPress.DB -- Expiring authentication evidence cannot use an object cache.
		$row  = $wpdb->get_row( $wpdb->prepare( "SELECT payload FROM {$wpdb->prefix}gwqsh_auth_challenges WHERE token_hash = %s AND expires_at >= %d", $hash, time() ), ARRAY_A );
		$data = $row ? json_decode( $row['payload'], true ) : null;
		if ( ! is_array( $data ) || ( $data['purpose'] ?? '' ) !== $purpose || $data['expires'] < time() || ! hash_equals( $data['ip'], hash( 'sha256', GWQSH_Settings::get_client_ip() ) ) ) {
			throw new RuntimeException( 'Authentication session expired.' ); }
		// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
		$count = $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_auth_challenges WHERE token_hash = %s AND payload = %s AND expires_at >= %d", $hash, $row['payload'], time() ) );
		if ( 1 !== $count ) {
			throw new RuntimeException( 'This authentication session was already used.' ); }
		return $data;
	}
	/**
	 * Execute an owner-bound management action after central AJAX authorization.
	 *
	 * @param mixed $action action value.
	 * @param array $input input value.
	 * @throws RuntimeException Internally handled verification failure.
	 */
	public static function management( $action, array $input ) {
		$user = wp_get_current_user();
		if ( ! $user->ID ) {
			return new WP_Error( 'permission', 'Sign in first.' ); }
		try {
			if ( 'passkey_list' === $action ) {
				return self::listing( $user->ID ); }
			if ( 'passkey_create_options' === $action ) {
				if ( ! GWQSH_Two_Factor::reserve_factor_attempt( $user->ID ) || ! wp_check_password( $input['password'] ?? '', $user->user_pass, $user->ID ) ) {
					throw new RuntimeException( 'Verify your current password to register a passkey, or retry after the attempt cooldown.' ); }
				$records = self::records( $user->ID );
				if ( count( $records ) >= 10 ) {
					throw new RuntimeException( 'Remove a passkey before adding another (maximum 10).' ); }
				$verifier = self::verifier();
				$args     = $verifier->getCreateArgs( hash_hmac( 'sha256', (string) $user->ID, wp_salt( 'auth' ), true ), $user->user_login, $user->display_name, 120, true, 'required', null, array_map( array( __CLASS__, 'decode' ), array_keys( $records ) ) );
				$token    = self::issue(
					array(
						'purpose'     => 'register',
						'user_id'     => $user->ID,
						'challenge'   => self::b64( $verifier->getChallenge()->getBinaryString() ),
						'fingerprint' => hash( 'sha256', $user->user_pass ),
					)
				);
				return array(
					'options' => $args,
					'token'   => $token,
				);
			}
			if ( 'passkey_create_verify' === $action ) {
				$challenge = self::consume( $input['token'] ?? '', 'register' );
				if ( $challenge['user_id'] !== $user->ID || ! hash_equals( $challenge['fingerprint'] ?? '', hash( 'sha256', $user->user_pass ) ) ) {
					throw new RuntimeException( 'Credential account mismatch.' ); }
				$result = self::verifier()->processCreate( self::origin( $input['clientDataJSON'] ?? '' ), self::decode( $input['attestationObject'] ?? '' ), self::decode( $challenge['challenge'] ), true, true );
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- External verifier API property names.
				$id  = self::b64( $result->credentialId );
				$old = self::records( $user->ID );
				if ( isset( $old[ $id ] ) || count( $old ) >= 10 ) {
					throw new RuntimeException( 'This passkey is already registered or the limit was reached.' ); }
				$new        = $old;
				$new[ $id ] = array(
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- External verifier API property names.
					'key'       => $result->credentialPublicKey,
					// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- External verifier API property names.
					'counter'   => (int) $result->signatureCounter,
					'name'      => self::name( $input['name'] ?? '' ),
					'created'   => time(),
					'last_used' => 0,
				);
				$success    = metadata_exists( 'user', $user->ID, 'gwqsh_passkeys' ) ? GWQSH_Two_Factor::compare_and_swap_meta( $user->ID, 'gwqsh_passkeys', $old, $new ) : add_user_meta( $user->ID, 'gwqsh_passkeys', $new, true );
				if ( ! $success ) {
					throw new RuntimeException( 'Passkeys changed concurrently. Retry registration.' ); }
				GWQSH_Activity_Logger::log( 'Passkey registered', 'A verified WebAuthn credential was enrolled.', 'Security', $user->user_login );
				return self::listing( $user->ID );
			}
			if ( in_array( $action, array( 'passkey_rename', 'passkey_remove' ), true ) ) {
				if ( ! GWQSH_Two_Factor::reserve_factor_attempt( $user->ID ) || ! wp_check_password( $input['password'] ?? '', $user->user_pass, $user->ID ) ) {
					throw new RuntimeException( 'Verify your current password to manage passkeys.' ); }
				$old = self::records( $user->ID );
				$id  = $input['id'] ?? '';
				if ( ! isset( $old[ $id ] ) ) {
					throw new RuntimeException( 'Passkey unavailable.' ); }
				$new = $old;
				if ( 'passkey_remove' === $action ) {
					unset( $new[ $id ] );
				} else {
					$new[ $id ]['name'] = self::name( $input['name'] ?? '' ); }
				if ( ! GWQSH_Two_Factor::compare_and_swap_meta( $user->ID, 'gwqsh_passkeys', $old, $new ) ) {
					throw new RuntimeException( 'Unable to save passkey changes.' ); }
				GWQSH_Activity_Logger::log( 'Passkey changed', 'Registered credential ' . ( 'passkey_remove' === $action ? 'removed' : 'renamed' ), 'Security', $user->user_login );
				return self::listing( $user->ID );
			}
			throw new RuntimeException( 'Unsupported passkey operation.' );
		} catch ( Throwable $error ) {
			return new WP_Error( 'passkey_error', $error instanceof \GracewellSecuritySuitePro\Vendor\WebAuthn\WebAuthnException ? 'Passkey verification failed. Start again.' : $error->getMessage() ); }
	}
	/**
	 * Verify public WebAuthn requests before issuing a one-use login ticket.
	 *
	 * @throws RuntimeException Internally caught and converted to a safe response.
	 */
	public static function login_ajax() {
		if ( false === check_ajax_referer( 'gwqsh_login_factor', 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => 'Reload the login page and retry.' ), 403 ); }
		try {
			foreach ( $_POST as $value ) {
				if ( ! is_scalar( $value ) ) {
					throw new RuntimeException( 'Invalid request.' ); }
			}
			if ( ! GWQSH_Settings::is_active() || GWQSH_IP_Blocks::blocked( GWQSH_Settings::get_client_ip() ) || GWQSH_Login_Protection::is_locked( GWQSH_Settings::get_client_ip() ) ) {
				throw new RuntimeException( 'Authentication unavailable. Retry later.' ); }
			$count = GWQSH_Enterprise_Store::hit( 'passkey-login', GWQSH_Settings::get_client_ip(), 60 );
			if ( null === $count || $count > 12 ) {
				throw new RuntimeException( 'Too many requests. Retry in a minute.' ); }
			$input = wp_unslash( $_POST );
			if ( 'options' === ( $input['operation'] ?? '' ) ) {
				$identity = sanitize_text_field( $input['username'] ?? '' );
				$user     = is_email( $identity ) ? get_user_by( 'email', $identity ) : get_user_by( 'login', sanitize_user( $identity ) );
				$records  = $user ? self::records( $user->ID ) : array();
				$ids      = array_keys( $records );
				// An unknown account gets a real challenge with a random, unusable credential ID.
				$verifier = self::verifier();
				$args     = $verifier->getGetArgs( $ids ? array_map( array( __CLASS__, 'decode' ), $ids ) : array( random_bytes( 32 ) ), 120, true, true, true, true, true, 'required' );
				$token    = self::issue(
					array(
						'purpose'   => 'assert',
						'user_id'   => $user ? $user->ID : 0,
						'challenge' => self::b64( $verifier->getChallenge()->getBinaryString() ),
					)
				);
				wp_send_json_success(
					array(
						'options' => $args,
						'token'   => $token,
					)
				);
			}
			$challenge = self::consume( $input['token'] ?? '', 'assert' );
			$id        = $input['id'] ?? '';
			$old       = self::records( $challenge['user_id'] );
			if ( ! isset( $old[ $id ] ) || ! GWQSH_Two_Factor::reserve_factor_attempt( $challenge['user_id'] ) ) {
				throw new RuntimeException( 'Verification failed.' ); }
			$verifier = self::verifier();
			$row      = $old[ $id ];
			$verifier->processGet( self::origin( $input['clientDataJSON'] ?? '' ), self::decode( $input['authenticatorData'] ?? '' ), self::decode( $input['signature'] ?? '' ), $row['key'], self::decode( $challenge['challenge'] ), $row['counter'], true, true );
			$new                     = $old;
			$new[ $id ]['counter']   = (int) $verifier->getSignatureCounter();
			$new[ $id ]['last_used'] = time();
			if ( ! GWQSH_Two_Factor::compare_and_swap_meta( $challenge['user_id'], 'gwqsh_passkeys', $old, $new ) ) {
				throw new RuntimeException( 'Credential changed during sign-in.' ); }
			$user   = get_userdata( $challenge['user_id'] );
			$ticket = self::issue(
				array(
					'purpose'     => 'login',
					'user_id'     => $user->ID,
					'credential'  => $id,
					'fingerprint' => hash( 'sha256', $user->user_pass ),
				),
				60
			);
			wp_send_json_success(
				array(
					'ticket'   => $ticket,
					'username' => $user->user_login,
				)
			);
		} catch ( Throwable $error ) {
			wp_send_json_error( array( 'message' => 'Passkey sign-in failed or expired. Start again and verify your username.' ), 400 ); }
	}
	/**
	 * Resume the WordPress authentication pipeline using a verified one-use ticket.
	 *
	 * @param mixed $user user value.

	 * @throws RuntimeException Internally handled verification failure.
	 */
	public static function resume( $user ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- One-use IP-bound login ticket from a nonce-verified WebAuthn assertion authorizes this native authentication step.
		if ( empty( $_POST['gwqsh_passkey_ticket'] ) ) {
			return $user; }
		if ( is_wp_error( $user ) ) {
			return $user; }
		try {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- One-use IP-bound login ticket from a nonce-verified WebAuthn assertion authorizes this native authentication step.
			$data    = self::consume( sanitize_text_field( wp_unslash( $_POST['gwqsh_passkey_ticket'] ) ), 'login' );
			$account = get_userdata( $data['user_id'] );
			if ( ! self::available() || ! $account || ! isset( self::records( $account->ID )[ $data['credential'] ] ) || ! hash_equals( $data['fingerprint'], hash( 'sha256', $account->user_pass ) ) ) {
				throw new RuntimeException(); }
			$GLOBALS['gwqsh_passkey_verified'] = $account->ID;
			update_user_meta( $account->ID, 'gwqsh_2fa_last_verified', current_time( 'mysql' ) );
			GWQSH_Activity_Logger::log( 'Passkey login verified', 'User verification and credential signature validated.', 'Security', $account->user_login );
			return $account;
		} catch ( Throwable $error ) {
			return new WP_Error( 'gwqsh_passkey_invalid', 'Passkey session expired. Start again.' ); }
	}
}
