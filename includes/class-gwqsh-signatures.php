<?php
/** Cryptographically authenticated structured malware signatures; no executable feed content.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding bounded Ed25519 signatures and public keys only; never executable data.
/** Signatures service. */
final class GWQSH_Signatures {
	const STATE = 'gwqsh_signature_state';

	/** Operator-owned verification keys; overlap at most three keys during rotation.
	 *
	 * @return array Base64 public keys, never publisher private keys.
	 */
	public static function trusted_keys() {
		$keys = defined( 'GWQSH_SIGNATURE_PUBLIC_KEYS' ) ? GWQSH_SIGNATURE_PUBLIC_KEYS : ( defined( 'GWQSH_SIGNATURE_PUBLIC_KEY' ) ? array( GWQSH_SIGNATURE_PUBLIC_KEY ) : array() );
		$keys = apply_filters( 'gwqsh_signature_trusted_keys', $keys );
		return is_array( $keys ) && count( $keys ) <= 3 ? array_values(
			array_filter(
				$keys,
				static function ( $key ) {
					return is_string( $key ) && strlen( $key ) <= 64 && 32 === strlen( (string) base64_decode( $key, true ) );
				}
			)
		) : array();
	}
	/**
	 * Init.
	 *
	 * @return mixed Operation result.
	 */
	public static function init() {
		add_action( 'gwqsh_update_signatures', array( __CLASS__, 'update' ) );}
	/**
	 * Available.
	 *
	 * @return mixed Operation result.
	 */
	public static function available() {
		return function_exists( 'sodium_crypto_sign_verify_detached' ) && defined( 'GWQSH_SIGNATURE_FEED_URL' ) && ! empty( self::trusted_keys() );}
	/**
	 * Database.
	 *
	 * @return mixed Operation result.
	 */
	public static function database() {
		$state = (array) get_option( self::STATE, array() );
		return (array) ( $state['current']['data'] ?? get_option( 'gwqsh_signature_database', array() ) );}
	/**
	 * Version.
	 *
	 * @return mixed Operation result.
	 */
	public static function version() {
		return (int) ( self::database()['version'] ?? 0 );}
	/**
	 * Accept.
	 *
	 * @param mixed $json Json.
	 * @param mixed $signature Signature.
	 * @param mixed $public_key Public key.
	 * @return mixed Operation result.
	 */
	public static function verify( $json, $signature, $public_key = null ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return new WP_Error( 'crypto', 'Ed25519 verification is unavailable.' );
		}
		if ( ! is_string( $json ) || strlen( $json ) > 1048576 || ! is_string( $signature ) || strlen( $signature ) > 128 ) {
			return new WP_Error( 'size', 'Invalid signature envelope size.' );
		}
		$sig   = base64_decode( $signature, true );
		$keys  = null === $public_key ? self::trusted_keys() : array( $public_key );
		$valid = false;
		foreach ( $keys as $encoded ) {
			$key = is_string( $encoded ) && strlen( $encoded ) <= 64 ? base64_decode( $encoded, true ) : false;
			if ( GWQSH_Crypto::verify_ed25519( $sig, $json, $key ) ) {
				$valid = true;
				break;
			}
		}
		if ( ! $valid ) {
			return new WP_Error( 'signature', 'Untrusted or unsigned signature database.' );
		}
		$data = json_decode( $json, true, 32 );
		$now  = time();
		if ( ! is_array( $data ) || array_diff( array_keys( $data ), array( 'schema', 'version', 'created_at', 'expires_at', 'signatures' ) ) || ( $data['schema'] ?? null ) !== 1 || ! is_int( $data['version'] ?? null ) || $data['version'] < 1 || ! is_int( $data['created_at'] ?? null ) || $data['created_at'] < 0 || ! is_int( $data['expires_at'] ?? null ) || $data['created_at'] > $now + 300 || $data['expires_at'] <= $now || $data['expires_at'] > $data['created_at'] + 90 * DAY_IN_SECONDS || $data['created_at'] >= $data['expires_at'] || ! is_array( $data['signatures'] ?? null ) || count( $data['signatures'] ) > 2000 ) {
			return new WP_Error( 'schema', 'Expired, replayed or malformed signature database.' );
		}
		$ids = array();
		foreach ( $data['signatures'] as $r ) {
			if ( ! is_array( $r ) || array_diff( array_keys( $r ), array( 'id', 'type', 'value', 'score', 'scopes' ) ) || ! is_string( $r['id'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_.-]{1,64}$/D', $r['id'] ) || isset( $ids[ $r['id'] ] ) || ! in_array( $r['type'] ?? null, array( 'sha256', 'literal' ), true ) || ! is_string( $r['value'] ?? null ) || ! is_int( $r['score'] ?? null ) || $r['score'] < 40 || $r['score'] > 100 || ! is_array( $r['scopes'] ?? null ) || count( $r['scopes'] ) > 4 || count( array_filter( $r['scopes'], 'is_string' ) ) !== count( $r['scopes'] ) || array_diff( $r['scopes'], array( 'Core', 'Plugin', 'Theme', 'Uploads' ) ) ) {
				return new WP_Error( 'entry', 'Invalid signature entry.' );
			}
			if ( ( 'sha256' === $r['type'] && ! preg_match( '/^[a-f0-9]{64}$/D', $r['value'] ) ) || ( 'literal' === $r['type'] && ( strlen( $r['value'] ) < 8 || strlen( $r['value'] ) > 256 || str_contains( $r['value'], "\0" ) ) ) ) {
				return new WP_Error( 'pattern', 'Unsafe or malformed signature pattern. Regex and executable entries are not supported.' );
			}
			$ids[ $r['id'] ] = true;
		}
		$data['_key_fingerprint'] = hash( 'sha256', $key );
		$data['_managed_trust']   = null === $public_key;
		return $data;
	}

	/** Activate verified bytes while retaining an independent anti-downgrade watermark.
	 *
	 * @param string      $json Signed bytes.
	 * @param string      $signature Detached signature.
	 * @param string|null $public_key Explicit trusted caller key, never supplied by HTTP controllers.
	 * @return true|WP_Error Activation result.
	 */
	public static function accept( $json, $signature, $public_key = null ) {
		$data = self::verify( $json, $signature, $public_key );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		$lock = GWQSH_Enterprise_Store::lock( 'signature-update', 15 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Another signature update is active.' );
		}
		try {
			$state = (array) get_option( self::STATE, array() );
			if ( $data['version'] <= max( self::version(), $state['high_water'] ?? 0 ) ) {
				return new WP_Error( 'replay', 'A newer database is already installed.' );
			}$old = self::database();
			if ( $old ) {
				update_option( 'gwqsh_signature_previous', $old, false );
			}$data['verified_at'] = time();
			$next                 = array(
				'current'    => array(
					'json'      => $json,
					'signature' => $signature,
					'data'      => $data,
				),
				'previous'   => $state['current'] ?? array(),
				'high_water' => $data['version'],
			);
			// Commit the watermark first: a failed mirror write must never enable replay.
			update_option( self::STATE, $next, false );
			if ( get_option( self::STATE ) !== $next ) {
				return new WP_Error( 'storage', 'Signature activation state could not be committed.' );
			}
			update_option( 'gwqsh_signature_database', $data, false );
			if ( self::database() !== $data ) {
				return new WP_Error( 'storage', 'Signature database could not be committed.' );
			}
			return true;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'signature-update', $lock );}
	}
	/**
	 * Update.
	 *
	 * @return mixed Operation result.
	 */
	public static function update() {
		if ( ! defined( 'GWQSH_SIGNATURE_FEED_URL' ) || ! self::available() || ! GWQSH_Enterprise_Config::get( 'signatures' )['enabled'] ) {
			self::record_status( 'unconfigured' );
			return new WP_Error( 'unconfigured', 'No trusted signature publisher is configured.' );
		}
		$response = GWQSH_Secure_HTTP::request( 'signatures', GWQSH_SIGNATURE_FEED_URL );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			self::record_status( 'transport' );
			return new WP_Error( 'transport', 'Signature update unavailable; last verified database retained.' );
		}
		$body   = wp_remote_retrieve_body( $response );
		$sig    = wp_remote_retrieve_header( $response, 'x-gwqsh-ed25519' );
		$result = self::accept( $body, $sig );
		self::record_status( is_wp_error( $result ) ? $result->get_error_code() : 'verified' );
		return $result;
	}
	/** Persist every attempted update result without remote bodies or credentials.
	 *
	 * @param string $status Validated local result code.
	 */
	private static function record_status( $status ) {
		update_option(
			'gwqsh_signature_update_status',
			array(
				'at'     => time(),
				'status' => $status,
			),
			false
		);
		if ( 'verified' !== $status && 1 === GWQSH_Enterprise_Store::hit( 'signature-update-alert', $status, DAY_IN_SECONDS ) ) {
			GWQSH_Activity_Logger::log( 'Signature intelligence update failed', $status, 'Security' );
		}
	}
	/**
	 * Match.
	 *
	 * @param mixed $content Content.
	 * @param mixed $scope Scope.
	 * @param mixed $sha256 Sha256.
	 * @return mixed Operation result.
	 */
	public static function match( $content, $scope, $sha256 ) {
		$db  = self::database();
		$out = array();
		if ( ! empty( $db['_managed_trust'] ) && ! in_array(
			$db['_key_fingerprint'] ?? '',
			array_map(
				static function ( $key ) {
					return hash( 'sha256', base64_decode( $key, true ) ); },
				self::trusted_keys()
			),
			true
		) ) {
			return $out;
		}
		if ( ( $db['expires_at'] ?? 0 ) <= time() ) {
			return $out;
		}
		$excluded = array_merge( (array) get_option( 'gwqsh_signature_exclusions', array() ), preg_split( '/[\s,]+/', GWQSH_Enterprise_Config::get( 'signatures' )['excluded_hashes'], -1, PREG_SPLIT_NO_EMPTY ) );
		if ( in_array( $sha256, $excluded, true ) ) {
			return $out;
		}
		// A signed database has at most 2,000 entries; literals inspect only the analyzer's bounded bytes.
		$budget = microtime( true ) + .025;
		foreach ( $db['signatures'] ?? array() as $r ) {
			if ( microtime( true ) > $budget ) {
				$out['signature_budget_limit'] = 0;
				break;
			}if ( $r['scopes'] && ! in_array( $scope, $r['scopes'], true ) ) {
				continue;
			}
			if ( ( 'sha256' === $r['type'] && $sha256 && hash_equals( $r['value'], $sha256 ) ) || ( 'literal' === $r['type'] && false !== strpos( $content, $r['value'] ) ) ) {
				$out[ 'signature:' . $r['id'] ] = $r['score'];
			}
		}
		return $out;
	}

	/** Reverify last-known-good bytes under current trust; never lower the watermark.
	 *
	 * @param int $expected Expected current version for stale-operation protection.
	 * @return true|WP_Error Rollback result; controller requires one-use recent authorization.
	 */
	public static function rollback( $expected ) {
		$lock = GWQSH_Enterprise_Store::lock( 'signature-update', 15 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Another signature update is active.' );
		}
		try {
			$state = (array) get_option( self::STATE, array() );
			if ( self::version() !== $expected || empty( $state['previous'] ) ) {
				return new WP_Error( 'changed', 'No signed previous package or active version changed.' );
			}
			$data = self::verify( $state['previous']['json'], $state['previous']['signature'] );
			if ( is_wp_error( $data ) ) {
				return $data;
			}
			$prior                    = $state['current'];
			$state['current']         = $state['previous'];
			$state['previous']        = $prior;
			$data['verified_at']      = time();
			$state['current']['data'] = $data;
			update_option( self::STATE, $state, false );
			if ( get_option( self::STATE ) !== $state ) {
				return new WP_Error( 'storage', 'Signature rollback state could not be committed.' );
			}
			update_option( 'gwqsh_signature_database', $data, false );
			if ( self::database() !== $data ) {
				return new WP_Error( 'storage', 'Signature rollback could not be committed.' );
			}
			GWQSH_Activity_Logger::log( 'Malware signature rollback', 'Verified version ' . $data['version'] . '; anti-replay watermark retained.', 'Security' );
			return true;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'signature-update', $lock );
		}
	}

	/** Describe actual coverage independently of a configured URL.
	 *
	 * @return array Current local feed health, never a claim of live protection.
	 */
	public static function health() {
		$db      = self::database();
		$trusted = empty( $db['_managed_trust'] ) || in_array(
			$db['_key_fingerprint'] ?? '',
			array_map(
				static function ( $key ) {
					return hash( 'sha256', base64_decode( $key, true ) );
				},
				self::trusted_keys()
			),
			true
		);
		return array(
			'configured'   => self::available(),
			'version'      => $db['version'] ?? 0,
			'verified_at'  => $db['verified_at'] ?? 0,
			'expires_at'   => $db['expires_at'] ?? 0,
			'coverage'     => ! $trusted ? 'Signing key removed; managed signatures inactive' : ( empty( $db['verified_at'] ) ? 'No verified signature coverage' : ( ( $db['expires_at'] ?? 0 ) > time() ? 'Installed signatures within validity window' : 'Expired signature coverage' ) ),
			'last_attempt' => get_option( 'gwqsh_signature_update_status', array() ),
		);
	}
}
