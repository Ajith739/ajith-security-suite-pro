<?php
/** Cryptographically authenticated structured malware signatures; no executable feed content.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Decoding bounded Ed25519 signatures and public keys only; never executable data.
/** Signatures service. */
final class GWQSH_Signatures {
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
		return function_exists( 'sodium_crypto_sign_verify_detached' ) && defined( 'GWQSH_SIGNATURE_FEED_URL' ) && defined( 'GWQSH_SIGNATURE_PUBLIC_KEY' ) && is_string( GWQSH_SIGNATURE_PUBLIC_KEY ) && strlen( (string) base64_decode( GWQSH_SIGNATURE_PUBLIC_KEY, true ) ) === 32;}
	/**
	 * Database.
	 *
	 * @return mixed Operation result.
	 */
	public static function database() {
		return (array) get_option( 'gwqsh_signature_database', array() );}
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
	public static function accept( $json, $signature, $public_key = null ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) ) {
			return new WP_Error( 'crypto', 'Ed25519 verification is unavailable.' );
		}
		if ( ! is_string( $json ) || strlen( $json ) > 1048576 || ! is_string( $signature ) || strlen( $signature ) > 128 ) {
			return new WP_Error( 'size', 'Invalid signature envelope size.' );
		}
		$sig = base64_decode( $signature, true );
		$key = null === $public_key ? ( defined( 'GWQSH_SIGNATURE_PUBLIC_KEY' ) ? base64_decode( GWQSH_SIGNATURE_PUBLIC_KEY, true ) : false ) : base64_decode( $public_key, true );
		if ( ! $sig || strlen( $sig ) !== 64 || ! $key || strlen( $key ) !== 32 || ! sodium_crypto_sign_verify_detached( $sig, $json, $key ) ) {
			return new WP_Error( 'signature', 'Untrusted or unsigned signature database.' );
		}
		$data = json_decode( $json, true, 32 );
		$now  = time();
		if ( ! is_array( $data ) || ( $data['schema'] ?? null ) !== 1 || ! is_int( $data['version'] ?? null ) || $data['version'] <= self::version() || ! is_int( $data['created_at'] ?? null ) || ! is_int( $data['expires_at'] ?? null ) || $data['created_at'] > $now + 300 || $data['expires_at'] <= $now || $data['expires_at'] > $now + 90 * DAY_IN_SECONDS || $data['created_at'] >= $data['expires_at'] || ! is_array( $data['signatures'] ?? null ) || count( $data['signatures'] ) > 2000 ) {
			return new WP_Error( 'schema', 'Expired, replayed or malformed signature database.' );
		}
		$ids = array();
		foreach ( $data['signatures'] as $r ) {
			if ( ! is_array( $r ) || array_diff( array_keys( $r ), array( 'id', 'type', 'value', 'score', 'scopes' ) ) || ! is_string( $r['id'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_.-]{1,64}$/D', $r['id'] ) || isset( $ids[ $r['id'] ] ) || ! in_array( $r['type'] ?? null, array( 'sha256', 'literal' ), true ) || ! is_string( $r['value'] ?? null ) || ! is_int( $r['score'] ?? null ) || $r['score'] < 40 || $r['score'] > 100 || ! is_array( $r['scopes'] ?? null ) || array_diff( $r['scopes'], array( 'Core', 'Plugin', 'Theme', 'Uploads' ) ) ) {
				return new WP_Error( 'entry', 'Invalid signature entry.' );
			}
			if ( ( 'sha256' === $r['type'] && ! preg_match( '/^[a-f0-9]{64}$/D', $r['value'] ) ) || ( 'literal' === $r['type'] && ( strlen( $r['value'] ) < 8 || strlen( $r['value'] ) > 256 || str_contains( $r['value'], "\0" ) ) ) ) {
				return new WP_Error( 'pattern', 'Unsafe or malformed signature pattern. Regex and executable entries are not supported.' );
			}
			$ids[ $r['id'] ] = true;
		}
		$lock = GWQSH_Enterprise_Store::lock( 'signature-update', 15 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Another signature update is active.' );
		}
		try {
			if ( $data['version'] <= self::version() ) {
				return new WP_Error( 'replay', 'A newer database is already installed.' );
			}$old = self::database();
			if ( $old ) {
				update_option( 'gwqsh_signature_previous', $old, false );
			}$data['verified_at'] = $now;
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
		if ( ! self::available() || ! GWQSH_Enterprise_Config::get( 'signatures' )['enabled'] ) {
			return new WP_Error( 'unconfigured', 'No trusted signature publisher is configured.' );
		}
		$response = GWQSH_Secure_HTTP::request( 'signatures', GWQSH_SIGNATURE_FEED_URL );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'transport', 'Signature update unavailable; last verified database retained.' );
		}
		$body   = wp_remote_retrieve_body( $response );
		$sig    = wp_remote_retrieve_header( $response, 'x-gwqsh-ed25519' );
		$result = self::accept( $body, $sig );
		update_option(
			'gwqsh_signature_update_status',
			array(
				'at'     => time(),
				'status' => is_wp_error( $result ) ? $result->get_error_code() : 'verified',
			),
			false
		);
		return $result;
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
		if ( ( $db['expires_at'] ?? 0 ) < time() ) {
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
}
