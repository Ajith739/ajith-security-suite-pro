<?php
/** Provider-neutral licensing state; never disables established protection.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** License service. */
final class GWQSH_License {
	/** Register byte-authenticated updates for this plugin only. */
	public static function init() {
		add_filter( 'upgrader_pre_download', array( __CLASS__, 'verified_download' ), 99, 4 );
	}

	/** Validate an operator-provided signed manifest, independent of a licensing outage.
	 *
	 * @param string $json Exact signed manifest bytes.
	 * @param string $signature Base64 detached signature.
	 * @return array|WP_Error Validated manifest.
	 */
	public static function verify_update_manifest( $json, $signature ) {
		$trust = (array) apply_filters( 'gwqsh_update_trust', array() );
		$data = is_string( $json ) && strlen( $json ) <= 8192 ? json_decode( $json, true, 8 ) : null;
		if ( ! is_array( $data ) || ! is_string( $signature ) || strlen( $signature ) > 128 || ! is_string( $data['key_id'] ?? null ) || ! is_array( $trust['keys'] ?? null ) ) {
			return new WP_Error( 'update_envelope', 'A signed update manifest is required.' );
		}
		$key = $trust['keys'][ $data['key_id'] ] ?? array();
		if ( ! is_array( $key ) ) {
			return new WP_Error( 'update_trust', 'Update signing key configuration is malformed.' );
		}
		$now = time();
		if ( ! is_string( $key['public_key'] ?? null ) || ! is_int( $key['not_before'] ?? null ) || ! is_int( $key['not_after'] ?? null ) || $key['not_before'] > $now || $key['not_after'] <= $now || ! GWQSH_Crypto::verify_ed25519( base64_decode( $signature, true ), $json, base64_decode( $key['public_key'], true ) ) ) {
			return new WP_Error( 'update_signature', 'Update signature is untrusted or expired.' );
		}
		$fields = array( 'schema', 'feed', 'publisher', 'key_id', 'version', 'issued_at', 'expires_at', 'plugin', 'package', 'sha256', 'size' );
		$url = is_string( $data['package'] ?? null ) ? wp_parse_url( $data['package'] ) : false;
		if ( array_diff( $fields, array_keys( $data ) ) || array_diff( array_keys( $data ), $fields ) || 1 !== $data['schema'] || 'plugin-update' !== $data['feed'] || empty( $trust['publisher'] ) || $data['publisher'] !== $trust['publisher'] || GWQSH_PLUGIN_BASENAME !== $data['plugin'] || ! is_string( $data['version'] ) || ! preg_match( '/^[0-9][A-Za-z0-9.-]{0,63}$/D', $data['version'] ) || version_compare( $data['version'], GWQSH_VERSION, '<=' ) || ! is_int( $data['issued_at'] ) || ! is_int( $data['expires_at'] ) || $data['issued_at'] < $key['not_before'] || $data['issued_at'] > $now + 300 || $data['expires_at'] <= $now || $data['expires_at'] <= $data['issued_at'] || $data['expires_at'] > min( $key['not_after'], $data['issued_at'] + 30 * DAY_IN_SECONDS ) || ! is_int( $data['size'] ) || $data['size'] < 1 || $data['size'] > 67108864 || ! is_string( $data['sha256'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $data['sha256'] ) || ! is_string( $data['package'] ) || strlen( $data['package'] ) > 2048 || preg_match( '/[\x00-\x20\x7f]/', $data['package'] ) || ! is_array( $url ) || 'https' !== ( $url['scheme'] ?? '' ) || empty( $url['host'] ) || isset( $url['user'] ) || isset( $url['pass'] ) || isset( $url['fragment'] ) || ( isset( $url['port'] ) && 443 !== $url['port'] ) ) {
			return new WP_Error( 'update_schema', 'Update manifest is malformed, expired or a downgrade.' );
		}
		return $data;
	}

	/** Check actual downloaded bytes before WordPress is allowed to extract them.
	 *
	 * @param string $file Downloaded local file.
	 * @param array $manifest Already authenticated manifest.
	 * @return bool Whether both exact length and SHA256 match.
	 */
	public static function verify_package_bytes( $file, array $manifest ) {
		return is_string( $file ) && is_file( $file ) && ! is_link( $file ) && filesize( $file ) === $manifest['size'] && hash_equals( $manifest['sha256'], (string) hash_file( 'sha256', $file ) );
	}

	/** WordPress upgrader gateway. A provider supplies signed bytes, never trusted URLs alone.
	 *
	 * @param mixed $reply Earlier download result.
	 * @param string $package Proposed package URL.
	 * @param object $upgrader WordPress upgrader.
	 * @param array $extra Operation context.
	 * @return mixed Verified temporary filename, error, or unchanged unrelated operation.
	 */
	public static function verified_download( $reply, $package, $upgrader, $extra ) {
		if ( ( $extra['plugin'] ?? '' ) !== GWQSH_PLUGIN_BASENAME ) {
			return $reply;
		}
		$envelope = (array) apply_filters( 'gwqsh_update_manifest', array(), $package );
		$manifest = self::verify_update_manifest( $envelope['json'] ?? '', $envelope['signature'] ?? '' );
		if ( is_wp_error( $manifest ) ) {
			return $manifest;
		}
		if ( $manifest['package'] !== $package ) {
			return new WP_Error( 'update_url', 'Package URL does not match its signed manifest.' );
		}
		$file = wp_tempnam( 'gwqsh-verified-update' );
		if ( ! $file ) {
			return new WP_Error( 'update_storage', 'Temporary update storage unavailable.' );
		}
		$response = wp_safe_remote_get( $package, array( 'timeout' => 60, 'redirection' => 0, 'stream' => true, 'filename' => $file, 'limit_response_size' => $manifest['size'] + 1 ) );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) || ! self::verify_package_bytes( $file, $manifest ) ) {
			wp_delete_file( $file );
			return new WP_Error( 'update_integrity', 'Downloaded package failed its signed size or SHA256 check.' );
		}
		return $file;
	}

	/**
	 * Status.
	 *
	 * @return mixed Operation result.
	 */
	public static function status() {
		$state = (array) get_option(
			'gwqsh_license_state',
			array(
				'state'      => 'unconfigured',
				'expires_at' => 0,
				'checked_at' => 0,
			)
		);
		if ( ! apply_filters( 'gwqsh_license_provider', null ) instanceof GWQSH_License_Provider ) {
			$state['state'] = 'unconfigured';
		} elseif ( 'active' === ( $state['state'] ?? '' ) && ! empty( $state['expires_at'] ) && $state['expires_at'] < time() ) {
			$state['state'] = 'expired';
		}
		return $state;
	}
	/**
	 * Operate.
	 *
	 * @param mixed $action Action.
	 * @return mixed Operation result.
	 */
	public static function operate( $action ) {
		if ( ! in_array( $action, array( 'activate', 'deactivate', 'refresh' ), true ) ) {
			return new WP_Error( 'action', 'Invalid license operation.' );
		}
		$provider = apply_filters( 'gwqsh_license_provider', null );
		$token    = GWQSH_Enterprise_Config::secret( 'license', 'key' );
		if ( ! $provider instanceof GWQSH_License_Provider || ! $token ) {
			return new WP_Error( 'unconfigured', 'Supply an official licensing provider adapter and token first.' );
		}
		$hit = GWQSH_Enterprise_Store::hit( 'license', get_current_user_id(), 60 );
		if ( null === $hit || $hit > 3 ) {
			return new WP_Error( 'rate', 'Retry the license action in one minute.' );
		}
		try {
			$result = $provider->$action( $token, hash( 'sha256', home_url() ) );
		} catch ( Throwable $error ) {
			$result = new WP_Error( 'unavailable', 'Licensing service unavailable. Existing protection continues.' );}
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		if ( ! is_array( $result ) || ! in_array( $result['state'] ?? null, array( 'active', 'inactive', 'expired', 'renewal' ), true ) || ! is_int( $result['expires_at'] ?? null ) || $result['expires_at'] < 0 ) {
			return new WP_Error( 'response', 'Invalid authenticated license response.' );
		}
		$state = array(
			'state'      => $result['state'],
			'expires_at' => $result['expires_at'],
			'checked_at' => time(),
		);
		update_option( 'gwqsh_license_state', $state, false );
		return $state;
	}
}
