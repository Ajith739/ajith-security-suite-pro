<?php
/** Fixed-destination HTTP transport. Never accepts a general-purpose URL from a visitor.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Secure http service. */
final class GWQSH_Secure_HTTP {
	/**
	 * Allowed.
	 *
	 * @param mixed $url Url.
	 * @param mixed $service Service.
	 * @return mixed Operation result.
	 */
	public static function allowed( $url, $service ) {
		if ( ! is_string( $url ) || strlen( $url ) > 2048 ) {
			return false;
		}$u = wp_parse_url( $url );
		if ( ! $u || ( $u['scheme'] ?? '' ) !== 'https' || isset( $u['user'] ) || isset( $u['pass'] ) || isset( $u['fragment'] ) || ( isset( $u['port'] ) && 443 !== (int) $u['port'] ) ) {
			return false;
		}
		$host = strtolower( $u['host'] ?? '' );
		$path = $u['path'] ?? '/';
		if ( 'slack' === $service ) {
			return 'hooks.slack.com' === $host && ! isset( $u['query'] ) && (bool) preg_match( '~^/services/[A-Za-z0-9_-]{6,128}/[A-Za-z0-9_-]{6,128}/[A-Za-z0-9_-]{10,256}$~D', $path );
		}
		if ( 'collector' === $service ) {
			return in_array( $host, array( 'http-intake.logs.datadoghq.com', 'http-intake.logs.datadoghq.eu' ), true ) && '/api/v2/logs' === $path && ! isset( $u['query'] );
		}
		if ( 'reputation' === $service ) {
			return 'api.abuseipdb.com' === $host && '/api/v2/check' === $path;
		}
		if ( 'cloudflare' === $service ) {
			return 'api.cloudflare.com' === $host && '/client/v4/ips' === $path && ! isset( $u['query'] );
		}
		if ( 'signatures' === $service ) {
			return defined( 'GWQSH_SIGNATURE_FEED_URL' ) && hash_equals( GWQSH_SIGNATURE_FEED_URL, $url ) && ! filter_var( $host, FILTER_VALIDATE_IP ) && false !== strpos( $host, '.' );
		}
		return false;
	}
	/**
	 * Request.
	 *
	 * @param mixed $service Service.
	 * @param mixed $url Url.
	 * @param array $args Args.
	 * @return mixed Operation result.
	 */
	public static function request( $service, $url, array $args = array() ) {
		if ( ! self::allowed( $url, $service ) ) {
			return new WP_Error( 'destination', 'This destination is not approved.' );
		}
		$args                        = wp_parse_args(
			$args,
			array(
				'method'  => 'GET',
				'headers' => array(),
			)
		);
		$args['timeout']             = 5;
		$args['redirection']         = 0;
		$args['sslverify']           = true;
		$args['reject_unsafe_urls']  = true;
		$args['limit_response_size'] = 'signatures' === $service ? 1048576 : 32768;
		return wp_safe_remote_request( $url, $args );
	}
}
