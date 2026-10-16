<?php
/**
 * Shared trusted network and nonblocking geography services.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Network service. */
final class GWQSH_Network {

	/**
	 * Normalize a validated IPv4 or IPv6 address.
	 *
	 * @param mixed $ip ip value.
	 */
	public static function canonical( $ip ) {
		if ( ! is_string( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			return ''; }
		$packed = inet_pton( $ip );
		if ( 16 === strlen( $packed ) && substr( $packed, 0, 12 ) === str_repeat( "\0", 10 ) . "\xff\xff" ) {
			return inet_ntop( substr( $packed, 12 ) ); }
		return inet_ntop( $packed );
	}

	/**
	 * Compare an address against a validated exact IP or CIDR range.
	 *
	 * @param mixed $ip ip value.
	 * @param mixed $range range value.
	 */
	public static function matches( $ip, $range ) {
		if ( ! is_string( $range ) ) {
			return false; }
		$parts = explode( '/', trim( $range ) );
		$addr  = self::canonical( $ip );
		$base  = self::canonical( $parts[0] );
		if ( ! $addr || ! $base ) {
			return false; }
		$a = inet_pton( $addr );
		$b = inet_pton( $base );
		if ( strlen( $a ) !== strlen( $b ) ) {
			return false; }
		if ( count( $parts ) === 1 ) {
			return hash_equals( $a, $b ); }
		if ( count( $parts ) !== 2 || ! ctype_digit( $parts[1] ) || (int) $parts[1] > strlen( $a ) * 8 ) {
			return false; }
		$bits  = (int) $parts[1];
		$bytes = intdiv( $bits, 8 );
		$tail  = $bits % 8;
		return substr( $a, 0, $bytes ) === substr( $b, 0, $bytes ) && ( ! $tail || ( ord( $a[ $bytes ] ) & ( 255 << ( 8 - $tail ) ) ) === ( ord( $b[ $bytes ] ) & ( 255 << ( 8 - $tail ) ) ) );
	}

	/** Return administrator-configured trusted proxy ranges. */
	public static function trusted() {
		$defined = defined( 'GWQSH_TRUSTED_PROXIES' ) && is_array( GWQSH_TRUSTED_PROXIES ) ? array_filter( GWQSH_TRUSTED_PROXIES, 'is_string' ) : array();
		$saved   = preg_split( '/[\s,]+/', (string) GWQSH_Settings::get( 'trusted_proxies', '' ), -1, PREG_SPLIT_NO_EMPTY );
		return array_values( array_unique( array_merge( $defined, $saved ) ) );
	}

	/**
	 * Check whether an address belongs to an explicitly trusted proxy range.
	 *
	 * @param mixed $ip ip value.
	 * @param mixed $ranges ranges value.
	 */
	public static function trusted_ip( $ip, $ranges = null ) {
		foreach ( null === $ranges ? self::trusted() : $ranges as $range ) {
			if ( self::matches( $ip, $range ) ) {
				return true; }
		}
		return false;
	}

	/** Register the service hooks. */
	public static function init() {
		add_action( 'gwqsh_geo_lookup', array( __CLASS__, 'resolve' ), 10, 1 ); }

	/**
	 * Return cached attribution and queue a bounded background lookup.
	 *
	 * @param mixed $ip ip value.
	 */
	public static function country( $ip ) {
		static $queued = null;
		if ( null === $queued ) {
			$queued = 0;
			foreach ( _get_cron_array() as $hooks ) {
				if ( isset( $hooks['gwqsh_geo_lookup'] ) ) {
					$queued += count( $hooks['gwqsh_geo_lookup'] ); }
			}
		}
		$ip = self::canonical( $ip );
		if ( ! $ip ) {
			return array(
				'country' => 'Invalid IP',
				'code'    => '',
			); }
		if ( self::matches( $ip, '127.0.0.0/8' ) || '::1' === $ip ) {
			return array(
				'country' => 'Localhost',
				'code'    => '',
			); }
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) || self::matches( $ip, '100.64.0.0/10' ) || self::matches( $ip, 'fe80::/10' ) ) {
			return array(
				'country' => 'Local Network',
				'code'    => '',
			);
		}
		$key    = 'gwqsh_geo_' . md5( $ip );
		$cached = GWQSH_Enterprise_Store::get( 'geolocation', $ip );
		if ( null === $cached ) {
			$cached = get_transient( $key ); }
		if ( is_array( $cached ) ) {
			return $cached; }
		if ( GWQSH_Settings::get( 'geo_enabled', false ) && $queued < 20 && ! wp_next_scheduled( 'gwqsh_geo_lookup', array( $ip ) ) ) {
			wp_schedule_single_event( time() + 5 + $queued * 10, 'gwqsh_geo_lookup', array( $ip ) );
			++$queued;
		}
		return array(
			'country' => GWQSH_Settings::get( 'geo_enabled', false ) ? 'Lookup pending' : 'Lookup disabled',
			'code'    => '',
		);
	}

	/**
	 * Resolve a public address through a fixed HTTPS provider and cache the result.
	 *
	 * @param mixed $ip ip value.
	 */
	public static function resolve( $ip ) {
		$ip = self::canonical( $ip );
		if ( ! $ip || ! GWQSH_Settings::get( 'geo_enabled', false ) || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return; }
		// A fixed HTTPS endpoint; untrusted request data cannot select a network host.
		$result = apply_filters( 'gwqsh_geolocation_result', null, $ip );
		if ( ! is_array( $result ) ) {
			$response = wp_safe_remote_get(
				'https://ipwho.is/' . rawurlencode( $ip ),
				array(
					'timeout'             => 4,
					'redirection'         => 0,
					'limit_response_size' => 8192,
				)
			);
			$body     = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ? json_decode( wp_remote_retrieve_body( $response ), true ) : array();
			$result   = ! empty( $body['success'] ) ? array(
				'country' => $body['country'] ?? '',
				'code'    => $body['country_code'] ?? '',
				'lat'     => $body['latitude'] ?? 0,
				'lon'     => $body['longitude'] ?? 0,
			) : array();
		}
		$valid = ! empty( $result['country'] ) && is_string( $result['country'] ) && is_string( $result['code'] ?? null ) && in_array( $result['code'], GWQSH_Enterprise_Config::country_codes(), true );
		$data  = $valid ? array(
			'country' => sanitize_text_field( $result['country'] ),
			'code'    => $result['code'],
			'lat'     => max( -90, min( 90, (float) ( $result['lat'] ?? 0 ) ) ),
			'lon'     => max( -180, min( 180, (float) ( $result['lon'] ?? 0 ) ) ),
		) : array(
			'country' => 'Lookup unavailable',
			'code'    => '',
		);
		GWQSH_Enterprise_Store::put( 'geolocation', $ip, $data, $valid ? 7 * DAY_IN_SECONDS : HOUR_IN_SECONDS );
		// Legacy transient readers remain supported; new writes use bounded storage.
	}
}
