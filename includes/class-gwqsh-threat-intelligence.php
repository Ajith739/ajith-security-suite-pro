<?php
/** Optional country and reputation access decisions; unknown data is never fabricated.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Threat intelligence service. */
final class GWQSH_Threat_Intelligence {
	/**
	 * Init.
	 *
	 * @return mixed Operation result.
	 */
	public static function init() {
		add_action( 'gwqsh_reputation_lookup', array( __CLASS__, 'resolve' ) );}
	/**
	 * Available.
	 *
	 * @return mixed Operation result.
	 */
	public static function available() {
		return GWQSH_Enterprise_Config::get( 'reputation' )['enabled'] && ( GWQSH_Enterprise_Config::has_secret( 'reputation', 'key' ) || apply_filters( 'gwqsh_reputation_provider', null ) instanceof GWQSH_Reputation_Provider );}
	/**
	 * Lookup.
	 *
	 * @param mixed $ip Ip.
	 * @return mixed Operation result.
	 */
	public static function lookup( $ip ) {
		$ip = GWQSH_Network::canonical( $ip );
		if ( ! $ip || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) || GWQSH_Login_Protection::is_ip_allowlisted( $ip ) || ! self::available() ) {
			return null;
		}
		$cached = GWQSH_Enterprise_Store::get( 'reputation', $ip );
		if ( null !== $cached ) {
			return $cached;
		}
		$gate = GWQSH_Enterprise_Store::hit( 'reputation-queue', 'site', 60 );
		if ( null !== $gate && $gate <= 10 && ! wp_next_scheduled( 'gwqsh_reputation_lookup', array( $ip ) ) ) {
			wp_schedule_single_event( time() + 10, 'gwqsh_reputation_lookup', array( $ip ) );
		}
		return null;
	}
	/**
	 * Validate.
	 *
	 * @param mixed $data Data.
	 * @return mixed Operation result.
	 */
	public static function validate( $data ) {
		if ( ! is_array( $data ) || ! isset( $data['score'] ) || ! is_int( $data['score'] ) || $data['score'] < 0 || $data['score'] > 100 || ! isset( $data['categories'] ) || ! is_array( $data['categories'] ) || count( $data['categories'] ) > 4 || count( array_filter( $data['categories'], 'is_string' ) ) !== count( $data['categories'] ) || array_diff( $data['categories'], array( 'brute_force', 'spam', 'scanner', 'hostile' ) ) ) {
			return new WP_Error( 'response', 'Invalid reputation data.' );
		}
		return array(
			'score'      => $data['score'],
			'categories' => array_values( array_unique( $data['categories'] ) ),
			'checked_at' => time(),
		);
	}
	/**
	 * Resolve.
	 *
	 * @param mixed $ip Ip.
	 * @return mixed Operation result.
	 */
	public static function resolve( $ip ) {
		$ip = GWQSH_Network::canonical( $ip );
		if ( ! $ip || ! self::available() || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) || GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return;
		}
		$lock = GWQSH_Enterprise_Store::lock( 'reputation-' . $ip, 15 );
		if ( ! $lock ) {
			return;
		}
		try {
			$adapter = apply_filters( 'gwqsh_reputation_provider', null );
			if ( $adapter instanceof GWQSH_Reputation_Provider ) {
				try {
							$data = $adapter->lookup( $ip );
				} catch ( Throwable $error ) {
							$data = new WP_Error( 'provider', 'Reputation provider failed.' );}
			} else {
						$response = GWQSH_Secure_HTTP::request(
							'reputation',
							'https://api.abuseipdb.com/api/v2/check?' . http_build_query(
								array(
									'ipAddress'    => $ip,
									'maxAgeInDays' => 30,
								)
							),
							array(
								'headers' => array(
									'Key'    => GWQSH_Enterprise_Config::secret( 'reputation', 'key' ),
									'Accept' => 'application/json',
								),
							)
						);
						$body     = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ? json_decode( wp_remote_retrieve_body( $response ), true ) : null;
				$row              = $body['data'] ?? null;
						$data     = is_array( $row ) && GWQSH_Network::canonical( $row['ipAddress'] ?? '' ) === $ip ? array(
							'score'      => $row['abuseConfidenceScore'] ?? null,
							'categories' => array( 'hostile' ),
						) : null;
			}
			$valid = self::validate( $data );
			GWQSH_Enterprise_Store::put( 'reputation', $ip, is_wp_error( $valid ) ? array( 'available' => false ) : $valid, is_wp_error( $valid ) ? 300 : 3600 );
		} finally {
			GWQSH_Enterprise_Store::unlock( 'reputation-' . $ip, $lock );}
	}
	/**
	 * Blocked.
	 *
	 * @param mixed $ip Ip.
	 * @return mixed Operation result.
	 */
	public static function blocked( $ip ) {
		$cfg = GWQSH_Enterprise_Config::get( 'reputation' );
		if ( ! $cfg['enabled'] || ! $cfg['blocking'] || GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return false;
		}$r = self::lookup( $ip );
		return isset( $r['score'] ) && $r['score'] >= $cfg['threshold'];}
}
