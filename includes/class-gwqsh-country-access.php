<?php
/** Enterprise service contract.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Country access service. */
final class GWQSH_Country_Access {
	/**
	 * Init.
	 *
	 * @return mixed Operation result.
	 */
	public static function init() {
		add_filter( 'authenticate', array( __CLASS__, 'authenticate' ), 80, 3 );
		add_action( 'init', array( __CLASS__, 'public_request' ), 3 );
		add_action( 'gwqsh_refresh_cloudflare_ranges', array( __CLASS__, 'refresh_cloudflare' ) );}
	/**
	 * Emergency.
	 *
	 * @return mixed Operation result.
	 */
	public static function emergency() {
		return ( defined( 'GWQSH_DISABLE_ENTERPRISE' ) && true === GWQSH_DISABLE_ENTERPRISE )
			|| ( defined( 'GWQSH_DISABLE_COUNTRY_BLOCKING' ) && true === GWQSH_DISABLE_COUNTRY_BLOCKING );
	}
	/**
	 * Decision.
	 *
	 * @param mixed $ip Ip.
	 * @param mixed $context Context.
	 * @param mixed $user User.
	 * @return mixed Operation result.
	 */
	public static function decision( $ip, $context = 'login', $user = null ) {
		$cfg = GWQSH_Enterprise_Config::get( 'geo' );
		if ( self::emergency() || ! GWQSH_Settings::is_active() || GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return '';
		}
		if ( $cfg['enabled'] && GWQSH_Settings::get( 'geo_enabled', false ) && ( 'login' === $context || $cfg['public'] ) ) {
			$geo  = GWQSH_Network::country( $ip );
			$code = $geo['code'] ?? '';
			if ( ! $code ) {
				if ( 'deny' === $cfg['unknown'] && ! ( $user instanceof WP_User && user_can( $user, 'manage_options' ) ) ) {
							return 'Unknown country';
				}
			} else {
				$listed = in_array( $code, explode( ',', $cfg['countries'] ), true );
				if ( ( 'deny' === $cfg['mode'] && $listed ) || ( 'allow' === $cfg['mode'] && ! $listed ) ) {
					return 'Country policy: ' . $code;
				}
			}
		}
		return GWQSH_Threat_Intelligence::blocked( $ip ) ? 'IP reputation policy' : '';
	}
	/**
	 * Authenticate.
	 *
	 * @param mixed $user User.
	 * @param mixed $name Name.
	 * @param mixed $password Password.
	 * @return mixed Operation result.
	 */
	public static function authenticate( $user, $name = '', $password = '' ) {
		if ( ! ( $user instanceof WP_User ) ) {
			return $user;
		}$ip    = GWQSH_Settings::get_client_ip();
		$reason = self::decision( $ip, 'login', $user );
		if ( ! $reason ) {
			return $user;
		}self::record( $ip, $reason, $user->user_login );
		return new WP_Error( 'gwqsh_access_policy', 'This sign-in is restricted by site security policy. Contact the administrator.' );
	}
	/**
	 * Record.
	 *
	 * @param mixed $ip Ip.
	 * @param mixed $reason Reason.
	 * @param mixed $user User.
	 * @return mixed Operation result.
	 */
	public static function record( $ip, $reason, $user = '' ) {
		$hit = GWQSH_Enterprise_Store::hit( 'policy-log', $ip . '|' . $reason, 60 );
		if ( 1 === $hit ) {
			GWQSH_Activity_Logger::log( 'IP reputation policy' === $reason ? 'Reputation request blocked' : 'Country request blocked', $reason, 'Security', $user ? $user : 'anonymous', $ip );
		}
	}
	/**
	 * Public request.
	 *
	 * @return mixed Operation result.
	 */
	public static function public_request() {
		if ( self::emergency() || is_user_logged_in() || is_admin() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}$path      = wp_parse_url( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ?? '/' ) ), PHP_URL_PATH );
		$login_path = wp_parse_url( GWQSH_Login_Protection::custom_login_url(), PHP_URL_PATH );
		if ( 'wp-login.php' === basename( sanitize_text_field( wp_unslash( $_SERVER['SCRIPT_NAME'] ?? '' ) ) ) || $path === $login_path ) {
			return;
		}$ip    = GWQSH_Settings::get_client_ip();
		$reason = self::decision( $ip, 'public' );
		if ( $reason ) {
			self::record( $ip, $reason );
			GWQSH_UI::error( 403, 'Request restricted', 'Site security policy restricts this request. Contact the administrator.' );}}
	/**
	 * Cloudflare peer.
	 *
	 * @param mixed $ip Ip.
	 * @return mixed Operation result.
	 */
	public static function cloudflare_peer( $ip ) {
		$data = get_option( 'gwqsh_cloudflare_ranges', array() );
		if ( ( $data['checked_at'] ?? 0 ) < time() - 8 * DAY_IN_SECONDS ) {
			return false;
		}
		return GWQSH_Network::trusted_ip( $ip, $data['ranges'] ?? array() );}
	/**
	 * Refresh cloudflare.
	 *
	 * @return mixed Operation result.
	 */
	public static function refresh_cloudflare() {
		if ( ! GWQSH_Settings::get( 'proxy', false ) || 'cf' !== GWQSH_Settings::get( 'proxyheader', 'xff' ) ) {
			return new WP_Error( 'inactive', 'Select Cloudflare proxy mode first.' );
		}
		$response = GWQSH_Secure_HTTP::request( 'cloudflare', 'https://api.cloudflare.com/client/v4/ips' );
		$body     = ! is_wp_error( $response ) && 200 === wp_remote_retrieve_response_code( $response ) ? json_decode( wp_remote_retrieve_body( $response ), true ) : null;
		if ( empty( $body['success'] ) || ! is_array( $body['result']['ipv4_cidrs'] ?? null ) || ! is_array( $body['result']['ipv6_cidrs'] ?? null ) ) {
			return new WP_Error( 'ranges', 'Unable to verify current Cloudflare ranges. Existing valid ranges are retained.' );
		}
		$ranges = array_merge( $body['result']['ipv4_cidrs'], $body['result']['ipv6_cidrs'] );
		if ( ! $ranges || count( $ranges ) > 100 ) {
			return new WP_Error( 'ranges', 'Invalid proxy range database.' );
		}
		foreach ( $ranges as $range ) {
			if ( ! is_string( $range ) || false === strpos( $range, '/' ) || ! GWQSH_Network::matches( explode( '/', $range )[0], $range ) ) {
				return new WP_Error( 'ranges', 'Invalid proxy CIDR.' );
			}
		}
		update_option(
			'gwqsh_cloudflare_ranges',
			array(
				'ranges'     => $ranges,
				'checked_at' => time(),
			),
			false
		);
		if ( ! wp_next_scheduled( 'gwqsh_refresh_cloudflare_ranges' ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', 'gwqsh_refresh_cloudflare_ranges' );
		}
		return true;
	}
}
