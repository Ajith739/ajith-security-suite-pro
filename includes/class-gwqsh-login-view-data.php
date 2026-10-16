<?php
/**
 * Read-only Login Protection projections and one protection-score calculation.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Read-only view model for the Login Protection page. */
final class GWQSH_Login_View_Data {
	/**
	 * Assemble settings and real recorded activity.
	 *
	 * @param int $days Chart period.
	 * @return array
	 */
	public static function get( $days = 7 ) {
		global $wpdb;
		$days        = in_array( absint( $days ), array( 7, 14, 30 ), true ) ? absint( $days ) : 7;
		$settings    = GWQSH_Login_Protection::get_settings();
		$active      = GWQSH_Settings::is_active();
		$xmlrpc      = $active && GWQSH_Hardening::is_enabled( 'xmlrpc' );
		$custom      = $active && $settings['custom_slug_enabled'] && GWQSH_Login_Protection::valid_slug( $settings['custom_slug'] ) && ! ( defined( 'GWQSH_DISABLE_LOGIN_URL' ) && GWQSH_DISABLE_LOGIN_URL );
		$locked      = GWQSH_Login_Protection::get_currently_locked_ips();
		$error       = ! empty( $wpdb->last_error );
		$table       = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$cutoff      = current_datetime()->modify( '-29 days' )->format( 'Y-m-d 00:00:00' );
		$names       = array( 'Login successful', 'Login attempt blocked', 'IP locked out', 'IP unlocked', 'Login blocked by lockout', 'XML-RPC access blocked', 'XML-RPC login blocked', 'IP allowlisted', 'IP allowlist updated' );
		$slots       = implode( ',', array_fill( 0, count( $names ), '%s' ) );
		$events      = $wpdb->get_results( $wpdb->prepare( "SELECT event_time,event_name,user_login,ip_address,details FROM {$table} WHERE event_time >= %s AND event_name IN ({$slots}) ORDER BY id DESC LIMIT 5", array_merge( array( $cutoff ), $names ) ), ARRAY_A ); // phpcs:ignore WordPress.DB -- Fixed table, prepared event filters.
		$error       = $error || ! empty( $wpdb->last_error );
		$lock_events = $locked ? $wpdb->get_results( $wpdb->prepare( "SELECT ip_address,user_login,details FROM {$table} WHERE event_name = %s ORDER BY id DESC LIMIT 500", 'IP locked out' ), ARRAY_A ) : array(); // phpcs:ignore WordPress.DB -- Bounded metadata query; no per-row database reads.
		$error       = $error || ! empty( $wpdb->last_error );
		$metadata    = array();
		foreach ( (array) $lock_events as $event ) {
			if ( ! isset( $metadata[ $event['ip_address'] ] ) ) {
				$metadata[ $event['ip_address'] ] = $event; }
		}
		foreach ( $locked as &$row ) {
			$row['username'] = isset( $metadata[ $row['ip'] ] ) ? $metadata[ $row['ip'] ]['user_login'] : '—';
			$row['reason']   = isset( $metadata[ $row['ip'] ] ) ? $metadata[ $row['ip'] ]['details'] : 'Reason not recorded'; }
		unset( $row );
		$chart           = self::chart( $days );
		$blocked         = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_time >= %s AND event_name IN (%s,%s,%s)", $cutoff, 'Login blocked by lockout', 'XML-RPC access blocked', 'XML-RPC login blocked' ) ); // phpcs:ignore WordPress.DB -- Count actual denied requests, not ordinary failed logins.
		$error           = $error || ! empty( $wpdb->last_error ) || $chart['error'];
		$global          = GWQSH_Settings::get_all();
		$trusted         = GWQSH_Network::trusted();
		$remote          = isset( $_SERVER['REMOTE_ADDR'] ) && is_string( $_SERVER['REMOTE_ADDR'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) ) : '';
		$proxy_effective = $global['proxy'] && filter_var( $remote, FILTER_VALIDATE_IP ) && GWQSH_Network::trusted_ip( $remote, $trusted );
		$detected_proxy  = $global['proxyheader'];
		$forwarded_ip    = '';
		if ( $proxy_effective ) {
			if ( 'cf' === $detected_proxy && GWQSH_Country_Access::cloudflare_peer( $remote ) && ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) && is_string( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
				$forwarded_ip = trim( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
			} elseif ( 'xreal' === $detected_proxy && ! empty( $_SERVER['HTTP_X_REAL_IP'] ) && is_string( $_SERVER['HTTP_X_REAL_IP'] ) ) {
				$forwarded_ip = trim( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
			} elseif ( 'trueclient' === $detected_proxy && ! empty( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) && is_string( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) ) {
				$forwarded_ip = trim( wp_unslash( $_SERVER['HTTP_TRUE_CLIENT_IP'] ) );
			} elseif ( 'xff' === $detected_proxy && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) && is_string( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
				$forwarded_ip   = GWQSH_Settings::forwarded_ip( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ), $trusted ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- forwarded_ip bounds and validates every IP before use.
				$detected_proxy = 'xff';
			}
			$proxy_effective = (bool) filter_var( $forwarded_ip, FILTER_VALIDATE_IP );
		}
		$proxy_names = array(
			'xff'        => 'X-Forwarded-For',
			'cf'         => 'Cloudflare',
			'xreal'      => 'X-Real-IP',
			'trueclient' => 'True-Client-IP',
		);
		$components  = array(
			'brute'   => $active && $settings['enabled'] ? 100 : 0,
			'custom'  => $custom ? 100 : 0,
			'xmlrpc'  => $xmlrpc ? 100 : 0,
			'rules'   => $active && $settings['enabled'] && $settings['max_attempts'] > 0 && $settings['time_window'] > 0 && $settings['lockout_duration'] > 0 ? 100 : 0,
			'country' => null,
		);
		$score       = (int) round( $components['brute'] * .4 + $components['custom'] * .2 + $components['xmlrpc'] * .2 + $components['rules'] * .2 );
		$roles       = array();
		foreach ( wp_roles()->roles as $key => $role ) {
			$roles[] = array(
				'key'  => $key,
				'name' => translate_user_role( $role['name'] ),
			); }
		return array(
			'settings'                => $settings,
			'locked_ips'              => $locked,
			'allow_ips'               => GWQSH_Login_Protection::get_allowlist(),
			'failed_24h'              => GWQSH_Login_Protection::get_failed_attempts_24h(),
			'chart'                   => $chart,
			'events'                  => $events ? $events : array(),
			'blocked_30d'             => $blocked,
			'xmlrpc'                  => $xmlrpc,
			'xmlrpc_configured'       => GWQSH_Hardening::is_enabled( 'xmlrpc' ),
			'engine_active'           => $active && $settings['enabled'],
			'plugin_active'           => $active,
			'custom_active'           => $custom,
			'score_components'        => $components,
			'protection_score'        => $score,
			'roles'                   => $roles,
			'proxy_mode'              => $global['proxy'] ? $global['proxyheader'] : 'remote',
			'proxy_effective'         => $proxy_effective,
			'proxy_name'              => $proxy_effective ? ( $proxy_names[ $detected_proxy ] ?? 'REMOTE_ADDR' ) : 'REMOTE_ADDR',
			'trusted_proxy_available' => ! empty( $trusted ),
			'trusted_proxies'         => $global['trusted_proxies'],
			'recovery_url'            => GWQSH_Login_Protection::recovery_url(),
			'login_url'               => $custom ? GWQSH_Login_Protection::custom_login_url() : wp_login_url(),
			'client_ip'               => GWQSH_Settings::get_client_ip(),
			'data_error'              => $error,
		);
	}

	/**
	 * Aggregate historical counts using the site's calendar dates.
	 *
	 * @param int $days Chart period.
	 * @return array
	 */
	private static function chart( $days ) {
		global $wpdb;
		$dates = array();
		$today = current_datetime();
		for ( $i = $days - 1; $i >= 0; --$i ) {
			$date                              = $today->modify( '-' . $i . ' days' );
			$dates[ $date->format( 'Y-m-d' ) ] = array(
				'label'      => $date->format( 'M j' ),
				'blocked'    => 0,
				'failed'     => 0,
				'xmlrpc'     => 0,
				'successful' => 0,
			); }
		$table = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT DATE(event_time) AS d,event_name,COUNT(*) AS c FROM {$table} WHERE event_time >= %s GROUP BY DATE(event_time),event_name", $today->modify( '-' . ( $days - 1 ) . ' days' )->format( 'Y-m-d 00:00:00' ) ), ARRAY_A ); // phpcs:ignore WordPress.DB -- Prepared cutoff; aggregate existing audit records.
		$error = ! empty( $wpdb->last_error );
		$map   = array(
			'Login successful'         => 'successful',
			'Login attempt blocked'    => 'failed',
			'Login blocked by lockout' => 'blocked',
			'XML-RPC access blocked'   => 'xmlrpc',
			'XML-RPC login blocked'    => 'xmlrpc',
		);
		foreach ( (array) $rows as $row ) {
			if ( isset( $dates[ $row['d'] ], $map[ $row['event_name'] ] ) ) {
				$dates[ $row['d'] ][ $map[ $row['event_name'] ] ] += (int) $row['c']; }
		}
		$result = array(
			'days'   => $days,
			'error'  => $error,
			'labels' => array_column( $dates, 'label' ),
		);
		foreach ( array( 'blocked', 'failed', 'xmlrpc', 'successful' ) as $key ) {
			$result[ $key ] = array_column( $dates, $key ); }
		return $result;
	}
}
