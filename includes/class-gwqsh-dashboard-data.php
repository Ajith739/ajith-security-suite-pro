<?php
/**
 * Read-only dashboard projections over existing security stores.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Projects existing records into dashboard widgets without changing settings. */
final class GWQSH_Dashboard_Data {
	/**
	 * One snapshot per request, shared by the view and script configuration.
	 *
	 * @param int $days Chart period.
	 * @param int $overview_days Overview period.
	 * @return array
	 */
	public static function get( $days = 7, $overview_days = 30 ) {
		static $snapshots = array();
		$days             = in_array( absint( $days ), array( 7, 14, 30 ), true ) ? absint( $days ) : 7;
		$overview_days    = in_array( absint( $overview_days ), array( 7, 30 ), true ) ? absint( $overview_days ) : 30;
		$key              = $days . ':' . $overview_days;
		if ( isset( $snapshots[ $key ] ) ) {
			return $snapshots[ $key ]; }
		global $wpdb;
		$scan           = GWQSH_File_Integrity::get_summary();
		$data_error     = ! empty( $wpdb->last_error );
		$components     = GWQSH_Admin::get_score_components();
		$coverage       = GWQSH_Two_Factor::coverage_counts();
		$protected      = $coverage['enabled'];
		$hardening      = GWQSH_Hardening::get_checks();
		$recent         = GWQSH_Activity_Logger::query_logs(
			array(
				'limit' => 5,
				'days'  => $overview_days,
			)
		);
		$data_error     = $data_error || ! empty( $wpdb->last_error );
		$activity_table = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$cutoff         = self::cutoff( $overview_days );
		// Count recorded enforcement decisions. Ordinary failed passwords are excluded.
		$blocked            = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$activity_table} WHERE event_name IN (%s,%s,%s,%s,%s,%s) AND event_time >= %s", 'IP locked out', 'Firewall request blocked', 'Login blocked by lockout', 'XML-RPC login blocked', 'XML-RPC access blocked', 'Manual IP request blocked', $cutoff ) ); // phpcs:ignore WordPress.DB -- Fixed plugin-owned table, prepared values.
		$data_error         = $data_error || ! empty( $wpdb->last_error );
		$threats            = $wpdb->get_results( $wpdb->prepare( "SELECT event_time, event_name, ip_address, details FROM {$activity_table} WHERE event_name IN (%s,%s,%s,%s,%s,%s) AND event_time >= %s ORDER BY event_time DESC, id DESC LIMIT 5", 'IP locked out', 'Firewall request blocked', 'Login blocked by lockout', 'XML-RPC login blocked', 'XML-RPC access blocked', 'Manual IP request blocked', $cutoff ), ARRAY_A ); // phpcs:ignore WordPress.DB -- Fixed plugin-owned table, prepared values.
		$data_error         = $data_error || ! empty( $wpdb->last_error );
		$guardian           = (array) get_option( 'gwqsh_guardian_status', array() );
		$active             = GWQSH_Settings::is_active();
		$shields            = array( $active && $components['login'] > 0, $protected > 0, $active && $scan['total'] > 0, $active && count( array_filter( $hardening ) ) > 0, (bool) wp_next_scheduled( 'gwqsh_daily_log_cleanup' ), $active && ! empty( $guardian['active'] ) );
		$history            = array_slice( GWQSH_File_Integrity::get_scan_history(), 0, 4 );
		$updates            = get_site_transient( 'update_plugins' );
		$chart              = self::chart( $days );
		$data               = array(
			'failed_24h'       => GWQSH_Login_Protection::get_failed_attempts_24h(),
			'locked_ips'       => GWQSH_Login_Protection::get_currently_locked_ips(),
			'allow_ips'        => GWQSH_Login_Protection::get_allowlist(),
			'users_total'      => $coverage['total'],
			'users_2fa'        => $protected,
			'scan_summary'     => $scan,
			'hardening'        => $hardening,
			'hardening_on'     => count( array_filter( $hardening ) ),
			'security_score'   => GWQSH_Admin::score_from_components( $components ),
			'score_components' => $components,
			'recent_activity'  => $recent['items'],
			'total_events'     => $recent['total'],
			'client_ip'        => GWQSH_Settings::get_client_ip(),
			'threats_blocked'  => $blocked,
			'live_threats'     => $threats ? $threats : array(),
			'active_shields'   => count( array_filter( $shields ) ),
			'shields_total'    => count( $shields ),
			'schedule'         => GWQSH_Scheduler::settings()['enabled'] ? GWQSH_Scheduler::data()['frequency_label'] : 'Disabled',
			'next_scan'        => GWQSH_Scheduler::data()['next'],
			'quarantine'       => array_values( array_slice( GWQSH_Quarantine_Manager::list_quarantined(), 0, 4 ) ),
			'scan_history'     => $history,
			'chart_data'       => $chart,
			'country_blocks'   => null,
			'geography'        => self::geography( $overview_days ),
			'active'           => $active,
			'version'          => GWQSH_VERSION,
			'update_status'    => isset( $updates->response[ GWQSH_PLUGIN_BASENAME ] ) ? 'Update available' : ( isset( $updates->no_update[ GWQSH_PLUGIN_BASENAME ] ) ? 'Up to date' : 'Update status unavailable' ),
			'auto_updates'     => GWQSH_Settings::get( 'autoupdate', false ),
			'updated'          => wp_date( 'g:i:s A' ),
			'overview_days'    => $overview_days,
			'coverage_warning' => (array) get_option( 'gwqsh_scan_health', array() ),
		);
		$data['data_error'] = $data_error || $chart['error'] || ! empty( $wpdb->last_error );
		$snapshots[ $key ]  = $data;
		return $data;
	}

	/**
	 * Regional threat sources projection for dashboard threat map.
	 *
	 * @param int $days Overview period.
	 * @return array
	 */
	public static function flag_url( $code, $country_name = '' ) {
		$code = strtolower( trim( (string) $code ) );
		$name = strtolower( trim( preg_replace( '/[^a-z0-9]+/i', '-', (string) $country_name ) ) );
		$map  = array(
			'us' => 'usa.png',
			'in' => 'india.png',
			'ru' => 'russia.png',
			'cn' => 'china.png',
			'br' => 'brazil.svg',
			'de' => 'germany.svg',
			'gb' => 'united-kingdom.svg',
			'uk' => 'united-kingdom.svg',
			'id' => 'indonesia.png',
			'au' => 'australia.png',
			'ca' => 'canada.png',
			'jp' => 'japan.png',
			'kr' => 'south-korea.png',
			'th' => 'thailand.png',
			'tr' => 'turkey.png',
			'vn' => 'vietnam.png',
			'se' => 'sweden.png',
			'ch' => 'switzerland.png',
			'no' => 'norway.png',
			'dk' => 'denmark.png',
			'nz' => 'new-zealand.png',
		);
		if ( isset( $map[ $code ] ) && file_exists( GWQSH_PATH . 'assets/img/country/' . $map[ $code ] ) ) {
			return GWQSH_URL . 'assets/img/country/' . $map[ $code ];
		}
		if ( file_exists( GWQSH_PATH . 'assets/img/country/' . $name . '.png' ) ) {
			return GWQSH_URL . 'assets/img/country/' . $name . '.png';
		}
		if ( file_exists( GWQSH_PATH . 'assets/img/country/' . $name . '.svg' ) ) {
			return GWQSH_URL . 'assets/img/country/' . $name . '.svg';
		}
		return GWQSH_URL . 'assets/img/country/others.svg';
	}

	public static function geography( $days = 30 ) {
		global $wpdb;
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT ip_address, COUNT(*) AS attacks FROM {$wpdb->prefix}gwqsh_activity_log WHERE event_time >= %s AND event_name IN ('Firewall request blocked','Login blocked by lockout','Manual IP request blocked','XML-RPC login blocked') GROUP BY ip_address ORDER BY attacks DESC LIMIT 100", self::cutoff( $days ) ), ARRAY_A );
		$groups = array();
		$total  = 0;
		foreach ( (array) $rows as $row ) {
			$geo = GWQSH_Network::country( $row['ip_address'] );
			if ( empty( $geo['code'] ) ) {
				continue;
			}
			$code = strtoupper( $geo['code'] );
			if ( ! isset( $groups[ $code ] ) ) {
				$groups[ $code ] = array(
					'code'    => $code,
					'country' => $geo['country'],
					'attacks' => 0,
					'flag'    => self::flag_url( $code, $geo['country'] ),
					'coords'  => array( round( ( (float) $geo['lon'] + 180 ) / 360 * 440, 1 ), round( ( 90 - (float) $geo['lat'] ) / 180 * 160, 1 ) ),
					'threat'  => 'Recorded site denials',
					'color'   => '#3b82f6',
					'level'   => 'Low',
				);
			}
			$groups[ $code ]['attacks'] += (int) $row['attacks'];
			$total                      += (int) $row['attacks'];
		}
		// Volume bands describe this site's attributed denials, not intrinsic country risk.
		// High: >=20% of attributed blocks; Medium: >=10%; Low: <10%.
		foreach ( $groups as &$group ) {
			$group['percent'] = $total ? round( $group['attacks'] / $total * 100, 1 ) : 0;
			if ( $group['percent'] >= 20 ) {
				$group['color'] = '#ef4444';
				$group['level'] = 'High';
			} elseif ( $group['percent'] >= 10 ) {
				$group['color'] = '#f59e0b';
				$group['level'] = 'Medium';
			} else {
				$group['color'] = '#3b82f6';
				$group['level'] = 'Low';
			}
		}
		unset( $group );
		usort(
			$groups,
			static function ( $a, $b ) {
				return $b['attacks'] <=> $a['attacks'];
			}
		);
		return array_values( $groups );
	}

	/**
	 * Local midnight at the start of a reporting period.
	 *
	 * @param int $days Period length.
	 * @return string
	 */
	private static function cutoff( $days ) {
		return current_datetime()->modify( '-' . ( absint( $days ) - 1 ) . ' days' )->format( 'Y-m-d 00:00:00' );
	}

	/**
	 * Aggregate counts without downloading the full log or resolving IPs externally.
	 *
	 * @param int $days Chart period.
	 * @return array
	 */
	private static function chart( $days ) {
		global $wpdb;
		$dates = array();
		$today = current_datetime();
		for ( $i = $days - 1; $i >= 0; --$i ) {
			$day                              = $today->modify( '-' . $i . ' days' );
			$dates[ $day->format( 'Y-m-d' ) ] = array(
				'label'   => $day->format( 'M j' ),
				'blocked' => 0,
				'login'   => 0,
				'files'   => 0,
				'malware' => 0,
			);
		}
		$table = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT DATE(event_time) AS dt, event_name, COUNT(*) AS c FROM {$table} WHERE event_time >= %s GROUP BY DATE(event_time), event_name", self::cutoff( $days ) ), ARRAY_A ); // phpcs:ignore WordPress.DB -- Fixed table; prepared cutoff.
		$error = ! empty( $wpdb->last_error );
		foreach ( (array) $rows as $row ) {
			if ( ! isset( $dates[ $row['dt'] ] ) ) {
				continue; }
			if ( in_array( $row['event_name'], array( 'IP locked out', 'Firewall request blocked', 'Login blocked by lockout', 'XML-RPC login blocked', 'XML-RPC access blocked', 'Manual IP request blocked' ), true ) ) {
				$dates[ $row['dt'] ]['blocked'] += (int) $row['c']; }
			if ( in_array( $row['event_name'], array( 'Login attempt blocked', 'Login successful' ), true ) ) {
				$dates[ $row['dt'] ]['login'] += (int) $row['c']; }
		}
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		$rows  = $wpdb->get_results( $wpdb->prepare( "SELECT DATE(detected_at) AS dt, status, COUNT(*) AS c FROM {$table} WHERE detected_at >= %s GROUP BY DATE(detected_at), status", self::cutoff( $days ) ), ARRAY_A ); // phpcs:ignore WordPress.DB -- Existing persisted findings; prepared cutoff.
		$error = $error || ! empty( $wpdb->last_error );
		foreach ( (array) $rows as $row ) {
			if ( ! isset( $dates[ $row['dt'] ] ) ) {
				continue; }
			$series = 'Suspicious' === $row['status'] ? 'malware' : ( in_array( $row['status'], array( 'Modified', 'Missing' ), true ) ? 'files' : null );
			if ( $series ) {
				$dates[ $row['dt'] ][ $series ] += (int) $row['c']; }
		}
		$result = array(
			'days'   => $days,
			'error'  => $error,
			'labels' => array_column( $dates, 'label' ),
		);
		foreach ( array( 'blocked', 'login', 'files', 'malware' ) as $series ) {
			$result[ $series ] = array_column( $dates, $series ); }
		// Preserve legacy consumers of the dashboard response.
		$result['failed'] = $result['login'];
		return $result;
	}
}
