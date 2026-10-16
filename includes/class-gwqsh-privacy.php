<?php
/** WordPress privacy tools and explicit disclosure of external services.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed site-owned tables and prepared values; atomic security state and privacy erasure must bypass object caches.
/** Privacy service. */
final class GWQSH_Privacy {
	/**
	 * Init.
	 *
	 * @return mixed Operation result.
	 */
	public static function init() {
		add_filter( 'wp_privacy_personal_data_exporters', array( __CLASS__, 'exporters' ) );
		add_filter( 'wp_privacy_personal_data_erasers', array( __CLASS__, 'erasers' ) );
		add_action( 'admin_init', array( __CLASS__, 'policy' ) );}
	/**
	 * Ip.
	 *
	 * @param mixed $ip Ip.
	 * @param mixed $anonymize Anonymize.
	 * @return mixed Operation result.
	 */
	public static function ip( $ip, $anonymize = null ) {
		$ip = GWQSH_Network::canonical( $ip );
		if ( ! $ip ) {
			return '';
		}if ( null === $anonymize ) {
			$anonymize = GWQSH_Enterprise_Config::get( 'privacy' )['anonymize'];
		}
		return $anonymize ? wp_privacy_anonymize_ip( $ip ) : $ip;}
	/**
	 * Exporters.
	 *
	 * @param mixed $items Items.
	 * @return mixed Operation result.
	 */
	public static function exporters( $items ) {
		$items['gwqsh-audit'] = array(
			'exporter_friendly_name' => 'Security Suite Pro audit data',
			'callback'               => array( __CLASS__, 'export' ),
		);
		return $items;}
	/**
	 * Erasers.
	 *
	 * @param mixed $items Items.
	 * @return mixed Operation result.
	 */
	public static function erasers( $items ) {
		$items['gwqsh-audit'] = array(
			'eraser_friendly_name' => 'Security Suite Pro audit data',
			'callback'             => array( __CLASS__, 'erase' ),
		);
		return $items;}
	/**
	 * Export.
	 *
	 * @param mixed $email Email.
	 * @param mixed $page Page.
	 * @return mixed Operation result.
	 */
	public static function export( $email, $page = 1 ) {
		global $wpdb;
		$user = get_user_by( 'email', $email );
		if ( ! $user ) {
			return array(
				'data' => array(),
				'done' => true,
			);
		}
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id,event_time,event_name,ip_address FROM {$wpdb->prefix}gwqsh_activity_log WHERE user_login=%s ORDER BY id LIMIT 100 OFFSET %d", $user->user_login, ( max( 1, (int) $page ) - 1 ) * 100 ), ARRAY_A );
		$out  = array();
		foreach ( $rows as $row ) {
			$out[] = array(
				'group_id'    => 'gwqsh-audit',
				'group_label' => 'Security Suite Pro audit events',
				'item_id'     => 'gwqsh-' . $row['id'],
				'data'        => array(
					array(
						'name'  => 'Event',
						'value' => $row['event_name'],
					),
					array(
						'name'  => 'Site time',
						'value' => $row['event_time'],
					),
					array(
						'name'  => 'IP address',
						'value' => $row['ip_address'],
					),
				),
			);
		}
		return array(
			'data' => $out,
			'done' => count( $rows ) < 100,
		);
	}
	/**
	 * Erase.
	 *
	 * @param mixed $email Email.
	 * @param mixed $page Page.
	 * @return mixed Operation result.
	 */
	public static function erase( $email, $page = 1 ) {
		global $wpdb;
		$user    = get_user_by( 'email', $email );
		$enabled = GWQSH_Enterprise_Config::get( 'privacy' )['erase'];
		if ( ! $user || ! $enabled ) {
			return array(
				'items_removed'  => false,
				'items_retained' => ! $enabled,
				'messages'       => $enabled ? array() : array( 'Site policy retains security audit evidence; contact the site administrator.' ),
				'done'           => true,
			);
		}
		$table = $wpdb->prefix . 'gwqsh_activity_log';
		$ids   = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$table} WHERE user_login=%s ORDER BY id LIMIT 100", $user->user_login ) );
		$ok    = true;
		foreach ( $ids as $id ) {
			if ( false === $wpdb->update(
				$table,
				array(
					'user_login'   => 'erased',
					'ip_address'   => '0.0.0.0',
					'details'      => 'Personal data erased through WordPress privacy tools.',
					'safe_details' => 'Personal data erased through WordPress privacy tools.',
				),
				array( 'id' => $id )
			) ) {
				$ok = false;
			}
		}
		$like   = '%' . $wpdb->esc_like( '"user":"' . $user->user_login . '"' ) . '%';
		$queued = $wpdb->get_results( $wpdb->prepare( "SELECT id,payload FROM {$wpdb->prefix}gwqsh_delivery_queue WHERE payload LIKE %s LIMIT 100", $like ), ARRAY_A );
		foreach ( $queued as $row ) {
			$event = json_decode( $row['payload'], true );
			if ( is_array( $event ) && ( $event['user'] ?? '' ) === $user->user_login ) {
				$event['user']   = 'erased';
					$event['ip'] = '';
				if ( false === $wpdb->update( $wpdb->prefix . 'gwqsh_delivery_queue', array( 'payload' => wp_json_encode( $event ) ), array( 'id' => $row['id'] ) ) ) {
					$ok = false; }
			}
		}
		delete_user_meta( $user->ID, 'gwqsh_last_login_country' );
		return array(
			'items_removed'  => $ok && ( ! empty( $ids ) || ! empty( $queued ) ),
			'items_retained' => ! $ok,
			'messages'       => $ok ? array() : array( 'Some security audit records could not be anonymized.' ),
			'done'           => count( $ids ) < 100 && count( $queued ) < 100,
		);
	}
	/**
	 * Policy.
	 *
	 * @return mixed Operation result.
	 */
	public static function policy() {
		if ( function_exists( 'wp_add_privacy_policy_content' ) ) {
			wp_add_privacy_policy_content( 'Gracewell Security Suite Pro', wp_kses_post( '<p>This plugin records security event times, account names, IP addresses and findings. Administrators can configure retention, IP anonymization, and WordPress data export/erasure. Required authentication records remain until account revocation.</p><p>Only configured opt-in services receive data: ipwho.is receives public IPs for country attribution; AbuseIPDB receives public IPs for reputation; Slack receives minimized alert names/severity/timestamps; Datadog receives minimized audit events; Twilio receives a verified phone number and expiring code. Signed feeds receive an HTTPS update request. No automatic telemetry is sent. WordPress.org checksums and verified core packages support integrity repair. License-provider disclosures must be supplied when an adapter is configured.</p>' ) );
		}}
}
