<?php
/**
 * Persistent manual blocks with an append-only management history.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** IP Blocks service. */
final class GWQSH_IP_Blocks {
	/** Create the indexed persistent manual block history table. */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = $wpdb->prefix . 'gwqsh_ip_blocks';
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
 id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
 ip_address varchar(45) NOT NULL,
 reason varchar(500) NOT NULL DEFAULT '',
 created_by bigint(20) unsigned NOT NULL DEFAULT 0,
 created_at bigint(20) unsigned NOT NULL,
 expires_at bigint(20) unsigned NOT NULL DEFAULT 0,
 revoked_at bigint(20) unsigned NOT NULL DEFAULT 0,
 PRIMARY KEY  (id),
 KEY ip_active (ip_address,revoked_at,expires_at),
 KEY created_at (created_at)
) {$charset};"
		);
	}
	/** Register the service hooks. */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'enforce' ), 0 );
		add_filter( 'authenticate', array( __CLASS__, 'authenticate' ), 99, 1 );
	}
	/**
	 * Read the current active restriction without serving stale enforcement state.
	 *
	 * @param mixed $ip ip value.
	 */
	public static function blocked( $ip ) {
		global $wpdb;
		$ip = GWQSH_Network::canonical( $ip );
		if ( ! $ip || ! GWQSH_Settings::is_active() ) {
			return false; }
		// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}gwqsh_ip_blocks WHERE ip_address = %s AND revoked_at = 0 AND (expires_at = 0 OR expires_at > %d) ORDER BY id DESC LIMIT 1", $ip, time() ), ARRAY_A );
		return $row ? $row : false;
	}
	/**
	 * Persist validated service configuration.
	 *
	 * @param mixed $ip ip value.
	 * @param mixed $reason reason value.
	 * @param mixed $minutes minutes value.
	 */
	public static function save( $ip, $reason, $minutes = 0 ) {
		global $wpdb;
		$ip = GWQSH_Network::canonical( $ip );
		if ( ! $ip || ! is_numeric( $minutes ) || $minutes < 0 || $minutes > 525600 ) {
			return new WP_Error( 'invalid_block', 'Enter a valid IP and a duration between 0 and 525600 minutes.' ); }
		if ( GWQSH_Network::canonical( GWQSH_Settings::get_client_ip() ) === $ip ) {
			return new WP_Error( 'self_block', 'Your current IP cannot be blocked from this session.' ); }
		if ( GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return new WP_Error( 'trusted_ip', 'Remove this address from the visitor allowlist before blocking it.' ); }
		$data = array(
			'ip_address' => $ip,
			'reason'     => substr( sanitize_text_field( $reason ), 0, 500 ),
			'created_by' => get_current_user_id(),
			'created_at' => time(),
			'expires_at' => $minutes ? time() + (int) $minutes * 60 : 0,
		);
		// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
		if ( false === $wpdb->insert( $wpdb->prefix . 'gwqsh_ip_blocks', $data ) ) {
			return new WP_Error( 'save_failed', 'The IP block could not be saved.' ); }
		GWQSH_Activity_Logger::log( 'IP manually blocked', $data['reason'] . ( $minutes ? ' (temporary)' : ' (permanent)' ), 'Security', wp_get_current_user()->user_login, $ip );
		return true;
	}
	/**
	 * Revoke manual restrictions while preserving management history.
	 *
	 * @param mixed $ip ip value.
	 */
	public static function remove( $ip ) {
		global $wpdb;
		$ip = GWQSH_Network::canonical( $ip );
		if ( ! $ip ) {
			return new WP_Error( 'invalid_ip', 'Enter a valid IP address.' ); }
		// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
		$count = $wpdb->update(
			$wpdb->prefix . 'gwqsh_ip_blocks',
			array( 'revoked_at' => time() ),
			array(
				'ip_address' => $ip,
				'revoked_at' => 0,
			)
		);
		if ( false === $count ) {
			return new WP_Error( 'save_failed', 'Unable to remove this block.' ); }
		GWQSH_Activity_Logger::log( 'IP manually unblocked', 'Manual restrictions removed by administrator.', 'Security', wp_get_current_user()->user_login, $ip );
		return true;
	}
	/**
	 * Return a bounded page of IP restriction history.
	 *
	 * @param mixed $page page value.
	 */
	public static function history( $page = 1 ) {
		global $wpdb;
		$page  = max( 1, min( 10000, absint( $page ) ) );
		$table = $wpdb->prefix . 'gwqsh_ip_blocks';
		// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} ORDER BY id DESC LIMIT 20 OFFSET %d", ( $page - 1 ) * 20 ), ARRAY_A );
		foreach ( $rows as &$row ) {
			$row['status']   = $row['revoked_at'] ? 'Unblocked' : ( $row['expires_at'] && $row['expires_at'] <= time() ? 'Expired' : 'Blocked' );
			$row['created']  = GWQSH_Time::format( (int) $row['created_at'] );
			$row['expires']  = $row['expires_at'] ? GWQSH_Time::format( (int) $row['expires_at'] ) : 'Permanent';
			$dur_mins        = $row['expires_at'] ? max( 1, (int) round( ( $row['expires_at'] - $row['created_at'] ) / 60 ) ) : 0;
			$row['duration'] = $dur_mins ? $dur_mins . ' minutes' : 'Permanent';
			$user_obj        = ! empty( $row['created_by'] ) ? get_userdata( $row['created_by'] ) : null;
			$row['added_by'] = $user_obj ? $user_obj->user_login : ( ! empty( $row['created_by'] ) ? 'user' : 'system' );
		} unset( $row );
		return array(
			'items' => $rows,
			'page'  => $page,
			// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
			'pages' => max( 1, (int) ceil( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) / 20 ) ),
		);
	}
	/**
	 * Deduplicate denied-request audit events.
	 *
	 * @param mixed $ip ip value.
	 */
	private static function log_denial( $ip ) {
		$key = 'gwqsh_manual_deny_' . md5( $ip );
		if ( ! get_transient( $key ) ) {
			GWQSH_Activity_Logger::log( 'Manual IP request blocked', 'Request denied by an administrator-managed IP restriction.', 'Security', '—', $ip );
			set_transient( $key, 1, MINUTE_IN_SECONDS ); }
	}
	/**
	 * Reject authentication for a manually restricted client address.
	 *
	 * @param mixed $user user value.
	 */
	public static function authenticate( $user ) {
		$ip = GWQSH_Settings::get_client_ip();
		if ( self::blocked( $ip ) ) {
			self::log_denial( $ip );
			return new WP_Error( 'gwqsh_manual_block', 'Access from this IP address is restricted.' ); }
		return $user;
	}
	/** Enforce administrator restrictions on public requests. */
	public static function enforce() {
		if ( wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) || ( is_admin() && current_user_can( GWQSH_Admin::management_capability() ) ) ) {
			return; }
		$ip = GWQSH_Settings::get_client_ip();
		if ( self::blocked( $ip ) ) {
			self::log_denial( $ip );
			GWQSH_UI::error( 403, 'Access restricted', 'This IP address has been restricted by the site administrator.' ); }
	}
}
