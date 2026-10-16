<?php
/**
 * Database schema and table management for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH DB implementation.
 */
final class GWQSH_DB {
	/**
	 * Init.
	 */
	public static function init() {
		global $wpdb;
		$table_activity = esc_sql( $wpdb->prefix . 'gwqsh_activity_log' );
		$installed_ver  = get_option( 'gwqsh_db_version', '0' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		if ( GWQSH_DB_VERSION !== $installed_ver ) {
			self::create_tables();
		}
	}
	/**
	 * Create tables.
	 */
	public static function create_tables() {
		global $wpdb;
		$previous_version = get_option( 'gwqsh_db_version', '0' );

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset_collate = $wpdb->get_charset_collate();

		// 1. Activity Log table
		$table_activity = $wpdb->prefix . 'gwqsh_activity_log';
		$sql_activity   = "CREATE TABLE {$table_activity} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            event_time datetime NOT NULL,
            event_name varchar(100) NOT NULL,
            event_type varchar(50) NOT NULL DEFAULT 'System',
            user_login varchar(60) NOT NULL DEFAULT '—',
            ip_address varchar(45) NOT NULL DEFAULT '—',
            details text NOT NULL,
            safe_details text DEFAULT NULL,
            PRIMARY KEY  (id),
            KEY idx_event_time (event_time),
            KEY idx_activity_time_id (event_time,id),
            KEY idx_activity_name_time (event_name,event_time),
            KEY idx_event_type (event_type),
            KEY idx_user_login (user_login),
            KEY idx_ip_address (ip_address)
        ) {$charset_collate};";
		dbDelta( $sql_activity );

		// 2. Lockouts table
		$table_lockouts = $wpdb->prefix . 'gwqsh_lockouts';
		$sql_lockouts   = "CREATE TABLE {$table_lockouts} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            ip_address varchar(45) NOT NULL,
            failed_attempts int(11) NOT NULL DEFAULT 1,
            locked_until datetime DEFAULT NULL,
            last_attempt datetime NOT NULL,
            first_attempt datetime DEFAULT NULL,
            is_locked tinyint(1) NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            UNIQUE KEY uq_ip (ip_address),
            KEY idx_locked_until (locked_until),
            KEY idx_is_locked (is_locked)
        ) {$charset_collate};";
		dbDelta( $sql_lockouts );
		if ( version_compare( $previous_version, '1.2.0', '<' ) ) {
			// Preserve existing counters and lock expiries; old rows have no known window start.
			// phpcs:ignore WordPress.DB -- Fixed plugin-owned table; additive migration without user input.
			// phpcs:ignore WordPress.DB,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$wpdb->query( "UPDATE {$table_lockouts} SET first_attempt = last_attempt WHERE first_attempt IS NULL" );
		}

		// 3. Scan results table
		$table_scan = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		$sql_scan   = "CREATE TABLE {$table_scan} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            file_path varchar(500) NOT NULL,
            file_type varchar(50) NOT NULL DEFAULT 'Core',
            status varchar(50) NOT NULL DEFAULT 'Modified',
            details text NOT NULL,
            evidence longtext DEFAULT NULL,
            detected_at datetime NOT NULL,
            is_resolved tinyint(1) NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            KEY idx_status (status),
            KEY idx_file_type (file_type),
            KEY idx_scan_path (file_path(190)),
            KEY idx_scan_resolved_date (is_resolved,detected_at,id),
            KEY idx_is_resolved (is_resolved)
        ) {$charset_collate};";
		dbDelta( $sql_scan );

		// 4. Scan history summary table
		$table_history = esc_sql( $wpdb->prefix . 'gwqsh_scan_history' );
		$sql_history   = "CREATE TABLE {$table_history} (
            id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
            scan_date datetime NOT NULL,
            duration int(11) NOT NULL DEFAULT 0,
            total_files int(11) NOT NULL DEFAULT 0,
            clean_files int(11) NOT NULL DEFAULT 0,
            modified_files int(11) NOT NULL DEFAULT 0,
            missing_files int(11) NOT NULL DEFAULT 0,
            suspicious_files int(11) NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            KEY idx_scan_date (scan_date)
        ) {$charset_collate};";
		dbDelta( $sql_history );

		if ( '0' === $previous_version ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->delete(
				$table_activity,
				array(
					'event_name' => 'Plugin activated',
					'details'    => 'Gracewell Security Suite Pro initialized and active',
					'ip_address' => '127.0.0.1',
				)
			);
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$wpdb->delete(
				$table_activity,
				array(
					'event_name' => 'Settings changed',
					'details'    => 'Security defaults established',
					'ip_address' => '127.0.0.1',
				)
			);
		}

		if ( '0' === $previous_version ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table identifier from the WordPress prefix.
			$wpdb->query( "DELETE FROM {$table_scan} WHERE file_type = 'Core' AND file_path LIKE '/wp-content/%'" );
		}

		if ( is_wp_error( GWQSH_Enterprise_Store::install() ) ) {
			return; }
		GWQSH_IP_Blocks::install();
		GWQSH_Passkeys::install();
		update_option( 'gwqsh_db_version', GWQSH_DB_VERSION );
	}
	/**
	 * Drop tables.
	 */
	public static function drop_tables() {
		global $wpdb;
		$tables = array(
			esc_sql( $wpdb->prefix . 'gwqsh_activity_log' ),
			esc_sql( $wpdb->prefix . 'gwqsh_lockouts' ),
			esc_sql( $wpdb->prefix . 'gwqsh_scan_results' ),
			esc_sql( $wpdb->prefix . 'gwqsh_scan_history' ),
			esc_sql( $wpdb->prefix . 'gwqsh_ip_blocks' ),
			esc_sql( $wpdb->prefix . 'gwqsh_auth_challenges' ),
			esc_sql( $wpdb->prefix . 'gwqsh_security_state' ),
			esc_sql( $wpdb->prefix . 'gwqsh_delivery_queue' ),
		);
		foreach ( $tables as $table ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.DirectDatabaseQuery.SchemaChange,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->query( "DROP TABLE IF EXISTS {$table}" );
		}
	}
}
