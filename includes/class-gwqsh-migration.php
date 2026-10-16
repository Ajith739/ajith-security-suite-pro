<?php
/**
 * One-time migration from the development prefix, without changing security payloads.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Migration implementation.
 */
final class GWQSH_Migration {
	/**
	 * Run.
	 */
	public static function run() {
		if ( get_option( 'gwqsh_prefix_migration' ) ) {
			self::request_compatibility();
			return;
		}
		$started = get_option( 'gwqsh_prefix_migration_lock' );
		if ( $started && (int) $started < time() - 300 ) {
			delete_option( 'gwqsh_prefix_migration_lock' );
		}
		if ( ! add_option( 'gwqsh_prefix_migration_lock', time(), '', false ) ) {
			wp_die( esc_html__( 'Security Suite Pro is migrating security data. Please retry shortly.', 'gracewell-security-suite-pro' ), '', array( 'response' => 503 ) );
		}
		try {
			self::tables();
			self::keys();
			self::cron();
			update_option( 'gwqsh_prefix_migration', 1, false );
		} catch ( Exception $error ) {
			delete_option( 'gwqsh_prefix_migration_lock' );
			wp_die( esc_html( $error->getMessage() ), '', array( 'response' => 503 ) );
		}
		delete_option( 'gwqsh_prefix_migration_lock' );
		self::request_compatibility();
	}
	/**
	 * Query.
	 *
	 * @param mixed $sql Sql.
	 * @throws RuntimeException When existing security data cannot be migrated safely.
	 */
	private static function query( $sql ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,WordPress.DB.DirectDatabaseQuery,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Migration callers prepare values; identifiers are fixed WordPress tables or validated plugin tables. Cache invalidation follows the migration.
		if ( false === $wpdb->query( $sql ) ) {
			throw new RuntimeException( 'Security Suite Pro could not migrate security data. Existing data was preserved; review database permissions and retry.' );
		}
	}
	/**
	 * Rename existing plugin tables without modifying any records.
	 *
	 * @throws RuntimeException When a rename would risk overwriting security data.
	 */
	private static function tables() {
		global $wpdb;
		foreach ( array( 'activity_log', 'lockouts', 'scan_results', 'scan_history' ) as $suffix ) {
			$old = esc_sql( $wpdb->prefix . 'gqs_' . $suffix );
			$new = esc_sql( $wpdb->prefix . 'gwqsh_' . $suffix );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$exists = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $old ) ) );
			if ( $exists !== $old ) {
				continue;
			}
			if ( ! preg_match( '/^[A-Za-z0-9_]+$/D', $old . $new ) ) {
				throw new RuntimeException( 'Security Suite Pro found an invalid database prefix.' );
			}
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			if ( $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $new ) ) ) === $new ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Validated identifier; migration must read live state before renaming.
				$count = $wpdb->get_var(
					"SELECT COUNT(*) FROM `{$new}`" // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Validated or fixed plugin-owned identifier; dynamic values are prepared, and WordPress 5.3 has no identifier placeholder.
				);
				if ( null === $count || (int) $count > 0 ) {
					throw new RuntimeException( 'Security Suite Pro found both legacy and current security tables. No records were overwritten. Reconcile these tables before continuing.' );
				}
				self::query( "DROP TABLE `{$new}`" );
			}
			// Atomic rename preserves IDs, indexes and every existing record; retries skip completed tables.
			self::query( "RENAME TABLE `{$old}` TO `{$new}`" );
		}
	}
	/**
	 * Keys.
	 */
	private static function keys() {
		global $wpdb;
		foreach ( array(
			'gqs_'                    => 'gwqsh_',
			'_transient_gqs_'         => '_transient_gwqsh_',
			'_transient_timeout_gqs_' => '_transient_timeout_gwqsh_',
		) as $old => $new ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
			$names = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE %s",
					$wpdb->esc_like( $old ) . '%'
				)
			);
			self::query(
				$wpdb->prepare(
					"UPDATE {$wpdb->options} legacy LEFT JOIN {$wpdb->options} modern ON modern.option_name = CONCAT(%s, SUBSTRING(legacy.option_name, %d)) SET legacy.option_name = CONCAT(%s, SUBSTRING(legacy.option_name, %d)) WHERE legacy.option_name LIKE %s AND modern.option_id IS NULL",
					$new,
					strlen( $old ) + 1,
					$new,
					strlen( $old ) + 1,
					$wpdb->esc_like( $old ) . '%'
				)
			);
			foreach ( $names as $name ) {
				wp_cache_delete( $name, 'options' );
				wp_cache_delete( $new . substr( $name, strlen( $old ) ), 'options' );
			}
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$users = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( 'gqs_' ) . '%' ) );
		self::query(
			$wpdb->prepare(
				"UPDATE {$wpdb->usermeta} legacy LEFT JOIN {$wpdb->usermeta} modern ON modern.user_id = legacy.user_id AND modern.meta_key = CONCAT(%s, SUBSTRING(legacy.meta_key, %d)) SET legacy.meta_key = CONCAT(%s, SUBSTRING(legacy.meta_key, %d)) WHERE legacy.meta_key LIKE %s AND modern.umeta_id IS NULL",
				'gwqsh_',
				5,
				'gwqsh_',
				5,
				$wpdb->esc_like( 'gqs_' ) . '%'
			)
		);
		foreach ( $users as $user_id ) {
			wp_cache_delete( (int) $user_id, 'user_meta' );
		}
		wp_cache_delete( 'alloptions', 'options' );
		wp_cache_delete( 'notoptions', 'options' );
	}
	/**
	 * Cron.
	 */
	private static function cron() {
		$cron = get_option( 'cron', array() );
		foreach ( $cron as $timestamp => &$hooks ) {
			if ( ! is_array( $hooks ) ) {
				continue;
			}
			foreach ( array_keys( $hooks ) as $hook ) {
				if ( 0 !== strpos( $hook, 'gqs_' ) ) {
					continue;
				}
				if ( 'gqs_scheduled_integrity_scan' !== $hook ) {
					$new           = 'gwqsh_' . substr( $hook, 4 );
					$hooks[ $new ] = array_merge( $hooks[ $hook ], isset( $hooks[ $new ] ) ? $hooks[ $new ] : array() );
				}
				unset( $hooks[ $hook ] );
			}
		}
		unset( $hooks );
		foreach ( $cron as $timestamp => $hooks ) {
			if ( is_array( $hooks ) && empty( $hooks ) ) {
				unset( $cron[ $timestamp ] );
			}
		}
		update_option( 'cron', $cron );
	}
	/**
	 * Request compatibility.
	 */
	public static function request_compatibility() {
		// Only legacy input names are normalized. Native validation still verifies every token/factor.
		foreach ( array( 'gqs_2fa_code', 'gqs_2fa_challenge', 'gqs_trust_device' ) as $old ) {
			$new = 'gwqsh_' . substr( $old, 4 );
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Legacy input-name normalization only; recovery, trusted-device and password-issued challenge verification remain in the authentication handlers.
			if ( ! isset( $_POST[ $new ] ) && isset( $_POST[ $old ] ) && is_string( $_POST[ $old ] ) ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Legacy input-name normalization only; recovery, trusted-device and password-issued challenge verification remain in the authentication handlers.
				$_POST[ $new ] = sanitize_text_field( wp_unslash( $_POST[ $old ] ) );
			}
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Legacy input-name normalization only; recovery, trusted-device and password-issued challenge verification remain in the authentication handlers.
		if ( ! isset( $_GET['gwqsh_recover'] ) && isset( $_GET['gqs_recover'] ) && is_string( $_GET['gqs_recover'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Legacy input-name normalization only; recovery, trusted-device and password-issued challenge verification remain in the authentication handlers.
			$_GET['gwqsh_recover'] = sanitize_text_field( wp_unslash( $_GET['gqs_recover'] ) );
		}
		if ( ! isset( $_COOKIE['gwqsh_trusted_device'] ) && isset( $_COOKIE['gqs_trusted_device'] ) && is_string( $_COOKIE['gqs_trusted_device'] ) ) {
			$_COOKIE['gwqsh_trusted_device'] = sanitize_text_field( wp_unslash( $_COOKIE['gqs_trusted_device'] ) );
		}
	}
}
