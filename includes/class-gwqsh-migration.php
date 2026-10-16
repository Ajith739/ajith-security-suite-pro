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
	 * Move existing plugin tables to the current prefix without modifying any records.
	 *
	 * MySQL/MariaDB keeps the atomic RENAME TABLE. The SQLite drop-in cannot rename
	 * tables portably: RENAME TABLE is rejected, and some driver versions accept
	 * ALTER TABLE ... RENAME TO with an error-free return value while leaving the
	 * table untouched, which would mark a migration complete with nothing migrated.
	 * On SQLite the table is therefore reproduced instead: identical DDL read from the
	 * source table, a verified row copy, and removal of the legacy table only once the
	 * copy is proven complete. Every path verifies its own outcome before continuing.
	 *
	 * @throws RuntimeException When a move would risk overwriting or losing security data.
	 */
	private static function tables() {
		global $wpdb;
		foreach ( array( 'activity_log', 'lockouts', 'scan_results', 'scan_history' ) as $suffix ) {
			$old = $wpdb->prefix . 'gqs_' . $suffix;
			$new = $wpdb->prefix . 'gwqsh_' . $suffix;
			if ( ! preg_match( '/^[A-Za-z0-9_]+$/D', $old . $new ) ) {
				throw new RuntimeException( 'Security Suite Pro found an invalid database prefix.' );
			}
			if ( ! self::table_exists( $old ) ) {
				continue;
			}
			if ( self::table_exists( $new ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Validated identifier; migration must read live state before moving data.
				$count = $wpdb->get_var( "SELECT COUNT(*) FROM `{$new}`" );
				if ( null === $count || (int) $count > 0 ) {
					throw new RuntimeException( 'Security Suite Pro found both legacy and current security tables. No records were overwritten. Reconcile these tables before continuing.' );
				}
				self::query( "DROP TABLE `{$new}`" );
			}
			self::move_table( $old, $new );
		}
	}

	/**
	 * Whether a plugin table is present, read from the live database.
	 *
	 * @param string $name Validated table name.
	 * @return bool Whether the table exists.
	 */
	private static function table_exists( $name ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $wpdb->esc_like( $name ) ) ) === $name;
	}

	/**
	 * Move one validated legacy table to its current name and verify the outcome.
	 *
	 * @param string $old Validated legacy table name.
	 * @param string $new Validated current table name.
	 * @throws RuntimeException When the move cannot be verified.
	 */
	private static function move_table( $old, $new ) {
		if ( 'sqlite' !== GWQSH_DB::driver() ) {
			self::query( "RENAME TABLE `{$old}` TO `{$new}`" );
			if ( ! self::table_exists( $new ) ) {
				throw new RuntimeException( 'Security Suite Pro could not rename a security table. Existing data was preserved; review database permissions and retry.' );
			}
			return;
		}
		self::copy_table( $old, $new );
	}

	/**
	 * Reproduce a table under the current prefix with a verified row copy.
	 *
	 * The source definition is read from the database so the copy keeps the same
	 * columns, indexes and types as the table the rename would have produced.
	 *
	 * @param string $old Validated legacy table name.
	 * @param string $new Validated current table name.
	 * @throws RuntimeException When the copied table cannot be verified.
	 */
	private static function copy_table( $old, $new ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$definition = $wpdb->get_row( "SHOW CREATE TABLE `{$old}`", ARRAY_N );
		$ddl        = is_array( $definition ) && isset( $definition[1] ) ? trim( (string) $definition[1] ) : '';
		if ( ! preg_match( '/^CREATE\s+TABLE\s+`?' . preg_quote( $old, '/' ) . '`?\s*/i', $ddl ) ) {
			throw new RuntimeException( 'Security Suite Pro could not read a legacy security table definition. Existing data was preserved; review database permissions and retry.' );
		}
		$ddl = preg_replace( '/^CREATE\s+TABLE\s+`?' . preg_quote( $old, '/' ) . '`?/i', 'CREATE TABLE `' . $new . '`', $ddl, 1 );
		self::query( $ddl );
		self::query( "INSERT INTO `{$new}` SELECT * FROM `{$old}`" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Validated identifiers; the row counts below are compared before anything is removed.
		$legacy_rows = $wpdb->get_var( "SELECT COUNT(*) FROM `{$old}`" );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Validated identifier; compared against the source table below.
		$copied_rows = $wpdb->get_var( "SELECT COUNT(*) FROM `{$new}`" );
		if ( null === $legacy_rows || null === $copied_rows || (int) $legacy_rows !== (int) $copied_rows ) {
			$wpdb->query( "DROP TABLE IF EXISTS `{$new}`" );
			throw new RuntimeException( 'Security Suite Pro copied a legacy security table but the copy did not verify. Existing data was preserved; review database permissions and retry.' );
		}
		$dropped = $wpdb->query( "DROP TABLE `{$old}`" );
		if ( false === $dropped || self::table_exists( $old ) ) {
			// The verified copy is in place, so the migration continues and the leftover
			// table is recorded for review instead of blocking the site with a 503.
			$leftovers   = (array) get_option( 'gwqsh_migration_leftover_tables', array() );
			$leftovers[] = $old;
			update_option( 'gwqsh_migration_leftover_tables', array_values( array_unique( $leftovers ) ), false );
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
			if ( 'sqlite' === GWQSH_DB::driver() ) {
				// The SQLite drop-in cannot run the self-join update below. A correlated
				// NOT EXISTS against a materialised derived table is equivalent: only keys
				// whose new name does not already exist are renamed, so no value is lost.
				self::query(
					$wpdb->prepare(
						"UPDATE {$wpdb->options} SET option_name = CONCAT(%s, SUBSTRING(option_name, %d)) WHERE option_name LIKE %s AND NOT EXISTS (SELECT 1 FROM (SELECT option_name AS taken FROM {$wpdb->options}) reserved WHERE reserved.taken = CONCAT(%s, SUBSTRING(option_name, %d)))",
						$new,
						strlen( $old ) + 1,
						$wpdb->esc_like( $old ) . '%',
						$new,
						strlen( $old ) + 1
					)
				);
			} else {
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
			}
			foreach ( $names as $name ) {
				wp_cache_delete( $name, 'options' );
				wp_cache_delete( $new . substr( $name, strlen( $old ) ), 'options' );
			}
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$users = $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT user_id FROM {$wpdb->usermeta} WHERE meta_key LIKE %s", $wpdb->esc_like( 'gqs_' ) . '%' ) );
		if ( 'sqlite' === GWQSH_DB::driver() ) {
			// Portable equivalent of the self-join below: rename only when the target key
			// does not already exist for that account, so no per-user value is replaced.
			self::query(
				$wpdb->prepare(
					"UPDATE {$wpdb->usermeta} SET meta_key = CONCAT(%s, SUBSTRING(meta_key, %d)) WHERE meta_key LIKE %s AND NOT EXISTS (SELECT 1 FROM (SELECT user_id AS owner, meta_key AS taken FROM {$wpdb->usermeta}) reserved WHERE reserved.owner = {$wpdb->usermeta}.user_id AND reserved.taken = CONCAT(%s, SUBSTRING({$wpdb->usermeta}.meta_key, %d)))",
					'gwqsh_',
					5,
					$wpdb->esc_like( 'gqs_' ) . '%',
					'gwqsh_',
					5
				)
			);
		} else {
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
		}
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
