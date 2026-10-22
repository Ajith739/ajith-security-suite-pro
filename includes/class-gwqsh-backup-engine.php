<?php
/**
 * Bounded database exports with authenticated completeness manifests.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
require_once __DIR__ . '/trait-gwqsh-database-restore.php';

/**
 * Administrator-started database exports continue in bounded background batches.
 * Database restoration uses this service's offline CLI operations; coordinated
 * filesystem recovery requires its separately verified snapshot workflow.
 */
final class GWQSH_Backup_Engine {
	use GWQSH_Database_Restore_Operations;
	const OPTION = 'gwqsh_backup_state';
	const HOOK = 'gwqsh_continue_database_backup';
	const RESTORES = 'gwqsh_database_restore_jobs';

	/** Reuse WordPress's scheduler solely to continue administrator-created jobs. */
	public static function init() {
		add_action( self::HOOK, array( __CLASS__, 'worker' ), 10, 1 );
		$state = (array) get_option( self::OPTION, array() );
		if ( 'running' === ( $state['state'] ?? '' ) && 'single_session' !== ( $state['execution'] ?? '' ) ) { self::schedule( $state['id'] ?? '' ); }
	}

	public static function deactivate() {
		wp_unschedule_hook( self::HOOK );
	}

	private static function schedule( $id, $delay = 10 ) {
		if ( is_string( $id ) && preg_match( '/^[a-f0-9]{32}$/D', $id ) && ! wp_next_scheduled( self::HOOK, array( $id ) ) ) {
			return wp_schedule_single_event( time() + $delay, self::HOOK, array( $id ), true );
		}
		return true;
	}

	/** Cron has no user identity: only resume the saved server-owned current job. */
	public static function worker( $id ) {
		$state = (array) get_option( self::OPTION, array() );
		if ( ! doing_action( self::HOOK ) || 'running' !== ( $state['state'] ?? '' ) || ( $state['id'] ?? '' ) !== $id || ( $state['blog_id'] ?? 0 ) !== get_current_blog_id() ) { return; }
		$result = self::process( $id );
		if ( is_wp_error( $result ) ) {
			$retry = (array) get_option( 'gwqsh_backup_worker_retry', array() );
			$count = ( $retry['id'] ?? '' ) === $id ? (int) $retry['count'] + 1 : 1;
			update_option( 'gwqsh_backup_worker_retry', array( 'id' => $id, 'count' => $count, 'reason' => $result->get_error_message() ), false );
			if ( $count < 3 ) { self::schedule( $id, 60 ); } else {
				wp_clear_scheduled_hook( self::HOOK, array( $id ) );
				$state['state'] = 'failed'; $state['verified'] = false; $state['reason'] = 'Worker stopped after three failures: ' . $result->get_error_message();
				update_option( self::OPTION, $state, false );
				$history = (array) get_option( 'gwqsh_backup_history', array() ); $history[ $id ] = $state;
				update_option( 'gwqsh_backup_history', $history, false );
			}
		} else { delete_option( 'gwqsh_backup_worker_retry' ); }
	}


	const MAX_BYTES = 52428800;
	const MAX_ROW = 262144;
	const BATCH = 20;
	const MAX_ARTIFACT = 10000000;
	const SNAPSHOT_SQL_MODE = 'NO_AUTO_VALUE_ON_ZERO,NO_ENGINE_SUBSTITUTION';

	private static function snapshot_environment() {
		return array( 'time_zone' => '+00:00', 'sql_mode' => self::SNAPSHOT_SQL_MODE, 'schema_literals' => 1 );
	}
	private static function snapshot_environment_valid( $environment ) {
		return is_array( $environment ) && ( $environment['time_zone'] ?? '' ) === '+00:00' && ( $environment['sql_mode'] ?? '' ) === self::SNAPSHOT_SQL_MODE && ( $environment['schema_literals'] ?? 0 ) === 1;
	}
	/** Independent bounded reader; never mutate the caller's session or reconnect
	 * transparently with a different timezone/mode halfway through a batch.
	 */
	private static function snapshot_connection( $name ) {
		$db = new class( DB_USER, DB_PASSWORD, $name, DB_HOST ) extends wpdb {
			public function db_connect( $allow_bail = true ) { return parent::db_connect( false ); }
			public function check_connection( $allow_bail = true ) { return false; }
		};
		$db->hide_errors(); $db->suppress_errors( true );
		if ( ! $db->ready ) { $db->close(); return new WP_Error( 'database', 'Snapshot connection unavailable; caller session was not changed.' ); }
		$db->set_prefix( $GLOBALS['wpdb']->prefix );
		if ( false === $db->query( "SET SESSION time_zone='+00:00',sql_mode='" . self::SNAPSHOT_SQL_MODE . "',sql_quote_show_create=1" ) ) { $db->close(); return new WP_Error( 'environment', 'Canonical snapshot session settings are unavailable.' ); }
		$version = (string) $db->get_var( 'SELECT VERSION()' );
		if ( false === $db->query( false !== stripos( $version, 'MariaDB' ) ? 'SET SESSION max_statement_time=5,lock_wait_timeout=5,innodb_lock_wait_timeout=5' : 'SET SESSION max_execution_time=5000,lock_wait_timeout=5,innodb_lock_wait_timeout=5' ) ) { $db->close(); return new WP_Error( 'budget', 'The database cannot enforce bounded snapshot statements.' ); }
		return $db;
	}

	/** Private storage must be validated on every operation, including existing directories. */
	public static function backup_dir() {
		$base = GWQSH_Quarantine_Manager::ensure_quarantine_dir();
		if ( is_wp_error( $base ) ) { return $base; }
		$dir = $base . '/backups';
		if ( ! method_exists( 'GWQSH_Guardian', 'private_path' ) || ! GWQSH_Guardian::private_path( $dir ) || ( 'Windows' === PHP_OS_FAMILY && ! GWQSH_Guardian::windows_private_acl( $dir ) ) || ! GWQSH_Security_Runtime::protect( $dir ) ) {
			return new WP_Error( 'storage', 'Private backup storage is unavailable.' );
		}
		return $dir;
	}

	/** Non-expiring filesystem ownership prevents slow database queries outliving a lease. */
	private static function lock( $dir ) {
		$file = $dir . '/backup.lock';
		if ( is_link( $file ) ) { return false; }
		$handle = fopen( $file, 'c' );
		if ( ! $handle ) { return false; }
		if ( ! chmod( $file, 0600 ) || ! flock( $handle, LOCK_EX | LOCK_NB ) ) { fclose( $handle ); return false; }
		return $handle;
	}

	private static function unlock( $handle ) {
		flock( $handle, LOCK_UN ); fclose( $handle );
	}

	/** Enumerate the actual database, including third-party and HPOS tables.
	 * Site scope excludes shared network identity and other blogs. Network/database
	 * exports require network management on multisite; exclusions are always explicit.
	 */
	public static function database_inventory( $scope = 'site' ) {
		global $wpdb;
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) { return new WP_Error( 'permission', 'Administrative permission required.' ); }
		if ( ! in_array( $scope, array( 'site', 'network', 'database' ), true ) || ( 'network' === $scope && ! is_multisite() ) ) { return new WP_Error( 'scope', 'Choose site, database, or an available multisite network scope.' ); }
		// A hard inventory limit fails visibly rather than silently truncating coverage.
		$rows = $wpdb->get_results( 'SELECT TABLE_NAME AS name,TABLE_TYPE AS type,ENGINE AS engine FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME LIMIT 2001', ARRAY_A );
		if ( $wpdb->last_error || ! is_array( $rows ) || ! $rows || count( $rows ) > 2000 ) { return new WP_Error( 'inventory', 'Database inventory failed, is empty, or exceeds the 2000-table budget; external recovery tooling is required.' ); }
		$inventory = array( 'scope' => $scope, 'database' => DB_NAME, 'prefix' => $wpdb->prefix, 'base_prefix' => $wpdb->base_prefix, 'tables' => array(), 'excluded' => array(), 'exportable' => true );
		$shared = is_multisite() ? array_merge( array_values( $wpdb->tables( 'global', true ) ), array_values( $wpdb->tables( 'ms_global', true ) ) ) : array();
		foreach ( $rows as $row ) {
			$name = $row['name'];
			$selected = 'database' === $scope || ( 'network' === $scope && ( str_starts_with( $name, $wpdb->base_prefix ) || in_array( $name, $shared, true ) ) );
			if ( 'site' === $scope ) {
				$selected = str_starts_with( $name, $wpdb->prefix ) && ! in_array( $name, $shared, true );
				// Blog 1's base prefix also prefixes every other site's tables.
				if ( is_multisite() && $wpdb->prefix === $wpdb->base_prefix && preg_match( '/^' . preg_quote( $wpdb->base_prefix, '/' ) . '[0-9]+_/', $name ) ) { $selected = false; }
			}
			if ( ! $selected ) { $inventory['excluded'][ $name ] = 'outside_selected_scope'; continue; }
			$supported = 'BASE TABLE' === $row['type'] && (bool) preg_match( '/^[a-zA-Z0-9_]{1,64}$/D', $name );
			$inventory['tables'][ $name ] = array( 'type' => $row['type'], 'engine' => $row['engine'], 'supported' => $supported );
			$inventory['exportable'] = $inventory['exportable'] && $supported;
		}
		if ( ! $inventory['tables'] ) { return new WP_Error( 'inventory', 'No tables exist in the selected scope.' ); }
		return $inventory;
	}

	/** Encrypt, restrict, read back and authenticate every artifact before advancing progress. */
	private static function write( $file, array $data ) {
		$json = wp_json_encode( $data );
		// Never publish an artifact the bounded reader cannot subsequently verify.
		if ( ! is_string( $json ) || strlen( $json ) > 7400000 ) { return false; }
		$cipher = GWQSH_Crypto::encrypt( $json );
		if ( ! $cipher || strlen( $cipher ) > self::MAX_ARTIFACT || ! GWQSH_Security_Runtime::atomic_write( $file, $cipher ) || ! chmod( $file, 0600 ) ) { return false; }
		$actual = file_get_contents( $file );
		return is_string( $actual ) && hash_equals( hash( 'sha256', $cipher ), hash( 'sha256', $actual ) ) && GWQSH_Crypto::decrypt( $actual ) === $json;
	}

	/** Never trust paths or completion claims stored only in mutable option metadata. */
	private static function read( $file, $dir ) {
		if ( ! GWQSH_Security_Runtime::safe_path( $file, $dir ) || ! is_file( $file ) || filesize( $file ) > self::MAX_ARTIFACT ) { return new WP_Error( 'artifact', 'Backup artifact is missing or exceeds its bounded size.' ); }
		$plain = GWQSH_Crypto::decrypt( file_get_contents( $file ) );
		$data = is_string( $plain ) ? json_decode( $plain, true, 64 ) : null;
		return is_array( $data ) ? $data : new WP_Error( 'integrity', 'Backup artifact authentication failed.' );
	}

	/** Persist authenticated completeness state; history entries are never silently dropped. */
	private static function save( array $state, $dir ) {
		$file = 'db-' . $state['id'] . '-manifest.enc';
		if ( ! self::write( $dir . '/' . $file, $state ) ) { return new WP_Error( 'storage', 'Backup manifest could not be authenticated after writing.' ); }
		$meta = array( 'id' => $state['id'], 'type' => 'database', 'format' => 2, 'context' => $state['context'], 'created_at' => $state['created_at'], 'blog_id' => $state['blog_id'], 'rows' => $state['rows'], 'size' => $state['bytes'], 'file' => $file, 'encrypted' => true, 'verified' => 'complete' === $state['state'], 'state' => $state['state'], 'coverage' => $state['coverage'], 'environment' => $state['environment'] ?? null, 'reason' => $state['reason'], 'consistency' => $state['consistency'] );
		if ( isset( $state['execution'] ) ) { $meta['execution'] = $state['execution']; $meta['snapshot'] = $state['snapshot'] ?? array(); }
		$history = (array) get_option( 'gwqsh_backup_history', array() );
		$history[ $state['id'] ] = $meta;
		update_option( 'gwqsh_backup_history', $history, false );
		if ( get_option( 'gwqsh_backup_history' ) !== $history ) { return new WP_Error( 'storage', 'Backup history persistence failed; retain private evidence.' ); }
		update_option( self::OPTION, $meta, false );
		if ( get_option( self::OPTION ) !== $meta ) { return new WP_Error( 'storage', 'Backup continuation state was not persisted.' ); }
		if ( 'running' === $meta['state'] && 'single_session' !== ( $meta['execution'] ?? '' ) ) { self::schedule( $state['id'] ); } else { wp_clear_scheduled_hook( self::HOOK, array( $state['id'] ) ); }
		return $meta;
	}

	private static function export_state( $context, array $inventory ) {
		return array( 'schema' => 2, 'id' => bin2hex( random_bytes( 16 ) ), 'blog_id' => get_current_blog_id(), 'context' => sanitize_key( $context ), 'created_at' => time(), 'state' => 'running', 'reason' => '', 'tables' => array_fill_keys( array_keys( $inventory['tables'] ), array() ), 'cursor' => 0, 'rows' => 0, 'bytes' => 0, 'chunks' => array(), 'coverage' => $inventory, 'environment' => self::snapshot_environment(), 'consistency' => 'Best effort keyset export across requests; not a transactionally consistent database snapshot. Concurrent updates/deletes may change contents; count and schema drift are refused.' );
	}

	/** CLI only: one bounded read-only InnoDB view, never resumed on a new session.
	 * Operators must freeze DDL; schema/inventory drift is refused, not ignored.
	 */
	public static function create_consistent_database_backup( $context = 'manual', $scope = 'site', $seconds = 30 ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Use WP-CLI with a security administrator for a single-session snapshot.' ); }
		if ( ! is_int( $seconds ) || $seconds < 1 || $seconds > 60 ) { return new WP_Error( 'budget', 'Snapshot time budget must be an integer from 1 to 60 seconds.' ); }
		$inventory = self::database_inventory( $scope ); if ( is_wp_error( $inventory ) ) { return $inventory; }
		if ( ! $inventory['exportable'] || array_filter( $inventory['tables'], static function ( $table ) { return 'InnoDB' !== $table['engine']; } ) ) { return new WP_Error( 'unsupported_snapshot', 'A consistent snapshot requires only supported InnoDB base tables; no silent exclusions are allowed.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup operation is active.' ); }
		$db = null;
		try {
			$active = self::restore_fresh_option( self::OPTION );
			if ( 'running' === ( $active['state'] ?? '' ) ) { return new WP_Error( 'busy', 'Finish or cancel the existing export before starting a consistent snapshot.' ); }
			$db = self::snapshot_connection( DB_NAME ); if ( is_wp_error( $db ) ) { return $db; }
			$state = self::export_state( $context, $inventory );
			$state['execution'] = 'single_session'; $state['snapshot'] = array( 'kind' => 'innodb-repeatable-read', 'state' => 'open' );
			$state['consistency'] = 'One read-only REPEATABLE READ InnoDB snapshot of the selected inventory. Operator must freeze DDL; detected schema/inventory drift fails. Interrupted sessions cannot resume.';
			$initial = self::save( $state, $dir ); if ( is_wp_error( $initial ) ) { return $initial; }
			try { $result = self::consistent_rows( $state, $dir, $db, $seconds ); }
			catch ( Throwable $error ) { $result = new WP_Error( 'snapshot', 'Snapshot execution stopped unexpectedly; partial encrypted evidence is retained.' ); }
			if ( is_wp_error( $result ) ) { $state['state'] = 'failed'; $state['snapshot']['state'] = 'failed'; $state['reason'] = $result->get_error_message(); }
			else { $state['state'] = 'complete'; $state['snapshot']['state'] = 'committed'; }
			return self::save( $state, $dir );
		} finally {
			if ( $db instanceof wpdb ) { $db->query( 'ROLLBACK' ); $db->close(); }
			self::unlock( $lock );
		}
	}

	private static function consistent_rows( &$state, $dir, $db, $seconds ) {
		$deadline = microtime( true ) + $seconds;
		if ( false === $db->query( 'SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ' ) || false === $db->query( 'START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY' ) || false === $db->query( 'SAVEPOINT gwqsh_consistent_guard' ) ) { return new WP_Error( 'snapshot', 'The database did not establish the required read-only consistent snapshot.' ); }
		// Open every selected table to retain metadata locks until the transaction ends.
		foreach ( array_keys( $state['tables'] ) as $table ) {
			if ( microtime( true ) >= $deadline ) { return new WP_Error( 'budget', 'Consistent snapshot time budget exhausted; partial evidence is not resumable.' ); }
			if ( false === $db->query( "SELECT 1 FROM `{$table}` LIMIT 0" ) ) { return new WP_Error( 'schema', 'Snapshot could not retain selected table metadata.' ); }
		}
		while ( $state['cursor'] < count( $state['tables'] ) ) {
			if ( microtime( true ) >= $deadline ) { return new WP_Error( 'budget', 'Consistent snapshot time budget exhausted; partial evidence is not resumable.' ); }
			$result = self::batch( $state, $dir, $db ); if ( is_wp_error( $result ) ) { return $result; }
			// Savepoints disappear on implicit commit, rollback or connection loss.
			if ( false === $db->query( 'RELEASE SAVEPOINT gwqsh_consistent_guard' ) || false === $db->query( 'SAVEPOINT gwqsh_consistent_guard' ) ) { return new WP_Error( 'snapshot_lost', 'The original snapshot transaction was lost; a fresh view cannot continue it.' ); }
		}
		$inventory = self::database_inventory( $state['coverage']['scope'] );
		if ( is_wp_error( $inventory ) || $inventory !== $state['coverage'] ) { return new WP_Error( 'drift', 'Selected database inventory changed during the snapshot.' ); }
		$saved = self::save( $state, $dir ); if ( is_wp_error( $saved ) ) { return $saved; }
		$check = self::verify( $state['id'] );
		if ( is_wp_error( $check ) || $check['rows'] !== $state['rows'] || $check['size'] !== $state['bytes'] ) { return new WP_Error( 'integrity', 'Consistent snapshot artifacts did not pass complete read-back verification.' ); }
		if ( microtime( true ) >= $deadline ) { return new WP_Error( 'budget', 'Consistent snapshot verification exceeded its budget; artifacts remain unverified.' ); }
		if ( false === $db->query( 'RELEASE SAVEPOINT gwqsh_consistent_guard' ) || false === $db->query( 'COMMIT' ) ) { return new WP_Error( 'snapshot_lost', 'The original snapshot did not finish cleanly; no completion claim is made.' ); }
		return true;
	}

	/** Start a bounded resumable export, or continue the currently running export.
	 * Native schemas and binary-safe rows use encrypted chunks. Offline restoration
	 * validates table-only DDL and inserts encoded cells strictly as data.
	 */
	public static function create_database_backup( $context = 'manual', $scope = 'site' ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) { return new WP_Error( 'permission', 'Administrative permission required.' ); }
		$inventory = self::database_inventory( $scope );
		if ( is_wp_error( $inventory ) ) { return $inventory; }
		$current = get_option( self::OPTION, array() );
		if ( 'running' === ( $current['state'] ?? '' ) ) {
			$active_scope = $current['coverage']['scope'] ?? 'site';
			if ( ! in_array( $active_scope, array( 'site', 'network', 'database' ), true ) ) { $active_scope = 'site'; }
			if ( $scope !== $active_scope ) { return new WP_Error( 'scope_mismatch', 'The running export has a different scope; finish or cancel it before starting another scope.' ); }
			return self::continue_database_backup( $current['id'] );
		}
		if ( ! $inventory['exportable'] ) { return new WP_Error( 'unsupported', 'Selected scope includes views or unsupported table identifiers; inventory retained for operator review, no incomplete export was started.' ); }
		$dir = self::backup_dir();
		if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir );
		if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup operation is running.' ); }
		try {
			$active = (array) get_option( self::OPTION, array() );
			if ( 'running' === ( $active['state'] ?? '' ) ) { return new WP_Error( 'busy', 'A backup was started concurrently; continue the current job.' ); }
			$state = self::export_state( $context, $inventory );
			return self::save( $state, $dir );
		} finally { self::unlock( $lock ); }
	}

	/** One table/keyset batch per invocation; caller explicitly continues running jobs. */
	public static function continue_database_backup( $id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) { return new WP_Error( 'permission', 'Administrative permission and a valid backup ID required.' ); }
		return self::process( $id );
	}

	private static function process( $id ) {
		if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) { return new WP_Error( 'id', 'Invalid backup identifier.' ); }
		$dir = self::backup_dir();
		if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir );
		if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup operation is running.' ); }
		try {
			$active = (array) get_option( self::OPTION, array() );
			if ( ( $active['id'] ?? '' ) !== $id || 'running' !== ( $active['state'] ?? '' ) ) { return new WP_Error( 'stale', 'The current running backup changed.' ); }
			$state = self::read( $dir . '/db-' . $id . '-manifest.enc', $dir );
			if ( is_wp_error( $state ) ) { return $state; }
			if ( 2 !== ( $state['schema'] ?? 0 ) || $state['blog_id'] !== get_current_blog_id() || $state['id'] !== $id ) { return new WP_Error( 'scope', 'Backup manifest belongs to another scope.' ); }
			if ( 'running' !== $state['state'] ) { return new WP_Error( 'state', 'Only running backups can be continued.' ); }
			if ( 'single_session' === ( $state['execution'] ?? '' ) ) {
				$state['state'] = 'failed'; $state['snapshot']['state'] = 'lost'; $state['reason'] = 'The original consistent snapshot session ended; preserve partial evidence and start a new export.';
				return self::save( $state, $dir );
			}
			$result = self::batch( $state, $dir );
			if ( is_wp_error( $result ) ) { $state['state'] = 'failed'; $state['reason'] = $result->get_error_message(); }
			return self::save( $state, $dir );
		} finally { self::unlock( $lock ); }
	}

	/** Stop pending continuation without deleting any evidence. */
	public static function cancel_database_backup( $id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) { return new WP_Error( 'permission', 'Administrative permission and valid ID required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'A backup batch is active; retry cancellation.' ); }
		try {
			$active = (array) get_option( self::OPTION, array() );
			if ( ( $active['id'] ?? '' ) !== $id || 'running' !== ( $active['state'] ?? '' ) ) { return new WP_Error( 'stale', 'The current running backup changed.' ); }
			$state = self::read( $dir . '/db-' . $id . '-manifest.enc', $dir );
			if ( is_wp_error( $state ) ) { return $state; }
			if ( ( $state['id'] ?? '' ) !== $id || ( $state['blog_id'] ?? 0 ) !== get_current_blog_id() || 'running' !== ( $state['state'] ?? '' ) ) { return new WP_Error( 'state', 'Only a running current-site backup may be cancelled.' ); }
			$state['state'] = 'cancelled'; $state['reason'] = 'Administrator cancelled export; partial evidence retained.';
			return self::save( $state, $dir );
		} finally { self::unlock( $lock ); }
	}

	/** Export a bounded batch, preserving binary values using base64 and NULL distinctly. */
	private static function batch( &$state, $dir, $database = null, $hash_only = false ) {
		if ( ! isset( $state['environment'] ) ) {
			if ( $state['cursor'] || $state['chunks'] || $state['rows'] ) { return new WP_Error( 'environment', 'Unmarked partial export cannot be mixed with UTC data; preserve it and start a new export.' ); }
			$state['environment'] = self::snapshot_environment();
		}
		if ( ! self::snapshot_environment_valid( $state['environment'] ) ) { return new WP_Error( 'environment', 'Unsupported snapshot environment.' ); }
		$owned = null === $database;
		$db = $owned ? self::snapshot_connection( DB_NAME ) : $database;
		if ( is_wp_error( $db ) ) { return $db; }
		try {
			$settings = $db->get_row( 'SELECT @@session.time_zone AS zone,@@session.sql_mode AS mode,@@session.sql_quote_show_create AS quoted', ARRAY_A );
			if ( $db->last_error || ! is_array( $settings ) || '+00:00' !== $settings['zone'] || self::SNAPSHOT_SQL_MODE !== $settings['mode'] || '1' !== (string) $settings['quoted'] ) { return new WP_Error( 'environment', 'Snapshot session changed or cannot be verified.' ); }
			return self::batch_rows( $state, $dir, $db, $hash_only );
		} finally { if ( $owned ) { $db->close(); } }
	}

	private static function batch_rows( &$state, $dir, $wpdb, $hash_only ) {
		$names = array_keys( $state['tables'] );
		if ( $state['cursor'] >= count( $names ) ) {
			$integrity = $hash_only ? true : self::verify( $state['id'] );
			if ( is_wp_error( $integrity ) ) { return $integrity; }
			$state['state'] = 'complete'; return true;
		}
		$table = $names[ $state['cursor'] ];
		$database_scope = in_array( $state['coverage']['scope'] ?? '', array( 'network', 'database' ), true );
		if ( ! preg_match( '/^[a-zA-Z0-9_]{1,64}$/D', $table ) || ( ! $database_scope && ! str_starts_with( $table, $wpdb->prefix ) ) ) { return new WP_Error( 'scope', 'Invalid table scope.' ); }
		$schema = $wpdb->get_row( "SHOW CREATE TABLE `{$table}`", ARRAY_N );
		if ( $wpdb->last_error || ! isset( $schema[1] ) || strlen( $schema[1] ) > self::MAX_ROW ) { return new WP_Error( 'schema', 'A required table is missing or its schema is unreadable or exceeds its budget.' ); }
		$info = &$state['tables'][ $table ];
		if ( ! $info ) {
			$columns = $wpdb->get_col( "SHOW COLUMNS FROM `{$table}`" );
			if ( $wpdb->last_error || ! $columns ) { return new WP_Error( 'columns', 'Column discovery failed.' ); }
			foreach ( $columns as $column ) { if ( '__gwqsh_bytes' === $column || ! preg_match( '/^[a-zA-Z0-9_]+$/D', $column ) ) { return new WP_Error( 'columns', 'Unsupported column identifier.' ); } }
			$keys = array();
			$indexes = $wpdb->get_results( "SHOW KEYS FROM `{$table}` WHERE Key_name='PRIMARY'", ARRAY_A );
			if ( ! $wpdb->last_error && $indexes ) {
				usort( $indexes, static function ( $a, $b ) { return (int) $a['Seq_in_index'] <=> (int) $b['Seq_in_index']; } );
				$keys = array_column( $indexes, 'Column_name' );
			} else {
				$col_meta = $wpdb->get_results( "SHOW COLUMNS FROM `{$table}`", ARRAY_A );
				$not_null = array();
				if ( is_array( $col_meta ) ) {
					foreach ( $col_meta as $c ) {
						if ( 'NO' === ( $c['Null'] ?? '' ) ) { $not_null[] = $c['Field']; }
					}
				}
				$uniques = $wpdb->get_results( "SHOW KEYS FROM `{$table}` WHERE Non_unique=0", ARRAY_A );
				if ( ! $wpdb->last_error && is_array( $uniques ) && $uniques ) {
					$grouped = array();
					foreach ( $uniques as $u ) {
						$grouped[ $u['Key_name'] ][] = $u;
					}
					foreach ( $grouped as $key_name => $parts ) {
						usort( $parts, static function ( $a, $b ) { return (int) $a['Seq_in_index'] <=> (int) $b['Seq_in_index']; } );
						$cols = array_column( $parts, 'Column_name' );
						if ( ! array_diff( $cols, $not_null ) ) {
							$keys = $cols;
							break;
						}
					}
				}
			}
			$count = $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );
			if ( $wpdb->last_error || null === $count ) { return new WP_Error( 'count', 'Initial row count failed.' ); }
			$info = array( 'schema' => $schema[1], 'columns' => $columns, 'keys' => $keys, 'expected_rows' => (int) $count, 'rows' => 0, 'last' => null, 'complete' => false );
		} elseif ( $info['schema'] !== $schema[1] ) { return new WP_Error( 'schema', 'Table schema changed during backup.' ); }
		$key_sql = $info['keys'] ? '`' . implode( '`,`', $info['keys'] ) . '`' : '`' . implode( '`,`', $info['columns'] ) . '`';
		$where = '';
		$limit_sql = ' LIMIT 20';
		if ( $info['keys'] ) {
			if ( null !== $info['last'] ) {
				$values = array_map( 'base64_decode', $info['last'] );
				$where = $wpdb->prepare( ' WHERE (' . $key_sql . ') > (' . implode( ',', array_fill( 0, count( $values ), '%s' ) ) . ')', $values );
			}
		} else {
			$offset = (int) $info['rows'];
			$limit_sql = " LIMIT 20 OFFSET {$offset}";
		}
		$lengths = implode( '+', array_map( static function ( $column ) { return 'COALESCE(OCTET_LENGTH(`' . $column . '`),0)'; }, $info['columns'] ) );
		$sizes = $wpdb->get_col( "SELECT {$lengths} FROM `{$table}`{$where} ORDER BY {$key_sql}{$limit_sql}" );
		if ( $wpdb->last_error ) { return new WP_Error( 'query', 'Row size preflight query failed.' ); }
		if ( $sizes && max( $sizes ) > self::MAX_ROW ) { return new WP_Error( 'size', 'A row exceeds the 256 KiB bounded exporter budget; use an external consistent snapshot.' ); }
		// CASE prevents a concurrently enlarged row from causing an unbounded allocation.
		$select = implode( ',', array_map( static function ( $column ) use ( $lengths ) { return 'CASE WHEN (' . $lengths . ') <= 262144 THEN `' . $column . '` ELSE NULL END AS `' . $column . '`'; }, $info['columns'] ) );
		$rows = $wpdb->get_results( "SELECT {$select},({$lengths}) AS __gwqsh_bytes FROM `{$table}`{$where} ORDER BY {$key_sql}{$limit_sql}", ARRAY_A );
		if ( $wpdb->last_error || ! is_array( $rows ) ) { return new WP_Error( 'query', 'Data export query failed.' ); }
		if ( ! $rows ) {
			$count = $wpdb->get_var( "SELECT COUNT(*) FROM `{$table}`" );
			if ( $wpdb->last_error || null === $count || (int) $count !== $info['expected_rows'] || $info['rows'] !== $info['expected_rows'] ) { return new WP_Error( 'drift', 'Row counts changed or coverage is incomplete.' ); }
			$info['complete'] = true; ++$state['cursor']; return true;
		}
		$encoded = array();
		foreach ( $rows as $row ) {
			if ( $row['__gwqsh_bytes'] > self::MAX_ROW ) { return new WP_Error( 'size', 'A row grew beyond the export budget.' ); }
			unset( $row['__gwqsh_bytes'] );
			$encoded[] = array_map( static function ( $value ) { return null === $value ? null : base64_encode( $value ); }, $row );
		}
		$chunk = array( 'schema' => 2, 'blog_id' => $state['blog_id'], 'backup_id' => $state['id'], 'table' => $table, 'rows' => $encoded );
		$json = wp_json_encode( $chunk );
		if ( ! is_string( $json ) || $state['bytes'] + strlen( $json ) > self::MAX_BYTES || count( $state['chunks'] ) >= 10000 ) { return new WP_Error( 'budget', 'Export budget exhausted; incomplete data is not a verified backup.' ); }
		$file = 'db-' . $state['id'] . '-' . count( $state['chunks'] ) . '.enc';
		if ( ! $hash_only && ! self::write( $dir . '/' . $file, $chunk ) ) { return new WP_Error( 'write', 'Encrypted chunk could not be written and authenticated.' ); }
		$state['chunks'][] = array( 'file' => $file, 'digest' => hash( 'sha256', $json ), 'content_digest' => hash( 'sha256', wp_json_encode( $encoded ) ), 'table' => $table, 'rows' => count( $rows ) );
		$state['bytes'] += strlen( $json ); $state['rows'] += count( $rows ); $info['rows'] += count( $rows );
		$last = end( $rows ); $info['last'] = array();
		if ( $info['keys'] ) {
			foreach ( $info['keys'] as $key ) { $info['last'][] = base64_encode( $last[ $key ] ); }
		}
		return true;
	}

	public static function list_backups() {
		return current_user_can( GWQSH_Admin::management_capability() ) ? (array) get_option( 'gwqsh_backup_history', array() ) : new WP_Error( 'permission', 'Administrative permission required.' );
	}

	/** Authenticate manifest plus all chunks; completeness is independent of integrity. */
	public static function verify_backup( $backup_id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! is_string( $backup_id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $backup_id ) ) { return new WP_Error( 'permission', 'Administrative permission and valid ID required.' ); }
		return self::verify( $backup_id );
	}

	private static function verify( $backup_id ) {
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$state = self::read( $dir . '/db-' . $backup_id . '-manifest.enc', $dir );
		if ( is_wp_error( $state ) ) { return $state; }
		if ( 2 !== ( $state['schema'] ?? 0 ) || ( $state['id'] ?? '' ) !== $backup_id || ( $state['blog_id'] ?? 0 ) !== get_current_blog_id() ) { return new WP_Error( 'scope', 'Manifest scope is invalid.' ); }
		if ( isset( $state['environment'] ) && ! self::snapshot_environment_valid( $state['environment'] ) ) { return new WP_Error( 'environment', 'Manifest environment is unsupported; UTC/SQL-mode semantics were not established.' ); }
		if ( isset( $state['execution'] ) && ( 'single_session' !== $state['execution'] || 'innodb-repeatable-read' !== ( $state['snapshot']['kind'] ?? '' ) || ! in_array( $state['snapshot']['state'] ?? '', array( 'open', 'failed', 'lost', 'committed' ), true ) || ( 'complete' === ( $state['state'] ?? '' ) && 'committed' !== $state['snapshot']['state'] ) ) ) { return new WP_Error( 'snapshot', 'Single-session snapshot state is unsupported or incomplete.' ); }
		if ( ! is_array( $state['chunks'] ?? null ) || count( $state['chunks'] ) > 10000 || ! is_array( $state['tables'] ?? null ) || count( $state['tables'] ) > 2000 || ! is_int( $state['rows'] ?? null ) || $state['rows'] < 0 || ! is_int( $state['bytes'] ?? null ) || $state['bytes'] < 0 || $state['bytes'] > self::MAX_BYTES || ! in_array( $state['state'] ?? null, array( 'running', 'complete', 'failed', 'cancelled' ), true ) || ! is_array( $state['coverage'] ?? null ) || ! is_string( $state['consistency'] ?? null ) ) { return new WP_Error( 'manifest', 'Manifest structure or budget is invalid.' ); }
		foreach ( $state['tables'] as $table => $info ) {
			if ( ! is_string( $table ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $table ) || ! is_array( $info ) ) { return new WP_Error( 'manifest', 'Invalid table metadata.' ); }
			if ( ! $info ) { continue; }
			if ( ! is_string( $info['schema'] ?? null ) || ! is_array( $info['columns'] ?? null ) || ! $info['columns'] || ! is_array( $info['keys'] ?? null ) || ! is_int( $info['rows'] ?? null ) || $info['rows'] < 0 || ! is_int( $info['expected_rows'] ?? null ) || $info['expected_rows'] < 0 || ! is_bool( $info['complete'] ?? null ) ) { return new WP_Error( 'manifest', 'Invalid table completeness metadata.' ); }
			foreach ( array_merge( $info['columns'], $info['keys'] ) as $column ) { if ( ! is_string( $column ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $column ) ) { return new WP_Error( 'manifest', 'Invalid column/key metadata.' ); } }
			if ( array_diff( $info['keys'], $info['columns'] ) || count( array_unique( $info['columns'] ) ) !== count( $info['columns'] ) ) { return new WP_Error( 'manifest', 'Column/key coverage is invalid.' ); }
		}
		$counts = array(); $bytes = 0; $deadline = microtime( true ) + max( 0, min( 10, (float) apply_filters( 'gwqsh_backup_verification_budget_seconds', 10 ) ) );
		foreach ( $state['chunks'] as $index => $chunk ) {
			if ( microtime( true ) > $deadline ) { return new WP_Error( 'incomplete_verification', 'Verification time budget reached; integrity has not been established for all chunks.' ); }
			if ( ! is_array( $chunk ) || ( $chunk['file'] ?? '' ) !== 'db-' . $backup_id . '-' . $index . '.enc' || ! is_string( $chunk['table'] ?? null ) || empty( $state['tables'][ $chunk['table'] ] ) || ! is_int( $chunk['rows'] ?? null ) || $chunk['rows'] < 1 || $chunk['rows'] > self::BATCH || ! is_string( $chunk['digest'] ?? null ) || ! preg_match( '/^[a-f0-9]{64}$/D', $chunk['digest'] ) ) { return new WP_Error( 'manifest', 'Chunk ordering or metadata is invalid.' ); }
			$data = self::read( $dir . '/' . $chunk['file'], $dir );
			if ( is_wp_error( $data ) || 2 !== ( $data['schema'] ?? 0 ) || ( $data['backup_id'] ?? '' ) !== $backup_id || ( $data['blog_id'] ?? 0 ) !== get_current_blog_id() || ( $data['table'] ?? '' ) !== $chunk['table'] || ! is_array( $data['rows'] ?? null ) || count( $data['rows'] ) !== $chunk['rows'] || ! hash_equals( $chunk['digest'], hash( 'sha256', wp_json_encode( $data ) ) ) ) { return new WP_Error( 'integrity', 'Encrypted chunk integrity or row count failed.' ); }
			foreach ( $data['rows'] as $row ) {
				if ( ! is_array( $row ) || array_keys( $row ) !== $state['tables'][ $chunk['table'] ]['columns'] ) { return new WP_Error( 'manifest', 'Chunk column coverage is invalid.' ); }
				$row_bytes = 0;
				foreach ( $row as $cell ) {
					if ( null === $cell ) { continue; }
					if ( ! is_string( $cell ) || false === ( $decoded = base64_decode( $cell, true ) ) || base64_encode( $decoded ) !== $cell ) { return new WP_Error( 'manifest', 'Invalid binary cell encoding.' ); }
					$row_bytes += strlen( $decoded );
				}
				if ( $row_bytes > self::MAX_ROW ) { return new WP_Error( 'manifest', 'Chunk row exceeds the bounded byte budget.' ); }
			}
			$counts[ $chunk['table'] ] = ( $counts[ $chunk['table'] ] ?? 0 ) + $chunk['rows'];
			$bytes += strlen( wp_json_encode( $data ) );
		}
		if ( array_sum( $counts ) !== $state['rows'] || $bytes !== $state['bytes'] || array_diff_key( $counts, $state['tables'] ) ) { return new WP_Error( 'manifest', 'Manifest totals do not match authenticated chunks.' ); }
		foreach ( $state['tables'] as $table => $info ) {
			if ( $info && ( $counts[ $table ] ?? 0 ) !== $info['rows'] ) { return new WP_Error( 'manifest', 'Per-table progress differs from authenticated chunks.' ); }
		}
		$complete = 'complete' === $state['state'];
		foreach ( $state['tables'] as $table => $info ) { $complete = $complete && ! empty( $info['complete'] ) && $info['rows'] === $info['expected_rows'] && ( $counts[ $table ] ?? 0 ) === $info['rows'] && ! empty( $info['schema'] ); }
		$complete = $complete && array_sum( $counts ) === $state['rows'] && $bytes === $state['bytes'];
		return array( 'backup_id' => $backup_id, 'integrity' => true, 'complete' => $complete, 'verified' => $complete, 'state' => $state['state'], 'decryptable' => true, 'rows' => array_sum( $counts ), 'size' => $bytes, 'coverage' => $state['coverage'], 'environment' => $state['environment'] ?? null, 'consistency' => $state['consistency'] );
	}
	/** API-compatible core checksum verification only; no restoration is performed.
	 *
	 * @return array|WP_Error Restoration result.
	 */
	public static function restore_core_files() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}

		$checksums = GWQSH_File_Integrity::get_core_checksums();
		if ( ! is_array( $checksums ) || empty( $checksums ) ) {
			return new WP_Error( 'checksums', 'Core checksums are unavailable. Verify WordPress API connectivity.' );
		}

		global $wp_version;



		$results = array(
			'operation' => 'verification_only',
			'state' => 'running',
			'expected' => count( $checksums ),
			'checked' => 0,
			'verified'  => 0,
			'modified'  => 0,
			'missing'   => 0,
			'restored'  => 0,
			'failed'    => 0,
			'skipped'   => 0,
			'details'   => array(),
		);

		$deadline = microtime( true ) + 30;

		foreach ( $checksums as $relative => $expected_md5 ) {
			if ( microtime( true ) > $deadline ) {
				$results['details'][] = 'Time budget reached; remaining files not checked.';
				break;
			}

			++$results['checked'];
			$resolved = GWQSH_Path_Guard::validate( $relative, false );
			if ( ! $resolved ) { ++$results['failed']; continue; }
			$file = $resolved['canonical'];
			if ( ! file_exists( $file ) ) {
				++$results['missing'];
				if ( count( $results['details'] ) < 50 ) {
					$results['details'][] = 'Missing: ' . $relative;
				}
				continue;
			}

			$actual_md5 = md5_file( $file );
			if ( $actual_md5 === $expected_md5 ) {
				++$results['verified'];
				continue;
			}

			++$results['modified'];
			if ( count( $results['details'] ) < 50 ) {
				$results['details'][] = 'Modified: ' . $relative . ' (expected ' . substr( $expected_md5, 0, 8 ) . '...)';
			}
		}

		$results['remaining'] = $results['expected'] - $results['checked'];
		$results['state'] = $results['remaining'] ? 'incomplete' : 'complete';
		GWQSH_Activity_Logger::log(
			'Core integrity verification: ' . $results['state'],
			$results['verified'] . ' verified, ' . $results['modified'] . ' modified, ' . $results['missing'] . ' missing',
			'Security'
		);

		$results['note'] = 'Verification only; no files were restored. Use reviewed finding-based trusted restoration with preserved prior bytes. Remaining files require another investigation.';

		return $results;
	}

	/** Never delete evidence without another freshly verified complete backup. */
	public static function delete_backup( $backup_id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) { return new WP_Error( 'permission', 'Administrative permission required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir );
		if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup operation is running.' ); }
		try {
			$history = (array) get_option( 'gwqsh_backup_history', array() );
			if ( ! isset( $history[ $backup_id ] ) || ! preg_match( '/^[a-f0-9]{32}$/D', $backup_id ) ) { return new WP_Error( 'missing', 'Backup not found.' ); }
			$referenced = self::restore_reference( $backup_id, $dir ); if ( is_wp_error( $referenced ) ) { return $referenced; }
			if ( 'running' === ( $history[ $backup_id ]['state'] ?? '' ) ) { return new WP_Error( 'running', 'Cancel a running backup before deleting its evidence.' ); }
			$replacement = false;
			foreach ( $history as $id => $meta ) {
				if ( $id !== $backup_id && ! empty( $meta['verified'] ) && 2 === ( $meta['format'] ?? 0 ) ) {
					$check = self::verify_backup( $id );
					if ( ! is_wp_error( $check ) && ! empty( $check['complete'] ) ) { $replacement = true; break; }
				}
			}
			if ( ! $replacement ) { return new WP_Error( 'last_backup', 'No other complete authenticated backup exists. Evidence was retained.' ); }
			$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
			// Only exact generated artifact names; legacy files are retained for manual review.
			if ( 2 !== ( $history[ $backup_id ]['format'] ?? 0 ) ) { return new WP_Error( 'legacy', 'Legacy backup completeness is unknown; preserve it for manual review.' ); }
			$files = glob( $dir . '/db-' . $backup_id . '-*.enc' );
			foreach ( $files as $file ) {
				if ( ! GWQSH_Security_Runtime::safe_path( $file, $dir ) || ! wp_delete_file( $file ) && file_exists( $file ) ) { return new WP_Error( 'delete', 'Some backup evidence could not be deleted; history retained.' ); }
			}
			unset( $history[ $backup_id ] ); update_option( 'gwqsh_backup_history', $history, false );
			return true;
		} finally { self::unlock( $lock ); }
	}

	/** Retention uses exactly the same sole-copy protection as manual deletion. */
	public static function enforce_retention( $max_age_days = 30 ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) { return new WP_Error( 'permission', 'Administrative permission required; scheduled retention is not enabled.' ); }
		foreach ( (array) get_option( 'gwqsh_backup_history', array() ) as $id => $meta ) {
			if ( ( $meta['created_at'] ?? 0 ) < time() - max( 1, (int) $max_age_days ) * DAY_IN_SECONDS ) { self::delete_backup( $id ); }
		}
	}
}
