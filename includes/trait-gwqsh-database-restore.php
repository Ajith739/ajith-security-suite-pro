<?php
/** Bounded offline database restore operations for the existing backup service. */
defined( 'ABSPATH' ) || exit;

trait GWQSH_Database_Restore_Operations {
	private static function restore_connection_scope() { return hash( 'sha256', DB_HOST . '|' . DB_NAME . '|' . DB_USER ); }
	private static function restore_fresh_option( $name ) {
		wp_cache_delete( $name, 'options' ); wp_cache_delete( 'alloptions', 'options' ); wp_cache_delete( 'notoptions', 'options' );
		return (array) get_option( $name, array() );
	}
	private static function restore_permission() {
		return defined( 'WP_CLI' ) && WP_CLI && current_user_can( GWQSH_Admin::management_capability() );
	}

	/** Same configured host/credentials; never restore the currently loaded WP DB. */
	private static function restore_connection( $name ) {
		if ( ! is_string( $name ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $name ) || 0 === strcasecmp( $name, DB_NAME ) || in_array( strtolower( $name ), array( 'mysql', 'sys', 'information_schema', 'performance_schema' ), true ) ) { return new WP_Error( 'target', 'Choose a separate, existing recovery database on the configured host.' ); }
		$available = $GLOBALS['wpdb']->get_var( $GLOBALS['wpdb']->prepare( 'SELECT SCHEMA_NAME FROM information_schema.SCHEMATA WHERE SCHEMA_NAME=%s', $name ) );
		if ( ! $available || $GLOBALS['wpdb']->last_error ) { return new WP_Error( 'target', 'The recovery database is unavailable.' ); }
		$db = self::snapshot_connection( $name ); if ( is_wp_error( $db ) ) { return $db; }
		if ( 0 !== strcasecmp( (string) $db->get_var( 'SELECT DATABASE()' ), $name ) ) { $db->close(); return new WP_Error( 'target', 'The recovery database could not be selected.' ); }
		return $db;
	}

	/** Only a native table definition, no executable data, external storage or FK side effects. */
	private static function restore_schema( $schema, $original, $destination, $environment = null ) {
		if ( ! is_string( $schema ) || strlen( $schema ) > self::MAX_ROW || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $original ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $destination ) || ! str_starts_with( $schema, 'CREATE TABLE `' . $original . '` (' ) ) { return new WP_Error( 'schema', 'Invalid or unsupported native table definition.' ); }
		$canonical = self::snapshot_environment_valid( $environment );
		$tokens = ''; $length = strlen( $schema );
		for ( $i = 0; $i < $length; ++$i ) {
			$char = $schema[ $i ];
			if ( in_array( $char, array( "'", '"', '`' ), true ) ) {
				$quote = $char; $closed = false;
				while ( ++$i < $length ) {
					if ( '\\' === $schema[ $i ] ) {
						if ( ! $canonical || '`' === $quote ) { return new WP_Error( 'unsupported_schema', 'Backslash-dependent schema literals require the canonical snapshot environment.' ); }
						++$i; continue;
					}
					if ( $schema[ $i ] === $quote ) {
						if ( $i + 1 < $length && $schema[ $i + 1 ] === $quote ) { ++$i; continue; }
						$closed = true; break;
					}
				}
				if ( ! $closed ) { return new WP_Error( 'schema', 'Unterminated schema literal.' ); }
				$tokens .= ' Q '; continue;
			}
			if ( ';' === $char || '#' === $char || "\0" === $char || ( $i + 1 < $length && in_array( substr( $schema, $i, 2 ), array( '--', '/*', '*/' ), true ) ) ) { return new WP_Error( 'schema', 'Schema statements/comments are not supported.' ); }
			$tokens .= $char;
		}
		if ( ! preg_match( '/\bENGINE\s*=\s*InnoDB\b/i', $tokens ) || preg_match( '/\b(?:SELECT|LIKE|AS|CHECK|REFERENCES|FOREIGN|PARTITION|GENERATED|DIRECTORY|TABLESPACE|CONNECTION|UNION|TEMPORARY|VERSIONING)\b/i', $tokens ) || ( ! $canonical && preg_match( '/\bTIMESTAMP\b/i', $tokens ) ) ) { return new WP_Error( 'unsupported_schema', 'Unsupported table feature or unmarked legacy TIMESTAMP semantics; additional validated recovery support is required.' ); }
		return 'CREATE TABLE `' . $destination . '`' . substr( $schema, strlen( 'CREATE TABLE `' . $original . '`' ) );
	}

	private static function restore_inventory( $db ) {
		$rows = $db->get_results( 'SELECT TABLE_NAME AS name,TABLE_TYPE AS type FROM information_schema.TABLES WHERE TABLE_SCHEMA=DATABASE() ORDER BY TABLE_NAME LIMIT 2001', ARRAY_A );
		if ( $db->last_error || ! is_array( $rows ) || count( $rows ) > 2000 ) { return new WP_Error( 'inventory', 'Recovery database inventory failed or exceeds its budget.' ); }
		$names = array();
		foreach ( $rows as $row ) {
			if ( 'BASE TABLE' !== $row['type'] || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $row['name'] ) ) { return new WP_Error( 'unsupported_schema', 'Recovery target contains unsupported objects; nothing was replaced.' ); }
			$names[] = $row['name'];
		}
		$triggers = $db->get_var( 'SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA=DATABASE()' );
		if ( $db->last_error || null === $triggers || (int) $triggers ) { return new WP_Error( 'unsupported_schema', 'Recovery target trigger inventory is unavailable or nonempty.' ); }
		return $names;
	}

	private static function restore_export_state( $id, array $names ) {
		return array( 'schema' => 2, 'id' => $id, 'blog_id' => get_current_blog_id(), 'context' => 'pre-restore-recovery-point', 'created_at' => time(), 'state' => 'running', 'reason' => '', 'tables' => array_fill_keys( $names, array() ), 'cursor' => 0, 'rows' => 0, 'bytes' => 0, 'chunks' => array(), 'coverage' => array( 'scope' => 'database' ), 'environment' => self::snapshot_environment(), 'consistency' => 'Validated against a read-only preview and rechecked under exclusive locks before activation.' );
	}

	/** Read with the same bounded exporter; no target or artifact writes during dry run. */
	private static function restore_fingerprint( $db, array $mapping ) {
		$state = self::restore_export_state( str_repeat( '0', 32 ), array_values( $mapping ) );
		$deadline = microtime( true ) + 15;
		while ( $state['cursor'] < count( $mapping ) ) {
			if ( microtime( true ) > $deadline ) { return new WP_Error( 'budget', 'Recovery verification budget exceeded; no activation was authorized.' ); }
			$result = self::batch( $state, '', $db, true );
			if ( is_wp_error( $result ) ) { return $result; }
		}
		$out = array();
		foreach ( $mapping as $original => $physical ) {
			$info = $state['tables'][ $physical ];
			$schema = self::restore_schema( $info['schema'], $physical, $original, $state['environment'] );
			if ( is_wp_error( $schema ) ) { return $schema; }
			$digests = array();
			foreach ( $state['chunks'] as $chunk ) { if ( $chunk['table'] === $physical ) { $digests[] = $chunk['content_digest']; } }
			$out[ $original ] = array( 'schema' => $schema, 'rows' => $info['rows'], 'digests' => $digests );
		}
		ksort( $out ); return $out;
	}

	private static function restore_source( $backup_id, $dir ) {
		$check = self::verify_backup( $backup_id );
		if ( is_wp_error( $check ) ) { return $check; }
		if ( empty( $check['complete'] ) ) { return new WP_Error( 'incomplete', 'Only a complete authenticated export can be restored.' ); }
		$source = self::read( $dir . '/db-' . $backup_id . '-manifest.enc', $dir );
		if ( is_wp_error( $source ) ) { return $source; }
		if ( ! $source['tables'] || count( $source['tables'] ) > 2000 ) { return new WP_Error( 'schema', 'Source table inventory is empty or exceeds its budget.' ); }
		$expected = array();
		foreach ( $source['tables'] as $table => $info ) {
			$schema = self::restore_schema( $info['schema'], $table, $table, $source['environment'] ?? null );
			if ( is_wp_error( $schema ) ) { return $schema; }
			if ( ! is_array( $info['columns'] ) || ! $info['columns'] || count( $info['columns'] ) > 1024 || ! is_array( $info['keys'] ?? null ) || array_diff( $info['keys'], $info['columns'] ) ) { return new WP_Error( 'schema', 'Column/key coverage is unsupported.' ); }
			foreach ( $info['columns'] as $column ) { if ( ! is_string( $column ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $column ) ) { return new WP_Error( 'schema', 'Column identifier is unsupported.' ); } }
			$expected[ $table ] = array( 'schema' => $schema, 'rows' => $info['rows'], 'digests' => array() );
		}
		foreach ( $source['chunks'] as $chunk ) {
			$data = self::read( $dir . '/' . $chunk['file'], $dir );
			if ( is_wp_error( $data ) ) { return $data; }
			if ( ! is_array( $data['rows'] ) || count( $data['rows'] ) > self::BATCH ) { return new WP_Error( 'chunk', 'Unsupported row batch.' ); }
			foreach ( $data['rows'] as $row ) {
				if ( ! is_array( $row ) || array_keys( $row ) !== $source['tables'][ $data['table'] ]['columns'] ) { return new WP_Error( 'chunk', 'Chunk column coverage differs from the table manifest.' ); }
				$bytes = 0;
				foreach ( $row as $value ) {
					if ( null === $value ) { continue; }
					if ( ! is_string( $value ) || false === ( $decoded = base64_decode( $value, true ) ) || base64_encode( $decoded ) !== $value ) { return new WP_Error( 'chunk', 'Invalid binary cell encoding.' ); }
					$bytes += strlen( $decoded );
				}
				if ( $bytes > self::MAX_ROW ) { return new WP_Error( 'budget', 'Restore row budget exceeded.' ); }
			}
			$expected[ $data['table'] ]['digests'][] = hash( 'sha256', wp_json_encode( $data['rows'] ) );
		}
		ksort( $expected );
		return array( 'manifest' => $source, 'expected' => $expected, 'hash' => hash( 'sha256', wp_json_encode( $source ) ) );
	}

	/** Table/schema/content diff; no target SQL writes and no activation. */
	public static function preview_database_restore( $backup_id, $target_database ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$db = self::restore_connection( $target_database ); if ( is_wp_error( $db ) ) { return $db; }
		try {
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$source = self::restore_source( $backup_id, $dir ); if ( is_wp_error( $source ) ) { return $source; }
		$names = self::restore_inventory( $db ); if ( is_wp_error( $names ) ) { return $names; }
		$mapping = $names ? array_combine( $names, $names ) : array();
		$before = self::restore_fingerprint( $db, $mapping ); if ( is_wp_error( $before ) ) { return $before; }
		$tables = array();
		foreach ( $source['expected'] as $table => $expected ) { $tables[ $table ] = array( 'before' => $before[ $table ] ?? null, 'after' => $expected ); }
		$plan = array( 'backup_id' => $backup_id, 'source_hash' => $source['hash'], 'snapshot_environment' => $source['manifest']['environment'] ?? null, 'connection_scope' => self::restore_connection_scope(), 'target_database' => $target_database, 'tables' => $tables, 'target_before' => $before, 'preserved_extra_tables' => array_values( array_diff( $names, array_keys( $tables ) ) ), 'confirmation' => 'RESTORE:' . $target_database, 'limitations' => array( 'Separate offline recovery database only; no URL/prefix/serialized-data rewriting.', 'Table-only format; triggers/routines/events are not restored.', $source['manifest']['consistency'] ) );
		$plan['plan_hash'] = hash( 'sha256', wp_json_encode( $plan ) );
		return $plan;
		} finally { $db->close(); }
	}

	private static function restore_save( array $job, $dir ) {
		if ( ! self::write( $dir . '/restore-' . $job['id'] . '.enc', $job ) ) { return new WP_Error( 'checkpoint', 'Restore checkpoint persistence failed; data and recovery evidence were retained.' ); }
		$ledger = self::restore_fresh_option( self::RESTORES );
		$ledger[ $job['id'] ] = array_intersect_key( $job, array_flip( array( 'id', 'backup_id', 'recovery_id', 'connection_scope', 'target_database', 'phase', 'created_at' ) ) );
		update_option( self::RESTORES, $ledger, false );
		if ( get_option( self::RESTORES ) !== $ledger ) { return new WP_Error( 'checkpoint', 'Restore ledger persistence failed; authenticated checkpoint retained.' ); }
		return $job;
	}

	private static function restore_job( $id, $dir ) {
		if ( ! is_string( $id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $id ) ) { return new WP_Error( 'id', 'Invalid restore identifier.' ); }
		$job = self::read( $dir . '/restore-' . $id . '.enc', $dir );
		if ( is_wp_error( $job ) ) { return $job; }
		if ( ( $job['id'] ?? '' ) !== $id || ( $job['blog_id'] ?? 0 ) !== get_current_blog_id() || 1 !== ( $job['restore_schema'] ?? 0 ) ) { return new WP_Error( 'scope', 'Restore checkpoint scope is invalid.' ); }
		if ( ( $job['connection_scope'] ?? '' ) !== self::restore_connection_scope() ) { return new WP_Error( 'scope', 'Configured database host/user changed; review a new restore plan.' ); }
		if ( ! is_string( $job['backup_id'] ?? null ) || ! preg_match( '/^[a-f0-9]{32}$/D', $job['backup_id'] ) || ! is_string( $job['recovery_id'] ?? null ) || ! preg_match( '/^[a-f0-9]{32}$/D', $job['recovery_id'] ) || ! is_string( $job['source_hash'] ?? null ) || ! preg_match( '/^[a-f0-9]{64}$/D', $job['source_hash'] ) || ! is_string( $job['target_database'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $job['target_database'] ) || ! is_array( $job['tables'] ?? null ) || ! $job['tables'] || count( $job['tables'] ) > 2000 || ! is_array( $job['target_before'] ?? null ) || count( $job['target_before'] ) > 2000 || ! is_int( $job['cursor'] ?? null ) || $job['cursor'] < 0 || ! is_int( $job['rows'] ?? null ) || $job['rows'] < 0 || ! in_array( $job['phase'] ?? null, array( 'recovery_point', 'schemas', 'import', 'ready', 'activating', 'complete', 'rolling_back', 'rolled_back', 'cancelled' ), true ) ) { return new WP_Error( 'checkpoint', 'Restore checkpoint structure is invalid.' ); }
		$index = 0;
		foreach ( $job['tables'] as $table => $item ) {
			if ( ! is_string( $table ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $table ) || ! is_array( $item ) || ( $item['stage'] ?? '' ) !== 'gwqsh_stage_' . $id . '_' . $index || ( $item['prior'] ?? '' ) !== 'gwqsh_prior_' . $id . '_' . $index || ( $item['after'] ?? '' ) !== 'gwqsh_after_' . $id . '_' . $index ) { return new WP_Error( 'checkpoint', 'Restore table mapping is invalid.' ); }
			++$index;
		}
		foreach ( $job['target_before'] as $table => $value ) { if ( ! is_string( $table ) || ! preg_match( '/^[A-Za-z0-9_]{1,64}$/D', $table ) || ! is_array( $value ) ) { return new WP_Error( 'checkpoint', 'Recovery-point mapping is invalid.' ); } }
		return $job;
	}

	/** Explicit confirmation binds the full reviewed target-content fingerprint. */
	public static function begin_database_restore( $backup_id, $target_database, $plan_hash, $confirmation ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		if ( ! is_string( $confirmation ) || $confirmation !== 'RESTORE:' . $target_database ) { return new WP_Error( 'confirmation', 'Confirm the exact recovery database after reviewing the dry run.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup/restore operation is active.' ); }
		try {
			$plan = self::preview_database_restore( $backup_id, $target_database ); if ( is_wp_error( $plan ) ) { return $plan; }
			if ( ! is_string( $plan_hash ) || ! hash_equals( $plan['plan_hash'], $plan_hash ) ) { return new WP_Error( 'stale_preview', 'The source or target changed; review a fresh dry run.' ); }
			$ledger = self::restore_fresh_option( self::RESTORES );
			if ( count( $ledger ) >= 1000 ) { return new WP_Error( 'capacity', 'Restore evidence ledger is full; archive it through a reviewed workflow.' ); }
			foreach ( $ledger as $existing ) { if ( ( $existing['connection_scope'] ?? '' ) === self::restore_connection_scope() && 0 === strcasecmp( $existing['target_database'], $target_database ) && ! in_array( $existing['phase'], array( 'complete', 'rolled_back', 'cancelled' ), true ) ) { return new WP_Error( 'busy', 'An unfinished restore already owns this recovery database.' ); } }
			$files = glob( $dir . '/restore-*.enc' ); $deadline = microtime( true ) + 5;
			if ( false === $files || count( $files ) >= 1000 ) { return new WP_Error( 'capacity', 'Restore artifact inventory could not be established within its budget.' ); }
			foreach ( $files as $file ) {
				$existing = self::read( $file, $dir );
				if ( microtime( true ) > $deadline || is_wp_error( $existing ) ) { return new WP_Error( 'busy', 'An authenticated restore checkpoint could not be verified; evidence retained.' ); }
				if ( ( $existing['connection_scope'] ?? '' ) === self::restore_connection_scope() && 0 === strcasecmp( $existing['target_database'] ?? '', $target_database ) && ! in_array( $existing['phase'] ?? '', array( 'complete', 'rolled_back', 'cancelled' ), true ) ) { return new WP_Error( 'busy', 'The durable restore intent still owns this recovery database.' ); }
			}
			$id = bin2hex( random_bytes( 16 ) ); $recovery = bin2hex( random_bytes( 16 ) ); $tables = array();
			foreach ( array_keys( $plan['tables'] ) as $index => $table ) { $tables[ $table ] = array( 'stage' => 'gwqsh_stage_' . $id . '_' . $index, 'prior' => 'gwqsh_prior_' . $id . '_' . $index, 'after' => 'gwqsh_after_' . $id . '_' . $index ); }
			$job = array( 'restore_schema' => 1, 'id' => $id, 'blog_id' => get_current_blog_id(), 'actor' => get_current_user_id(), 'created_at' => time(), 'backup_id' => $backup_id, 'source_hash' => $plan['source_hash'], 'connection_scope' => self::restore_connection_scope(), 'target_database' => $target_database, 'target_before' => $plan['target_before'], 'tables' => $tables, 'phase' => 'recovery_point', 'cursor' => 0, 'rows' => 0, 'recovery_id' => $recovery, 'recovery' => self::restore_export_state( $recovery, array_keys( $plan['target_before'] ) ) );
			$result = self::restore_save( $job, $dir );
			if ( ! is_wp_error( $result ) ) { GWQSH_Activity_Logger::log( 'Database restore prepared', 'Reviewed offline recovery job ' . $id . '; target tables preserved pending verified shadow import.', 'Security' ); }
			return $result;
		} finally { self::unlock( $lock ); }
	}

	/** One target-backup batch, one schema, or one transactional import chunk. */
	public static function continue_database_restore( $id ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup/restore operation is active.' ); }
		$db = null;
		try {
			$job = self::restore_job( $id, $dir ); if ( is_wp_error( $job ) ) { return $job; }
			if ( 'cancelled' === $job['phase'] ) { return new WP_Error( 'phase', 'Restore is cancelled and cannot be continued.' ); }
			if ( in_array( $job['phase'], array( 'ready', 'complete', 'rolled_back' ), true ) ) { return $job; }
			$db = self::restore_connection( $job['target_database'] ); if ( is_wp_error( $db ) ) { return $db; }
			$source = self::restore_source( $job['backup_id'], $dir ); if ( is_wp_error( $source ) ) { return $source; }
			if ( ! hash_equals( $job['source_hash'], $source['hash'] ) ) { return new WP_Error( 'drift', 'Restore source changed; no target activation occurred.' ); }
			if ( 'recovery_point' === $job['phase'] ) {
				$pre = &$job['recovery'];
				if ( ! self::write( $dir . '/db-' . $pre['id'] . '-manifest.enc', $pre ) ) { return new WP_Error( 'checkpoint', 'Recovery manifest could not be persisted.' ); }
				$result = self::batch( $pre, $dir, $db ); if ( is_wp_error( $result ) ) { return $result; }
				if ( ! self::write( $dir . '/db-' . $pre['id'] . '-manifest.enc', $pre ) ) { return new WP_Error( 'checkpoint', 'Recovery progress could not be persisted.' ); }
				if ( 'complete' === $pre['state'] ) {
					$verified = self::verify( $pre['id'] ); if ( is_wp_error( $verified ) || empty( $verified['complete'] ) ) { return new WP_Error( 'recovery_point', 'Pre-restore recovery point is not verified.' ); }
					if ( $job['target_before'] ) {
						$point = self::restore_source( $pre['id'], $dir );
						if ( is_wp_error( $point ) || $point['expected'] !== $job['target_before'] ) { return new WP_Error( 'drift', 'Recovery-point bytes differ from the reviewed target; originals were not replaced.' ); }
					}
					$before = self::restore_fingerprint( $db, $job['target_before'] ? array_combine( array_keys( $job['target_before'] ), array_keys( $job['target_before'] ) ) : array() );
					if ( is_wp_error( $before ) || $before !== $job['target_before'] ) { return new WP_Error( 'drift', 'Recovery target changed since preview; no target tables were replaced.' ); }
					$history = self::restore_fresh_option( 'gwqsh_backup_history' );
					$history[ $pre['id'] ] = array( 'id' => $pre['id'], 'type' => 'database', 'format' => 2, 'context' => 'pre-restore-recovery-point', 'created_at' => $pre['created_at'], 'blog_id' => $pre['blog_id'], 'rows' => $pre['rows'], 'size' => $pre['bytes'], 'file' => 'db-' . $pre['id'] . '-manifest.enc', 'encrypted' => true, 'verified' => true, 'state' => 'complete', 'coverage' => $pre['coverage'], 'target_database' => $job['target_database'], 'restore_job' => $id );
					update_option( 'gwqsh_backup_history', $history, false );
					if ( get_option( 'gwqsh_backup_history' ) !== $history ) { return new WP_Error( 'checkpoint', 'Recovery-point history was not persisted.' ); }
					$job['phase'] = 'schemas'; $job['cursor'] = 0;
				}
			} elseif ( 'schemas' === $job['phase'] ) {
				$names = array_keys( $job['tables'] );
				if ( $job['cursor'] >= count( $names ) ) { $job['phase'] = 'import'; $job['cursor'] = 0; }
				else {
					$table = $names[ $job['cursor'] ]; $stage = $job['tables'][ $table ]['stage'];
					$schema = self::restore_schema( $source['manifest']['tables'][ $table ]['schema'], $table, $stage, $source['manifest']['environment'] ?? null );
					if ( is_wp_error( $schema ) ) { return $schema; }
					$existing = $db->get_row( "SHOW CREATE TABLE `{$stage}`", ARRAY_N );
					if ( $existing ) {
						if ( $existing[1] !== $schema || '0' !== (string) $db->get_var( "SELECT COUNT(*) FROM `{$stage}`" ) ) { return new WP_Error( 'collision', 'Shadow table is not the expected empty schema; evidence retained.' ); }
					} elseif ( false === $db->query( $schema ) ) { return new WP_Error( 'schema', 'Shadow schema creation failed; target tables are unchanged.' ); }
					++$job['cursor'];
				}
			} elseif ( 'import' === $job['phase'] ) {
				if ( $job['cursor'] >= count( $source['manifest']['chunks'] ) ) {
					$mapping = array_map( static function ( $item ) { return $item['stage']; }, $job['tables'] );
					$actual = self::restore_fingerprint( $db, $mapping );
					if ( is_wp_error( $actual ) || $actual !== $source['expected'] ) { return new WP_Error( 'verification', 'Imported schema/rows/bytes differ; activation prohibited.' ); }
					$job['phase'] = 'ready';
				} else {
					$chunk = $source['manifest']['chunks'][ $job['cursor'] ];
					$data = self::read( $dir . '/' . $chunk['file'], $dir ); if ( is_wp_error( $data ) ) { return $data; }
					$result = self::restore_insert_chunk( $db, $job, $source['manifest'], $data ); if ( is_wp_error( $result ) ) { return $result; }
					$job['rows'] += count( $data['rows'] ); ++$job['cursor'];
				}
			} else { return new WP_Error( 'phase', 'Restore phase requires explicit verification/recovery; no automatic mutation occurred.' ); }
			return self::restore_save( $job, $dir );
		} finally { if ( $db instanceof wpdb ) { $db->close(); } self::unlock( $lock ); }
	}

	/** Retrying a committed but uncheckpointed chunk must verify exact existing bytes. */
	private static function restore_insert_chunk( $db, array $job, array $source, array $chunk ) {
		$table = $chunk['table']; $stage = $job['tables'][ $table ]['stage']; $info = $source['tables'][ $table ];
		if ( false === $db->query( 'START TRANSACTION' ) ) { return new WP_Error( 'transaction', 'Import transaction unavailable.' ); }
		try {
			if ( ! empty( $info['keys'] ) ) {
				foreach ( $chunk['rows'] as $row ) {
					$where = array();
					foreach ( $info['keys'] as $key ) { $where[] = $db->prepare( 'BINARY `' . $key . '`=UNHEX(%s)', bin2hex( base64_decode( $row[ $key ], true ) ) ); }
					$existing = $db->get_row( "SELECT * FROM `{$stage}` WHERE " . implode( ' AND ', $where ), ARRAY_A );
					if ( $db->last_error ) { return new WP_Error( 'query', 'Shadow-row verification query failed.' ); }
					if ( $existing ) {
						$encoded = array_map( static function ( $value ) { return null === $value ? null : base64_encode( $value ); }, $existing );
						if ( $encoded !== $row ) { return new WP_Error( 'collision', 'Existing shadow row differs; no replacement or deletion was performed.' ); }
						continue;
					}
					$values = array();
					foreach ( $row as $value ) { $values[] = null === $value ? 'NULL' : $db->prepare( 'UNHEX(%s)', bin2hex( base64_decode( $value, true ) ) ); }
					$columns = '`' . implode( '`,`', $info['columns'] ) . '`';
					if ( 1 !== $db->query( "INSERT INTO `{$stage}` ({$columns}) VALUES (" . implode( ',', $values ) . ')' ) ) { return new WP_Error( 'insert', 'Shadow import failed; original target data remains unchanged.' ); }
				}
			} else {
				$prior_rows = 0;
				for ( $i = 0; $i < $job['cursor']; ++$i ) {
					if ( ( $source['chunks'][ $i ]['table'] ?? '' ) === $table ) {
						$prior_rows += (int) ( $source['chunks'][ $i ]['rows'] ?? 0 );
					}
				}
				$stage_count = $db->get_var( "SELECT COUNT(*) FROM `{$stage}`" );
				if ( $db->last_error || null === $stage_count ) { return new WP_Error( 'query', 'Shadow count query failed.' ); }
				$current_count = (int) $stage_count;
				if ( $current_count === $prior_rows + count( $chunk['rows'] ) ) {
					// Chunk already committed in previous run before checkpoint save.
				} elseif ( $current_count === $prior_rows ) {
					foreach ( $chunk['rows'] as $row ) {
						$values = array();
						foreach ( $row as $value ) { $values[] = null === $value ? 'NULL' : $db->prepare( 'UNHEX(%s)', bin2hex( base64_decode( $value, true ) ) ); }
						$columns = '`' . implode( '`,`', $info['columns'] ) . '`';
						if ( 1 !== $db->query( "INSERT INTO `{$stage}` ({$columns}) VALUES (" . implode( ',', $values ) . ')' ) ) { return new WP_Error( 'insert', 'Shadow import failed; original target data remains unchanged.' ); }
					}
				} else {
					return new WP_Error( 'collision', 'Shadow table row count mismatch during keyless chunk insertion; no replacement or deletion was performed.' );
				}
			}
			if ( false === $db->query( 'COMMIT' ) ) { return new WP_Error( 'transaction', 'Import commit was not confirmed; retry verifies exact rows.' ); }
			return true;
		} finally { $db->query( 'ROLLBACK' ); }
	}

	public static function verify_database_restore( $id ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$job = self::restore_job( $id, $dir ); if ( is_wp_error( $job ) ) { return $job; }
		if ( ! in_array( $job['phase'], array( 'ready', 'complete' ), true ) ) { return new WP_Error( 'phase', 'Restore is not ready for complete-data verification.' ); }
		$db = self::restore_connection( $job['target_database'] ); if ( is_wp_error( $db ) ) { return $db; }
		try {
		$source = self::restore_source( $job['backup_id'], $dir ); if ( is_wp_error( $source ) ) { return $source; }
		if ( ! hash_equals( $job['source_hash'], $source['hash'] ) ) { return new WP_Error( 'drift', 'Source manifest changed.' ); }
		$mapping = array(); foreach ( $job['tables'] as $table => $item ) { $mapping[ $table ] = 'complete' === $job['phase'] ? $table : $item['stage']; }
		$actual = self::restore_fingerprint( $db, $mapping );
		if ( is_wp_error( $actual ) || $actual !== $source['expected'] ) { return new WP_Error( 'drift', 'Restored data/schema verification failed.' ); }
		if ( 'ready' === $job['phase'] ) {
			$names = array_keys( $job['target_before'] );
			$before = self::restore_fingerprint( $db, $names ? array_combine( $names, $names ) : array() );
			if ( is_wp_error( $before ) || $before !== $job['target_before'] ) { return new WP_Error( 'drift', 'Original target changed after the recovery point; activation prohibited.' ); }
		}
		return array( 'id' => $id, 'verified' => true, 'phase' => $job['phase'], 'target_database' => $job['target_database'], 'rows' => $job['rows'] );
		} finally { $db->close(); }
	}

	/** Crash-atomic metadata cutover is a capability requirement, not an assumption. */
	private static function restore_atomic_server( $db ) {
		$version = $db->get_var( 'SELECT VERSION()' );
		if ( ! is_string( $version ) || ! preg_match( '/^(\d+\.\d+\.\d+)/', $version, $match ) ) { return new WP_Error( 'unsupported_server', 'The recovery server atomic-DDL capability is unknown.' ); }
		$minimum = false !== stripos( $version, 'MariaDB' ) ? '10.6.1' : '8.0.0';
		return version_compare( $match[1], $minimum, '>=' ) ? $version : new WP_Error( 'unsupported_server', 'Activation requires crash-atomic InnoDB rename support: MySQL 8.0+ or MariaDB 10.6.1+. Verified shadows and originals are retained.' );
	}

	private static function restore_reference( $backup_id, $dir ) {
		$files = glob( $dir . '/restore-*.enc' );
		if ( false === $files || count( $files ) > 1000 ) { return new WP_Error( 'restore_reference', 'Restore evidence inventory could not be verified; backup retained.' ); }
		$deadline = microtime( true ) + 5;
		foreach ( $files as $file ) {
			if ( microtime( true ) > $deadline ) { return new WP_Error( 'restore_reference', 'Restore-reference verification exceeded its budget; backup retained.' ); }
			$job = self::read( $file, $dir );
			if ( is_wp_error( $job ) || 1 !== ( $job['restore_schema'] ?? 0 ) || ! is_string( $job['backup_id'] ?? null ) || ! is_string( $job['recovery_id'] ?? null ) || $job['backup_id'] === $backup_id || $job['recovery_id'] === $backup_id ) { return new WP_Error( 'restore_reference', 'Backup is referenced by restore evidence or that evidence is unverifiable; retained.' ); }
		}
		return true;
	}

	/** Activate/rollback only after exclusive verification; never DROP, DELETE or TRUNCATE. */
	private static function restore_cutover( $id, $confirmation, $rollback ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup/restore operation is active.' ); }
		$db = null;
		try {
			$job = self::restore_job( $id, $dir ); if ( is_wp_error( $job ) ) { return $job; }
			$word = $rollback ? 'ROLLBACK_OFFLINE:' : 'ACTIVATE_OFFLINE:';
			if ( ! is_string( $confirmation ) || $confirmation !== $word . $job['target_database'] . ':' . $id ) { return new WP_Error( 'confirmation', 'Confirm the exact offline target and restore identifier.' ); }
			$allowed = $rollback ? array( 'complete', 'rolling_back' ) : array( 'ready', 'activating' );
			if ( ! in_array( $job['phase'], $allowed, true ) ) { return new WP_Error( 'phase', 'Restore is not in an activatable/rollback phase.' ); }
			$db = self::restore_connection( $job['target_database'] ); if ( is_wp_error( $db ) ) { return $db; }
			$server = self::restore_atomic_server( $db ); if ( is_wp_error( $server ) ) { return $server; }
			// This adapter restores a separate, operator-confirmed offline database.
			// Refuse other visible target sessions rather than silently replacing an
			// active application's tables. DBA/other-user activity must be stopped too.
			$others = $db->get_var( $db->prepare( 'SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB=%s AND ID<>CONNECTION_ID()', $job['target_database'] ) );
			if ( $db->last_error || null === $others || (int) $others > 0 ) { return new WP_Error( 'offline_target', 'Close all other recovery-database sessions and keep applications/DBA writers offline throughout cutover.' ); }
			$source = self::restore_source( $job['backup_id'], $dir ); if ( is_wp_error( $source ) ) { return $source; }
			if ( ! hash_equals( $job['source_hash'], $source['hash'] ) ) { return new WP_Error( 'drift', 'Restore source changed.' ); }
			$names = self::restore_inventory( $db ); if ( is_wp_error( $names ) ) { return $names; }
			$locks = array_map( static function ( $name ) { return '`' . $name . '` WRITE'; }, $names );
			if ( ! $locks || false === $db->query( 'LOCK TABLES ' . implode( ',', $locks ) ) ) { return new WP_Error( 'locking', 'Exclusive target verification locks are unavailable; nothing was replaced.' ); }
			try {
				$originals = array(); $stages = array(); $prior = array(); $after = array();
				foreach ( $job['tables'] as $table => $item ) { $originals[ $table ] = $table; $stages[ $table ] = $item['stage']; $after[ $table ] = $item['after']; }
				foreach ( $job['target_before'] as $table => $value ) { $prior[ $table ] = isset( $job['tables'][ $table ] ) ? $job['tables'][ $table ]['prior'] : $table; }
				$before_map = $job['target_before'] ? array_combine( array_keys( $job['target_before'] ), array_keys( $job['target_before'] ) ) : array();
				$pre_layout = array_merge( array_keys( $job['target_before'] ), array_values( $stages ) );
				$post_layout = array_values( array_unique( array_merge( array_values( $prior ), array_values( $originals ) ) ) );
				$rolled_layout = array_merge( array_keys( $job['target_before'] ), array_values( $after ) );
				$expected_layout = $rollback ? $post_layout : $pre_layout;
				$done_layout = $rollback ? $rolled_layout : $post_layout;
				sort( $names ); sort( $expected_layout ); sort( $done_layout );
				$intent = $rollback ? 'rolling_back' : 'activating';
				$already_done = $job['phase'] === $intent && $names === $done_layout;
				if ( ! $already_done && $names !== $expected_layout ) { return new WP_Error( 'drift', 'Target layout changed or cutover state is ambiguous; all evidence retained for reviewed recovery.' ); }
				$source_map = $rollback ? ( $already_done ? $after : $originals ) : ( $already_done ? $originals : $stages );
				$target_map = $rollback ? ( $already_done ? $before_map : $prior ) : ( $already_done ? $prior : $before_map );
				$actual = self::restore_fingerprint( $db, $source_map );
				$point = self::restore_fingerprint( $db, $target_map );
				if ( is_wp_error( $actual ) || $actual !== $source['expected'] || is_wp_error( $point ) || $point !== $job['target_before'] ) { return new WP_Error( 'drift', 'Source shadows/current data or preserved recovery bytes changed; no cutover authorized.' ); }
				if ( ! $already_done ) {
					$job['phase'] = $intent; $job['server'] = $server;
					$saved = self::restore_save( $job, $dir ); if ( is_wp_error( $saved ) ) { return $saved; }
					$renames = array();
					foreach ( $job['tables'] as $table => $item ) {
						if ( $rollback ) {
							$renames[] = '`' . $table . '` TO `' . $item['after'] . '`';
							if ( isset( $job['target_before'][ $table ] ) ) { $renames[] = '`' . $item['prior'] . '` TO `' . $table . '`'; }
						} else {
							if ( isset( $job['target_before'][ $table ] ) ) { $renames[] = '`' . $table . '` TO `' . $item['prior'] . '`'; }
							$renames[] = '`' . $item['stage'] . '` TO `' . $table . '`';
						}
					}
					// MariaDB disallows RENAME while LOCK TABLES is active. Its separate
					// offline-target contract is essential across this lock handoff.
					// Atomic RENAME preserves every old table; after reacquiring locks,
					// any conflicting change fails verification and retains both versions.
					$mariadb = false !== stripos( $server, 'MariaDB' );
					if ( $mariadb && false === $db->query( 'UNLOCK TABLES' ) ) { return new WP_Error( 'locking', 'Verification locks could not be released for offline cutover.' ); }
					if ( false === $db->query( 'RENAME TABLE ' . implode( ',', $renames ) ) ) { return new WP_Error( 'cutover', 'Cutover was not confirmed; resume verifies the durable intent and exact table layout.' ); }
					if ( $mariadb ) {
						$final_locks = array_map( static function ( $name ) { return '`' . $name . '` WRITE'; }, $done_layout );
						if ( false === $db->query( 'LOCK TABLES ' . implode( ',', $final_locks ) ) ) { return new WP_Error( 'locking', 'Post-cutover locks unavailable; durable intent and both data versions retained.' ); }
					}
				}
				$verify_source = self::restore_fingerprint( $db, $rollback ? $after : $originals );
				$verify_point = self::restore_fingerprint( $db, $rollback ? $before_map : $prior );
				if ( is_wp_error( $verify_source ) || $verify_source !== $source['expected'] || is_wp_error( $verify_point ) || $verify_point !== $job['target_before'] ) { return new WP_Error( 'verification', 'Post-cutover verification failed; recovery point and durable intent retained.' ); }
				$job['phase'] = $rollback ? 'rolled_back' : 'complete'; $job['verified_at'] = time();
				$result = self::restore_save( $job, $dir );
			} finally { $db->query( 'UNLOCK TABLES' ); }
			if ( ! is_wp_error( $result ) ) { GWQSH_Activity_Logger::log( $rollback ? 'Database restore rolled back' : 'Database restore activated', 'Verified offline recovery job ' . $id . '; prior and replacement bytes retained.', 'Security' ); }
			return $result;
		} finally { if ( $db instanceof wpdb ) { $db->close(); } self::unlock( $lock ); }
	}

	public static function activate_database_restore( $id, $confirmation ) { return self::restore_cutover( $id, $confirmation, false ); }
	public static function rollback_database_restore( $id, $confirmation ) { return self::restore_cutover( $id, $confirmation, true ); }

	/** Non-destructive cancellation: transitions in-flight restore to cancelled, preserving all files and recovery data. */
	public static function cancel_database_restore( $id, $confirmation ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup/restore operation is active.' ); }
		try {
			$job = self::restore_job( $id, $dir ); if ( is_wp_error( $job ) ) { return $job; }
			if ( 'cancelled' === $job['phase'] ) { return $job; }
			if ( in_array( $job['phase'], array( 'complete', 'rolled_back' ), true ) ) {
				return new WP_Error( 'phase', 'Completed or rolled-back restores cannot be cancelled; review rollback or archival instead.' );
			}
			if ( in_array( $job['phase'], array( 'activating', 'rolling_back' ), true ) ) {
				return new WP_Error( 'phase', 'Restore is actively in cutover/rollback; complete or recover the cutover state first.' );
			}
			$expected_confirmation = 'CANCEL_RESTORE:' . $job['target_database'] . ':' . $id;
			if ( ! is_string( $confirmation ) || $confirmation !== $expected_confirmation ) {
				return new WP_Error( 'confirmation', 'Confirm the exact recovery database and restore identifier to cancel.' );
			}
			$job['phase'] = 'cancelled';
			$job['cancelled_at'] = time();
			$job['cancelled_by'] = get_current_user_id();
			$saved = self::restore_save( $job, $dir );
			if ( ! is_wp_error( $saved ) ) {
				GWQSH_Activity_Logger::log( 'Database restore cancelled', 'Offline recovery job ' . $id . ' cancelled; artifacts, recovery point and shadow tables retained.', 'Security' );
			}
			return $saved;
		} finally { self::unlock( $lock ); }
	}

	/** Explicitly drop orphaned shadow staging tables for a cancelled restore job. Never touches live, prior or after tables. */
	public static function abandon_database_restore_shadows( $id, $confirmation ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup/restore operation is active.' ); }
		$db = null;
		try {
			$job = self::restore_job( $id, $dir ); if ( is_wp_error( $job ) ) { return $job; }
			if ( 'cancelled' !== $job['phase'] ) {
				return new WP_Error( 'phase', 'Only cancelled restore jobs can have their shadow tables abandoned; cancel the job first.' );
			}
			$expected_confirmation = 'ABANDON_SHADOWS:' . $job['target_database'] . ':' . $id;
			if ( ! is_string( $confirmation ) || $confirmation !== $expected_confirmation ) {
				return new WP_Error( 'confirmation', 'Confirm the exact recovery database and restore identifier to abandon shadow tables.' );
			}
			$db = self::restore_connection( $job['target_database'] ); if ( is_wp_error( $db ) ) { return $db; }
			$others = $db->get_var( $db->prepare( 'SELECT COUNT(*) FROM information_schema.PROCESSLIST WHERE DB=%s AND ID<>CONNECTION_ID()', $job['target_database'] ) );
			if ( $db->last_error || null === $others || (int) $others > 0 ) { return new WP_Error( 'offline_target', 'Close all other recovery-database sessions before modifying shadow tables.' ); }
			$dropped = array();
			foreach ( $job['tables'] as $table => $item ) {
				$stage = $item['stage'];
				if ( ! preg_match( '/^gwqsh_stage_' . preg_quote( $id, '/' ) . '_\d+$/D', $stage ) ) {
					return new WP_Error( 'checkpoint', 'Unrecognized shadow table identifier format; abandonment aborted.' );
				}
				$exists = $db->get_var( $db->prepare( 'SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA=%s AND TABLE_NAME=%s', $job['target_database'], $stage ) );
				if ( $exists === $stage ) {
					if ( false === $db->query( "DROP TABLE `{$stage}`" ) ) {
						return new WP_Error( 'cleanup', 'Failed to drop shadow table ' . $stage . '; partial state retained.' );
					}
					$dropped[] = $stage;
				}
			}
			$job['shadows_abandoned'] = true;
			$job['shadows_abandoned_at'] = time();
			$job['shadows_abandoned_count'] = count( $dropped );
			$saved = self::restore_save( $job, $dir );
			if ( ! is_wp_error( $saved ) ) {
				GWQSH_Activity_Logger::log( 'Database restore shadows abandoned', 'Dropped ' . count( $dropped ) . ' orphaned shadow tables for cancelled job ' . $id . '; recovery point and journal retained.', 'Security' );
			}
			return array(
				'id' => $id,
				'target_database' => $job['target_database'],
				'dropped_tables' => $dropped,
				'shadows_abandoned' => true,
			);
		} finally { if ( $db instanceof wpdb ) { $db->close(); } self::unlock( $lock ); }
	}

	/** Archives completed, rolled-back or cancelled restore records from active ledger to an encrypted file. */
	public static function archive_database_restore_ledger( $confirmation ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		if ( ! is_string( $confirmation ) || 'ARCHIVE_RESTORE_LEDGER' !== $confirmation ) {
			return new WP_Error( 'confirmation', 'Provide exact confirmation string ARCHIVE_RESTORE_LEDGER.' );
		}
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$lock = self::lock( $dir ); if ( ! $lock ) { return new WP_Error( 'busy', 'Another backup/restore operation is active.' ); }
		try {
			$ledger = self::restore_fresh_option( self::RESTORES );
			if ( empty( $ledger ) ) {
				return array( 'archived_count' => 0, 'remaining_count' => 0, 'message' => 'Restore ledger is empty.' );
			}
			$terminal_phases = array( 'complete', 'rolled_back', 'cancelled' );
			$to_archive = array();
			$remaining = array();
			foreach ( $ledger as $id => $entry ) {
				if ( in_array( $entry['phase'] ?? '', $terminal_phases, true ) ) {
					$to_archive[ $id ] = $entry;
				} else {
					$remaining[ $id ] = $entry;
				}
			}
			if ( empty( $to_archive ) ) {
				return array( 'archived_count' => 0, 'remaining_count' => count( $remaining ), 'message' => 'No completed, rolled-back or cancelled restore records to archive.' );
			}
			$archive_id = bin2hex( random_bytes( 16 ) );
			$archive_file = $dir . '/archive-restores-' . $archive_id . '.enc';
			$payload = array(
				'archive_id' => $archive_id,
				'created_at' => time(),
				'archived_by' => get_current_user_id(),
				'count' => count( $to_archive ),
				'entries' => $to_archive,
			);
			if ( ! self::write( $archive_file, $payload ) ) {
				return new WP_Error( 'checkpoint', 'Failed to write encrypted restore ledger archive.' );
			}
			$history = self::restore_fresh_option( 'gwqsh_restore_ledger_archives' );
			$history[ $archive_id ] = array(
				'id' => $archive_id,
				'file' => basename( $archive_file ),
				'count' => count( $to_archive ),
				'created_at' => $payload['created_at'],
			);
			update_option( 'gwqsh_restore_ledger_archives', $history, false );
			update_option( self::RESTORES, $remaining, false );
			if ( get_option( self::RESTORES ) !== $remaining ) {
				return new WP_Error( 'checkpoint', 'Active restore ledger update could not be verified; archive retained.' );
			}
			GWQSH_Activity_Logger::log( 'Database restore ledger archived', 'Archived ' . count( $to_archive ) . ' restore records to ' . basename( $archive_file ) . '; ' . count( $remaining ) . ' active records retained.', 'Security' );
			return array(
				'archive_id' => $archive_id,
				'file' => basename( $archive_file ),
				'archived_count' => count( $to_archive ),
				'remaining_count' => count( $remaining ),
			);
		} finally { self::unlock( $lock ); }
	}

	public static function database_restore_status( $id ) {
		if ( ! self::restore_permission() ) { return new WP_Error( 'permission', 'Offline WP-CLI and a security administrator are required.' ); }
		$dir = self::backup_dir(); if ( is_wp_error( $dir ) ) { return $dir; }
		$job = self::restore_job( $id, $dir ); if ( is_wp_error( $job ) ) { return $job; }
		$db = self::restore_connection( $job['target_database'] );
		if ( ! is_wp_error( $db ) ) {
			try {
				$names = self::restore_inventory( $db );
				if ( is_array( $names ) ) {
					$stages = array(); $priors = array(); $afters = array();
					foreach ( $job['tables'] as $item ) {
						if ( in_array( $item['stage'], $names, true ) ) { $stages[] = $item['stage']; }
						if ( in_array( $item['prior'], $names, true ) ) { $priors[] = $item['prior']; }
						if ( in_array( $item['after'], $names, true ) ) { $afters[] = $item['after']; }
					}
					$layout_state = 'clean';
					if ( ! empty( $stages ) ) { $layout_state = 'staging_present'; }
					if ( ! empty( $priors ) ) { $layout_state = 'priors_present'; }
					if ( ! empty( $afters ) ) { $layout_state = 'afters_present'; }
					$job['layout'] = array(
						'state' => $layout_state,
						'stages' => $stages,
						'priors' => $priors,
						'afters' => $afters,
						'total_tables' => count( $names ),
					);
				}
			} finally { $db->close(); }
		}
		return $job;
	}
}

