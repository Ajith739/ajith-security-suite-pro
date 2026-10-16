<?php
/**
 * Quarantine manager: safe, evidence-preserving file isolation.
 *
 * Original evidence is copied to a random-named, execution-blocked
 * storage area with complete provenance. Restore/delete only by an administrator
 * through capability + nonce protected actions.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH_Quarantine_Manager — finding-ID-based quarantine operations.
 */
final class GWQSH_Quarantine_Manager {

	/** Serialize filesystem + option mutations across requests.
	 *
	 * @var int
	 */
	private static $lock_depth = 0;

	/** Locked.
	 *
	 * @param mixed $callback Callback.
	 * @return mixed Operation result.
	 */
	/** Coordinate trusted internal metadata import with filesystem actions.
	 *
	 * @param callable $callback Internal callback.
	 * @return mixed Operation result.
	 */
	public static function synchronize( $callback ) {
		return self::locked( $callback );
	}

	/** Run an internal action under the private storage lock.
	 *
	 * @param callable $callback Internal operation.
	 * @return mixed Operation result.
	 */
	private static function locked( $callback ) {
		if ( self::$lock_depth ) {
			return call_user_func( $callback );
		}
		$dir = self::ensure_quarantine_dir();
		if ( is_wp_error( $dir ) || is_link( $dir ) || is_link( $dir . '/integrity.lock' ) ) {
			return new WP_Error( 'quarantine_lock', 'Quarantine storage is unavailable.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$handle = @fopen( $dir . '/integrity.lock', 'c' );
		if ( ! $handle || ! flock( $handle, LOCK_EX | LOCK_NB ) ) {
			if ( $handle ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				fclose( $handle );
			}
			return new WP_Error( 'quarantine_busy', 'Another file action is running. Retry shortly.' );
		}
		self::$lock_depth = 1;
		try {
			// Other requests may have updated the option while this request loaded.
			clearstatcache();
			wp_cache_delete( 'alloptions', 'options' );
			wp_cache_delete( 'notoptions', 'options' );
			wp_cache_delete( self::METADATA_OPTION, 'options' );
			wp_cache_delete( 'gwqsh_intentional_removals', 'options' );
			return call_user_func( $callback );
		} finally {
			self::$lock_depth = 0;
			flock( $handle, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			fclose( $handle );
		}
	}

	/** Canonical operation key for labels, relative paths and absent targets.
	 *
	 * @param mixed $path Path.
	 * @return mixed Operation result.
	 */
	public static function path_key( $path ) {
		$validated = GWQSH_Path_Guard::validate( $path, false );
		return $validated ? $validated['canonical'] : '';
	}

	/** Human-readable path only; never an authorization token.
	 *
	 * @param mixed $path Path.
	 * @return mixed Operation result.
	 */
	public static function display_path( $path ) {
		$map = array(
			'plugin'  => 'wp-content/plugins/',
			'mu'      => 'wp-content/mu-plugins/',
			'theme'   => 'wp-content/themes/',
			'uploads' => 'wp-content/uploads/',
			'content' => 'wp-content/',
			'root'    => '',
		);
		if ( preg_match( '#^/?@([a-z]+)/(.+)$#D', $path, $matches ) && isset( $map[ $matches[1] ] ) ) {
			return $map[ $matches[1] ] . $matches[2];
		}
		return ltrim( $path, '/' );
	}

	/** Exact, versioned sentinel bytes tied to owned metadata.
	 *
	 * @param mixed $id Id.
	 * @return mixed Operation result.
	 */
	private static function sentinel( $id ) {
		return "<?php\n// Blocked by Gracewell Security Suite Pro. Evidence: " . $id . ".\nreturn;\n";
	}

	/** Is owned sentinel.
	 *
	 * @param mixed $path Path.
	 * @param mixed $record Record.
	 * @return mixed Operation result.
	 */
	public static function is_owned_sentinel( $path, $record = null ) {
		$key = self::path_key( $path );
		if ( ! $key || ! is_file( $key ) || is_link( $key ) || filesize( $key ) >= 256 ) {
			return false;
		}
		$records = $record ? array( $record ) : array_merge( (array) get_option( self::METADATA_OPTION, array() ), (array) get_option( 'gwqsh_intentional_removals', array() ) );
		foreach ( $records as $item ) {
			if ( ! is_array( $item ) || ! isset( $item['id'], $item['original'], $item['hash'] ) || ! is_string( $item['id'] ) || ! is_string( $item['original'] ) || ! is_string( $item['hash'] ) || ! preg_match( '/^[a-f0-9]{32,64}$/D', $item['id'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $item['hash'] ) ) {
				continue;
			}

			if ( isset( $item['component'] ) && 'mu_plugin' !== $item['component'] ) {
				continue;
			}

			if ( ! empty( $item['id'] ) && ! empty( $item['original'] ) && 'restore_backup' !== ( $item['reason'] ?? '' ) && self::path_key( $item['original'] ) === $key && filesize( $key ) < 256 && in_array( hash_file( 'sha256', $key ), array( hash( 'sha256', self::sentinel( $item['id'] ) ), hash( 'sha256', "<?php\n// Gracewell-blocked; evidence " . $item['id'] . ".\nreturn;\n" ) ), true ) ) {
				return true;
			}
		}
		return false;
	}

	/** Only suppress absence, never a recreated live file or core expectation.
	 *
	 * @param mixed $path Path.
	 * @return mixed Operation result.
	 */
	public static function get_active_quarantine_for_path( $path ) {
		$key = self::path_key( $path );
		if ( ! $key || ( file_exists( $key ) && ! self::is_owned_sentinel( $path ) ) ) {
			return null;
		}
		foreach ( self::list_quarantined() as $record ) {
			if ( ! empty( $record['hash'] ) && is_string( $record['hash'] ) && preg_match( '/^[a-f0-9]{64}$/D', $record['hash'] ) && 'restore_backup' !== ( $record['reason'] ?? '' ) && 'restore backup' !== ( $record['reason'] ?? '' ) && ! empty( $record['original'] ) && is_string( $record['original'] ) && self::path_key( $record['original'] ) === $key ) {
				return $record;
			}
		}
		return null;
	}

	/** Is path quarantined.
	 *
	 * @param mixed $path Path.
	 * @return mixed Operation result.
	 */
	public static function is_path_quarantined( $path ) {
		return null !== self::get_active_quarantine_for_path( $path );
	}

	/** Absence state.
	 *
	 * @param mixed $path Path.
	 * @param mixed $hash Hash.
	 * @return mixed Operation result.
	 */
	public static function absence_state( $path, $hash = '' ) {
		$record = self::get_active_quarantine_for_path( $path );
		if ( $record ) {
			return ! empty( $record['present'] ) ? 'Quarantined' : 'Damaged';
		}
		$key     = self::path_key( $path );
		$removed = (array) get_option( 'gwqsh_intentional_removals', array() );
		if ( $key && ( ! file_exists( $key ) || self::is_owned_sentinel( $path, $removed[ $key ] ?? null ) ) && isset( $removed[ $key ]['baseline_hash'] ) && is_string( $removed[ $key ]['baseline_hash'] ) && $hash && hash_equals( $removed[ $key ]['baseline_hash'], $hash ) ) {
			return 'Removed';
		}
		return '';
	}

	/** Keep official core requirements visible, including when their index is unavailable.
	 *
	 * @param string $canonical Validated canonical path.
	 * @return bool Whether this path requires official restoration.
	 */
	private static function requires_official_restoration( $canonical ) {
		if ( 'core' !== GWQSH_Path_Guard::detect_component( $canonical ) ) {
			return false;
		}
		$root = GWQSH_Path_Guard::root() . '/';
		if ( 0 !== strpos( $canonical, $root ) ) {
			return true;
		}
		$checksums = GWQSH_File_Integrity::get_core_checksums();
		return ! is_array( $checksums ) || isset( $checksums[ substr( $canonical, strlen( $root ) ) ] );
	}

	/** Resolve obsolete findings only while an owned non-core path is absent or blocked.
	 *
	 * @param array      $record Owned quarantine/removal record.
	 * @param string     $state Resolution label.
	 * @param array|null $row_index Optional unresolved rows grouped by stored label.
	 */
	private static function resolve_absent_findings( $record, $state, $row_index = null ) {
		global $wpdb;
		if ( ! is_array( $record ) || empty( $record['original'] ) || ! is_string( $record['original'] ) || ! isset( $record['hash'] ) || ! is_string( $record['hash'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $record['hash'] ) ) {
			return;
		}
		$key = self::path_key( $record['original'] );
		if ( ! $key || self::requires_official_restoration( $key ) || ( file_exists( $key ) && ! self::is_owned_sentinel( $record['original'], $record ) ) ) {
			return;
		}
		$labels = array( $record['original'], '/' . ltrim( $record['original'], '/' ), ltrim( $record['original'], '/' ), GWQSH_Scan_Engine::label( $key ), $key );
		if ( null !== $row_index ) {
			$rows = array();
			foreach ( array_unique( $labels ) as $label ) {
				$rows = array_merge( $rows, $row_index[ $label ] ?? array() );
			}
		} else {
			$placeholders = implode( ',', array_fill( 0, count( $labels ), '%s' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Placeholder list contains only generated %s tokens; paths are passed to prepare().
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, file_path FROM {$wpdb->prefix}gwqsh_scan_results WHERE is_resolved = 0 AND file_path IN ($placeholders)", $labels ), ARRAY_A );
		}
		foreach ( $rows as $row ) {
			if ( self::path_key( $row['file_path'] ) === $key ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
				$wpdb->update(
					$wpdb->prefix . 'gwqsh_scan_results',
					array(
						'status'      => $state,
						'is_resolved' => 1,
					),
					array( 'id' => (int) $row['id'] )
				);
			}
		}
	}

	/** Keep removal history separate from deletable evidence metadata.
	 *
	 * @param mixed $record Record.
	 * @param mixed $state State.
	 * @return mixed Operation result.
	 */
	private static function record_resolution( $record, $state ) {
		global $wpdb;
		$key    = self::path_key( $record['original'] );
		$absent = $key && ( ! file_exists( $key ) || self::is_owned_sentinel( $record['original'], $record ) );
		if ( ! empty( $record['finding_id'] ) && ( 'Resolved — Removed' !== $state || $absent ) ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$wpdb->update(
				$wpdb->prefix . 'gwqsh_scan_results',
				array(
					'status'      => $state,
					'is_resolved' => 1,
				),
				array( 'id' => (int) $record['finding_id'] )
			);
		}
		$key     = self::path_key( $record['original'] );
		$removed = (array) get_option( 'gwqsh_intentional_removals', array() );
		if ( 'Resolved — Removed' === $state && $absent && ! self::requires_official_restoration( $key ) && ! in_array( $record['reason'] ?? '', array( 'restore_backup', 'restore backup' ), true ) ) {
			$baseline      = GWQSH_Scan_Engine::load( 'gwqsh_file_baseline' );
			$baseline_hash = $record['hash'];
			foreach ( $baseline as $label => $trusted ) {
				if ( self::path_key( $label ) === $key ) {
					$baseline_hash = $trusted['hash'];
					break;
				}
			}
			$removed[ $key ] = array_merge(
				$record,
				array(
					'baseline_hash' => $baseline_hash,
					'status'        => 'intentionally_removed',
					'resolved_at'   => time(),
				)
			);
		} elseif ( 'Restored' === $state && $key ) {
			unset( $removed[ $key ] );
		}
		update_option( 'gwqsh_intentional_removals', $removed, false );
		if ( (array) get_option( 'gwqsh_intentional_removals', array() ) !== $removed ) {
			return new WP_Error( self::ERR_WRITE_FAILED, 'Could not persist removal history; evidence ownership was retained.' );
		}
		if ( 'Resolved — Removed' === $state && isset( $removed[ $key ] ) ) {
			self::resolve_absent_findings( $record, $state );
		}
		return true;
	}

	/** Retain verified text when it becomes trusted, independently of quarantine copies.
	 *
	 * @param string $path Finding/baseline label.
	 * @param string $hash Expected full SHA-256.
	 * @return bool|WP_Error True or storage error; unsupported binary/large files are skipped.
	 */
	public static function retain_trusted_text( $path, $hash ) {
		$validated = GWQSH_Path_Guard::validate( $path, true );
		if ( ! $validated || ! preg_match( '/^[a-f0-9]{64}$/D', $hash ) ) {
			return new WP_Error( 'snapshot_invalid', 'Trusted source is unavailable.' );
		}
		$file = $validated['canonical'];
		if ( filesize( $file ) > 524288 || ! preg_match( '/\.(php|js|css|txt|json|html?|xml|svg|md|ini|ya?ml|sql)$/i', $file ) ) {
			return true;
		}
		$content = file_get_contents( $file );
		if ( false === $content || ! hash_equals( $hash, hash( 'sha256', $content ) ) ) {
			return new WP_Error( 'snapshot_changed', 'Trusted source changed before preservation.' );
		}
		if ( false !== strpos( $content, "\0" ) || substr_count( $content, "\n" ) > 5000 ) {
			return true;
		}
		$dir = self::ensure_quarantine_dir();
		if ( is_wp_error( $dir ) ) {
			return $dir;
		}
		$target = $dir . '/trusted-' . $hash . '.snapshot';
		if ( is_link( $target ) || ( ! GWQSH_Security_Runtime::atomic_write( $target, $content ) ) || ! hash_equals( $hash, hash_file( 'sha256', $target ) ) ) {
			return new WP_Error( 'snapshot_failed', 'Could not retain verified old content. Baseline was not changed.' );
		}
		return true;
	}

	/** Find actual trusted bytes by baseline SHA-256, never by backup reason alone.
	 *
	 * @param mixed $path Path.
	 * @return mixed Operation result.
	 */
	public static function trusted_copy( $path ) {
		$key      = self::path_key( $path );
		$baseline = GWQSH_Scan_Engine::load( 'gwqsh_file_baseline' );
		$trusted  = null;
		foreach ( $baseline as $label => $record ) {
			if ( $key && self::path_key( $label ) === $key ) {
				$trusted = $record;
				break;
			}
		}
		if ( ! $trusted || empty( $trusted['hash'] ) || ! is_string( $trusted['hash'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $trusted['hash'] ) ) {
			return null;
		}
		$snapshot = self::quarantine_dir() . '/trusted-' . $trusted['hash'] . '.snapshot';
		if ( ! is_link( self::quarantine_dir() ) && ! is_link( $snapshot ) && is_file( $snapshot ) && hash_equals( $trusted['hash'], hash_file( 'sha256', $snapshot ) ) ) {
			return array_merge( $trusted, array( 'source' => $snapshot ) );
		}
		foreach ( self::list_quarantined() as $item ) {
			$source = self::quarantine_dir() . '/' . $item['file'];
			if ( $item['present'] && self::path_key( $item['original'] ) === $key && ! empty( $item['hash'] ) && hash_equals( $trusted['hash'], $item['hash'] ) && hash_equals( $trusted['hash'], hash_file( 'sha256', $source ) ) ) {
				return array_merge( $trusted, array( 'source' => $source ) );
			}
		}
		return null;
	}

	/** Quarantine by finding.
	 *
	 * @param mixed $finding_id Finding id.
	 * @param mixed $is_backup Is backup.
	 * @param mixed $expected_hash Expected hash.
	 * @return mixed Operation result.
	 */
	public static function quarantine_by_finding( $finding_id, $is_backup = false, $expected_hash = '' ) {
		return self::locked(
			static function () use ( $finding_id, $is_backup, $expected_hash ) {
				return self::quarantine_by_finding_locked( $finding_id, $is_backup, $expected_hash );
			}
		);
	}

	/** Restore quarantined.
	 *
	 * @param mixed $artifact_name Artifact name.
	 * @return mixed Operation result.
	 */
	public static function restore_quarantined( $artifact_name ) {
		$result = self::locked(
			static function () use ( $artifact_name ) {
				return self::restore_quarantined_locked( $artifact_name );
			}
		);
		if ( is_array( $result ) && ! empty( $result['restored'] ) ) {
			self::recheck_restored( $result['restored'] ); }
		return $result;
	}

	/** Reinspect restored bytes without automatic deletion or changes to provenance. */
	public static function recheck_restored( $path ) {
		$validated = GWQSH_Path_Guard::validate( $path, true );
		if ( ! $validated ) {
			return new WP_Error( 'recheck_path', 'Restored location could not be revalidated.' ); }
		$file   = $validated['canonical'];
		$scope  = GWQSH_Scan_Engine::scope( $file );
		$result = GWQSH_Scan_Engine::inspect( $file, $scope );
		if ( ! empty( $result['error'] ) ) {
			GWQSH_Activity_Logger::log( 'Restored file recheck failed', 'Restored copy is retained; inspect the location manually.', 'Security' );
			return new WP_Error( 'recheck', 'Restoration completed but inspection was unavailable.' ); }
		if ( $result['score'] >= 40 ) {
			GWQSH_Scan_Engine::finding( GWQSH_Scan_Engine::label( $file ), $scope, 'Suspicious', 'Restored content still has reviewable evidence; no automatic deletion.', $result ); }
		do_action( 'gwqsh_remediation_rechecked', $path, $result );
		return $result;
	}
	/** Delete quarantined.
	 *
	 * @param mixed $artifact_name Artifact name.
	 * @return mixed Operation result.
	 */
	public static function delete_quarantined( $artifact_name ) {
		return self::locked(
			static function () use ( $artifact_name ) {
				return self::delete_quarantined_locked( $artifact_name );
			}
		);
	}

	/** Delete all owned copies while retaining failed records.
	 *
	 * @return array|WP_Error Deletion summary or locking error.
	 */
	public static function clear_all_quarantine() {
		return self::locked(
			static function () {
				return self::clear_all_quarantine_locked();
			}
		);
	}

	/** Accept current.
	 *
	 * @param mixed $finding_id Finding id.
	 * @return mixed Operation result.
	 */
	public static function accept_current( $finding_id ) {
		return self::locked(
			static function () use ( $finding_id ) {
				return self::accept_current_locked( $finding_id );
			}
		);
	}

	/** Restore trusted.
	 *
	 * @param mixed $finding_id Finding id.
	 * @return mixed Operation result.
	 */
	public static function restore_trusted( $finding_id ) {
		return self::locked(
			static function () use ( $finding_id ) {
				return self::restore_trusted_locked( $finding_id );
			}
		);
	}

	/** Write verified bytes through a fresh sibling and revalidate just before rename.
	 *
	 * @param mixed $path Path.
	 * @param mixed $content Content.
	 * @param mixed $expected_hash Expected hash.
	 * @return mixed Operation result.
	 */
	public static function replace_verified( $path, $content, $expected_hash ) {
		$validated = GWQSH_Path_Guard::validate( $path, false );
		if ( ! $validated || ! is_dir( dirname( $validated['canonical'] ) ) ) {
			return false;
		}
		$target = $validated['canonical'];
		$temp   = dirname( $target ) . '/.' . bin2hex( random_bytes( 16 ) ) . '.tmp';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$handle = @fopen( $temp, 'xb' );
		if ( ! $handle ) {
			return false; }
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$ok = fwrite( $handle, $content ) === strlen( $content ) && fflush( $handle );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		fclose( $handle );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		@chmod( $temp, 0644 );
		$recheck = GWQSH_Path_Guard::validate( $path, false );
		$ok      = $ok && hash_file( 'sha256', $temp ) === hash( 'sha256', $content ) && $recheck && $recheck['canonical'] === $target;
		$ok      = $ok && ( $expected_hash ? is_file( $target ) && hash_equals( $expected_hash, hash_file( 'sha256', $target ) ) : ! file_exists( $target ) );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$ok = $ok && @rename( $temp, $target );
		if ( is_file( $temp ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@unlink( $temp ); }
		return $ok && hash_file( 'sha256', $target ) === hash( 'sha256', $content );
	}

	/** Report orphaned artifacts without promoting filesystem markers to owned state. */
	public static function reconcile() {
		global $wpdb;
		$records   = self::list_quarantined();
		$row_index = array();
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		foreach ( $wpdb->get_results( "SELECT id,file_path FROM {$wpdb->prefix}gwqsh_scan_results WHERE is_resolved=0", ARRAY_A ) as $row ) {
			$row_index[ $row['file_path'] ][] = $row;
		}
		foreach ( (array) get_option( 'gwqsh_intentional_removals', array() ) as $record ) {
			self::resolve_absent_findings( $record, 'Resolved — Removed', $row_index );
		}
		$dir     = self::quarantine_dir();
		$orphans = array();
		if ( $dir && is_dir( $dir ) && ! is_link( $dir ) ) {
			foreach ( new DirectoryIterator( $dir ) as $entry ) {
				$name = $entry->getFilename();
				if ( preg_match( '/^[a-f0-9]{32,64}\.quarantine$/D', $name ) && ! isset( $records[ $name ] ) ) {
					$orphans[] = $name;
				}
			}
		}
		update_option( 'gwqsh_quarantine_orphans', $orphans, false );
		foreach ( $records as $record ) {
			if ( in_array( $record['reason'] ?? '', array( 'restore_backup', 'restore backup' ), true ) ) {
				continue;
			}
			self::resolve_absent_findings( $record, 'Quarantined', $row_index );
		}
	}

	/** Metadata option key (same as legacy). */
	const METADATA_OPTION = 'gwqsh_quarantine_metadata';

	/** Allowed page sizes for pagination. */
	const ALLOWED_PAGE_SIZES = array( 5, 10, 20, 25, 30, 50, 100, 250, 500 );

	/** Default page size. */
	const DEFAULT_PAGE_SIZE = 20;

	/**
	 * Error code constants for structured responses.
	 */
	const ERR_FINDING_NOT_FOUND   = 'finding_not_found';
	const ERR_FILE_MISSING        = 'file_missing';
	const ERR_PATH_NOT_ALLOWED    = 'path_not_allowed';
	const ERR_SYMLINK_REJECTED    = 'symlink_rejected';
	const ERR_HASH_FAILED         = 'hash_failed';
	const ERR_QUARANTINE_WRITABLE = 'quarantine_not_writable';
	const ERR_COPY_FAILED         = 'copy_failed';
	const ERR_HASH_MISMATCH       = 'hash_mismatch';
	const ERR_STATE_CHANGED       = 'state_changed';
	const ERR_ALREADY_QUARANTINED = 'already_quarantined';
	const ERR_PERMISSION_DENIED   = 'permission_denied';
	const ERR_NONCE_FAILED        = 'nonce_failed';
	const ERR_PROTECTED_FILE      = 'protected_file';
	const ERR_SELF_QUARANTINE     = 'self_quarantine';
	const ERR_QUARANTINE_RECORD   = 'quarantine_record_missing';
	const ERR_TARGET_EXISTS       = 'target_exists';
	const ERR_READ_FAILED         = 'read_failed';
	const ERR_WRITE_FAILED        = 'write_failed';
	const ERR_VERIFY_FAILED       = 'verify_failed';
	const ERR_CRITICAL_MALWARE    = 'critical_malware_cannot_accept';
	const ERR_NO_BASELINE         = 'no_baseline_content';

	/**
	 * Human-readable error messages for error codes.
	 *
	 * @param string $code Error code.
	 * @return string User-safe message.
	 */
	public static function error_message( $code ) {
		$messages = array(
			self::ERR_FINDING_NOT_FOUND   => 'The scan finding could not be found. It may have been resolved already.',
			self::ERR_FILE_MISSING        => 'The file no longer exists on disk. It may have already been removed.',
			self::ERR_PATH_NOT_ALLOWED    => 'The file path is outside the allowed WordPress directories.',
			self::ERR_SYMLINK_REJECTED    => 'Symbolic links cannot be quarantined for security reasons.',
			self::ERR_HASH_FAILED         => 'Could not compute a file checksum. The file may be unreadable.',
			self::ERR_QUARANTINE_WRITABLE => 'The quarantine storage directory is not writable. Check server permissions.',
			self::ERR_COPY_FAILED         => 'Could not copy the file to quarantine storage.',
			self::ERR_HASH_MISMATCH       => 'The quarantined copy does not match the original. Quarantine was rolled back.',
			self::ERR_STATE_CHANGED       => 'The file changed after the scan. Run a new scan before quarantining.',
			self::ERR_ALREADY_QUARANTINED => 'This finding has already been quarantined.',
			self::ERR_PERMISSION_DENIED   => 'You do not have permission to perform this action.',
			self::ERR_NONCE_FAILED        => 'Your session expired. Reload the page and try again.',
			self::ERR_PROTECTED_FILE      => 'Core bootstrap files cannot be quarantined; use checksum-verified restoration instead.',
			self::ERR_SELF_QUARANTINE     => 'Security Suite Pro cannot quarantine its own files.',
			self::ERR_QUARANTINE_RECORD   => 'No quarantine record exists for this item.',
			self::ERR_TARGET_EXISTS       => 'The original location is not empty. Remove or review the current file first.',
			self::ERR_READ_FAILED         => 'The file could not be read.',
			self::ERR_WRITE_FAILED        => 'Could not write to the target location. Check file permissions.',
			self::ERR_VERIFY_FAILED       => 'The restored file failed integrity verification.',
			self::ERR_CRITICAL_MALWARE    => 'Files with Critical malware findings cannot be accepted as trusted. Quarantine them first.',
			self::ERR_NO_BASELINE         => 'No trusted baseline content is available for restoration.',
		);
		return isset( $messages[ $code ] ) ? $messages[ $code ] : 'An unexpected error occurred.';
	}

	/**
	 * Quarantine a scan finding by its database ID.
	 *
	 * @param int    $finding_id Database ID from gwqsh_scan_results.
	 * @param bool   $is_backup  If true, copy without removing original.
	 * @param string $expected_hash Optional SHA-256 to verify before quarantine.
	 * @return array|WP_Error Success metadata or error.
	 */
	private static function quarantine_by_finding_locked( $finding_id, $is_backup = false, $expected_hash = '' ) {
		global $wpdb;

		$finding_id = absint( $finding_id );
		if ( ! $finding_id ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		// Load finding from database.
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d LIMIT 1", $finding_id ), ARRAY_A );

		if ( ! $finding ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		// Repeated requests for already isolated bytes reuse the owned record.
		if ( ! $is_backup ) {
			$active   = self::get_active_quarantine_for_path( $finding['file_path'] );
			$evidence = json_decode( $finding['evidence'] ?? '', true );
			if ( $active && ! empty( $active['present'] ) && ! empty( $evidence['hash'] ) && ( hash_equals( $active['hash'], $evidence['hash'] ) || self::is_owned_sentinel( $finding['file_path'], $active ) ) ) {
				self::resolve_absent_findings( $active, 'Quarantined' );
				return array(
					'artifact_id' => $active['id'],
					'original'    => $active['original'],
					'hash'        => $active['hash'],
					'finding_id'  => $finding_id,
				);
			}
		}
		if ( ! empty( $finding['is_resolved'] ) ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		// Resolve the stored path securely.
		$stored_path = $finding['file_path'];
		$validated   = GWQSH_Path_Guard::validate( $stored_path, true );

		if ( ! $validated ) {
			// Try without leading slash.
			$validated = GWQSH_Path_Guard::validate( ltrim( $stored_path, '/' ), true );
		}

		if ( ! $validated ) {
			return new WP_Error( self::ERR_PATH_NOT_ALLOWED, self::error_message( self::ERR_PATH_NOT_ALLOWED ) );
		}

		$canonical = $validated['canonical'];
		$relative  = $validated['relative'];

		// Verify it's a regular file.
		if ( ! is_file( $canonical ) ) {
			return new WP_Error( self::ERR_FILE_MISSING, self::error_message( self::ERR_FILE_MISSING ) );
		}

		// Reject symlinks.
		if ( is_link( $canonical ) ) {
			return new WP_Error( self::ERR_SYMLINK_REJECTED, self::error_message( self::ERR_SYMLINK_REJECTED ) );
		}

		// Protected files.
		$protected = array(
			GWQSH_Path_Guard::root() . '/wp-config.php',
			GWQSH_Path_Guard::root() . '/wp-load.php',
			GWQSH_Path_Guard::root() . '/wp-settings.php',
			GWQSH_Path_Guard::root() . '/wp-blog-header.php',
		);
		if ( ! $is_backup && in_array( $canonical, $protected, true ) ) {
			return new WP_Error( self::ERR_PROTECTED_FILE, self::error_message( self::ERR_PROTECTED_FILE ) );
		}

		// Cannot quarantine own files.
		if ( defined( 'GWQSH_PATH' ) && 0 === strpos( $canonical, rtrim( str_replace( '\\', '/', GWQSH_PATH ), '/' ) . '/' ) ) {
			return new WP_Error( self::ERR_SELF_QUARANTINE, self::error_message( self::ERR_SELF_QUARANTINE ) );
		}

		// Calculate full-file SHA-256.
		$hash = @hash_file( 'sha256', $canonical );
		if ( ! $hash ) {
			return new WP_Error( self::ERR_HASH_FAILED, self::error_message( self::ERR_HASH_FAILED ) );
		}

		// Race condition check: compare with scan-time hash if available.
		$evidence = ! empty( $finding['evidence'] ) ? json_decode( $finding['evidence'], true ) : array();
		if ( ! $is_backup && ( empty( $evidence['hash'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $evidence['hash'] ) ) ) {
			return new WP_Error( self::ERR_STATE_CHANGED, 'A fresh finding with a full SHA-256 is required.' );
		}
		if ( is_array( $evidence ) && ! empty( $evidence['hash'] ) && $evidence['hash'] !== $hash ) {
			return new WP_Error( self::ERR_STATE_CHANGED, self::error_message( self::ERR_STATE_CHANGED ) );
		}
		if ( $expected_hash && ! hash_equals( $expected_hash, $hash ) ) {
			return new WP_Error( self::ERR_STATE_CHANGED, self::error_message( self::ERR_STATE_CHANGED ) );
		}

		// Prepare quarantine directory.
		$quar_dir = self::ensure_quarantine_dir();
		if ( is_wp_error( $quar_dir ) ) {
			return $quar_dir;
		}

		// Reuse owned, hash-verified bytes even after a failed removal or recreation.
		$existing = null;
		foreach ( self::list_quarantined() as $item ) {
			$source = $quar_dir . '/' . $item['file'];
			if ( $item['present'] && self::path_key( $item['original'] ) === $canonical && hash_equals( $hash, $item['hash'] ) && hash_equals( $hash, hash_file( 'sha256', $source ) ) ) {
				if ( $is_backup && ! in_array( $item['reason'] ?? '', array( 'restore_backup', 'restore backup' ), true ) ) {
					continue;
				}
				$existing = $item;
				break;
			}
		}
		if ( $is_backup && $existing ) {
			return array(
				'artifact_id' => $existing['id'],
				'original'    => $existing['original'],
				'hash'        => $hash,
				'finding_id'  => $finding_id,
			);
		}
		$artifact_id = $existing ? $existing['id'] : bin2hex( random_bytes( 16 ) );
		$dest        = $quar_dir . '/' . $artifact_id . '.quarantine';
		if ( ! $existing ) {
			if ( ! @copy( $canonical, $dest ) ) {
				return new WP_Error( self::ERR_COPY_FAILED, self::error_message( self::ERR_COPY_FAILED ) );
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@chmod( $dest, 0600 );
		}
		$dest_hash = @hash_file( 'sha256', $dest );
		if ( ! $dest_hash || $dest_hash !== $hash ) {
			if ( ! $existing ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				@unlink( $dest );
			}
			return new WP_Error( self::ERR_HASH_MISMATCH, self::error_message( self::ERR_HASH_MISMATCH ) );
		}

		// Determine if this is an MU plugin that needs sentinel replacement.
		$is_mu     = false;
		$mu_root   = defined( 'WPMU_PLUGIN_DIR' ) ? realpath( WPMU_PLUGIN_DIR ) : realpath( WP_CONTENT_DIR . '/mu-plugins' );
		$mu_root_n = $mu_root ? str_replace( '\\', '/', $mu_root ) : '';
		if ( $mu_root_n && dirname( $canonical ) === $mu_root_n && 'php' === strtolower( pathinfo( $canonical, PATHINFO_EXTENSION ) ) ) {
			$is_mu = true;
		}

		// Build metadata record.
		$severity   = '';
		$score      = 0;
		$confidence = '';
		if ( is_array( $evidence ) ) {
			$severity   = isset( $evidence['severity'] ) ? $evidence['severity'] : '';
			$score      = isset( $evidence['score'] ) ? (int) $evidence['score'] : 0;
			$confidence = isset( $evidence['confidence'] ) ? $evidence['confidence'] : '';
		}

		$record = array(
			'id'         => $artifact_id,
			'finding_id' => $finding_id,
			'original'   => '/' . ltrim( $relative, '/' ),
			'file_type'  => $finding['file_type'],
			'component'  => $validated['component'],
			'hash'       => $hash,
			'size'       => filesize( $dest ),
			'time'       => time(),
			'reason'     => $is_backup ? 'restore_backup' : 'scan_quarantine',
			'severity'   => $severity,
			'score'      => $score,
			'confidence' => $confidence,
			'status'     => 'quarantined',
			'details'    => isset( $finding['details'] ) ? substr( $finding['details'], 0, 500 ) : '',
		);

		// Store metadata.
		$metadata                                 = (array) get_option( self::METADATA_OPTION, array() );
		$previous_metadata                        = $metadata;
		$metadata[ $artifact_id . '.quarantine' ] = $record;
		if ( $previous_metadata !== $metadata && ! update_option( self::METADATA_OPTION, $metadata, false ) ) {
			if ( ! $existing ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				@unlink( $dest );
			}
			return new WP_Error( self::ERR_WRITE_FAILED, 'Could not persist quarantine ownership; original retained.' );
		}

		// Write JSON sidecar for Guardian compatibility.
		$json_meta = array(
			'id'       => $artifact_id,
			'original' => $relative,
			'hash'     => $hash,
			'time'     => time(),
			'rules'    => array( $is_backup ? 'restore_backup' : 'scan_quarantine' ),
			'decision' => $is_mu ? 'blocked' : 'preserved',
		);
		if ( ! GWQSH_Security_Runtime::atomic_write( $quar_dir . '/' . $artifact_id . '.json', wp_json_encode( $json_meta ) ) ) {
			$metadata[ $artifact_id . '.quarantine' ]['reason']           = 'restore_backup';
			$metadata[ $artifact_id . '.quarantine' ]['isolation_failed'] = true;
			update_option( self::METADATA_OPTION, $metadata, false );
			return new WP_Error( self::ERR_WRITE_FAILED, 'Could not persist quarantine sidecar; original retained.' );
		}

		$recheck = GWQSH_Path_Guard::validate( $stored_path, true );
		if ( ! $recheck || $recheck['canonical'] !== $canonical || hash_file( 'sha256', $canonical ) !== $hash ) {
			$metadata[ $artifact_id . '.quarantine' ]['reason']           = 'restore_backup';
			$metadata[ $artifact_id . '.quarantine' ]['isolation_failed'] = true;
			update_option( self::METADATA_OPTION, $metadata, false );
			return new WP_Error( self::ERR_STATE_CHANGED, self::error_message( self::ERR_STATE_CHANGED ) );
		}
		// Now remove or replace the original.
		if ( ! $is_backup ) {
			if ( $is_mu ) {
				// MU plugin: replace with safe sentinel.
				$sentinel = self::sentinel( $artifact_id );
				$temp     = dirname( $canonical ) . '/.' . $artifact_id . '.tmp';
				$ok       = @file_put_contents( $temp, $sentinel, LOCK_EX );
				if ( false !== $ok ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
					@chmod( $temp, 0644 );
					// Verify source hasn't changed during our operation.
					if ( @hash_file( 'sha256', $canonical ) === $hash ) {
						// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
						$ok = @rename( $temp, $canonical );
					} else {
						// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
						@unlink( $temp );
						$ok = false;
					}
				}
				if ( ! $ok && is_file( $temp ) ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
					@unlink( $temp );
				}
			} else {
				// Regular file: verify hash one more time, then unlink.
				if ( @hash_file( 'sha256', $canonical ) !== $hash ) {
					return new WP_Error( self::ERR_STATE_CHANGED, self::error_message( self::ERR_STATE_CHANGED ) );
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				$ok = @unlink( $canonical );
			}
		}

		if ( ! $is_backup && ! $ok ) {
			$metadata[ $artifact_id . '.quarantine' ]['reason']           = 'restore_backup';
			$metadata[ $artifact_id . '.quarantine' ]['isolation_failed'] = true;
			update_option( self::METADATA_OPTION, $metadata, false );
			return new WP_Error( self::ERR_WRITE_FAILED, 'The copy was preserved, but the server could not remove the original. Grant the PHP server delete access to this file’s folder, then retry. The live file remains active.' );
		}

		// Mark finding as resolved.
		if ( ! $is_backup ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$wpdb->update(
				$table,
				array(
					'is_resolved' => 1,
					'status'      => 'Quarantined',
				),
				array( 'id' => $finding_id )
			);

			self::resolve_absent_findings( $record, 'Quarantined' );
			GWQSH_Activity_Logger::log(
				'File quarantined',
				'Quarantined: /' . ltrim( $relative, '/' ) . ' (finding #' . $finding_id . ')',
				'Security'
			);
		} else {
			GWQSH_Activity_Logger::log(
				'Restore backup stored',
				'Backup of /' . ltrim( $relative, '/' ) . ' stored before restoration.',
				'Security'
			);
		}

		return array(
			'artifact_id' => $artifact_id,
			'original'    => '/' . ltrim( $relative, '/' ),
			'hash'        => $hash,
			'finding_id'  => $finding_id,
		);
	}

	/**
	 * List all quarantined items with metadata.
	 *
	 * @return array
	 */
	public static function list_quarantined() {
		$metadata = (array) get_option( self::METADATA_OPTION, array() );
		$dir      = self::quarantine_dir();
		$result   = array();
		foreach ( $metadata as $name => $record ) {
			if ( ! preg_match( '/^[a-f0-9]{32,64}\.quarantine$/D', (string) $name ) ) {
				continue;
			}
			if ( ! is_array( $record ) ) {
				$record = array(
					'original' => '',
					'hash'     => '',
					'status'   => 'Damaged / invalid metadata',
				);
			}
			$path              = $dir . '/' . $name;
			$record['file']    = $name;
			$valid_record      = ! empty( $record['original'] ) && is_string( $record['original'] ) && ! empty( $record['hash'] ) && is_string( $record['hash'] ) && preg_match( '/^[a-f0-9]{64}$/D', $record['hash'] );
			$record['present'] = $valid_record && $dir && ! is_link( $dir ) && is_file( $path ) && ! is_link( $path );
			$record['status']  = $record['present'] ? ( in_array( $record['reason'] ?? '', array( 'restore_backup', 'restore backup' ), true ) ? 'Preserved backup' : 'Quarantined' ) : 'Damaged / missing evidence';
			if ( ! empty( $record['isolation_failed'] ) && $record['present'] ) {
				$record['status'] = 'Isolation failed — original retained';
			}
			$record['display_path'] = self::display_path( is_string( $record['original'] ?? null ) ? $record['original'] : '' );
			$result[ $name ]        = $record;
		}
		return $result;
	}

	/**
	 * Restore a quarantined file by its artifact name.
	 *
	 * @param string $artifact_name Quarantine artifact filename (e.g., "abc123.quarantine").
	 * @return array|WP_Error
	 */
	private static function restore_quarantined_locked( $artifact_name ) {
		if ( is_string( $artifact_name ) && ! preg_match( '/\.quarantine$/D', $artifact_name ) ) {
			$artifact_name .= '.quarantine';
		}
		if ( ! is_string( $artifact_name ) || ! preg_match( '/^[a-f0-9]{32,64}\.quarantine$/D', $artifact_name ) ) {
			return new WP_Error( self::ERR_QUARANTINE_RECORD, self::error_message( self::ERR_QUARANTINE_RECORD ) );
		}

		$metadata = (array) get_option( self::METADATA_OPTION, array() );
		if ( ! isset( $metadata[ $artifact_name ] ) || ! is_array( $metadata[ $artifact_name ] ) || empty( $metadata[ $artifact_name ]['original'] ) || ! is_string( $metadata[ $artifact_name ]['original'] ) ) {
			return new WP_Error( self::ERR_QUARANTINE_RECORD, self::error_message( self::ERR_QUARANTINE_RECORD ) );
		}

		$record = $metadata[ $artifact_name ];
		if ( empty( $record['original'] ) || ! is_string( $record['original'] ) ) {
			return new WP_Error( self::ERR_QUARANTINE_RECORD, 'The quarantine record is incomplete.' );
		}

		$dir = self::quarantine_dir();
		if ( ! $dir || ! is_dir( $dir ) ) {
			return new WP_Error( self::ERR_QUARANTINE_WRITABLE, self::error_message( self::ERR_QUARANTINE_WRITABLE ) );
		}

		$source = $dir . '/' . $artifact_name;
		if ( ! is_file( $source ) || is_link( $source ) ) {
			return new WP_Error( self::ERR_FILE_MISSING, 'The quarantined file copy is no longer available.' );
		}

		// Validate original location.
		$original  = $record['original'];
		$validated = GWQSH_Path_Guard::validate( $original, false );
		if ( ! $validated && 0 === strpos( $original, '/' ) ) {
			$validated = GWQSH_Path_Guard::validate( ltrim( $original, '/' ), false );
		}
		if ( ! $validated ) {
			return new WP_Error( self::ERR_PATH_NOT_ALLOWED, 'The recorded original path is no longer valid.' );
		}

		$target = $validated['canonical'];

		// If original is an MU sentinel, we can overwrite it.
		$overwrite_sentinel = false;
		if ( file_exists( $target ) ) {
			if ( self::is_owned_sentinel( $original, $record ) ) {
				$overwrite_sentinel = true;
			} else {
				return new WP_Error( self::ERR_TARGET_EXISTS, self::error_message( self::ERR_TARGET_EXISTS ) );
			}
		}

		// Verify quarantined file integrity.
		$source_hash = @hash_file( 'sha256', $source );
		if ( ! $source_hash ) {
			return new WP_Error( self::ERR_READ_FAILED, self::error_message( self::ERR_READ_FAILED ) );
		}
		if ( empty( $record['hash'] ) || ! preg_match( '/^[a-f0-9]{64}$/D', $record['hash'] ) || ! hash_equals( $record['hash'], $source_hash ) ) {
			return new WP_Error( self::ERR_HASH_MISMATCH, 'The quarantined file no longer matches its recorded checksum.' );
		}

		// Ensure parent directory exists.
		$parent = dirname( $target );
		if ( ! is_dir( $parent ) ) {
			wp_mkdir_p( $parent );
		}

		// Revalidate after directory creation; no symlink or racing target overwrite.
		$recheck = GWQSH_Path_Guard::validate( $original, false );
		if ( ! $recheck || $recheck['canonical'] !== $target ) {
			return new WP_Error( self::ERR_PATH_NOT_ALLOWED, 'Restore target changed.' );
		}
		// Stage and verify complete bytes before exposing a live PHP file.
		$temp = dirname( $target ) . '/.' . bin2hex( random_bytes( 16 ) ) . '.restore';
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$input = @fopen( $source, 'rb' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$output = @fopen( $temp, 'xb' );
		if ( ! $input || ! $output ) {
			if ( $input ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				fclose( $input ); }
			if ( $output ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				fclose( $output );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				@unlink( $temp ); }
			return new WP_Error( self::ERR_WRITE_FAILED, 'Could not stage restored content.' );
		}
		$copied = stream_copy_to_stream( $input, $output );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		fclose( $input );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		fclose( $output );
		if ( false === $copied || @hash_file( 'sha256', $temp ) !== $source_hash ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@unlink( $temp );
			return new WP_Error( self::ERR_VERIFY_FAILED, 'Staged restore failed verification; original target retained.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		@chmod( $temp, 0644 );
		$recheck = GWQSH_Path_Guard::validate( $original, false );
		if ( ! $recheck || $recheck['canonical'] !== $target ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@unlink( $temp );
			return new WP_Error( self::ERR_PATH_NOT_ALLOWED, 'Restore target changed.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		if ( $overwrite_sentinel && ( ! self::is_owned_sentinel( $original, $record ) || ! @unlink( $target ) ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@unlink( $temp );
			return new WP_Error( self::ERR_STATE_CHANGED, 'The sentinel changed before restore.' );
		}
		// Exclusive hard-link publication fails if a target appeared during staging.
		$published = @link( $temp, $target );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		@unlink( $temp );
		if ( ! $published ) {
			return new WP_Error( self::ERR_TARGET_EXISTS, 'Restore target is occupied or cannot publish verified content.' );
		}

		// Verify restored file.
		$restored_hash = @hash_file( 'sha256', $target );
		if ( ! $restored_hash || $restored_hash !== $source_hash ) {
			return new WP_Error( self::ERR_VERIFY_FAILED, self::error_message( self::ERR_VERIFY_FAILED ) );
		}

		$resolution = self::record_resolution( $record, 'Restored' );
		if ( is_wp_error( $resolution ) ) {
			return $resolution;
		}
		// Retain ownership if evidence cleanup fails after a successful restore.
		$json_file = $dir . '/' . str_replace( '.quarantine', '.json', $artifact_name );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$cleaned = @unlink( $source );
		if ( file_exists( $json_file ) || is_link( $json_file ) ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			$cleaned = ! is_link( $json_file ) && @unlink( $json_file ) && $cleaned;
		}
		if ( ! $cleaned ) {
			$metadata[ $artifact_name ]['reason'] = 'restore_backup';
			$metadata[ $artifact_name ]['status'] = 'restore_cleanup_failed';
			update_option( self::METADATA_OPTION, $metadata, false );
			GWQSH_Activity_Logger::log( 'Restore cleanup requires review', 'Restored ' . self::display_path( $original ) . '; retained quarantine ownership after cleanup failure.', 'Security' );
			return new WP_Error( 'restore_cleanup_failed', 'File restored and verified, but quarantine cleanup failed. Review the retained record.' );
		}

		unset( $metadata[ $artifact_name ] );
		update_option( self::METADATA_OPTION, $metadata, false );

		$display = isset( $validated['relative'] ) ? $validated['relative'] : ltrim( $original, '/' );
		GWQSH_Activity_Logger::log(
			'File restored from quarantine',
			'Restored /' . $display . ' from quarantine.',
			'Security'
		);

		return array( 'restored' => '/' . $display );
	}

	/**
	 * Alias for restore_quarantined.
	 *
	 * @param string $artifact_name Artifact name or ID.
	 * @return array|WP_Error
	 */
	public static function restore_quarantine( $artifact_name ) {
		return self::restore_quarantined( $artifact_name );
	}

	/**
	 * Alias for delete_quarantined.
	 *
	 * @param string $artifact_name Artifact name or ID.
	 * @return true|WP_Error
	 */
	public static function delete_quarantine( $artifact_name ) {
		return self::delete_quarantined( $artifact_name );
	}

	/**
	 * Permanently delete a quarantined copy.
	 *
	 * @param string $artifact_name Quarantine artifact filename.
	 * @return true|WP_Error
	 */
	private static function delete_quarantined_locked( $artifact_name ) {
		if ( is_string( $artifact_name ) && ! preg_match( '/\.quarantine$/D', $artifact_name ) ) {
			$artifact_name .= '.quarantine';
		}
		if ( ! is_string( $artifact_name ) || ! preg_match( '/^[a-f0-9]{32,64}\.quarantine$/D', $artifact_name ) ) {
			return new WP_Error( self::ERR_QUARANTINE_RECORD, self::error_message( self::ERR_QUARANTINE_RECORD ) );
		}

		$metadata = (array) get_option( self::METADATA_OPTION, array() );
		if ( ! isset( $metadata[ $artifact_name ] ) || ! is_array( $metadata[ $artifact_name ] ) || empty( $metadata[ $artifact_name ]['original'] ) || ! is_string( $metadata[ $artifact_name ]['original'] ) ) {
			return new WP_Error( self::ERR_QUARANTINE_RECORD, 'No owned quarantine record exists.' );
		}
		$dir = self::quarantine_dir();
		if ( ! $dir || is_link( $dir ) || ! is_dir( $dir ) ) {
			return new WP_Error( self::ERR_WRITE_FAILED, 'Quarantine storage is unavailable.' );
		}
		$resolution = self::record_resolution( $metadata[ $artifact_name ], 'Resolved — Removed' );
		if ( is_wp_error( $resolution ) ) {
			return $resolution;
		}
		foreach ( array( $artifact_name, str_replace( '.quarantine', '.json', $artifact_name ) ) as $name ) {
			$path = $dir . '/' . $name;
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			if ( is_link( $path ) || ( file_exists( $path ) && ( ! is_file( $path ) || ! @unlink( $path ) ) ) ) {
				return new WP_Error( self::ERR_WRITE_FAILED, 'Could not delete an owned artifact; metadata retained.' );
			}
		}
		$original = $metadata[ $artifact_name ]['original'];
		unset( $metadata[ $artifact_name ] );
		update_option( self::METADATA_OPTION, $metadata, false );
		GWQSH_Activity_Logger::log( 'Quarantine item deleted', 'Permanently deleted quarantined copy of ' . $original, 'Security' );
		return true;
	}

	/** Delete owned copies only, retaining metadata for every failure. */
	private static function clear_all_quarantine_locked() {
		$results = array(
			'deleted' => 0,
			'failed'  => 0,
			'errors'  => array(),
		);
		foreach ( self::list_quarantined() as $name => $record ) {
			$result = self::delete_quarantined( $name );
			if ( is_wp_error( $result ) ) {
				++$results['failed'];
				$results['errors'][] = array(
					'id'      => $name,
					'message' => $result->get_error_message(),
				);
			} else {
				++$results['deleted'];
			}
		}
		GWQSH_Activity_Logger::log( 'Quarantine cleared', $results['deleted'] . ' deleted; ' . $results['failed'] . ' failed.', 'Security' );
		return $results;
	}

	/**
	 * Accept current version of a file as the new trusted baseline.
	 *
	 * @param int $finding_id Database ID from gwqsh_scan_results.
	 * @return true|WP_Error
	 */
	private static function accept_current_locked( $finding_id ) {
		global $wpdb;

		$finding_id = absint( $finding_id );
		if ( ! $finding_id ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d AND is_resolved = 0 LIMIT 1", $finding_id ), ARRAY_A );

		if ( ! $finding ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		// Check for Critical malware.
		$evidence = ! empty( $finding['evidence'] ) ? json_decode( $finding['evidence'], true ) : array();
		if ( is_array( $evidence ) ) {
			$score    = isset( $evidence['score'] ) ? (int) $evidence['score'] : 0;
			$severity = isset( $evidence['severity'] ) ? $evidence['severity'] : '';
			if ( $score >= 80 || 'Critical' === $severity ) {
				return new WP_Error( self::ERR_CRITICAL_MALWARE, self::error_message( self::ERR_CRITICAL_MALWARE ) );
			}
		}

		// Validate path.
		$stored_path = $finding['file_path'];
		$validated   = GWQSH_Path_Guard::validate( $stored_path, true );
		if ( ! $validated ) {
			$validated = GWQSH_Path_Guard::validate( ltrim( $stored_path, '/' ), true );
		}
		if ( ! $validated ) {
			return new WP_Error( self::ERR_FILE_MISSING, 'The file is no longer accessible.' );
		}

		$canonical = $validated['canonical'];

		// Calculate current hash.
		$hash = @hash_file( 'sha256', $canonical );
		if ( ! $hash ) {
			return new WP_Error( self::ERR_HASH_FAILED, self::error_message( self::ERR_HASH_FAILED ) );
		}

		if ( empty( $evidence['hash'] ) || ! hash_equals( $evidence['hash'], $hash ) ) {
			return new WP_Error( self::ERR_STATE_CHANGED, self::error_message( self::ERR_STATE_CHANGED ) );
		}
		$analysis = GWQSH_Scan_Engine::inspect( $canonical, $finding['file_type'], array() );
		if ( isset( $analysis['error'] ) || ! empty( $analysis['partial'] ) || ( $analysis['hash'] ?? '' ) !== $hash || @hash_file( 'sha256', $canonical ) !== $hash ) {
			return new WP_Error( self::ERR_STATE_CHANGED, 'Complete, unchanged malware analysis is required before acceptance.' );
		}
		if ( 80 <= $analysis['score'] || 'Critical' === $analysis['severity'] || ! empty( $analysis['auto_block'] ) ) {
			return new WP_Error( self::ERR_CRITICAL_MALWARE, self::error_message( self::ERR_CRITICAL_MALWARE ) );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$active = $wpdb->get_results( $wpdb->prepare( 'SELECT evidence FROM ' . $wpdb->prefix . 'gwqsh_scan_results WHERE file_path = %s AND is_resolved = 0', $stored_path ), ARRAY_A );
		foreach ( $active as $item ) {
			$other = json_decode( $item['evidence'], true );
			if ( ( $other['score'] ?? 0 ) >= 80 || 'Critical' === ( $other['severity'] ?? '' ) || ! empty( $other['auto_block'] ) ) {
				return new WP_Error( self::ERR_CRITICAL_MALWARE, self::error_message( self::ERR_CRITICAL_MALWARE ) );
			}
		}
		$retained = self::retain_trusted_text( $stored_path, $hash );
		if ( is_wp_error( $retained ) ) {
			return $retained;
		}
		// Update baseline.
		$label    = GWQSH_Scan_Engine::label( $canonical );
		$baseline = GWQSH_Scan_Engine::load( 'gwqsh_file_baseline' );
		if ( $label ) {
			$baseline[ $label ] = array(
				'hash'  => $hash,
				'size'  => filesize( $canonical ),
				'mtime' => filemtime( $canonical ),
				'scope' => $finding['file_type'],
			);
			GWQSH_Scan_Engine::save( 'gwqsh_file_baseline', $baseline );
		}

		// Mark finding as resolved.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$wpdb->update(
			$table,
			array(
				'is_resolved' => 1,
				'status'      => 'Accepted',
			),
			array( 'id' => $finding_id )
		);

		GWQSH_Activity_Logger::log(
			'Baseline updated',
			'Accepted current version as trusted: ' . $stored_path,
			'Security'
		);

		return true;
	}

	/**
	 * Restore a file's trusted baseline version.
	 *
	 * @param int $finding_id Database ID from gwqsh_scan_results.
	 * @return true|WP_Error
	 */
	private static function restore_trusted_locked( $finding_id ) {
		global $wpdb;

		$finding_id = absint( $finding_id );
		if ( ! $finding_id ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$finding = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$table} WHERE id = %d AND is_resolved = 0 LIMIT 1", $finding_id ), ARRAY_A );

		if ( ! $finding ) {
			return new WP_Error( self::ERR_FINDING_NOT_FOUND, self::error_message( self::ERR_FINDING_NOT_FOUND ) );
		}

		// For core files, delegate to the existing restore_core_file.
		$validated = GWQSH_Path_Guard::validate( $finding['file_path'], false );
		$evidence  = json_decode( $finding['evidence'] ?? '', true );
		if ( ! $validated || ( is_file( $validated['canonical'] ) && ! empty( $evidence['hash'] ) && ! hash_equals( $evidence['hash'], hash_file( 'sha256', $validated['canonical'] ) ) ) ) {
			return new WP_Error( self::ERR_STATE_CHANGED, self::error_message( self::ERR_STATE_CHANGED ) );
		}
		if ( 'Core' === $finding['file_type'] ) {
			$res = GWQSH_File_Integrity::restore_core_file( $finding['file_path'] );
			if ( is_wp_error( $res ) ) {
				return $res;
			}
			return true;
		}

		$trusted   = self::trusted_copy( $finding['file_path'] );
		$validated = GWQSH_Path_Guard::validate( $finding['file_path'], true );
		if ( ! $trusted || ! $validated ) {
			return new WP_Error( self::ERR_NO_BASELINE, self::error_message( self::ERR_NO_BASELINE ) );
		}
		$content = @file_get_contents( $trusted['source'] );
		if ( false === $content || ! hash_equals( $trusted['hash'], hash( 'sha256', $content ) ) ) {
			return new WP_Error( self::ERR_VERIFY_FAILED, 'Trusted content failed verification.' );
		}
		$backup = self::quarantine_by_finding( $finding_id, true );
		if ( is_wp_error( $backup ) ) {
			return $backup;
		}
		$recheck = GWQSH_Path_Guard::validate( $finding['file_path'], true );
		if ( ! $recheck || $validated['canonical'] !== $recheck['canonical'] || @hash_file( 'sha256', $recheck['canonical'] ) !== $backup['hash'] ) {
			return new WP_Error( self::ERR_STATE_CHANGED, 'Current version changed; backup retained.' );
		}
		if ( ! self::replace_verified( $finding['file_path'], $content, $backup['hash'] ) ) {
			return new WP_Error( self::ERR_VERIFY_FAILED, 'Trusted restoration failed; current version backup retained.' );
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$wpdb->update(
			$table,
			array(
				'is_resolved' => 1,
				'status'      => 'Restored',
			),
			array( 'id' => $finding_id )
		);
		self::recheck_restored( $finding['file_path'] );
		GWQSH_Activity_Logger::log( 'Trusted file restored', self::display_path( $finding['file_path'] ) . '; previous current version preserved.', 'Security' );
		return true;
	}

	/**
	 * Get the quarantine directory path.
	 *
	 * @return string|null
	 */
	public static function quarantine_dir() {
		return GWQSH_Guardian::state_dir();
	}

	/**
	 * Ensure quarantine directory exists and is hardened.
	 *
	 * @return string|WP_Error
	 */
	public static function ensure_quarantine_dir() {
		$dir = self::quarantine_dir();
		if ( ! $dir ) {
			return new WP_Error( self::ERR_QUARANTINE_WRITABLE, self::error_message( self::ERR_QUARANTINE_WRITABLE ) );
		}
		if ( ! GWQSH_Security_Runtime::protect( $dir ) ) {
			return new WP_Error( self::ERR_QUARANTINE_WRITABLE, self::error_message( self::ERR_QUARANTINE_WRITABLE ) );
		}
		return $dir;
	}

	/**
	 * Validate and normalize a page size value.
	 *
	 * @param int $size Requested page size.
	 * @return int Valid page size.
	 */
	public static function validate_page_size( $size ) {
		$size = (int) $size;
		if ( in_array( $size, self::ALLOWED_PAGE_SIZES, true ) ) {
			return $size;
		}
		return self::DEFAULT_PAGE_SIZE;
	}
}
