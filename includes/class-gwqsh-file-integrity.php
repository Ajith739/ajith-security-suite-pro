<?php
/**
 * Real file integrity scanner and core verifier for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH File Integrity implementation.
 */
final class GWQSH_File_Integrity {

	private const API_URL = 'https://api.wordpress.org/core/checksums/1.0/';
	/**
	 * Inspected.
	 *
	 * @var array
	 */
	private static $inspected = array(
		'Plugin'  => 0,
		'Theme'   => 0,
		'Uploads' => 0,
	);
	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'gwqsh_continue_integrity_scan', array( 'GWQSH_Scan_Engine', 'run' ) );
		// One-time cleanup of the removed development scan scheduler.
		if ( ! get_option( 'gwqsh_manual_scan_migration', false ) ) {
			wp_clear_scheduled_hook( 'gwqsh_scheduled_integrity_scan' );
			delete_option( 'gwqsh_scan_frequency' );
			delete_option( 'gwqsh_scan_time' );
			update_option( 'gwqsh_manual_scan_migration', 1, false );
		}
	}
	/**
	 * Get core checksums.
	 */
	public static function get_core_checksums() {
		global $wp_version;
		$cache_key = 'gwqsh_checksums_' . md5( $wp_version . '|' . get_locale() );
		$cached    = get_transient( $cache_key );
		if ( is_array( $cached ) && ! empty( $cached ) ) {
			if ( isset( $cached[ $wp_version ] ) && is_array( $cached[ $wp_version ] ) ) {
				$cached = $cached[ $wp_version ];
			} elseif ( 1 === count( $cached ) && is_array( reset( $cached ) ) ) {
				$cached = reset( $cached );
			}
			return self::core_only_checksums( $cached );
		}

		$locale = get_locale();
		$url    = add_query_arg(
			array(
				'version' => $wp_version,
				'locale'  => $locale,
			),
			self::API_URL
		);

		$response = wp_remote_get(
			$url,
			array(
				'timeout'             => 3,
				'limit_response_size' => 1048576,
			)
		);
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			// Fallback without locale.
			$url_fallback = add_query_arg( array( 'version' => $wp_version ), self::API_URL );
			$response     = wp_remote_get(
				$url_fallback,
				array(
					'timeout'             => 3,
					'limit_response_size' => 1048576,
				)
			);
			if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
				return false;
			}
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $body['checksums'] ) || ! is_array( $body['checksums'] ) ) {
			return false;
		}

		$checksums = $body['checksums'];
		if ( isset( $checksums[ $wp_version ] ) && is_array( $checksums[ $wp_version ] ) ) {
			$checksums = $checksums[ $wp_version ];
		} elseif ( 1 === count( $checksums ) && is_array( reset( $checksums ) ) ) {
			$checksums = reset( $checksums );
		}

		set_transient( $cache_key, $checksums, WEEK_IN_SECONDS );
		return self::core_only_checksums( $checksums );
	}
	/**
	 * Core only checksums.
	 *
	 * @param array $checksums Checksums.
	 */
	private static function core_only_checksums( array $checksums ) {
		return array_filter(
			$checksums,
			static function ( $hash, $path ) {
				return is_string( $path ) && is_string( $hash ) && preg_match( '/^[a-f0-9]{32}$/D', $hash ) &&
				0 !== strpos( $path, 'wp-content/' ) && ! preg_match( '#(^/|(^|/)\.{1,2}(/|$)|[\\\\\x00:])#', $path );
			},
			ARRAY_FILTER_USE_BOTH
		);
	}
	/**
	 * Get scan history.
	 */
	public static function get_scan_history() {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_history' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table identifier from the WordPress prefix; all dynamic values use prepare(). WordPress 5.3 has no %i placeholder.
		return $wpdb->get_results( "SELECT scan_date, total_files, clean_files, modified_files, missing_files, suspicious_files FROM {$table} ORDER BY scan_date DESC LIMIT 100", ARRAY_A );
	}
	/**
	 * Run full scan.
	 */
	public static function run_full_scan() {
		return GWQSH_Scan_Engine::run();
	}
	/**
	 * Get scan issues.
	 *
	 * @param array $filters Filters.
	 */
	/**
	 * Get scan issues with pagination support.
	 *
	 * @param array $filters Query filters.
	 * @return array Paginated array with items, total, page, per_page, pages.
	 */
	public static function get_scan_issues_paged( array $filters = array() ) {
		$filters['paginate'] = true;
		return self::get_scan_issues( $filters );
	}

	/**
	 * Get scan issues from database.
	 *
	 * When 'paginate' => true is in $filters, returns an associative array
	 * with 'items', 'total', 'page', 'per_page', 'pages'. Otherwise returns
	 * a flat array of issue rows for backward compatibility with tests and callers.
	 *
	 * @param array $filters Query filters.
	 * @return array Array of issue rows, or paginated structure if paginate=true.
	 */
	public static function get_scan_issues( array $filters = array() ) {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );

		$where        = array( 'is_resolved = 0' );
		$where_values = array();

		if ( ! empty( $filters['type'] ) ) {
			$allowed_types = array( 'Core', 'Plugin', 'Theme', 'Uploads', 'MU Plugin', 'Root / Config', 'Drop-in' );
			if ( in_array( $filters['type'], $allowed_types, true ) ) {
				$components = array(
					'MU Plugin'     => 'mu_plugin',
					'Root / Config' => 'config',
					'Drop-in'       => 'dropin',
				);
				if ( isset( $components[ $filters['type'] ] ) ) {
					$where[]        = "JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(evidence), evidence, '{}'), '$.component')) = %s";
					$where_values[] = $components[ $filters['type'] ];
				} else {
					$where[]        = 'file_type = %s';
					$where_values[] = $filters['type'];
				}
			}
		}
		if ( ! empty( $filters['status'] ) ) {
			$allowed_statuses = array( 'Modified', 'Missing', 'Suspicious' );
			if ( in_array( $filters['status'], $allowed_statuses, true ) ) {
				$where[]        = 'status = %s';
				$where_values[] = $filters['status'];
			}
		}
		if ( ! empty( $filters['severity'] ) ) {
			$allowed_severities = array( 'Critical', 'High', 'Medium', 'Low', 'Informational' );
			if ( in_array( $filters['severity'], $allowed_severities, true ) ) {
				$where[]        = 'evidence LIKE %s';
				$where_values[] = '%"severity":"' . $wpdb->esc_like( $filters['severity'] ) . '"%';
			}
		}
		if ( ! empty( $filters['search'] ) ) {
			$like           = '%' . $wpdb->esc_like( sanitize_text_field( $filters['search'] ) ) . '%';
			$where[]        = '(file_path LIKE %s OR details LIKE %s)';
			$where_values[] = $like;
			$where_values[] = $like;
		}

		$where_sql = implode( ' AND ', $where );

		// Sort field whitelist.
		$sort_map   = array(
			'date'     => 'detected_at',
			'path'     => 'file_path',
			'status'   => 'status',
			'type'     => 'file_type',
			'modified' => "CAST(JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(evidence), evidence, '{}'), '$.mtime')) AS UNSIGNED)",
			'score'    => "CAST(JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(evidence), evidence, '{}'), '$.score')) AS UNSIGNED)",
			'severity' => "FIELD(JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(evidence), evidence, '{}'), '$.severity')), 'Informational', 'Low', 'Medium', 'High', 'Critical')",
		);
		$sort_field = 'detected_at';
		if ( ! empty( $filters['sort'] ) && isset( $sort_map[ $filters['sort'] ] ) ) {
			$sort_field = $sort_map[ $filters['sort'] ];
		}
		$sort_dir = 'DESC';
		if ( ! empty( $filters['order'] ) && 'ASC' === strtoupper( $filters['order'] ) ) {
			$sort_dir = 'ASC';
		}

		$paginate = ! empty( $filters['paginate'] );

		if ( $paginate ) {
			// Count total matching.
			$count_sql = "SELECT COUNT(*) FROM {$table} WHERE {$where_sql}";
			if ( ! empty( $where_values ) ) {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
				$total = (int) $wpdb->get_var( $wpdb->prepare( $count_sql, $where_values ) );
			} else {
				// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
				$total = (int) $wpdb->get_var( $count_sql );
			}

			$per_page = GWQSH_Quarantine_Manager::DEFAULT_PAGE_SIZE;
			if ( ! empty( $filters['per_page'] ) ) {
				$per_page = GWQSH_Quarantine_Manager::validate_page_size( (int) $filters['per_page'] );
			}
			$pages  = max( 1, (int) ceil( $total / $per_page ) );
			$page   = min( $pages, max( 1, isset( $filters['page'] ) ? absint( $filters['page'] ) : 1 ) );
			$offset = ( $page - 1 ) * $per_page;

			$sql          = "SELECT id, file_path as path, file_type as type, status as st, details as det, evidence, detected_at as date FROM {$table} WHERE {$where_sql} ORDER BY {$sort_field} {$sort_dir}, id {$sort_dir} LIMIT %d OFFSET %d";
			$query_values = array_merge( $where_values, array( $per_page, $offset ) );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$results = $wpdb->get_results( $wpdb->prepare( $sql, $query_values ), ARRAY_A );
		} else {
			$limit        = isset( $filters['limit'] ) ? absint( $filters['limit'] ) : 500;
			$sql          = "SELECT id, file_path as path, file_type as type, status as st, details as det, evidence, detected_at as date FROM {$table} WHERE {$where_sql} ORDER BY {$sort_field} {$sort_dir}, id {$sort_dir} LIMIT %d";
			$query_values = array_merge( $where_values, array( $limit ) );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$results = $wpdb->get_results( $wpdb->prepare( $sql, $query_values ), ARRAY_A );
		}

		// Enrich results with parsed evidence.
		if ( $results ) {
			foreach ( $results as &$row ) {
				$ev                    = ! empty( $row['evidence'] ) ? json_decode( $row['evidence'], true ) : array();
				$row['severity']       = is_array( $ev ) && isset( $ev['severity'] ) ? $ev['severity'] : '';
				$row['confidence']     = is_array( $ev ) && isset( $ev['confidence'] ) ? $ev['confidence'] : '';
				$row['score']          = is_array( $ev ) && isset( $ev['score'] ) ? (int) $ev['score'] : 0;
				$row['component']      = is_array( $ev ) && isset( $ev['component'] ) ? $ev['component'] : strtolower( $row['type'] );
				$row['hash']           = is_array( $ev ) && isset( $ev['hash'] ) ? $ev['hash'] : '';
				$row['canonical_path'] = $row['path'];
				$row['display_path']   = GWQSH_Quarantine_Manager::display_path( $row['path'] );
				$key                   = GWQSH_Quarantine_Manager::path_key( $row['canonical_path'] );
				$row['can_quarantine'] = in_array( $row['st'], array( 'Modified', 'Suspicious' ), true ) && $key && is_file( $key ) && ! in_array( $key, array( GWQSH_Path_Guard::root() . '/wp-config.php', GWQSH_Path_Guard::root() . '/wp-load.php', GWQSH_Path_Guard::root() . '/wp-settings.php', GWQSH_Path_Guard::root() . '/wp-blog-header.php' ), true ) && 0 !== strpos( $key, rtrim( GWQSH_PATH, '/' ) . '/' );
				// Remove raw evidence from response to keep payloads small.
				unset( $row['evidence'] );
			}
			unset( $row );
		}

		if ( $paginate ) {
			return array(
				'items'    => $results ? $results : array(),
				'total'    => $total,
				'page'     => $page,
				'per_page' => $per_page,
				'pages'    => max( 1, (int) ceil( $total / $per_page ) ),
			);
		}

		return $results ? $results : array();
	}
	/**
	 * Get summary.
	 */
	public static function get_summary() {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$issues = $wpdb->get_results(
			"SELECT status, file_type, COUNT(*) as c FROM {$table} WHERE is_resolved = 0 GROUP BY status, file_type", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Validated or fixed plugin-owned identifier; dynamic values are prepared, and WordPress 5.3 has no identifier placeholder.
			ARRAY_A
		);

		$counts = array(
			'Modified'   => 0,
			'Missing'    => 0,
			'Suspicious' => 0,
		);

		$scope_counts = get_option( 'gwqsh_last_scan_scope_counts', array() );
		$breakdown    = array(
			'core-mod'  => 0,
			'core-miss' => 0,
			'core-ok'   => max( 0, (int) get_option( 'gwqsh_last_scan_core_total', 0 ) ),
			'pl-mod'    => 0,
			'pl-sus'    => 0,
			'pl-ok'     => (int) ( $scope_counts['Plugin'] ?? 0 ),
			'th-mod'    => 0,
			'th-sus'    => 0,
			'th-ok'     => (int) ( $scope_counts['Theme'] ?? 0 ),
			'up-php'    => 0,
			'up-ok'     => (int) ( $scope_counts['Uploads'] ?? 0 ),
		);

		if ( $issues ) {
			foreach ( $issues as $row ) {
				$st = $row['status'];
				$tp = $row['file_type'];
				$c  = (int) $row['c'];

				if ( isset( $counts[ $st ] ) ) {
					$counts[ $st ] += $c;
				}

				if ( 'Core' === $tp && 'Modified' === $st ) {
					$breakdown['core-mod'] += $c;
					$breakdown['core-ok']   = max( 0, $breakdown['core-ok'] - $c );
				} elseif ( 'Core' === $tp && 'Missing' === $st ) {
					$breakdown['core-miss'] += $c;
					$breakdown['core-ok']    = max( 0, $breakdown['core-ok'] - $c );
				} elseif ( 'Plugin' === $tp && 'Modified' === $st ) {
					$breakdown['pl-mod'] += $c;
					$breakdown['pl-ok']   = max( 0, $breakdown['pl-ok'] - $c );
				} elseif ( 'Plugin' === $tp && 'Suspicious' === $st ) {
					$breakdown['pl-sus'] += $c;
					$breakdown['pl-ok']   = max( 0, $breakdown['pl-ok'] - $c );
				} elseif ( 'Theme' === $tp && 'Modified' === $st ) {
					$breakdown['th-mod'] += $c;
					$breakdown['th-ok']   = max( 0, $breakdown['th-ok'] - $c );
				} elseif ( 'Theme' === $tp && 'Suspicious' === $st ) {
					$breakdown['th-sus'] += $c;
					$breakdown['th-ok']   = max( 0, $breakdown['th-ok'] - $c );
				} elseif ( 'Uploads' === $tp && 'Suspicious' === $st ) {
					$breakdown['up-php'] += $c;
					$breakdown['up-ok']   = max( 0, $breakdown['up-ok'] - $c );
				}
			}
		}

		$omissions = (array) get_option( 'gwqsh_last_scan_omissions', array() );
		foreach ( array(
			'Core'    => 'core-ok',
			'Plugin'  => 'pl-ok',
			'Theme'   => 'th-ok',
			'Uploads' => 'up-ok',
		) as $scope => $key ) {
			$breakdown[ $key ] = max( 0, $breakdown[ $key ] - (int) ( $omissions['scopes'][ $scope ] ?? 0 ) );
		}
		$breakdown['up-sus'] = $breakdown['up-php'];
		$upload_php_total    = get_option( 'gwqsh_last_scan_upload_php_total', null );
		$breakdown['up-php'] = null === $upload_php_total ? null : (int) $upload_php_total;

		$total_files  = (int) get_option( 'gwqsh_last_scan_total', 0 );
		$issues_count = $counts['Modified'] + $counts['Missing'] + $counts['Suspicious'];
		$clean_files  = max( 0, $total_files - $issues_count - (int) ( $omissions['count'] ?? 0 ) );

		$last_date = get_option( 'gwqsh_last_scan_time', '' );
		$last_dur  = get_option( 'gwqsh_last_scan_duration', 0 );
		$coverage  = (array) get_option( 'gwqsh_scan_health', array() );

		return array(
			'quarantined'        => count( GWQSH_Quarantine_Manager::list_quarantined() ),
			'quarantine_damaged' => count(
				array_filter(
					GWQSH_Quarantine_Manager::list_quarantined(),
					static function ( $record ) {
						return empty( $record['present'] ); }
				)
			),
			'total'              => $total_files,
			'clean'              => $clean_files,
			'uninspected'        => (int) ( $omissions['count'] ?? 0 ),
			'omitted_files'      => $omissions['files'] ?? array(),
			'clean_percent'      => $total_files ? round( $clean_files / $total_files * 100, 1 ) : 0,
			'scan_running'       => (bool) get_option( 'gwqsh_scan_progress', false ),
			'protection'         => ! GWQSH_Settings::get( 'status', true ) ? 'Disabled' : ( $issues_count || $coverage ? 'Attention Required' : 'Monitoring' ),
			'coverage'           => $coverage,
			'modified'           => $counts['Modified'],
			'missing'            => $counts['Missing'],
			'suspicious'         => $counts['Suspicious'],
			'last_date'          => $last_date ? GWQSH_Time::format( $last_date ) : '',
			'duration'           => $last_dur,
			'breakdown'          => $breakdown,
			'scope_counts'       => get_option(
				'gwqsh_last_scan_scope_counts',
				array(
					'Plugin'  => 0,
					'Theme'   => 0,
					'Uploads' => 0,
				)
			),
		);
	}
	/**
	 * Resolve scan path.
	 *
	 * @param mixed $relative_path Relative path.
	 * @param mixed $required_type Required type.
	 */
	private static function resolve_scan_path( $relative_path, $required_type = '' ) {
		global $wpdb;
		if ( ! is_string( $relative_path ) || '' === $relative_path || false !== strpos( $relative_path, "\0" ) || false !== strpos( $relative_path, '\\' ) ) {
			return false;
		}
		$relative = ltrim( $relative_path, '/' );
		if ( '' === $relative || preg_match( '#(^|/)\.{1,2}(/|$)#', $relative ) || false !== strpos( $relative, ':' ) ) {
			return false;
		}
		if ( 0 === strpos( $relative, '@' ) ) {
			$full = GWQSH_Scan_Engine::resolve_label( $relative );
			if ( ! $full ) {
				return false;
			}
			$root = realpath( dirname( $full ) );
		} else {
			$full = ABSPATH . $relative;
			$root = realpath( ABSPATH );
		}
		$dir = dirname( $full );
		while ( ! file_exists( $dir ) && dirname( $dir ) !== $dir && $dir !== $root ) {
			$dir = dirname( $dir );
		}
		$cursor = $full;
		while ( dirname( $cursor ) !== $cursor ) {
			if ( is_link( $cursor ) ) {
				return false;
			}
			$cursor = dirname( $cursor );
		}
		$parent = realpath( $dir );
		if ( ! $root || ! $parent || ( $parent !== $root && 0 !== strpos( $parent, $root . DIRECTORY_SEPARATOR ) ) || is_link( $full ) ) {
			return false;
		}
		if ( file_exists( $full ) ) {
			$real = realpath( $full );
			if ( ! $real || 0 !== strpos( $real, $root . DIRECTORY_SEPARATOR ) || ! is_file( $real ) ) {
				return false;
			}
		}
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table identifier from the WordPress prefix.
		$type = $wpdb->get_var( $wpdb->prepare( "SELECT file_type FROM {$table} WHERE is_resolved = 0 AND (file_path = %s OR file_path = %s) LIMIT 1", '/' . $relative, $relative ) );
		if ( ! $type || ( $required_type && $type !== $required_type ) ) {
			return false;
		}
		return array( $relative, $full, $type );
	}
	/**
	 * Restore core file.
	 *
	 * @param mixed $relative_path Relative path.
	 */
	public static function restore_core_file( $relative_path ) {
		global $wp_version;
		$resolved = self::resolve_scan_path( $relative_path, 'Core' );
		if ( ! $resolved ) {
			return new WP_Error( 'invalid_path', 'Invalid core file path' );
		}
		list( $clean_path, $full_path ) = $resolved;
		$checksums                      = self::get_core_checksums();
		if ( ! is_array( $checksums ) || ! isset( $checksums[ $clean_path ] ) ) {
			return new WP_Error( 'invalid_core_file', 'File is not in official WordPress checksums.' );
		}

		// Fetch official file from WordPress SVN/Git CDN.
		$official_url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$clean_path}";
		$resp         = wp_remote_get(
			$official_url,
			array(
				'timeout'             => 3,
				'limit_response_size' => 1048576,
			)
		);

		if ( is_wp_error( $resp ) || 200 !== wp_remote_retrieve_response_code( $resp ) ) {
			return new WP_Error( 'fetch_failed', 'Could not fetch clean file from WordPress.org' );
		}

		$clean_content = wp_remote_retrieve_body( $resp );
		if ( md5( $clean_content ) !== $checksums[ $clean_path ] ) {
			return new WP_Error( 'checksum_mismatch', 'Downloaded file failed checksum verification.' );
		}

		// Backup existing file if present (best-effort backup).
		if ( file_exists( $full_path ) ) {
			if ( ! self::quarantine_file( $clean_path, true ) ) {
				return new WP_Error( 'backup_failed', 'Original could not be preserved; restoration stopped.' );
			}
		}

		// Ensure parent directory exists.
		if ( ! is_dir( dirname( $full_path ) ) ) {
			wp_mkdir_p( dirname( $full_path ) );
		}

		if ( ! GWQSH_Quarantine_Manager::replace_verified( $relative_path, $clean_content, file_exists( $full_path ) ? hash_file( 'sha256', $full_path ) : '' ) ) {
			return new WP_Error( 'write_failed', 'Could not restore the core file. Please check file permissions.' );
		}
		self::mark_as_reviewed( $relative_path );

		GWQSH_Quarantine_Manager::recheck_restored( $relative_path );
		GWQSH_Activity_Logger::log( 'Core file restored', "Restored official clean copy for {$clean_path}", 'System' );
		return true;
	}
	/**
	 * Quarantine file.
	 *
	 * @param mixed $relative_path Relative path.
	 * @param mixed $is_backup Is backup.
	 */
	public static function quarantine_file( $relative_path, $is_backup = false ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gwqsh_scan_results';
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed plugin table; dynamic paths are prepared.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT id,file_type,evidence FROM {$table} WHERE is_resolved=0 AND file_path IN (%s,%s) ORDER BY id DESC LIMIT 1", '/' . ltrim( $relative_path, '/' ), ltrim( $relative_path, '/' ) ), ARRAY_A );
		if ( ! $row ) {
			return false;
		}
		$evidence = json_decode( $row['evidence'] ?? '', true );
		if ( empty( $evidence['hash'] ) ) {
			$validated = GWQSH_Path_Guard::validate( $relative_path, true );
			if ( ! $validated ) {
				return false; }
			$analysis = GWQSH_Scan_Engine::inspect( $validated['canonical'], $row['file_type'], array() );
			if ( ! empty( $analysis['error'] ) || ! empty( $analysis['partial'] ) || empty( $analysis['hash'] ) ) {
				return false; }
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$wpdb->update(
				$table,
				array( 'evidence' => wp_json_encode( $analysis ) ),
				array(
					'id'          => (int) $row['id'],
					'is_resolved' => 0,
				)
			);
		}
		return ! is_wp_error( GWQSH_Quarantine_Manager::quarantine_by_finding( (int) $row['id'], $is_backup ) );
	}

	/** Render the complete bounded text comparison, with old/new line numbers.
	 *
	 * @param string $old Trusted content.
	 * @param string $current Current content.
	 * @return string Escaped comparison HTML.
	 */
	public static function render_complete_diff( $old, $current ) {
		require_once ABSPATH . WPINC . '/Text/Diff.php';
		$old_lines     = '' === $old ? array() : explode( "\n", $old );
		$current_lines = '' === $current ? array() : explode( "\n", $current );
		if ( "\n" === substr( $old, -1 ) ) {
			array_pop( $old_lines ); }
		if ( "\n" === substr( $current, -1 ) ) {
			array_pop( $current_lines ); }
		$diff        = new Text_Diff( 'auto', array( $old_lines, $current_lines ) );
		$old_num     = 1;
		$current_num = 1;
		$added       = 0;
		$deleted     = 0;
		$rows        = array();
		foreach ( $diff->getDiff() as $edit ) {
			if ( $edit instanceof Text_Diff_Op_copy ) {
				foreach ( $edit->orig as $line ) {
					$rows[] = array(
						'old'  => $old_num,
						'new'  => $current_num,
						'kind' => '',
						'html' => self::diff_line( '', $old_num++, $current_num++, ' ', $line ),
					);
				}
				continue;
			}
			foreach ( is_array( $edit->orig ) ? $edit->orig : array() as $line ) {
				$rows[] = array(
					'old'  => $old_num,
					'new'  => $current_num,
					'kind' => 'del',
					'html' => self::diff_line( $edit instanceof Text_Diff_Op_change ? 'del gwqsh-modified' : 'del', $old_num++, '', '-', $line ),
				);
				++$deleted;
			}
			foreach ( is_array( $edit->final ) ? $edit->final : array() as $line ) {
				$rows[] = array(
					'old'  => $old_num,
					'new'  => $current_num,
					'kind' => 'add',
					'html' => self::diff_line( $edit instanceof Text_Diff_Op_change ? 'add gwqsh-modified' : 'add', '', $current_num++, '+', $line ),
				);
				++$added;
			}
		}
		$ranges = array();
		foreach ( $rows as $i => $row ) {
			if ( ! $row['kind'] ) {
				continue; }
			$start = max( 0, $i - 3 );
			$end   = min( count( $rows ) - 1, $i + 3 );
			$last  = count( $ranges ) - 1;
			if ( $last >= 0 && $start <= $ranges[ $last ][1] + 1 ) {
				$ranges[ $last ][1] = $end;
			} else {
				$ranges[] = array( $start, $end );
			}
		}
		$header = '<div class="diff-header">--- Trusted / Old Version<br>+++ Current / New Version</div>';
		$hunks  = '';
		foreach ( $ranges as $range ) {
			$lines     = array_slice( $rows, $range[0], $range[1] - $range[0] + 1 );
			$old_count = 0;
			$new_count = 0;
			foreach ( $lines as $line ) {
				$old_count += 'add' !== $line['kind'] ? 1 : 0;
				$new_count += 'del' !== $line['kind'] ? 1 : 0;
			}
			$hunks .= '<div class="diff-header">@@ -' . ( $old_count ? $lines[0]['old'] : max( 0, $lines[0]['old'] - 1 ) ) . ',' . $old_count . ' +' . ( $new_count ? $lines[0]['new'] : max( 0, $lines[0]['new'] - 1 ) ) . ',' . $new_count . ' @@</div>' . implode( '', array_column( $lines, 'html' ) );
		}
		$notes = '';
		if ( ( "\n" === substr( $old, -1 ) ) !== ( "\n" === substr( $current, -1 ) ) ) {
			$notes .= '<p class="diff-summary">Final newline ' . ( "\n" === substr( $current, -1 ) ? 'added' : 'removed' ) . '.</p>';
		}
		if ( ( false !== strpos( $old, "\r\n" ) ) !== ( false !== strpos( $current, "\r\n" ) ) ) {
			$notes .= '<p class="diff-summary">Line endings differ: old ' . ( false !== strpos( $old, "\r\n" ) ? 'CRLF' : 'LF' ) . ' → new ' . ( false !== strpos( $current, "\r\n" ) ? 'CRLF' : 'LF' ) . '.</p>';
		}
		$summary = '<p class="diff-summary">' . $added . ' added lines · ' . $deleted . ' removed lines · All change hunks</p>';
		return $summary . $notes . ( $hunks ? '<div class="git-diff" role="region" tabindex="0" aria-label="All file changes">' . $header . $hunks . '</div>' : '<p>No line content changes.</p>' ) . '<details class="diff-full"><summary>Show complete old / new file with unchanged lines</summary><div class="git-diff" role="region" tabindex="0" aria-label="Complete file comparison">' . $header . implode( '', array_column( $rows, 'html' ) ) . '</div></details>';
	}

	/** Format an escaped line of the comparison.
	 *
	 * @param string $change_class Change class.
	 * @param mixed  $old Old line number.
	 * @param mixed  $current New line number.
	 * @param string $sign Change marker.
	 * @param string $line Source line.
	 * @return string HTML.
	 */
	private static function diff_line( $change_class, $old, $current, $sign, $line ) {
		return '<div class="diff-line ' . esc_attr( $change_class ) . '"><span class="old-ln">' . esc_html( $old ) . '</span><span class="new-ln">' . esc_html( $current ) . '</span><span>' . esc_html( $sign ) . '</span><code>' . esc_html( $line ) . '</code></div>';
	}

	/** Get a verified old/current comparison for an active finding.
	 *
	 * @param string $relative_path Finding path.
	 * @return string|WP_Error Comparison or validation error.
	 */
	public static function get_file_diff( $relative_path ) {
		global $wp_version;
		$resolved = self::resolve_scan_path( $relative_path );
		if ( ! $resolved ) {
			return new WP_Error( 'invalid_path', 'This file is not an unresolved scan finding.' );
		}
		list( $clean_path, $full_path ) = $resolved;
		$limit                          = 524288;
		if ( 'Core' !== $resolved[2] ) {
			$trusted   = GWQSH_Quarantine_Manager::trusted_copy( $relative_path );
			$old       = array();
			$canonical = GWQSH_Path_Guard::validate( $relative_path, false );
			foreach ( GWQSH_Scan_Engine::load( 'gwqsh_file_baseline' ) as $label => $record ) {
				$path = GWQSH_Path_Guard::validate( $label, false );
				if ( $canonical && $path && $canonical['canonical'] === $path['canonical'] ) {
					$old = $record;
					break;
				}
			}
			$exists      = is_file( $full_path ) && is_readable( $full_path );
			$hash        = $exists ? hash_file( 'sha256', $full_path ) : 'Unavailable';
			$info        = '<div class="diff-meta"><div><b>Trusted / Old</b><code>SHA-256: ' . esc_html( $old['hash'] ?? 'Unavailable' ) . '</code>Size: ' . esc_html( $old['size'] ?? 'Unavailable' ) . ' bytes</div><div><b>Current / New</b><code>SHA-256: ' . esc_html( $hash ) . '</code>Size: ' . esc_html( $exists ? filesize( $full_path ) : 'Unavailable' ) . ' bytes</div></div>';
			$text        = $exists && filesize( $full_path ) <= $limit && preg_match( '/\.(php|js|css|txt|json|html?|xml|svg|md|ini|ya?ml|sql)$/i', $full_path );
			$new_content = $text ? file_get_contents( $full_path ) : false;
			if ( ! $text || false === $new_content || false !== strpos( $new_content, "\0" ) ) {
				return $info . '<p class="muted">Text comparison is unavailable for binary files, unreadable files, or files above 512 KiB. Compare the complete hashes and sizes above.</p>';
			}
			if ( ! $trusted ) {
				return $info . '<p class="muted">A verified old copy was not retained, so the previous content cannot be reconstructed from its hash. Restore and comparison require a verified trusted copy.</p><details><summary>View complete current source</summary><pre class="review-source">' . esc_html( $new_content ) . '</pre></details>';
			}
			if ( filesize( $trusted['source'] ) > $limit ) {
				return $info . '<p class="muted">The trusted copy exceeds the 512 KiB comparison limit. Compare it offline.</p>';
			}
			$old_content = file_get_contents( $trusted['source'] );
		} else {
			$info      = '';
			$checksums = self::get_core_checksums();
			if ( ! is_array( $checksums ) || ! isset( $checksums[ $clean_path ] ) ) {
				return new WP_Error( 'no_original', 'No official baseline exists for this file.' );
			}
			if ( file_exists( $full_path ) && ( ! is_readable( $full_path ) || filesize( $full_path ) > $limit ) ) {
				return new WP_Error( 'large_file', 'This file is too large or unreadable. Compare it offline.' );
			}
			$new_content = file_exists( $full_path ) ? file_get_contents( $full_path ) : '';
			$resp        = wp_remote_get(
				"https://core.svn.wordpress.org/tags/{$wp_version}/{$clean_path}",
				array(
					'timeout'             => 15,
					'limit_response_size' => $limit + 1,
				)
			);
			$old_content = ( ! is_wp_error( $resp ) && 200 === wp_remote_retrieve_response_code( $resp ) ) ? wp_remote_retrieve_body( $resp ) : false;
			if ( false === $old_content || strlen( $old_content ) > $limit || md5( $old_content ) !== $checksums[ $clean_path ] ) {
				return new WP_Error( 'baseline_unavailable', 'Could not retrieve a bounded, checksum-verified official file for comparison.' );
			}
		}
		if ( false === $old_content || false === $new_content || false !== strpos( $old_content . $new_content, "\0" ) || substr_count( $old_content, "\n" ) > 5000 || substr_count( $new_content, "\n" ) > 5000 ) {
			return $info . '<p class="muted">Binary content or files above 5,000 lines require offline comparison. No partial diff is shown.</p>';
		}
		return $info . self::render_complete_diff( $old_content, $new_content );
	}

	/** Review an explicitly selected page without accepting file contents as trusted.
	 *
	 * @param array $ids Finding IDs.
	 * @return array|WP_Error Review counts.
	 */
	public static function review_findings( $ids ) {
		global $wpdb;
		$ids = array_values( array_unique( array_map( 'absint', $ids ) ) );
		if ( ! $ids || count( $ids ) > 500 || in_array( 0, $ids, true ) ) {
			return new WP_Error( 'invalid_ids', 'Select 1–500 valid finding IDs.' );
		}
		$table = $wpdb->prefix . 'gwqsh_scan_results';
		$slots = implode( ',', array_fill( 0, count( $ids ), '%d' ) );
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed plugin table and generated %d slots; all IDs are prepared.
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$updated = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET is_resolved=1 WHERE is_resolved=0 AND id IN ({$slots})", $ids ) );
		if ( false === $updated ) {
			return new WP_Error( 'review_failed', 'Could not save the review. Retry shortly.' );
		}
		return array(
			'reviewed' => (int) $updated,
			'skipped'  => count( $ids ) - (int) $updated,
		);
	}

	/**
	 * Mark as reviewed.
	 *
	 * @param mixed $relative_path Relative path.
	 */
	public static function mark_as_reviewed( $relative_path ) {
		global $wpdb;
		if ( ! self::resolve_scan_path( $relative_path ) ) {
			return false; }
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
		$path1 = '/' . ltrim( $relative_path, '/' );
		$path2 = ltrim( $relative_path, '/' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,PluginCheck.Security.DirectDB.UnescapedDBParameter
		$wpdb->query(
			$wpdb->prepare(
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed plugin-owned table identifier from the WordPress prefix; all dynamic values use prepare(). WordPress 5.3 has no %i placeholder.
				"UPDATE {$table} SET is_resolved = 1 WHERE file_path = %s OR file_path = %s",
				$path1,
				$path2
			)
		);
		return true;
	}
}
