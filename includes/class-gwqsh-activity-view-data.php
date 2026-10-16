<?php
/** Activity screen queries and protected audit workflows.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Uses the existing local-time audit table; never rewrites historical records. */
final class GWQSH_Activity_View_Data {
	const LOGIN_EVENTS = array( 'Login successful', 'Login attempt blocked', 'User logged out', 'Login blocked by lockout', 'XML-RPC login blocked', 'IP locked out', 'IP unlocked', '2FA verification failed', 'Backup code used' );
	const FILE_EVENTS  = array( 'File scan completed', 'File quarantined', 'File restored', 'File restored from quarantine', 'Baseline updated', 'Core file restored', 'Restore backup stored', 'Restore cleanup requires review', 'Quarantine item deleted', 'Quarantine cleared', 'Bulk quarantine', 'Trusted file restored', 'File repaired', 'Integrity baseline changed' );
	const GROUPS       = array(
		'Security' => 'Security & Login',
		'User'     => 'User Actions',
		'File'     => 'File Changes',
		'System'   => 'System Events',
		'Other'    => 'Other Events',
	);

	/** Register a POST-only export, with no public counterpart. */
	public static function init() {
		add_action( 'admin_post_gwqsh_activity_export', array( __CLASS__, 'export' ) );
		add_action( 'gwqsh_activity_search_backfill', array( __CLASS__, 'backfill_search' ) );
		if ( ! get_option( 'gwqsh_activity_search_ready', false ) ) {
			self::backfill_search();
		}
	}
	/** Populate only derived searchable text, in bounded migration batches. Original records remain intact. */
	public static function backfill_search() {
		global $wpdb;
		$table  = $wpdb->prefix . 'gwqsh_activity_log';
		$cursor = (int) get_option( 'gwqsh_activity_search_cursor', 0 );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT id,details FROM {$table} WHERE id > %d AND safe_details IS NULL ORDER BY id LIMIT 250", $cursor ), ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB -- Fixed plugin table and prepared cursor; bounded one-time derived-field migration.
		if ( $wpdb->last_error ) {
			return; }
		foreach ( $rows as $row ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			if ( false === $wpdb->update( $table, array( 'safe_details' => self::safe_text( $row['details'] ) ), array( 'id' => (int) $row['id'] ), array( '%s' ), array( '%d' ) ) ) {
				return; } // phpcs:ignore WordPress.DB -- Migration-safe derived field only; original details are never rewritten.
			$cursor = (int) $row['id'];
		}
		update_option( 'gwqsh_activity_search_cursor', $cursor, false );
		if ( 250 > count( $rows ) ) {
			update_option( 'gwqsh_activity_search_ready', true, false ); } elseif ( ! wp_next_scheduled( 'gwqsh_activity_search_backfill' ) ) {
			wp_schedule_single_event( time() + MINUTE_IN_SECONDS, 'gwqsh_activity_search_backfill' ); }
	}
	/** Central exact-event classification, not filename or description heuristics. */
	public static function category_sql() {
		global $wpdb;
		$names = implode( ',', array_fill( 0, count( self::FILE_EVENTS ), '%s' ) );
		// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		return $wpdb->prepare( "CASE WHEN event_name IN ({$names}) THEN 'File' WHEN event_type='Security' OR event_name IN ('Login successful','Login attempt blocked','User logged out','Login blocked by lockout','XML-RPC login blocked','IP locked out','IP unlocked','2FA verification failed','Backup code used') THEN 'Security' WHEN event_type='User' THEN 'User' WHEN event_type IN ('System','Plugin') THEN 'System' ELSE 'Other' END", self::FILE_EVENTS ); // phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
	}
	/** Conservatively redact legacy descriptions as well as new logger inputs.
	 *
	 * @param string $value Text to redact.
	 */
	public static function safe_text( $value ) {
		$value = is_scalar( $value ) ? (string) $value : '';
		// A description with credential-bearing fields is withheld as a whole: partial redaction can leak multiline or nested values.
		if ( preg_match( '/(?:password|passwd|pwd|secret|token|nonce|cookie|authorization|backup[ _-]*codes?|recovery[ _-]*codes?|private[ _-]*key|challenge|totp(?:[ _-]*(?:code|value))?|session(?:[ _-]*(?:id|token|cookie))?|(?:2fa|otp|one[ _-]*time)[ _-]*(?:code|value|secret)|gwqsh_2fa_code)\s*["\x27]?\s*[:=]|\b(?:Bearer|Basic)\s+[A-Za-z0-9+\/=._-]+|-----BEGIN .*PRIVATE KEY-----/i', $value ) ) {
			return '[Sensitive authentication data withheld]';
		}
		return sanitize_textarea_field( substr( $value, 0, 8192 ) );
	}
	/** Validate bounded filters. Dates are site dates because existing storage is site-local.
	 *
	 * @param array $input Requested filters.
	 */
	public static function filters( array $input ) {
		foreach ( $input as $value ) {
			if ( ! is_scalar( $value ) ) {
				return new WP_Error( 'filter', 'Invalid filter format.' );
			}
		}
		$f = array();
		foreach ( array( 'category', 'event', 'user', 'ip', 'severity', 'search', 'start', 'end' ) as $key ) {
			$f[ $key ] = sanitize_text_field( substr( (string) ( $input[ $key ] ?? '' ), 0, 'search' === $key ? 200 : 100 ) );
		}
		$f['days'] = (int) ( $input['days'] ?? 30 );
		if ( ! in_array( $f['days'], array( 1, 7, 30, 90, 365 ), true ) || ( $f['category'] && ! isset( self::GROUPS[ $f['category'] ] ) && 'Login' !== $f['category'] ) || ! in_array( $f['severity'], array( '', 'unrecorded' ), true ) ) {
			return new WP_Error( 'filter', 'Choose a supported filter.' );
		}
		if ( $f['ip'] && ! filter_var( $f['ip'], FILTER_VALIDATE_IP ) ) {
			return new WP_Error( 'ip', 'Enter a valid IPv4 or IPv6 address.' );
		}
		$today = current_datetime()->format( 'Y-m-d' );
		if ( $f['start'] || $f['end'] ) {
			foreach ( array( 'start', 'end' ) as $key ) {
				$d = DateTimeImmutable::createFromFormat( '!Y-m-d', $f[ $key ], wp_timezone() );
				if ( ! $d || $d->format( 'Y-m-d' ) !== $f[ $key ] || $f[ $key ] > $today ) {
					return new WP_Error( 'date', 'Enter both valid dates, no later than today.' );
				}
			}
			if ( $f['start'] > $f['end'] || ( new DateTimeImmutable( $f['start'], wp_timezone() ) )->diff( new DateTimeImmutable( $f['end'], wp_timezone() ) )->days > 365 ) {
				return new WP_Error( 'date', 'Start must precede end; choose at most 366 calendar days.' );
			}
		} else {
			$f['start'] = current_datetime()->modify( '-' . ( $f['days'] - 1 ) . ' days' )->format( 'Y-m-d' );
			$f['end']   = $today;
		}
		$f['from'] = $f['start'] . ' 00:00:00';
		$f['to']   = ( new DateTimeImmutable( $f['end'], wp_timezone() ) )->modify( '+1 day' )->format( 'Y-m-d 00:00:00' );
		return $f;
	}
	/** Shared prepared predicate for table and export.
	 *
	 * @param array $f Validated filters.
	 */
	public static function where( array $f ) {
		global $wpdb;
		$sql = $wpdb->prepare( 'event_time >= %s AND event_time < %s', $f['from'], $f['to'] );
		if ( 'Login' === $f['category'] ) {
			$sql .= ' AND ' . $wpdb->prepare( 'event_name IN (' . implode( ',', array_fill( 0, count( self::LOGIN_EVENTS ), '%s' ) ) . ')', self::LOGIN_EVENTS );
		} elseif ( $f['category'] ) {
			$sql .= $wpdb->prepare( ' AND (' . self::category_sql() . ') = %s', $f['category'] ); // phpcs:ignore WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		}
		foreach ( array(
			'event' => 'event_name',
			'user'  => 'user_login',
		) as $key => $column ) {
			if ( '' !== $f[ $key ] ) {
				$sql .= $wpdb->prepare( " AND {$column} = %s", $f[ $key ] ); // phpcs:ignore WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
			}
		}
		if ( $f['ip'] ) {
			$sql .= $wpdb->prepare( ' AND (ip_address = %s OR INET6_ATON(ip_address) = INET6_ATON(%s))', $f['ip'], $f['ip'] );
		}
		if ( $f['search'] ) {
			$like = '%' . $wpdb->esc_like( $f['search'] ) . '%';
			// Search only the redacted derivative; raw legacy descriptions are excluded.
			$sql .= $wpdb->prepare( ' AND (event_name LIKE %s OR safe_details LIKE %s OR user_login LIKE %s OR ip_address LIKE %s)', $like, $like, $like, $like );
		}
		return $sql;
	}
	/** Sanitize one record; original type is retained alongside the display group.
	 *
	 * @param array $row Stored row.
	 */
	public static function record( array $row ) {
		foreach ( array( 'event_name', 'event_type', 'user_login', 'ip_address', 'details' ) as $key ) {
			$row[ $key ] = self::safe_text( $row[ $key ] );
		}
		unset( $row['safe_details'] );
		$row['id']           = (int) $row['id'];
		$d                   = DateTimeImmutable::createFromFormat( 'Y-m-d H:i:s', $row['event_time'], wp_timezone() );
		$row['display_time'] = $d ? wp_date( 'M j, g:i A', $d->getTimestamp(), wp_timezone() ) : 'Unknown time';
		$row['timestamp']    = $d ? $d->format( DATE_ATOM ) : '';
		$row['severity']     = 'Not recorded';
		$row['badge']        = in_array( $row['event_name'], self::LOGIN_EVENTS, true ) ? 'Login' : ( self::GROUPS[ $row['category'] ] ?? 'Other Events' );
		return $row;
	}
	/** Aggregate a bounded window with one grouped query.
	 *
	 * @param string $from Inclusive local timestamp.
	 * @param string $to Exclusive local timestamp.
	 */
	public static function counts( $from, $to ) {
		global $wpdb;
		$table  = $wpdb->prefix . 'gwqsh_activity_log';
		$counts = array_fill_keys( array_keys( self::GROUPS ), 0 );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$rows   = $wpdb->get_results( $wpdb->prepare( 'SELECT ' . self::category_sql() . " AS category, COUNT(*) AS n FROM {$table} WHERE event_time >= %s AND event_time < %s GROUP BY category", $from, $to ), ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Activity statistics could not be loaded.' ); }
		foreach ( $rows as $row ) {
			$counts[ $row['category'] ] = (int) $row['n'];
		}
		return $counts;
	}
	/** Main protected, paginated snapshot.
	 *
	 * @param array $input Requested filters and report options.
	 */
	public static function get( array $input = array() ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'permission', 'Permission denied.' );
		}
		global $wpdb;
		$f = self::filters( $input );
		if ( is_wp_error( $f ) ) {
			return $f;
		}
		$table = $wpdb->prefix . 'gwqsh_activity_log';
		$where = self::where( $f );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Activity count could not be loaded.' ); }
		$pages = max( 1, (int) ceil( $total / 10 ) );
		$page  = min( $pages, max( 1, (int) ( $input['page_num'] ?? 1 ) ) );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$rows  = $wpdb->get_results( 'SELECT *, ' . self::category_sql() . " AS category FROM {$table} WHERE {$where} ORDER BY event_time DESC, id DESC" . $wpdb->prepare( ' LIMIT 10 OFFSET %d', ( $page - 1 ) * 10 ), ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Activity records could not be loaded.' );
		}
		$result = array(
			'items'        => array_map( array( __CLASS__, 'record' ), $rows ),
			'total'        => $total,
			'pages'        => $pages,
			'page'         => $page,
			'filters'      => $f,
			'timezone'     => wp_timezone_string(),
			'search_ready' => (bool) get_option( 'gwqsh_activity_search_ready', false ),
		);
		if ( empty( $input['overview'] ) ) {
			return $result;
		}
		$now                = current_datetime();
		$until              = $now->modify( '+1 second' );
		$result['counts']   = self::counts( $until->modify( '-30 days' )->format( 'Y-m-d H:i:s' ), $until->format( 'Y-m-d H:i:s' ) );
		$result['previous'] = self::counts( $until->modify( '-60 days' )->format( 'Y-m-d H:i:s' ), $until->modify( '-30 days' )->format( 'Y-m-d H:i:s' ) );
		if ( is_wp_error( $result['counts'] ) ) {
			return $result['counts']; }
		if ( is_wp_error( $result['previous'] ) ) {
			return $result['previous']; }
		$days = in_array( (int) ( $input['chart_days'] ?? 7 ), array( 7, 30, 90 ), true ) ? (int) ( $input['chart_days'] ?? 7 ) : 7;
		$from = $now->modify( '-' . ( $days - 1 ) . ' days' )->format( 'Y-m-d 00:00:00' );
		$to   = $now->modify( '+1 day' )->format( 'Y-m-d 00:00:00' );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$rows = $wpdb->get_results( $wpdb->prepare( 'SELECT DATE(event_time) AS day, ' . self::category_sql() . " AS category, COUNT(*) AS n FROM {$table} WHERE event_time >= %s AND event_time < %s GROUP BY day, category", $from, $to ), ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Activity chart could not be loaded.' ); }
		$chart  = array(
			'labels' => array(),
			'dates'  => array(),
			'series' => array_fill_keys( array_keys( self::GROUPS ), array() ),
		);
		$lookup = array();
		foreach ( $rows as $row ) {
			$lookup[ $row['day'] ][ $row['category'] ] = (int) $row['n'];
		}
		for ( $i = $days - 1; $i >= 0; --$i ) {
			$d                 = $now->modify( "-{$i} days" );
			$day               = $d->format( 'Y-m-d' );
			$chart['labels'][] = $d->format( 'M j' );
			$chart['dates'][]  = $day;
			foreach ( self::GROUPS as $key => $label ) {
				$chart['series'][ $key ][] = $lookup[ $day ][ $key ] ?? 0;
			}
		}
		$result['chart']   = $chart;
		$result['options'] = array();
		foreach ( array( 'user_login', 'ip_address' ) as $column ) {
			// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$result['options'][ $column ] = array_map( array( __CLASS__, 'safe_text' ), $wpdb->get_col( $wpdb->prepare( "SELECT DISTINCT {$column} FROM {$table} WHERE event_time >= %s ORDER BY {$column} LIMIT 200", $now->modify( '-365 days' )->format( 'Y-m-d H:i:s' ) ) ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
			if ( $wpdb->last_error ) {
				return new WP_Error( 'database', 'Activity filter options could not be loaded.' ); }
		}
		$result['options']['ip_address'] = array_values(
			array_filter(
				$result['options']['ip_address'],
				static function ( $ip ) {
					return (bool) filter_var( $ip, FILTER_VALIDATE_IP );
				}
			)
		);
		return $result;
	}
	/** Mitigate formula injection, including leading whitespace/control characters.
	 *
	 * @param string $value CSV field.
	 */
	public static function csv_cell( $value ) {
		$value = self::safe_text( $value );
		return preg_match( '/^[\x00-\x20]*[=+@-]/u', $value ) ? "'" . $value : $value;
	}
	/** Secure, capped keyset streaming export of all matching records. */
	public static function export() {
		if ( 'POST' !== ( isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : '' ) || ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Permission denied.', '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'gwqsh_activity_export' );
		$f = self::filters( wp_unslash( $_POST ) );
		if ( is_wp_error( $f ) ) {
			wp_die( esc_html( $f->get_error_message() ), '', array( 'response' => 400 ) );
		}
		global $wpdb;
		$table  = $wpdb->prefix . 'gwqsh_activity_log';
		$where  = self::where( $f );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$max    = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		$where .= $wpdb->prepare( ' AND id <= %d', $max );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$count  = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error || $count > 50000 ) {
			wp_die( 'Export unavailable. Narrow your filters to at most 50,000 events.', '', array( 'response' => 400 ) );
		}
		nocache_headers();
		header( 'Content-Type: text/csv; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="quietshield-activity-' . gmdate( 'Ymd-His' ) . '.csv"' );
		header( 'X-Content-Type-Options: nosniff' );
		$out = fopen( 'php://output', 'w' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Writes or closes the authenticated CSV download stream; no remote filesystem is involved.
		fwrite( $out, "\xEF\xBB\xBF" );
		fputcsv( $out, array( 'Event ID', 'Timestamp (site timezone, ISO 8601)', 'Category', 'Original type', 'Severity', 'User', 'IP address', 'Event', 'Description' ), ',', '"', '' );
		$cursor  = '';
		$written = 0;
		do {
			// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$rows = $wpdb->get_results( 'SELECT *, ' . self::category_sql() . " AS category FROM {$table} WHERE {$where} {$cursor} ORDER BY event_time DESC, id DESC LIMIT 500", ARRAY_A ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
			if ( $wpdb->last_error ) {
				fputcsv( $out, array( 'EXPORT ERROR: Database read failed; export incomplete.' ) );
				break;
			}
			foreach ( $rows as $raw ) {
				$row = self::record( $raw );
				fputcsv( $out, array_map( array( __CLASS__, 'csv_cell' ), array( $row['id'], $row['timestamp'], $row['badge'], $row['event_type'], $row['severity'], $row['user_login'], $row['ip_address'], $row['event_name'], $row['details'] ) ), ',', '"', '' );
				++$written;
			}
			if ( $rows ) {
				$last   = end( $rows );
				$cursor = $wpdb->prepare( ' AND (event_time < %s OR (event_time = %s AND id < %d))', $last['event_time'], $last['event_time'], $last['id'] );
			}
			$batch_size = count( $rows );
		} while ( 500 === $batch_size && $written < 50000 && ! connection_aborted() );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Writes or closes the authenticated CSV download stream; no remote filesystem is involved.
		fclose( $out );
		exit;
	}
	/** Retention preview with a short-lived, user-bound snapshot. */
	public static function cleanup_preview() {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new WP_Error( 'permission', 'Permission denied.' );
		}
		global $wpdb;
		$days = (int) GWQSH_Settings::get( 'retention', 30 );
		if ( $days <= 0 ) {
			return new WP_Error( 'retention', 'Retention is unlimited. No records are eligible for cleanup.' );
		}
		$table  = $wpdb->prefix . 'gwqsh_activity_log';
		$cutoff = current_datetime()->modify( "-{$days} days" )->format( 'Y-m-d H:i:s' );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$max    = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL,PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$count  = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$table} WHERE event_time < %s AND id <= %d", $cutoff, $max ) ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL,PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Could not preview cleanup.' );
		}
		$token = wp_generate_password( 32, false, false );
		set_transient(
			'gwqsh_log_cleanup_' . get_current_user_id(),
			array(
				'token'  => $token,
				'cutoff' => $cutoff,
				'max'    => $max,
				'days'   => $days,
			),
			10 * MINUTE_IN_SECONDS
		);
		return array(
			'token'    => $token,
			'cutoff'   => $cutoff,
			'count'    => $count,
			'days'     => $days,
			'timezone' => wp_timezone_string(),
		);
	}
	/** One confirmed batch; recheck policy on every request. Controller checks nonce.
	 *
	 * @param string $token Preview token.
	 * @param string $confirmed Explicit confirmation.
	 */
	public static function cleanup( $token, $confirmed ) {
		if ( ! current_user_can( 'manage_options' ) || '1' !== (string) $confirmed ) {
			return new WP_Error( 'permission', 'Explicit administrator confirmation is required.' );
		}
		$preview = get_transient( 'gwqsh_log_cleanup_' . get_current_user_id() );
		if ( ! $preview || ! is_string( $token ) || ! hash_equals( $preview['token'], $token ) || (int) GWQSH_Settings::get( 'retention', 30 ) !== $preview['days'] ) {
			return new WP_Error( 'preview', 'Cleanup preview expired or retention changed. Preview again.' );
		}
		if ( $preview['cutoff'] > current_datetime()->modify( '-' . $preview['days'] . ' days' )->format( 'Y-m-d H:i:s' ) ) {
			return new WP_Error( 'retention', 'The retention cutoff changed. Preview again.' );
		}
		global $wpdb;
		$table   = $wpdb->prefix . 'gwqsh_activity_log';
		$where   = $wpdb->prepare( 'event_time < %s AND id <= %d', $preview['cutoff'], $preview['max'] );
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$deleted = $wpdb->query( "DELETE FROM {$table} WHERE {$where} ORDER BY event_time, id LIMIT 1000" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( false === $deleted ) {
			return new WP_Error( 'database', 'Cleanup failed. No further deletion attempted.' );
		}
		if ( $deleted ) {
			GWQSH_Activity_Logger::log( 'Expired activity logs removed', sprintf( '%d expired records removed; retention %d days; cutoff %s site time.', $deleted, $preview['days'], $preview['cutoff'] ), 'System' );
		}
		// phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$remaining = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" ); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter,WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL -- Fixed plugin-owned identifiers, whitelisted columns and already-prepared predicates; all external values use placeholders.
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Cleanup count could not be loaded. Preview again.' ); }
		if ( ! $remaining ) {
			delete_transient( 'gwqsh_log_cleanup_' . get_current_user_id() );
		}
		return array(
			'deleted'   => $deleted,
			'remaining' => $remaining,
		);
	}
}
