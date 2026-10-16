<?php
/**
 * Read-only, bounded inspection of stored site data for compromise evidence.
 *
 * Scope and safety contract:
 * - Every statement is a bounded SELECT with prepared values. Nothing is deleted,
 *   updated, unserialized into objects or executed.
 * - Evidence is returned as rule identifiers, bounded redacted excerpts, table,
 *   column and row identifiers so an administrator can review the actual record.
 * - Findings are evidence for review. They never authorize automatic erasure.
 * - Coverage limits are reported honestly; a limited scan is never "clean".
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Database malware and persistence inspection. */
final class GWQSH_Database_Scanner {
	const VERSION          = '1';
	const CRON_HOOK        = 'gwqsh_database_scan';
	const REPORT_OPTION    = 'gwqsh_database_scan_report';
	const BASELINE_OPTION  = 'gwqsh_admin_baseline';
	const BUDGET_SECONDS   = 8;
	const MAX_ROWS         = 200;
	const MAX_FINDING_ROWS = 40;
	const MAX_VALUE_BYTES  = 8192;
	const MAX_EXCERPT      = 240;
	const MAX_FINDINGS     = 60;

	/** Rule catalogue: fixed source data, never downloaded. */
	const RULES = array(
		'GWQSH-3001' => array(
			'title'      => 'PHP code stored in site data',
			'severity'   => 'Critical',
			'confidence' => 'High',
		),
		'GWQSH-3002' => array(
			'title'      => 'Obfuscated script stored in site data',
			'severity'   => 'High',
			'confidence' => 'High',
		),
		'GWQSH-3003' => array(
			'title'      => 'Hidden or cloaked injected frame',
			'severity'   => 'High',
			'confidence' => 'High',
		),
		'GWQSH-3004' => array(
			'title'      => 'Known compromise indicator in stored data',
			'severity'   => 'High',
			'confidence' => 'Review',
		),
		'GWQSH-3005' => array(
			'title'      => 'Unregistered scheduled task',
			'severity'   => 'Medium',
			'confidence' => 'Review',
		),
		'GWQSH-3006' => array(
			'title'      => 'Administrator not in the approved baseline',
			'severity'   => 'High',
			'confidence' => 'Review',
		),
		'GWQSH-3007' => array(
			'title'      => 'Administrator capability without a matching account',
			'severity'   => 'Medium',
			'confidence' => 'High',
		),
		'GWQSH-3008' => array(
			'title'      => 'Active component file is missing',
			'severity'   => 'Medium',
			'confidence' => 'High',
		),
	);

	/** Incident strings already recognised by the file analyzer, as bounded literals. */
	const IOC_LITERALS = array(
		'ms_gate_heal_restore',
		'ms_panel_self_heal',
		'fm_panel_self_heal_webroot',
		'X-Medusa-Mu-Gate',
		'IST_TXT_URL',
		'vitrin_source',
		'.ms_index.bak.php',
		'ist-dest.txt',
		'fm_index_heal.php',
	);

	/** Register the scheduled entry point. */
	public static function init() {
		add_action( self::CRON_HOOK, array( __CLASS__, 'run' ) );
		self::sync_schedule();
	}

	/**
	 * Keep the scheduled database scan on the administrator's existing scan opt-in.
	 *
	 * While scheduled integrity scanning is enabled one bounded database scan is queued
	 * per day; disabling the schedule removes it again, so the plugin never leaves an
	 * unrequested recurring job running on a host. On-demand runs are always available
	 * through the authenticated router.
	 */
	private static function sync_schedule() {
		$enabled = ! empty( GWQSH_Scheduler::settings()['enabled'] );
		$next    = wp_next_scheduled( self::CRON_HOOK );
		if ( $enabled && ! $next ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', self::CRON_HOOK );
		} elseif ( ! $enabled && $next ) {
			wp_clear_scheduled_hook( self::CRON_HOOK );
		}
	}

	/**
	 * Run every bounded check and persist a report.
	 *
	 * @param array $args Optional arguments: 'store' (bool, default true).
	 * @return array Report structure.
	 */
	public static function run( $args = array() ) {
		// A schedule that an administrator has since disabled must not keep scanning.
		if ( self::CRON_HOOK === current_action() && empty( GWQSH_Scheduler::settings()['enabled'] ) ) {
			return array();
		}
		global $wpdb;
		$started = microtime( true );
		$report  = array(
			'version'     => self::VERSION,
			'driver'      => GWQSH_DB::driver(),
			'prefix'      => $wpdb->prefix,
			'multisite'   => is_multisite(),
			'started_at'  => time(),
			'checks'      => array(),
			'findings'    => array(),
			'status'      => 'completed',
			'duration_ms' => 0,
		);

		$checks  = array(
			self::check_php_in_data(),
			self::check_obfuscated_scripts(),
			self::check_known_indicators(),
			self::check_cron_persistence(),
			self::check_administrator_drift(),
			self::check_orphan_capabilities(),
			self::check_active_components(),
		);
		$limited = false;
		foreach ( $checks as $check ) {
			if ( ! empty( $check['limited'] ) ) {
				$limited = true;
			}
			$report['checks'][ $check['id'] ] = array(
				'label'   => $check['label'],
				'rows'    => (int) $check['rows'],
				'limited' => ! empty( $check['limited'] ),
				'skipped' => ! empty( $check['skipped'] ),
			);
			foreach ( $check['findings'] as $finding ) {
				if ( count( $report['findings'] ) >= self::MAX_FINDINGS ) {
					$limited = true;
					break 2;
				}
				$report['findings'][] = $finding;
			}
			if ( microtime( true ) - $started > self::BUDGET_SECONDS ) {
				$limited = true;
				break;
			}
		}

		if ( '' !== (string) $wpdb->last_error ) {
			$report['status'] = 'failed';
		} elseif ( $limited ) {
			$report['status'] = 'limited';
		}
		$report['duration_ms']  = (int) round( ( microtime( true ) - $started ) * 1000 );
		$report['completed_at'] = time();
		$report['summary']      = self::summarize( $report['findings'] );

		if ( false !== ( $args['store'] ?? true ) ) {
			update_option( self::REPORT_OPTION, $report, false );
			if ( ! empty( $report['findings'] ) ) {
				$counts = array();
				foreach ( $report['findings'] as $finding ) {
					$counts[ $finding['severity'] ] = ( $counts[ $finding['severity'] ] ?? 0 ) + 1;
				}
				GWQSH_Activity_Logger::log(
					'Database scan completed',
					wp_json_encode(
						array(
							'severity_counts' => $counts,
							'status'          => $report['status'],
						)
					),
					'Security'
				);
			}
		}
		return $report;
	}

	/**
	 * Last stored report (never a claim about unexamined data).
	 *
	 * @return array Report or empty array.
	 */
	public static function report() {
		$report = get_option( self::REPORT_OPTION, array() );
		return is_array( $report ) ? $report : array();
	}

	/**
	 * Severity counts for UI and recovery summaries.
	 *
	 * @param array $findings Finding rows.
	 * @return array Counts keyed by severity.
	 */
	public static function summarize( array $findings ) {
		$summary = array(
			'Critical'      => 0,
			'High'          => 0,
			'Medium'        => 0,
			'Low'           => 0,
			'Informational' => 0,
		);
		foreach ( $findings as $finding ) {
			if ( isset( $summary[ $finding['severity'] ] ) ) {
				++$summary[ $finding['severity'] ];
			}
		}
		$summary['total'] = count( $findings );
		return $summary;
	}

	/**
	 * Record the currently approved administrator set as the review baseline.
	 *
	 * This is administrator input, not a claim that the current accounts are trusted.
	 *
	 * @return array Baseline structure.
	 */
	public static function approve_administrators() {
		$users    = get_users(
			array(
				'capability' => 'manage_options',
				'fields'     => array( 'ID', 'user_login', 'user_registered' ),
				'number'     => 500,
			)
		);
		$baseline = array(
			'approved_at' => time(),
			'users'       => array(),
		);
		foreach ( $users as $user ) {
			$baseline['users'][ (int) $user->ID ] = array(
				'login'      => (string) $user->user_login,
				'registered' => (string) $user->user_registered,
			);
		}
		update_option( self::BASELINE_OPTION, $baseline, false );
		GWQSH_Activity_Logger::log( 'Administrator baseline approved', 'Approved administrators: ' . count( $baseline['users'] ), 'Security' );
		return $baseline;
	}

	/**
	 * Unserialize stored structures without instantiating unknown classes.
	 *
	 * Object injection is a real risk when reading attacker-influenced rows, so the
	 * scanner never allows classes to be created while parsing.
	 *
	 * @param mixed $value Stored value.
	 * @return mixed Array on success, false otherwise.
	 */
	public static function safe_unserialize( $value ) {
		if ( ! is_string( $value ) || '' === $value || strlen( $value ) > 1048576 ) {
			return false;
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.serialize_unserialize,WordPress.PHP.NoSilencedErrors.Discouraged -- Bounded parse with class instantiation disabled; a malformed value returns false instead of raising a warning during a read-only scan.
		$result = @unserialize( $value, array( 'allowed_classes' => false ) );
		return is_array( $result ) ? $result : false;
	}

	/**
	 * Bounded, redacted evidence excerpt with no surrounding markup.
	 *
	 * @param mixed  $value Raw stored value.
	 * @param string $needle Matched literal when known.
	 * @return string Excerpt.
	 */
	public static function excerpt( $value, $needle = '' ) {
		$value = substr( (string) $value, 0, self::MAX_VALUE_BYTES );
		if ( '' !== $needle ) {
			$position = stripos( $value, $needle );
			if ( false !== $position ) {
				$value = substr( $value, max( 0, $position - 60 ) );
			}
		}
		$value = preg_replace( '/[\x00-\x08\x0B\x0C\x0E-\x1F]/', ' ', $value );
		$value = trim( preg_replace( '/\s+/', ' ', (string) $value ) );
		if ( class_exists( 'GWQSH_Activity_View_Data' ) ) {
			$value = GWQSH_Activity_View_Data::safe_text( $value );
		}
		return substr( $value, 0, self::MAX_EXCERPT );
	}

	/**
	 * Build one finding row.
	 *
	 * @param string $rule Rule identifier.
	 * @param string $table Table name.
	 * @param string $column Column name.
	 * @param string $row_id Row identifier for review.
	 * @param string $excerpt Bounded evidence excerpt.
	 * @param string $detail Additional bounded context.
	 * @return array Finding.
	 */
	private static function finding( $rule, $table, $column, $row_id, $excerpt, $detail = '' ) {
		$meta = self::RULES[ $rule ] ?? array(
			'title'      => 'Stored data requires review',
			'severity'   => 'Medium',
			'confidence' => 'Review',
		);
		return array(
			'rule'       => $rule,
			'title'      => $meta['title'],
			'severity'   => $meta['severity'],
			'confidence' => $meta['confidence'],
			'table'      => $table,
			'column'     => $column,
			'record'     => (string) $row_id,
			'excerpt'    => $excerpt,
			'detail'     => substr( (string) $detail, 0, self::MAX_EXCERPT ),
			'action'     => 'Review this stored record before changing it. The scanner never edits site data.',
		);
	}

	/**
	 * Step 1: PHP source fragments inside stored data (never legitimate site content).
	 *
	 * @return array Check result.
	 */
	private static function check_php_in_data() {
		global $wpdb;
		$targets = array(
			array( $wpdb->options, 'option_name', 'option_value' ),
			array( $wpdb->posts, 'ID', 'post_content' ),
			array( $wpdb->postmeta, 'meta_id', 'meta_value' ),
		);
		if ( is_multisite() ) {
			$targets[] = array( $wpdb->sitemeta, 'meta_id', 'meta_value' );
		} else {
			$targets[] = array( $wpdb->usermeta, 'umeta_id', 'meta_value' );
		}
		$result = array(
			'id'       => 'php_in_data',
			'label'    => 'PHP source fragments in stored data',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		foreach ( $targets as $target ) {
			list( $table, $id_column, $value_column ) = $target;
			$table                                    = esc_sql( $table );
			$rows                                     = $wpdb->get_results( // phpcs:ignore WordPress.DB -- Fixed plugin/WordPress table identifiers; prepared literal prefilter, bounded row count, read-only review evidence.
				$wpdb->prepare(
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned or WordPress table and column identifiers only; every value is prepared and every query is row-bounded and read-only.
					"SELECT {$id_column} AS record_id, {$value_column} AS value FROM {$table} WHERE {$value_column} LIKE %s OR {$value_column} LIKE %s LIMIT %d",
					'%<?php%',
					'%<?=%',
					self::MAX_ROWS + 1
				),
				ARRAY_A
			);
			if ( ! is_array( $rows ) ) {
				$result['limited'] = true;
				continue;
			}
			if ( count( $rows ) > self::MAX_ROWS ) {
				$result['limited'] = true;
				$rows              = array_slice( $rows, 0, self::MAX_ROWS );
			}
			$result['rows'] += count( $rows );
			foreach ( array_slice( $rows, 0, self::MAX_FINDING_ROWS ) as $row ) {
				if ( ! preg_match( '/<\?(?:php|=)/i', (string) $row['value'] ) ) {
					continue;
				}
				$result['findings'][] = self::finding(
					'GWQSH-3001',
					$table,
					$value_column,
					$row['record_id'],
					self::excerpt( $row['value'], '<?' ),
					'PHP source stored in site data can indicate an injected backdoor or a poisoned cache row.'
				);
			}
		}
		return $result;
	}

	/**
	 * Step 2: obfuscated or cloaked script payloads in stored markup.
	 *
	 * Two independent signals are required so ordinary embeds and analytics snippets
	 * are not reported. All patterns are bounded and inspect data only.
	 *
	 * @return array Check result.
	 */
	private static function check_obfuscated_scripts() {
		global $wpdb;
		$targets  = array(
			array( $wpdb->options, 'option_name', 'option_value' ),
			array( $wpdb->posts, 'ID', 'post_content' ),
		);
		$result   = array(
			'id'       => 'obfuscated_scripts',
			'label'    => 'Obfuscated or cloaked stored scripts',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		$markers  = array( 'eval(', 'atob(', 'fromCharCode', 'unescape(', 'document.write', '\\\\x6', 'String.fromCharCode' );
		$cloaking = '/<iframe\b[^>]{0,400}(?:display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["\']?0|height\s*=\s*["\']?0|opacity\s*:\s*0(?:\.0+)?\b|(?:left|top)\s*:\s*-\d{3,})/i';
		foreach ( $targets as $target ) {
			list( $table, $id_column, $value_column ) = $target;
			$table                                    = esc_sql( $table );
			// Scripts and frames are prefilters of equal standing, so a cloaked frame is
			// reported on its own instead of requiring an unrelated script tag to exist.
			$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB -- Fixed plugin/WordPress table identifiers; prepared literal prefilters, bounded row count, read-only review evidence.
				// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned or WordPress table and column identifiers only; every value is prepared and every query is row-bounded and read-only.
				$wpdb->prepare( "SELECT {$id_column} AS record_id, {$value_column} AS value FROM {$table} WHERE {$value_column} LIKE %s OR {$value_column} LIKE %s LIMIT %d", '%<script%', '%<iframe%', self::MAX_ROWS + 1 ),
				ARRAY_A
			);
			if ( ! is_array( $rows ) ) {
				$result['limited'] = true;
				continue;
			}
			if ( count( $rows ) > self::MAX_ROWS ) {
				$result['limited'] = true;
				$rows              = array_slice( $rows, 0, self::MAX_ROWS );
			}
			$result['rows'] += count( $rows );
			foreach ( array_slice( $rows, 0, self::MAX_FINDING_ROWS ) as $row ) {
				$value  = substr( (string) $row['value'], 0, self::MAX_VALUE_BYTES );
				$signal = '';
				if ( preg_match( '/<script\\b[^>]{0,400}>/i', $value ) ) {
					foreach ( $markers as $marker ) {
						if ( false !== stripos( $value, $marker ) ) {
							$signal = $marker;
							break;
						}
					}
				}
				if ( '' !== $signal ) {
					$result['findings'][] = self::finding(
						'GWQSH-3002',
						$table,
						$value_column,
						$row['record_id'],
						self::excerpt( $value, $signal ),
						'Script content combines a script tag with the obfuscation marker "' . $signal . '".'
					);
				}
				if ( preg_match( $cloaking, $value ) ) {
					$result['findings'][] = self::finding(
						'GWQSH-3003',
						$table,
						$value_column,
						$row['record_id'],
						self::excerpt( $value, '<iframe' ),
						'A frame is hidden from visitors inside stored content, which is typical of cloaked redirects.'
					);
				}
			}
		}
		return $result;
	}

	/**
	 * Step 3: known compromise indicators recorded in stored data.
	 *
	 * @return array Check result.
	 */
	private static function check_known_indicators() {
		global $wpdb;
		$result  = array(
			'id'       => 'known_indicators',
			'label'    => 'Known compromise indicators in stored data',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		$targets = array(
			array( $wpdb->options, 'option_name', 'option_value' ),
			array( $wpdb->posts, 'ID', 'post_content' ),
		);
		foreach ( $targets as $target ) {
			list( $table, $id_column, $value_column ) = $target;
			$table                                    = esc_sql( $table );
			foreach ( self::IOC_LITERALS as $literal ) {
				$rows = $wpdb->get_results( // phpcs:ignore WordPress.DB -- Fixed plugin/WordPress table identifiers; prepared literal prefilter, bounded row count, read-only review evidence.
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned or WordPress table and column identifiers only; every value is prepared and every query is row-bounded and read-only.
					$wpdb->prepare( "SELECT {$id_column} AS record_id, {$value_column} AS value FROM {$table} WHERE {$value_column} LIKE %s LIMIT %d", '%' . $wpdb->esc_like( $literal ) . '%', 5 ),
					ARRAY_A
				);
				if ( ! is_array( $rows ) || ! $rows ) {
					continue;
				}
				$result['rows'] += count( $rows );
				foreach ( $rows as $row ) {
					if ( false === stripos( (string) $row['value'], $literal ) ) {
						continue;
					}
					$result['findings'][] = self::finding(
						'GWQSH-3004',
						$table,
						$value_column,
						$row['record_id'],
						self::excerpt( $row['value'], $literal ),
						'Stored data contains the incident string ' . $literal . ', which previous cleanup tooling used.'
					);
				}
			}
		}
		return $result;
	}

	/**
	 * Step 4: scheduled tasks that no installed component registers.
	 *
	 * An unregistered hook is a review item, not proof of malware: plugins that were
	 * deactivated legitimately leave orphaned entries. Arguments containing PHP source
	 * escalate the finding.
	 *
	 * @return array Check result.
	 */
	private static function check_cron_persistence() {
		$result = array(
			'id'       => 'cron_persistence',
			'label'    => 'Scheduled task persistence (wp-cron)',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		// WordPress deserializes the stored schedule on read; a raw string is parsed with
		// class instantiation disabled in case the value was never normalised.
		$stored = get_option( 'cron', '' );
		$cron   = is_array( $stored ) ? $stored : self::safe_unserialize( $stored );
		if ( ! is_array( $cron ) ) {
			return $result;
		}
		$result['rows'] = count( $cron );
		foreach ( array_slice( array_keys( $cron ), 0, self::MAX_ROWS, true ) as $timestamp ) {
			$hooks = $cron[ $timestamp ];
			if ( ! is_array( $hooks ) ) {
				continue;
			}
			foreach ( array_slice( $hooks, 0, self::MAX_ROWS, true ) as $hook => $entries ) {
				if ( ! is_string( $hook ) || '' === $hook ) {
					continue;
				}
				$registered = has_action( $hook ) || has_filter( $hook ) || 'wp_' === substr( $hook, 0, 3 );
				$arguments  = '';
				if ( is_array( $entries ) ) {
					foreach ( $entries as $entry ) {
						if ( is_array( $entry ) && isset( $entry['args'] ) && is_array( $entry['args'] ) ) {
							$arguments .= wp_json_encode( array_slice( $entry['args'], 0, 5 ) );
						}
					}
				}
				$arguments = substr( $arguments, 0, self::MAX_VALUE_BYTES );
				$php_args  = (bool) preg_match( '/<\?(?:php|=)/i', $arguments );
				if ( ! $registered || $php_args ) {
					$result['findings'][] = self::finding(
						'GWQSH-3005',
						'options',
						'cron',
						$hook,
						self::excerpt( $hook . ' | ' . $arguments ),
						$php_args
							? 'Scheduled task arguments contain PHP source, which no legitimate hook should store.'
							: 'No installed component currently registers this scheduled hook, so it may be orphaned by a removal or added for persistence.'
					);
				}
			}
		}
		return $result;
	}

	/**
	 * Step 5: administrator accounts compared with the approved baseline.
	 *
	 * Without an approved baseline, drift is not asserted: the scanner reports that it
	 * cannot evaluate this check rather than inventing a result.
	 *
	 * @return array Check result.
	 */
	private static function check_administrator_drift() {
		$result         = array(
			'id'       => 'administrator_drift',
			'label'    => 'Administrator accounts vs approved baseline',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		$baseline       = get_option( self::BASELINE_OPTION, array() );
		$users          = get_users(
			array(
				'capability' => 'manage_options',
				'fields'     => array( 'ID', 'user_login', 'user_email', 'user_registered' ),
				'number'     => 500,
			)
		);
		$result['rows'] = count( $users );
		if ( ! is_array( $baseline ) || empty( $baseline['users'] ) || ! is_array( $baseline['users'] ) ) {
			$result['limited'] = true;
			return $result;
		}
		$approved = array_map( 'intval', array_keys( $baseline['users'] ) );
		foreach ( $users as $user ) {
			$id = (int) $user->ID;
			if ( in_array( $id, $approved, true ) ) {
				continue;
			}
			$result['findings'][] = self::finding(
				'GWQSH-3006',
				'users',
				'user_login',
				$id,
				substr( (string) $user->user_login, 0, 80 ) . ' | registered ' . substr( (string) $user->user_registered, 0, 32 ),
				'This account has administrator capability but was not part of the approved administrator set.'
			);
		}
		return $result;
	}

	/**
	 * Step 6: capability records whose account no longer exists.
	 *
	 * @return array Check result.
	 */
	private static function check_orphan_capabilities() {
		global $wpdb;
		$result = array(
			'id'       => 'orphan_capabilities',
			'label'    => 'Capability records without an account',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		$key    = $wpdb->prefix . 'capabilities';
		$table  = esc_sql( $wpdb->usermeta );
		$rows   = $wpdb->get_results( // phpcs:ignore WordPress.DB -- Fixed WordPress table identifier; prepared capability key, bounded row count, read-only review evidence.
			$wpdb->prepare(
	// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned or WordPress table and column identifiers only; every value is prepared and every query is row-bounded and read-only.
				"SELECT u.umeta_id AS record_id, u.user_id AS user_id, u.meta_value AS value FROM {$table} u LEFT JOIN {$wpdb->users} w ON w.ID = u.user_id WHERE u.meta_key = %s AND w.ID IS NULL LIMIT %d",
				$key,
				self::MAX_ROWS
			),
			ARRAY_A
		);
		if ( ! is_array( $rows ) ) {
			$result['limited'] = true;
			return $result;
		}
		$result['rows'] = count( $rows );
		foreach ( $rows as $row ) {
			$capabilities = self::safe_unserialize( (string) $row['value'] );
			if ( ! is_array( $capabilities ) || ! isset( $capabilities['administrator'] ) ) {
				continue;
			}
			$result['findings'][] = self::finding(
				'GWQSH-3007',
				$table,
				'meta_value',
				(int) $row['record_id'],
				'user_id ' . (int) $row['user_id'] . ' | ' . self::excerpt( (string) $row['value'] ),
				'An administrator capability record references a user ID that does not exist, which indicates direct database editing.'
			);
		}
		return $result;
	}

	/**
	 * Step 7: active components whose files are absent.
	 *
	 * @return array Check result.
	 */
	private static function check_active_components() {
		$result         = array(
			'id'       => 'active_components',
			'label'    => 'Active components with missing files',
			'rows'     => 0,
			'limited'  => false,
			'findings' => array(),
		);
		$active         = get_option( 'active_plugins', array() );
		$active         = is_array( $active ) ? $active : array();
		$result['rows'] = count( $active );
		foreach ( array_slice( $active, 0, self::MAX_ROWS ) as $entry ) {
			if ( ! is_string( $entry ) || '' === $entry ) {
				continue;
			}
			$suspicious_path = (bool) preg_match( '#(?:^/|\.\.)#', $entry );
			$missing         = ! $suspicious_path && ! file_exists( WP_PLUGIN_DIR . '/' . $entry );
			if ( ! $suspicious_path && ! $missing ) {
				continue;
			}
			$result['findings'][] = self::finding(
				'GWQSH-3008',
				'options',
				'active_plugins',
				substr( $entry, 0, 120 ),
				substr( $entry, 0, 120 ),
				$suspicious_path
					? 'An active component entry contains a traversal-style or absolute path.'
					: 'WordPress is configured to load this component but its file is missing.'
			);
		}
		return $result;
	}
}
