<?php
/**
 * Read-only, resumable database evidence inspection. Never executes stored content.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Identifiers come exclusively from the current wpdb instance and fixed source definitions. Values use prepare; keyset reads must bypass caches.

/** Site-scoped database investigation, separate from authentication recovery. */
final class GWQSH_Database_Scanner {
	const OPTION = 'gwqsh_database_scan';
	const HOOK   = 'gwqsh_continue_database_scan';
	const BYTES  = 65536;
	const ROWS   = 50000;

	/** Register continuation only; visiting the site never starts a scan. */
	public static function init() {
		add_action( self::HOOK, array( __CLASS__, 'step' ) );
	}

	/** Stop owned continuations on deactivation, retaining investigation evidence. */
	public static function deactivate() {
		$state = (array) get_option( self::OPTION, array() );
		if ( 'running' === ( $state['state'] ?? '' ) ) {
			// An in-flight worker must observe cancellation before publishing or
			// scheduling more work, even when deactivation cannot acquire its lease.
			update_option( 'gwqsh_database_scan_cancelled_job', $state['id'], false );
			$lock = GWQSH_Enterprise_Store::lock( 'database-scan', 30 );
			if ( $lock ) {
				try {
					wp_cache_delete( self::OPTION, 'options' );
					$current = (array) get_option( self::OPTION, array() );
					if ( ( $current['id'] ?? '' ) === $state['id'] && 'running' === ( $current['state'] ?? '' ) ) {
						$current['state']      = 'cancelled';
						$current['updated_at'] = time();
						self::persist( $current );
					}
				} finally {
					GWQSH_Enterprise_Store::unlock( 'database-scan', $lock );
				}
			}
		}
		wp_unschedule_hook( self::HOOK );
	}

	/** Fixed identifier definitions; custom prefixes and current blog are respected. */
	private static function sources() {
		global $wpdb;
		return array(
			'options'      => array( $wpdb->options, 'option_id', 'option_name', 'option_value' ),
			'posts'        => array( $wpdb->posts, 'ID', 'post_type', 'post_content' ),
			'postmeta'     => array( $wpdb->postmeta, 'meta_id', 'meta_key', 'meta_value' ),
			'capabilities' => array( $wpdb->usermeta, 'umeta_id', 'meta_key', 'meta_value' ),
		);
	}

	/** Return evidence metadata to authorized administrators, never raw record content. */
	public static function status() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		return (array) get_option( self::OPTION, array() );
	}

	/** Start an administrator-requested job with fixed upper ID boundaries. */
	public static function start() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		$lock = GWQSH_Enterprise_Store::lock( 'database-scan', 30 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Database inspection is busy.' );
		}
		try {
			$previous = (array) get_option( self::OPTION, array() );
			if ( 'running' === ( $previous['state'] ?? '' ) ) {
				return new WP_Error( 'running', 'Continue or cancel the active database inspection first.' );
			}
			global $wpdb;
			$state = array(
				'id'            => bin2hex( random_bytes( 16 ) ),
				'blog_id'       => get_current_blog_id(),
				'engine'        => 1,
				'state'         => 'running',
				'started_at'    => time(),
				'updated_at'    => time(),
				'source'        => 0,
				'cursor'        => 0,
				'read'          => 0,
				'inspected'     => 0,
				'findings'      => array(),
				'finding_count' => 0,
				'omitted'       => array(),
				'omitted_count' => 0,
				'upper'         => array(),
				'coverage'      => array( 'credential records excluded', 'no custom tables or network sitemeta', 'records can change during inspection; not a transactional snapshot' ),
			);
			foreach ( self::sources() as $name => $definition ) {
				list( $table, $id )      = $definition;
				$state['upper'][ $name ] = (int) $wpdb->get_var( "SELECT MAX(`{$id}`) FROM `{$table}`" );
				if ( $wpdb->last_error ) {
					return new WP_Error( 'database', 'Unable to read database inspection boundaries.' );
				}
			}
			GWQSH_Database_Context::begin( $state );
			if ( ! self::persist( $state ) ) {
				return new WP_Error( 'storage', 'Unable to save database inspection state.' );
			}
			GWQSH_Activity_Logger::log( 'Database scan started', 'Read-only inspection requested; no database records will be remediated.', 'Security' );
			return self::schedule( $state );
		} finally {
			GWQSH_Enterprise_Store::unlock( 'database-scan', $lock );
		}
	}

	/** Persist and verify metadata without using PHP deserialization on inspected data.
	 *
	 * @param array $state Validated internal job state.
	 */
	private static function persist( array $state ) {
		update_option( self::OPTION, $state, false );
		wp_cache_delete( self::OPTION, 'options' );
		return get_option( self::OPTION ) === $state;
	}

	/** Queue continuation and make scheduling failures visible.
	 *
	 * @param array $state Job state.
	 */
	private static function schedule( array $state ) {
		$args = array( $state['id'] );
		if ( ! wp_next_scheduled( self::HOOK, $args ) ) {
			$result = wp_schedule_single_event( time() + 10, self::HOOK, $args, true );
			if ( is_wp_error( $result ) || ! $result ) {
				$state['state']      = 'failed';
				$state['coverage'][] = 'continuation scheduling failed';
				self::persist( $state );
				return new WP_Error( 'schedule', 'Database scan continuation could not be scheduled.' );
			}
		}
		// Deactivation may race the scheduler while this worker owns the lease.
		// Recheck after enqueue: either we remove that event here, or subsequent
		// deactivation removes an event that already exists.
		wp_cache_delete( 'notoptions', 'options' );
		wp_cache_delete( 'gwqsh_database_scan_cancelled_job', 'options' );
		if ( get_option( 'gwqsh_database_scan_cancelled_job', '' ) === $state['id'] ) {
			$state['state'] = 'cancelled';
			self::persist( $state );
			wp_clear_scheduled_hook( self::HOOK, $args );
		}
		return $state;
	}

	/** Scan up to 100 rows/2 seconds with bounded SQL result payloads and an owned lease.
	 *
	 * @param string $job_id Exact current job identifier, including cron invocations.
	 */
	public static function step( $job_id ) {
		$lock = GWQSH_Enterprise_Store::lock( 'database-scan', 30 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Database inspection is busy.' );
		}
		try {
			$state = (array) get_option( self::OPTION, array() );
			if ( ! is_string( $job_id ) || ! preg_match( '/^[a-f0-9]{32}$/D', $job_id ) || ( $state['id'] ?? '' ) !== $job_id || ( $state['blog_id'] ?? 0 ) !== get_current_blog_id() || 'running' !== ( $state['state'] ?? '' ) ) {
				return new WP_Error( 'stale', 'No matching running database inspection.' );
			}
			global $wpdb;
			$sources      = self::sources();
			$names        = array_keys( $sources );
			$source_count = count( $names );
			$until        = microtime( true ) + 2;
			$processed    = 0;
			while ( $state['source'] < $source_count && $processed < 100 && microtime( true ) < $until ) {
				$name                               = $names[ $state['source'] ];
				list( $table, $id, $label, $value ) = $sources[ $name ];
				// Only this site's capability records are read from the shared usermeta table.
				$where = 'capabilities' === $name ? $wpdb->prepare( ' AND meta_key=%s', $wpdb->prefix . 'capabilities' ) : '';
				if ( 'capabilities' === $name ) {
					$rows = $wpdb->get_results( $wpdb->prepare( "SELECT m.umeta_id AS record_id,m.meta_key AS label,m.user_id,u.ID AS account_id,LEFT(u.user_login,60) AS login,u.user_registered AS registered,OCTET_LENGTH(m.meta_value) AS bytes,LEFT(CAST(m.meta_value AS BINARY),%d) AS sample FROM {$wpdb->usermeta} m LEFT JOIN {$wpdb->users} u ON u.ID=m.user_id WHERE m.meta_key=%s AND m.umeta_id>%d AND m.umeta_id<=%d ORDER BY m.umeta_id LIMIT 10", self::BYTES, $wpdb->prefix . 'capabilities', $state['cursor'], $state['upper'][ $name ] ), ARRAY_A );
				} else {
					$rows = $wpdb->get_results( $wpdb->prepare( "SELECT `{$id}` AS record_id, LEFT(`{$label}`,191) AS label, OCTET_LENGTH(`{$value}`) AS bytes, LEFT(CAST(`{$value}` AS BINARY),%d) AS sample FROM `{$table}` WHERE `{$id}`>%d AND `{$id}`<=%d {$where} ORDER BY `{$id}` LIMIT 10", self::BYTES, $state['cursor'], $state['upper'][ $name ] ), ARRAY_A );
				}
				if ( $wpdb->last_error ) {
					$state['state']      = 'failed';
					$state['coverage'][] = 'query failed for ' . $name;
					break;
				}
				if ( ! $rows ) {
					++$state['source'];
					$state['cursor'] = 0;
					continue;
				}
				foreach ( $rows as $row ) {
					$state['cursor'] = (int) $row['record_id'];
					++$state['read'];
					++$processed;
					$record = array(
						'source' => $name,
						'table'  => $table,
						'id'     => (int) $row['record_id'],
						'field'  => $value,
					);
					if ( 'options' === $name && 0 === strpos( $row['label'], 'gwqsh_' ) ) {
						self::omit( $state, $record, 'all gwqsh_ options excluded', false );
					} elseif ( preg_match( '/password|secret|token|nonce|session|api.?key|private.?key|credential/i', $row['label'] ) ) {
						self::omit( $state, $record, 'credential record excluded' );
					} else {
						++$state['inspected'];
						if ( (int) $row['bytes'] > self::BYTES ) {
							self::omit( $state, $record, 'content beyond first 65536 bytes not inspected' );
						}
						$rules = array_merge( self::analyze( $row['sample'], $name, $row['label'] ), GWQSH_Database_Context::inspect( $row, $name, $state ) );
						if ( $rules ) {
							++$state['finding_count'];
							if ( count( $state['findings'] ) < 100 ) {
								$state['findings'][] = array_merge(
									$record,
									array(
										'rules'         => $rules,
										'confidence'    => 'Review required',
										'sample_sha256' => hash( 'sha256', $row['sample'] ),
										'bytes'         => (int) $row['bytes'],
										'partial'       => (int) $row['bytes'] > self::BYTES,
									)
								);
							}
						}
					}
					if ( $state['read'] >= self::ROWS ) {
						$state['state']      = 'incomplete';
						$state['coverage'][] = '50000 row budget exhausted; remaining source ranges not inspected';
						break 2;
					}
				}
			}
			if ( $state['source'] >= count( $names ) ) {
				$state['state'] = 'complete';
			}
			$state['updated_at'] = time();
			wp_cache_delete( 'notoptions', 'options' );
			wp_cache_delete( 'gwqsh_database_scan_cancelled_job', 'options' );
			if ( get_option( 'gwqsh_database_scan_cancelled_job', '' ) === $job_id ) {
				$state['state'] = 'cancelled';
			}
			if ( ! self::persist( $state ) ) {
				return new WP_Error( 'storage', 'Inspection state could not be saved; completion is unverified.' );
			}
			wp_clear_scheduled_hook( self::HOOK, array( $job_id ) );
			if ( 'running' === $state['state'] ) {
				return self::schedule( $state );
			}
			GWQSH_Activity_Logger::log(
				'Database scan ' . ( 'complete' === $state['state'] ? 'completed' : 'failed or incomplete' ),
				wp_json_encode(
					array(
						'state'    => $state['state'],
						'read'     => $state['read'],
						'findings' => $state['finding_count'],
						'omitted'  => $state['omitted_count'],
					)
				),
				'Security'
			);
			return $state;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'database-scan', $lock );
		}
	}

	/** Retain bounded omission references and the total omitted count.
	 *
	 * @param array  $state Job state.
	 * @param array  $record Record locator without content.
	 * @param string $reason Coverage reason.
	 * @param bool   $retain Whether a record locator is needed in addition to an exact prefix exclusion.
	 */
	private static function omit( &$state, array $record, $reason, $retain = true ) {
		++$state['omitted_count'];
		$state['omission_reasons'][ $reason ] = ( $state['omission_reasons'][ $reason ] ?? 0 ) + 1;
		if ( $retain && count( $state['omitted'] ) < 100 ) {
			$state['omitted'][] = array_merge( $record, array( 'reason' => $reason ) );
		}
	}

	/** Safe lexical correlations; all are investigation signals, never deletion authority.
	 *
	 * @param string $value Bounded raw database bytes, never unserialized.
	 * @param string $source Fixed source name.
	 * @param string $label Record context.
	 * @return array Original rule IDs with review descriptions.
	 */
	public static function analyze( $value, $source, $label = '' ) {
		$value = substr( (string) $value, 0, self::BYTES );
		$rules = array();
		if ( preg_match( '/<script\b[^>]{0,512}\bsrc\s*=\s*[\'"]?https?:\/\//i', $value ) ) {
			$rules['DB-1001'] = 'External script reference: verify publisher and authorization.';
		}
		if ( preg_match( '/\b(?:eval|document\.write)\s*\(\s*(?:atob|unescape|String\.fromCharCode)\s*\(/i', $value ) ) {
			$rules['DB-1002'] = 'Encoded JavaScript execution correlation.';
		}
		if ( preg_match( '/document\.cookie/i', $value ) && preg_match( '/\b(?:fetch|XMLHttpRequest|sendBeacon)\s*\(/i', $value ) ) {
			$rules['DB-1003'] = 'Cookie access and outbound JavaScript request coexist.';
		}
		if ( preg_match( '/(?:window\.|document\.)?location\.(?:href|replace|assign)\s*(?:=|\()\s*[\'"]https?:\/\//i', $value ) ) {
			$rules['DB-1004'] = 'Absolute JavaScript redirect: verify intended destination.';
		}
		if ( 'capabilities' === $source && preg_match( '/s:\d+:"(?:administrator|manage_options|edit_users|promote_users)";b:1;/', $value ) ) {
			$rules['DB-1005'] = 'Privileged account membership: confirm the account is authorized.';
		}
		if ( in_array( $label, array( 'cron', 'active_plugins' ), true ) && preg_match( '/(?:eval|base64_decode|shell_exec)\s*\(|<\?php/i', $value ) ) {
			$rules['DB-1006'] = 'Executable-looking persistence configuration requires review.';
		}
		if ( preg_match( '/<iframe\b[^>]{0,512}(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:left|top)\s*:\s*-[0-9]{3,}px)/i', $value ) ) {
			$rules['DB-1007'] = 'Hidden or off-screen iframe: verify whether the embed and destination are intended.';
		}
		if ( preg_match( '/<\?php\b[\s\S]{0,1024}\b(?:eval|system|shell_exec)\s*\([^;]{0,512}\$_(?:GET|POST|REQUEST)/i', $value ) ) {
			$rules['DB-1008'] = 'Stored PHP fragment correlates request input with execution; review code storage and persistence context.';
		}
		return $rules;
	}

	/** Cancel only the current site's exact job; no inspected records are changed.
	 *
	 * @param string $job_id Current job identifier.
	 */
	public static function cancel( $job_id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		$lock = GWQSH_Enterprise_Store::lock( 'database-scan', 30 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Database inspection is busy.' );
		}
		try {
			$state = (array) get_option( self::OPTION, array() );
			if ( ( $state['id'] ?? '' ) !== $job_id || 'running' !== ( $state['state'] ?? '' ) ) {
				return new WP_Error( 'stale', 'No matching running database inspection.' );
			}
			$state['state']      = 'cancelled';
			$state['updated_at'] = time();
			if ( ! self::persist( $state ) ) {
				return new WP_Error( 'storage', 'Unable to persist cancellation.' );
			}
			wp_clear_scheduled_hook( self::HOOK, array( $job_id ) );
			GWQSH_Activity_Logger::log( 'Database scan cancelled', 'Investigation remains incomplete.', 'Security' );
			return $state;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'database-scan', $lock );
		}
	}
}
