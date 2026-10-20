<?php
/**
 * Contextual database investigation within the existing bounded scan job.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed current-site wpdb identifiers and prepared values; live trust decisions bypass caches.

/** Original bounded adaptation of reviewed Arena investigation concepts. */
final class GWQSH_Database_Context {
	const BASELINE    = 'gwqsh_database_baseline';
	const MAX_MEMBERS = 500;

	/** Initialize a new job's contextual candidate.
	 *
	 * @param array $state Existing job state.
	 */
	public static function begin( &$state ) {
		$baseline         = (array) get_option( self::BASELINE, array() );
		$state['context'] = array(
			'baseline_id'   => $baseline['id'] ?? '',
			'members'       => array(),
			'configuration' => array(),
			'gaps'          => array(),
			'duplicates'    => array(),
			'member_count'  => 0,
		);
	}

	/** Record aggregate coverage without unbounded per-record messages.
	 *
	 * @param array  $state Job state.
	 * @param string $code Fixed coverage code.
	 */
	private static function gap( &$state, $code ) {
		$state['context']['gaps'][ $code ] = ( $state['context']['gaps'][ $code ] ?? 0 ) + 1;
		$message                           = 'Context inspection: ' . $code;
		if ( ! in_array( $message, $state['coverage'], true ) ) {
			$state['coverage'][] = $message;
		}
	}

	/** Add contextual rules without storing source values or cron arguments.
	 *
	 * @param array  $row Bounded database row.
	 * @param string $source Fixed source name.
	 * @param array  $state Mutable scan metadata.
	 * @return array Review rule IDs and descriptions.
	 */
	public static function inspect( array $row, $source, &$state ) {
		if ( ! isset( $state['context'] ) ) {
			self::begin( $state );
			self::gap( $state, 'pre-upgrade job requires a fresh scan before baseline approval' );
		}
		$rules = array();
		if ( ! in_array( $source, array( 'capabilities', 'options' ), true ) ) {
			return $rules;
		}
		global $wpdb;
		$label   = $row['label'];
		$special = in_array( $label, array( 'cron', 'active_plugins', 'home', 'siteurl', $wpdb->prefix . 'user_roles' ), true );
		if ( 'options' === $source && ! $special ) {
			return $rules;
		}
		if ( (int) $row['bytes'] > GWQSH_Database_Scanner::BYTES ) {
			self::gap( $state, 'structured record exceeds byte limit' );
			return $rules;
		}
		$baseline = (array) get_option( self::BASELINE, array() );
		if ( ( $baseline['id'] ?? '' ) !== $state['context']['baseline_id'] ) {
			self::gap( $state, 'baseline changed during inspection' );
			$baseline = array();
		}
		if ( in_array( $label, array( 'home', 'siteurl' ), true ) ) {
			$value = $row['sample'];
			$url   = wp_parse_url( $value );
			if ( ! $url || ! in_array( $url['scheme'] ?? '', array( 'http', 'https' ), true ) || empty( $url['host'] ) || isset( $url['user'] ) || isset( $url['pass'] ) ) {
				$rules['DB-1108'] = 'Site URL configuration is malformed or contains user information; review privately.';
				self::gap( $state, 'invalid site URL configuration' );
			}
			$state['context']['configuration'][ $label ] = hash( 'sha256', $value );
		} else {
			$value = GWQSH_Safe_Data::decode( $row['sample'] );
			if ( is_wp_error( $value ) || ! is_array( $value ) ) {
				self::gap( $state, 'unsupported structured ' . $source . ' data' );
				return $rules;
			}
			if ( 'capabilities' === $source ) {
				return self::member( $row, $value, $baseline, $state );
			}
			if ( 'cron' === $label ) {
				$hooks = array();
				foreach ( $value as $timestamp => $events ) {
					if ( 'version' === $timestamp ) {
						continue;
					}
					if ( ! is_numeric( $timestamp ) || ! is_array( $events ) ) {
						self::gap( $state, 'malformed cron structure' );
						continue;
					}
					foreach ( $events as $hook => $entries ) {
						if ( ! is_string( $hook ) || strlen( $hook ) > 191 || ! is_array( $entries ) ) {
							self::gap( $state, 'malformed cron event' );
							continue;
						}
						if ( in_array( $hook, array( GWQSH_Database_Scanner::HOOK, 'gwqsh_continue_integrity_scan', 'gwqsh_geo_lookup', 'gwqsh_reputation_lookup', 'gwqsh_deliver_events' ), true ) ) {
							continue;
						}
						$hooks[ $hook ] = true;
						if ( ! has_action( $hook ) && ! has_filter( $hook ) ) {
							$rules['DB-1105'] = 'Scheduled hooks have no handler in this request; stale jobs and lazy registration are possible. Review the cron record.';
						}
					}
				}
				$names = array_keys( $hooks );
				sort( $names, SORT_STRING );
				$state['context']['configuration']['cron_hooks'] = hash( 'sha256', wp_json_encode( $names ) );
			} elseif ( 'active_plugins' === $label ) {
				$names = array();
				foreach ( $value as $entry ) {
					if ( ! is_string( $entry ) || strlen( $entry ) > 191 || ! preg_match( '~^[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.php$~D', $entry ) || preg_match( '~(?:^|/)\.{1,2}(?:/|$)~', $entry ) ) {
						$rules['DB-1106'] = 'Active plugin configuration contains an invalid or escaping component path.';
						self::gap( $state, 'invalid active plugin path' );
						continue;
					}
					if ( ! GWQSH_Security_Runtime::safe_path( WP_PLUGIN_DIR . '/' . $entry, WP_PLUGIN_DIR ) || ! is_file( WP_PLUGIN_DIR . '/' . $entry ) ) {
						$rules['DB-1106'] = 'An active plugin file is missing or linked; review component integrity.';
					}
					$names[] = $entry;
				}
				sort( $names, SORT_STRING );
				$state['context']['configuration']['active_plugins'] = hash( 'sha256', wp_json_encode( $names ) );
			} else {
				$state['context']['configuration']['roles'] = hash( 'sha256', $row['sample'] );
			}
		}
		$key = $label === $wpdb->prefix . 'user_roles' ? 'roles' : $label;
		if ( 'cron' === $key ) {
			$key = 'cron_hooks';
		}
		if ( isset( $baseline['configuration'][ $key ], $state['context']['configuration'][ $key ] ) && $baseline['configuration'][ $key ] !== $state['context']['configuration'][ $key ] ) {
			$rules['DB-1107'] = 'Site, role, component or scheduled-hook configuration differs from the explicitly approved baseline. Legitimate changes require review.';
		}
		return $rules;
	}

	/** Inspect site-specific membership and exact account/capability drift.
	 *
	 * @param array $row Capability row with joined account identity.
	 * @param array $caps Data-only capability map.
	 * @param array $baseline Approved baseline.
	 * @param array $state Job metadata.
	 * @return array Review rules.
	 */
	private static function member( array $row, array $caps, array $baseline, &$state ) {
		$rules = array();
		++$state['context']['member_count'];
		if ( empty( $row['account_id'] ) ) {
			$rules['DB-1101'] = 'This site capability record references an account that does not exist; review the inconsistency.';
			self::gap( $state, 'orphan capability record' );
		}
		foreach ( $caps as $name => $enabled ) {
			if ( ! is_string( $name ) || ! is_bool( $enabled ) ) {
				self::gap( $state, 'malformed capability map' );
			}
		}
		$id         = (int) $row['record_id'];
		$user_id    = (int) $row['user_id'];
		$privileged = ! empty( $caps['administrator'] ) || ! empty( $caps['manage_options'] ) || ! empty( $caps['promote_users'] ) || ! empty( $caps['edit_users'] );
		foreach ( $caps as $role => $enabled ) {
			$definition = is_string( $role ) ? get_role( $role ) : null;
			if ( $enabled && $definition && $definition->has_cap( 'manage_options' ) ) {
				$privileged = true;
			}
		}
		$member = array(
			'id'         => $id,
			'user_id'    => $user_id,
			'login'      => (string) ( $row['login'] ?? '' ),
			'identity'   => hash( 'sha256', ( $row['login'] ?? '' ) . '|' . ( $row['registered'] ?? '' ) ),
			'hash'       => hash( 'sha256', $row['sample'] ),
			'privileged' => $privileged,
		);
		if ( isset( $state['context']['duplicates'][ $user_id ] ) ) {
			$rules['DB-1102'] = 'More than one capability record exists for this account and site; review ambiguous membership.';
			self::gap( $state, 'duplicate capability records' );
		}
		if ( count( $state['context']['members'] ) < self::MAX_MEMBERS ) {
			$state['context']['duplicates'][ $user_id ] = true;
			$state['context']['members'][ $id ]         = $member;
		} else {
			self::gap( $state, 'membership baseline exceeds 500 records' );
		}
		$old = $baseline['members'][ $id ] ?? null;
		if ( ! empty( $baseline['id'] ) && ( ( $privileged && ! $old ) || ( $old && ( $old['hash'] !== $member['hash'] || $old['identity'] !== $member['identity'] || $old['user_id'] !== $member['user_id'] ) ) ) ) {
			$rules['DB-1103'] = 'Account identity or capabilities differ from the approved site baseline; confirm authorization before action.';
		}
		return $rules;
	}

	/** Build a revalidated candidate for an explicit trust action.
	 *
	 * @param array $state Completed job.
	 * @return array|WP_Error Candidate snapshot.
	 */
	private static function candidate( array $state ) {
		if ( 'complete' !== ( $state['state'] ?? '' ) || ( $state['blog_id'] ?? 0 ) !== get_current_blog_id() || ( $state['updated_at'] ?? 0 ) < time() - 600 || ! empty( $state['context']['gaps'] ) || empty( $state['context']['members'] ) ) {
			return new WP_Error( 'candidate', 'A recent completed scan with valid, bounded membership/configuration evidence is required.' );
		}
		$context = $state['context'];
		foreach ( array( 'home', 'siteurl', 'roles', 'active_plugins' ) as $key ) {
			if ( ! isset( $context['configuration'][ $key ] ) ) {
				return new WP_Error( 'coverage', 'Required configuration evidence is missing; run a fresh complete scan.' );
			}
		}
		global $wpdb;
		// Hash bounded capability values in the database rather than loading 500 raw values.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT m.umeta_id AS id,m.user_id,LEFT(u.user_login,60) AS login,u.user_registered AS registered,CASE WHEN OCTET_LENGTH(m.meta_value)<=65536 THEN SHA2(m.meta_value,256) ELSE '' END AS digest FROM {$wpdb->usermeta} m LEFT JOIN {$wpdb->users} u ON u.ID=m.user_id WHERE m.meta_key=%s ORDER BY m.umeta_id LIMIT 501", $wpdb->prefix . 'capabilities' ), ARRAY_A );
		if ( $wpdb->last_error || ! is_array( $rows ) || count( $rows ) !== count( $context['members'] ) ) {
			return new WP_Error( 'changed', 'Membership changed or could not be revalidated. Rescan before approval.' );
		}
		foreach ( $rows as $row ) {
			$member = $context['members'][ $row['id'] ] ?? null;
			if ( ! $member || $member['hash'] !== $row['digest'] || (int) $row['user_id'] !== $member['user_id'] || hash( 'sha256', $row['login'] . '|' . $row['registered'] ) !== $member['identity'] ) {
				return new WP_Error( 'changed', 'Membership changed after inspection. Rescan before approval.' );
			}
		}
		$configuration = $wpdb->get_results( $wpdb->prepare( "SELECT option_name AS label,OCTET_LENGTH(option_value) AS bytes,LEFT(CAST(option_value AS BINARY),65536) AS sample FROM {$wpdb->options} WHERE option_name IN (%s,%s,%s,%s,%s)", 'home', 'siteurl', 'active_plugins', 'cron', $wpdb->prefix . 'user_roles' ), ARRAY_A );
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Configuration revalidation failed.' );
		}
		$check = array( 'coverage' => array() );
		self::begin( $check );
		foreach ( $configuration as $row ) {
			self::inspect( $row, 'options', $check );
		}
		ksort( $check['context']['configuration'] );
		ksort( $context['configuration'] );
		if ( $check['context']['configuration'] !== $context['configuration'] || $check['context']['gaps'] ) {
			return new WP_Error( 'changed', 'Configuration changed or is incomplete. Rescan before approval.' );
		}
		return array(
			'members'       => $context['members'],
			'configuration' => $context['configuration'],
		);
	}

	/** Explicit password/factor-verified baseline approval, never automatic trust.
	 *
	 * @param string $job_id Exact reviewed job.
	 * @param string $confirmed Explicit confirmation.
	 * @param string $token One-use current-session authorization.
	 * @return array|WP_Error Trust metadata only.
	 */
	public static function approve( $job_id, $confirmed, $token ) {
		$proof = GWQSH_Enterprise_UI::consume_proof( $token );
		if ( is_wp_error( $proof ) ) {
			return $proof;
		}
		if ( '1' !== $confirmed ) {
			return new WP_Error( 'confirmation', 'Confirm that account identities and capabilities were independently reviewed.' );
		}
		$lock = GWQSH_Enterprise_Store::lock( 'database-scan', 30 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'An investigation worker is active.' );
		}
		try {
			wp_cache_delete( GWQSH_Database_Scanner::OPTION, 'options' );
			$state = (array) get_option( GWQSH_Database_Scanner::OPTION, array() );
			if ( ! is_string( $job_id ) || ( $state['id'] ?? '' ) !== $job_id ) {
				return new WP_Error( 'stale', 'The reviewed investigation changed.' );
			}
			$candidate = self::candidate( $state );
			if ( is_wp_error( $candidate ) ) {
				return $candidate;
			}
			$previous = get_option( self::BASELINE, false );
			$backup   = array(
				'exists' => false !== $previous,
				'value'  => $previous,
			);
			update_option( self::BASELINE . '_previous', $backup, false );
			if ( get_option( self::BASELINE . '_previous' ) !== $backup ) {
				return new WP_Error( 'storage', 'Previous trust state could not be preserved.' );
			}
			$baseline = array_merge(
				$candidate,
				array(
					'schema'      => 1,
					'id'          => bin2hex( random_bytes( 16 ) ),
					'blog_id'     => get_current_blog_id(),
					'approved_at' => time(),
					'approved_by' => get_current_user_id(),
					'job_id'      => $job_id,
				)
			);
			update_option( self::BASELINE, $baseline, false );
			if ( get_option( self::BASELINE ) !== $baseline ) {
				return new WP_Error( 'storage', 'The trust baseline was not committed.' );
			}
			GWQSH_Activity_Logger::log(
				'Database trust baseline approved',
				wp_json_encode(
					array(
						'id'      => $baseline['id'],
						'members' => count( $baseline['members'] ),
					)
				),
				'Security'
			);
			return array(
				'id'          => $baseline['id'],
				'approved_at' => $baseline['approved_at'],
				'members'     => count( $baseline['members'] ),
			);
		} finally {
			GWQSH_Enterprise_Store::unlock( 'database-scan', $lock );
		}
	}

	/** Restore only the immediately preceding trust metadata, never account records.
	 *
	 * @param string $confirmed Explicit confirmation.
	 * @param string $token One-use current-session proof.
	 * @return array|WP_Error Result metadata.
	 */
	public static function rollback( $confirmed, $token ) {
		$proof = GWQSH_Enterprise_UI::consume_proof( $token );
		if ( is_wp_error( $proof ) ) {
			return $proof;
		}
		if ( '1' !== $confirmed ) {
			return new WP_Error( 'confirmation', 'Confirm restoration of the previous trust baseline.' );
		}
		$lock = GWQSH_Enterprise_Store::lock( 'database-scan', 30 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'An investigation worker is active.' );
		}
		try {
			$job      = (array) get_option( GWQSH_Database_Scanner::OPTION, array() );
			$previous = get_option( self::BASELINE . '_previous', false );
			if ( 'running' === ( $job['state'] ?? '' ) || ! is_array( $previous ) || ! is_bool( $previous['exists'] ?? null ) || ( $previous['exists'] && ( ! is_array( $previous['value'] ) || ( $previous['value']['blog_id'] ?? 0 ) !== get_current_blog_id() ) ) ) {
				return new WP_Error( 'baseline', 'No compatible previous baseline is available, or an investigation is still running.' );
			}
			$old    = get_option( self::BASELINE, false );
			$backup = array(
				'exists' => false !== $old,
				'value'  => $old,
			);
			update_option( self::BASELINE . '_previous', $backup, false );
			if ( get_option( self::BASELINE . '_previous' ) !== $backup ) {
				return new WP_Error( 'storage', 'Current trust state could not be preserved for reversal.' );
			}
			if ( $previous['exists'] ) {
				update_option( self::BASELINE, $previous['value'], false );
			} else {
				delete_option( self::BASELINE );
			}
			if ( get_option( self::BASELINE, false ) !== $previous['value'] ) {
				return new WP_Error( 'storage', 'Baseline restoration could not be verified.' );
			}
			GWQSH_Activity_Logger::log( 'Database trust baseline restored', 'Only the preceding trust metadata was restored; account and configuration records were not changed.', 'Security' );
			return array( 'configured' => $previous['exists'] );
		} finally {
			GWQSH_Enterprise_Store::unlock( 'database-scan', $lock );
		}
	}
}
