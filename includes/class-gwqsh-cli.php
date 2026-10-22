<?php
/** Read-only WP-CLI adapters for existing services.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** No license server, scan completion or protection coverage is simulated. */
final class GWQSH_CLI {

	/** Register only when WP-CLI is present. */
	public static function init() {
		if ( defined( 'WP_CLI' ) && WP_CLI ) {
			WP_CLI::add_command( 'gracewell report', array( __CLASS__, 'report' ) );
			WP_CLI::add_command( 'gracewell inventory', array( __CLASS__, 'inventory' ) );
			WP_CLI::add_command( 'gracewell network-policy', array( __CLASS__, 'network_policy' ) );
			WP_CLI::add_command( 'gracewell network-summary', array( __CLASS__, 'network_summary' ) );
			WP_CLI::add_command( 'gracewell backup', array( __CLASS__, 'backup' ) );
            WP_CLI::add_command( 'gracewell doctor', array( __CLASS__, 'doctor' ) );
		}
	}


    /** Read-only site readiness details; use --user=<security-administrator>.
     *
     * ## OPTIONS
     * [--format=<format>]
     * : json (default) or text.
     *
     * @param array $args Positional arguments.
     * @param array $options Named options.
     */
    public static function doctor( $args, $options ) {
        $format = $options['format'] ?? 'json';
        if ( ! in_array( $format, array( 'json', 'text' ), true ) ) {
            WP_CLI::error( 'Supported formats: json, text.' );
        }
        $report = GWQSH_Security_Doctor::collect();
        if ( is_wp_error( $report ) ) {
            WP_CLI::error( $report->get_error_message() );
        }
        if ( 'json' === $format ) {
            WP_CLI::line( wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
            return;
        }
        foreach ( $report['checks'] as $check ) {
            WP_CLI::line( strtoupper( $check['state'] ) . ' | ' . $check['title'] . ' | ' . $check['detail'] );
        }
        WP_CLI::line( 'Reminder: configuration checks are not a production security rating.' );
    }

	/** Export retained audit data using --user=<administrator>.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : json (default) or html. Redirect stdout to a private destination.
	 *
	 * [--days=<days>]
	 * : 1, 7, 30 (default), 90 or 365 calendar days.
	 *
	 * [--start=<date>]
	 * : Start date in site timezone, YYYY-MM-DD. Requires --end.
	 *
	 * [--end=<date>]
	 * : Inclusive end date in site timezone, YYYY-MM-DD.
	 *
	 * [--interval=<interval>]
	 * : day (default), week or month.
	 *
	 * @param array $args Positional arguments.
	 * @param array $options Validated service options.
	 */
	public static function report( $args, $options ) {
		$format = $options['format'] ?? 'json';
		if ( ! in_array( $format, array( 'json', 'html' ), true ) ) {
			WP_CLI::error( 'Supported report formats: json, html. CSV remains available from Activity Log.' );
		}
		$report = GWQSH_Security_Report::collect( $options );
		if ( is_wp_error( $report ) ) {
			WP_CLI::error( $report->get_error_message() );
		}
		WP_CLI::line( 'html' === $format ? GWQSH_Security_Report::html( $report ) : wp_json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
	}

	/** List core, plugins, MU-plugins and themes using --user=<administrator>.
	 *
	 * @param array $args Positional arguments.
	 * @param array $options Options.
	 */
	public static function inventory( $args, $options ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			WP_CLI::error( 'Administrative permission required; select --user.' );
		}
		WP_CLI::line( wp_json_encode( GWQSH_Vulnerabilities::inventory(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
	}
	/** Read or set network WAF policy using --user=<network-super-admin>.
	 *
	 * ## OPTIONS
	 * [--settings-file=<path>]
	 * : JSON object using the existing WAF schema. Omit for read-only status.
	 * [--allow-site-overrides]
	 * : Inherit network defaults while retaining per-site overrides.
	 * [--remove]
	 * : Remove network inheritance; existing per-site settings are retained.
	 *
	 * @param array $args Positional arguments.
	 * @param array $options Named options.
	 */
	public static function network_policy( $args, $options ) {
		if ( ! is_multisite() || ! is_super_admin() || ! current_user_can( 'manage_network_options' ) ) {
			WP_CLI::error( 'Select a network super administrator using --user.' );
		}
		if ( isset( $options['remove'], $options['settings-file'] ) ) {
			WP_CLI::error( 'Choose settings-file or remove.' );
		}
		if ( isset( $options['settings-file'] ) ) {
			$file = $options['settings-file'];
			if ( ! is_file( $file ) || ! is_readable( $file ) || filesize( $file ) > 16384 ) {
				WP_CLI::error( 'Provide a readable WAF JSON settings file up to 16 KiB.' );
			}
			$input = json_decode( file_get_contents( $file ), true, 8 );
			if ( ! is_array( $input ) || JSON_ERROR_NONE !== json_last_error() ) {
				WP_CLI::error( 'Invalid WAF JSON settings object.' );
			}
			$result = GWQSH_Enterprise_Config::save_network_waf( $input, ! isset( $options['allow-site-overrides'] ) );
		} elseif ( isset( $options['remove'] ) ) {
			$result = GWQSH_Enterprise_Config::save_network_waf( null );
		} else {
			$result = true;
		}
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		WP_CLI::line( wp_json_encode( get_site_option( 'gwqsh_enterprise_policy', array() ), JSON_PRETTY_PRINT ) );
	}

	/** Export bounded network site health metadata using --user=<network-super-admin>.
	 *
	 * ## OPTIONS
	 * [--offset=<offset>]
	 * : Paginate through sites; each call returns at most 100 entries.
	 *
	 * @param array $args Positional arguments.
	 * @param array $options Named options.
	 */
	public static function network_summary( $args, $options ) {
		if ( ! is_multisite() || ! is_super_admin() || ! current_user_can( 'manage_network_options' ) ) {
			WP_CLI::error( 'Select a network super administrator using --user.' );
		}
		$offset = max( 0, min( 1000000, (int) ( $options['offset'] ?? 0 ) ) );
		$out    = array();
		foreach ( get_sites(
			array(
				'number'  => 100,
				'offset'  => $offset,
				'orderby' => 'id',
				'order'   => 'ASC',
			)
		) as $site ) {
			switch_to_blog( $site->blog_id );
			try {
				$scan  = (array) get_option( 'gwqsh_database_scan', array() );
				$out[] = array(
					'blog_id'                     => (int) $site->blog_id,
					'domain'                      => $site->domain,
					'path'                        => $site->path,
					'waf_mode'                    => GWQSH_Enterprise_Config::get( 'waf' )['mode'],
					'database_scan_state'         => $scan['state'] ?? 'not_run',
					'database_scan_updated_at'    => $scan['updated_at'] ?? 0,
					'last_file_scan_scope_counts' => get_option( 'gwqsh_last_scan_scope_counts', array() ),
					'signature_health'            => GWQSH_Signatures::health(),
					'advisory_last_attempt'       => get_option( 'gwqsh_advisory_health', array() ),
				);
			} finally {
				restore_current_blog();
			}
		}
		WP_CLI::line(
			wp_json_encode(
				array(
					'offset'      => $offset,
					'sites'       => $out,
					'next_offset' => count( $out ) === 100 ? $offset + 100 : null,
				),
				JSON_PRETTY_PRINT
			)
		);
	}
	/** Manage bounded database snapshots using --user=<security-administrator>.
	 *
	 * ## OPTIONS
	 * [--start]
	 * : Start an export, or resume the existing running job. WP-Cron continues batches.
	 * [--continue=<id>]
	 * : Process one batch of an existing job.
	 * [--verify=<id>]
	 * : Verify authenticated scope and all stored chunks.
	 * [--cancel=<id>]
	 * : Cancel pending continuation while retaining evidence.
	 *
	 * @param array $args Positional arguments.
	 * @param array $options Named options.
	 */
	public static function backup( $args, $options ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			WP_CLI::error( 'Select a security administrator using --user.' );
		}
		$actions = array_intersect( array_keys( $options ), array( 'start', 'continue', 'verify', 'cancel' ) );
		if ( count( $actions ) > 1 ) {
			WP_CLI::error( 'Choose a single backup operation.' );
		}
		$action = $actions ? reset( $actions ) : 'list';
		if ( 'start' === $action ) {
			$result = GWQSH_Backup_Engine::create_database_backup( 'cli' );
		} elseif ( 'continue' === $action ) {
			$result = GWQSH_Backup_Engine::continue_database_backup( $options['continue'] );
		} elseif ( 'verify' === $action ) {
			$result = GWQSH_Backup_Engine::verify_backup( $options['verify'] );
		} elseif ( 'cancel' === $action ) {
			$result = GWQSH_Backup_Engine::cancel_database_backup( $options['cancel'] );
		} else {
			$result = GWQSH_Backup_Engine::list_backups();
		}
		if ( is_wp_error( $result ) ) {
			WP_CLI::error( $result->get_error_message() );
		}
		WP_CLI::line( wp_json_encode( $result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
	}

}
