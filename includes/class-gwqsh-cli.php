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
		}
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
}
