<?php
/**
 * Screen data for the database malware & persistence scan.
 *
 * The stored report is the single source of truth for every surface: the server-rendered
 * Firewall & Cleanup card, the authenticated AJAX refresh, and any future view. Nothing
 * here decides policy, and nothing is reported as clean without a completed scan.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Database scan view model. */
final class GWQSH_Database_View_Data {

	/** Maximum findings rendered in one response, matching the scanner's own cap. */
	const MAX_ROWS = 60;

	/**
	 * Assemble the screen payload.
	 *
	 * @return array View data.
	 */
	public static function get() {
		$report   = GWQSH_Database_Scanner::report();
		$scanned  = ! empty( $report );
		$baseline = get_option( GWQSH_Database_Scanner::BASELINE_OPTION, array() );
		$baseline = is_array( $baseline ) ? $baseline : array();
		$view     = self::report( $report );

		return array(
			'scanned'      => $scanned,
			'baseline'     => ! empty( $baseline['users'] ) && is_array( $baseline['users'] ) ? count( $baseline['users'] ) : 0,
			'baseline_at'  => (int) ( $baseline['approved_at'] ?? 0 ),
			'baseline_url' => 'Not recorded',
			'report'       => $view,
			'version'      => GWQSH_Database_Scanner::VERSION,
			'driver'       => GWQSH_DB::driver(),
			'status_label' => self::status_label( $view['status'] ),
			'coverage'     => self::coverage( $view ),
			'disclaimer'   => 'Database findings are evidence for review. Nothing is deleted or modified automatically.',
			'lede'         => 'Inspect stored options, posts, widgets, scheduled tasks and administrator records for malware and persistence.',
		);
	}

	/**
	 * Reduce a stored report to bounded, view-safe fields.
	 *
	 * Identifiers and labels are stripped of markup; evidence text is passed through as
	 * plain text because it is attacker-controlled by definition and must stay readable
	 * in the interface. The rendering layer escapes it exactly once, so a payload such as
	 * <script>alert(1)</script> is shown as inert characters rather than entities or markup.
	 *
	 * @param array $report Stored report.
	 * @return array View-safe report.
	 */
	public static function report( $report ) {
		$report = is_array( $report ) ? $report : array();
		$rows   = array();
		foreach ( array_slice( (array) ( $report['findings'] ?? array() ), 0, self::MAX_ROWS ) as $finding ) {
			if ( ! is_array( $finding ) ) {
				continue;
			}
			$rows[] = array(
				'rule'       => sanitize_text_field( (string) ( $finding['rule'] ?? '' ) ),
				'title'      => sanitize_text_field( (string) ( $finding['title'] ?? '' ) ),
				'severity'   => sanitize_text_field( (string) ( $finding['severity'] ?? '' ) ),
				'confidence' => sanitize_text_field( (string) ( $finding['confidence'] ?? '' ) ),
				'table'      => sanitize_text_field( (string) ( $finding['table'] ?? '' ) ),
				'column'     => sanitize_text_field( (string) ( $finding['column'] ?? '' ) ),
				'record'     => sanitize_text_field( (string) ( $finding['record'] ?? '' ) ),
				// Deliberately not escaped here: the interface escapes exactly once at render,
				// so stored evidence stays readable instead of double-encoded.
				'excerpt'    => (string) ( $finding['excerpt'] ?? '' ),
				'detail'     => (string) ( $finding['detail'] ?? '' ),
				'action'     => (string) ( $finding['action'] ?? '' ),
			);
		}

		$checks = array();
		foreach ( (array) ( $report['checks'] ?? array() ) as $key => $check ) {
			if ( ! is_array( $check ) ) {
				continue;
			}
			$checks[ sanitize_key( (string) $key ) ] = array(
				'label'   => sanitize_text_field( (string) ( $check['label'] ?? '' ) ),
				'rows'    => (int) ( $check['rows'] ?? 0 ),
				'limited' => ! empty( $check['limited'] ),
			);
		}

		$status = sanitize_key( (string) ( $report['status'] ?? 'none' ) );

		return array(
			'status'       => '' === $status ? 'none' : $status,
			'completed_at' => (int) ( $report['completed_at'] ?? 0 ),
			'duration_ms'  => (int) ( $report['duration_ms'] ?? 0 ),
			'summary'      => array_map( 'intval', (array) ( $report['summary'] ?? array() ) ),
			'checks'       => $checks,
			'findings'     => $rows,
			'multisite'    => ! empty( $report['multisite'] ),
		);
	}

	/**
	 * Human label for a scan status.
	 *
	 * @param string $status Sanitized status.
	 * @return string Label.
	 */
	public static function status_label( $status ) {
		$labels = array(
			'none'      => 'Never scanned',
			'completed' => 'Completed',
			'limited'   => 'Limited coverage',
			'failed'    => 'Failed',
		);
		return $labels[ $status ] ?? 'Unknown';
	}

	/**
	 * Coverage sentence for the interface.
	 *
	 * A scan that hit a limit or failed never reads as a clean result.
	 *
	 * @param array $view View-safe report.
	 * @return string Coverage description.
	 */
	public static function coverage( $view ) {
		if ( 'none' === $view['status'] ) {
			return 'No database scan has been recorded on this site yet.';
		}
		if ( 'failed' === $view['status'] ) {
			return 'The last scan could not complete. Its result is unknown, not clean: re-run it before trusting the site.';
		}
		$limited = array();
		foreach ( $view['checks'] as $check ) {
			if ( ! empty( $check['limited'] ) ) {
				$limited[] = $check['label'];
			}
		}
		if ( 'limited' === $view['status'] || $limited ) {
			return 'Coverage was incomplete for: ' . ( $limited ? implode( ', ', $limited ) : 'at least one check' ) . '. Treat the result as partial, not as proof that the database is clean.';
		}
		return 'Every check ran within its bounds. Findings still require review, and a clean scan is not a guarantee.';
	}
}
