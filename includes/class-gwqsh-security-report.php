<?php
/** Bounded, read-only reporting over the existing activity store.
 *
 * @package GracewellSecuritySuitePro
 */
defined( 'ABSPATH' ) || exit;

/** Reports reuse the activity filters, redaction, categorization and CSV encoder. */
final class GWQSH_Security_Report {

	/** Register a protected download alongside the existing activity export. */
	public static function init() {
		add_action( 'admin_post_gwqsh_security_report', array( __CLASS__, 'download' ) );
	}

	/** Generate a coherent ID-bounded report with site-local calendar boundaries.
	 *
	 * @param array $input Existing activity filters; interval is day, week or month.
	 * @return array|WP_Error Report data, with explicit sampling/retention limitations.
	 */
	public static function collect( array $input = array() ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		$filters = GWQSH_Activity_View_Data::filters( $input );
		if ( is_wp_error( $filters ) ) {
			return $filters;
		}
		$interval = $input['interval'] ?? 'day';
		if ( ! in_array( $interval, array( 'day', 'week', 'month' ), true ) ) {
			return new WP_Error( 'interval', 'Choose day, week or month.' );
		}
		global $wpdb;
		$table = $wpdb->prefix . 'gwqsh_activity_log';
		// Fixed plugin-owned identifier. All filters are prepared by the shared builder.
		$max = (int) $wpdb->get_var( "SELECT MAX(id) FROM {$table}" );
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Report boundary could not be read.' );
		}
		$where = GWQSH_Activity_View_Data::where( $filters ) . $wpdb->prepare( ' AND id <= %d', $max );
		// Aggregate by calendar day and the existing fixed category expression, never user SQL identifiers.
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Category is a fixed source expression; where() prepares all external filter values and the boundary above is prepared.
		$groups = $wpdb->get_results( 'SELECT DATE(event_time) AS day, ' . GWQSH_Activity_View_Data::category_sql() . " AS category, COUNT(*) AS n FROM {$table} WHERE {$where} GROUP BY day, category ORDER BY day", ARRAY_A );
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Report aggregates could not be read.' );
		}
		$counts = array_fill_keys( array_keys( GWQSH_Activity_View_Data::GROUPS ), 0 );
		$daily  = array();
		foreach ( $groups as $row ) {
			$counts[ $row['category'] ] += (int) $row['n'];
			$daily[ $row['day'] ] = ( $daily[ $row['day'] ] ?? 0 ) + (int) $row['n'];
		}
		$trends = array();
		$window = array();
		$day    = new DateTimeImmutable( $filters['start'], wp_timezone() );
		$end    = new DateTimeImmutable( $filters['end'], wp_timezone() );
		while ( $day <= $end ) {
			$key = $day->format( 'Y-m-d' );
			$n   = $daily[ $key ] ?? 0;
			$window[] = $n;
			if ( count( $window ) > 7 ) {
				array_shift( $window );
			}
			$bucket = 'month' === $interval ? $day->format( 'Y-m-01' ) : ( 'week' === $interval ? $day->modify( 'monday this week' )->format( 'Y-m-d' ) : $key );
			if ( ! isset( $trends[ $bucket ] ) ) {
				$trends[ $bucket ] = array( 'date' => $bucket, 'count' => 0 );
			}
			$trends[ $bucket ]['count'] += $n;
			// Calendar-day trailing average, including zero-event days, as of the bucket's last included day.
			$trends[ $bucket ]['trailing_7day_average'] = round( array_sum( $window ) / count( $window ), 2 );
			$day = $day->modify( '+1 day' );
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Category is a fixed source expression; where() prepares all external filter values and the boundary above is prepared.
		$rows = $wpdb->get_results( 'SELECT *, ' . GWQSH_Activity_View_Data::category_sql() . " AS category FROM {$table} WHERE {$where} ORDER BY event_time DESC, id DESC LIMIT 200", ARRAY_A );
		if ( $wpdb->last_error ) {
			return new WP_Error( 'database', 'Report events could not be read.' );
		}
		return array(
			'generated_at' => current_datetime()->format( DATE_ATOM ),
			'timezone'     => wp_timezone_string(),
			'filters'      => $filters,
			'interval'     => $interval,
			'max_event_id' => $max,
			'total'        => array_sum( $counts ),
			'by_category'  => $counts,
			'trends'       => array_values( $trends ),
			'events'       => array_map( array( 'GWQSH_Activity_View_Data', 'record' ), $rows ),
			'limitations'  => array(
				'Only retained activity records are counted; deleted/expired history is unavailable.',
				'Recent event detail is capped at 200 rows. Aggregates cover all matching retained rows.',
				'Historical event severity and resolution status were not recorded and are not inferred.',
				'The maximum event ID excludes new inserts; concurrent deletion can change totals during generation.',
			),
		);
	}

	/** Self-contained HTML with escaped data and no network or executable dependencies.
	 *
	 * @param array $data Validated report.
	 * @return string Downloadable HTML, also printable using the browser.
	 */
	public static function html( array $data ) {
		$out = '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Gracewell Security Report</title><body><main><h1>Gracewell Security Report</h1>';
		$out .= '<p>Generated: ' . esc_html( $data['generated_at'] ) . ' | Timezone: ' . esc_html( $data['timezone'] ) . '</p>';
		$out .= '<p>Period: ' . esc_html( $data['filters']['start'] ) . ' to ' . esc_html( $data['filters']['end'] ) . '</p><h2>Retained events: ' . esc_html( (string) $data['total'] ) . '</h2><ul>';
		foreach ( $data['by_category'] as $category => $count ) {
			$out .= '<li>' . esc_html( GWQSH_Activity_View_Data::GROUPS[ $category ] ) . ': ' . esc_html( (string) $count ) . '</li>';
		}
		$out .= '</ul><h2>Event trends (' . esc_html( $data['interval'] ) . ')</h2><table><thead><tr><th>Date</th><th>Events</th><th>Trailing calendar-day average (up to 7 days)</th></tr></thead><tbody>';
		foreach ( $data['trends'] as $trend ) {
			$out .= '<tr><td>' . esc_html( $trend['date'] ) . '</td><td>' . esc_html( (string) $trend['count'] ) . '</td><td>' . esc_html( (string) $trend['trailing_7day_average'] ) . '</td></tr>';
		}
		$out .= '</tbody></table><h2>Recent matching events (maximum 200)</h2><table><thead><tr><th>Time</th><th>Category</th><th>Event</th><th>Description</th></tr></thead><tbody>';
		foreach ( $data['events'] as $event ) {
			$out .= '<tr><td>' . esc_html( $event['timestamp'] ) . '</td><td>' . esc_html( $event['badge'] ) . '</td><td>' . esc_html( $event['event_name'] ) . '</td><td>' . esc_html( $event['details'] ) . '</td></tr>';
		}
		$out .= '</tbody></table><h2>Coverage and limitations</h2><ul>';
		foreach ( $data['limitations'] as $limitation ) {
			$out .= '<li>' . esc_html( $limitation ) . '</li>';
		}
		return $out . '</ul></main></body></html>';
	}

	/** POST-only authenticated HTML/JSON download; CSV keeps its existing streaming route. */
	public static function download() {
		if ( 'POST' !== ( $_SERVER['REQUEST_METHOD'] ?? '' ) || ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			wp_die( 'Permission denied.', '', array( 'response' => 403 ) );
		}
		check_admin_referer( 'gwqsh_security_report' );
		$input  = wp_unslash( $_POST );
		$format = $input['format'] ?? 'html';
		if ( ! in_array( $format, array( 'html', 'json' ), true ) ) {
			wp_die( 'Unsupported report format.', '', array( 'response' => 400 ) );
		}
		$data = self::collect( $input );
		if ( is_wp_error( $data ) ) {
			wp_die( esc_html( $data->get_error_message() ), '', array( 'response' => 400 ) );
		}
		nocache_headers();
		header( 'X-Content-Type-Options: nosniff' );
		header( "Content-Security-Policy: default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" );
		header( 'Content-Type: ' . ( 'html' === $format ? 'text/html' : 'application/json' ) . '; charset=utf-8' );
		header( 'Content-Disposition: attachment; filename="gracewell-security-report.' . $format . '"' );
		// HTML is escaped by the renderer; JSON is never embedded in executable markup.
		echo 'html' === $format ? self::html( $data ) : wp_json_encode( $data, JSON_PRETTY_PRINT ); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped
		exit;
	}
}
