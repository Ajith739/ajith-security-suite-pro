<?php
// phpcs:ignoreFile -- Development-only sanitized integration tests.
use PHPUnit\Framework\TestCase;

/**
 * The database scan screen must expose bounded evidence, never raw payloads, and must not
 * claim a clean result for a scan that failed or ran with limited coverage.
 */
final class DatabaseScanPageTest extends TestCase {

	private $restore = array();

	private function set_option( $name, $value ) {
		global $wpdb;
		if ( ! array_key_exists( $name, $this->restore ) ) {
			$row                    = $wpdb->get_row( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", $name ), ARRAY_A );
			$this->restore[ $name ] = array(
				'exists'   => is_array( $row ),
				'value'    => get_option( $name, null ),
				'autoload' => is_array( $row ) ? $row['autoload'] : 'no',
			);
		}
		update_option( $name, $value, false );
	}

	public function tearDown(): void {
		foreach ( $this->restore as $name => $original ) {
			if ( $original['exists'] ) {
				update_option( $name, $original['value'], 'yes' === $original['autoload'] );
			} else {
				delete_option( $name );
			}
		}
		$this->restore = array();
		parent::tearDown();
	}

	public function test_screen_data_reports_an_unscanned_site_as_untrusted() {
		delete_option( GWQSH_Database_Scanner::REPORT_OPTION );
		$data = GWQSH_Database_View_Data::get();
		$this->assertFalse( $data['scanned'] );
		$this->assertSame( 'none', $data['report']['status'] );
		$this->assertSame( 'Never scanned', $data['status_label'] );
		$this->assertStringContainsString( 'No database scan has been recorded', $data['coverage'] );
		$this->assertSame( array(), $data['report']['findings'], 'An unscanned site must not present findings.' );
	}

	public function test_limited_and_failed_scans_are_never_described_as_clean() {
		$this->set_option(
			GWQSH_Database_Scanner::REPORT_OPTION,
			array(
				'status'   => 'limited',
				'checks'   => array( 'administrator_drift' => array( 'label' => 'Administrator accounts vs approved baseline', 'limited' => true ) ),
				'findings' => array(),
			)
		);
		$limited = GWQSH_Database_View_Data::get();
		$this->assertSame( 'Limited coverage', $limited['status_label'] );
		$this->assertStringContainsString( 'partial', $limited['coverage'] );
		$this->assertStringContainsString( 'Administrator accounts vs approved baseline', $limited['coverage'] );

		$this->set_option( GWQSH_Database_Scanner::REPORT_OPTION, array( 'status' => 'failed' ) );
		$failed = GWQSH_Database_View_Data::get();
		$this->assertSame( 'Failed', $failed['status_label'] );
		$this->assertStringContainsString( 'unknown, not clean', $failed['coverage'] );
	}

	public function test_attacker_controlled_evidence_is_escaped_and_bounded() {
		$payload = '<?php system($_GET["c"]); ?><script>alert(1)</script>';
		$this->set_option(
			GWQSH_Database_Scanner::REPORT_OPTION,
			array(
				'status'   => 'completed',
				'summary'  => array( 'Critical' => 1 ),
				'checks'   => array(),
				'findings' => array(
					array(
						'rule'       => 'GWQSH-3001<script>',
						'title'      => 'PHP <b>code</b>',
						'severity'   => 'Critical',
						'confidence' => 'High',
						'table'      => 'wp_options',
						'column'     => 'option_value',
						'record'     => 'gwqsh_fixture',
						'excerpt'    => $payload,
						'detail'     => 'Evidence   with   whitespace',
						'action'     => 'Review',
					),
					'not-an-array',
				),
			)
		);
		$data    = GWQSH_Database_View_Data::get();
		$finding = $data['report']['findings'][0];
		$this->assertCount( 1, $data['report']['findings'], 'Malformed findings must be dropped, not rendered.' );
		$this->assertStringNotContainsString( '<script>', $finding['rule'], 'Identifiers are stripped of markup.' );
		$this->assertStringNotContainsString( '<b>', $finding['title'] );
		// Evidence travels as plain text and is escaped exactly once by the interface, so
		// stored payloads stay readable instead of appearing as HTML entities. The escape
		// itself is verified in tests/jsdom-database-card.cjs against the rendered DOM.
		$this->assertSame( $payload, $finding['excerpt'], 'The excerpt is the stored evidence, unescaped, so it cannot be double-encoded.' );
		$this->assertStringNotContainsString( '&lt;', $finding['excerpt'], 'Pre-escaping here would double-encode every payload in the interface.' );
	}

	public function test_findings_are_capped_at_the_scanner_bound() {
		$findings = array();
		for ( $i = 0; $i < 120; $i++ ) {
			$findings[] = array(
				'rule'       => 'GWQSH-3004',
				'severity'   => 'High',
				'confidence' => 'Review',
				'table'      => 'wp_options',
				'column'     => 'option_value',
				'record'     => 'record-' . $i,
				'excerpt'    => 'indicator',
			);
		}
		$this->set_option( GWQSH_Database_Scanner::REPORT_OPTION, array( 'status' => 'completed', 'findings' => $findings ) );
		$data = GWQSH_Database_View_Data::get();
		$this->assertSame( GWQSH_Database_View_Data::MAX_ROWS, count( $data['report']['findings'] ) );
	}

	public function test_page_initial_data_carries_the_database_screen() {
		$data = GWQSH_Admin::get_page_initial_data( 'firewall-cleanup' );
		$this->assertArrayHasKey( 'database', $data );
		$this->assertArrayHasKey( 'report', $data['database'] );
		$this->assertArrayHasKey( 'status_label', $data['database'] );
		$this->assertStringContainsString( 'evidence for review', $data['database']['disclaimer'] );
		$this->assertArrayNotHasKey( 'raw', $data['database'], 'Internal scanner state must not be exposed.' );
	}

	public function test_scan_actions_require_the_management_capability_and_a_nonce() {
		$subscriber = wp_create_user( 'gwqsh_view_' . wp_generate_password( 8, false ), wp_generate_password( 20 ), 'gwqsh-view@example.invalid' );
		$viewer     = get_current_user_id();
		try {
			$user = new WP_User( $subscriber );
			$user->set_role( 'subscriber' );
			wp_set_current_user( $subscriber );
			$this->assertFalse( current_user_can( GWQSH_Admin::management_capability() ), 'A subscriber must not manage the scan.' );

			$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
			wp_set_current_user( $admins[0]->ID );
			$this->assertTrue( current_user_can( GWQSH_Admin::management_capability() ) );
			$this->assertFalse( check_ajax_referer( 'gwqsh_nonce', 'nonce', false ), 'Without a nonce the dispatcher must reject the request.' );
			$this->assertNotFalse( wp_create_nonce( 'gwqsh_nonce' ) );
		} finally {
			wp_set_current_user( $viewer );
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $subscriber );
		}
	}

	public function test_baseline_approval_records_current_administrators_only() {
		$before = get_option( GWQSH_Database_Scanner::BASELINE_OPTION, null );
		$temp   = wp_create_user( 'gwqsh_baseline_' . wp_generate_password( 8, false ), wp_generate_password( 20 ), 'gwqsh-baseline@example.invalid' );
		try {
			$approved = GWQSH_Database_Scanner::approve_administrators();
			$this->assertIsArray( $approved );
			$stored = get_option( GWQSH_Database_Scanner::BASELINE_OPTION );
			$this->assertIsArray( $stored );
			$this->assertArrayHasKey( 'users', $stored );
			$this->assertGreaterThan( 0, (int) $stored['approved_at'] );
			foreach ( array_keys( $stored['users'] ) as $user_id ) {
				$this->assertTrue( user_can( (int) $user_id, 'manage_options' ), 'Only administrators may be recorded in the baseline.' );
			}
			$this->assertArrayNotHasKey( (string) $temp, $stored['users'], 'A subscriber account must never enter the baseline.' );
			$rendered = GWQSH_Database_View_Data::get();
			$this->assertSame( count( $stored['users'] ), $rendered['baseline'] );
		} finally {
			if ( null === $before ) {
				delete_option( GWQSH_Database_Scanner::BASELINE_OPTION );
			} else {
				update_option( GWQSH_Database_Scanner::BASELINE_OPTION, $before, false );
			}
			require_once ABSPATH . 'wp-admin/includes/user.php';
			wp_delete_user( $temp );
		}
	}
}
