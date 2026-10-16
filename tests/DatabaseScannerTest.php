<?php
// phpcs:ignoreFile -- Development-only sanitized integration tests.
use PHPUnit\Framework\TestCase;

/**
 * Database malware and persistence scanning must be bounded, read-only and honest
 * about coverage. These tests create and remove their own fixture rows.
 */
final class DatabaseScannerTest extends TestCase {

	/**
	 * Options this test overrides, with their exact original state so a test run can
	 * never destroy real site configuration (active_plugins, cron and others).
	 */
	private $restore = array();

	/**
	 * Override an option while remembering how to put it back exactly.
	 *
	 * @param string $name  Option name.
	 * @param mixed  $value Fixture value.
	 */
	private function set_option( $name, $value ) {
		global $wpdb;
		if ( ! array_key_exists( $name, $this->restore ) ) {
			$row = $wpdb->get_row( $wpdb->prepare( "SELECT autoload FROM {$wpdb->options} WHERE option_name = %s", $name ), ARRAY_A );
			$this->restore[ $name ] = array(
				'exists'   => is_array( $row ),
				'value'    => get_option( $name, null ),
				'autoload' => is_array( $row ) ? $row['autoload'] : 'no',
			);
		}
		update_option( $name, $value, false );
	}

	/**
	 * Remove a fixture option that this test created (never a pre-existing option).
	 *
	 * @param string $name Option name.
	 */
	private function unset_fixture_option( $name ) {
		if ( ! isset( $this->restore[ $name ] ) || ! $this->restore[ $name ]['exists'] ) {
			delete_option( $name );
		}
	}

	public function tearDown(): void {
		global $wpdb;
		foreach ( $this->restore as $name => $original ) {
			if ( $original['exists'] ) {
				update_option( $name, $original['value'], 'yes' === $original['autoload'] );
			} else {
				delete_option( $name );
			}
		}
		$this->restore = array();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->posts} WHERE post_title = %s", 'gwqsh-db-scan-fixture' ) );
		parent::tearDown();
	}

	public function test_report_is_untrusted_when_never_scanned() {
		delete_option( GWQSH_Database_Scanner::REPORT_OPTION );
		$this->assertSame( array(), GWQSH_Database_Scanner::report() );
	}

	public function test_php_source_stored_in_an_option_is_reported_with_review_evidence() {
		$this->set_option( 'gwqsh_fixture_php_payload', '<?php system($_GET["c"]); ?>' );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$rules  = array_column( $report['findings'], 'rule' );
		$this->assertContains( 'GWQSH-3001', $rules );
		$finding = null;
		foreach ( $report['findings'] as $row ) {
			if ( 'GWQSH-3001' === $row['rule'] && 'gwqsh_fixture_php_payload' === $row['record'] ) {
				$finding = $row;
			}
		}
		$this->assertNotNull( $finding, 'The specific stored record must be identifiable for review.' );
		$this->assertSame( 'Critical', $finding['severity'] );
		$this->assertSame( $GLOBALS['wpdb']->options, $finding['table'] );
		$this->assertLessThanOrEqual( GWQSH_Database_Scanner::MAX_EXCERPT, strlen( $finding['excerpt'] ) );
		$this->assertStringContainsString( 'never edits site data', $finding['action'] );
	}

	public function test_benign_markup_and_scripts_are_not_reported() {
		$benign = '<div class="promo"><script src="https://cdn.example.test/embed.js"></script>'
			. '<script>window.dataLayer=window.dataLayer||[];dataLayer.push({"event":"view"});</script></div>';
		$this->set_option( 'gwqsh_fixture_benign_markup', $benign );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		// The script prefilter must have examined rows, otherwise the negative result is meaningless.
		$this->assertGreaterThan( 0, $report['checks']['obfuscated_scripts']['rows'], 'The obfuscation check must actually inspect script-bearing rows.' );
		$records = array();
		foreach ( $report['findings'] as $row ) {
			$records[] = $row['record'];
		}
		$this->assertNotContains( 'gwqsh_fixture_benign_markup', $records, 'Ordinary embed markup must not be reported.' );
		$this->assertSame( $benign, get_option( 'gwqsh_fixture_benign_markup' ), 'Inspection must not modify the inspected value.' );
	}

	public function test_obfuscated_script_in_a_widget_option_is_reported() {
		$payload = '<script>var _0x1=atob("ZG9jdW1lbnQ=");eval(_0x1);document.write("<iframe src=\'http://bad.example\' style=\'display:none\'></iframe>");</script>';
		$this->set_option( 'widget_gwqsh_fixture', array( 'text' => $payload ) );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$rules  = array_column( $report['findings'], 'rule' );
		$this->assertContains( 'GWQSH-3002', $rules );
		$this->assertContains( 'GWQSH-3003', $rules );
	}

	public function test_cloaked_frame_without_any_script_tag_is_reported() {
		// Regression: the frame check used to be reachable only for values that also
		// contained a script tag, so an iframe-only cloaked redirect was never reported.
		$this->set_option( 'gwqsh_fixture_frame_only', '<iframe src="http://203.0.113.9/go.php" width="1" height="1" style="position:absolute;left:-9999px"></iframe>' );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$rules  = array_column( $report['findings'], 'rule' );
		$this->assertContains( 'GWQSH-3003', $rules );
		$this->assertNotContains( 'GWQSH-3002', $rules, 'A frame without an obfuscated script is a frame finding, not a script finding.' );
	}

	public function test_visible_embeds_are_not_reported_as_cloaked_frames() {
		$benign = '<iframe width="560" height="315" src="https://www.youtube.com/embed/aBcDeFg" title="Product tour" frameborder="0" allowfullscreen></iframe>'
			. '<div class="helper" style="display:none">Hidden layout helper, not a frame.</div>';
		$this->set_option( 'gwqsh_fixture_visible_embed', $benign );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$frames = array();
		foreach ( $report['findings'] as $row ) {
			if ( 'GWQSH-3003' === $row['rule'] && 'gwqsh_fixture_visible_embed' === $row['record'] ) {
				$frames[] = $row;
			}
		}
		$this->assertSame( array(), $frames, 'A visible embed must not be reported as a cloaked frame.' );
		$this->assertGreaterThan( 0, (int) $GLOBALS['wpdb']->get_var( "SELECT COUNT(*) FROM {$GLOBALS['wpdb']->options}" ), 'Fixture guard: the scan must have had rows to inspect.' );
		$this->assertSame( $benign, get_option( 'gwqsh_fixture_visible_embed' ) );
	}

	public function test_known_indicator_in_stored_data_is_reported() {
		$this->set_option( 'gwqsh_fixture_ioc', 'a:1:{s:4:"path";s:24:"/wp-content/ms_gate_heal_restore.php";}' );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$this->assertContains( 'GWQSH-3004', array_column( $report['findings'], 'rule' ) );
	}

	public function test_unregistered_cron_hook_is_flagged_but_wordpress_hooks_are_not() {
		$existing = get_option( 'cron', array() );
		$cron     = is_array( $existing ) ? $existing : array();
		$cron[ time() + 600 ] = array(
			'wp_version_check'          => array( array( 'schedule' => 'twicedaily', 'args' => array() ) ),
			'gwqsh_x7f9_persist_a91c2e' => array( array( 'schedule' => 'hourly', 'args' => array( '<?php eval($_POST[1]);' ) ) ),
		);
		$this->set_option( 'cron', $cron );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$records = array();
		foreach ( $report['findings'] as $row ) {
			if ( 'GWQSH-3005' === $row['rule'] ) {
				$records[] = $row['record'];
			}
		}
		$this->assertContains( 'gwqsh_x7f9_persist_a91c2e', $records );
		$this->assertNotContains( 'wp_version_check', $records );
		$this->unset_fixture_option( 'cron' );
	}

	public function test_administrator_drift_requires_an_approved_baseline() {
		$user_id = wp_create_user( 'gwqsh-fixture-admin-' . bin2hex( random_bytes( 4 ) ), 'Str0ng-FixTure-Pass-1!', 'gwqsh-fixture-' . bin2hex( random_bytes( 4 ) ) . '@example.test' );
		$this->assertIsInt( $user_id );
		$user = new WP_User( $user_id );
		$user->set_role( 'administrator' );

		delete_option( GWQSH_Database_Scanner::BASELINE_OPTION );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$this->assertSame( array(), array_values( array_filter( array_column( $report['findings'], 'rule' ), static function ( $rule ) { return 'GWQSH-3006' === $rule; } ) ), 'Drift must not be asserted without an approved baseline.' );
		$this->assertTrue( $report['checks']['administrator_drift']['limited'], 'An unapproved baseline must be reported as a coverage limitation.' );

		GWQSH_Database_Scanner::approve_administrators();
		$user_id2 = wp_create_user( 'gwqsh-fixture-admin2-' . bin2hex( random_bytes( 4 ) ), 'Str0ng-FixTure-Pass-2!', 'gwqsh-fixture2-' . bin2hex( random_bytes( 4 ) ) . '@example.test' );
		( new WP_User( $user_id2 ) )->set_role( 'administrator' );
		$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$records = array();
		foreach ( $report['findings'] as $row ) {
			if ( 'GWQSH-3006' === $row['rule'] ) {
				$records[] = (int) $row['record'];
			}
		}
		$this->assertContains( (int) $user_id2, $records );
		$this->assertNotContains( (int) $user_id, $records );

		require_once ABSPATH . 'wp-admin/includes/user.php';
		wp_delete_user( $user_id );
		wp_delete_user( $user_id2 );
		delete_option( GWQSH_Database_Scanner::BASELINE_OPTION );
	}

	public function test_capability_record_without_an_account_is_reported() {
		global $wpdb;
		$orphan_id = 990000 + wp_rand( 1, 9000 );
		$wpdb->insert(
			$wpdb->usermeta,
			array(
				'user_id'    => $orphan_id,
				'meta_key'   => $wpdb->prefix . 'capabilities',
				'meta_value' => serialize( array( 'administrator' => true ) ),
			)
		);
		$record_id = (int) $wpdb->insert_id;
		try {
			$report = GWQSH_Database_Scanner::run( array( 'store' => false ) );
			$records = array();
			foreach ( $report['findings'] as $row ) {
				if ( 'GWQSH-3007' === $row['rule'] ) {
					$records[] = (int) $row['record'];
				}
			}
			$this->assertContains( $record_id, $records );
		} finally {
			$wpdb->delete( $wpdb->usermeta, array( 'umeta_id' => $record_id ) );
		}
	}

	public function test_stored_objects_are_never_instantiated_while_parsing() {
		$payload = 'a:1:{s:4:"evil";O:24:"GWQSH_Unsafe_Fixture_Obj":0:{}}';
		$this->assertFalse( class_exists( 'GWQSH_Unsafe_Fixture_Obj', false ) );
		$parsed = GWQSH_Database_Scanner::safe_unserialize( $payload );
		$this->assertIsArray( $parsed );
		$this->assertInstanceOf( __PHP_Incomplete_Class::class, $parsed['evil'], 'Object payloads must remain inert incomplete classes.' );
	}

	public function test_missing_active_plugin_file_is_reported() {
		$active   = (array) get_option( 'active_plugins', array() );
		$active[] = 'gwqsh-missing-fixture/plugin.php';
		$this->set_option( 'active_plugins', $active );
		$report  = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$records = array();
		foreach ( $report['findings'] as $row ) {
			if ( 'GWQSH-3008' === $row['rule'] ) {
				$records[] = $row['record'];
			}
		}
		$this->assertContains( 'gwqsh-missing-fixture/plugin.php', $records );
	}

	public function test_scan_is_read_only_and_reports_coverage_limits() {
		global $wpdb;
		$sentinel        = 'gwqsh-sentinel-' . bin2hex( random_bytes( 4 ) );
		$payload_before  = '<?php echo "fixture"; ?>';
		$this->set_option( 'gwqsh_fixture_readonly', $payload_before );
		$options_before = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( $sentinel ) . '%' ) );

		$report = GWQSH_Database_Scanner::run();

		$this->assertSame( $payload_before, get_option( 'gwqsh_fixture_readonly' ), 'Scanning must not alter stored data.' );
		$this->assertSame( $options_before, (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE %s", $wpdb->esc_like( $sentinel ) . '%' ) ) );
		$this->assertArrayHasKey( 'checks', $report );
		$this->assertArrayHasKey( 'php_in_data', $report['checks'] );
		$this->assertArrayHasKey( 'cron_persistence', $report['checks'] );
		$this->assertContains( $report['status'], array( 'completed', 'limited' ), 'A failed scan must never be reported as a clean result.' );
		foreach ( $report['findings'] as $row ) {
			$this->assertLessThanOrEqual( GWQSH_Database_Scanner::MAX_EXCERPT, strlen( $row['excerpt'] ) );
			$this->assertNotSame( '', $row['rule'] );
		}
		$stored = GWQSH_Database_Scanner::report();
		$this->assertSame( $report['status'], $stored['status'] );
		$this->assertSame( $report['version'], $stored['version'] );
	}
	public function test_scheduled_scan_follows_the_administrator_scan_opt_in() {
		$this->set_option( 'gwqsh_scan_schedule', array( 'enabled' => false ) );
		wp_clear_scheduled_hook( GWQSH_Database_Scanner::CRON_HOOK );
		GWQSH_Database_Scanner::init();
		$this->assertFalse( wp_next_scheduled( GWQSH_Database_Scanner::CRON_HOOK ), 'A disabled schedule must not leave a recurring database scan behind.' );

		$this->set_option( 'gwqsh_scan_schedule', array( 'enabled' => true ) );
		GWQSH_Database_Scanner::init();
		$next = wp_next_scheduled( GWQSH_Database_Scanner::CRON_HOOK );
		$this->assertIsInt( $next, 'Enabling scheduled scanning must queue the bounded database scan.' );

		$this->set_option( 'gwqsh_scan_schedule', array( 'enabled' => false ) );
		GWQSH_Database_Scanner::init();
		$this->assertFalse( wp_next_scheduled( GWQSH_Database_Scanner::CRON_HOOK ) );
	}

	public function test_scheduled_run_is_skipped_when_scheduling_was_disabled() {
		$this->set_option( 'gwqsh_scan_schedule', array( 'enabled' => false ) );
		update_option( GWQSH_Database_Scanner::REPORT_OPTION, array( 'status' => 'completed', 'sentinel' => true ), false );
		// The hook is the only caller allowed to skip; direct calls must still scan.
		add_action(
			GWQSH_Database_Scanner::CRON_HOOK,
			static function () {
				GWQSH_Database_Scanner::run(); }
		);
		do_action( GWQSH_Database_Scanner::CRON_HOOK );
		$this->assertSame( 'completed', GWQSH_Database_Scanner::report()['status'] );
		$this->assertArrayHasKey( 'sentinel', GWQSH_Database_Scanner::report(), 'A disabled schedule must not replace the stored report.' );

		$direct = GWQSH_Database_Scanner::run( array( 'store' => false ) );
		$this->assertArrayHasKey( 'findings', $direct, 'On-demand runs must not depend on the schedule opt-in.' );
	}
}
