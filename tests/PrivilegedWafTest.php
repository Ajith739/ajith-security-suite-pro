<?php
// phpcs:ignoreFile -- Development-only sanitized integration tests.
use PHPUnit\Framework\TestCase;

/**
 * Authenticated (privileged) payload inspection: bounded scope, detection by default,
 * never blocks content authoring, records no submitted values, and honours per-rule
 * exemptions.
 */
final class PrivilegedWafTest extends TestCase {

	private $restore  = array();
	private $globals = array();

	public function setUp(): void {
		parent::setUp();
		$this->globals = array(
			'post'        => $_POST,
			'get'         => $_GET,
			'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : null,
		);
	}


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
		// Superglobals are restored, never cleared: the rest of the suite renders admin pages
		// and needs the request environment exactly as it was.
		$_POST = $this->globals['post'];
		$_GET  = $this->globals['get'];
		if ( null === $this->globals['request_uri'] ) {
			unset( $_SERVER['REQUEST_URI'] );
		} else {
			$_SERVER['REQUEST_URI'] = $this->globals['request_uri'];
		}
		parent::tearDown();
	}

	/**
	 * Enable authenticated inspection, optionally enforcing it.
	 *
	 * @param array $overrides Section overrides.
	 * @return array Effective configuration.
	 */
	private function enable( array $overrides = array() ) {
		$stored = (array) get_option( 'gwqsh_enterprise', array() );
		$waf    = wp_parse_args(
			$overrides,
			array(
				'privileged' => true,
				'mode'       => 'block',
			)
		);
		$this->set_option( 'gwqsh_enterprise', array_merge( $stored, array( 'waf' => array_merge( (array) ( $stored['waf'] ?? array() ), $waf ) ) ) );
		return GWQSH_Enterprise_Config::get( 'waf' );
	}

	/** Highest recorded log id, so a test only sees the events it caused. */
	private function log_mark() {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		return (int) $wpdb->get_var( "SELECT MAX(id) FROM {$wpdb->prefix}gwqsh_activity_log" );
	}

	/**
	 * Authenticated-context firewall events recorded after a mark.
	 *
	 * @param int $mark Log id captured before the request under test.
	 * @return array Event names.
	 */
	private function events( $mark ) {
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$rows = $wpdb->get_col(
			$wpdb->prepare(
				"SELECT event_name FROM {$wpdb->prefix}gwqsh_activity_log WHERE id > %d AND event_name IN (%s, %s) ORDER BY id DESC LIMIT 5",
				$mark,
				'Firewall authenticated request detected',
				'Firewall authenticated request blocked'
			)
		);
		return array_map( 'strval', (array) $rows );
	}

	public function test_authenticated_sql_and_script_payloads_are_detected_by_default() {
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		wp_set_current_user( $admins[0]->ID );
		$this->enable( array( 'privileged' => true, 'mode' => 'block', 'privileged_enforce' => false ) );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		// A unique parameter name keeps the per-minute audit deduplication from hiding the
		// event when the suite is re-run inside the same minute.
		$param = 'price_filter_' . bin2hex( random_bytes( 4 ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixture request shape for the inspection test.
		$_POST = array( $param => "' UNION SELECT NULL, NULL -- " );
		$mark  = $this->log_mark();

		GWQSH_Firewall::inspect_privileged();
		$events = $this->events( $mark );

		$this->assertContains( 'Firewall authenticated request detected', $events, 'A matching payload must be recorded for review.' );
		$this->assertNotContains( 'Firewall authenticated request blocked', $events, 'Detection is the default: nothing is denied until enforcement is enabled.' );
		$this->assertSame( "' UNION SELECT NULL, NULL -- ", $_POST[ $param ], 'Inspection must never modify the request.' );
	}

	public function test_sensitive_parameters_and_oversized_content_are_never_inspected() {
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		wp_set_current_user( $admins[0]->ID );
		$this->enable( array( 'privileged' => true, 'privileged_enforce' => true ) );
		$_SERVER['REQUEST_URI'] = '/wp-admin/options.php';
		// Credentials, nonces and editor content must all be ignored, whatever they contain.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixture request shape for the inspection test.
		$_POST = array(
			'password'      => "' OR 1=1 --",
			'nonce'         => "' OR 1=1 --",
			'session_token' => "' OR 1=1 --",
			'post_content'  => str_repeat( '<script>alert(1)</script>', 200 ),
		);
		$mark = $this->log_mark();

		GWQSH_Firewall::inspect_privileged();

		$this->assertSame( array(), $this->events( $mark ), 'Credentials, nonces and long editor content are out of scope.' );
	}

	public function test_per_rule_exemptions_are_honoured_individually() {
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		wp_set_current_user( $admins[0]->ID );
		$this->enable( array( 'privileged' => true, 'privileged_enforce' => true, 'privileged_exclusions' => 'GWQSH-1006' ) );
		$_SERVER['REQUEST_URI'] = '/wp-admin/options.php';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixture request shape for the inspection test.
		$_POST = array( 'filter_a' => "' UNION SELECT NULL, NULL -- " );
		$mark  = $this->log_mark();

		GWQSH_Firewall::inspect_privileged();
		$this->assertSame( array(), $this->events( $mark ), 'An exempted rule must be skipped entirely.' );

		// Traversal is a different rule and stays in scope.
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixture request shape for the inspection test.
		$_POST = array( 'filter_b' => 'php://filter/convert.base64-encode/resource=wp-config.php' );
		$config = GWQSH_Enterprise_Config::get( 'waf' );
		$this->assertSame( 'block', GWQSH_Firewall::privileged_decision( 'GWQSH-1007', '/wp-admin/options.php', $config ) );
	}

	public function test_content_authoring_endpoints_are_never_blocked() {
		$config = array(
			'privileged'         => true,
			'privileged_enforce' => true,
			'mode'               => 'block',
			'exclusions'         => '',
		);
		foreach ( GWQSH_Firewall::content_writer_paths() as $path ) {
			$this->assertSame( 'detect', GWQSH_Firewall::privileged_decision( 'GWQSH-1006', $path, $config ), $path . ' must never be denied.' );
		}
		$this->assertSame( 'block', GWQSH_Firewall::privileged_decision( 'GWQSH-1006', '/wp-admin/options.php', $config ) );

		$exempt = array_merge( $config, array( 'exclusions' => "/wp-admin/options-general.php\n/wp-admin/options.php" ) );
		$this->assertSame( 'detect', GWQSH_Firewall::privileged_decision( 'GWQSH-1006', '/wp-admin/options.php', $exempt ) );

		$report_only = array_merge( $config, array( 'mode' => 'report' ) );
		$this->assertSame( 'detect', GWQSH_Firewall::privileged_decision( 'GWQSH-1006', '/wp-admin/options.php', $report_only ) );

		$disabled = array_merge( $config, array( 'privileged' => false ) );
		$this->assertSame( 'ignore', GWQSH_Firewall::privileged_decision( 'GWQSH-1006', '/wp-admin/options.php', $disabled ) );
	}

	public function test_opt_in_is_required_and_public_requests_are_untouched() {
		$config = (array) get_option( 'gwqsh_enterprise', array() );
		$this->set_option( 'gwqsh_enterprise', array_merge( $config, array( 'waf' => array( 'privileged' => false ) ) ) );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixture request shape for the inspection test.
		$_POST = array( 'any' => "' UNION SELECT NULL, NULL -- " );

		$viewer = get_current_user_id();
		$mark   = $this->log_mark();
		wp_set_current_user( 0 );
		GWQSH_Firewall::inspect_privileged();
		$this->assertSame( array(), $this->events( $mark ), 'Anonymous requests stay the public firewall path.' );

		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		wp_set_current_user( $admins[0]->ID );
		GWQSH_Firewall::inspect_privileged();
		$this->assertSame( array(), $this->events( $mark ), 'Authenticated inspection stays off until it is enabled.' );
		wp_set_current_user( $viewer );
	}

	public function test_recorded_events_never_contain_the_submitted_value() {
		global $wpdb;
		$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
		wp_set_current_user( $admins[0]->ID );
		$secret = 'gwqsh-payload-marker-' . bin2hex( random_bytes( 4 ) );
		$this->enable( array( 'privileged' => true, 'privileged_enforce' => false ) );
		$_SERVER['REQUEST_URI'] = '/wp-admin/admin-ajax.php';
		$param                  = 'marker_param_' . bin2hex( random_bytes( 4 ) );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Fixture request shape for the inspection test.
		$_POST = array( $param => "' OR 1=1 -- " . $secret );

		GWQSH_Firewall::inspect_privileged();

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching
		$details = (string) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT details FROM {$wpdb->prefix}gwqsh_activity_log WHERE event_name = %s ORDER BY id DESC LIMIT 1",
				'Firewall authenticated request detected'
			)
		);
		$this->assertNotSame( '', $details );
		$this->assertStringContainsString( 'GWQSH-1006', $details );
		$this->assertStringContainsString( $param, $details, 'The parameter name is recorded for review.' );
		$this->assertStringNotContainsString( $secret, $details, 'Submitted values must never be stored in the audit log.' );

		$rows = (array) get_option( 'gwqsh_enterprise', array() );
		$this->assertArrayHasKey( 'waf', $rows );
	}
}
