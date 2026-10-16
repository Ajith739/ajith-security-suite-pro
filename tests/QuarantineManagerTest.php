<?php
// phpcs:ignoreFile -- Development-only sanitized integration tests.
use PHPUnit\Framework\TestCase;

final class QuarantineManagerTest extends TestCase {

	/**
	 * Test PathGuard validates WordPress roots correctly and blocks traversal.
	 */
	public function test_path_guard_validates_and_protects() {
		// Valid relative paths within WordPress root.
		$val = GWQSH_Path_Guard::validate( 'wp-includes/version.php' );
		$this->assertIsArray( $val );
		$this->assertSame( 'wp-includes/version.php', $val['relative'] );
		$this->assertTrue( is_file( $val['canonical'] ) );

		// Traversal attack should be blocked (returns null).
		$this->assertNull( GWQSH_Path_Guard::validate( '../../../etc/passwd' ) );
		$this->assertNull( GWQSH_Path_Guard::validate( 'wp-content/../../../../etc/shadow' ) );

		// Safe check helper.
		$this->assertTrue( GWQSH_Path_Guard::is_safe( 'wp-config.php' ) );
		$this->assertFalse( GWQSH_Path_Guard::is_safe( '/etc/passwd' ) );
	}

	/**
	 * Test PathGuard handles macOS /tmp symlink correctly.
	 */
	public function test_path_guard_normalizes_tmp() {
		$tmp = get_temp_dir();
		$norm_tmp = GWQSH_Path_Guard::normalize( $tmp );
		$this->assertNotEmpty( $norm_tmp );
		$this->assertStringNotContainsString( '\\', $norm_tmp );
	}

	/**
	 * Test QuarantineManager page size validation.
	 */
	public function test_page_size_validation() {
		$this->assertSame( 5, GWQSH_Quarantine_Manager::validate_page_size( 5 ) );
		$this->assertSame( 25, GWQSH_Quarantine_Manager::validate_page_size( 25 ) );
		$this->assertSame( 10, GWQSH_Quarantine_Manager::validate_page_size( 10 ) );
		$this->assertSame( 20, GWQSH_Quarantine_Manager::validate_page_size( 20 ) );
		$this->assertSame( 50, GWQSH_Quarantine_Manager::validate_page_size( 50 ) );
		$this->assertSame( 500, GWQSH_Quarantine_Manager::validate_page_size( 500 ) );

		// Invalid values fall back to default (20).
		$this->assertSame( 20, GWQSH_Quarantine_Manager::validate_page_size( 7 ) );
		$this->assertSame( 20, GWQSH_Quarantine_Manager::validate_page_size( 9999 ) );
		$this->assertSame( 20, GWQSH_Quarantine_Manager::validate_page_size( -5 ) );
	}

	/**
	 * Test QuarantineManager error messages.
	 */
	public function test_structured_error_messages() {
		$msg = GWQSH_Quarantine_Manager::error_message( GWQSH_Quarantine_Manager::ERR_FINDING_NOT_FOUND );
		$this->assertStringContainsString( 'could not be found', $msg );

		$msg2 = GWQSH_Quarantine_Manager::error_message( GWQSH_Quarantine_Manager::ERR_PROTECTED_FILE );
		$this->assertStringContainsString( 'cannot be quarantined', $msg2 );

		$msg3 = GWQSH_Quarantine_Manager::error_message( GWQSH_Quarantine_Manager::ERR_CRITICAL_MALWARE );
		$this->assertStringContainsString( 'Critical malware', $msg3 );
	}

	/**
	 * Test full quarantine, restore, and delete lifecycle.
	 */
	public function test_quarantine_lifecycle() {
		global $wpdb;
		$wpdb->query( 'START TRANSACTION' );

		// Create a test file in uploads.
		$uploads = wp_upload_dir();
		$filename = 'gwqsh-test-' . bin2hex( random_bytes( 6 ) ) . '.php';
		$test_file = trailingslashit( $uploads['basedir'] ) . $filename;
		$content = "<?php\n// Test malicious content " . bin2hex( random_bytes( 8 ) ) . "\neval('phpinfo();');\n";
		file_put_contents( $test_file, $content );
		$file_hash = hash( 'sha256', $content );

		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );

		try {
			// Insert finding into gwqsh_scan_results.
			$relative = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $test_file ) ), '/' );
			$wpdb->insert(
				$table,
				array(
					'file_path'   => '/' . $relative,
					'file_type'   => 'Uploads',
					'status'      => 'Suspicious',
					'details'     => 'Test suspicious eval in uploads',
					'detected_at' => current_time( 'mysql' ),
					'is_resolved' => 0,
					'evidence'    => wp_json_encode(
						array(
							'severity'   => 'High',
							'confidence' => 'Firm',
							'score'      => 85,
							'hash'       => $file_hash,
						)
					),
				)
			);
			$finding_id = (int) $wpdb->insert_id;
			$this->assertGreaterThan( 0, $finding_id );

			// 1. Quarantine the file by finding ID.
			$q_result = GWQSH_Quarantine_Manager::quarantine_by_finding( $finding_id );
			$this->assertIsArray( $q_result );
			$this->assertSame( $finding_id, $q_result['finding_id'] );
			$this->assertSame( $file_hash, $q_result['hash'] );
			$this->assertFalse( file_exists( $test_file ), 'Original file must be removed after quarantine' );
			$stored_file = GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $q_result['artifact_id'] . '.quarantine';
			$this->assertTrue( file_exists( $stored_file ), 'Quarantined file must exist in storage' );

			// Check quarantine list.
			$list = GWQSH_Quarantine_Manager::list_quarantined();
			$this->assertIsArray( $list );
			$found_in_list = false;
			foreach ( $list as $item ) {
				if ( isset( $item['finding_id'] ) && (int) $item['finding_id'] === $finding_id ) {
					$found_in_list = true;
					break;
				}
			}
			$this->assertTrue( $found_in_list );

			// 2. Restore the quarantined file.
			$restore_res = GWQSH_Quarantine_Manager::restore_quarantine( $q_result['artifact_id'] );
			$this->assertIsArray( $restore_res );
			$this->assertTrue( file_exists( $test_file ), 'File must exist at original path after restore' );
			$this->assertSame( $file_hash, hash_file( 'sha256', $test_file ), 'Restored file content must match original' );

			// 3. Restored paths need a new active finding; stale IDs cannot mutate.
			$this->assertInstanceOf( WP_Error::class, GWQSH_Quarantine_Manager::quarantine_by_finding( $finding_id ) );
			GWQSH_Scan_Engine::finding( '/' . $relative, 'Uploads', 'Suspicious', 'Restored fixture', array( 'hash' => $file_hash ) );
			$finding_id = (int) $wpdb->insert_id;
			// Re-quarantine and permanently delete.
			$q_result2 = GWQSH_Quarantine_Manager::quarantine_by_finding( $finding_id );
			$this->assertIsArray( $q_result2 );
			$stored_file2 = GWQSH_Quarantine_Manager::quarantine_dir() . '/' . $q_result2['artifact_id'] . '.quarantine';
			$del_res = GWQSH_Quarantine_Manager::delete_quarantine( $q_result2['artifact_id'] );
			$this->assertTrue( $del_res );
			$this->assertFalse( file_exists( $stored_file2 ), 'Quarantine file should be deleted from disk' );

		} finally {
			$wpdb->query( 'ROLLBACK' );
			if ( file_exists( $test_file ) ) {
				unlink( $test_file );
			}
		}
	}

	/**
	 * Test protected files cannot be quarantined.
	 */
	public function test_protected_files_blocked_from_quarantine() {
		global $wpdb;
		$wpdb->query( 'START TRANSACTION' );
		$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );

		try {
			// Insert fake finding for wp-config.php.
			$wpdb->insert(
				$table,
				array(
					'file_path'   => '/wp-config.php',
					'file_type'   => 'Core',
					'status'      => 'Modified',
					'details'     => 'Attempt to quarantine wp-config.php',
					'detected_at' => current_time( 'mysql' ),
					'is_resolved' => 0,
				)
			);
			$finding_id = (int) $wpdb->insert_id;

			$res = GWQSH_Quarantine_Manager::quarantine_by_finding( $finding_id );
			$this->assertInstanceOf( WP_Error::class, $res );
			$this->assertSame( GWQSH_Quarantine_Manager::ERR_PROTECTED_FILE, $res->get_error_code() );

		} finally {
			$wpdb->query( 'ROLLBACK' );
		}
	}
}
