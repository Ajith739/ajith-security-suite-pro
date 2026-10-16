<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
use PHPUnit\Framework\TestCase;

final class ReleaseTest extends TestCase {
    public function test_encrypted_backup_display_is_owned_persistent_and_consumed() {
        $id = $this->user(); $current = get_current_user_id();
        try {
            $codes = GWQSH_Two_Factor::generate_backup_codes( 2 );
            GWQSH_Two_Factor::save_user_backup_codes( $id, $codes );
            $stored = get_user_meta( $id, 'gwqsh_backup_codes', true );
            $this->assertStringStartsWith( 'gwqsh1:', $stored[0]['display'] );
            $this->assertStringNotContainsString( $codes[0], serialize( $stored ) );
            wp_set_current_user( $id ); clean_user_cache( $id );
            $this->assertSame( $codes[0], GWQSH_Two_Factor::get_user_backup_codes( $id )[0]['code'] );
            wp_set_current_user( 0 );
            $this->assertArrayNotHasKey( 'code', GWQSH_Two_Factor::get_user_backup_codes( $id )[0] );
            $this->assertTrue( GWQSH_Two_Factor::verify_and_burn_backup_code( $id, $codes[0] ) );
            $stored = get_user_meta( $id, 'gwqsh_backup_codes', true );
            $this->assertArrayNotHasKey( 'hash', $stored[0] );
            $this->assertArrayNotHasKey( 'display', $stored[0] );
            wp_set_current_user( $id );
            $this->assertArrayNotHasKey( 'code', GWQSH_Two_Factor::get_user_backup_codes( $id )[0] );
            $this->assertFalse( GWQSH_Two_Factor::verify_and_burn_backup_code( $id, $codes[0] ) );
        } finally { wp_set_current_user( $current ); $this->remove_user( $id ); }
    }
    public function test_reset_forms_preserve_the_cookie_path() {
        $old = get_option( 'gwqsh_login_protection' ); $old_settings = get_option( 'gwqsh_settings' );
        $request = isset( $_SERVER['REQUEST_URI'] ) ? $_SERVER['REQUEST_URI'] : null;
        try {
            GWQSH_Settings::set( 'status', true );
            update_option( 'gwqsh_login_protection', array_merge( GWQSH_Login_Protection::get_settings(), array( 'custom_slug_enabled' => true, 'custom_slug' => 'gwqsh-test-login-123' ) ) );
            $standard = get_option( 'siteurl' ) . '/wp-login.php?action=resetpass';
            $_SERVER['REQUEST_URI'] = wp_parse_url( $standard, PHP_URL_PATH ) . '?action=rp';
            $this->assertSame( $standard, GWQSH_Login_Protection::filter_login_url( $standard ) );
            $_SERVER['REQUEST_URI'] = wp_parse_url( home_url( '/gwqsh-test-login-123/' ), PHP_URL_PATH ) . '?action=rp';
            $this->assertSame( home_url( '/gwqsh-test-login-123/' ) . '?action=resetpass', GWQSH_Login_Protection::filter_login_url( $standard ) );
        } finally {
            update_option( 'gwqsh_login_protection', $old ); update_option( 'gwqsh_settings', $old_settings );
            if ( null === $request ) { unset( $_SERVER['REQUEST_URI'] ); } else { $_SERVER['REQUEST_URI'] = $request; }
        }
    }
    public function test_diff_escapes_source_and_bounds_large_files() {
        global $wpdb, $wp_version;
        require_once ABSPATH . 'wp-admin/includes/template.php';
        $relative = 'gwqsh-diff-' . bin2hex( random_bytes( 6 ) ) . '.txt';
        $official = "original text\n";
        $cache_key = 'gwqsh_checksums_' . md5( $wp_version . '|' . get_locale() );
        $cache = get_transient( $cache_key );
        $mock = static function ( $pre, $args, $url ) use ( $relative, $official ) {
            return false !== strpos( $url, '/' . $relative ) ? array( 'headers' => array(), 'body' => $official, 'response' => array( 'code' => 200, 'message' => 'OK' ) ) : $pre;
        };
        $wpdb->query( 'START TRANSACTION' );
        try {
            file_put_contents( ABSPATH . $relative, "<script>alert('fixture')</script>\n" );
            set_transient( $cache_key, array( $relative => md5( $official ) ), 60 );
            $wpdb->insert( $wpdb->prefix . 'gwqsh_scan_results', array( 'file_path' => '/' . $relative, 'file_type' => 'Core', 'status' => 'Modified', 'details' => 'Test fixture', 'detected_at' => current_time( 'mysql' ), 'is_resolved' => 0 ) );
            add_filter( 'pre_http_request', $mock, 10, 3 );
            $diff = GWQSH_File_Integrity::get_file_diff( $relative );
            $this->assertIsString( $diff );
            $this->assertStringNotContainsString( '<script>', $diff );
            $this->assertStringContainsString( '&lt;script&gt;', $diff );
            file_put_contents( ABSPATH . $relative, str_repeat( 'x', 524289 ) ); clearstatcache();
            $error = GWQSH_File_Integrity::get_file_diff( $relative );
            $this->assertInstanceOf( WP_Error::class, $error );
            $this->assertSame( 'large_file', $error->get_error_code() );
        } finally {
            remove_filter( 'pre_http_request', $mock, 10 );
            $wpdb->query( 'ROLLBACK' ); wp_cache_flush(); wp_delete_file( ABSPATH . $relative );
            false === $cache ? delete_transient( $cache_key ) : set_transient( $cache_key, $cache, WEEK_IN_SECONDS );
        }
    }
    private function user() {
        $id = wp_create_user( 'gwqsh_release_' . bin2hex( random_bytes( 5 ) ), wp_generate_password( 24 ), 'gwqsh-release@example.invalid' );
        $this->assertIsInt( $id ); return $id;
    }
    private function remove_user( $id ) {
        require_once ABSPATH . 'wp-admin/includes/user.php'; wp_delete_user( $id );
    }
    public function test_removed_global_flag_cannot_bypass_user_second_factor() {
        $id = $this->user(); $policy = get_option( 'gwqsh_two_factor_settings', null ); $post = $_POST;
        try {
            $secret = GWQSH_Two_Factor::generate_secret(); GWQSH_Two_Factor::save_user_secret( $id, $secret );
            update_user_meta( $id, 'gwqsh_2fa_enabled', 1 ); $_POST = array();
            update_option( 'gwqsh_two_factor_settings', array( 'enabled' => false ) );
            $u = get_userdata( $id );
            $result = GWQSH_Two_Factor::intercept_2fa_login( $u, $u->user_login, 'password' );
            $this->assertInstanceOf( WP_Error::class, $result );
            $this->assertSame( 'gwqsh_2fa_required', $result->get_error_code() );
            unset( $GLOBALS['gwqsh_2fa_prompt'], $GLOBALS['gwqsh_2fa_challenge'] );
            delete_user_meta( $id, 'gwqsh_2fa_enabled' );
            $this->assertSame( $u, GWQSH_Two_Factor::intercept_2fa_login( $u, $u->user_login, 'password' ) );
        } finally { $_POST = $post; null === $policy ? delete_option( 'gwqsh_two_factor_settings' ) : update_option( 'gwqsh_two_factor_settings', $policy ); $this->remove_user( $id ); }
    }
    public function test_backup_regeneration_and_legacy_migration() {
        $id = $this->user();
        try {
            update_user_meta( $id, 'gwqsh_backup_codes', array( array( 'code' => 'ABCD-2345', 'used' => false ) ) );
            $this->assertCount( 1, GWQSH_Two_Factor::get_user_backup_codes( $id ) );
            $this->assertArrayNotHasKey( 'code', get_user_meta( $id, 'gwqsh_backup_codes', true )[0] );
            $this->assertTrue( GWQSH_Two_Factor::verify_and_burn_backup_code( $id, 'ABCD-2345' ) );
            $codes = GWQSH_Two_Factor::generate_backup_codes( 2 ); GWQSH_Two_Factor::save_user_backup_codes( $id, $codes );
            $replacement = GWQSH_Two_Factor::generate_backup_codes( 2 ); GWQSH_Two_Factor::save_user_backup_codes( $id, $replacement );
            $this->assertFalse( GWQSH_Two_Factor::verify_and_burn_backup_code( $id, $codes[0] ) );
            $this->assertTrue( GWQSH_Two_Factor::verify_and_burn_backup_code( $id, $replacement[0] ) );
            $this->assertFalse( GWQSH_Two_Factor::verify_and_burn_backup_code( $id, $replacement[0] ) );
        } finally { $this->remove_user( $id ); }
    }
    public function test_slug_validation_and_risk_extremes() {
        foreach ( array( 'wp-admin', 'wp-json', '../login', 'wp-login.php', 'login', 'Foo', 'xy', 'a/b/c' ) as $slug ) { $this->assertFalse( GWQSH_Login_Protection::valid_slug( $slug ), $slug ); }
        $this->assertTrue( GWQSH_Login_Protection::valid_slug( 'gwqsh-test-login-123' ) );
        $old = get_option( 'gwqsh_hardening', null );
        try {
            update_option( 'gwqsh_hardening', array_fill_keys( array_keys( GWQSH_Hardening::get_defaults() ), false ) );
            $risk = GWQSH_Hardening::get_risk();
            $this->assertSame( array( 'score' => 0, 'passed' => 0, 'failed' => 6, 'level' => 'Critical' ), $risk );
            update_option( 'gwqsh_hardening', array( 'xmlrpc' => true, 'editor' => true, 'version' => true, 'enum' => true, 'headers' => false, 'uploads' => false ) );
            $this->assertSame( array( 'score' => 55, 'passed' => 4, 'failed' => 2, 'level' => 'High' ), GWQSH_Hardening::get_risk() );
        } finally { null === $old ? delete_option( 'gwqsh_hardening' ) : update_option( 'gwqsh_hardening', $old ); }
    }
    /** Real temporary files and a test-only checksum provider; every mutation is rolled back. */
    public function test_scanner_reports_modified_missing_and_suspicious() {
        global $wpdb, $wp_version;
        $directory = 'gwqsh-release-' . bin2hex( random_bytes( 6 ) );
        $core_root = ABSPATH . $directory; mkdir($core_root);
        $relative = $directory . '/modified.txt';
        $missing = $directory . '/missing.txt';
        $uploads = wp_upload_dir(); $upload_root = trailingslashit($uploads['basedir']) . $directory; mkdir($upload_root);
        $file = $upload_root . '/suspicious.php';
        $roots = static function() use ($core_root, $upload_root) { return array($core_root, $upload_root); };
        add_filter('gwqsh_scan_enumeration_roots', $roots);
        file_put_contents( ABSPATH . $relative, 'changed test content' ); file_put_contents( $file, '<?php /* inert test fixture */' );
        $cache_key = 'gwqsh_checksums_' . md5( $wp_version . '|' . get_locale() ); $cache = get_transient( $cache_key );
        $settings = get_option( 'gwqsh_settings', array() );
        $wpdb->query( 'START TRANSACTION' );
        try {
            GWQSH_Scan_Engine::clear('gwqsh_scan_progress');
            set_transient( $cache_key, array( $relative => md5( 'original test content' ), $missing => md5( 'missing original' ) ), 60 );
            do { $result = GWQSH_File_Integrity::run_full_scan(); } while ( is_array($result) && !empty($result['pending']) );
            $this->assertIsArray( $result );
            $issues = GWQSH_File_Integrity::get_scan_issues();
            $match = static function ( $path ) { foreach ( GWQSH_File_Integrity::get_scan_issues( array( 'search' => $path ) ) as $issue ) { if ( '/' . $path === $issue['path'] ) { return $issue['st']; } } return null; };
            $this->assertSame( 'Modified', $match( $relative ) );
            $this->assertSame( 'Missing', $match( $missing ) );
            $upload_relative = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file ) ), '/' );
            $this->assertSame( 'Suspicious', $match( $upload_relative ) );
        } finally {
            remove_filter('gwqsh_scan_enumeration_roots', $roots);
            $wpdb->query( 'ROLLBACK' ); wp_cache_flush();
            wp_delete_file( ABSPATH . $relative ); wp_delete_file( $file );
            rmdir($core_root); rmdir($upload_root);
            false === $cache ? delete_transient( $cache_key ) : set_transient( $cache_key, $cache, WEEK_IN_SECONDS );
            update_option( 'gwqsh_settings', $settings );
        }
    }
}
