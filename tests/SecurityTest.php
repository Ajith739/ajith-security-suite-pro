<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
use PHPUnit\Framework\TestCase;

final class SecurityTest extends TestCase {
    public function test_crypto_roundtrip_and_tampering() {
        $plain = GWQSH_Two_Factor::generate_secret();
        $cipher = GWQSH_Crypto::encrypt( $plain );
        $this->assertStringStartsWith( 'gwqsh1:', $cipher );
        $this->assertSame( $plain, GWQSH_Crypto::decrypt( $cipher ) );
        $this->assertFalse( GWQSH_Crypto::decrypt( substr( $cipher, 0, -3 ) . 'abc' ) );
    }

    public function test_totp_window_and_invalid_code() {
        $secret = GWQSH_Two_Factor::generate_secret();
        $code = GWQSH_Two_Factor::calculate_totp( $secret );
        $this->assertTrue( GWQSH_Two_Factor::verify_totp( $secret, $code ) );
        $this->assertFalse( GWQSH_Two_Factor::verify_totp( $secret, 'not-a-code' ) );
        $this->assertFalse( GWQSH_Two_Factor::verify_totp( $secret, GWQSH_Two_Factor::calculate_totp( $secret, (int) floor( time() / 30 ) - 3 ) ) );
    }

    public function test_legacy_plaintext_secret_is_encrypted() {
        $user = wp_create_user( 'gwqsh_test_' . wp_generate_password( 12, false ), wp_generate_password( 24 ), 'gwqsh-test@example.invalid' );
        $this->assertIsInt( $user );
        try {
            $secret = GWQSH_Two_Factor::generate_secret();
            update_user_meta( $user, 'gwqsh_2fa_secret', $secret );
            $this->assertSame( $secret, GWQSH_Two_Factor::get_user_secret( $user ) );
            $stored = get_user_meta( $user, 'gwqsh_2fa_secret', true );
            $this->assertNotSame( $secret, $stored );
            $this->assertSame( $secret, GWQSH_Two_Factor::get_user_secret( $user ) );
        } finally {
            require_once ABSPATH . 'wp-admin/includes/user.php';
            wp_delete_user( $user );
        }
    }

    public function test_backup_codes_are_hashed_and_one_time() {
        $user = wp_create_user( 'gwqsh_test_' . wp_generate_password( 12, false ), wp_generate_password( 24 ), 'gwqsh-test@example.invalid' );
        $this->assertIsInt( $user );
        try {
            $code = GWQSH_Two_Factor::generate_backup_codes( 1 )[0];
            GWQSH_Two_Factor::save_user_backup_codes( $user, array( $code ) );
            $stored = get_user_meta( $user, 'gwqsh_backup_codes', true );
            $this->assertArrayNotHasKey( 'code', $stored[0] );
            $exposed = GWQSH_Two_Factor::get_user_backup_codes( $user );
            $this->assertArrayNotHasKey( 'hash', $exposed[0] );
            $this->assertTrue( GWQSH_Two_Factor::verify_and_burn_backup_code( $user, $code ) );
            $this->assertFalse( GWQSH_Two_Factor::verify_and_burn_backup_code( $user, $code ) );
        } finally {
            require_once ABSPATH . 'wp-admin/includes/user.php';
            wp_delete_user( $user );
        }
    }

    public function test_path_traversal_is_rejected() {
        $method = new ReflectionMethod( GWQSH_File_Integrity::class, 'resolve_scan_path' );
        $method->setAccessible( true );
        $this->assertFalse( $method->invoke( null, '../wp-config.php' ) );
        $this->assertFalse( $method->invoke( null, 'C:\\Windows\\win.ini' ) );
        $this->assertFalse( $method->invoke( null, "/etc/passwd" ) );
    }

    public function test_totp_replay_is_rejected_after_first_login() {
        $policy = get_option( 'gwqsh_two_factor_settings', null );
        update_option( 'gwqsh_two_factor_settings', array( 'enabled' => true ) );
        $user_id = wp_create_user( 'gwqsh_test_' . wp_generate_password( 12, false ), wp_generate_password( 24 ), 'gwqsh-test@example.invalid' );
        $this->assertIsInt( $user_id );
        $previous = isset( $_POST['gwqsh_2fa_code'] ) ? $_POST['gwqsh_2fa_code'] : null;
        try {
            $secret = GWQSH_Two_Factor::generate_secret();
            GWQSH_Two_Factor::save_user_secret( $user_id, $secret );
            update_user_meta( $user_id, 'gwqsh_2fa_enabled', 1 );
            $_POST['gwqsh_2fa_code'] = GWQSH_Two_Factor::calculate_totp( $secret );
            $user = get_userdata( $user_id );
            $this->assertInstanceOf( WP_User::class, GWQSH_Two_Factor::intercept_2fa_login( $user, $user->user_login, 'unused' ) );
            $this->assertInstanceOf( WP_Error::class, GWQSH_Two_Factor::intercept_2fa_login( $user, $user->user_login, 'unused' ) );
        } finally {
            null === $policy ? delete_option( 'gwqsh_two_factor_settings' ) : update_option( 'gwqsh_two_factor_settings', $policy );
            if ( null === $previous ) { unset( $_POST['gwqsh_2fa_code'] ); } else { $_POST['gwqsh_2fa_code'] = $previous; }
            require_once ABSPATH . 'wp-admin/includes/user.php';
            wp_delete_user( $user_id );
        }
    }

    public function test_untrusted_proxy_header_is_ignored() {
        $remote = isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : null;
        $forwarded = isset( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : null;
        $settings = get_option( 'gwqsh_settings', array() );
        try {
            $_SERVER['REMOTE_ADDR'] = '2001:db8::4';
            $_SERVER['HTTP_X_FORWARDED_FOR'] = '192.0.2.99';
            GWQSH_Settings::set( 'proxy', true );
            $this->assertSame( '2001:db8::4', GWQSH_Settings::get_client_ip() );
        } finally {
            if ( null === $remote ) { unset( $_SERVER['REMOTE_ADDR'] ); } else { $_SERVER['REMOTE_ADDR'] = $remote; }
            if ( null === $forwarded ) { unset( $_SERVER['HTTP_X_FORWARDED_FOR'] ); } else { $_SERVER['HTTP_X_FORWARDED_FOR'] = $forwarded; }
            update_option( 'gwqsh_settings', $settings );
        }
    }

    public function test_admin_pages_render_in_wordpress() {
        $admins = get_users( array( 'role' => 'administrator', 'number' => 1, 'fields' => 'ID' ) );
        if ( ! $admins ) { $this->markTestSkipped( 'No administrator exists in this WordPress installation.' ); }
        $old_user = get_current_user_id();
        $old_page = isset( $_GET['page'] ) ? $_GET['page'] : null;
        wp_set_current_user( $admins[0] );
        try {
            foreach ( array( 'dashboard' => 'gracewell-security-suite-pro', 'login-protection' => 'gracewell-security-suite-pro-login', 'two-factor' => 'gracewell-security-suite-pro-two-factor', 'file-integrity' => 'gracewell-security-suite-pro-file-integrity', 'hardening' => 'gracewell-security-suite-pro-hardening', 'activity-log' => 'gracewell-security-suite-pro-activity-log', 'settings' => 'gracewell-security-suite-pro-settings' ) as $page => $slug ) {
                $_GET['page'] = $slug;
                ob_start();
                GWQSH_Admin::render();
                $html = ob_get_clean();
                $this->assertStringContainsString( 'id="gracewell-security-suite-pro-app"', $html, $page );
            }
        } finally {
            if ( null === $old_page ) { unset( $_GET['page'] ); } else { $_GET['page'] = $old_page; }
            wp_set_current_user( $old_user );
        }
    }

    public function test_recovery_key_is_unpredictable_and_stable() {
        $first = GWQSH_Login_Protection::recovery_key();
        $this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/D', $first );
        $this->assertSame( $first, GWQSH_Login_Protection::recovery_key() );
        $this->assertNotSame( '1', $first );
    }

    public function test_quarantine_records_metadata_for_a_scanned_file() {
        global $wpdb;
        $uploads = wp_upload_dir();
        $name = 'gwqsh-test-' . bin2hex( random_bytes( 8 ) ) . '.php';
        $file = trailingslashit( $uploads['basedir'] ) . $name;
        $relative = ltrim( str_replace( wp_normalize_path( ABSPATH ), '', wp_normalize_path( $file ) ), '/' );
        file_put_contents( $file, '<?php /* test fixture */' );
        $table = $wpdb->prefix . 'gwqsh_scan_results';
        $wpdb->insert( $table, array( 'file_path' => '/' . $relative, 'file_type' => 'Uploads', 'status' => 'Suspicious', 'details' => 'Test fixture', 'detected_at' => current_time( 'mysql' ), 'is_resolved' => 0 ) );
        $id = $wpdb->insert_id;
        $before = get_option( 'gwqsh_quarantine_metadata', array() );
        try {
            $this->assertTrue( GWQSH_File_Integrity::quarantine_file( $relative ) );
            $after = get_option( 'gwqsh_quarantine_metadata', array() );
            $new = array_diff_key( $after, $before );
            $this->assertCount( 1, $new );
            $record = reset( $new );
            $this->assertSame( $relative, ltrim( $record['original'], '/' ) );
            $this->assertMatchesRegularExpression( '/^[a-f0-9]{64}$/D', $record['hash'] );
        } finally {
            if ( is_file( $file ) ) { wp_delete_file( $file ); }
            $after = get_option( 'gwqsh_quarantine_metadata', array() );
            foreach ( array_diff_key( $after, $before ) as $quarantine_name => $record ) {
                $dir = trailingslashit( get_temp_dir() ) . 'gwqsh-quarantine-' . substr( hash_hmac( 'sha256', home_url(), wp_salt( 'auth' ) ), 0, 20 );
                $quarantine_file = trailingslashit( $dir ) . $quarantine_name;
                if ( is_file( $quarantine_file ) ) { wp_delete_file( $quarantine_file ); }
            }
            update_option( 'gwqsh_quarantine_metadata', $before );
            $wpdb->delete( $table, array( 'id' => $id ) );
        }
    }

    public function test_removed_integrity_scheduler_preserves_other_cron() {
        delete_option( 'gwqsh_manual_scan_migration' );
        wp_schedule_event( time() + 3600, 'daily', 'gwqsh_scheduled_integrity_scan' );
        GWQSH_File_Integrity::init();
        $this->assertFalse( wp_next_scheduled( 'gwqsh_scheduled_integrity_scan' ) );
        $this->assertNotFalse( wp_next_scheduled( 'gwqsh_daily_log_cleanup' ) );
        $this->assertNotFalse( wp_next_scheduled( 'gwqsh_cleanup_lockouts' ) );
    }
}
