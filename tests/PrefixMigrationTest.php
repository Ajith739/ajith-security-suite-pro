<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
use PHPUnit\Framework\TestCase;

final class PrefixMigrationTest extends TestCase {
    public function test_stored_keys_cron_and_legacy_ciphertexts_survive_idempotent_upgrade() {
        $id = wp_create_user('gwqsh_migration_' . bin2hex(random_bytes(5)), wp_generate_password(24), 'migration@example.invalid');
        $this->assertIsInt($id);
        $marker = get_option('gwqsh_prefix_migration');
        $cron = get_option('cron');
        $suffix = 'migration_fixture_' . bin2hex(random_bytes(5));
        $legacy_key = 'gqs_' . $suffix;
        $new_key = 'gwqsh_' . $suffix;
        $secret = GWQSH_Two_Factor::generate_secret();
        $ciphertext = preg_replace('/^gwqsh1:/', 'gqs1:', GWQSH_Crypto::encrypt($secret));
        $payload = array('settings' => true, 'nested' => array('slug' => 'gqs_unchanged_value'));
        try {
            add_option($legacy_key, $payload, '', false);
            update_user_meta($id, 'gqs_2fa_secret', $ciphertext);
            update_user_meta($id, 'gqs_2fa_enabled', 1);
            $backup = GWQSH_Two_Factor::generate_backup_codes(2);
            GWQSH_Two_Factor::save_user_backup_codes($id, $backup);
            $records = get_user_meta($id, 'gwqsh_backup_codes', true);
            delete_user_meta($id, 'gwqsh_backup_codes');
            update_user_meta($id, 'gqs_backup_codes', $records);
            wp_schedule_single_event(time()+3600, 'gqs_' . $suffix);
            delete_option('gwqsh_prefix_migration');
            GWQSH_Migration::run();
            $this->assertSame($payload, get_option($new_key));
            $this->assertFalse(get_option($legacy_key));
            $this->assertSame($ciphertext, get_user_meta($id, 'gwqsh_2fa_secret', true));
            $this->assertSame($secret, GWQSH_Two_Factor::get_user_secret($id));
            $this->assertTrue(GWQSH_Two_Factor::is_user_2fa_enabled($id));
            $this->assertSame($records, get_user_meta($id, 'gwqsh_backup_codes', true));
            $this->assertNotFalse(wp_next_scheduled('gwqsh_' . $suffix));
            $this->assertFalse(wp_next_scheduled('gqs_' . $suffix));
            GWQSH_Migration::run();
            $this->assertSame($records, get_user_meta($id, 'gwqsh_backup_codes', true));
            $this->assertTrue(GWQSH_Two_Factor::verify_and_burn_backup_code($id, $backup[0]));
            $this->assertFalse(GWQSH_Two_Factor::verify_and_burn_backup_code($id, $backup[0]));
        } finally {
            update_option('cron', $cron); update_option('gwqsh_prefix_migration', $marker);
            delete_option($legacy_key); delete_option($new_key);
            require_once ABSPATH . 'wp-admin/includes/user.php'; wp_delete_user($id);
        }
    }

    public function test_table_rename_preserves_ids_and_records_without_touching_live_tables() {
        global $wpdb;
        $prefix = esc_sql( $wpdb->prefix );
        $fixture = $prefix . 'gwqsh_fixture_' . bin2hex(random_bytes(5)) . '_';
        $old = esc_sql( $fixture . 'gqs_activity_log' );
        $new = esc_sql( $fixture . 'gwqsh_activity_log' );
        try {
            $wpdb->query("CREATE TABLE `{$old}` LIKE `{$prefix}gwqsh_activity_log`");
            $wpdb->insert($old, array('id'=>781, 'event_time'=>current_time('mysql'), 'event_name'=>'Migration fixture', 'details'=>'Preserve every field', 'event_type'=>'System'));
            $record = $wpdb->get_row("SELECT * FROM `{$old}`", ARRAY_A);
            $wpdb->prefix = $fixture;
            $method = new ReflectionMethod(GWQSH_Migration::class, 'tables');
            $method->setAccessible(true); $method->invoke(null);
            $this->assertSame($record, $wpdb->get_row("SELECT * FROM `{$new}`", ARRAY_A));
            $method->invoke(null);
            $this->assertSame('1', $wpdb->get_var("SELECT COUNT(*) FROM `{$new}`"));
        } finally {
            $wpdb->prefix = $prefix;
            $wpdb->query("DROP TABLE IF EXISTS `{$old}`"); $wpdb->query("DROP TABLE IF EXISTS `{$new}`");
        }
    }
}
