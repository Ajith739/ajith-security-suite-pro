<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
use PHPUnit\Framework\TestCase;

final class LifecycleTest extends TestCase {
    public function test_fresh_activation_deactivation_and_opt_in_uninstall_are_isolated() {
        global $wpdb;
        $live = $wpdb;
        $fixture_prefix = $live->prefix . 'gwqsh_lifecycle_' . bin2hex(random_bytes(5)) . '_';
        $fixture = new wpdb(DB_USER, DB_PASSWORD, DB_NAME, DB_HOST);
        $fixture->set_prefix($fixture_prefix);
        $home = home_url('/gwqsh-lifecycle-' . bin2hex(random_bytes(6)));
        $tables = array('options','usermeta','users','gwqsh_activity_log','gwqsh_lockouts','gwqsh_scan_results','gwqsh_scan_history','gwqsh_ip_blocks','gwqsh_auth_challenges','gwqsh_security_state','gwqsh_delivery_queue');
        $dir = trailingslashit(get_temp_dir()) . 'gwqsh-lifecycle-' . bin2hex(random_bytes(6));
        wp_mkdir_p($dir);
        $upload_filter = static function($value) use($dir) { $value['basedir']=$dir; $value['path']=$dir; $value['error']=false; return $value; };
        try {
            foreach(array('options','usermeta','users') as $suffix) {
                $fixture->query("CREATE TABLE `{$fixture_prefix}{$suffix}` LIKE `{$live->prefix}{$suffix}`");
            }
            $wpdb=$fixture; wp_cache_flush();
            add_option('home',$home); add_option('siteurl',$home);
            add_option('gwqsh_hardening',array('uploads'=>false));
            add_filter('upload_dir',$upload_filter);
            gwqsh_pro_activate_plugin();
            GWQSH_Activity_Logger::init(); GWQSH_Login_Protection::init();
            foreach(array_slice($tables,3) as $suffix) {
                $name=$fixture_prefix.$suffix;
                $this->assertSame($name,$wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($name))));
            }
            $this->assertSame(GWQSH_DB_VERSION,get_option('gwqsh_db_version'));
            $secret=GWQSH_Two_Factor::generate_secret();
            GWQSH_Two_Factor::save_user_secret(985347,$secret);
            update_user_meta(985347,'gwqsh_2fa_enabled',1);
            wp_schedule_single_event(time()+3600,'unrelated_lifecycle_fixture');
            $this->assertNotFalse(wp_next_scheduled('gwqsh_daily_log_cleanup'));
            gwqsh_pro_deactivate_plugin();
            $this->assertFalse(wp_next_scheduled('gwqsh_daily_log_cleanup'));
            $this->assertFalse(wp_next_scheduled('gwqsh_cleanup_lockouts'));
            $this->assertSame($secret,GWQSH_Two_Factor::get_user_secret(985347));
            if(!defined('WP_UNINSTALL_PLUGIN')) define('WP_UNINSTALL_PLUGIN',GWQSH_PLUGIN_BASENAME);
            update_option('gwqsh_settings',array('uninstall'=>false));
            require GWQSH_PATH.'uninstall.php';
            $this->assertSame($secret,GWQSH_Two_Factor::get_user_secret(985347));
            $this->assertSame(GWQSH_DB_VERSION,get_option('gwqsh_db_version'));
            update_option('gwqsh_settings',array('uninstall'=>true));
            require GWQSH_PATH.'uninstall.php';
            $this->assertFalse(get_option('gwqsh_db_version'));
            $this->assertSame('',get_user_meta(985347,'gwqsh_2fa_secret',true));
            $this->assertNotFalse(wp_next_scheduled('unrelated_lifecycle_fixture'));
            foreach(array_slice($tables,3) as $suffix) {
                $this->assertNull($wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s',$wpdb->esc_like($fixture_prefix.$suffix))));
            }
        } finally {
            remove_filter('upload_dir',$upload_filter);
            $wpdb=$live; wp_cache_flush(); wp_upload_dir(null,false,true);
            GWQSH_Guardian::install();
            foreach($tables as $suffix) $fixture->query("DROP TABLE IF EXISTS `{$fixture_prefix}{$suffix}`");
            global $wp_filesystem;
            if ( empty( $wp_filesystem ) ) {
                require_once ABSPATH . 'wp-admin/includes/file.php';
                WP_Filesystem();
            }
            $fixture_real = realpath($dir);
            $fixture_temp = realpath(get_temp_dir());
            if (!$fixture_real || !$fixture_temp || dirname($fixture_real) !== $fixture_temp || !preg_match('/^gwqsh-lifecycle-[a-f0-9]{12}$/D',basename($fixture_real))) {
                throw new RuntimeException('Refusing lifecycle cleanup outside the exact owned temporary fixture.');
            }
            if ( $wp_filesystem && $wp_filesystem->is_dir( $fixture_real ) ) {
                $wp_filesystem->delete( $fixture_real, true );
            }
        }
    }
}
