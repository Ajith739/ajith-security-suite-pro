<?php
// phpcs:ignoreFile -- Isolated development regressions, excluded from release.
use PHPUnit\Framework\TestCase;
final class SharedUiTest extends TestCase {
    public function test_all_eight_pages_share_ordered_real_navigation_and_active_state() {
        $get=$_GET; $viewer=get_current_user_id();
        $admin=get_users(array('role'=>'administrator','number'=>1))[0];wp_set_current_user($admin->ID);
        $pages=array('dashboard'=>'','login-protection'=>'-login','two-factor'=>'-two-factor','file-integrity'=>'-file-integrity','firewall-cleanup'=>'-firewall-cleanup','hardening'=>'-hardening','activity-log'=>'-activity-log','settings'=>'-settings');
        try {
            foreach($pages as $page=>$suffix) {
                $_GET['page']='gracewell-security-suite-pro'.$suffix;
                ob_start();GWQSH_Admin::render();$html=ob_get_clean();
                $dom=new DOMDocument();@$dom->loadHTML($html);$xp=new DOMXPath($dom);
                $links=$xp->query('//nav[@id="mainNav"]/a');$this->assertCount(7,$links,$page);
                foreach(array_values(array_slice($pages,0,7)) as $i=>$target) $this->assertStringContainsString('page=gracewell-security-suite-pro'.$target,$links[$i]->getAttribute('href'));
                $this->assertCount('settings'===$page?0:1,$xp->query('//nav[@id="mainNav"]/a[@aria-current="page"]'),$page);
                $this->assertCount(0,$xp->query('//header//button[contains(@class,"pro-link")]'),$page);
                $this->assertStringContainsString('id="heroBirds"',$html,$page);
            }
        } finally {$_GET=$get;wp_set_current_user($viewer);}
    }
    public function test_settings_normalization_is_pure_and_partial_saves_preserve_other_fields() {
        $original=get_option('gwqsh_settings');$updates=get_site_option('auto_update_plugins');
        try {
            $before=GWQSH_Settings::get_all();
            $expected=GWQSH_Settings::normalize(array('theme'=>'dark','retention'=>'90'));
            $this->assertSame($before,GWQSH_Settings::get_all());
            GWQSH_Settings::update_all(array('theme'=>'dark','retention'=>'90'));
            $this->assertSame($expected,GWQSH_Settings::get_all());
            GWQSH_Settings::update_all(array('tips'=>false));
            $this->assertSame('dark',GWQSH_Settings::get('theme'));
            $this->assertSame('90',GWQSH_Settings::get('retention'));
            GWQSH_Settings::update_all(array('autoupdate'=>true));
            $this->assertContains(GWQSH_PLUGIN_BASENAME,get_site_option('auto_update_plugins'));
            GWQSH_Settings::update_all(array('autoupdate'=>false));
            $this->assertNotContains(GWQSH_PLUGIN_BASENAME,get_site_option('auto_update_plugins'));
        } finally { update_option('gwqsh_settings',$original);update_site_option('auto_update_plugins',$updates); }
    }
    public function test_native_update_controls_follow_wordpress_capabilities() {
        $viewer=get_current_user_id();
        try {
            wp_set_current_user(0);$this->assertFalse(GWQSH_Settings::can_manage_updates());
            $admin=get_users(array('role'=>'administrator','number'=>1))[0];wp_set_current_user($admin->ID);
            $this->assertTrue(GWQSH_Settings::can_manage_updates());
            $data=GWQSH_Admin::get_page_initial_data('settings');$this->assertTrue($data['can_manage_updates']);
            $deny=static function($caps) { $caps['update_plugins']=false;return $caps; };add_filter('user_has_cap',$deny);
            try { $this->assertTrue(current_user_can('manage_options'));$this->assertFalse(GWQSH_Settings::can_manage_updates()); }
            finally { remove_filter('user_has_cap',$deny); }
        } finally {wp_set_current_user($viewer);}
    }
    public function test_geography_never_returns_invented_country_statistics() {
        foreach(array(7,14,30) as $days)$this->assertSame(array(),GWQSH_Dashboard_Data::geography($days));
    }
    public function test_forwarded_chain_rejects_spoofed_leading_entries_and_invalid_edges() {
        $trusted=array('192.0.2.240','2001:db8::240');
        $this->assertSame('198.51.100.5',GWQSH_Settings::forwarded_ip('203.0.113.99, 198.51.100.5, 192.0.2.240',$trusted));
        $this->assertSame('198.51.100.5',GWQSH_Settings::forwarded_ip('198.51.100.5, 2001:0db8:0:0:0:0:0:0240',$trusted));
        $this->assertSame('',GWQSH_Settings::forwarded_ip('198.51.100.5, invalid',$trusted));
        $this->assertSame('',GWQSH_Settings::forwarded_ip(str_repeat('192.0.2.240,',33),$trusted));
    }
    public function test_log_clear_failure_returns_an_error_and_preserves_records() {
        global $wpdb;
        $before=GWQSH_Activity_Logger::query_logs(array('limit'=>1))['total'];
        $filter=static function($query) { return strpos($query,'TRUNCATE TABLE ')===0 ? 'TRUNCATE TABLE gwqsh_nonexistent_audit_fixture' : $query; };
        $old=$wpdb->suppress_errors(true);add_filter('query',$filter);
        try { $this->assertInstanceOf(WP_Error::class,GWQSH_Activity_Logger::clear_all()); }
        finally { remove_filter('query',$filter);$wpdb->suppress_errors($old); }
        $this->assertSame($before,GWQSH_Activity_Logger::query_logs(array('limit'=>1))['total']);
    }
}
