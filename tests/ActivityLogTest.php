<?php
// phpcs:ignoreFile -- Transactional development integration fixtures, excluded from releases.
use PHPUnit\Framework\TestCase;
final class ActivityLogTest extends TestCase {
    private $viewer;
    private $settings;
    private $timezone;
    private $actor='activity-unit-fixture';
    protected function setUp(): void {
        global $wpdb;
        $this->viewer=get_current_user_id();
        $this->settings=get_option('gwqsh_settings');
        $this->timezone=get_option('timezone_string');
        $admins=get_users(array('role'=>'administrator','number'=>1));
        wp_set_current_user($admins[0]->ID);
        $wpdb->query('START TRANSACTION');
        $wpdb->query('DELETE FROM '.$wpdb->prefix.'gwqsh_activity_log');
    }
    protected function tearDown(): void {
        global $wpdb;
        $wpdb->query('ROLLBACK');
        wp_cache_flush();
        update_option('gwqsh_settings',$this->settings);
        update_option('timezone_string',$this->timezone);
        delete_transient('gwqsh_log_cleanup_'.get_current_user_id());
        wp_set_current_user($this->viewer);
    }
    private function row($name='Profile updated',$type='User',$time=null,$details='Fixture description',$ip='2001:db8::1') {
        global $wpdb;
        $wpdb->insert($wpdb->prefix.'gwqsh_activity_log',array('event_time'=>$time?:current_time('mysql'),'event_name'=>$name,'event_type'=>$type,'user_login'=>$this->actor,'ip_address'=>$ip,'details'=>$details));
        return (int)$wpdb->insert_id;
    }
    public function test_counts_chart_and_exact_categories_are_consistent() {
        foreach(array(array('Login successful','User'),array('Firewall request blocked','Security'),array('File quarantined','Security'),array('Plugin activated','Plugin'),array('Profile updated','User'),array('Unknown event','Custom')) as $r) $this->row(...$r);
        $data=GWQSH_Activity_View_Data::get(array('overview'=>1));
        $this->assertSame(6,$data['total']);
        $this->assertSame(array('Security'=>2,'User'=>1,'File'=>1,'System'=>1,'Other'=>1),$data['counts']);
        $this->assertSame(6,array_sum(array_map('array_sum',$data['chart']['series'])));
        $this->assertCount(7,$data['chart']['dates']);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('category'=>'Login'))['total']);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('category'=>'File'))['total']);
        $this->assertSame('User',array_values(array_filter($data['items'],fn($r)=>$r['event_name']==='Login successful'))[0]['event_type']);
        $this->assertSame('Not recorded',$data['items'][0]['severity']);
    }
    public function test_simultaneous_records_have_stable_pagination_and_server_clamp() {
        $ids=array(); for($i=0;$i<25;$i++) $ids[]=$this->row();
        $first=GWQSH_Activity_View_Data::get(); $second=GWQSH_Activity_View_Data::get(array('page_num'=>2)); $last=GWQSH_Activity_View_Data::get(array('page_num'=>999));
        $this->assertSame(array_reverse(array_slice($ids,15)),array_column($first['items'],'id'));
        $this->assertSame(array_reverse(array_slice($ids,5,10)),array_column($second['items'],'id'));
        $this->assertSame(3,$last['page']); $this->assertCount(5,$last['items']);
        $this->assertSame(array(),array_intersect(array_column($first['items'],'id'),array_column($second['items'],'id')));
    }
    public function test_inclusive_site_dates_and_iso_timestamps_across_dst() {
        update_option('timezone_string','America/New_York');
        $this->row('Profile updated','User','2025-11-02 00:00:00');
        $this->row('Profile updated','User','2025-11-02 23:59:59');
        $this->row('Profile updated','User','2025-11-03 00:00:00');
        $data=GWQSH_Activity_View_Data::get(array('start'=>'2025-11-02','end'=>'2025-11-02'));
        $this->assertSame(2,$data['total']);
        $this->assertStringEndsWith('-05:00',$data['items'][0]['timestamp']);
        $this->assertStringEndsWith('-04:00',$data['items'][1]['timestamp']);
        $this->assertSame('2025-11-03 00:00:00',$data['filters']['to']);
    }
    public function test_filters_reject_invalid_unbounded_or_injected_values() {
        foreach(array(array('start'=>'2025-02-30','end'=>'2025-03-01'),array('start'=>'2025-03-02','end'=>'2025-03-01'),array('start'=>'2020-01-01','end'=>'2025-01-01'),array('end'=>'2999-01-01','start'=>'2999-01-01'),array('ip'=>'1.2.3.4 OR 1=1'),array('days'=>0),array('category'=>"' OR 1=1"),array('severity'=>'Critical'),array('user'=>array('x'))) as $f) $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::get($f)));
        $this->row('Profile updated','User',null,"password=fixture-secret");
        $this->assertSame(0,GWQSH_Activity_View_Data::get(array('search'=>'fixture-secret'))['total']);
        $this->assertSame(0,GWQSH_Activity_View_Data::get(array('search'=>"' OR 1=1 --"))['total']);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('user'=>$this->actor,'ip'=>'2001:db8::1'))['total']);
    }
    public function test_sensitive_legacy_and_new_records_are_redacted_everywhere() {
        foreach(array('password=never-display','{"Authorization":"Bearer never-display"}','totp_secret: never-display',"Cookie: session=never-display",'backup_codes=[never-display]', 'totp=never-display', 'session_token=never-display','?access_token=never-display','-----BEGIN PRIVATE KEY-----never-display') as $text) {
            $this->assertStringNotContainsString('never-display',GWQSH_Activity_View_Data::safe_text($text));
            $this->row('Test event','System',null,$text);
        }
        $this->assertStringNotContainsString('never-display',json_encode(GWQSH_Activity_View_Data::get()));
        $this->assertStringNotContainsString('never-display',json_encode(GWQSH_Activity_Logger::query_logs()));
        $id=GWQSH_Activity_Logger::log('Test event','password=never-store','System');
        global $wpdb;
        $this->assertStringNotContainsString('never-store',$wpdb->get_var($wpdb->prepare('SELECT details FROM '.$wpdb->prefix.'gwqsh_activity_log WHERE id=%d',$id)));
        foreach(array('=1+1','+SUM(A1)','-1+2','@SUM(A1)'," 	=1") as $value) $this->assertStringStartsWith("'",GWQSH_Activity_View_Data::csv_cell($value));
        $this->assertSame('ordinary text',GWQSH_Activity_View_Data::csv_cell('ordinary text'));
    }
    public function test_cleanup_respects_retention_snapshot_confirmation_and_policy_changes() {
        global $wpdb;
        GWQSH_Settings::set('retention',30);
        $old=$this->row('Old fixture','System',current_datetime()->modify('-31 days')->format('Y-m-d H:i:s'));
        $recent=$this->row();
        $p=GWQSH_Activity_View_Data::cleanup_preview(); $this->assertSame(1,$p['count']);
        $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::cleanup($p['token'],'0')));
        $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::cleanup('wrong','1')));
        GWQSH_Settings::set('retention',90);
        $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::cleanup($p['token'],'1')));
        GWQSH_Settings::set('retention',30);
        $late=$this->row('Late old fixture','System',current_datetime()->modify('-31 days')->format('Y-m-d H:i:s'));
        $result=GWQSH_Activity_View_Data::cleanup($p['token'],'1');
        $this->assertSame(1,$result['deleted']); $this->assertSame(0,$result['remaining']);
        $this->assertNull($wpdb->get_var($wpdb->prepare('SELECT id FROM '.$wpdb->prefix.'gwqsh_activity_log WHERE id=%d',$old)));
        $this->assertNotNull($wpdb->get_var($wpdb->prepare('SELECT id FROM '.$wpdb->prefix.'gwqsh_activity_log WHERE id=%d',$recent)));
        $this->assertNotNull($wpdb->get_var($wpdb->prepare('SELECT id FROM '.$wpdb->prefix.'gwqsh_activity_log WHERE id=%d',$late)));
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('event'=>'Expired activity logs removed'))['total']);
        GWQSH_Settings::set('retention',0); $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::cleanup_preview()));
    }
    public function test_nonadministrators_cannot_view_preview_or_cleanup() {
        wp_set_current_user(0);
        $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::get()));
        $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::cleanup_preview()));
        $this->assertTrue(is_wp_error(GWQSH_Activity_View_Data::cleanup('x','1')));
    }
    public function test_pro_view_has_real_controls_and_preserved_firewall_navigation() {
        ob_start(); require GWQSH_PATH.'admin/views/activity-log.php'; $html=ob_get_clean();
        foreach(array('Activity Overview','Event Types','Recent Activity','Filter Logs','Quick Actions','Security Tips','activityExport','gracewell-security-suite-pro-firewall-cleanup') as $text) $this->assertStringContainsString($text,$html);
        $this->assertStringNotContainsString('href="#"',$html);
        $this->assertStringContainsString('heroBirds',$html);
        $this->assertStringNotContainsString('<option>sarah</option>',$html);
    }

    public function test_percent_placeholder_search_stays_literal_and_ipv6_is_equivalent() {
        $this->row('Literal %s and %d','User');
        $data=GWQSH_Activity_View_Data::get(array('search'=>'%s'));
        $this->assertSame(1,$data['total']);
        $this->assertCount(1,$data['items']);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('ip'=>'2001:0db8:0000:0000:0000:0000:0000:0001'))['total']);
    }
    public function test_cleanup_is_batched_and_new_audit_events_survive() {
        GWQSH_Settings::set('retention',30);
        $time=current_datetime()->modify('-31 days')->format('Y-m-d H:i:s');
        for($i=0;$i<1002;$i++) $this->row('Expired fixture','System',$time);
        $p=GWQSH_Activity_View_Data::cleanup_preview();
        $one=GWQSH_Activity_View_Data::cleanup($p['token'],'1');
        $this->assertSame(1000,$one['deleted']); $this->assertSame(2,$one['remaining']);
        $two=GWQSH_Activity_View_Data::cleanup($p['token'],'1');
        $this->assertSame(2,$two['deleted']); $this->assertSame(0,$two['remaining']);
        $this->assertSame(2,GWQSH_Activity_View_Data::get(array('event'=>'Expired activity logs removed'))['total']);
    }
    public function test_wordpress_collectors_are_registered_once_and_preserve_event_meaning() {
        $this->assertSame(10,has_action('user_register',array('GWQSH_Activity_Logger','on_user_created')));
        $this->assertSame(10,has_action('deleted_user',array('GWQSH_Activity_Logger','on_user_deleted')));
        $this->assertSame(10,has_action('switch_theme',array('GWQSH_Activity_Logger','on_theme_activated')));
        GWQSH_Activity_Logger::on_plugin_activated('fixture/plugin.php',false);
        GWQSH_Activity_Logger::on_plugin_deactivated('fixture/plugin.php',false);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('event'=>'Plugin activated'))['total']);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('event'=>'Plugin deactivated'))['total']);
    }

    public function test_safe_description_migration_is_bounded_and_preserves_original_records() {
        global $wpdb; $table=$wpdb->prefix.'gwqsh_activity_log';
        update_option('gwqsh_activity_search_cursor',0); update_option('gwqsh_activity_search_ready',false);
        $ids=array(); for($i=0;$i<253;$i++) $ids[]=$this->row('Migration fixture','System',null,$i===0?'password=legacy-secret':'Searchable description '. $i);
        GWQSH_Activity_View_Data::backfill_search();
        $this->assertSame(250,(int)$wpdb->get_var('SELECT COUNT(*) FROM '.$table.' WHERE safe_details IS NOT NULL'));
        $this->assertFalse((bool)get_option('gwqsh_activity_search_ready'));
        GWQSH_Activity_View_Data::backfill_search();
        $this->assertSame(253,(int)$wpdb->get_var('SELECT COUNT(*) FROM '.$table.' WHERE safe_details IS NOT NULL'));
        $this->assertTrue((bool)get_option('gwqsh_activity_search_ready'));
        $this->assertSame('password=legacy-secret',$wpdb->get_var($wpdb->prepare('SELECT details FROM '.$table.' WHERE id=%d',$ids[0])));
        $this->assertSame(0,GWQSH_Activity_View_Data::get(array('search'=>'legacy-secret'))['total']);
        $this->assertSame(1,GWQSH_Activity_View_Data::get(array('search'=>'Searchable description 252'))['total']);
        $this->assertArrayNotHasKey('safe_details',GWQSH_Activity_View_Data::get()['items'][0]);
    }
    public function test_new_records_have_immediate_safe_description_search() {
        $id=GWQSH_Activity_Logger::log('Safe fixture','Distinct searchable narrative','System');
        $data=GWQSH_Activity_View_Data::get(array('search'=>'searchable narrative'));
        $this->assertSame(1,$data['total']); $this->assertSame($id,$data['items'][0]['id']);
    }

    public function test_scheduled_retention_cleanup_is_bounded_and_keeps_recent_records() {
        GWQSH_Settings::set('retention',30); global $wpdb;
        $time=current_datetime()->modify('-31 days')->format('Y-m-d H:i:s');
        for($i=0;$i<1001;$i++) $this->row('Scheduled expiry fixture','System',$time);
        $recent=$this->row(); GWQSH_Activity_Logger::prune_expired_logs();
        $this->assertSame(2,(int)$wpdb->get_var('SELECT COUNT(*) FROM '.$wpdb->prefix.'gwqsh_activity_log'));
        $this->assertNotNull($wpdb->get_var($wpdb->prepare('SELECT id FROM '.$wpdb->prefix.'gwqsh_activity_log WHERE id=%d',$recent)));
        $this->assertNotFalse(wp_next_scheduled('gwqsh_daily_log_cleanup'));
    }
}
