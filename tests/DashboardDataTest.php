<?php
// phpcs:ignoreFile -- Development-only fixtures are removed after each test.
use PHPUnit\Framework\TestCase;
final class DashboardDataTest extends TestCase {
    public function test_lockouts_are_not_inflated_by_failed_login_audit_records() {
        global $wpdb;
        $table=$wpdb->prefix.'gwqsh_activity_log';
        $cutoff=current_datetime()->modify('-6 days')->format('Y-m-d 00:00:00');
        $before=(int)$wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE event_name IN (%s,%s,%s,%s,%s) AND event_time >= %s",'IP locked out','Firewall request blocked','Login blocked by lockout','XML-RPC login blocked','XML-RPC access blocked',$cutoff));
        $ids=array();
        $settings=get_option('gwqsh_hardening');
        try {
            foreach(array('IP locked out','Firewall request blocked','XML-RPC access blocked','Login attempt blocked','Login attempt blocked') as $name) {
                $wpdb->insert($table,array('event_time'=>current_time('mysql'),'event_name'=>$name,'event_type'=>'Security','user_login'=>'dashboard-unit-fixture','ip_address'=>'192.0.2.17','details'=>'Ephemeral dashboard unit fixture'));
                $ids[]=$wpdb->insert_id;
            }
            $snapshot=GWQSH_Dashboard_Data::get(14,7);
            $this->assertSame($before+3,$snapshot['threats_blocked']);
            $this->assertGreaterThanOrEqual(3,array_sum($snapshot['chart_data']['blocked']));
            $this->assertContains('Firewall request blocked',array_column($snapshot['live_threats'],'event_name'));
            $this->assertSame(14,count($snapshot['chart_data']['labels']));
            $this->assertFalse($snapshot['chart_data']['error']);
            $this->assertNull($snapshot['country_blocks']);
            $this->assertSame(array(),$snapshot['geography']);
            $this->assertSame($settings,get_option('gwqsh_hardening'));
            $this->assertSame(GWQSH_Admin::score_from_components($snapshot['score_components']),$snapshot['security_score']);
        } finally { foreach($ids as $id) $wpdb->delete($table,array('id'=>$id),array('%d')); }
    }
    public function test_template_escapes_recorded_ip_addresses_and_details() {
        global $wpdb;
        $table=$wpdb->prefix.'gwqsh_activity_log';
        $payload='<img src=x onerror=alert(1)>';
        $wpdb->insert($table,array('event_time'=>current_time('mysql'),'event_name'=>'IP locked out','event_type'=>'Security','user_login'=>'dashboard-unit-fixture','ip_address'=>$payload,'details'=>$payload));
        $id=$wpdb->insert_id;
        try {
            ob_start(); require GWQSH_PATH.'admin/views/dashboard.php'; $html=ob_get_clean();
            $this->assertStringNotContainsString($payload,$html);
            $this->assertStringContainsString(esc_html($payload),$html);
            $this->assertStringNotContainsString('href="#"',$html);
        } finally { $wpdb->delete($table,array('id'=>$id),array('%d')); }
    }
}
