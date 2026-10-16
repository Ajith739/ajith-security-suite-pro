<?php
// phpcs:ignoreFile -- Development tests, excluded from releases.
use PHPUnit\Framework\TestCase;

final class LoginProtectionTest extends TestCase {
    private $options, $remote, $log_ids;
    private const IP = '192.0.2.231';
    protected function setUp(): void {
        global $wpdb;
        $this->options = array();
        foreach (array('gwqsh_login_protection','gwqsh_settings','gwqsh_allowlist','gwqsh_hardening','gwqsh_cloudflare_ranges') as $key) $this->options[$key] = get_option($key, null);
        $this->remote = $_SERVER['REMOTE_ADDR'] ?? null;
        $_SERVER['REMOTE_ADDR'] = self::IP;
        $this->log_ids = (int)$wpdb->get_var("SELECT MAX(id) FROM {$wpdb->prefix}gwqsh_activity_log");
        $wpdb->delete($wpdb->prefix.'gwqsh_lockouts', array('ip_address'=>self::IP));
        GWQSH_Settings::set('status',true);
        GWQSH_Settings::set('proxy',false);
        GWQSH_Login_Protection::update_settings(array('enabled'=>true,'max_attempts'=>2,'time_window'=>15,'lockout_duration'=>30,'repeat_lockouts'=>2,'repeat_duration'=>24,'email_lockout'=>false,'track_username'=>true));
    }
    protected function tearDown(): void {
        global $wpdb;
        foreach ($this->options as $key=>$value) { null === $value ? delete_option($key) : update_option($key,$value); }
        if (null === $this->remote) { unset($_SERVER['REMOTE_ADDR']); } else { $_SERVER['REMOTE_ADDR']=$this->remote; }
        $wpdb->delete($wpdb->prefix.'gwqsh_lockouts',array('ip_address'=>self::IP));
        $wpdb->query($wpdb->prepare("DELETE FROM {$wpdb->prefix}gwqsh_activity_log WHERE id > %d AND (ip_address = %s OR details LIKE %s)",$this->log_ids,self::IP,'%qs-login-fixture%'));
    }
    public function test_threshold_lockout_does_not_extend_on_blocked_requests_and_manual_unlock_is_scoped() {
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertFalse(GWQSH_Login_Protection::is_locked(self::IP));
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertTrue(GWQSH_Login_Protection::is_locked(self::IP));
        $before=GWQSH_Login_Protection::get_ip_lock_info(self::IP);
        $this->assertInstanceOf(WP_Error::class,GWQSH_Login_Protection::check_lockout_before_auth(null,'qs-login-fixture','wrong'));
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertSame($before,GWQSH_Login_Protection::get_ip_lock_info(self::IP));
        $this->assertFalse(GWQSH_Login_Protection::unlock_ip('invalid'));
        $this->assertTrue(GWQSH_Login_Protection::unlock_ip(self::IP));
        $this->assertFalse(GWQSH_Login_Protection::unlock_ip(self::IP));
        $this->assertFalse(GWQSH_Login_Protection::is_locked(self::IP));
        $this->assertSame('0',GWQSH_Login_Protection::get_ip_lock_info(self::IP)['failed_attempts']);
    }
    public function test_repeat_escalation_and_expired_counter_restart() {
        global $wpdb;
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $first=GWQSH_Login_Protection::get_ip_lock_info(self::IP);
        $this->assertEqualsWithDelta(30*60,strtotime($first['locked_until'])-current_time('timestamp'),2);
        $wpdb->update($wpdb->prefix.'gwqsh_lockouts',array('locked_until'=>current_datetime()->modify('-1 minute')->format('Y-m-d H:i:s')),array('ip_address'=>self::IP));
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertFalse(GWQSH_Login_Protection::is_locked(self::IP));
        $this->assertSame('1',GWQSH_Login_Protection::get_ip_lock_info(self::IP)['failed_attempts']);
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $second=GWQSH_Login_Protection::get_ip_lock_info(self::IP);
        $this->assertEqualsWithDelta(24*3600,strtotime($second['locked_until'])-current_time('timestamp'),2);
    }
    public function test_allowlist_pause_and_second_factor_challenge_bypass_failures() {
        GWQSH_Login_Protection::add_to_allowlist(self::IP);
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertNull(GWQSH_Login_Protection::get_ip_lock_info(self::IP));
        GWQSH_Login_Protection::remove_from_allowlist(self::IP);
        GWQSH_Login_Protection::update_settings(array('enabled'=>false));
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertNull(GWQSH_Login_Protection::get_ip_lock_info(self::IP));
        GWQSH_Login_Protection::update_settings(array('enabled'=>true));
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture',new WP_Error('gwqsh_2fa_required'));
        $this->assertNull(GWQSH_Login_Protection::get_ip_lock_info(self::IP));
    }
    public function test_alert_is_once_per_lockout_and_username_recording_can_be_disabled() {
        global $wpdb;
        $sent=0;
        $mail=function($pre,$args) use (&$sent) { ++$sent; return true; };
        add_filter('pre_wp_mail',$mail,10,2);
        try {
            GWQSH_Login_Protection::update_settings(array('max_attempts'=>1,'email_lockout'=>true,'track_username'=>false));
            GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
            GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
            $this->assertSame(1,$sent);
            $name=$wpdb->get_var($wpdb->prepare("SELECT user_login FROM {$wpdb->prefix}gwqsh_activity_log WHERE event_name='IP locked out' AND ip_address=%s ORDER BY id DESC LIMIT 1",self::IP));
            $this->assertSame('—',$name);
            GWQSH_Activity_Logger::on_login_failed('qs-login-fixture');
            $row=$wpdb->get_row($wpdb->prepare("SELECT user_login,details FROM {$wpdb->prefix}gwqsh_activity_log WHERE event_name='Login attempt blocked' AND ip_address=%s ORDER BY id DESC LIMIT 1",self::IP),ARRAY_A);
            $this->assertSame('—',$row['user_login']);
            $this->assertStringNotContainsString('qs-login-fixture',$row['details']);
        } finally { remove_filter('pre_wp_mail',$mail,10); }
    }
    public function test_window_expiry_is_measured_from_first_failure_not_last_activity() {
        global $wpdb;
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $wpdb->update($wpdb->prefix.'gwqsh_lockouts',array('first_attempt'=>current_datetime()->modify('-16 minutes')->format('Y-m-d H:i:s'),'last_attempt'=>current_time('mysql')),array('ip_address'=>self::IP));
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertFalse(GWQSH_Login_Protection::is_locked(self::IP));
        $this->assertSame('1',GWQSH_Login_Protection::get_ip_lock_info(self::IP)['failed_attempts']);
        GWQSH_Login_Protection::record_failed_attempt('qs-login-fixture');
        $this->assertTrue(GWQSH_Login_Protection::is_locked(self::IP));
    }
    public function test_equivalent_ipv6_allowlist_addresses_match() {
        GWQSH_Login_Protection::add_to_allowlist('2001:db8::231');
        $this->assertTrue(GWQSH_Login_Protection::is_ip_allowlisted('2001:0db8:0000:0000:0000:0000:0000:0231'));
        $this->assertFalse(GWQSH_Login_Protection::is_ip_allowlisted('2001:db8::232'));
    }
    public function test_proxy_status_requires_a_valid_header_from_a_trusted_peer() {
        if (defined('GWQSH_TRUSTED_PROXIES')) $this->markTestSkipped('Site has its own trusted proxy configuration.');
        define('GWQSH_TRUSTED_PROXIES',array('192.0.2.240'));
        delete_option('gwqsh_cloudflare_ranges');
        $old = array();
        foreach(array('HTTP_CF_CONNECTING_IP','HTTP_X_FORWARDED_FOR') as $key) { $old[$key]=$_SERVER[$key]??null; unset($_SERVER[$key]); }
        try {
            $_SERVER['REMOTE_ADDR']='192.0.2.240';
            GWQSH_Settings::update_all(array('proxy'=>true,'proxyheader'=>'cf'));
            $this->assertFalse(GWQSH_Login_View_Data::get()['proxy_effective']);
            $_SERVER['HTTP_CF_CONNECTING_IP']='2001:db8::240';
            // Explicit proxy trust alone cannot establish Cloudflare provenance.
            $this->assertFalse(GWQSH_Login_View_Data::get()['proxy_effective']);
            update_option('gwqsh_cloudflare_ranges',array('ranges'=>array('192.0.2.240/32'),'checked_at'=>time()));
            $d=GWQSH_Login_View_Data::get();
            $this->assertTrue($d['proxy_effective']);
            $this->assertSame('Cloudflare',$d['proxy_name']);
            $this->assertSame('2001:db8::240',$d['client_ip']);
            $_SERVER['HTTP_CF_CONNECTING_IP']='invalid';
            $this->assertFalse(GWQSH_Login_View_Data::get()['proxy_effective']);
            unset($_SERVER['HTTP_CF_CONNECTING_IP']);$_SERVER['HTTP_X_FORWARDED_FOR']='192.0.2.241, 192.0.2.240';
            // Selecting Cloudflare must not silently fall back to a different header.
            $this->assertSame('REMOTE_ADDR',GWQSH_Login_View_Data::get()['proxy_name']);
            GWQSH_Settings::update_all(array('proxyheader'=>'xff'));
            $this->assertSame('X-Forwarded-For',GWQSH_Login_View_Data::get()['proxy_name']);
        } finally { foreach($old as $key=>$value) { if(null===$value) unset($_SERVER[$key]); else $_SERVER[$key]=$value; } }
    }
    public function test_snapshot_counts_actual_denials_separately_from_ordinary_failed_logins() {
        $before=GWQSH_Login_View_Data::get();
        GWQSH_Activity_Logger::on_login_failed('qs-login-fixture');
        $failed=GWQSH_Login_View_Data::get();
        $this->assertSame($before['blocked_30d'],$failed['blocked_30d']);
        $this->assertSame(array_sum($before['chart']['failed'])+1,array_sum($failed['chart']['failed']));
        GWQSH_Activity_Logger::log('Login blocked by lockout','qs-login-fixture','Security','qs-login-fixture',self::IP);
        $denied=GWQSH_Login_View_Data::get(30);
        $this->assertSame($before['blocked_30d']+1,$denied['blocked_30d']);
        $this->assertCount(30,$denied['chart']['labels']);
        $this->assertNull($denied['score_components']['country']);
        $this->assertFalse($denied['data_error']);
        $parts=$denied['score_components'];
        $this->assertSame((int)round($parts['brute']*.4+$parts['custom']*.2+$parts['xmlrpc']*.2+$parts['rules']*.2),$denied['protection_score']);
    }
}

