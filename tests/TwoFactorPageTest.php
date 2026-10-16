<?php
// phpcs:ignoreFile -- Development security integration tests, excluded from release.
use PHPUnit\Framework\TestCase;
final class TwoFactorPageTest extends TestCase {
    private $user;
    private $viewer;
    protected function setUp(): void {
        $this->viewer=get_current_user_id();
        $this->user=wp_create_user('gwqsh_tf_test_'.bin2hex(random_bytes(5)),wp_generate_password(32),'gwqsh-tf-'.bin2hex(random_bytes(5)).'@example.invalid');
        $this->assertIsInt($this->user);
        wp_set_current_user($this->user);
    }
    protected function tearDown(): void {
        wp_set_current_user($this->viewer);
        require_once ABSPATH.'wp-admin/includes/user.php';
        wp_delete_user($this->user);
    }
    public function test_pending_setup_does_not_activate_or_replace_a_factor() {
        $secret=GWQSH_Two_Factor::get_setup_secret($this->user);
        $this->assertSame('',get_user_meta($this->user,'gwqsh_2fa_secret',true));
        $this->assertFalse(GWQSH_Two_Factor::is_user_2fa_enabled($this->user));
        $this->assertStringStartsWith('gwqsh1:',get_user_meta($this->user,'gwqsh_2fa_pending_secret',true));
        $this->assertSame($secret,GWQSH_Two_Factor::get_setup_secret($this->user));
        $this->assertTrue(GWQSH_Two_Factor::enable_user_2fa($this->user,$secret));
        $replacement=GWQSH_Two_Factor::generate_secret();
        update_user_meta($this->user,'gwqsh_2fa_pending_secret',GWQSH_Crypto::encrypt($replacement));
        $this->assertSame($secret,GWQSH_Two_Factor::get_user_secret($this->user));
        $this->assertSame($replacement,GWQSH_Two_Factor::get_provisioning_secret($this->user));
    }
    public function test_snapshot_is_owned_and_paginated_and_hides_device_tokens() {
        $secret=GWQSH_Two_Factor::get_setup_secret($this->user);
        GWQSH_Two_Factor::enable_user_2fa($this->user,$secret);
        GWQSH_Two_Factor::save_user_backup_codes($this->user,GWQSH_Two_Factor::generate_backup_codes(2));
        $token=hash('sha256','gwqsh-tf-device-fixture');
        update_user_meta($this->user,'gwqsh_trusted_devices',array(array('token_hash'=>$token,'expires'=>time()+1000,'label'=>'Integration test browser')));
        $snapshot=GWQSH_Two_Factor_View_Data::get();
        $this->assertCount(1,$snapshot['users']);
        $this->assertFalse($snapshot['can_manage']);
        $this->assertSame('',$snapshot['secret']);
        $this->assertSame('Enabled',$snapshot['users'][0]['st']);
        $this->assertSame(2,$snapshot['backup_remaining']);
        $this->assertArrayNotHasKey('backup_codes',$snapshot['users'][0]);
        $this->assertStringNotContainsString($token,json_encode($snapshot));
        $this->assertSame('TOTP',$snapshot['users'][0]['m']);
    }
    public function test_device_revocation_cannot_use_a_stale_position_or_another_owner() {
        $records=array();
        foreach(array('one','two') as $key)$records[]=array('token_hash'=>hash('sha256',$key),'expires'=>time()+1000,'label'=>$key);
        update_user_meta($this->user,'gwqsh_trusted_devices',$records);
        $devices=GWQSH_Two_Factor::get_trusted_devices($this->user);
        $this->assertFalse(GWQSH_Two_Factor::remove_trusted_device($this->user,0));
        $this->assertTrue(GWQSH_Two_Factor::remove_trusted_device($this->user,$devices[0]['id']));
        $this->assertFalse(GWQSH_Two_Factor::remove_trusted_device($this->user,$devices[0]['id']));
        $this->assertTrue(GWQSH_Two_Factor::remove_trusted_device($this->user,$devices[1]['id']));
        $this->assertSame(array(),GWQSH_Two_Factor::get_trusted_devices($this->user));
    }
    public function test_factor_attempts_share_an_atomic_account_window() {
        for($i=0;$i<10;$i++)$this->assertTrue(GWQSH_Two_Factor::reserve_factor_attempt($this->user));
        $this->assertFalse(GWQSH_Two_Factor::reserve_factor_attempt($this->user));
        update_user_meta($this->user,'gwqsh_2fa_attempts',array('until'=>time()-1,'count'=>10));
        $this->assertTrue(GWQSH_Two_Factor::reserve_factor_attempt($this->user));
    }
    public function test_real_custom_role_enforcement_and_reset_cleanup() {
        $original=get_option('gwqsh_two_factor_settings',null);
        add_role('gwqsh_tf_custom','Two-Factor test role',array('read'=>true));
        try {
            (new WP_User($this->user))->set_role('gwqsh_tf_custom');
            update_option('gwqsh_two_factor_settings',array('enforce_roles'=>true,'required_roles'=>array('gwqsh_tf_custom')));
            $this->assertTrue(GWQSH_Two_Factor::required($this->user));
            $this->assertTrue(GWQSH_Two_Factor::needs_setup($this->user));
            $secret=GWQSH_Two_Factor::get_setup_secret($this->user);
            GWQSH_Two_Factor::enable_user_2fa($this->user,$secret);
            $this->assertFalse(GWQSH_Two_Factor::needs_setup($this->user));
            GWQSH_Two_Factor::save_user_backup_codes($this->user,GWQSH_Two_Factor::generate_backup_codes(2));
            update_user_meta($this->user,'gwqsh_backup_generated','2026-10-08 12:00:00');
            GWQSH_Two_Factor::reset_user_2fa($this->user);
            foreach(array('gwqsh_2fa_secret','gwqsh_2fa_pending_secret','gwqsh_backup_codes','gwqsh_backup_generated','gwqsh_2fa_last_verified','gwqsh_trusted_devices') as $key)$this->assertSame('',get_user_meta($this->user,$key,true));
            $this->assertTrue(GWQSH_Two_Factor::required($this->user));
        } finally {remove_role('gwqsh_tf_custom');null===$original?delete_option('gwqsh_two_factor_settings'):update_option('gwqsh_two_factor_settings',$original);}
    }
    public function test_backup_regeneration_and_atomic_consumption() {
        $old=GWQSH_Two_Factor::generate_backup_codes(2);GWQSH_Two_Factor::save_user_backup_codes($this->user,$old);
        $new=GWQSH_Two_Factor::generate_backup_codes(2);GWQSH_Two_Factor::save_user_backup_codes($this->user,$new);
        $this->assertFalse(GWQSH_Two_Factor::verify_and_burn_backup_code($this->user,$old[0]));
        $this->assertTrue(GWQSH_Two_Factor::verify_and_burn_backup_code($this->user,$new[0]));
        $this->assertFalse(GWQSH_Two_Factor::verify_and_burn_backup_code($this->user,$new[0]));
        $stored=get_user_meta($this->user,'gwqsh_backup_codes',true);
        $this->assertArrayNotHasKey('hash',$stored[0]);$this->assertArrayNotHasKey('display',$stored[0]);
    }
    public function test_summary_cache_invalidates_and_email_search_is_paginated() {
        (new WP_User($this->user))->set_role('administrator');
        wp_set_current_user(0);wp_set_current_user($this->user);
        GWQSH_Two_Factor_View_Data::invalidate();
        $before=GWQSH_Two_Factor_View_Data::get();
        $secret=GWQSH_Two_Factor::get_setup_secret($this->user);
        GWQSH_Two_Factor::enable_user_2fa($this->user,$secret);
        $after=GWQSH_Two_Factor_View_Data::get(array('search'=>get_userdata($this->user)->user_email,'status'=>'Enabled'));
        $this->assertSame($before['counts']['enabled']+1,$after['counts']['enabled']);
        $this->assertCount(1,$after['users']);
        $this->assertSame($this->user,$after['users'][0]['id']);
        $this->assertLessThanOrEqual(25,count($after['users']));
        $this->assertStringNotContainsString($secret,json_encode(get_transient('gwqsh_tf_summary')));
        $this->assertSame(array(),GWQSH_Two_Factor_View_Data::get(array('status'=>'unknown'))['users']);
    }
    public function test_management_totp_cannot_replay_a_consumed_login_code() {
        $secret=GWQSH_Two_Factor::get_setup_secret($this->user);GWQSH_Two_Factor::enable_user_2fa($this->user,$secret);
        $code=GWQSH_Two_Factor::calculate_totp($secret);
        $this->assertTrue(GWQSH_Two_Factor::consume_totp($this->user,$code));
        $this->assertFalse(GWQSH_Two_Factor::consume_totp($this->user,$code));
    }

}
