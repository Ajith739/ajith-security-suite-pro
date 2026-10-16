<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
use PHPUnit\Framework\TestCase;
final class UiBackendTest extends TestCase {
    public function test_login_urls_support_plain_index_and_pretty_permalinks() {
        $structure=get_option('permalink_structure');
        $login=get_option('gwqsh_login_protection');
        $settings=get_option('gwqsh_settings');
        try {
            GWQSH_Settings::set('status',true);
            GWQSH_Login_Protection::update_settings(array('custom_slug'=>'gwqsh-route-fixture','custom_slug_enabled'=>true));
            foreach(array(''=>home_url('/').'?gwqsh_login=gwqsh-route-fixture','/index.php/%postname%/'=>home_url('/index.php/gwqsh-route-fixture/'),'/%postname%/'=>home_url('/gwqsh-route-fixture/')) as $format=>$expected) {
                update_option('permalink_structure',$format);
                $this->assertSame($expected,GWQSH_Login_Protection::custom_login_url());
                $this->assertSame($expected,GWQSH_Login_Protection::filter_login_url(get_option('siteurl').'/wp-login.php'));
                $this->assertSame($expected.($format?'?':'&').'redirect_to=test',GWQSH_Login_Protection::filter_login_url(get_option('siteurl').'/wp-login.php?redirect_to=test'));
            }
        } finally { update_option('permalink_structure',$structure); update_option('gwqsh_login_protection',$login); update_option('gwqsh_settings',$settings); }
    }
    public function test_custom_login_url_preserves_subdirectory_and_actions() {
        $original = GWQSH_Login_Protection::get_settings();
        try {
            GWQSH_Login_Protection::update_settings(array('custom_slug'=>'test-login','custom_slug_enabled'=>true));
            $base=get_option('siteurl').'/wp-login.php';
            $this->assertSame($base.'?action=lostpassword',GWQSH_Login_Protection::filter_login_url($base.'?action=lostpassword'));
            $this->assertSame($base.'.backup',GWQSH_Login_Protection::filter_login_url($base.'.backup'));
        } finally { GWQSH_Login_Protection::update_settings($original); }
    }
    public function test_optional_bundled_plugins_are_not_core_files() {
        $method=new ReflectionMethod(GWQSH_File_Integrity::class,'core_only_checksums');
        $method->setAccessible(true);
        $filtered=$method->invoke(null,array('wp-includes/version.php'=>md5('one'),'wp-content/plugins/hello.php'=>md5('two'),'wp-admin/index.php'=>md5('three')));
        $this->assertArrayNotHasKey('wp-content/plugins/hello.php',$filtered);
        $this->assertCount(2,$filtered);
    }
    public function test_backup_status_survives_user_meta_cache_refresh() {
        $id=wp_create_user('gwqsh_ui_'.wp_generate_password(10,false),wp_generate_password(24),'gwqsh-ui@example.invalid');
        try {
            $codes=GWQSH_Two_Factor::generate_backup_codes(2);
            GWQSH_Two_Factor::save_user_backup_codes($id,$codes);
            clean_user_cache($id);
            $this->assertSame(array(array('used'=>false),array('used'=>false)),GWQSH_Two_Factor::get_user_backup_codes($id));
            $this->assertTrue(GWQSH_Two_Factor::verify_and_burn_backup_code($id,$codes[0]));
            clean_user_cache($id);
            $this->assertSame(array(array('used'=>true),array('used'=>false)),GWQSH_Two_Factor::get_user_backup_codes($id));
        } finally { require_once ABSPATH.'wp-admin/includes/user.php'; wp_delete_user($id); }
    }
    public function test_score_uses_actual_components() {
        $viewer=get_current_user_id();
        $admins=get_users(array('role'=>'administrator','number'=>1));wp_set_current_user($admins[0]->ID);
        try {
        $parts=GWQSH_Admin::get_score_components();
        $this->assertSame(GWQSH_Login_Protection::get_settings()['enabled']?100:0,$parts['login']);
        $this->assertSame(GWQSH_Admin::score_from_components($parts),GWQSH_Admin::get_page_initial_data('hardening')['overall']);
        } finally { wp_set_current_user($viewer); }
    }
}
