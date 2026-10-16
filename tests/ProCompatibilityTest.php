<?php
// phpcs:ignoreFile -- Isolated upgrade regressions; excluded from release archives.
use PHPUnit\Framework\TestCase;

final class ProCompatibilityTest extends TestCase {
    public function test_free_and_legacy_pro_encryption_payloads_remain_readable() {
        $plain = 'JBSWY3DPEHPK3PXP';
        $keys = array(
            hash('sha256', GWQSH_Crypto::get_site_salt(), true),
            hash('sha256', wp_salt('auth').'|'.wp_salt('secure_auth').'|'.wp_salt('logged_in'), true),
        );
        foreach ($keys as $key) {
            $nonce = random_bytes(12);$tag = '';
            $cipher = openssl_encrypt($plain,'aes-256-gcm',$key,OPENSSL_RAW_DATA,$nonce,$tag);
            $payload = 'gwqsh1:o:'.base64_encode($nonce.$tag.$cipher);
            $this->assertSame($plain,GWQSH_Crypto::decrypt($payload));
            $this->assertSame($plain,GWQSH_Crypto::decrypt(str_replace('gwqsh1:','gqs1:',$payload)));
        }
    }

    public function test_free_and_legacy_pro_backup_verifiers_are_atomic_and_new_codes_use_site_salt() {
        $viewer=get_current_user_id();
        $id=wp_create_user('pro_compat_'.bin2hex(random_bytes(5)),wp_generate_password(24),'pro-compat@example.invalid');
        $this->assertIsInt($id);
        try {
            $codes=array('ABCD-2345','DEFG-6789');
            update_user_meta($id,'gwqsh_backup_codes',array(
                array('hash'=>'sha256:'.hash_hmac('sha256',$codes[0],GWQSH_Crypto::get_site_salt()),'used'=>false),
                array('hash'=>'sha256:'.hash_hmac('sha256',$codes[1],wp_salt('auth')),'used'=>false),
            ));
            foreach($codes as $code) {
                $this->assertTrue(GWQSH_Two_Factor::verify_and_burn_backup_code($id,$code));
                $this->assertFalse(GWQSH_Two_Factor::verify_and_burn_backup_code($id,$code));
            }
            GWQSH_Two_Factor::save_user_backup_codes($id,array('JKLM-2345'));
            $stored=get_user_meta($id,'gwqsh_backup_codes',true);
            $this->assertStringStartsWith('sha256-site:',$stored[0]['hash']);
            $this->assertTrue(GWQSH_Two_Factor::verify_and_burn_backup_code($id,'JKLM-2345'));
        } finally {
            wp_set_current_user($viewer);require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user($id);
        }
    }

    public function test_missing_free_site_key_is_not_silently_replaced() {
        $salt=get_option('gwqsh_site_salt');$legacy=get_option('gwqsh_legacy_pro_crypto',null);
        $id=wp_create_user('pro_key_'.bin2hex(random_bytes(5)),wp_generate_password(24),'pro-key@example.invalid');
        $payload=GWQSH_Crypto::encrypt('JBSWY3DPEHPK3PXP');
        try {
            update_user_meta($id,'gwqsh_2fa_secret',$payload);
            delete_option('gwqsh_site_salt');delete_option('gwqsh_legacy_pro_crypto');
            $this->assertFalse(GWQSH_Crypto::decrypt($payload));
            $this->assertFalse(get_option('gwqsh_site_salt',false));
            $this->assertFalse(GWQSH_Crypto::encrypt('JBSWY3DPEHPK3PXP'));
            $this->assertFalse(get_option('gwqsh_site_salt',false));
        } finally {
            update_option('gwqsh_site_salt',$salt,false);
            null===$legacy?delete_option('gwqsh_legacy_pro_crypto'):update_option('gwqsh_legacy_pro_crypto',$legacy,false);
            require_once ABSPATH.'wp-admin/includes/user.php';wp_delete_user($id);
        }
    }

    public function test_conflict_detection_covers_network_and_site_activation_without_own_directory() {
        $active=get_option('active_plugins');$network=get_site_option('active_sitewide_plugins',null);
        try {
            update_option('active_plugins',array('gracewell-security-suite/gracewell-security-suite.php',GWQSH_PLUGIN_BASENAME));
            $this->assertContains('gracewell-security-suite/gracewell-security-suite.php',GWQSH_Pro_Compatibility::conflicts(GWQSH_PLUGIN_FILE));
            update_option('active_plugins',array(GWQSH_PLUGIN_BASENAME));
            update_site_option('active_sitewide_plugins',array('gracewell-security-suite/gracewell-security-suite.php'=>time()));
            $this->assertCount(1,GWQSH_Pro_Compatibility::conflicts(GWQSH_PLUGIN_FILE));
            delete_site_option('active_sitewide_plugins');
            $this->assertSame(array(),GWQSH_Pro_Compatibility::conflicts(GWQSH_PLUGIN_FILE));
        } finally {
            update_option('active_plugins',$active);
            null===$network?delete_site_option('active_sitewide_plugins'):update_site_option('active_sitewide_plugins',$network);
        }
    }
}
