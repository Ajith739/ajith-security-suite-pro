<?php
// phpcs:ignoreFile -- Transactional development fixtures, excluded from releases.
use PHPUnit\Framework\TestCase;
final class HardeningPageTest extends TestCase {
    private $viewer, $server, $dir, $uploadFilter, $httpFilter;
    protected function setUp(): void {
        global $wpdb;
        $this->viewer=get_current_user_id(); $this->server=$_SERVER['SERVER_SOFTWARE']??null;
        $wpdb->query('START TRANSACTION');
        $admins=get_users(array('role'=>'administrator','number'=>1)); wp_set_current_user($admins[0]->ID);
        $settings=get_option('gwqsh_settings',array()); $settings['status']=true; update_option('gwqsh_settings',$settings);
        $_SERVER['SERVER_SOFTWARE']='Apache/2.4';
        $this->dir=WP_CONTENT_DIR.'/quietshield-hardening-fixture-'.bin2hex(random_bytes(6)); mkdir($this->dir);
        $this->uploadFilter=function($u){$u['basedir']=$this->dir;$u['path']=$this->dir;$u['baseurl']=home_url('/wp-content/'.basename($this->dir));$u['url']=$u['baseurl'];$u['error']=false;return $u;};
        add_filter('upload_dir',$this->uploadFilter);
        foreach(array('gwqsh_hardening_uploads_backup','gwqsh_hardening_uploads_last_backup') as $key) delete_option($key);
        delete_transient('gwqsh_hardening_evidence'); delete_transient('gwqsh_hardening_probe_'.get_current_user_id());
        update_option('gwqsh_hardening',array_fill_keys(array_keys(GWQSH_Hardening::get_defaults()),true));
    }
    protected function tearDown(): void {
        global $wpdb;
        if($this->httpFilter)remove_filter('pre_http_request',$this->httpFilter,10);
        remove_filter('upload_dir',$this->uploadFilter);
        foreach(glob($this->dir.'/*') as $file) if(is_file($file))unlink($file);
        foreach(array('.htaccess','.quietshield-hardening.lock') as $file)if(file_exists($this->dir.'/'.$file))unlink($this->dir.'/'.$file);
        rmdir($this->dir);
        $wpdb->query('ROLLBACK');wp_cache_flush();wp_set_current_user($this->viewer);
        if($this->server===null)unset($_SERVER['SERVER_SOFTWARE']);else $_SERVER['SERVER_SOFTWARE']=$this->server;
    }
    public function test_read_only_assessment_distinguishes_intent_and_effectiveness() {
        $a=GWQSH_Hardening_Data::get();
        $this->assertSame(55,$a['score']);$this->assertSame(4,$a['passed']);$this->assertSame(2,$a['pending']);
        $this->assertSame('Verification Pending',$a['rows']['headers']['status']);
        $this->assertSame('Partially Applied',$a['rows']['uploads']['status']);
        $this->assertFileDoesNotExist($this->dir.'/.htaccess');
        $this->assertSame($a['score'],GWQSH_Hardening::get_risk()['score']);
        $this->assertSame($a['score'],$a['components']['hardening']);
    }
    public function test_owned_rules_preserve_unrelated_bytes_and_back_up_before_write() {
        $foreign="# Host rules\r\nOptions -Indexes\r\n# Custom end";
        file_put_contents($this->dir.'/.htaccess',$foreign);
        $this->assertTrue(GWQSH_Hardening_Rules::sync(true));
        $this->assertSame($foreign,get_option('gwqsh_hardening_uploads_last_backup')['content']);
        $first=file_get_contents($this->dir.'/.htaccess');
        $this->assertTrue(GWQSH_Hardening_Rules::sync(true));$this->assertSame($first,file_get_contents($this->dir.'/.htaccess'));
        $this->assertTrue(GWQSH_Hardening_Rules::sync(false));$this->assertSame($foreign,file_get_contents($this->dir.'/.htaccess'));
        $this->assertFileDoesNotExist($this->dir.'/.quietshield-hardening.lock');
    }
    public function test_ambiguous_managed_blocks_and_lock_prevent_writes() {
        foreach(array(GWQSH_Hardening_Rules::block().GWQSH_Hardening_Rules::block(),str_replace('Require all denied','Require all granted',GWQSH_Hardening_Rules::block())) as $bad){
            file_put_contents($this->dir.'/.htaccess',$bad);$this->assertFalse(GWQSH_Hardening_Rules::sync(false));$this->assertSame($bad,file_get_contents($this->dir.'/.htaccess'));
        }
        unlink($this->dir.'/.htaccess');file_put_contents($this->dir.'/.quietshield-hardening.lock','busy');
        $this->assertFalse(GWQSH_Hardening_Rules::sync(true));$this->assertFileDoesNotExist($this->dir.'/.htaccess');
    }
    public function test_nginx_intent_is_manual_and_reset_differs_from_revert() {
        $_SERVER['SERVER_SOFTWARE']='nginx';$this->assertTrue(GWQSH_Hardening::set('uploads',true));
        $this->assertFileDoesNotExist($this->dir.'/.htaccess');$this->assertSame('Manual Configuration Required',GWQSH_Hardening_Data::get()['rows']['uploads']['status']);
        $_SERVER['SERVER_SOFTWARE']='Apache';
        $this->assertTrue(GWQSH_Hardening::reset_defaults());$this->assertSame(GWQSH_Hardening::get_defaults(),GWQSH_Hardening::get_all());
        $this->assertTrue(GWQSH_Hardening_Rules::inspect()['owned']);
        $this->assertTrue(GWQSH_Hardening::revert_all());$this->assertSame(0,GWQSH_Hardening::get_risk()['score']);
        $this->assertSame('off',GWQSH_Hardening_Data::csp()['mode']);$this->assertFileDoesNotExist($this->dir.'/.htaccess');
    }
    public function test_csp_rejects_injection_and_requires_enforcement_confirmation() {
        foreach(array("default-src 'self'\r\nX-Evil: yes","default-src 'self'; default-src *","img-src 'none' https:","report-uri https://example.test","script-src javascript:",str_repeat('a',2049)) as $policy)$this->assertInstanceOf(WP_Error::class,GWQSH_Hardening_Data::save_csp('report',$policy,'1'));
        $policy="default-src 'self'; img-src 'self' https: data:";
        $this->assertTrue(GWQSH_Hardening_Data::save_csp('report',$policy,'1'));
        $this->assertInstanceOf(WP_Error::class,GWQSH_Hardening_Data::save_csp('enforce',$policy,'0'));
        $this->assertSame('report',GWQSH_Hardening_Data::csp()['mode']);
        $this->assertTrue(GWQSH_Hardening_Data::save_csp('enforce',$policy,'1'));
        wp_set_current_user(0);$this->assertInstanceOf(WP_Error::class,GWQSH_Hardening_Data::save_csp('off','','1'));
        $this->assertInstanceOf(WP_Error::class,GWQSH_Hardening_Data::get());
    }
    public function test_runtime_guards_preserve_cache_keys_and_authorized_rest() {
        $version=get_bloginfo('version');
        $core=includes_url('js/core.js');
        $this->assertSame($core.'?x=1',GWQSH_Hardening::remove_version_param($core.'?ver='.$version.'&x=1'));
        $this->assertSame('/plugin.js?ver='.$version,GWQSH_Hardening::remove_version_param('/plugin.js?ver='.$version));
        foreach(array($version.'1','custom-cache-key','1.2.3') as $v)$this->assertSame('/plugin.js?ver='.$v,GWQSH_Hardening::remove_version_param('/plugin.js?ver='.$v));
        $routes=array('/wp/v2/users'=>array(),'/wp/v2/posts'=>array(),'/custom/route'=>array());
        $this->assertSame($routes,GWQSH_Hardening::restrict_rest_users($routes));wp_set_current_user(0);
        $this->assertSame(array('/wp/v2/posts'=>array(),'/custom/route'=>array()),GWQSH_Hardening::restrict_rest_users($routes));
        update_option('gwqsh_hardening',array_fill_keys(array_keys(GWQSH_Hardening::get_defaults()),false));
        $this->assertSame($routes,GWQSH_Hardening::restrict_rest_users($routes));
        $this->assertSame('generator',GWQSH_Hardening::generator('generator'));
        $this->assertTrue(GWQSH_Hardening::xmlrpc_enabled(true));
        $this->assertSame(array('edit_plugins'=>true),GWQSH_Hardening::remove_editor_caps(array('edit_plugins'=>true),array(),array()));
        $this->assertFalse(GWQSH_Hardening::set('unknown',true));
    }
    public function test_fixed_same_site_verification_cleanup_cooldown_and_evidence_invalidation() {
        $this->assertTrue(GWQSH_Hardening_Rules::sync(true));$requests=array();
        $this->httpFilter=function($pre,$args,$url)use(&$requests){
            $requests[]=$url;$this->assertSame(wp_parse_url(home_url(),PHP_URL_HOST),wp_parse_url($url,PHP_URL_HOST));$this->assertSame(0,$args['redirection']);$this->assertSame(5,$args['timeout']);
            $php=str_ends_with($url,'.php');return array('headers'=>GWQSH_Hardening_Data::expected_headers(),'body'=>'Security Suite Pro inert access probe','response'=>array('code'=>$php?403:200,'message'=>'fixture'),'cookies'=>array());
        };add_filter('pre_http_request',$this->httpFilter,10,3);
        $e=GWQSH_Hardening_Data::verify();$this->assertIsArray($e);$this->assertTrue($e['headers_pass']);$this->assertTrue($e['uploads_pass']);$this->assertCount(3,$requests);
        $this->assertSame(100,GWQSH_Hardening_Data::assessment()['score']);
        $this->assertEmpty(glob($this->dir.'/quietshield-probe-*'));
        $this->assertInstanceOf(WP_Error::class,GWQSH_Hardening_Data::verify());
        file_put_contents($this->dir.'/.htaccess',"# external change\n".file_get_contents($this->dir.'/.htaccess'));
        $this->assertEmpty(GWQSH_Hardening_Data::evidence());$this->assertSame(55,GWQSH_Hardening_Data::assessment()['score']);
    }
    public function test_verification_redirect_failure_never_awards_credit() {
        $this->httpFilter=fn()=>array('headers'=>array(),'body'=>'','response'=>array('code'=>301,'message'=>'Redirect'),'cookies'=>array());add_filter('pre_http_request',$this->httpFilter);
        $this->assertInstanceOf(WP_Error::class,GWQSH_Hardening_Data::verify());$this->assertEmpty(GWQSH_Hardening_Data::evidence());$this->assertSame(55,GWQSH_Hardening_Data::assessment()['score']);
    }
    public function test_failed_settings_persistence_does_not_touch_files_and_rule_failure_restores_options() {
        $old=GWQSH_Hardening::get_all();$old['uploads']=false;update_option('gwqsh_hardening',$old);
        $reject=fn($new,$previous)=>$previous;add_filter('pre_update_option_gwqsh_hardening',$reject,10,2);
        try {$this->assertFalse(GWQSH_Hardening::set('uploads',true));$this->assertFileDoesNotExist($this->dir.'/.htaccess');}finally{remove_filter('pre_update_option_gwqsh_hardening',$reject,10);}
        file_put_contents($this->dir.'/.quietshield-hardening.lock','busy');
        $this->assertFalse(GWQSH_Hardening::set('uploads',true));$this->assertSame($old,GWQSH_Hardening::get_all());
        $this->assertSame($old,get_option('gwqsh_hardening_settings_backup')['settings']);
    }
    public function test_external_edits_are_preserved_during_owned_block_removal() {
        $foreign='# Original';file_put_contents($this->dir.'/.htaccess',$foreign);
        $this->assertTrue(GWQSH_Hardening_Rules::sync(true));
        $external="\n# Added by host\n";file_put_contents($this->dir.'/.htaccess',$external,FILE_APPEND);
        $this->assertTrue(GWQSH_Hardening_Rules::sync(false));
        $this->assertSame($foreign."\n".$external,file_get_contents($this->dir.'/.htaccess'));
    }

}
