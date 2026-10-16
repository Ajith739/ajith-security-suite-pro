<?php
// Development-only transactional enterprise integration tests; excluded from release archives.
use PHPUnit\Framework\TestCase;
final class EnterpriseSecurityTest extends TestCase {
 private $viewer; private $server;
 protected function setUp(): void {global $wpdb;$wpdb->query('START TRANSACTION');$this->viewer=get_current_user_id();$this->server=$_SERVER;$_SERVER['REMOTE_ADDR']='127.0.0.1';$admins=get_users(array('role'=>'administrator','number'=>1));wp_set_current_user($admins[0]->ID);update_option('gwqsh_enterprise',array());}
 protected function tearDown(): void {global $wpdb;$wpdb->query('ROLLBACK');wp_cache_flush();$_SERVER=$this->server;wp_set_current_user($this->viewer);}
 public function test_new_settings_reject_types_unknown_codes_and_nonadmin_recipients(): void {
  $this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_Config::save('geo',array('enabled'=>'yes')));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_Config::save('geo',array('countries'=>'ZZ')));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_Config::save('alerts',array('recipient'=>'absent@example.test')));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_Config::save('waf',array('mode'=>'execute')));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_Config::save('geo',array('unknown_field'=>true)));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_Config::save('alerts',array('slack_url'=>'https://127.0.0.1/private')));
 }
 public function test_credential_encryption_keep_and_revoke(): void {
  $secret='fixture-api-'.bin2hex(random_bytes(8));$this->assertIsArray(GWQSH_Enterprise_Config::save('reputation',array('key'=>$secret)));
  $this->assertSame($secret,GWQSH_Enterprise_Config::secret('reputation','key'));
  $this->assertStringNotContainsString($secret,wp_json_encode(get_option('gwqsh_enterprise_credentials')));
  $this->assertIsArray(GWQSH_Enterprise_Config::save('reputation',array('key'=>'')));$this->assertSame($secret,GWQSH_Enterprise_Config::secret('reputation','key'));
  $this->assertIsArray(GWQSH_Enterprise_Config::save('reputation',array('_clear'=>array('key'))));$this->assertSame('',GWQSH_Enterprise_Config::secret('reputation','key'));
  $this->assertStringNotContainsString($secret,wp_json_encode(GWQSH_Customization::export()));
 }
 public function test_http_transport_rejects_ssrf_redirect_credentials_and_wrong_hosts(): void {
  foreach(array('http://hooks.slack.com/services/ABCDEF/ABCDEF/ABCDEFGHIJK','https://hooks.slack.com.evil.test/services/ABCDEF/ABCDEF/ABCDEFGHIJK','https://user:pass@hooks.slack.com/services/ABCDEF/ABCDEF/ABCDEFGHIJK','https://hooks.slack.com:444/services/ABCDEF/ABCDEF/ABCDEFGHIJK','https://127.0.0.1/services/ABCDEF/ABCDEF/ABCDEFGHIJK','https://hooks.slack.com/services/ABCDEF/ABCDEF/ABCDEFGHIJK?forward=http://localhost') as $url)$this->assertFalse(GWQSH_Secure_HTTP::allowed($url,'slack'));
  $this->assertTrue(GWQSH_Secure_HTTP::allowed('https://hooks.slack.com/services/ABCDEF/ABCDEF/ABCDEFGHIJK','slack'));
  $this->assertTrue(GWQSH_Secure_HTTP::allowed('https://http-intake.logs.datadoghq.com/api/v2/logs','collector'));
  $this->assertFalse(GWQSH_Secure_HTTP::allowed('https://localhost/api/v2/logs','collector'));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Secure_HTTP::request('collector','https://169.254.169.254/latest'));
 }
 public function test_atomic_counters_and_owned_lease_release(): void {
  $name='fixture-'.bin2hex(random_bytes(4));$this->assertSame(1,GWQSH_Enterprise_Store::hit($name,'a',60));$this->assertSame(2,GWQSH_Enterprise_Store::hit($name,'a',60));
  $lock=GWQSH_Enterprise_Store::lock($name);$this->assertIsString($lock);$this->assertFalse(GWQSH_Enterprise_Store::lock($name));
  $this->assertSame(0,GWQSH_Enterprise_Store::unlock($name,'wrong'));$this->assertFalse(GWQSH_Enterprise_Store::lock($name));GWQSH_Enterprise_Store::unlock($name,$lock);$this->assertIsString(GWQSH_Enterprise_Store::lock($name));
 }
 public function test_country_policy_ipv6_unknown_administrator_and_allowlist(): void {
  GWQSH_Settings::update_all(array('geo_enabled'=>true,'status'=>true));
  $this->assertIsArray(GWQSH_Enterprise_Config::save('geo',array('enabled'=>true,'countries'=>'US,IN','mode'=>'deny','unknown'=>'deny')));
  GWQSH_Enterprise_Store::put('geolocation','2001:4860:4860::8888',array('country'=>'United States','code'=>'US','lat'=>0,'lon'=>0));
  $this->assertSame('Country policy: US',GWQSH_Country_Access::decision('2001:4860:4860::8888'));
  $this->assertSame('Unknown country',GWQSH_Country_Access::decision('1.1.1.1'));
  $this->assertSame('',GWQSH_Country_Access::decision('1.1.1.1','login',wp_get_current_user()));
  GWQSH_Login_Protection::add_to_allowlist('2001:4860:4860::8888');$this->assertSame('',GWQSH_Country_Access::decision('2001:4860:4860::8888'));
  $this->assertIsArray(GWQSH_Enterprise_Config::save('geo',array('unknown'=>'allow')));$this->assertSame('',GWQSH_Country_Access::decision('1.1.1.1'));
 }
 public function test_cloudflare_requires_verified_unexpired_ranges(): void {
  GWQSH_Settings::update_all(array('proxy'=>true,'proxyheader'=>'cf','trusted_proxies'=>'173.245.48.0/20'));
  $_SERVER['REMOTE_ADDR']='173.245.48.1';$_SERVER['HTTP_CF_CONNECTING_IP']='2001:4860:4860::8888';delete_option('gwqsh_cloudflare_ranges');
  $this->assertSame('173.245.48.1',GWQSH_Settings::get_client_ip());
  update_option('gwqsh_cloudflare_ranges',array('checked_at'=>time(),'ranges'=>array('173.245.48.0/20')));$this->assertSame('2001:4860:4860::8888',GWQSH_Settings::get_client_ip());
  update_option('gwqsh_cloudflare_ranges',array('checked_at'=>time()-9*DAY_IN_SECONDS,'ranges'=>array('173.245.48.0/20')));$this->assertSame('173.245.48.1',GWQSH_Settings::get_client_ip());
  $_SERVER['REMOTE_ADDR']='198.51.100.1';$this->assertSame('198.51.100.1',GWQSH_Settings::get_client_ip());
 }
 public function test_reputation_adapter_validates_and_caches_without_manufacturing(): void {
  $this->assertFalse(GWQSH_Threat_Intelligence::available());$this->assertNull(GWQSH_Threat_Intelligence::lookup('8.8.8.8'));
  $provider=new class implements GWQSH_Reputation_Provider {public $calls=0;public function lookup($ip){++$this->calls;return array('score'=>95,'categories'=>array('scanner'));}};
  $filter=static function()use($provider){return $provider;};add_filter('gwqsh_reputation_provider',$filter);
  try{GWQSH_Enterprise_Config::save('reputation',array('enabled'=>true,'blocking'=>true));GWQSH_Threat_Intelligence::resolve('8.8.8.8');$this->assertSame(1,$provider->calls);$this->assertTrue(GWQSH_Threat_Intelligence::blocked('8.8.8.8'));GWQSH_Login_Protection::add_to_allowlist('8.8.8.8');$this->assertFalse(GWQSH_Threat_Intelligence::blocked('8.8.8.8'));$this->assertInstanceOf(WP_Error::class,GWQSH_Threat_Intelligence::validate(array('score'=>150,'categories'=>array('anything'))));}finally{remove_filter('gwqsh_reputation_provider',$filter);}
 }
 public function test_signed_feed_authentication_replay_expiry_and_analyzer_integration(): void {
  if(!function_exists('sodium_crypto_sign_keypair'))$this->markTestSkipped('Ed25519 unavailable.');
  delete_option('gwqsh_signature_database');$pair=sodium_crypto_sign_keypair();$pub=base64_encode(sodium_crypto_sign_publickey($pair));$key=sodium_crypto_sign_secretkey($pair);
  $data=array('schema'=>1,'version'=>1,'created_at'=>time(),'expires_at'=>time()+3600,'signatures'=>array(array('id'=>'test.hash','type'=>'sha256','value'=>hash('sha256','fixture'), 'score'=>95,'scopes'=>array('Plugin'))));$json=wp_json_encode($data);$sig=base64_encode(sodium_crypto_sign_detached($json,$key));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Signatures::accept($json,'',$pub));$this->assertInstanceOf(WP_Error::class,GWQSH_Signatures::accept($json.' ',$sig,$pub));$this->assertTrue(GWQSH_Signatures::accept($json,$sig,$pub));
  $this->assertSame(1,GWQSH_Signatures::version());$this->assertInstanceOf(WP_Error::class,GWQSH_Signatures::accept($json,$sig,$pub));
  $analysis=GWQSH_Malware_Analyzer::analyze('fixture','test.php','Plugin');$this->assertContains('signature:test.hash',$analysis['evidence']);$this->assertSame(95,$analysis['score']);
  $complex='<?php '.str_repeat('$v=1;',6000);$db=GWQSH_Signatures::database();$db['signatures'][0]['value']=hash('sha256',$complex);update_option('gwqsh_signature_database',$db,false);
  $partial=GWQSH_Malware_Analyzer::analyze($complex,'test.php','Plugin');$this->assertTrue($partial['analysis_partial']);$this->assertContains('signature:test.hash',$partial['signature_ids']);$this->assertSame(95,$partial['score']);
  $data['version']=2;$data['expires_at']=time()-1;$json=wp_json_encode($data);$this->assertInstanceOf(WP_Error::class,GWQSH_Signatures::accept($json,base64_encode(sodium_crypto_sign_detached($json,$key)),$pub));$this->assertSame(1,GWQSH_Signatures::version());
  $data['expires_at']=time()+3600;$data['signatures'][0]['type']='regex';$data['signatures'][0]['value']='(a+)+$';$json=wp_json_encode($data);$this->assertInstanceOf(WP_Error::class,GWQSH_Signatures::accept($json,base64_encode(sodium_crypto_sign_detached($json,$key)),$pub));$this->assertSame(1,GWQSH_Signatures::version());
 }
 public function test_additional_waf_rules_and_safe_default(): void {
  $s=GWQSH_Enterprise_Config::get('waf');$this->assertFalse($s['enforce_new']);
  $this->assertSame('GWQSH-1001',GWQSH_Firewall::advanced(array('file'=>'../../etc/passwd'),array(),array(),'/',$s));
  $this->assertSame('GWQSH-1002',GWQSH_Firewall::advanced(array('file'=>'php://filter/resource=wp-config.php'),array(),array(),'/',$s));
  $this->assertSame('GWQSH-1003',GWQSH_Firewall::advanced(array(),array(),array('upload'=>array('name'=>'attack.php.jpg')),'/upload',$s));
  $s['post']=true;$this->assertSame('',GWQSH_Firewall::advanced(array(),array('password'=>'<script>alert(1)</script>','comment'=>'ordinary content'),array(),'/',$s));
  $this->assertSame('GWQSH-1004',GWQSH_Firewall::advanced(array(),array('query'=>"' OR 1=1 --"),array(),'/',$s));
  $this->assertCount(5,GWQSH_Firewall::rules());
 }
 public function test_event_projection_dedup_queue_retry_and_no_secret_payload(): void {
  global $wpdb;GWQSH_Enterprise_Config::save('alerts',array('enabled'=>true,'slack'=>true,'minimum'=>'High'));
  $id=GWQSH_Activity_Logger::log('Security configuration changed','password=DO_NOT_SHIP secret=PRIVATE','Security','fixture','8.8.8.8');GWQSH_Activity_Logger::log('Security configuration changed','duplicate','Security','fixture','8.8.8.8');
  $rows=$wpdb->get_results("SELECT * FROM {$wpdb->prefix}gwqsh_delivery_queue WHERE channel='slack' AND payload LIKE '%8.8.8.8%'",ARRAY_A);$this->assertCount(1,$rows);$this->assertStringNotContainsString('DO_NOT_SHIP',$rows[0]['payload']);$this->assertStringNotContainsString('PRIVATE',$rows[0]['payload']);$this->assertStringNotContainsString('fixture',$rows[0]['payload']);
  GWQSH_Events::work();$row=$wpdb->get_row($wpdb->prepare("SELECT * FROM {$wpdb->prefix}gwqsh_delivery_queue WHERE id=%d",$rows[0]['id']),ARRAY_A);$this->assertSame('pending',$row['status']);$this->assertSame('1',$row['attempts']);$this->assertSame('inactive',$row['last_error']);
  $adapter=new class implements GWQSH_Delivery_Provider{public function deliver(array $event){return true;}};$filter=static function()use($adapter){return $adapter;};add_filter('gwqsh_delivery_provider',$filter,10,2);
  try{$wpdb->update($wpdb->prefix.'gwqsh_delivery_queue',array('available_at'=>time()),array('id'=>$row['id']));GWQSH_Events::work();$this->assertSame('delivered',$wpdb->get_var($wpdb->prepare("SELECT status FROM {$wpdb->prefix}gwqsh_delivery_queue WHERE id=%d",$row['id'])));}finally{remove_filter('gwqsh_delivery_provider',$filter,10);}
 }
 public function test_wordpress_privacy_export_erase_and_ipv6_masking(): void {
  $user=wp_get_current_user();GWQSH_Activity_Logger::log('Fixture privacy event','Private detail','User',$user->user_login,'2001:4860:4860::8888');$this->assertNotSame('2001:4860:4860::8888',GWQSH_Privacy::ip('2001:4860:4860::8888',true));
  $export=GWQSH_Privacy::export($user->user_email);$this->assertNotEmpty($export['data']);$removed=false;for($i=0;$i<100;$i++){$erase=GWQSH_Privacy::erase($user->user_email);$removed=$removed||$erase['items_removed'];if($erase['done'])break;}$this->assertTrue($removed);$this->assertTrue($erase['done']);$this->assertEmpty(GWQSH_Privacy::export($user->user_email)['data']);
 }
 public function test_application_passwords_cannot_bypass_enrolled_or_required_factor(): void {
  $user=wp_get_current_user();update_user_meta($user->ID,'gwqsh_2fa_required',1);$error=new WP_Error();GWQSH_Two_Factor::application_password_policy($error,$user,array(),'');$this->assertContains('gwqsh_app_password_restricted',$error->get_error_codes());
 }
 public function test_subscriber_cannot_execute_or_authorize_enterprise_changes(): void {
  $sub=get_users(array('role'=>'subscriber','number'=>1));if(!$sub)$this->markTestSkipped('No subscriber fixture available.');wp_set_current_user($sub[0]->ID);$this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_UI::authorize('invalid',''));$this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_UI::execute(array('operation'=>'save')));
 }
 public function test_mutation_proof_is_one_use_and_bound_to_account_and_session(): void {
  $u=wp_get_current_user();$token=GWQSH_Passkeys::issue(array('purpose'=>'enterprise-mutation','user_id'=>$u->ID,'session'=>hash('sha256',wp_get_session_token()),'fingerprint'=>hash('sha256',$u->user_pass)),120);
  $in=array('operation_token'=>$token,'operation'=>'save','section'=>'privacy','settings'=>'{"anonymize":true}');$this->assertIsArray(GWQSH_Enterprise_UI::execute($in));$this->assertInstanceOf(WP_Error::class,GWQSH_Enterprise_UI::execute($in));
 }
 public function test_license_mock_provider_and_outage_do_not_disable_protection(): void {
  GWQSH_Enterprise_Config::save('license',array('key'=>'fixture-license'));$adapter=new class implements GWQSH_License_Provider{public function activate($token,$site){return array('state'=>'active','expires_at'=>time()+3600);}public function deactivate($token,$site){return array('state'=>'inactive','expires_at'=>0);}public function refresh($token,$site){throw new RuntimeException('outage');}};$filter=static function()use($adapter){return $adapter;};add_filter('gwqsh_license_provider',$filter);
  try{$before=GWQSH_Settings::is_active();$result=GWQSH_License::operate('activate');$this->assertSame('active',$result['state']);$this->assertInstanceOf(WP_Error::class,GWQSH_License::operate('refresh'));$this->assertSame('active',GWQSH_License::status()['state']);$this->assertSame($before,GWQSH_Settings::is_active());}finally{remove_filter('gwqsh_license_provider',$filter);}$this->assertSame('unconfigured',GWQSH_License::status()['state']);
 }
 public function test_wizard_is_resumable_and_does_not_change_security_configuration(): void {
  $before=GWQSH_Login_Protection::get_settings();$this->assertSame(array('step'=>3,'completed'=>false),GWQSH_Setup_Wizard::save(array('step'=>3,'completed'=>false)));$this->assertSame($before,GWQSH_Login_Protection::get_settings());$this->assertSame(3,GWQSH_Setup_Wizard::state()['step']);$this->assertInstanceOf(WP_Error::class,GWQSH_Setup_Wizard::save(array('step'=>8,'completed'=>true)));
 }
 public function test_pending_enrollment_expires_without_changing_active_secret(): void {
  $id=get_current_user_id();$secret=GWQSH_Two_Factor::generate_secret();
  update_user_meta($id,'gwqsh_2fa_pending_secret',GWQSH_Crypto::encrypt($secret));update_user_meta($id,'gwqsh_2fa_pending_created',time());
  $this->assertSame($secret,GWQSH_Two_Factor::get_pending_secret($id));
  $active=get_user_meta($id,'gwqsh_2fa_secret',true);update_user_meta($id,'gwqsh_2fa_pending_created',time()-1801);
  $this->assertFalse(GWQSH_Two_Factor::get_pending_secret($id));$this->assertSame('',get_user_meta($id,'gwqsh_2fa_pending_secret',true));$this->assertSame($active,get_user_meta($id,'gwqsh_2fa_secret',true));
 }
 public function test_expired_recovery_cleanup_preserves_live_codes_and_factors(): void {
  $id=get_current_user_id();$active=get_user_meta($id,'gwqsh_2fa_secret',true);update_option('gwqsh_recovery_cleanup_cursor',0,false);
  update_user_meta($id,'gwqsh_recovery_setup_email',array('expires'=>time()-5,'used'=>false));
  update_user_meta($id,'gwqsh_recovery_login_sms',array('expires'=>time()+300,'used'=>false));
  GWQSH_Recovery::cleanup();$this->assertSame('',get_user_meta($id,'gwqsh_recovery_setup_email',true));$this->assertIsArray(get_user_meta($id,'gwqsh_recovery_login_sms',true));$this->assertSame($active,get_user_meta($id,'gwqsh_2fa_secret',true));
 }

 public function test_scan_lease_rejects_overlap_and_survives_wrong_owner_release(): void {
  $token=GWQSH_Enterprise_Store::lock('file-scan',300);$this->assertIsString($token);$this->assertTrue(GWQSH_Enterprise_Store::lease_active('file-scan'));
  $this->assertInstanceOf(WP_Error::class,GWQSH_Scan_Engine::run());GWQSH_Enterprise_Store::unlock('file-scan','not-owner');$this->assertTrue(GWQSH_Enterprise_Store::lease_active('file-scan'));GWQSH_Enterprise_Store::unlock('file-scan',$token);$this->assertFalse(GWQSH_Enterprise_Store::lease_active('file-scan'));
 }

}
