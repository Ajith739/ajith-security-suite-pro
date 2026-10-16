<?php
// Development-only transactional integration tests; excluded from releases.
use PHPUnit\Framework\TestCase;
final class UpgradeServicesTest extends TestCase {
 private $server; private $viewer;
 protected function setUp(): void { global $wpdb; $this->server=$_SERVER;$this->viewer=get_current_user_id();$wpdb->query('START TRANSACTION');$_SERVER['REMOTE_ADDR']='127.0.0.1';$admins=get_users(array('role'=>'administrator','number'=>1));wp_set_current_user($admins[0]->ID); }
 protected function tearDown(): void { global $wpdb;$wpdb->query('ROLLBACK');wp_cache_flush();$_SERVER=$this->server;wp_set_current_user($this->viewer); }
 public function test_trusted_cidrs_header_selection_and_spoofing(): void {
  $this->assertTrue(GWQSH_Network::matches('2001:db8::12','2001:db8::/32'));
  $this->assertFalse(GWQSH_Network::matches('2001:db9::12','2001:db8::/32'));
  $this->assertFalse(GWQSH_Network::matches('192.0.2.2','192.0.2.0/33'));
  GWQSH_Settings::update_all(array('proxy'=>true,'proxyheader'=>'xff','trusted_proxies'=>'10.0.0.0/24'));
  $_SERVER['REMOTE_ADDR']='10.0.0.9';$_SERVER['HTTP_X_FORWARDED_FOR']='1.2.3.4, 198.51.100.42, 10.0.0.8';
  $this->assertSame('198.51.100.42',GWQSH_Settings::get_client_ip());
  $_SERVER['REMOTE_ADDR']='198.51.100.99';$this->assertSame('198.51.100.99',GWQSH_Settings::get_client_ip());
  $_SERVER['REMOTE_ADDR']='10.0.0.9';GWQSH_Settings::update_all(array('proxyheader'=>'cf'));unset($_SERVER['HTTP_CF_CONNECTING_IP']);
  $this->assertSame('10.0.0.9',GWQSH_Settings::get_client_ip());
  $_SERVER['HTTP_CF_CONNECTING_IP']=array('1.2.3.4');$this->assertSame('10.0.0.9',GWQSH_Settings::get_client_ip());
  GWQSH_Settings::update_all(array('proxyheader'=>'trueclient'));$_SERVER['HTTP_TRUE_CLIENT_IP']='2001:db8::12';$this->assertSame('2001:db8::12',GWQSH_Settings::get_client_ip());
 }
 public function test_site_time_and_private_geography_do_not_use_browser_timezone(): void {
  update_option('timezone_string','Asia/Kolkata');
  $this->assertSame('Oct 14, 2026, 1:15 PM',GWQSH_Time::format('2026-10-14 13:15:00'));
  $this->assertSame('Oct 14, 2026, 1:15 PM',GWQSH_Time::format(strtotime('2026-10-14 07:45:00 UTC')));
  $this->assertSame('Localhost',GWQSH_Network::country('::1')['country']);
  $this->assertSame('Local Network',GWQSH_Network::country('10.1.2.3')['country']);
  $this->assertSame('Local Network',GWQSH_Network::country('fd00::12')['country']);
 }
 public function test_manual_blocks_expiry_history_and_self_protection(): void {
  GWQSH_Settings::update_all(array('status'=>true,'proxy'=>false));
  $this->assertInstanceOf(WP_Error::class,GWQSH_IP_Blocks::save('127.0.0.1','self',60));
  $this->assertTrue(GWQSH_IP_Blocks::save('2001:db8::cafe','Temporary test',60));
  $this->assertNotFalse(GWQSH_IP_Blocks::blocked('2001:0db8:0000:0000:0000:0000:0000:cafe'));
  $this->assertTrue(GWQSH_IP_Blocks::remove('2001:db8::cafe'));
  $this->assertFalse(GWQSH_IP_Blocks::blocked('2001:db8::cafe'));
  $this->assertSame('Unblocked',GWQSH_IP_Blocks::history()['items'][0]['status']);
  $this->assertTrue(GWQSH_IP_Blocks::save('198.51.100.17','Permanent test',0));
  $this->assertSame('Permanent',GWQSH_IP_Blocks::history()['items'][0]['expires']);
 }
 public function test_schedules_reschedule_without_duplicates_and_disable(): void {
  $input=array('enabled'=>true,'frequency'=>'hourly','type'=>'quick','scopes'=>array('Core'));
  $this->assertTrue(GWQSH_Scheduler::save($input));$first=wp_next_scheduled(GWQSH_Scheduler::HOOK);
  $this->assertTrue(GWQSH_Scheduler::save($input));$this->assertSame($first,wp_next_scheduled(GWQSH_Scheduler::HOOK));
  $input['frequency']='gwqsh_weekly';$this->assertTrue(GWQSH_Scheduler::save($input));
  $event=wp_get_scheduled_event(GWQSH_Scheduler::HOOK);$this->assertSame(WEEK_IN_SECONDS,$event->interval);
  $input['enabled']=false;$this->assertTrue(GWQSH_Scheduler::save($input));$this->assertFalse(wp_next_scheduled(GWQSH_Scheduler::HOOK));
  $input['scopes']=array('invalid');$this->assertInstanceOf(WP_Error::class,GWQSH_Scheduler::save($input));
 }
 public function test_email_recovery_delivery_hash_cooldown_binding_and_one_use(): void {
  GWQSH_Recovery::save_settings(array('email'=>true));$id=get_current_user_id();delete_user_meta($id,'gwqsh_2fa_attempts');delete_user_meta($id,'gwqsh_recovery_setup');$code='';
  $mail=function($pre,$args)use(&$code){preg_match('/code is ([0-9]{6})/',$args['message'],$m);$code=$m[1];return true;};add_filter('pre_wp_mail',$mail,10,2);
  try {
   $sent=GWQSH_Recovery::send($id,'email','upgrade@example.test','setup','binding');$this->assertIsArray($sent);
   $this->assertStringNotContainsString($code,wp_json_encode(get_user_meta($id,'gwqsh_recovery_setup_email',true)));
   $this->assertInstanceOf(WP_Error::class,GWQSH_Recovery::send($id,'email','upgrade@example.test','setup','binding'));
   $this->assertFalse(GWQSH_Recovery::verify($id,$code,'setup','wrong'));
   $this->assertIsArray(GWQSH_Recovery::verify($id,$code,'setup','binding'));
   $this->assertFalse(GWQSH_Recovery::verify($id,$code,'setup','binding'));
  }finally{remove_filter('pre_wp_mail',$mail,10);}
 }
 public function test_sms_adapter_and_secrets_excluded_from_export(): void {
  $id=get_current_user_id();delete_user_meta($id,'gwqsh_2fa_attempts');delete_user_meta($id,'gwqsh_recovery_setup');
  $secret=bin2hex(random_bytes(16));GWQSH_Recovery::save_settings(array('sms'=>true,'sms_provider'=>'test_provider','twilio_token'=>$secret));
  $received=array();$providers=function($all)use(&$received){$all['test_provider']=function($phone,$message)use(&$received){$received=array($phone,$message);return true;};return $all;};add_filter('gwqsh_sms_providers',$providers);
  try{$this->assertIsArray(GWQSH_Recovery::send($id,'sms','+919876543210','setup','binding'));$this->assertSame('+919876543210',$received[0]);$this->assertStringNotContainsString($secret,wp_json_encode(GWQSH_Customization::export()));$this->assertNotSame($secret,GWQSH_Recovery::settings()['twilio_token']);}
  finally{remove_filter('gwqsh_sms_providers',$providers);}
 }
 public function test_challenges_are_atomic_single_use_and_ip_bound(): void {
  $token=GWQSH_Passkeys::issue(array('purpose'=>'test','user_id'=>get_current_user_id()));
  $this->assertSame(get_current_user_id(),GWQSH_Passkeys::consume($token,'test')['user_id']);
  $this->expectException(RuntimeException::class);GWQSH_Passkeys::consume($token,'test');
 }
 public function test_invalid_import_is_validated_before_writes(): void {
  $before=GWQSH_Settings::get('theme');$payload=GWQSH_Customization::export();$payload['sections']['appearance']['theme']='dark';$payload['sections']['scan_schedule']['frequency']='invalid';
  $this->assertInstanceOf(WP_Error::class,GWQSH_Customization::import($payload));$this->assertSame($before,GWQSH_Settings::get('theme'));
 }
 public function test_password_issued_challenge_accepts_verified_email_backup_once(): void {
  $post=$_POST;$globals=array($GLOBALS['gwqsh_2fa_challenge']??null,$GLOBALS['gwqsh_2fa_prompt']??null);
  $password=wp_generate_password(24);$username='gwqsh_factor_'.bin2hex(random_bytes(6));$id=wp_create_user($username,$password,$username.'@example.test');
  $this->assertIsInt($id);GWQSH_Settings::update_all(array('status'=>true,'proxy'=>false));$_SERVER['REMOTE_ADDR']='198.51.100.240';
  GWQSH_Two_Factor::enable_user_2fa($id,GWQSH_Two_Factor::generate_secret());GWQSH_Recovery::save_settings(array('email'=>true));update_user_meta($id,'gwqsh_recovery_email_verified',$username.'@example.test');
  $code='';$mail=function($pre,$args)use(&$code){if(preg_match('/code is ([0-9]{6})/',$args['message'],$m))$code=$m[1];return true;};add_filter('pre_wp_mail',$mail,10,2);
  try {
   unset($GLOBALS['gwqsh_2fa_challenge'],$GLOBALS['gwqsh_2fa_prompt']);$_POST=array();$first=wp_authenticate($username,$password);$this->assertInstanceOf(WP_Error::class,$first);$this->assertContains('gwqsh_2fa_required',$first->get_error_codes());
   $token=$GLOBALS['gwqsh_2fa_challenge'];$this->assertIsArray(GWQSH_Recovery::send($id,'email',$username.'@example.test','login',hash('sha256',$token)));
   $_POST=array('gwqsh_2fa_challenge'=>$token,'gwqsh_2fa_code'=>$code);$verified=wp_authenticate($username,'');$this->assertInstanceOf(WP_User::class,$verified);$this->assertSame($id,$verified->ID);
   $this->assertInstanceOf(WP_Error::class,wp_authenticate($username,''));
  }finally{remove_filter('pre_wp_mail',$mail,10);$_POST=$post;foreach(array('gwqsh_2fa_challenge','gwqsh_2fa_prompt') as $i=>$key){if(null===$globals[$i])unset($GLOBALS[$key]);else$GLOBALS[$key]=$globals[$i];}clean_user_cache($id);}
 }
 public function test_real_public_country_lookup_is_cached_and_private_addresses_never_fetch(): void {
  GWQSH_Settings::update_all(array('geo_enabled'=>true));delete_transient('gwqsh_geo_'.md5('8.8.8.8'));$calls=0;
  $http=function($pre,$args,$url)use(&$calls){if(strpos($url,'https://ipwho.is/')===0){++$calls;return array('response'=>array('code'=>200),'body'=>wp_json_encode(array('success'=>true,'country'=>'United States','country_code'=>'US','latitude'=>37.4,'longitude'=>-122.1)),'headers'=>array());}return $pre;};add_filter('pre_http_request',$http,10,3);
  try{$this->assertSame('Lookup pending',GWQSH_Network::country('8.8.8.8')['country']);$this->assertSame(0,$calls);GWQSH_Network::resolve('8.8.8.8');$this->assertSame('US',GWQSH_Network::country('8.8.8.8')['code']);$this->assertSame(1,$calls);GWQSH_Network::country('127.0.0.1');GWQSH_Network::resolve('127.0.0.1');$this->assertSame(1,$calls);}finally{remove_filter('pre_http_request',$http,10);}
 }
 public function test_resumable_enumeration_preserves_cursor_and_limits_scope(): void {
  $folder=WP_PLUGIN_DIR.'/gwqsh_enum_'.bin2hex(random_bytes(6));mkdir($folder);file_put_contents($folder.'/one.php','<?php return;');file_put_contents($folder.'/two.txt','safe');
  $state=array('enumeration'=>array('queue'=>array(array('dir'=>$folder,'root'=>$folder,'depth'=>0,'offset'=>0)),'entries'=>0,'done'=>false),'files'=>array(),'errors'=>array(),'options'=>array('type'=>'quick','scopes'=>array('Plugin')));
  $method=new ReflectionMethod(GWQSH_Scan_Engine::class,'enumerate_batch');$method->setAccessible(true);
  try{$args=array(&$state,microtime(true)-1);$method->invokeArgs(null,$args);$this->assertFalse($state['enumeration']['done']);$this->assertSame(0,$state['enumeration']['entries']);$args=array(&$state,microtime(true)+2);$method->invokeArgs(null,$args);$this->assertTrue($state['enumeration']['done']);$this->assertCount(1,$state['files']);$this->assertStringEndsWith('one.php',array_keys($state['files'])[0]);}
  finally{unlink($folder.'/one.php');unlink($folder.'/two.txt');rmdir($folder);}
 }
 public function test_manual_restriction_is_not_overridden_by_core_authentication(): void {
  $password=wp_generate_password(24);$username='gwqsh_block_'.bin2hex(random_bytes(6));$id=wp_create_user($username,$password,$username.'@example.test');
  GWQSH_Settings::update_all(array('status'=>true,'proxy'=>false));$this->assertTrue(GWQSH_IP_Blocks::save('198.51.100.239','Native auth regression',0));$_SERVER['REMOTE_ADDR']='198.51.100.239';
  try{$result=wp_authenticate($username,$password);$this->assertInstanceOf(WP_Error::class,$result);$this->assertContains('gwqsh_manual_block',$result->get_error_codes());}finally{clean_user_cache($id);}
 }
}
