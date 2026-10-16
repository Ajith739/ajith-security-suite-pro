<?php
/** Query firewall regression tests. @package GracewellSecuritySuitePro */
class FirewallPageTest extends PHPUnit\Framework\TestCase {
 public function test_correlated_query_signatures_and_benign_inputs() {
  $settings=array('sql'=>true,'xss'=>true,'bots'=>true);
  $this->assertSame('SQL Injection',GWQSH_Firewall::match(array('q'=>"' OR 1=1 --"),'Mozilla/5.0','/',$settings));
  $this->assertSame('SQL Injection',GWQSH_Firewall::match(array('q'=>'UNION SELECT NULL, NULL'),'Mozilla/5.0','/',$settings));
  $this->assertSame('XSS Attempt',GWQSH_Firewall::match(array('q'=>'<svg onload=alert(1)>'),'Mozilla/5.0','/',$settings));
  $this->assertSame('XSS Attempt',GWQSH_Firewall::match(array('q'=>'%3Cscript%3Ealert(1)'),'Mozilla/5.0','/',$settings));
  foreach(array('SELECT a theme','UNION membership','<p>normal HTML</p>','1 < 2','javascript documentation') as $query){$this->assertSame('',GWQSH_Firewall::match(array('q'=>$query),'Mozilla/5.0','/',$settings));}
 }
 public function test_bot_agent_requires_sensitive_path_and_search_engines_are_preserved() {
  $settings=array('sql'=>true,'xss'=>true,'bots'=>true);
  $this->assertSame('Bad Bot',GWQSH_Firewall::match(array(),'sqlmap/1','/.env',$settings));
  $this->assertSame('',GWQSH_Firewall::match(array(),'sqlmap/1','/news/',$settings));
  $this->assertSame('',GWQSH_Firewall::match(array(),'Googlebot','/.env',$settings));
  $this->assertSame('',GWQSH_Firewall::match(array(),'Mozilla/5.0','/.env',$settings));
 }
 public function test_disabled_rules_and_bounded_input() {
  $settings=array('sql'=>false,'xss'=>false,'bots'=>false);
  $this->assertSame('',GWQSH_Firewall::match(array('q'=>"' OR 1=1 -- <script>"),'sqlmap','/.env',$settings));
  $settings['sql']=true;
  $this->assertSame('',GWQSH_Firewall::match(array('q'=>str_repeat('a',50000)."' OR 1=1 --"),'Mozilla/5.0','/',$settings));
 }
 public function test_validation_rejects_ambiguous_states_without_mutation() {
  $before=get_option('gwqsh_firewall',null);
  $this->assertWPError(GWQSH_Firewall::save(array('enabled'=>'yes','sql'=>'1','xss'=>'1','bots'=>'1','login'=>'1')));
  $this->assertSame($before,get_option('gwqsh_firewall',null));
  $this->assertWPError(GWQSH_Firewall::save(array('enabled'=>array('1'),'sql'=>'1','xss'=>'1','bots'=>'1','login'=>'1')));
  $this->assertSame($before,get_option('gwqsh_firewall',null));
 }
 private function assertWPError($result){$this->assertInstanceOf(WP_Error::class,$result);}
 public function test_data_matches_shared_summary_and_filters_wrong_password_events() {
  $data=GWQSH_Firewall::data();$summary=GWQSH_File_Integrity::get_summary();
  $this->assertSame($summary,$data['summary']);
  foreach($data['events'] as $event){$this->assertNotSame('Login attempt blocked',$event['event_name']);$this->assertArrayNotHasKey('details',$event);}
  $this->assertSame('', $GLOBALS['wpdb']->last_error);
  $this->assertIsInt($data['blocked']);$this->assertIsInt($data['month']);
 }
}
