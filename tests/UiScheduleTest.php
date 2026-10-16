<?php
// Development-only integration coverage; never included in release builds.
use PHPUnit\Framework\TestCase;
final class UiScheduleTest extends TestCase {
 protected function setUp(): void { global $wpdb; $wpdb->query('START TRANSACTION'); }
 protected function tearDown(): void { global $wpdb; $wpdb->query('ROLLBACK'); wp_cache_flush(); }
 public function test_invalid_time_is_rejected_without_changing_saved_schedule(): void {
  $before=GWQSH_Scheduler::settings();
  $result=GWQSH_Scheduler::save(array_merge($before,array('time'=>'25:61')));
  $this->assertInstanceOf(WP_Error::class,$result);
  $this->assertSame($before,GWQSH_Scheduler::settings());
 }
 public function test_failed_cron_replacement_restores_saved_configuration_and_old_event(): void {
  $old=array('enabled'=>true,'frequency'=>'hourly','time'=>'02:15','type'=>'quick','scopes'=>array('Core'));
  $this->assertTrue(GWQSH_Scheduler::save($old));
  $event=wp_get_scheduled_event(GWQSH_Scheduler::HOOK);$saved=GWQSH_Scheduler::settings();
  $reject=static function($pre,$event){ return GWQSH_Scheduler::HOOK===$event->hook && 'daily'===$event->schedule ? new WP_Error('fixture_failure','Cron rejected the change.') : $pre; };
  add_filter('pre_schedule_event',$reject,10,2);
  try { $this->assertInstanceOf(WP_Error::class,GWQSH_Scheduler::save(array_merge($saved,array('frequency'=>'daily')))); }
  finally { remove_filter('pre_schedule_event',$reject,10); }
  $this->assertSame($saved,GWQSH_Scheduler::settings());
  $this->assertEquals($event,wp_get_scheduled_event(GWQSH_Scheduler::HOOK));
 }
 public function test_next_scan_uses_site_timezone_and_repeated_save_keeps_one_event(): void {
  update_option('timezone_string','Asia/Kolkata');
  $input=array('enabled'=>true,'frequency'=>'gwqsh_weekly','time'=>'03:17','type'=>'quick','scopes'=>array('Core'));
  $this->assertTrue(GWQSH_Scheduler::save($input));
  $next=wp_next_scheduled(GWQSH_Scheduler::HOOK);
  $this->assertSame('03:17',wp_date('H:i',$next,wp_timezone()));
  $this->assertTrue(GWQSH_Scheduler::save($input));
  $this->assertSame($next,wp_next_scheduled(GWQSH_Scheduler::HOOK));
  $count=0;foreach(_get_cron_array() as $hooks){$count+=count($hooks[GWQSH_Scheduler::HOOK]??array());}
  $this->assertSame(1,$count);
 }
}
