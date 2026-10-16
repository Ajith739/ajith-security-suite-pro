<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
use PHPUnit\Framework\TestCase;

final class RestoreTest extends TestCase {
    public function test_restore_rejects_bad_download_and_writes_only_checksum_verified_content() {
        global $wpdb, $wp_version;
        $relative='gwqsh-restore-fixture-'.bin2hex(random_bytes(6)).'.txt';
        $file=ABSPATH.$relative; $official="Verified development fixture\n";
        $body='tampered download';
        $cache_key='gwqsh_checksums_'.md5($wp_version.'|'.get_locale());
        $cache=get_transient($cache_key);
        $metadata=get_option('gwqsh_quarantine_metadata',array());
        $mock=static function($pre,$args,$url) use($relative,&$body) {
            return false!==strpos($url,'/'.$relative) ? array('headers'=>array(),'body'=>$body,'response'=>array('code'=>200,'message'=>'OK')) : $pre;
        };
        $id=0;
        try {
            file_put_contents($file,'Modified fixture');
            set_transient($cache_key,array($relative=>md5($official)),60);
            $wpdb->insert($wpdb->prefix.'gwqsh_scan_results',array('file_path'=>'/'.$relative,'file_type'=>'Core','status'=>'Modified','details'=>'Development fixture','detected_at'=>current_time('mysql'),'is_resolved'=>0));
            $id=$wpdb->insert_id;
            add_filter('pre_http_request',$mock,10,3);
            $result=GWQSH_File_Integrity::restore_core_file($relative);
            $this->assertInstanceOf(WP_Error::class,$result);
            $this->assertSame('checksum_mismatch',$result->get_error_code());
            $this->assertSame('Modified fixture',file_get_contents($file));
            $body=$official;
            $this->assertTrue(GWQSH_File_Integrity::restore_core_file($relative));
            $this->assertSame($official,file_get_contents($file));
            $this->assertSame('1',$wpdb->get_var($wpdb->prepare('SELECT is_resolved FROM '.$wpdb->prefix.'gwqsh_scan_results WHERE id=%d',$id)));
        } finally {
            remove_filter('pre_http_request',$mock,10);
            wp_delete_file($file);
            if($id) $wpdb->delete($wpdb->prefix.'gwqsh_scan_results',array('id'=>$id));
            $after=get_option('gwqsh_quarantine_metadata',array());
            $dir=trailingslashit(get_temp_dir()).'gwqsh-quarantine-'.substr(hash_hmac('sha256',home_url(),wp_salt('auth')),0,20);
            foreach(array_diff_key($after,$metadata) as $name=>$record) {
                if(preg_match('/^[a-f0-9]{32}\.quarantine$/D',$name)) wp_delete_file(trailingslashit($dir).$name);
            }
            update_option('gwqsh_quarantine_metadata',$metadata);
            false===$cache ? delete_transient($cache_key) : set_transient($cache_key,$cache,WEEK_IN_SECONDS);
        }
    }
}
