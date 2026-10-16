<?php
// phpcs:ignoreFile -- Development integration tests, excluded from production.
use PHPUnit\Framework\TestCase;

final class ScanStateTest extends TestCase {
    public function test_slow_consumer_does_not_truncate_directory_enumeration() {
        $root = get_temp_dir() . 'gwqsh-enumeration-' . bin2hex(random_bytes(6));
        mkdir($root);
        file_put_contents($root . '/first.txt', 'first');
        file_put_contents($root . '/second.txt', 'second');
        try {
            $errors = array();
            $files = array();
            foreach (GWQSH_Scan_Engine::files($root, $errors) as $file) {
                $files[] = $file;
                if (count($files) === 1) { usleep(3200000); }
            }
            $this->assertCount(2, $files);
            $this->assertSame(array(), $errors);
        } finally {
            unlink($root . '/first.txt');
            unlink($root . '/second.txt');
            rmdir($root);
        }
    }
    public function test_dependency_and_test_directories_are_excluded_from_plugin_enumeration() {
        $errors = array();
        $files = iterator_to_array(GWQSH_Scan_Engine::files(GWQSH_PATH, $errors));
        $this->assertNotEmpty($files);
        $this->assertSame(array(), $errors);
        $prefix = rtrim(wp_normalize_path(GWQSH_PATH), '/') . '/';
        foreach ($files as $file) {
            $relative = substr(wp_normalize_path($file), strlen($prefix));
            $this->assertDoesNotMatchRegularExpression('#^(vendor|tests|bin|docs)/#', $relative);
        }
    }

    public function test_chunked_state_exceeds_database_packet_without_losing_data() {
        $key='gwqsh_test_chunk_'.bin2hex(random_bytes(6));$value=array('data'=>base64_encode(random_bytes(1800000)));
        try {
            GWQSH_Scan_Engine::save($key,$value);$pointer=get_option($key);$this->assertGreaterThan(1,$pointer['chunks']);$this->assertSame($value,GWQSH_Scan_Engine::load($key));
            GWQSH_Scan_Engine::save($key,array('data'=>'changed'));$this->assertSame(array('data'=>'changed'),GWQSH_Scan_Engine::load($key));
            $this->assertFalse(get_option($key.'_'.$pointer['generation'].'_0'));
            GWQSH_Scan_Engine::clear($key);$this->assertFalse(get_option($key));
            update_option($key,array('chunks'=>999999,'generation'=>'../../bad'));$this->assertSame(array(),GWQSH_Scan_Engine::load($key));
        }finally{GWQSH_Scan_Engine::clear($key);}
    }
    public function test_baseline_requires_recent_complete_noncritical_inspection() {
        global $wpdb; $wpdb->query('START TRANSACTION');
        $file=ABSPATH.'gwqsh-baseline-'.bin2hex(random_bytes(6)).'.txt'; file_put_contents($file,'safe data');
        $label=GWQSH_Scan_Engine::label($file);$record=array('hash'=>hash_file('sha256',$file),'size'=>filesize($file),'mtime'=>filemtime($file),'scope'=>'Core');
        try {
            GWQSH_Scan_Engine::clear('gwqsh_scan_progress');
            $candidate=array('manifest'=>array($label=>$record),'critical'=>1,'errors'=>array(),'time'=>time());
            GWQSH_Scan_Engine::save('gwqsh_scan_candidate',$candidate);$this->assertInstanceOf(WP_Error::class,GWQSH_Scan_Engine::trust_baseline());
            $candidate['critical']=0;$candidate['errors']=array('unreadable_file');GWQSH_Scan_Engine::save('gwqsh_scan_candidate',$candidate);$this->assertInstanceOf(WP_Error::class,GWQSH_Scan_Engine::trust_baseline());
            $candidate['errors']=array();GWQSH_Scan_Engine::save('gwqsh_scan_candidate',$candidate);$this->assertTrue(GWQSH_Scan_Engine::trust_baseline());$this->assertSame($record,GWQSH_Scan_Engine::load('gwqsh_file_baseline')[$label]);
            file_put_contents($file,'changed data');$this->assertInstanceOf(WP_Error::class,GWQSH_Scan_Engine::trust_baseline());
        }finally{unlink($file);$wpdb->query('ROLLBACK');wp_cache_flush();}
    }
    public function test_full_scan_covers_mu_nested_root_uploads_and_changed_new_baseline() {
        global $wpdb,$wp_version;$wpdb->query('START TRANSACTION');
        $id=bin2hex(random_bytes(6));$mu=GWQSH_Guardian::root().'/gwqsh-test-'.$id;mkdir($mu);
        $root=ABSPATH.'gwqsh-test-'.$id.'.php';$uploads=wp_upload_dir();$image=$uploads['basedir'].'/gwqsh-test-'.$id.'.jpg';
        $nested=$mu.'/renamed.php';file_put_contents($nested,file_get_contents(__DIR__.'/fixtures/bot-gate.fixture'));file_put_contents($root,file_get_contents(__DIR__.'/fixtures/webshell.fixture'));file_put_contents($image,file_get_contents(__DIR__.'/fixtures/image.fixture'));
        $cache_key='gwqsh_checksums_'.md5($wp_version.'|'.get_locale());$old=get_transient($cache_key);
        try {
            GWQSH_Scan_Engine::clear('gwqsh_scan_progress');GWQSH_Scan_Engine::clear('gwqsh_analysis_cache');
            $baseline=array(GWQSH_Scan_Engine::label($root)=>array('hash'=>hash('sha256','old'),'scope'=>'Core'));
            $deleted='/gwqsh-deleted-'.$id.'.php';$baseline[$deleted]=array('hash'=>hash('sha256','expected'),'scope'=>'Core');
            GWQSH_Scan_Engine::save('gwqsh_file_baseline',$baseline);set_transient($cache_key,array(basename($root)=>md5('original')),60);
            do{$scan=GWQSH_File_Integrity::run_full_scan();$this->assertIsArray($scan);}while($scan['pending']);
            foreach(array($root,$nested,$image) as $file){$path=GWQSH_Scan_Engine::label($file);$issues=GWQSH_File_Integrity::get_scan_issues(array('search'=>$path));$found=array_values(array_filter($issues,static function($r)use($path){return $r['path']===$path;}));$this->assertCount(1,$found,$path);$this->assertSame('Suspicious',$found[0]['st']);}
            $deleted_rows=GWQSH_File_Integrity::get_scan_issues(array('search'=>$deleted));$this->assertCount(1,$deleted_rows);$this->assertSame('Missing',$deleted_rows[0]['st']);
            $table=$wpdb->prefix.'gwqsh_scan_results';$evidence=json_decode($wpdb->get_var($wpdb->prepare("SELECT evidence FROM {$table} WHERE file_path=%s ORDER BY id DESC LIMIT 1",GWQSH_Scan_Engine::label($root))),true);$this->assertSame('changed',$evidence['baseline_state']);$this->assertSame('Critical',$evidence['severity']);$this->assertContains('core_checksum_mismatch',$evidence['evidence']);
            $evidence=json_decode($wpdb->get_var($wpdb->prepare("SELECT evidence FROM {$table} WHERE file_path=%s ORDER BY id DESC LIMIT 1",GWQSH_Scan_Engine::label($nested))),true);$this->assertSame('new',$evidence['baseline_state']);$this->assertSame('mu_plugin',$evidence['component']);
            $this->assertIsString(GWQSH_File_Integrity::get_file_diff(GWQSH_Scan_Engine::label($nested)));
            $this->assertStringContainsString('SHA-256',GWQSH_File_Integrity::get_file_diff(GWQSH_Scan_Engine::label($nested)));
            $this->assertStringContainsString('View complete current source',GWQSH_File_Integrity::get_file_diff(GWQSH_Scan_Engine::label($nested)));
            $this->assertStringNotContainsString('<script>',GWQSH_File_Integrity::get_file_diff(GWQSH_Scan_Engine::label($nested)));
            $this->assertInstanceOf(WP_Error::class,GWQSH_Scan_Engine::trust_baseline());
        }finally{foreach(array($nested,$root,$image) as $f)if(is_file($f))unlink($f);rmdir($mu);$wpdb->query('ROLLBACK');wp_cache_flush();false===$old?delete_transient($cache_key):set_transient($cache_key,$old,WEEK_IN_SECONDS);}
    }
    public function test_unavailable_checksums_do_not_disable_local_inspection() {
        global $wpdb,$wp_version;$wpdb->query('START TRANSACTION');$key='gwqsh_checksums_'.md5($wp_version.'|'.get_locale());$old=get_transient($key);
        $mock=static function($pre,$args,$url){return false!==strpos($url,'api.wordpress.org/core/checksums/')?new WP_Error('offline','Fixture offline'):$pre;};add_filter('pre_http_request',$mock,10,3);
        // The separate full-tree regression covers enumeration; this case isolates offline core inspection.
        $roots = static function() { return array(ABSPATH . 'wp-includes'); };
        add_filter('gwqsh_scan_enumeration_roots', $roots);
        try{GWQSH_Scan_Engine::clear('gwqsh_scan_progress');delete_transient($key);do{$scan=GWQSH_File_Integrity::run_full_scan();$this->assertIsArray($scan);}while($scan['pending']);$this->assertGreaterThan(100,$scan['total']);$this->assertContains('checksums_unavailable',$scan['coverage']);}
        finally{remove_filter('gwqsh_scan_enumeration_roots',$roots);remove_filter('pre_http_request',$mock,10);$wpdb->query('ROLLBACK');wp_cache_flush();false===$old?delete_transient($key):set_transient($key,$old,WEEK_IN_SECONDS);}
    }
}
