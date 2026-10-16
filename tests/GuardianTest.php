<?php
// phpcs:ignoreFile -- Development-only sanitized integration tests.
use PHPUnit\Framework\TestCase;

final class GuardianTest extends TestCase {
    private function process($code) {
        $pipes=array(); $proc=proc_open(array(PHP_BINARY,'-d','display_errors=1','-r',$code),array(1=>array('pipe','w'),2=>array('pipe','w')),$pipes);
        $out=stream_get_contents($pipes[1]); $err=stream_get_contents($pipes[2]); fclose($pipes[1]);fclose($pipes[2]);
        $this->assertSame(0,proc_close($proc),$err.$out); $this->assertSame('',$err); return $out;
    }
    private function removeTree($root) {
        foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root,FilesystemIterator::SKIP_DOTS),RecursiveIteratorIterator::CHILD_FIRST) as $f) {
            if($f->isDir()&&!$f->isLink()) rmdir($f->getPathname()); else unlink($f->getPathname());
        } rmdir($root);
    }
    public static function malicious(){return array(array('bot-gate'),array('self-heal-index'),array('self-heal-htaccess'),array('webshell'),array('downloader'),array('obfuscated'));}
    /** @dataProvider malicious */
    public function test_standalone_guardian_handles_precomputed_load_list($fixture) {
        $root=realpath(sys_get_temp_dir()).'/gwqsh-guardian-test-'.bin2hex(random_bytes(6));mkdir($root);mkdir($root.'/mu');
        $state=$root.'/state'; GWQSH_Security_Runtime::protect($state);
        $guardian=$root.'/mu/'.GWQSH_Guardian::NAME;file_put_contents($guardian,GWQSH_Guardian::source($state));
        $file=$root.'/mu/z-renamed.php'; $body=file_get_contents(__DIR__.'/fixtures/'.$fixture.'.fixture');file_put_contents($file,$body);
        file_put_contents($state.'/mu-baseline.json','{broken state');
        try {
            $code='define("ABSPATH",'.var_export($root.'/',true).'); define("WPMU_PLUGIN_DIR",'.var_export($root.'/mu',true).');$files=glob(WPMU_PLUGIN_DIR."/*.php");sort($files);foreach($files as $f)include $f;echo json_encode(array("executed"=>!empty($GLOBALS["gwqsh_fixture_executed"]),"continued"=>true));';
            $result=json_decode($this->process($code),true);$this->assertFalse($result['executed']);$this->assertTrue($result['continued']);
            $this->assertStringContainsString('Gracewell-blocked',file_get_contents($file));
            $artifacts=glob($state.'/*.quarantine');$this->assertCount(1,$artifacts);$this->assertSame(hash('sha256',$body),hash_file('sha256',$artifacts[0]));
            $records=glob($state.'/*.json');$found=false;foreach($records as $r){$meta=json_decode(file_get_contents($r),true);if(isset($meta['decision'])&&$meta['decision']==='blocked'){$found=true;$this->assertSame('z-renamed.php',$meta['original']);$this->assertNotEmpty($meta['rules']);}}
            $this->assertTrue($found);
        } finally{$this->removeTree($root);}
    }
    public function test_benign_mu_plugins_are_not_blocked_and_missing_state_fails_open() {
        $root=realpath(sys_get_temp_dir()).'/gwqsh-benign-test-'.bin2hex(random_bytes(6));mkdir($root);mkdir($root.'/mu');GWQSH_Security_Runtime::protect($root.'/state');
        $guardian=$root.'/mu/'.GWQSH_Guardian::NAME;file_put_contents($guardian,GWQSH_Guardian::source($root.'/state'));
        try {
            foreach(array('benign-api','benign-cache','benign-loader','benign-sso','benign-config','benign-redirect') as $name) file_put_contents($root.'/mu/'.$name.'.php',file_get_contents(__DIR__.'/fixtures/'.$name.'.fixture'));
            $code='define("ABSPATH",'.var_export($root.'/',true).');define("WPMU_PLUGIN_DIR",'.var_export($root.'/mu',true).');require '.var_export($guardian,true).';echo "ok";';
            $this->assertSame('ok',$this->process($code));$this->assertCount(0,glob($root.'/state/*.quarantine'));
            file_put_contents($guardian,GWQSH_Guardian::source($root.'/missing-state'));$this->assertSame('ok',$this->process($code));
            file_put_contents($guardian,GWQSH_Guardian::source($root.'/state'));chmod($root.'/state',0500);$this->assertSame('ok',$this->process($code));chmod($root.'/state',0700);
        }finally{chmod($root.'/state',0700);$this->removeTree($root);}
    }
    public function test_alphabetically_earlier_attacker_file_can_execute_first() {
        $root=realpath(sys_get_temp_dir()).'/gwqsh-order-test-'.bin2hex(random_bytes(6));mkdir($root);mkdir($root.'/mu');GWQSH_Security_Runtime::protect($root.'/state');
        file_put_contents($root.'/mu/'.GWQSH_Guardian::NAME,GWQSH_Guardian::source($root.'/state'));
        file_put_contents($root.'/mu/000000-aaa.php',file_get_contents(__DIR__.'/fixtures/bot-gate.fixture'));
        try {
            $code='define("ABSPATH",'.var_export($root.'/',true).');define("WPMU_PLUGIN_DIR",'.var_export($root.'/mu',true).');$files=glob(WPMU_PLUGIN_DIR."/*.php");sort($files);foreach($files as $f)include $f;echo !empty($GLOBALS["gwqsh_fixture_executed"])?"earlier executed":"blocked";';
            $this->assertSame('earlier executed',$this->process($code));
        }finally{$this->removeTree($root);}
    }
    public function test_real_local_wordpress_blocks_fixture_and_keeps_main_plugin_loading() {
        $this->assertTrue(GWQSH_Guardian::install());
        $state=GWQSH_Guardian::state_dir();$before=glob($state.'/*.quarantine');
        $file=GWQSH_Guardian::root().'/z-gwqsh-regression-'.bin2hex(random_bytes(6)).'.php';
        try {
            foreach(array('bot-gate','self-heal-index') as $fixture) {
                file_put_contents($file,file_get_contents(__DIR__.'/fixtures/'.$fixture.'.fixture'));
                $code='require '.var_export(ABSPATH.'wp-load.php',true).';echo json_encode(array("main"=>class_exists("GWQSH_File_Integrity"),"fixture"=>!empty($GLOBALS["gwqsh_fixture_executed"])));';
                $result=json_decode($this->process($code),true);$this->assertTrue($result['main']);$this->assertFalse($result['fixture']);$this->assertStringContainsString('Gracewell-blocked',file_get_contents($file));
            }
        }finally{
            if(is_file($file))unlink($file);
            foreach(array_diff(glob($state.'/*.quarantine'),$before) as $f){unlink($f);$json=substr($f,0,-11).'.json';if(is_file($json))unlink($json);}
        }
    }
    public function test_guardian_installer_update_collision_and_deactivation() {
        $file=GWQSH_Guardian::root().'/'.GWQSH_Guardian::NAME;
        $this->assertTrue(GWQSH_Guardian::install());
        $original=file_get_contents($file);
        try {
            file_put_contents($file,$original."\n// prior version");$this->assertTrue(GWQSH_Guardian::install());$this->assertSame($original,file_get_contents($file));
            $this->assertTrue(GWQSH_Guardian::remove());$this->assertFileDoesNotExist($file);
            file_put_contents($file,'<?php // unrelated host file');$this->assertFalse(GWQSH_Guardian::install());$this->assertSame('<?php // unrelated host file',file_get_contents($file));unlink($file);
        }finally{if(is_file($file))file_put_contents($file,$original);else GWQSH_Guardian::install();}
    }
}
