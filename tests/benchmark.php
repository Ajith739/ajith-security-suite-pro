<?php
// Development-only CLI benchmark; synthetic files are removed in finally.
if(PHP_SAPI!=='cli')exit;
require dirname(__DIR__,4).'/wp-load.php';
$root=realpath(sys_get_temp_dir()).'/gwqsh-bench-'.bin2hex(random_bytes(6));mkdir($root);
$filter=static function($value)use($root){$value['basedir']=$root;return $value;};add_filter('upload_dir',$filter);wp_upload_dir(null,false,true);
$report=array();
try{
 $cache=array();
 for($i=0;$i<10000;$i++)file_put_contents($root.'/'.$i.'.txt','Harmless synthetic fixture '.$i);
 foreach(array(1000,10000) as $limit){$t=microtime(true);$errors=array();$n=0;foreach(GWQSH_Scan_Engine::files($root,$errors) as $file){$cache[$file]=GWQSH_Scan_Engine::inspect($file,'Uploads');if(++$n>=$limit)break;}$report['scan_'.$limit.'_seconds']=microtime(true)-$t;}
 $t=microtime(true);foreach($cache as $file=>$entry)GWQSH_Scan_Engine::inspect($file,'Uploads',$entry);$report['unchanged_10000_seconds']=microtime(true)-$t;
 $large='<?php /*'.str_repeat('a',524288).'*/return;';$t=microtime(true);for($i=0;$i<20;$i++)GWQSH_Malware_Analyzer::analyze($large,'large.php','Plugin');$report['bounded_large_php_mean_ms']=(microtime(true)-$t)*1000/20;
 GWQSH_Guardian::install();$file=GWQSH_Guardian::root().'/'.GWQSH_Guardian::NAME;$t=microtime(true);for($i=0;$i<200;$i++)include $file;$report['guardian_empty_directory_mean_ms']=(microtime(true)-$t)*1000/200;
 $benign=array();for($i=0;$i<10;$i++){$name=GWQSH_Guardian::root().'/z-gwqsh-bench-'.$i.'.php';if(file_exists($name))throw new RuntimeException('Benchmark collision');file_put_contents($name,'<?php return;');$benign[]=$name;}
 $t=microtime(true);for($i=0;$i<200;$i++)include $file;$report['guardian_10_benign_mean_ms']=(microtime(true)-$t)*1000/200;
 echo json_encode($report,JSON_PRETTY_PRINT),"\n";
}finally{foreach(glob($root.'/*') as $file)unlink($file);rmdir($root);foreach(isset($benign)?$benign:array() as $file)unlink($file);remove_filter('upload_dir',$filter);wp_upload_dir(null,false,true);}
