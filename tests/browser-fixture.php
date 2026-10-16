<?php
// phpcs:ignoreFile -- CLI-only fixture control; excluded from release.
if (PHP_SAPI !== 'cli') { exit; }
require __DIR__ . '/bootstrap.php';
$a = json_decode(file_get_contents(getenv('GWQSH_BROWSER_ACCOUNT')), true);
$file = $a['root'] . '/review.php';
$label = '/wp-content/plugins/' . $a['marker'] . '/review.php';
$mode = $argv[1] ?? 'old';
$content = 'old' === $mode ? "<?php\n// Trusted old version\nreturn;\n" : ('critical' === $mode ? file_get_contents(GWQSH_PATH . 'tests/fixtures/webshell.fixture') : "<?php\n// New version <script>alert(1)</script>\nreturn;\n");
if (file_exists($file)) { unlink($file); }
file_put_contents($file, $content); chmod($file,0666);
if ('old' === $mode) {
    $baseline = GWQSH_Scan_Engine::load('gwqsh_file_baseline');
    $baseline[$label] = array('hash'=>hash('sha256',$content),'size'=>strlen($content),'mtime'=>time(),'scope'=>'Plugin');
    GWQSH_Scan_Engine::save('gwqsh_file_baseline',$baseline);
}
GWQSH_Scan_Engine::finding($label,'Plugin','Modified',$a['marker'],array('hash'=>hash('sha256',$content),'score'=> 'critical' === $mode ? 90 : 0,'severity'=> 'critical' === $mode ? 'Critical' : 'Low','component'=>'plugin'));
echo 'Fixture prepared: ' . $mode . "\n";
