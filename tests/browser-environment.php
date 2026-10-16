<?php
// phpcs:ignoreFile -- CLI-only, reversible local browser fixtures. Never shipped.
if (PHP_SAPI !== 'cli') { exit; }
require __DIR__ . '/bootstrap.php';
$directory = getenv('GWQSH_BROWSER_WORKDIR');
if (!$directory || !is_dir($directory)) { exit("Set GWQSH_BROWSER_WORKDIR to a private existing test directory.\n"); }
$snapshot = $directory . '/browser-snapshot.bin';
$accountFile = $directory . '/browser-account.json';
$mode = $argv[1] ?? 'setup';
if ('cleanup' === $mode) {
    if (!is_file($snapshot)) { exit("No fixture snapshot exists.\n"); }
    $backup = unserialize(file_get_contents($snapshot), array('allowed_classes' => false));
    $marker = basename($backup['root']);
    if (!preg_match('/^gwqsh-browser-[a-f0-9]{12}$/D', $marker) || dirname($backup['root']) !== rtrim(WP_PLUGIN_DIR, '/')) { exit("Invalid fixture root.\n"); }
    $current = get_option('gwqsh_quarantine_metadata', array());
    foreach ($current as $item) {
        if (strpos($item['original'] ?? '', $marker) !== false) { exit("Delete browser fixture copies through the logged-in browser before cleanup.\n"); }
    }
    $wpdb->query($wpdb->prepare('DELETE FROM ' . $wpdb->prefix . 'gwqsh_scan_results WHERE file_path LIKE %s', '%' . $wpdb->esc_like($marker) . '%'));
    update_option('gwqsh_quarantine_metadata', array_merge($backup['metadata'], $current), false);
    GWQSH_Scan_Engine::save('gwqsh_file_baseline', $backup['baseline']);
    $removed = get_option('gwqsh_intentional_removals', array());
    foreach ($removed as $key => $record) { if (strpos($key,$marker)!==false) unset($removed[$key]); }
    update_option('gwqsh_intentional_removals',$removed,false);
    require_once ABSPATH . 'wp-admin/includes/user.php';
    wp_delete_user($backup['user']); wp_delete_user($backup['subscriber']);
    foreach (glob($backup['root'] . '/*') as $file) { if (is_file($file) || is_link($file)) unlink($file); }
    rmdir($backup['root']); unlink($snapshot); unlink($accountFile);
    echo "Temporary accounts, fixtures and baseline/quarantine view restored.\n";
    exit;
}
if (file_exists($snapshot)) { exit("A fixture snapshot already exists; clean it up first.\n"); }
$original = array('metadata' => get_option('gwqsh_quarantine_metadata', array()), 'baseline' => GWQSH_Scan_Engine::load('gwqsh_file_baseline'));
$marker = 'gwqsh-browser-' . bin2hex(random_bytes(6));
$password = wp_generate_password(30, true, false);
$user = wp_create_user($marker, $password, $marker . '@example.invalid');
if (is_wp_error($user)) { exit("User setup failed.\n"); }
(new WP_User($user))->set_role('administrator');
$subscriber = wp_create_user($marker . '-reader', $password, $marker . '-reader@example.invalid');
(new WP_User($subscriber))->set_role('subscriber');
$root = WP_PLUGIN_DIR . '/' . $marker; mkdir($root,0777); chmod($root,0777);
$ids = array();
for ($i=0; $i<1100; $i++) {
    $path = '/wp-content/plugins/' . $marker . '/' . sprintf('%04d',$i) . '.txt';
    $content = 'sanitized browser fixture ' . $i;
    file_put_contents($root . '/' . sprintf('%04d',$i) . '.txt',$content); chmod($root . '/' . sprintf('%04d',$i) . '.txt',0666);
    GWQSH_Scan_Engine::finding($path,'Plugin','Modified',$marker,array('hash'=>hash('sha256',$content),'severity'=>'Low','score'=>0,'component'=>'plugin'));
    $ids[]=(int)$wpdb->insert_id;
}
update_option('gwqsh_quarantine_metadata',array(),false);
$original['root']=$root; $original['ids']=$ids; $original['user']=$user; $original['subscriber']=$subscriber;
file_put_contents($snapshot,serialize($original)); chmod($snapshot,0600);
file_put_contents($accountFile,wp_json_encode(array('base'=>home_url('/'),'login'=>wp_login_url(),'username'=>$marker,'password'=>$password,'subscriber'=>$marker.'-reader','marker'=>$marker,'root'=>$root,'ids'=>$ids)));
chmod($accountFile,0600);
echo "Created isolated browser fixtures and temporary accounts.\n";
