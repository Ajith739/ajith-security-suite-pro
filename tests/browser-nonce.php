<?php
// phpcs:ignoreFile -- CLI-only permission-test nonce, using the temporary reader's own session.
if (PHP_SAPI !== 'cli') { exit; }
require __DIR__ . '/bootstrap.php';
$a = json_decode(file_get_contents(getenv('GWQSH_BROWSER_ACCOUNT')), true);
$user = get_user_by('login', $a['subscriber']);
if (!$user || !preg_match('/^gwqsh-browser-[a-f0-9]{12}-reader$/D',$user->user_login)) { exit(1); }
$_COOKIE[LOGGED_IN_COOKIE] = urldecode(trim(stream_get_contents(STDIN)));
wp_set_current_user($user->ID);
echo wp_create_nonce('gwqsh_nonce');
