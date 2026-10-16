<?php
// phpcs:ignoreFile -- Development test suite; excluded from release package.
if ( PHP_SAPI !== 'cli' ) { exit; }
// Tests invoke cron callbacks explicitly; never spawn asynchronous site workers.
if ( ! defined( 'DISABLE_WP_CRON' ) ) { define( 'DISABLE_WP_CRON', true ); }
$gwqsh_test_root = getenv( 'GWQSH_TEST_WP_ROOT' ) ?: dirname( __DIR__, 4 );
require rtrim( $gwqsh_test_root, '/\\' ) . '/wp-load.php';

defined( 'ABSPATH' ) || exit;
