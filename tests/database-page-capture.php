<?php
// phpcs:ignoreFile -- Development-only fixture capture for the jsdom card test.
/**
 * Renders the Firewall & Cleanup admin screen and its bootstrap payload into a directory
 * so tests/jsdom-database-card.cjs can drive the real controller against real markup.
 *
 * Usage: php-wasm-cli tests/database-page-capture.php <output-dir>
 * Requires a loaded WordPress (wp-load.php found via GWQSH_TEST_WP_ROOT).
 */
$root = getenv( 'GWQSH_TEST_WP_ROOT' ) ? getenv( 'GWQSH_TEST_WP_ROOT' ) : dirname( __DIR__, 4 ) . '/wp';
if ( ! is_file( $root . '/wp-load.php' ) ) {
	fwrite( STDERR, "No WordPress at {$root}. Set GWQSH_TEST_WP_ROOT.\n" );
	exit( 1 );
}
require $root . '/wp-load.php';
require_once ABSPATH . 'wp-admin/includes/class-wp-screen.php';
require_once ABSPATH . 'wp-admin/includes/screen.php';

$out = isset( $argv[1] ) ? $argv[1] : dirname( __DIR__, 2 ) . '/jstest';
if ( ! is_dir( $out ) && ! mkdir( $out, 0755, true ) ) {
	fwrite( STDERR, "Cannot create {$out}.\n" );
	exit( 1 );
}

$admins = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
if ( $admins ) {
	wp_set_current_user( $admins[0]->ID );
}
set_current_screen( 'toplevel_page_gracewell-security-suite-pro-firewall-cleanup' );

ob_start();
require dirname( __DIR__ ) . '/admin/views/firewall-cleanup.php';
$html = ob_get_clean();

file_put_contents( $out . '/page.html', '<!doctype html><html><body>' . $html . '</body></html>' );
file_put_contents( $out . '/data.json', wp_json_encode( GWQSH_Admin::get_page_initial_data( 'firewall-cleanup' ) ) );
echo 'captured ', strlen( $html ), ' bytes of markup and ', (int) filesize( $out . '/data.json' ), ' bytes of page data', PHP_EOL;
