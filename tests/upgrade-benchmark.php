<?php
// CLI-only measurements; excluded from release artifacts.
if ( PHP_SAPI !== 'cli' ) { exit; }
require __DIR__ . '/bootstrap.php';
global $wpdb;
$admin = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
wp_set_current_user( $admin[0]->ID );
$results = array();
foreach ( array( 'dashboard', 'login-protection', 'firewall-cleanup', 'file-integrity' ) as $page ) {
 $queries = $wpdb->num_queries; $start = microtime( true );
 GWQSH_Admin::get_page_initial_data( $page );
 $results[$page] = array( 'adapter_ms' => round( ( microtime( true ) - $start ) * 1000, 2 ), 'queries' => $wpdb->num_queries - $queries );
}
$value = array( 'files' => array_fill( 0, 10000, array( 'hash' => str_repeat( 'a', 64 ), 'version' => '1', 'scope' => 'Plugin', 'severity' => 'Informational', 'evidence' => array() ) ) );
$json = wp_json_encode( $value );
$results['representative_state'] = array( 'json_bytes' => strlen( $json ), 'gzip_base64_bytes' => strlen( base64_encode( gzencode( $json, 1 ) ) ), 'note' => 'Representative repetitive metadata; actual compression depends on file hashes and paths.' );
$results['optional_hero_bytes'] = filesize( GWQSH_PATH . 'assets/js/hero-birds.js' ) + filesize( GWQSH_PATH . 'assets/vendor/three/three.module.js' );
file_put_contents( GWQSH_PATH . 'docs/upgrade-benchmark.json', wp_json_encode( $results, JSON_PRETTY_PRINT ) );
echo wp_json_encode( $results ) . "\n";
