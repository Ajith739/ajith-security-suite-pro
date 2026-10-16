<?php
if ( PHP_SAPI !== 'cli' ) { exit; }
require __DIR__ . '/bootstrap.php';
global $wpdb;
$output = array();
foreach ( $wpdb->get_results( 'SHOW PROCESSLIST', ARRAY_A ) as $process ) {
 if ( 'Sleep' !== $process['Command'] ) { $output[] = array_intersect_key( $process, array_flip( array( 'Id', 'Command', 'Time', 'State' ) ) ); }
}
echo wp_json_encode( $output ) . "\n";
$wpdb->query( 'SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED' );
wp_cache_delete( 'gwqsh_scan_progress', 'options' );
$progress = GWQSH_Scan_Engine::load( 'gwqsh_scan_progress' );
echo wp_json_encode( array( 'offset' => $progress['offset'] ?? null, 'files' => count( $progress['files'] ?? array() ), 'enumerated_entries' => $progress['enumeration']['entries'] ?? null, 'directories_remaining' => count( $progress['enumeration']['queue'] ?? array() ), 'errors' => array_keys( $progress['errors'] ?? array() ) ) ) . "\n";
