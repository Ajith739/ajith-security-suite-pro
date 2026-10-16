<?php
// CLI-only backup and data-preserving table maintenance; excluded from releases.
if ( PHP_SAPI !== 'cli' ) { exit; }
require __DIR__ . '/bootstrap.php';
global $wpdb;
$mode = $argv[1] ?? 'stats';
$stats = $wpdb->get_row( "SELECT COUNT(*) AS row_count, SUM(OCTET_LENGTH(option_value)) AS live_bytes FROM {$wpdb->options}", ARRAY_A );
if ( 'stats' === $mode ) { echo wp_json_encode( $stats ) . "\n"; exit; }
$directory = 'D:/GracewellUpgrade/private';
if ( ! is_dir( $directory ) ) { mkdir( $directory, 0700, true ); }
$backup = $directory . '/wordpress-options-before-compaction.jsonl';
if ( 'backup' === $mode ) {
 $handle = fopen( $backup, 'xb' ); if ( ! $handle ) { exit( "Backup already exists or cannot be written.\n" ); }
 $wpdb->query( 'START TRANSACTION WITH CONSISTENT SNAPSHOT' );
 $count = 0; $offset = 0;
 try {
  do {
   $rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_id,option_name,option_value,autoload FROM {$wpdb->options} ORDER BY option_id LIMIT 100 OFFSET %d", $offset ), ARRAY_A );
   foreach ( $rows as $row ) { $encoded = array_map( 'base64_encode', array_map( 'strval', $row ) ); $line = json_encode( $encoded ) . "\n"; if ( fwrite( $handle, $line ) !== strlen( $line ) ) { throw new RuntimeException( 'Backup write failed.' ); } ++$count; }
   $offset += 100;
  } while ( count( $rows ) === 100 );
  fflush( $handle );
 } finally { fclose( $handle ); $wpdb->query( 'COMMIT' ); }
 chmod( $backup, 0600 );
 file_put_contents( $backup . '.sha256', hash_file( 'sha256', $backup ) );
 echo 'Backed up ' . $count . ' option rows to private storage; values preserved as binary-safe base64.' . "\n"; exit;
}
if ( 'optimize' === $mode ) {
 if ( ! is_file( $backup ) || ! is_file( $backup . '.sha256' ) || ! hash_equals( trim( file_get_contents( $backup . '.sha256' ) ), hash_file( 'sha256', $backup ) ) ) { exit( "Verified backup required.\n" ); }
 $wpdb->query( "SET SESSION innodb_tmpdir = 'D:/GracewellUpgrade/temp'" );
 $before = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options}" );
 $result = $wpdb->get_results( "OPTIMIZE TABLE {$wpdb->options}", ARRAY_A );
 $after = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options}" );
 echo wp_json_encode( array( 'rows_before' => $before, 'rows_after' => $after, 'maintenance' => $result ) ) . "\n";
}
