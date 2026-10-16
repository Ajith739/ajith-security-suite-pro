<?php
// CLI-only temporary account. Never included in the distributable plugin.
if ( PHP_SAPI !== 'cli' ) { exit; }
require __DIR__ . '/bootstrap.php';
$directory = getenv( 'GWQSH_UPGRADE_TEST_DIR' );
if ( ! $directory || ! is_dir( $directory ) ) { exit( "Set GWQSH_UPGRADE_TEST_DIR to an existing private directory.\n" ); }
$file = $directory . '/account.json';
if ( 'cleanup' === ( $argv[1] ?? '' ) ) {
 $account = json_decode( file_get_contents( $file ), true );
 if ( ! preg_match( '/^gwqsh_upgrade_[a-f0-9]{12}$/D', $account['username'] ?? '' ) ) { exit( "Invalid fixture marker.\n" ); }
 global $wpdb;
 $wpdb->delete( $wpdb->prefix . 'gwqsh_ip_blocks', array( 'created_by' => $account['id'] ) );
 require_once ABSPATH . 'wp-admin/includes/user.php';
 wp_delete_user( $account['id'] );
 $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_activity_log WHERE user_login = %s OR details LIKE %s", $account['username'], '%' . $wpdb->esc_like( $account['username'] ) . '%' ) );
 unlink( $file ); echo "Temporary browser account and its test records removed.\n"; exit;
}
$username = 'gwqsh_upgrade_' . bin2hex( random_bytes( 6 ) ); $password = wp_generate_password( 32, true, true );
$id = wp_create_user( $username, $password, $username . '@example.test' );
if ( is_wp_error( $id ) ) { exit( "Cannot create test account.\n" ); }
$user = new WP_User( $id ); $user->set_role( 'administrator' );
update_user_meta( $id, 'gwqsh_2fa_required', 0 );
file_put_contents( $file, wp_json_encode( array( 'id' => $id, 'username' => $username, 'password' => $password, 'base' => trailingslashit( home_url() ), 'login' => wp_login_url() ) ) );
chmod( $file, 0600 );
echo 'Browser fixture created; WordPress ' . get_bloginfo( 'version' ) . ', PHP ' . PHP_VERSION . ".\n";
