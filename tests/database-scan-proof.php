<?php
// phpcs:ignoreFile -- Development-only sanitized CLI proof; excluded from release package.
/**
 * End-to-end proof that the database malware scanner detects planted persistence
 * artifacts on a real WordPress install and changes nothing while doing it.
 *
 * Usage: GWQSH_TEST_WP_ROOT=/path/to/wordpress php tests/database-scan-proof.php
 *
 * Every fixture this script creates is removed in the finally block, including the
 * active_plugins entry and the wp-cron entry, so it is safe to run against a scratch
 * install. Do not run it on a production site.
 */

if ( PHP_SAPI !== 'cli' ) {
	exit;
}
if ( ! defined( 'DISABLE_WP_CRON' ) ) {
	define( 'DISABLE_WP_CRON', true );
}
$gwqsh_root = getenv( 'GWQSH_TEST_WP_ROOT' ) ?: dirname( __DIR__, 4 );
require rtrim( $gwqsh_root, '/\\' ) . '/wp-load.php';

global $wpdb;

$fixture_options = array(
	'gwqsh_proof_payload'  => '<?php system($_GET["c"]); ?>',
	'gwqsh_proof_widget'   => '<script>var _0x1a2b=atob("ZG9jdW1lbnQ=");eval(_0x1a2b);</script>',
	'gwqsh_proof_frame'    => '<iframe src="http://198.51.100.7/p.php" width="1" height="1" style="position:absolute;left:-9999px"></iframe>',
	'gwqsh_proof_incident' => 'a:1:{s:4:"path";s:34:"/wp-content/ms_gate_heal_restore.php";}',
);
$active_before   = get_option( 'active_plugins' );
$cron_before     = get_option( 'cron' );
$orphan_user     = 987654;
$orphan_hook     = 'gwqsh_proof_orphan_hook';
$orphan_plugin   = 'gwqsh-proof-missing/plugin.php';
$report_present  = (bool) get_option( GWQSH_Database_Scanner::REPORT_OPTION, false );

$fingerprint = static function () use ( $wpdb ) {
	return array(
		'options'  => (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name <> %s", GWQSH_Database_Scanner::REPORT_OPTION ) ),
		'usermeta' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->usermeta}" ),
		'fixtures' => (string) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE 'gwqsh_proof_%'" ),
	);
};

echo "Database scan proof\n";

try {
	foreach ( $fixture_options as $name => $value ) {
		update_option( $name, $value, false );
	}
	$cron                       = is_array( $cron_before ) ? $cron_before : array();
	$cron[ time() + 3600 ][ $orphan_hook ] = array( array( 'args' => array() ) );
	update_option( 'cron', $cron, true );
	$wpdb->insert(
		$wpdb->usermeta,
		array(
			'user_id'    => $orphan_user,
			'meta_key'   => $wpdb->prefix . 'capabilities',
			'meta_value' => 'a:1:{s:13:"administrator";b:1;}',
		)
	);
	$active   = is_array( $active_before ) ? $active_before : array();
	$active[] = $orphan_plugin;
	update_option( 'active_plugins', $active, true );

	$before = $fingerprint();
	$start  = microtime( true );
	$report = GWQSH_Database_Scanner::run();
	$ms     = (int) round( ( microtime( true ) - $start ) * 1000 );
	$after  = $fingerprint();

	$by_rule = array();
	foreach ( $report['findings'] as $finding ) {
		$by_rule[ $finding['rule'] ][] = $finding['record'];
	}
	ksort( $by_rule );

	echo "status: {$report['status']}  duration_ms: {$ms}  findings: " . count( $report['findings'] ) . "\n";
	echo 'driver: ' . $report['driver'] . '  prefix: ' . $report['prefix'] . '  multisite: ' . ( $report['multisite'] ? 'yes' : 'no' ) . "\n";
	foreach ( $by_rule as $rule => $records ) {
		echo "  {$rule}: " . implode( ', ', array_slice( $records, 0, 4 ) ) . "\n";
	}
	$expected = array( 'GWQSH-3001', 'GWQSH-3002', 'GWQSH-3003', 'GWQSH-3004', 'GWQSH-3005', 'GWQSH-3007', 'GWQSH-3008' );
	$missing  = array_diff( $expected, array_keys( $by_rule ) );
	echo 'rules missing: ' . ( $missing ? implode( ', ', $missing ) : 'none' ) . "\n";
	echo 'read_only: options ' . $before['options'] . ' -> ' . $after['options']
		. ', usermeta ' . $before['usermeta'] . ' -> ' . $after['usermeta']
		. ', planted rows ' . $before['fixtures'] . ' -> ' . $after['fixtures'] . "\n";
	echo 'planted payload unchanged: ' . ( get_option( 'gwqsh_proof_payload' ) === $fixture_options['gwqsh_proof_payload'] ? 'yes' : 'NO' ) . "\n";
	echo 'stored report status: ' . ( GWQSH_Database_Scanner::report()['status'] ?? 'none' ) . "\n";
} finally {
	foreach ( array_keys( $fixture_options ) as $name ) {
		delete_option( $name );
	}
	$cron = get_option( 'cron' );
	if ( is_array( $cron ) ) {
		foreach ( array_keys( $cron ) as $timestamp ) {
			if ( ! is_array( $cron[ $timestamp ] ) ) {
				continue;
			}
			unset( $cron[ $timestamp ][ $orphan_hook ] );
			if ( ! $cron[ $timestamp ] ) {
				unset( $cron[ $timestamp ] );
			}
		}
		update_option( 'cron', $cron, true );
	}
	$wpdb->delete( $wpdb->usermeta, array( 'user_id' => $orphan_user ) );
	if ( false === $active_before || null === $active_before ) {
		delete_option( 'active_plugins' );
	} else {
		update_option( 'active_plugins', $active_before, true );
	}
	if ( ! $report_present ) {
		delete_option( GWQSH_Database_Scanner::REPORT_OPTION );
	}
	echo 'cleanup: planted options ' . (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->options} WHERE option_name LIKE 'gwqsh_proof_%'" )
		. ', active_plugins restored: ' . ( get_option( 'active_plugins' ) === $active_before ? 'yes' : 'NO' )
		. ', orphan usermeta rows: ' . (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->usermeta} WHERE user_id = %d", $orphan_user ) ) . "\n";
}
