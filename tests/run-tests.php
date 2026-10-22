<?php
/**
 * Isolated regression runner for Gracewell Security Suite Pro security engines.
 *
 * Usage: php tests/run-tests.php [--json=path] [--verbose]
 *
 * The runner executes real plugin source (no mocks of the code under test)
 * against minimal WordPress stubs in tests/bootstrap.php. It does not replace a
 * WordPress integration test; see docs/TEST-EVIDENCE.md for what is proven.
 *
 * @package GracewellSecuritySuitePro
 */

$root = dirname( __DIR__ );
require __DIR__ . '/bootstrap.php';
require __DIR__ . '/lib/harness.php';

// Real plugin source under test.
require_once $root . '/includes/class-gwqsh-network.php';
require_once $root . '/includes/class-gwqsh-settings.php';
require_once $root . '/includes/class-gwqsh-enterprise-config.php';
require_once $root . '/includes/class-gwqsh-enterprise-store.php';
require_once $root . '/includes/class-gwqsh-country-access.php';
require_once $root . '/includes/class-gwqsh-bot-shield.php';
require_once $root . '/includes/class-gwqsh-firewall.php';
require_once $root . '/includes/waf/class-gracewell-waf-inspector.php';
require_once $root . '/includes/alerts/class-gracewell-ssrf-safe-dispatcher.php';
require_once $root . '/includes/auth/class-gracewell-auth-guard.php';

$cases = glob( __DIR__ . '/cases/*.php' );
sort( $cases );
foreach ( $cases as $case ) {
	require $case;
}

$passed  = 0;
$failed  = 0;
$skipped = 0;
foreach ( $GLOBALS['gw_results'] as $result ) {
	if ( ! empty( $result['skipped'] ) ) {
		++$skipped;
	} elseif ( $result['passed'] ) {
		++$passed;
	} else {
		++$failed;
	}
}

$verbose = in_array( '--verbose', $argv, true );
$lines   = array();
foreach ( $GLOBALS['gw_results'] as $result ) {
	$state = ! empty( $result['skipped'] ) ? 'SKIP' : ( $result['passed'] ? 'PASS' : 'FAIL' );
	$line  = sprintf( '%s  [%s] %s%s', $state, $result['group'], $result['test'], '' !== $result['detail'] ? ' — ' . $result['detail'] : '' );
	$lines[] = $line;
	if ( 'FAIL' === $state || $verbose || 'SKIP' === $state ) {
		echo $line . "\n";
	}
}

echo "\n";
echo sprintf( "PHP %s | %d passed, %d failed, %d skipped, %d total\n", PHP_VERSION, $passed, $failed, $skipped, $passed + $failed + $skipped );

$json_path = '';
foreach ( $argv as $arg ) {
	if ( str_starts_with( $arg, '--json=' ) ) {
		$json_path = substr( $arg, 7 );
	}
}
if ( '' !== $json_path ) {
	$payload = array(
		'generated_at' => gmdate( 'c' ),
		'php_version'  => PHP_VERSION,
		'extensions'   => array(
			'sodium'    => function_exists( 'sodium_crypto_sign_verify_detached' ),
			'openssl'   => function_exists( 'openssl_encrypt' ),
			'mbstring'  => function_exists( 'mb_strlen' ),
			'tokenizer' => function_exists( 'token_get_all' ),
			'pdo'       => extension_loaded( 'pdo' ),
		),
		'summary'      => array(
			'passed'  => $passed,
			'failed'  => $failed,
			'skipped' => $skipped,
			'total'   => $passed + $failed + $skipped,
		),
		'results'      => $GLOBALS['gw_results'],
	);
	$dir = dirname( $json_path );
	if ( ! is_dir( $dir ) ) {
		mkdir( $dir, 0775, true );
	}
	file_put_contents( $json_path, json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
	echo "Wrote {$json_path}\n";
}

exit( $failed > 0 ? 1 : 0 );
