<?php
/**
 * Syntax lint for plugin PHP sources without requiring the php CLI binary.
 *
 * Uses token_get_all() with TOKEN_PARSE, which raises a ParseError on invalid
 * syntax. Usage: php tests/lint.php <root>
 *
 * @package GracewellSecuritySuitePro
 */

$root  = rtrim( $argv[1] ?? dirname( __DIR__ ), '/' );
$files = array();
$iterator = new RecursiveIteratorIterator(
	new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS )
);
foreach ( $iterator as $file ) {
	$path = $file->getPathname();
	if ( false !== strpos( $path, '/.git/' ) || false !== strpos( $path, '/node_modules/' ) || false !== strpos( $path, '/tests/.runtime/' ) ) {
		continue;
	}
	if ( 'php' === strtolower( $file->getExtension() ) ) {
		$files[] = $path;
	}
}
sort( $files );

$failed = array();
foreach ( $files as $file ) {
	try {
		token_get_all( (string) file_get_contents( $file ), TOKEN_PARSE );
	} catch ( Throwable $error ) {
		$failed[] = array( 'file' => $file, 'error' => $error->getMessage(), 'line' => $error->getLine() );
	}
}

$payload = array(
	'generated_at' => gmdate( 'c' ),
	'php_version'  => PHP_VERSION,
	'files'        => count( $files ),
	'failed'       => count( $failed ),
	'failures'     => $failed,
);
$out = $root . '/docs/evidence/lint.json';
if ( ! is_dir( dirname( $out ) ) ) {
	mkdir( dirname( $out ), 0775, true );
}
file_put_contents( $out, json_encode( $payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );
echo sprintf( "Linted %d PHP files, %d failures\n", count( $files ), count( $failed ) );
foreach ( $failed as $failure ) {
	echo sprintf( "  FAIL %s (line %d): %s\n", $failure['file'], $failure['line'], $failure['error'] );
}
if ( ! defined( 'GW_LINT_EMBEDDED' ) ) {
	exit( $failed ? 1 : 0 );
}
