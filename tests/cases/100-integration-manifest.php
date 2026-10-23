<?php
/**
 * Architecture guard: no engine may be advertised as wired unless production
 * code actually references it, and unwired engines must stay recorded.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'integration-manifest' );

$root     = dirname( __DIR__, 2 );
$manifest = $root . '/docs/engine-manifest.json';
if ( ! is_file( $manifest ) ) {
	gw_assert( 'Engine manifest exists', false, 'docs/engine-manifest.json is missing' );
	return;
}
$data = json_decode( (string) file_get_contents( $manifest ), true );
if ( ! is_array( $data ) || ! isset( $data['engines'] ) ) {
	gw_assert( 'Engine manifest is valid JSON', false, 'manifest could not be decoded' );
	return;
}

$sources = array();
$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
foreach ( $iterator as $file ) {
	$path = $file->getPathname();
	if ( 'php' !== strtolower( $file->getExtension() ) ) {
		continue;
	}
	if ( false !== strpos( $path, '/.git/' ) || false !== strpos( $path, '/node_modules/' ) || false !== strpos( $path, '/tests/' ) ) {
		continue;
	}
	$sources[ str_replace( '\\', '/', $path ) ] = (string) file_get_contents( $path );
}

// Engine-family files are not production wiring for each other.
$engine_files = array();
foreach ( $data['engines'] as $engine ) {
	$engine_files[] = '/' . ltrim( (string) ( $engine['file'] ?? '' ), '/' );
}

$wired = 0;
$unwired = 0;
foreach ( $data['engines'] as $engine ) {
	$short      = substr( (string) $engine['class'], strrpos( (string) $engine['class'], '\\' ) + 1 );
	$referenced = false;
	foreach ( $sources as $path => $source ) {
		foreach ( $engine_files as $engine_file ) {
			if ( '' !== $engine_file && str_ends_with( $path, $engine_file ) ) {
				continue 2;
			}
		}
		if ( preg_match( '/\b' . preg_quote( $short, '/' ) . '\b/', $source ) ) {
			$referenced = true;
			break;
		}
	}
	if ( 'wired' === ( $engine['status'] ?? '' ) ) {
		++$wired;
		gw_assert( $short . ' is genuinely wired', $referenced, 'manifest claims wired but no production file references it' );
	} else {
		++$unwired;
		gw_assert( $short . ' is recorded as unwired and stays unreferenced', ! $referenced, 'engine is referenced by production code; update docs/engine-manifest.json' );
	}
}

gw_record( 'Manifest coverage', $wired + $unwired === count( $data['engines'] ), $wired . ' wired, ' . $unwired . ' unwired' );
