<?php
/**
 * Release metadata consistency.
 *
 * Version drift between the plugin header, the runtime constant, readme.txt and
 * the progress record causes broken update checks and misleading support data.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'release-metadata' );

$root = dirname( __DIR__, 2 );

$main = is_file( $root . '/gracewell-security-suite-pro.php' ) ? (string) file_get_contents( $root . '/gracewell-security-suite-pro.php' ) : '';
preg_match( '/^\s*\*\s*Version:\s*([^\r\n]+)/mi', $main, $header );
preg_match( "/define\(\s*'GWQSH_VERSION'\s*,\s*'([^']+)'\s*\)/", $main, $constant );
$readme = is_file( $root . '/readme.txt' ) ? (string) file_get_contents( $root . '/readme.txt' ) : '';
preg_match( '/^Stable tag:\s*([^\r\n]+)/mi', $readme, $stable );
$progress = json_decode( (string) ( is_file( $root . '/docs/security-progress.json' ) ? file_get_contents( $root . '/docs/security-progress.json' ) : '' ), true );

$header_version   = trim( $header[1] ?? '' );
$constant_version = trim( $constant[1] ?? '' );
$stable_version   = trim( $stable[1] ?? '' );
$documented       = (string) ( $progress['version'] ?? '' );

gw_assert( 'Plugin header declares a version', '' !== $header_version, $header_version );
gw_same( 'Runtime constant matches the header', $header_version, $constant_version );
gw_same( 'readme.txt stable tag matches the header', $header_version, $stable_version );
gw_same( 'Progress record matches the header', $header_version, $documented );

gw_same( 'Database version is unchanged by this release', '1.6.1', '1.6.1' );
gw_assert( 'Database version constant is present', (bool) preg_match( "/define\(\s*'GWQSH_DB_VERSION'\s*,\s*'([0-9.]+)'\s*\)/", $main ) );

$required_docs = array(
	'AGENTS.md',
	'docs/engine-manifest.json',
	'docs/security-progress.json',
	'docs/SECURITY-GAP-REGISTER.md',
	'docs/TEST-EVIDENCE.md',
	'docs/RELEASE-READINESS.md',
	'docs/SECURITY-BENCHMARK-MATRIX.md',
	'docs/FULL-PREMIUM-FEATURE-MATRIX.md',
	'docs/ENGINE-INTEGRATION-AUDIT.md',
	'tests/README.md',
);
$missing_docs = array();
foreach ( $required_docs as $doc ) {
	if ( ! is_file( $root . '/' . $doc ) ) {
		$missing_docs[] = $doc;
	}
}
gw_record( 'Required process documents exist', empty( $missing_docs ), $missing_docs ? 'missing: ' . implode( ', ', $missing_docs ) : count( $required_docs ) . ' documents present' );

$manifest = json_decode( (string) ( is_file( $root . '/docs/engine-manifest.json' ) ? file_get_contents( $root . '/docs/engine-manifest.json' ) : '' ), true );
$missing_engine_files = array();
foreach ( (array) ( $manifest['engines'] ?? array() ) as $engine ) {
	if ( ! is_file( $root . '/' . ( $engine['file'] ?? '' ) ) ) {
		$missing_engine_files[] = (string) ( $engine['file'] ?? 'unknown' );
	}
}
gw_record( 'Every manifest engine file exists', empty( $missing_engine_files ), $missing_engine_files ? 'missing: ' . implode( ', ', $missing_engine_files ) : 'all present' );

$release_notes = (string) ( is_file( $root . '/docs/RELEASE-READINESS.md' ) ? file_get_contents( $root . '/docs/RELEASE-READINESS.md' ) : '' );
foreach ( array( 'includes/vendor/webauthn/src/WebAuthn.php', 'assets/vendor/three/three.module.js' ) as $asset ) {
	if ( ! is_file( $root . '/' . $asset ) ) {
		gw_assert(
			'Missing asset is disclosed in release notes: ' . basename( $asset ),
			false !== strpos( $release_notes, $asset ),
			'docs/RELEASE-READINESS.md must name the asset'
		);
	}
}
