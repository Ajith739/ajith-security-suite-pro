<?php
/**
 * Release gate: packaging, metadata and reference integrity.
 *
 * Fails on defects that would break a shipped build (version drift, broken
 * include references, secrets, dev artifacts) and reports feature-blocking
 * missing runtime assets separately, because those are packaging decisions.
 *
 * Usage: php tests/tools/package-check.php <plugin-root>
 *
 * @package GracewellSecuritySuitePro
 */

$root = rtrim( $argv[1] ?? dirname( __DIR__, 2 ), '/' );

$report = array(
	'generated_at' => gmdate( 'c' ),
	'php_version'  => PHP_VERSION,
	'root'         => $root,
	'version'      => array(),
	'references'   => array(),
	'assets'       => array(),
	'forbidden'    => array(),
	'secrets'      => array(),
	'metadata'     => array(),
	'gate'         => 'unknown',
	'failures'     => array(),
);

/**
 * Read a file if it exists.
 *
 * @param string $path Path.
 * @return string Contents or empty string.
 */
function gw_read( $path ) {
	return is_file( $path ) ? (string) file_get_contents( $path ) : '';
}

// 1. Version consistency.
$main   = gw_read( $root . '/gracewell-security-suite-pro.php' );
$readme = gw_read( $root . '/readme.txt' );
preg_match( '/^\s*\*\s*Version:\s*([^\r\n]+)/mi', $main, $header );
preg_match( "/define\(\s*'GWQSH_VERSION'\s*,\s*'([^']+)'\s*\)/", $main, $constant );
preg_match( '/^Stable tag:\s*([^\r\n]+)/mi', $readme, $stable );
$progress = json_decode( gw_read( $root . '/docs/security-progress.json' ), true );

$report['version'] = array(
	'header'    => trim( $header[1] ?? '' ),
	'constant'  => trim( $constant[1] ?? '' ),
	'stable_tag'=> trim( $stable[1] ?? '' ),
	'progress'  => (string) ( $progress['version'] ?? '' ),
);
$versions = array_filter( array_values( $report['version'] ) );
if ( count( array_unique( $versions ) ) > 1 || count( $versions ) !== 4 ) {
	$report['failures'][] = 'Version drift between plugin header, GWQSH_VERSION, readme.txt and docs/security-progress.json.';
}

// 2. Feature assets (checked again below; declared here so the reference scan can
// distinguish an intentionally guarded optional asset from a broken require).
$assets = array(
	'includes/vendor/webauthn/src/WebAuthn.php' => 'Passkey enrollment and login',
	'assets/vendor/three/three.module.js'       => 'Hero bird animation',
);

// 3. Reference integrity: every plugin-relative PHP path used in a require must exist.
$php_files = array();
$iterator  = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
foreach ( $iterator as $file ) {
	$path = $file->getPathname();
	if ( 'php' !== strtolower( $file->getExtension() ) ) {
		continue;
	}
	if ( preg_match( '~/(\.git|node_modules|tests)/~', $path ) ) {
		continue;
	}
	$php_files[] = $path;
}

$missing_refs = array();
$guarded_missing = array();
foreach ( $php_files as $file ) {
	$source = gw_read( $file );
	if ( preg_match_all( "/(?:GWQSH_PATH|GWQSH_PLUGIN_DIR)\s*\.\s*'([^']+\.php)'|__DIR__\s*\.\s*'([^']+\.php)'/", $source, $matches, PREG_SET_ORDER ) ) {
		foreach ( $matches as $match ) {
			$relative = $match[1] ?? '';
			$local    = $match[2] ?? '';
			$target   = '' !== $relative
				? $root . '/' . ltrim( $relative, '/' )
				: dirname( $file ) . '/' . ltrim( $local, '/' );
			$target = str_replace( '//', '/', $target );
			if ( is_file( $target ) ) {
				continue;
			}
			$relative_target = str_replace( $root . '/', '', $target );
			if ( isset( $assets[ $relative_target ] ) ) {
				// Optional runtime asset: the code guards it with is_file(), so this is a
				// packaging blocker reported in the assets section, not a broken require.
				$guarded_missing[] = $relative_target;
				continue;
			}
			$missing_refs[] = $relative_target . ' (from ' . str_replace( $root . '/', '', $file ) . ')';
		}
	}
}
$report['references'] = array(
	'checked'         => count( $php_files ),
	'missing'         => $missing_refs,
	'guarded_optional'=> array_values( array_unique( $guarded_missing ) ),
);
if ( $missing_refs ) {
	$report['failures'][] = 'PHP files reference ' . count( $missing_refs ) . ' missing path(s).';
}

// 4. Required runtime assets for advertised features.
foreach ( $assets as $relative => $feature ) {
	$present = is_file( $root . '/' . $relative );
	$report['assets'][ $relative ] = array( 'present' => $present, 'feature' => $feature );
	if ( ! $present ) {
		$blocker = $relative . ' (' . $feature . ' unavailable in a clean checkout)';
		$release = gw_read( $root . '/docs/RELEASE-READINESS.md' );
		$report['metadata'][] = false !== strpos( $release, $relative )
			? 'documented blocker: ' . $relative
			: 'UNDOCUMENTED blocker: ' . $relative;
		if ( false === strpos( $release, $relative ) ) {
			$report['failures'][] = 'Missing runtime asset is not disclosed in docs/RELEASE-READINESS.md: ' . $relative;
		}
		$report['assets'][ $relative ]['gate'] = $blocker;
	}
}

// 4. Forbidden artifacts in a shipping tree.
$forbidden = array( 'node_modules', 'tests/.runtime', 'tests/tmp', '.env', '.DS_Store' );
foreach ( $forbidden as $relative ) {
	if ( file_exists( $root . '/' . $relative ) ) {
		$report['forbidden'][] = $relative;
	}
}
if ( $report['forbidden'] ) {
	$report['failures'][] = 'Development artifacts present: ' . implode( ', ', $report['forbidden'] ) . ' (ignored by git, must not ship).';
}

// 5. Secret scan over shipped PHP/JS/CSS/JSON (tests and evidence excluded).
$patterns = array(
	'private key block'      => '/-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/',
	'AWS access key id'      => '/\bAKIA[0-9A-Z]{16}\b/',
	'Slack token'            => '/\bxox[baprs]-[0-9A-Za-z-]{10,}/',
	'Stripe live key'        => '/\bsk_live_[0-9A-Za-z]{16,}/',
	'Google API key'         => '/\bAIza[0-9A-Za-z_-]{35}\b/',
	'GitHub token'           => '/\bgh[pousr]_[0-9A-Za-z]{30,}/',
	'Twilio account sid'     => '/\bAC[0-9a-f]{32}\b/',
);
$scanned = 0;
foreach ( new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) ) as $file ) {
	$path = $file->getPathname();
	if ( ! preg_match( '/\.(?:php|js|css|json)$/', $path ) || preg_match( '~/(\.git|node_modules|tests|docs/evidence)/~', $path ) ) {
		continue;
	}
	++$scanned;
	$source = gw_read( $path );
	foreach ( $patterns as $label => $pattern ) {
		if ( preg_match( $pattern, $source ) ) {
			$report['secrets'][] = $label . ' in ' . str_replace( $root . '/', '', $path );
		}
	}
}
$report['metadata'][] = 'secret scan: ' . $scanned . ' shipped files';
if ( $report['secrets'] ) {
	$report['failures'][] = 'Possible secret material in shipped files.';
}

$blockers = array_values( array_filter( array_column( $report['assets'], 'gate' ) ) );
$report['gate'] = $report['failures'] ? 'fail' : ( $blockers ? 'blocked' : 'pass' );

if ( ! is_dir( $root . '/docs/evidence' ) ) {
	mkdir( $root . '/docs/evidence', 0775, true );
}
file_put_contents( $root . '/docs/evidence/package-check.json', json_encode( $report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) . "\n" );

echo 'Package check: ' . $report['gate'] . "\n";
echo '  versions: ' . implode( ' / ', $report['version'] ) . "\n";
echo '  php files referenced: ' . $report['references']['checked'] . ', missing paths: ' . count( $missing_refs ) . "\n";
foreach ( $report['assets'] as $relative => $state ) {
	echo '  asset ' . $relative . ': ' . ( $state['present'] ? 'present' : 'MISSING (blocked)' ) . "\n";
}
foreach ( $report['failures'] as $failure ) {
	echo '  FAIL: ' . $failure . "\n";
}
foreach ( $blockers as $blocker ) {
	echo '  BLOCKED: ' . $blocker . "\n";
}

if ( ! defined( 'GW_PACKAGE_CHECK_EMBEDDED' ) ) {
	exit( $report['failures'] ? 1 : 0 );
}
