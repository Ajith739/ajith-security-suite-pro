<?php
/**
 * Standalone production-package builder; excluded from the release.
 *
 * @package GracewellSecuritySuitePro
 */

if ( ! defined( 'ABSPATH' ) ) {
	if ( ! defined( 'PHP_SAPI' ) || 'cli' !== PHP_SAPI ) {
		exit;
	}
}

/**
 * Build production release package.
 *
 * @throws RuntimeException Internally handled package validation failure.
 */
function gwqsh_build_release() {
	if ( ! class_exists( 'ZipArchive' ) ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- CLI utility only.
		fwrite( STDERR, "ZipArchive PHP extension is required.\n" );
		exit( 1 );
	}

	$plugin = dirname( __DIR__ );
	$slug   = 'gracewell-security-suite-pro';
	$dist   = dirname( $plugin, 3 ) . '/dist';
	if ( ! empty( $GLOBALS['argv'][1] ) ) {
		$dist = $GLOBALS['argv'][1];
	}

	$files = array();

	try {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- CLI reads an existing local source file.
		$header = file_get_contents( $plugin . '/' . $slug . '.php' );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- CLI reads an existing local source file.
		$readme = file_get_contents( $plugin . '/readme.txt' );
		if ( ! preg_match( '/^\s*\* Version:\s*([0-9]+(?:\.[0-9]+){2})\s*$/m', $header, $matches ) ) {
			throw new RuntimeException( 'Bootstrap must contain a semantic release version.' );
		}
		$version = $matches[1];
		if ( ! preg_match( '/^Stable tag:\s*' . preg_quote( $version, '/' ) . '\s*$/m', $readme ) || ! preg_match( '/^\s*\* Text Domain:\s*' . $slug . '\s*$/m', $header ) ) {
			throw new RuntimeException( 'Bootstrap version, readme stable tag, and text domain must match the release.' );
		}
		// Resolve the nearest existing ancestor before creating any output directories.
		$ancestor = $dist;
		while ( ! file_exists( $ancestor ) && dirname( $ancestor ) !== $ancestor ) {
			$ancestor = dirname( $ancestor );
		}
		$source_real   = strtolower( str_replace( '\\', '/', realpath( $plugin ) ) );
		$ancestor_real = strtolower( str_replace( '\\', '/', (string) realpath( $ancestor ) ) );
		if ( $source_real === $ancestor_real || 0 === strpos( $ancestor_real . '/', $source_real . '/' ) ) {
			throw new RuntimeException( 'Release output must be outside the plugin source directory.' );
		}
		foreach ( array( $slug . '.php', 'uninstall.php', 'readme.txt', 'SECURITY.md', 'THIRD-PARTY-NOTICES.txt', 'includes/vendor/webauthn/LICENSE' ) as $name ) {
			if ( ! is_file( $plugin . '/' . $name ) ) {
				throw new RuntimeException( 'Missing required release file: ' . $name );
			}
			$files[] = $plugin . '/' . $name;
		}

		foreach ( array( 'admin', 'assets', 'includes', 'languages' ) as $folder ) {
			$folder_path = $plugin . '/' . $folder;
			if ( ! is_dir( $folder_path ) ) {
				continue;
			}
			$iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $folder_path, FilesystemIterator::SKIP_DOTS ) );
			foreach ( $iterator as $file ) {
				if ( $file->isLink() ) {
					throw new RuntimeException( 'Release assets must not contain symbolic links.' );
				}
				if ( $file->isFile() ) {
					$relative = str_replace( '\\', '/', substr( $file->getPathname(), strlen( $plugin ) + 1 ) );
					if ( preg_match( '~(?:^|/)(?:\.[^/]+|node_modules|tests)(?:/|$)|\.(?:zip|log|bak|tmp|map)$~i', $relative ) ) {
						throw new RuntimeException( 'Unexpected development file: ' . $relative );
					}
					$files[] = $file->getPathname();
				}
			}
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- CLI utility only.
		if ( ! is_dir( $dist ) && ! mkdir( $dist, 0775, true ) ) {
			throw new RuntimeException( 'Cannot create plugin dist directory.' );
		}

		$archive_path = $dist . '/' . $slug . '-' . $version . '.zip';
		$temporary    = $archive_path . '.tmp';
		$zip          = new ZipArchive();

		if ( true !== $zip->open( $temporary, ZipArchive::CREATE | ZipArchive::OVERWRITE ) ) {
			throw new RuntimeException( 'Cannot open the production archive for writing.' );
		}

		$files = array_values(
			array_unique(
				array_map(
					static function ( $file ) {
						return str_replace( '\\', '/', $file );
					},
					$files
				)
			)
		);
		sort( $files );
		foreach ( $files as $file ) {
			$relative = str_replace( '\\', '/', substr( $file, strlen( $plugin ) + 1 ) );
			if ( ! $zip->addFile( $file, $slug . '/' . $relative ) ) {
				throw new RuntimeException( 'Cannot package file: ' . $relative );
			}
		}

		// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename,PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite -- CLI utility only.
		if ( ! $zip->close() || ! rename( $temporary, $archive_path ) ) {
			throw new RuntimeException( 'Cannot finalize the production archive.' );
		}

		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- CLI utility output.
		echo $archive_path . ' (' . count( $files ) . " files)\n";
	} catch ( Exception $error ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- CLI utility only.
		fwrite( STDERR, 'Security Suite Pro build failed: ' . $error->getMessage() . "\n" );
		exit( 1 );
	}
}

gwqsh_build_release();
