<?php
/**
 * Central path validation for all Gracewell Security Suite Pro filesystem operations.
 *
 * Every read, write, quarantine or restore routes through this guard.
 * Traversal, null bytes, stream wrappers, symlink escapes are all rejected.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH_Path_Guard — unified path security.
 */
final class GWQSH_Path_Guard {

	/** Cached canonical root.
	 *
	 * @var string|null
	 */
	private static $root = null;

	/** Cached allowed roots.
	 *
	 * @var array|null
	 */
	private static $allowed_roots = null;

	/**
	 * Reset cached roots (for tests).
	 */
	public static function reset_cache() {
		self::$root          = null;
		self::$allowed_roots = null;
	}

	/**
	 * Canonical ABSPATH without trailing slash.
	 *
	 * @return string
	 */
	public static function root() {
		if ( null === self::$root ) {
			$real       = realpath( ABSPATH );
			self::$root = $real ? rtrim( str_replace( '\\', '/', $real ), '/' ) : rtrim( str_replace( '\\', '/', ABSPATH ), '/' );
		}
		return self::$root;
	}

	/**
	 * Normalize path separators and trim trailing slash.
	 *
	 * @param string $path Path to normalize.
	 * @return string Normalized path with forward slashes.
	 */
	public static function normalize( $path ) {
		if ( ! is_string( $path ) ) {
			return '';
		}
		return rtrim( str_replace( '\\', '/', $path ), '/' );
	}

	/**
	 * Check if a path is safe and valid within allowed roots.
	 *
	 * @param string $path Path to check.
	 * @param bool   $must_exist Whether path must exist.
	 * @return bool True if valid and safe.
	 */
	public static function is_safe( $path, $must_exist = true ) {
		return null !== self::validate( $path, $must_exist );
	}

	/**
	 * Allowed root directories for security I/O.
	 *
	 * @return array List of canonical paths (no trailing slash).
	 */
	public static function allowed_roots() {
		if ( null !== self::$allowed_roots ) {
			return self::$allowed_roots;
		}
		$roots   = array( ABSPATH, WP_CONTENT_DIR );
		$uploads = wp_upload_dir();
		if ( ! empty( $uploads['basedir'] ) ) {
			$roots[] = $uploads['basedir'];
		}
		if ( defined( 'WP_PLUGIN_DIR' ) && WP_PLUGIN_DIR ) {
			$roots[] = WP_PLUGIN_DIR;
		}
		if ( defined( 'WPMU_PLUGIN_DIR' ) && WPMU_PLUGIN_DIR ) {
			$roots[] = WPMU_PLUGIN_DIR;
		}
		if ( function_exists( 'get_theme_root' ) ) {
			$theme_root = get_theme_root();
			if ( $theme_root && ! is_wp_error( $theme_root ) ) {
				$roots[] = $theme_root;
			}
		}

		$canonical = array();
		foreach ( $roots as $path ) {
			if ( ! is_string( $path ) || '' === $path ) {
				continue;
			}
			$real = realpath( $path );
			$norm = rtrim( str_replace( '\\', '/', $path ), '/' );
			if ( $real ) {
				$canonical[] = rtrim( str_replace( '\\', '/', $real ), '/' );
			} elseif ( is_dir( $norm ) ) {
				$canonical[] = $norm;
			}
		}
		self::$allowed_roots = array_values( array_unique( $canonical ) );
		return self::$allowed_roots;
	}

	/**
	 * True when the canonical path is inside one of the allowed roots.
	 *
	 * @param string $canonical_path Canonical (realpath-resolved) path.
	 * @return bool
	 */
	public static function is_within_allowed_roots( $canonical_path ) {
		$check = rtrim( str_replace( '\\', '/', $canonical_path ), '/' );
		foreach ( self::allowed_roots() as $root ) {
			if ( $check === $root || 0 === strpos( $check, $root . '/' ) ) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Validate a relative (to ABSPATH) or label path.
	 *
	 * Returns array with 'canonical', 'relative', 'component' keys, or null.
	 *
	 * @param string $path      Relative or label path.
	 * @param bool   $must_exist Whether the file must currently exist.
	 * @return array|null
	 */
	public static function validate( $path, $must_exist = true ) {
		if ( ! is_string( $path ) || '' === $path ) {
			return null;
		}
		// Reject null bytes.
		if ( false !== strpos( $path, "\0" ) ) {
			return null;
		}
		// Reject backslashes (Windows-style).
		if ( false !== strpos( $path, '\\' ) ) {
			return null;
		}
		// Reject drive letters.
		if ( preg_match( '#^[A-Za-z]:#', $path ) ) {
			return null;
		}
		// Reject stream wrappers.
		if ( preg_match( '#^[A-Za-z][A-Za-z0-9+.-]*://#', $path ) ) {
			return null;
		}
		// Reject traversal.
		if ( false !== strpos( $path, '../' ) || preg_match( '#(^|/)\\.{1,2}(/|$)#', $path ) ) {
			return null;
		}

		$root = self::root();

		// Handle @-prefix labels from scan engine.
		if ( preg_match( '#^/?@([a-z]+)/(.+)$#D', $path, $matches ) ) {
			$roots = GWQSH_Scan_Engine::roots();
			if ( ! isset( $roots[ $matches[1] ] ) ) {
				return null;
			}
			$label_root = $roots[ $matches[1] ];
			$real_root  = realpath( $label_root );
			if ( ! $real_root ) {
				return null;
			}
			$absolute = rtrim( str_replace( '\\', '/', $real_root ), '/' ) . '/' . $matches[2];
		} elseif ( 0 === strpos( $path, '/' ) ) {
			// Site-rooted path like /wp-content/plugins/...
			$relative = ltrim( $path, '/' );
			if ( '' === $relative ) {
				return null;
			}
			$absolute = $root . '/' . $relative;
		} else {
			// Plain relative path.
			$absolute = $root . '/' . $path;
		}

		// Re-validate segments.
		$segments = explode( '/', ltrim( str_replace( $root . '/', '', $absolute ), '/' ) );
		foreach ( $segments as $segment ) {
			if ( '.' === $segment || '..' === $segment ) {
				return null;
			}
		}

		if ( $must_exist && ! file_exists( $absolute ) ) {
			return null;
		}

		// Resolve deepest existing ancestor.
		$dir   = dirname( $absolute );
		$limit = 0;
		while ( ! file_exists( $dir ) && dirname( $dir ) !== $dir && 64 > ( ++$limit ) ) {
			$dir = dirname( $dir );
		}
		$real_dir = realpath( $dir );
		if ( ! $real_dir ) {
			return null;
		}
		$real_dir = rtrim( str_replace( '\\', '/', $real_dir ), '/' );
		if ( ! self::is_within_allowed_roots( $real_dir ) ) {
			return null;
		}

		// Keep missing intermediate directories; never collapse a restore target.
		$canonical = $real_dir . substr( $absolute, strlen( $dir ) );
		// Reject every symlink segment, including dangling links.
		$probe = $absolute;
		while ( dirname( $probe ) !== $probe ) {
			if ( is_link( $probe ) ) {
				return null;
			}
			$probe = dirname( $probe );
		}

		if ( file_exists( $absolute ) ) {
			if ( is_link( $absolute ) ) {
				// Symlinks only if they resolve inside allowed roots.
				$target = realpath( $absolute );
				if ( ! $target ) {
					return null;
				}
				$target = str_replace( '\\', '/', $target );
				if ( ! self::is_within_allowed_roots( $target ) ) {
					return null;
				}
				$canonical = $target;
			} elseif ( is_file( $absolute ) || is_dir( $absolute ) ) {
				$real = realpath( $absolute );
				if ( ! $real ) {
					return null;
				}
				$canonical = str_replace( '\\', '/', $real );
			}
		}

		if ( ! self::is_within_allowed_roots( $canonical ) ) {
			return null;
		}

		// Compute relative path from WordPress root.
		$wp_root  = self::root();
		$relative = $canonical;
		if ( 0 === strpos( $canonical, $wp_root . '/' ) ) {
			$relative = substr( $canonical, strlen( $wp_root ) + 1 );
		} else {
			// File is in an external allowed root (temp dir, etc.).
			$relative = ltrim( $path, '/' );
		}

		// Determine component.
		$component = self::detect_component( $canonical );

		return array(
			'canonical' => $canonical,
			'relative'  => $relative,
			'component' => $component,
		);
	}

	/**
	 * Detect the WordPress component type for a given canonical path.
	 *
	 * @param string $canonical Canonical file path.
	 * @return string Component identifier.
	 */
	public static function detect_component( $canonical ) {
		$mu_root = defined( 'WPMU_PLUGIN_DIR' ) ? realpath( WPMU_PLUGIN_DIR ) : realpath( WP_CONTENT_DIR . '/mu-plugins' );
		if ( $mu_root && 0 === strpos( $canonical, str_replace( '\\', '/', $mu_root ) . '/' ) ) {
			return 'mu_plugin';
		}

		$plugin_root = realpath( WP_PLUGIN_DIR );
		if ( $plugin_root && 0 === strpos( $canonical, str_replace( '\\', '/', $plugin_root ) . '/' ) ) {
			return 'plugin';
		}

		$theme_root = function_exists( 'get_theme_root' ) ? realpath( get_theme_root() ) : null;
		if ( $theme_root && 0 === strpos( $canonical, str_replace( '\\', '/', $theme_root ) . '/' ) ) {
			return 'theme';
		}

		$uploads = wp_upload_dir();
		$up_root = ! empty( $uploads['basedir'] ) ? realpath( $uploads['basedir'] ) : null;
		if ( $up_root && 0 === strpos( $canonical, str_replace( '\\', '/', $up_root ) . '/' ) ) {
			return 'uploads';
		}

		$content_root = realpath( WP_CONTENT_DIR );
		if ( $content_root ) {
			$content_norm = str_replace( '\\', '/', $content_root );
			// Drop-ins live directly in wp-content.
			$dropins = array( 'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'sunrise.php', 'fatal-error-handler.php' );
			if ( dirname( $canonical ) === $content_norm && in_array( basename( $canonical ), $dropins, true ) ) {
				return 'dropin';
			}
		}

		// Root config files.
		$wp_root      = self::root();
		$root_configs = array( 'wp-config.php', '.htaccess', 'wp-config-sample.php' );
		if ( dirname( $canonical ) === $wp_root && in_array( basename( $canonical ), $root_configs, true ) ) {
			return 'config';
		}

		return 'core';
	}

	/**
	 * Validate that a path is a regular file inside allowed roots.
	 *
	 * @param string $path Path.
	 * @return string|null Canonical path or null.
	 */
	public static function regular_file( $path ) {
		$resolved = self::validate( $path, true );
		if ( ! $resolved ) {
			return null;
		}
		$canonical = $resolved['canonical'];
		if ( ! is_file( $canonical ) || is_link( $canonical ) ) {
			return null;
		}
		return $canonical;
	}
}
