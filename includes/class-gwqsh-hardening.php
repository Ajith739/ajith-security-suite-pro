<?php
/**
 * Real WordPress security hardening modules for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Hardening implementation.
 */
final class GWQSH_Hardening {

	private const OPTION_KEY = 'gwqsh_hardening';
	/**
	 * Get defaults.
	 */
	public static function get_defaults() {
		return array(
			'xmlrpc'  => true,
			'editor'  => true,
			'version' => true,
			'enum'    => true,
			'headers' => false,
			'uploads' => true,
		);
	}
	/**
	 * Get all.
	 */
	public static function get_all() {
		$saved = get_option( self::OPTION_KEY, array() );
		if ( ! is_array( $saved ) ) {
			$saved = array();
		}
		return array_map( 'boolval', array_intersect_key( wp_parse_args( $saved, self::get_defaults() ), self::get_defaults() ) );
	}
	/**
	 * Get checks.
	 */
	public static function get_checks() {
		return GWQSH_Hardening_Data::checks(); }

	/**
	 * Get risk.
	 */
	public static function get_risk() {
		$weights = array(
			'xmlrpc'  => 15,
			'editor'  => 15,
			'version' => 10,
			'enum'    => 15,
			'headers' => 33,
			'uploads' => 12,
		);
		$checks  = self::get_checks();
		$score   = 0;
		foreach ( $weights as $key => $weight ) {
			if ( ! empty( $checks[ $key ] ) ) {
				$score += $weight; }
		}
		return array(
			'score'  => $score,
			'passed' => count( array_filter( $checks ) ),
			'failed' => count( $checks ) - count( array_filter( $checks ) ),
			'level'  => $score >= 85 ? 'Low' : ( $score >= 60 ? 'Medium' : ( $score >= 35 ? 'High' : 'Critical' ) ),
		);
	}
	/**
	 * Is enabled.
	 *
	 * @param mixed $feature Feature.
	 */
	public static function is_enabled( $feature ) {
		$all = self::get_all();
		return ! empty( $all[ $feature ] );
	}
	/**
	 * Set.
	 *
	 * @param mixed $feature Feature.
	 * @param mixed $enabled Enabled.
	 */
	public static function set( $feature, $enabled ) {
		if ( ! array_key_exists( $feature, self::get_defaults() ) ) {
			return false; }
		$all             = self::get_all();
		$all[ $feature ] = (bool) $enabled;
		if ( ! self::persist_change( $all, false, 'uploads' === $feature ) ) {
			return false; }

		$names = array(
			'xmlrpc'  => 'Disable XML-RPC',
			'editor'  => 'Disable file editor',
			'version' => 'Hide WordPress version',
			'enum'    => 'Block user enumeration',
			'headers' => 'Security headers',
			'uploads' => 'Block PHP in uploads',
		);
		$name  = isset( $names[ $feature ] ) ? $names[ $feature ] : $feature;
		GWQSH_Activity_Logger::log(
			$enabled ? 'Hardening enabled' : 'Hardening disabled',
			sprintf( '%s was turned %s', $name, $enabled ? 'on' : 'off' ),
			'System'
		);

		return true;
	}
	/**
	 * Reset defaults.
	 */
	public static function reset_defaults() {
		if ( ! self::persist_change( self::get_defaults(), true, true ) ) {
			return false; }
		GWQSH_Activity_Logger::log( 'Hardening reset', 'Hardening options restored to default values', 'System' );
		return true;
	}
	/**
	 * Revert all.
	 */
	public static function revert_all() {
		if ( ! self::persist_change( array_fill_keys( array_keys( self::get_defaults() ), false ), true, true ) ) {
			return false; }
		GWQSH_Activity_Logger::log( 'Hardening reverted', 'All hardening features disabled', 'System' );
		return true;
	}
	/** Persist settings before touching files, restoring prior settings on failure.
	 *
	 * @param array $new New six-control configuration.
	 * @param bool  $reset_csp Whether to disable custom CSP.
	 * @param bool  $sync Whether uploads rules require synchronization.
	 * @return bool Persistence and file result.
	 */
	private static function persist_change( $new, $reset_csp, $sync ) {
		$old    = self::get_all();
		$csp    = GWQSH_Hardening_Data::csp();
		$backup = array(
			'settings' => $old,
			'csp'      => $csp,
		);
		update_option( 'gwqsh_hardening_settings_backup', $backup, false );
		if ( get_option( 'gwqsh_hardening_settings_backup' ) !== $backup ) {
			return false; }
		update_option( self::OPTION_KEY, $new );
		if ( self::get_all() !== $new ) {
			return false; }
		if ( $reset_csp ) {
			$off = array(
				'mode'   => 'off',
				'policy' => '',
			);
			update_option( 'gwqsh_hardening_csp', $off, false );
			if ( GWQSH_Hardening_Data::csp() !== $off ) {
				update_option( self::OPTION_KEY, $old );
				update_option( 'gwqsh_hardening_csp', $csp, false );
				return false;
			}
		}
		if ( $sync && ! self::sync_uploads_protection( $new['uploads'] ) ) {
			update_option( self::OPTION_KEY, $old );
			update_option( 'gwqsh_hardening_csp', $csp, false );
			GWQSH_Activity_Logger::log( 'Hardening change failed', 'Uploads rule synchronization failed; prior plugin settings were restored where persistence allowed. Review the filesystem before retrying.', 'System' );
			return false;
		}
		delete_transient( 'gwqsh_hardening_evidence' );
		return true;
	}
	/**
	 * Init.
	 */
	public static function init() {

		add_filter( 'xmlrpc_enabled', array( __CLASS__, 'xmlrpc_enabled' ) );
		add_filter( 'the_generator', array( __CLASS__, 'generator' ) );
		add_filter( 'wp_headers', array( __CLASS__, 'remove_pingback_header' ) );
		add_action( 'init', array( __CLASS__, 'block_xmlrpc_requests' ), 1 );
		add_filter( 'user_has_cap', array( __CLASS__, 'remove_editor_caps' ), 10, 3 );
		add_filter( 'script_loader_src', array( __CLASS__, 'remove_version_param' ), 99 );
		add_filter( 'style_loader_src', array( __CLASS__, 'remove_version_param' ), 99 );
		add_action( 'template_redirect', array( __CLASS__, 'block_author_scan' ), 1 );
		add_filter( 'rest_endpoints', array( __CLASS__, 'restrict_rest_users' ) );
		add_action( 'send_headers', array( __CLASS__, 'send_security_headers' ), 99 );
		add_filter( 'wp_handle_upload_prefilter', array( __CLASS__, 'guard_upload' ) );
		add_filter( 'wp_handle_sideload_prefilter', array( __CLASS__, 'guard_upload' ) );
	}
	/** Runtime configuration guards allow safe changes on the next request without duplicate hooks.
	 *
	 * @param string $feature Control key.
	 */
	public static function active( $feature ) {
		return GWQSH_Settings::is_active() && self::is_enabled( $feature );
	}
	/** XML-RPC authentication policy.
	 *
	 * @param bool $enabled Existing policy.
	 */
	public static function xmlrpc_enabled( $enabled ) {
		return self::active( 'xmlrpc' ) ? false : $enabled;
	}
	/** Generator visibility.
	 *
	 * @param string $generator Existing generator.
	 */
	public static function generator( $generator ) {
		return self::active( 'version' ) ? '' : $generator;
	}
	/** Conditional native upload filtering.
	 *
	 * @param array $file Native upload payload.
	 */
	public static function guard_upload( $file ) {
		return self::active( 'uploads' ) ? self::inspect_upload( $file ) : $file; }

	/*
	-------------------------------------------------------------
		Feature Hook Callbacks
		-------------------------------------------------------------
	 */
	/**
	 * Remove pingback header.
	 *
	 * @param mixed $headers Headers.
	 */
	public static function remove_pingback_header( $headers ) {
		if ( self::active( 'xmlrpc' ) ) {
			unset( $headers['X-Pingback'] ); }
		return $headers;
	}
	/**
	 * Block xmlrpc requests.
	 */
	public static function block_xmlrpc_requests() {
		$uri = isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
		if ( self::active( 'xmlrpc' ) && ( ( defined( 'XMLRPC_REQUEST' ) && XMLRPC_REQUEST ) || preg_match( '~(?:^|/)xmlrpc\.php$~i', (string) wp_parse_url( $uri, PHP_URL_PATH ) ) ) ) {
			GWQSH_Activity_Logger::log( 'XML-RPC access blocked', 'XML-RPC request denied by the configured hardening rule.', 'Security' );
			status_header( 403 );
			exit( 'XML-RPC is disabled on this site.' );
		}
	}
	/**
	 * Remove editor caps.
	 *
	 * @param mixed $allcaps Allcaps.
	 * @param mixed $caps Caps.
	 * @param mixed $args Args.
	 */
	public static function remove_editor_caps( $allcaps, $caps, $args ) {
		if ( ! self::active( 'editor' ) ) {
			return $allcaps;
		}
		$allcaps['edit_themes']  = false;
		$allcaps['edit_plugins'] = false;
		$allcaps['edit_files']   = false;
		return $allcaps;
	}
	/**
	 * Remove version param.
	 *
	 * @param mixed $src Src.
	 */
	public static function remove_version_param( $src ) {
		$path  = (string) wp_parse_url( $src, PHP_URL_PATH );
		$core  = (string) wp_parse_url( includes_url(), PHP_URL_PATH );
		$admin = (string) wp_parse_url( admin_url(), PHP_URL_PATH );
		if ( self::active( 'version' ) && ( 0 === strpos( $path, $core ) || 0 === strpos( $path, $admin ) ) && (string) get_bloginfo( 'version' ) === (string) self::asset_version( $src ) ) {
			$src = remove_query_arg( 'ver', $src );
		}
		return $src;
	}
	/**
	 * Block author scan.
	 */
	public static function block_author_scan() {
		if ( ! self::active( 'enum' ) || is_admin() || is_user_logged_in() ) {
			return;
		}

		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only public author-enumeration routing check; no settings or data are changed.
		if ( isset( $_REQUEST['author'] ) && is_numeric( $_REQUEST['author'] ) ) {
			wp_safe_redirect( home_url(), 301 );
			exit;
		}
	}
	/**
	 * Restrict rest users.
	 *
	 * @param mixed $endpoints Endpoints.
	 */
	public static function restrict_rest_users( $endpoints ) {
		if ( ! self::active( 'enum' ) || is_user_logged_in() ) {
			return $endpoints;
		}

		if ( isset( $endpoints['/wp/v2/users'] ) ) {
			unset( $endpoints['/wp/v2/users'] );
		}
		if ( isset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] ) ) {
			unset( $endpoints['/wp/v2/users/(?P<id>[\d]+)'] );
		}

		return $endpoints;
	}
	/**
	 * Send security headers.
	 */
	public static function send_security_headers() {
		GWQSH_Hardening_Data::emit_headers(); }

	/**
	 * Sync uploads protection.
	 *
	 * @param mixed $enable Enable.
	 */
	public static function sync_uploads_protection( $enable ) {
		return GWQSH_Hardening_Rules::sync( (bool) $enable ); }

	/**
	 * Reject executable extensions or actual PHP tags through existing uploads hardening.
	 *
	 * @param mixed $file File.
	 */
	public static function inspect_upload( $file ) {
		if ( ! empty( $file['error'] ) ) {
			return $file;
		}
		$name = isset( $file['name'] ) ? $file['name'] : '';
		if ( preg_match( '/\.(?:php[0-9]?|phtml|phps|phar|inc)(?:\.|$|[ .]+$)/i', $name ) ) {
			$file['error'] = 'Executable uploads are blocked by Gracewell.';
			return $file;
		}
		$temp = isset( $file['tmp_name'] ) ? $file['tmp_name'] : '';
		if ( is_file( $temp ) && ! is_link( $temp ) && is_readable( $temp ) ) {
			$content = file_get_contents( $temp, false, null, 0, GWQSH_Security_Runtime::LIMIT );
			if ( is_string( $content ) && GWQSH_Malware_Analyzer::has_php( $content ) ) {
				$file['error'] = 'Executable PHP content is blocked by Gracewell.';
			}
		}
		return $file;
	}
	/** Read only the version query argument; preserve plugin cache keys.
	 *
	 * @param string $src Asset URL.
	 */
	public static function asset_version( $src ) {
		$query = array();
		parse_str( (string) wp_parse_url( $src, PHP_URL_QUERY ), $query );
		return isset( $query['ver'] ) && is_scalar( $query['ver'] ) ? $query['ver'] : ''; }
}
