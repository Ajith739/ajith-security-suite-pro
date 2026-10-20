<?php
/** Central hardening assessment, CSP and explicit same-site verification.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Distinguishes configured controls from runtime evidence. */
final class GWQSH_Hardening_Data {
	const WEIGHTS = array(
		'xmlrpc'  => 15,
		'editor'  => 15,
		'version' => 10,
		'enum'    => 15,
		'headers' => 33,
		'uploads' => 12,
	);
	const NAMES   = array(
		'xmlrpc'  => 'Disable XML-RPC',
		'editor'  => 'Disable file editor',
		'version' => 'Hide WordPress version',
		'enum'    => 'Block user enumeration',
		'headers' => 'Security headers',
		'uploads' => 'Block PHP in uploads',
	);
	/** Configured browser headers. Existing headers are preserved during emission. */
	public static function expected_headers() {
		return array(
			'X-Content-Type-Options' => 'nosniff',
			'X-Frame-Options'        => 'SAMEORIGIN',
			'Referrer-Policy'        => 'strict-origin-when-cross-origin',
		); }
	/** Evidence cache is invalidated by configuration changes, site URL and server changes. */
	public static function fingerprint() {
		return hash( 'sha256', wp_json_encode( array( GWQSH_Hardening::get_all(), self::csp(), GWQSH_Settings::is_active(), home_url( '/' ), GWQSH_Hardening_Rules::server(), GWQSH_Hardening_Rules::inspect() ) ) ); }
	/** Return only recent evidence for the current configuration. */
	public static function evidence() {
		$e = get_transient( 'gwqsh_hardening_evidence' );
		return $e && isset( $e['fingerprint'] ) && hash_equals( self::fingerprint(), $e['fingerprint'] ) ? $e : array();
	}
	/** Assess six controls without network calls or filesystem writes. */
	public static function assessment() {
		$all    = GWQSH_Hardening::get_all();
		$active = GWQSH_Settings::is_active();
		$e      = self::evidence();
		$rules  = GWQSH_Hardening_Rules::inspect();
		$checks = array(
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Inspect the existing WordPress core filter.
			'xmlrpc'  => false === apply_filters( 'xmlrpc_enabled', true ) && false !== has_action( 'init', array( 'GWQSH_Hardening', 'block_xmlrpc_requests' ) ),
			'editor'  => false === ( GWQSH_Hardening::remove_editor_caps( array( 'edit_plugins' => true ), array(), array() )['edit_plugins'] ),
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedHooknameFound -- Inspect the existing WordPress core filter.
			'version' => '' === apply_filters( 'the_generator', 'WordPress generator' ) && false !== has_filter( 'script_loader_src', array( 'GWQSH_Hardening', 'remove_version_param' ) ),
			'enum'    => false !== has_filter( 'rest_endpoints', array( 'GWQSH_Hardening', 'restrict_rest_users' ) ) && false !== has_action( 'template_redirect', array( 'GWQSH_Hardening', 'block_author_scan' ) ),
			'headers' => ! empty( $e['headers_pass'] ),
			'uploads' => $rules['owned'] && 'Apache' === GWQSH_Hardening_Rules::server() && ! empty( $e['uploads_pass'] ),
		);
		$rows   = array();
		$score  = 0;
		$passed = 0;
		foreach ( self::NAMES as $k => $name ) {
			$configured = ! empty( $all[ $k ] );
			$effective  = $active && $configured && $checks[ $k ];
			$status     = ! $configured ? 'Disabled' : ( ! $active ? 'Plugin disabled' : ( $effective ? 'Enabled' : 'Verification Pending' ) );
			$note       = 'Verified in WordPress hooks; external caches and other plugins may affect public responses.';
			if ( 'editor' === $k ) {
				$note = 'WordPress editor capabilities are denied. wp-config.php is untouched. External DISALLOW_FILE_EDIT restrictions cannot be reverted here.'; }
			if ( 'enum' === $k ) {
				$note = 'Anonymous numeric author probes and users REST routes are restricted; authenticated REST and named author archives remain available.'; }
			if ( 'version' === $k ) {
				$note = 'Generator output and exact core version query values are removed. Other asset cache versions remain intact; this is a minor disclosure reduction.'; }
			if ( 'xmlrpc' === $k ) {
				$note = 'Authentication filter plus the exact XML-RPC request blocker. This can interrupt Jetpack, remote publishing and mobile clients.'; }
			if ( 'headers' === $k ) {
				$note = 'Configured values are not proof of emitted headers. Verify an uncached public response; existing headers are preserved.';
				if ( $configured && isset( $e['headers_pass'] ) && ! $e['headers_pass'] ) {
					$status = 'Partially Applied'; }
			}
			if ( 'uploads' === $k ) {
				$note = $rules['message'] . ' Web-server denial needs a separate HTTP probe; upload filtering alone does not block direct PHP execution.';
				if ( $configured && $active && 'Apache' !== GWQSH_Hardening_Rules::server() ) {
					$status = 'Manual Configuration Required'; } elseif ( $configured && ! $rules['safe'] ) {
					$status = 'Failed'; } elseif ( $configured && ! $effective ) {
						$status = $rules['owned'] ? 'Verification Pending' : 'Partially Applied'; }
			}
			$rows[ $k ] = array(
				'name'       => $name,
				'configured' => $configured,
				'effective'  => $effective,
				'status'     => $status,
				'note'       => $note,
				'weight'     => self::WEIGHTS[ $k ],
			);
			if ( $effective ) {
				$score += self::WEIGHTS[ $k ];
				++$passed; }
		}
		return array(
			'rows'    => $rows,
			'score'   => $score,
			'passed'  => $passed,
			'pending' => 6 - $passed,
			'level'   => $score >= 85 ? 'Low' : ( $score >= 60 ? 'Medium' : ( $score >= 35 ? 'High' : 'Critical' ) ),
		);
	}
	/** Compatibility provider for completed pages. */
	public static function checks() {
		$a = self::assessment();
		return array_map(
			static function ( $row ) {
				return $row['effective'];
			},
			$a['rows']
		); }
	/** One page snapshot; permission checked by admin/controller. */
	public static function get() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Permission denied.' ); }
		$a          = self::assessment();
		$components = GWQSH_Admin::get_score_components();
		$all        = GWQSH_Hardening::get_all();
		$apache     = '# Generated guidance; not applied to the site root. Review existing headers first.' . "\n";
		if ( ! empty( $all['headers'] ) ) {
			$apache .= "<IfModule mod_headers.c>\n";
			foreach ( self::expected_headers() as $name => $value ) {
				$apache .= '    Header always set ' . $name . ' "' . $value . '"' . "\n";
			} $apache .= "</IfModule>\n"; }
		if ( ! empty( $all['uploads'] ) ) {
			$apache .= "\n# Place ONLY in the WordPress uploads directory:\n" . GWQSH_Hardening_Rules::block(); }
		$uploads = wp_upload_dir( null, false );
		$path    = (string) wp_parse_url( $uploads['baseurl'], PHP_URL_PATH );
		$nginx   = "# Manual deployment: add within your site's server block.\n# Review location ordering and existing headers; avoid duplicates.
# Run nginx -t, then reload.\n";
		if ( ! empty( $all['xmlrpc'] ) ) {
			$nginx .= 'location = ' . rtrim( (string) wp_parse_url( site_url(), PHP_URL_PATH ), '/' ) . "/xmlrpc.php { deny all; }\n"; }
		if ( ! empty( $all['uploads'] ) && preg_match( '~^/[A-Za-z0-9/_-]+$~', $path ) ) {
			$nginx .= 'location ~* "^' . preg_quote( rtrim( $path, '/' ), '~' ) . '/.*\\\\.(?:php[0-9]?|phtml|phps|phar|inc)(?:[. ]*)$" { deny all; }' . "\n"; }
		if ( ! empty( $all['headers'] ) ) {
			foreach ( self::expected_headers() as $name => $value ) {
				$nginx .= 'add_header ' . $name . ' "' . $value . '" always;' . "\n"; }
		}
		return array_merge(
			$a,
			array(
				'components'       => $components,
				'overall'          => GWQSH_Admin::score_from_components( $components ),
				'server'           => GWQSH_Hardening_Rules::server(),
				'apache'           => $apache,
				'nginx'            => $nginx,
				'expected_headers' => GWQSH_Hardening::active( 'headers' ) ? self::expected_headers() : array(),
				'evidence'         => self::evidence(),
				'csp'              => self::csp(),
				'defaults'         => GWQSH_Hardening::get_defaults(),
			)
		);
	}
	/** Report-only is the initial testing workflow; defaults are off. */
	public static function csp() {
		return wp_parse_args(
			(array) get_option( 'gwqsh_hardening_csp', array() ),
			array(
				'mode'   => 'off',
				'policy' => '',
			)
		); }
	/** Validate a bounded policy without accepting header injection.
	 *
	 * @param string $mode Off/report/enforce mode.
	 * @param string $policy Raw policy text.
	 * @param string $confirmed Enforcement confirmation.
	 * @return true|WP_Error Validation/persistence result.
	 */
	public static function save_csp( $mode, $policy, $confirmed ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Permission denied.' ); }
		if ( ! is_string( $policy ) || strlen( $policy ) > 2048 || preg_match( '/[\x00-\x1f\x7f]/', $policy ) || ! in_array( $mode, array( 'off', 'report', 'enforce' ), true ) ) {
			return new WP_Error( 'policy', 'Use a single-line policy of at most 2,048 bytes.' ); }
		$seen = array();
		foreach ( array_filter( array_map( 'trim', explode( ';', $policy ) ) ) as $directive ) {
			$tokens = preg_split( '/\s+/', $directive );
			$name   = array_shift( $tokens );
			if ( ! in_array( $name, array( 'default-src', 'script-src', 'style-src', 'img-src', 'connect-src', 'font-src', 'frame-ancestors' ), true ) || isset( $seen[ $name ] ) || ! $tokens ) {
				return new WP_Error( 'policy', 'Use supported directives once, with at least one valid source.' ); }
			foreach ( $tokens as $token ) {
				if ( ! in_array( $token, array( "'self'", "'none'", "'unsafe-inline'", "'unsafe-eval'", "'strict-dynamic'", '*', 'https:', 'data:', 'blob:' ), true ) && ! preg_match( '~^https://(?:\*\.)?[A-Za-z0-9.-]+(?::[0-9]{1,5})?(?:/[A-Za-z0-9/_.*-]*)?$~', $token ) ) {
					return new WP_Error( 'policy', 'Use supported quoted keywords, schemes or HTTPS sources.' ); }
			}
			if ( in_array( "'none'", $tokens, true ) && count( $tokens ) > 1 ) {
				return new WP_Error( 'policy', "'none' must be used alone." ); }
			$seen[ $name ] = true;
		}
		if ( 'off' !== $mode && ! $seen ) {
			return new WP_Error( 'policy', 'Enter a policy before enabling it.' ); }
		if ( 'enforce' === $mode && '1' !== $confirmed ) {
			return new WP_Error( 'confirmation', 'Explicitly confirm enforcement after report-only testing.' ); }
		$new = array(
			'mode'   => $mode,
			'policy' => trim( $policy ),
		);
		update_option( 'gwqsh_hardening_csp', $new, false );
		if ( self::csp() !== $new ) {
			return new WP_Error( 'save', 'Could not persist CSP.' ); }
		delete_transient( 'gwqsh_hardening_evidence' );
		GWQSH_Activity_Logger::log( 'CSP configuration changed', 'Public frontend policy mode: ' . $mode, 'System' );
		return true;
	}
	/** Preserve existing application/plugin headers, and never emit CSP in admin or REST. */
	public static function emit_headers() {
		if ( headers_sent() || ! GWQSH_Settings::is_active() ) {
			return; }
		$existing = array();
		foreach ( headers_list() as $header ) {
			$existing[ strtolower( trim( strtok( $header, ':' ) ) ) ] = true; }
		if ( GWQSH_Hardening::active( 'headers' ) ) {
			foreach ( self::expected_headers() as $name => $value ) {
				if ( ! isset( $existing[ strtolower( $name ) ] ) && ( 'X-Frame-Options' !== $name || ! isset( $existing['content-security-policy'] ) ) ) {
					header( $name . ': ' . $value ); }
			}
		}
		$csp = self::csp(); if ( ! is_admin() && ! ( defined( 'REST_REQUEST' ) && REST_REQUEST ) && 'off' !== $csp['mode'] && $csp['policy'] ) {
			$name = 'enforce' === $csp['mode'] ? 'Content-Security-Policy' : 'Content-Security-Policy-Report-Only';
			if ( ! isset( $existing['content-security-policy'] ) && ! isset( $existing['content-security-policy-report-only'] ) ) {
				header( $name . ': ' . $csp['policy'] ); }
		}
	}
	/** Write a same-site probe without following a pre-created symlink. */
	private static function write_probe( $path, $body ) {
		if ( ! is_string( $path ) || is_link( $path ) || file_exists( $path ) ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Exclusive local probe creation prevents symlink-following races.
		$handle = @fopen( $path, 'xb' );
		if ( ! $handle ) {
			return false;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Bounded inert local verification probe.
		$ok = fwrite( $handle, $body ) === strlen( $body ) && fflush( $handle );
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closes the exclusive local probe handle.
		fclose( $handle );
		if ( ! $ok || is_link( $path ) ) {
			if ( is_file( $path ) && ! is_link( $path ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_unlink -- Removes only the just-created inert probe.
				@unlink( $path );
			}
			return false;
		}
		return true;
	}
	/** Explicit verification only; fixed own-site target, no arbitrary URL or redirects.
	 *
	 * @return array|WP_Error Evidence/result.
	 */
	public static function verify() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Permission denied.' ); }
		$cooldown = 'gwqsh_hardening_probe_' . get_current_user_id();
		if ( get_transient( $cooldown ) ) {
			return new WP_Error( 'cooldown', 'Wait one minute before verifying again.' ); }
		set_transient( $cooldown, 1, MINUTE_IN_SECONDS );
		delete_transient( 'gwqsh_hardening_evidence' );
		$url  = home_url( '/' );
		$host = wp_parse_url( $url, PHP_URL_HOST );
		if ( ! in_array( wp_parse_url( $url, PHP_URL_SCHEME ), array( 'http', 'https' ), true ) || ! $host ) {
			return new WP_Error( 'url', 'The configured home URL is unsupported.' ); }
		$args     = array(
			'timeout'             => 5,
			'redirection'         => 0,
			'limit_response_size' => 2048,
			'sslverify'           => true,
			'headers'             => array( 'Cache-Control' => 'no-cache' ),
		);
		$response = wp_remote_get( add_query_arg( 'gwqsh_hardening_probe', wp_generate_password( 16, false ), $url ), $args );
		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'http', 'Could not verify a public HTTP 200 response. Check redirects, TLS and loopback access.' ); }
		$observed = array();
		$pass     = true;
		foreach ( self::expected_headers() as $name => $value ) {
			$observed[ $name ] = substr( sanitize_text_field( (string) wp_remote_retrieve_header( $response, $name ) ), 0, 256 );
			if ( $observed[ $name ] !== $value ) {
				$pass = false; }
		}
		$e       = array(
			'checked'      => current_time( 'mysql' ),
			'fingerprint'  => self::fingerprint(),
			'headers'      => $observed,
			'headers_pass' => $pass,
			'uploads_pass' => false,
			'upload_note'  => 'Uploads verification requires a writable same-origin uploads directory.',
		);
		$uploads = wp_upload_dir( null, false );
		$dir     = $uploads['basedir'];
		if ( GWQSH_Hardening::active( 'uploads' ) && wp_parse_url( $uploads['baseurl'], PHP_URL_HOST ) === $host && wp_parse_url( $uploads['baseurl'], PHP_URL_SCHEME ) === wp_parse_url( $url, PHP_URL_SCHEME ) && wp_parse_url( $uploads['baseurl'], PHP_URL_PORT ) === wp_parse_url( $url, PHP_URL_PORT ) && GWQSH_Hardening_Rules::path() && wp_is_writable( $dir ) ) {
			$name    = 'quietshield-probe-' . bin2hex( random_bytes( 12 ) );
			$php     = trailingslashit( $dir ) . $name . '.php';
			$control = trailingslashit( $dir ) . $name . '.txt';
			try {
				if ( self::write_probe( $php, 'Security Suite Pro inert access probe' ) && self::write_probe( $control, 'Security Suite Pro inert access probe' ) ) {
					$ok                = wp_remote_get( trailingslashit( $uploads['baseurl'] ) . $name . '.txt', $args );
					$denied            = wp_remote_get( trailingslashit( $uploads['baseurl'] ) . $name . '.php', $args );
					$e['uploads_pass'] = ! is_wp_error( $ok ) && ! is_wp_error( $denied ) && 200 === wp_remote_retrieve_response_code( $ok ) && 'Security Suite Pro inert access probe' === wp_remote_retrieve_body( $ok ) && 403 === wp_remote_retrieve_response_code( $denied );
					$e['upload_note']  = $e['uploads_pass'] ? 'HTTP sample: ordinary text delivered; .php access denied with 403. This verifies one path, not every handler or extension.' : 'Expected media HTTP 200 and PHP HTTP 403 were not observed. Review server rules/AllowOverride; no execution-blocking assurance is awarded.';
				}
			} finally {
				if ( file_exists( $php ) && ! is_link( $php ) ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
					if ( ! unlink( $php ) ) {
						$e['uploads_pass'] = false;
						$e['upload_note']  = 'Probe cleanup failed; review the uploads directory before retrying.'; }
				} if ( file_exists( $control ) && ! is_link( $control ) ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
					if ( ! unlink( $control ) ) {
						$e['uploads_pass'] = false;
						$e['upload_note']  = 'Probe cleanup failed; review the uploads directory before retrying.'; }
				}
			}
		}
		set_transient( 'gwqsh_hardening_evidence', $e, 5 * MINUTE_IN_SECONDS );
		GWQSH_Activity_Logger::log( 'Hardening verification completed', 'Fixed same-site HTTP checks completed; no authentication data was sent.', 'System' );
		return $e;
	}
}
