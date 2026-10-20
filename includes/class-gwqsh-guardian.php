<?php
/**
 * Guardian lifecycle. Installed code has no dependency on this class.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Install, verify and remove only the Guardian owned by this site. */
final class GWQSH_Guardian {
	const NAME = '000000-gracewell-guardian.php';

	/**
	 * Resolve WordPress's configured MU root.
	 */
	public static function root() {
		return defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
	}

	/**
	 * Use the existing site-specific private quarantine location, outside webroot.
	 */
	public static function state_dir() {
		$hash = substr( hash_hmac( 'sha256', home_url(), wp_salt( 'auth' ) ), 0, 20 );
		return rtrim( realpath( get_temp_dir() ) ? realpath( get_temp_dir() ) : get_temp_dir(), '/\\' ) . '/gwqsh-quarantine-' . $hash;
	}

	/** Ensure private state cannot be placed below a public document root. */
	public static function state_dir_is_private() {
		$state = self::state_dir();
		if ( ! is_string( $state ) || '' === $state || is_link( $state ) ) {
			return false;
		}
		$state_root = realpath( dirname( $state ) );
		if ( ! $state_root ) {
			return false;
		}
		$state_root = rtrim( str_replace( '\\', '/', $state_root ), '/' );
		$public_roots = array( ABSPATH, WP_CONTENT_DIR );
		if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) && is_string( $_SERVER['DOCUMENT_ROOT'] ) ) {
			$public_roots[] = wp_unslash( $_SERVER['DOCUMENT_ROOT'] );
		}
		foreach ( $public_roots as $root ) {
			$real = realpath( $root );
			if ( $real ) {
				$real = rtrim( str_replace( '\\', '/', $real ), '/' );
				if ( $state_root === $real || 0 === strpos( $state_root, $real . '/' ) ) {
					return false;
				}
			}
		}
		return true;
	}

	/**
	 * Generate standalone PHP from trusted plugin sources only.
	 *
	 * @param mixed $state State.
	 */
	public static function source( $state = '' ) {
		$state    = $state ? $state : self::state_dir();
		$runtime  = @file_get_contents( GWQSH_PATH . 'includes/class-gwqsh-security-runtime.php' );
		$template = @file_get_contents( GWQSH_PATH . 'includes/guardian-template.php' );
		return "<?php\n// Gracewell-owned Early Guardian v" . GWQSH_Security_Runtime::VERSION . ".\ndefined( 'ABSPATH' ) || exit;\n" .
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Serialize a path as a safe PHP literal in the generated Guardian; no debug output.
			"if ( ! defined( 'GWQSH_GUARDIAN_STATE' ) ) { define( 'GWQSH_GUARDIAN_STATE', " . var_export( $state, true ) . " ); }\n" . str_replace( 'GWQSH_Security_Runtime', 'GWQSH_Early_Runtime', substr( $runtime, 5 ) . substr( $template, 5 ) );
	}

	/**
	 * Failures are visible in backend state, without breaking WordPress.
	 *
	 * @throws RuntimeException Caught locally if installation fails.
	 */
	public static function install() {
		try {
			$root = self::root();
			if ( is_link( $root ) || ( ! is_dir( $root ) && ! wp_mkdir_p( $root ) ) || ! self::state_dir_is_private() || ! GWQSH_Security_Runtime::protect( self::state_dir() ) ) {
				throw new RuntimeException( 'Guardian directories unavailable' );
			}
			$file = $root . '/' . self::NAME;
			$body = self::source();
			if ( is_link( $file ) || ( file_exists( $file ) && strpos( (string) @file_get_contents( $file, false, null, 0, 100 ), '// Gracewell-owned Early Guardian v' ) === false ) ) {
				throw new RuntimeException( 'Guardian filename is owned by another file' );
			}
			if ( ! file_exists( $file ) || hash_file( 'sha256', $file ) !== hash( 'sha256', $body ) ) {
				$temp = $root . '/.' . bin2hex( random_bytes( 12 ) ) . '.tmp';
				// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				if ( @file_put_contents( $temp, $body, LOCK_EX ) !== strlen( $body ) || ! @rename( $temp, $file ) ) {
					throw new RuntimeException( 'Guardian install failed' );
				}
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				@chmod( $file, 0644 );
			}
			$ok = GWQSH_Security_Runtime::safe_path( $file, $root ) && hash_file( 'sha256', $file ) === hash( 'sha256', $body );
			update_option(
				'gwqsh_guardian_status',
				array(
					'active'  => (bool) $ok,
					'version' => GWQSH_Security_Runtime::VERSION,
					'time'    => time(),
				),
				false
			);
			if ( $ok ) {
				self::baseline();
			}
			return (bool) $ok;
		} catch ( Throwable $error ) {
			update_option(
				'gwqsh_guardian_status',
				array(
					'active' => false,
					'error'  => 'Local installation unavailable',
					'time'   => time(),
				),
				false
			);
			return false;
		}
	}

	/**
	 * Verify on admin requests and upgrades, not every frontend request.
	 */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'install' ) );
		add_action( 'admin_init', array( __CLASS__, 'events' ), 20 );
		add_action( 'upgrader_process_complete', array( __CLASS__, 'install' ), 20 );
		if ( ! get_option( 'gwqsh_guardian_status' ) ) {
			self::install();
		}
	}

	/**
	 * Removal always precedes data-retention decisions. Quarantined originals remain.
	 */
	public static function remove() {
		$file = self::root() . '/' . self::NAME;
		$ok   = ! file_exists( $file );
		if ( GWQSH_Security_Runtime::safe_path( $file, self::root() ) && is_file( $file ) && strpos( (string) @file_get_contents( $file, false, null, 0, 100 ), '// Gracewell-owned Early Guardian v' ) !== false ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			$ok = @unlink( $file );
		}
		update_option(
			'gwqsh_guardian_status',
			array(
				'active' => ! $ok,
				'error'  => $ok ? '' : 'Removal failed',
				'time'   => time(),
			),
			false
		);
		return $ok;
	}
	/**
	 * Snapshot only bounded, inspected non-Critical MU files on first installation.
	 * This is change evidence, never an allowlist that bypasses early analysis.
	 */
	private static function baseline() {
		$state = self::state_dir();
		$file  = $state . '/mu-baseline.json';
		if ( file_exists( $file ) ) {
			return;
		}
		$manifest = array();
		$count    = 0;
		foreach ( new DirectoryIterator( self::root() ) as $item ) {
			if ( $item->isDot() || 'php' !== $item->getExtension() || self::NAME === $item->getFilename() ) {
				continue;
			}
			if ( ++$count > 128 || $item->isLink() || ! $item->isFile() || ! is_readable( $item->getPathname() ) || $item->getSize() > GWQSH_Security_Runtime::LIMIT ) {
				return;
			}
			$content = @file_get_contents( $item->getPathname(), false, null, 0, GWQSH_Security_Runtime::LIMIT );
			$result  = GWQSH_Malware_Analyzer::analyze( $content, $item->getPathname(), 'Plugin' );
			if ( $result['score'] >= 80 || ! empty( $result['analysis_partial'] ) ) {
				return;
			}
			$manifest[ $item->getFilename() ] = array(
				'hash' => hash( 'sha256', $content ),
				'size' => strlen( $content ),
				'time' => time(),
			);
		}
		GWQSH_Security_Runtime::atomic_write(
			$file,
			wp_json_encode(
				array(
					'version' => 1,
					'files'   => $manifest,
					'time'    => time(),
				)
			)
		);
	}

	/** Revalidate a bounded early detection before publishing an actionable finding.
	 *
	 * @param string $state Private Guardian storage.
	 */
	private static function review_detection( $state ) {
		$file = GWQSH_Security_Runtime::safe_path( $state . '/guardian-health.json', $state );
		if ( ! $file || ! is_file( $file ) || filesize( $file ) > 8192 ) {
			return;
		}
		$event = json_decode( (string) file_get_contents( $file ), true );
		if ( ! is_array( $event ) || 'review_required' !== ( $event['decision'] ?? '' ) || ! is_string( $event['original'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_.-]+\.php$/D', $event['original'] ) || ! is_string( $event['hash'] ?? null ) || ! preg_match( '/^[a-f0-9]{64}$/D', $event['hash'] ) ) {
			return;
		}
		$source = GWQSH_Security_Runtime::safe_path( self::root() . '/' . $event['original'], self::root() );
		if ( ! $source || ! is_file( $source ) || filesize( $source ) > GWQSH_Security_Runtime::LIMIT ) {
			return;
		}
		$content = file_get_contents( $source, false, null, 0, GWQSH_Security_Runtime::LIMIT + 1 );
		if ( false === $content || ! hash_equals( $event['hash'], hash( 'sha256', $content ) ) ) {
			return;
		}
		$result = GWQSH_Security_Runtime::analyze( $content );
		$path   = GWQSH_Scan_Engine::label( $source );
		if ( ! $path || $result['score'] < 95 || ! $result['auto_block'] ) {
			return;
		}
		GWQSH_Scan_Engine::finding( $path, 'Plugin', 'Suspicious', 'Early Guardian detection; administrator review required.', array( 'hash' => $event['hash'], 'severity' => 'Critical', 'confidence' => 'Very High', 'decision' => 'review_required', 'evidence' => $result['rules'] ) );
		if ( 1 === GWQSH_Enterprise_Store::hit( 'guardian-review', $event['hash'], DAY_IN_SECONDS ) ) {
			GWQSH_Activity_Logger::log( 'Suspicious file requires review', 'Early Guardian detected a high-confidence pattern; no source file was modified.', 'Security' );
		}
	}

	/** Ingest verified event sidecars once, with only rule IDs and hashes.
	 *
	 * @param bool $cleanup Whether explicitly opted-in uninstall should delete owned records.
	 */
	public static function events( $cleanup = false ) {
		if ( $cleanup || ! class_exists( 'GWQSH_Quarantine_Manager' ) ) {
			return self::events_locked( $cleanup );
		}
		return GWQSH_Quarantine_Manager::synchronize(
			static function () {
				return self::events_locked( false );
			}
		);
	}

	/** Import bounded Guardian events under the shared metadata lock.
	 *
	 * @param bool $cleanup Whether lifecycle cleanup was requested.
	 */
	private static function events_locked( $cleanup = false ) {
		$state = self::state_dir();
		if ( ! GWQSH_Security_Runtime::safe_path( $state . '/index.php', $state ) ) {
			return;
		}
		if ( ! $cleanup ) {
			self::review_detection( $state );
		}
		$metadata = (array) get_option( 'gwqsh_quarantine_metadata', array() );
		$count    = 0;
		foreach ( new DirectoryIterator( $state ) as $item ) {
			if ( ++$count > 1000 ) {
				break;
			}
			if ( $item->isLink() || ! $item->isFile() || $item->getSize() > 8192 || ! preg_match( '/^([a-f0-9]{32})\.json$/D', $item->getFilename(), $match ) ) {
				continue;
			}
			$id       = $match[1];
			$artifact = $state . '/' . $id . '.quarantine';
			$event    = json_decode( @file_get_contents( $item->getPathname() ), true );
			if ( ! is_array( $event ) || ! isset( $event['id'], $event['original'], $event['hash'], $event['rules'], $event['decision'] ) || $id !== $event['id'] || ! preg_match( '/^[a-f0-9]{64}$/D', $event['hash'] ) || ! is_array( $event['rules'] ) || ! GWQSH_Security_Runtime::safe_path( $artifact, $state ) || hash_file( 'sha256', $artifact ) !== $event['hash'] ) {
				continue;
			}
			if ( $cleanup ) {
				wp_delete_file( $artifact );
				wp_delete_file( $item->getPathname() );
				continue;
			}
			if ( 'blocked' !== $event['decision'] || isset( $metadata[ $id . '.quarantine' ] ) || preg_match( '#(^|/)\.{1,2}(/|$)|[:\\\\\x00]#', $event['original'] ) ) {
				continue;
			}
			$path = GWQSH_Scan_Engine::label( self::root() . '/' . $event['original'] );
			if ( ! $path ) {
				continue;
			}
			$rules = array_intersect( $event['rules'], array( 'request_execution', 'encoded_execution', 'remote_php_write', 'locked_root_restoration', 'remote_bot_gate' ) );
			GWQSH_Scan_Engine::finding(
				$path,
				'Plugin',
				'Suspicious',
				'Early Guardian blocked MU file: ' . implode( ', ', $rules ),
				array(
					'severity'   => 'Critical',
					'confidence' => 'Very High',
					'hash'       => $event['hash'],
					'quarantine' => $id,
					'decision'   => 'blocked',
					'evidence'   => $rules,
				)
			);
			global $wpdb;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$event['finding_id'] = (int) $wpdb->get_var( $wpdb->prepare( 'SELECT id FROM ' . $wpdb->prefix . 'gwqsh_scan_results WHERE file_path=%s AND is_resolved=0 LIMIT 1', $path ) );
			$event['status']     = 'quarantined';
			$event['reason']     = 'early_guardian';
			$event['component']  = 'mu_plugin';
			$event['file_type']  = 'Plugin';
			$event['severity']   = 'Critical';
			$event['confidence'] = 'Very High';
			$event['score']      = 100;
			$event['size']       = filesize( $artifact );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
			$wpdb->update(
				$wpdb->prefix . 'gwqsh_scan_results',
				array(
					'status'      => 'Quarantined',
					'is_resolved' => 1,
				),
				array( 'id' => $event['finding_id'] )
			);
			$event['original']               = ltrim( $path, '/' );
			$metadata[ $id . '.quarantine' ] = $event;
		}
		if ( ! $cleanup ) {
			update_option( 'gwqsh_quarantine_metadata', $metadata, false );
		}
	}
}
