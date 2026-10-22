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

	/** Resolve configured durable storage without silently relocating existing evidence.
	 * GWQSH_PRIVATE_STORAGE_DIR is an operator-owned absolute base directory.
	 * Existing installations retain their legacy location unless explicitly configured.
	 */
	public static function state_dir() {
		$hash = substr( hash_hmac( 'sha256', home_url(), wp_salt( 'auth' ) ), 0, 20 );
		if ( defined( 'GWQSH_PRIVATE_STORAGE_DIR' ) ) {
			return is_string( GWQSH_PRIVATE_STORAGE_DIR ) && '' !== GWQSH_PRIVATE_STORAGE_DIR ? rtrim( GWQSH_PRIVATE_STORAGE_DIR, '/' ) . '/gwqsh-quarantine-' . $hash : '';
		}
		return rtrim( realpath( get_temp_dir() ) ? realpath( get_temp_dir() ) : get_temp_dir(), '/\\' ) . '/gwqsh-quarantine-' . $hash;
	}

	/** Validate the final destination and every existing ancestor, including missing parents.
	 * Additional vhost/alias document roots must be declared through GWQSH_PUBLIC_DOCUMENT_ROOTS.
	 * Unknown server aliases cannot be discovered safely from PHP.
	 *
	 * @param string $state Absolute candidate directory.
	 * @return bool Whether the candidate is outside every known public root.
	 */
	public static function private_path( $state ) {
		if ( ! is_string( $state ) || '' === $state || preg_match( '/[\x00-\x1f\x7f]/', $state ) || false !== strpos( $state, '://' ) ) {
			return false;
		}
		$windows = 'Windows' === PHP_OS_FAMILY;
		if ( $windows ) {
			$state = str_replace( '\\', '/', $state );
			// Only local absolute drives: no UNC, device namespaces, ADS or aliases.
			if ( ! preg_match( '#^[a-zA-Z]:/[^:]++$#D', $state ) || strpos( $state, '//') !== false || preg_match( '/[<>"|?*]/', $state ) ) { return false; }
			foreach ( explode( '/', substr( $state, 3 ) ) as $part ) {
				if ( '' !== $part && ( preg_match( '/[. ]$/D', $part ) || preg_match( '/^(?:CON|PRN|AUX|NUL|COM[1-9\x{00b9}\x{00b2}\x{00b3}]|LPT[1-9\x{00b9}\x{00b2}\x{00b3}])(?:\.|$)/iu', $part ) ) ) { return false; }
			}
		} elseif ( '/' !== substr( $state, 0, 1 ) || str_starts_with( $state, '//' ) || false !== strpos( $state, '\\' ) ) { return false; }
		if ( preg_match( '#(^|/)\.{1,2}(/|$)#', $state ) ) { return false; }
		$state = rtrim( $state, '/' );
		$probe = $state;
		while ( dirname( $probe ) !== $probe ) {
			if ( is_link( $probe ) || ( file_exists( $probe ) && ! is_dir( $probe ) ) ) {
				return false;
			}
			if ( $windows && file_exists( $probe ) ) {
				// PHP is_link does not consistently identify all junctions. Compare
				// each existing ancestor with its resolved path, case-insensitively.
				$resolved = realpath( $probe );
				if ( ! $resolved || 0 !== strcasecmp( rtrim( str_replace( '\\', '/', $resolved ), '/' ), $probe ) ) { return false; }
			}
			$probe = dirname( $probe );
		}
		$ancestor = $state;
		while ( ! file_exists( $ancestor ) && dirname( $ancestor ) !== $ancestor ) {
			$ancestor = dirname( $ancestor );
		}
		$real = realpath( $ancestor );
		if ( ! $real ) {
			return false;
		}
		$candidate = rtrim( str_replace( '\\', '/', $real ), '/' ) . substr( $state, strlen( $ancestor ) );
		if ( $windows ) { $candidate = strtolower( $candidate ); }
		$public_roots = array_merge( array( ABSPATH, WP_CONTENT_DIR ), GWQSH_Path_Guard::allowed_roots() );
		if ( ! empty( $_SERVER['DOCUMENT_ROOT'] ) && is_string( $_SERVER['DOCUMENT_ROOT'] ) ) {
			$public_roots[] = wp_unslash( $_SERVER['DOCUMENT_ROOT'] );
		}
		if ( defined( 'GWQSH_PUBLIC_DOCUMENT_ROOTS' ) ) {
			if ( ! is_array( GWQSH_PUBLIC_DOCUMENT_ROOTS ) ) {
				return false;
			}
			$public_roots = array_merge( $public_roots, GWQSH_PUBLIC_DOCUMENT_ROOTS );
		}
		foreach ( $public_roots as $root ) {
			if ( ! is_string( $root ) || '' === $root || ! realpath( $root ) ) {
				return false;
			}
			$public = rtrim( str_replace( '\\', '/', realpath( $root ) ), '/' );
			if ( $windows ) { $public = strtolower( $public ); }
			// Reject public descendants and ancestors: never chmod a document-root parent.
			if ( $candidate === $public || 0 === strpos( $candidate, $public . '/' ) || 0 === strpos( $public, $candidate . '/' ) ) {
				return false;
			}
		}
		return '' !== $candidate;
	}

	/** Read native Windows ACLs; never modify permissions or interpolate shell input.
	 * Reject unknown owners and any Allow ACE outside this process, SYSTEM and
	 * local Administrators. Disabled process support or failed inspection is unsafe.
	 * Missing descendants inherit only from the nearest existing private directory.
	 */
	public static function windows_private_acl( $path ) {
		static $cache = array();
		if ( 'Windows' !== PHP_OS_FAMILY || ! self::private_path( $path ) || ! function_exists( 'proc_open' ) ) { return false; }
		while ( ! file_exists( $path ) && dirname( $path ) !== $path ) { $path = dirname( $path ); }
		$system_root = getenv( 'SystemRoot' );
		if ( ! is_string( $system_root ) || ! preg_match( '#^[a-zA-Z]:[\\\\/]#', $system_root ) ) { return false; }
		$cache_key = $path . '|' . $system_root;
		if ( isset( $cache[ $cache_key ] ) ) { return $cache[ $cache_key ]; }
		$executable = rtrim( $system_root, '/\\' ) . '/System32/WindowsPowerShell/v1.0/powershell.exe';
		if ( ! is_file( $executable ) || ! is_dir( $path ) ) { return false; }
		$encoded = base64_encode( $path );
		$script = '$ErrorActionPreference="Stop";try{' .
			'$p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("' . $encoded . '"));' .
			'$a=Get-Acl -LiteralPath $p;$s=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;' .
			'$allowed=@($s,"S-1-5-18","S-1-5-32-544");$ok=$allowed -contains $a.GetOwner([Security.Principal.SecurityIdentifier]).Value;' .
			'$q=$p;while($q){if((Get-Item -LiteralPath $q -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){$ok=$false};$q=[IO.Path]::GetDirectoryName($q)};' .
			'$rules=$a.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]);$allow=0;' .
			'foreach($r in $rules){if($r.AccessControlType -eq "Allow"){$allow++;if($allowed -notcontains $r.IdentityReference.Value){$ok=$false}}};' .
			'[Console]::Write((@{private=($ok -and $allow -gt 0)}|ConvertTo-Json -Compress));exit 0}catch{exit 1}';
		$process = null; $pipes = array();
		try {
			$process = @proc_open( array( $executable, '-NoProfile', '-NonInteractive', '-Command', $script ), array( 0 => array( 'pipe', 'r' ), 1 => array( 'pipe', 'w' ), 2 => array( 'pipe', 'w' ) ), $pipes, null, null, array( 'bypass_shell' => true ) );
			if ( ! is_resource( $process ) ) { return false; }
			fclose( $pipes[0] ); unset( $pipes[0] );
			stream_set_blocking( $pipes[1], false ); stream_set_blocking( $pipes[2], false );
			$output = ''; $errors = ''; $deadline = microtime( true ) + 10;
			do {
				$output .= stream_get_contents( $pipes[1] ); $errors .= stream_get_contents( $pipes[2] );
				$status = proc_get_status( $process );
				if ( strlen( $output ) + strlen( $errors ) > 65536 || microtime( true ) >= $deadline ) { proc_terminate( $process ); return false; }
				if ( $status['running'] ) { usleep( 10000 ); }
			} while ( $status['running'] );
			$output .= stream_get_contents( $pipes[1] ); $errors .= stream_get_contents( $pipes[2] );
			$result = json_decode( $output, true );
			$is_private = ( 0 === $status['exitcode'] && '' === $errors && is_array( $result ) && true === ( $result['private'] ?? false ) );
			$cache[ $cache_key ] = $is_private;
			return $is_private;
		} catch ( Throwable $error ) {
			return false;
		} finally {
			foreach ( $pipes as $pipe ) { if ( is_resource( $pipe ) ) { fclose( $pipe ); } }
			if ( is_resource( $process ) ) { proc_close( $process ); }
		}
	}

	/** Ensure private state cannot be placed below a known public document root. */
	public static function state_dir_is_private() {
		// Windows needs an explicitly provisioned ACL-protected durable base;
		// do not probe or create a default temporary directory on ordinary requests.
		if ( 'Windows' === PHP_OS_FAMILY && ! defined( 'GWQSH_PRIVATE_STORAGE_DIR' ) ) { return false; }
		$path = self::state_dir();
		return self::private_path( $path ) && ( 'Windows' !== PHP_OS_FAMILY || self::windows_private_acl( $path ) );
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
