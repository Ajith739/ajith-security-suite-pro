<?php
/**
 * Resumable file enumeration, content/hash analysis and finding persistence.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Backend scan coordinator preserving the existing File Integrity interface. */
final class GWQSH_Scan_Engine {
	/**
	 * Read bounded chunked JSON state without PHP object deserialization.
	 *
	 * @param string $key Plugin-owned option name.
	 */
	public static function load( $key ) {
		$value = get_option( $key, array() );
		if ( ! is_array( $value ) ) {
			return array(); }
		if ( ! isset( $value['chunks'], $value['generation'] ) ) {
			return is_array( $value ) ? $value : array();
		}
		if ( ! is_int( $value['chunks'] ) || $value['chunks'] < 1 || $value['chunks'] > 256 || ! preg_match( '/^[a-f0-9]{16}$/D', $value['generation'] ) ) {
			return array();
		}
		$json = '';
		for ( $i = 0; $i < $value['chunks']; $i++ ) {
			$part = get_option( $key . '_' . $value['generation'] . '_' . $i, false );
			if ( ! is_string( $part ) || strlen( $part ) > 131072 ) {
				return array();
			}
			$json .= $part;
		}
		if ( 'gzip-base64' === ( $value['encoding'] ?? '' ) ) {
			if ( ! function_exists( 'gzdecode' ) || ! isset( $value['bytes'] ) || ! is_int( $value['bytes'] ) || $value['bytes'] > 33554432 ) {
				return array(); }
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- Bounded compressed state transport, never executable data.
			$packed = base64_decode( $json, true );
			// phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- Corrupted bounded state must fail validation without leaking codec warnings into responses.
			$json = false === $packed ? false : @gzdecode( $packed, 33554432 );
			if ( ! is_string( $json ) || strlen( $json ) !== $value['bytes'] ) {
				return array(); }
		}
		if ( isset( $value['digest'] ) && ( ! is_string( $value['digest'] ) || ! hash_equals( $value['digest'], hash( 'sha256', $json ) ) ) ) {
			return array(); }
		$decoded = json_decode( $json, true, 64 );
		return is_array( $decoded ) ? $decoded : array();
	}

	/**
	 * Publish the small pointer last so readers cannot see partial state.
	 *
	 * @param string $key Plugin-owned option name.
	 * @param array  $value State without source content.
	 * @throws RuntimeException When bounded persistence fails.
	 */
	public static function save( $key, array $value ) {
		$old  = get_option( $key, array() );
		$json = wp_json_encode( $value );
		if ( ! is_string( $json ) || strlen( $json ) > 33554432 ) {
			throw new RuntimeException( 'Scan state limit exceeded' );
		}
		$bytes    = strlen( $json );
		$digest   = hash( 'sha256', $json );
		$encoding = 'json';
		if ( function_exists( 'gzencode' ) ) {
			// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- Compress bounded JSON metadata to reduce state write amplification.
			$compressed = base64_encode( gzencode( $json, 1 ) );
			if ( strlen( $compressed ) < strlen( $json ) ) {
				$json     = $compressed;
				$encoding = 'gzip-base64'; }
		}
		$parts      = str_split( $json, 131072 );
		$generation = bin2hex( random_bytes( 8 ) );
		foreach ( $parts as $i => $part ) {
			if ( ! add_option( $key . '_' . $generation . '_' . $i, $part, '', false ) ) {
				throw new RuntimeException( 'Scan state persistence unavailable' );
			}
		}
		if ( ! update_option(
			$key,
			array(
				'chunks'     => count( $parts ),
				'generation' => $generation,
				'encoding'   => $encoding,
				'bytes'      => $bytes,
				'digest'     => $digest,
			),
			false
		) ) {
			throw new RuntimeException( 'Scan pointer persistence unavailable' );
		}
		if ( isset( $old['chunks'], $old['generation'] ) && is_int( $old['chunks'] ) && $old['chunks'] <= 256 && preg_match( '/^[a-f0-9]{16}$/D', $old['generation'] ) ) {
			for ( $i = 0; $i < $old['chunks']; $i++ ) {
				delete_option( $key . '_' . $old['generation'] . '_' . $i );
			}
		}
	}

	/**
	 * Remove only a completed state pointer and its owned JSON chunks.
	 *
	 * @param string $key Plugin-owned option name.
	 */
	public static function clear( $key ) {
		$value = get_option( $key, array() );
		if ( isset( $value['chunks'], $value['generation'] ) && is_int( $value['chunks'] ) && $value['chunks'] <= 256 && preg_match( '/^[a-f0-9]{16}$/D', $value['generation'] ) ) {
			for ( $i = 0; $i < $value['chunks']; $i++ ) {
				delete_option( $key . '_' . $value['generation'] . '_' . $i );
			}
		}
		delete_option( $key );
	}

	/**
	 * The only approved roots are those configured by this WordPress installation.
	 */
	public static function roots() {
		$uploads = wp_upload_dir();
		return array(
			'root'    => ABSPATH,
			'content' => WP_CONTENT_DIR,
			'plugin'  => WP_PLUGIN_DIR,
			'theme'   => get_theme_root(),
			'mu'      => GWQSH_Guardian::root(),
			'uploads' => $uploads['basedir'],
		);
	}

	/**
	 * Stable relative paths; custom external configured roots receive explicit aliases.
	 *
	 * @param mixed $file File.
	 */
	public static function label( $file ) {
		foreach ( self::roots() as $name => $root ) {
			$real = GWQSH_Security_Runtime::safe_path( $file, $root );
			if ( $real ) {
				return '/' . ( 'root' === $name ? '' : '@' . $name . '/' ) . str_replace( '\\', '/', substr( $real, strlen( realpath( $root ) ) + 1 ) );
			}
		}
		return false;
	}

	/**
	 * Context is derived from configured roots, not attacker-supplied file names.
	 *
	 * @param mixed $file File.
	 */
	public static function scope( $file ) {
		$roots           = self::roots();
		static $resolved = array();
		$roots_key       = implode( '|', $roots );
		if ( ! isset( $resolved[ $roots_key ] ) ) {
			$resolved[ $roots_key ] = array_map( 'realpath', $roots ); }
		$real = realpath( $file );
		foreach ( array(
			'uploads' => 'Uploads',
			'mu'      => 'Plugin',
			'plugin'  => 'Plugin',
			'theme'   => 'Theme',
			'content' => 'Plugin',
		) as $key => $type ) {
			$root = $resolved[ $roots_key ][ $key ];
			if ( $real && $root && ( $real === $root || strpos( $real, $root . DIRECTORY_SEPARATOR ) === 0 ) ) {
				return $type;
			}
		}
		return 'Core';
	}

	/**
	 * Bounded enumeration; no following symlinks, devices or dependency/test trees.
	 *
	 * @param mixed $root Root.
	 * @param mixed $errors Errors.
	 */
	public static function files( $root, &$errors = array() ) {
		if ( ! is_dir( $root ) || is_link( $root ) ) {
			return;
		}
		$queue             = array( array( rtrim( $root, '/\\' ), 0 ) );
		$count             = 0;
		$entries           = 0;
		$enumeration_start = microtime( true );
		while ( $queue ) {
			list( $dir, $depth ) = array_pop( $queue );
			try {
				foreach ( new DirectoryIterator( $dir ) as $item ) {
					if ( ++$entries > 75000 || microtime( true ) - $enumeration_start > 3 ) {
						$errors['enumeration_limit'] = true;
						return;
					}
					if ( $item->isDot() || $item->isLink() ) {
						continue;
					}
					$path = $item->getPathname();
					if ( ! GWQSH_Security_Runtime::safe_path( $path, $root ) ) {
						continue;
					}
					if ( $item->isDir() ) {
						$dirname = $item->getFilename();
						if ( in_array( $dirname, array( '.git', '.svn', '.hg', 'node_modules' ), true )
							|| ( 'dist' === $dirname && realpath( dirname( $path ) ) === realpath( ABSPATH ) )
							|| ( strpos( wp_normalize_path( $path ), rtrim( wp_normalize_path( GWQSH_PATH ), '/' ) . '/' ) === 0 && in_array( $dirname, array( 'vendor', 'tests', 'bin', 'docs' ), true ) ) ) {
							continue;
						}
						if ( $depth < 16 ) {
							$queue[] = array( $path, $depth + 1 );
						} else {
							$errors['depth_limit'] = true;
						}
					} elseif ( $item->isFile() ) {
						if ( ++$count > 50000 ) {
							$errors['file_limit'] = true;
							return;
						}
						// Only directory enumeration counts toward its budget; consumer analysis
						// can span scan chunks and must not make a complete tree look truncated.
						$analysis_start = microtime( true );
						yield $path;
						$enumeration_start += microtime( true ) - $analysis_start;
					}
				}
			} catch ( Throwable $error ) {
				$errors['unreadable_directory'] = true;
			}
		}
	}

	/**
	 * Hash unchanged files before skipping token analysis; mtime is never trust evidence.
	 *
	 * @param mixed $file File.
	 * @param mixed $scope Scope.
	 * @param array $cache Cache.
	 */
	public static function inspect( $file, $scope, array $cache = array() ) {
		$label = self::label( $file );
		if ( ! $label || ! is_file( $file ) || ! is_readable( $file ) ) {
			return array( 'error' => 'unreadable_file' );
		}
		$size = filesize( $file );
		if ( false === $size || $size > 16777216 ) {
			return array( 'error' => 'size_limit' );
		}
		$hash = hash_file( 'sha256', $file );
		if ( ! $hash ) {
			return array( 'error' => 'hash_unavailable' );
		}
		if ( isset( $cache['hash'], $cache['version'] ) && $cache['hash'] === $hash && GWQSH_Malware_Analyzer::VERSION === $cache['version'] && ( $cache['signature_version'] ?? 0 ) === GWQSH_Signatures::version() ) {
			return $cache;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Validated local file inspection, bounded and never a remote URL.
		$content = file_get_contents( $file, false, null, 0, GWQSH_Security_Runtime::LIMIT );
		if ( false === $content ) {
			return array( 'error' => 'unreadable_file' );
		}
		$result                      = GWQSH_Malware_Analyzer::analyze( $content, $file, $scope, $hash );
		$result['signature_version'] = GWQSH_Signatures::version();
		if ( 'zip' === strtolower( pathinfo( $file, PATHINFO_EXTENSION ) ) ) {
			$archive                   = self::archive( $file );
			$result['score']           = max( $result['score'], $archive['score'] );
			$result['evidence']        = array_merge( $result['evidence'], $archive['evidence'] );
			$result['archive_partial'] = $archive['partial'];
			$result['severity']        = $result['score'] >= 80 ? 'Critical' : ( $result['score'] >= 60 ? 'High' : $result['severity'] );
		}

		$result['component'] = GWQSH_Security_Runtime::safe_path( $file, GWQSH_Guardian::root() ) ? 'mu_plugin' : ( in_array( basename( $file ), array( 'advanced-cache.php', 'object-cache.php', 'db.php', 'db-error.php', 'install.php', 'maintenance.php', 'sunrise.php', 'fatal-error-handler.php' ), true ) && dirname( $file ) === realpath( WP_CONTENT_DIR ) ? 'dropin' : strtolower( $scope ) );
		if ( 'config' === GWQSH_Path_Guard::detect_component( $file ) ) {
			$result['component'] = 'config';
		}
		$result['hash']    = $hash;
		$result['size']    = $size;
		$result['mtime']   = filemtime( $file );
		$result['partial'] = $size > GWQSH_Security_Runtime::LIMIT || ! empty( $result['archive_partial'] ) || ! empty( $result['analysis_partial'] );
		if ( $result['partial'] ) {
			$result['evidence'][] = 'content_size_limit';
		}
		return $result;
	}

	/**
	 * Read a bounded archive surface without extracting or executing anything.
	 *
	 * @param string $file Approved regular archive file.
	 */
	private static function archive( $file ) {
		$result = array(
			'score'    => 0,
			'evidence' => array(),
			'partial'  => false,
		);
		if ( ! class_exists( 'ZipArchive' ) ) {
			$result['partial'] = true;
			return $result;
		}
		$zip = new ZipArchive();
		if ( true !== $zip->open( $file ) ) {
			$result['evidence'][] = 'invalid_archive';
			$result['score']      = 25;
			return $result;
		}
		try {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Native ZipArchive API property.
			$count = min( 200, $zip->numFiles );
			$bytes = 0;
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Native ZipArchive API property.
			$result['partial'] = $zip->numFiles > 200;
			for ( $i = 0; $i < $count; $i++ ) {
				$entry = $zip->statIndex( $i );
				if ( ! $entry || ! preg_match( '/\.(?:php[0-9]?|phtml|inc|js|html?)$/i', $entry['name'] ) ) {
					continue;
				}
				$result['evidence'][] = 'archive_executable_entry';
				if ( $entry['size'] > GWQSH_Security_Runtime::LIMIT || $entry['size'] > 100 * max( 1, $entry['comp_size'] ) || $bytes + $entry['size'] > 1048576 ) {
					$result['partial'] = true;
					continue;
				}
				$fp = $zip->getStream( $entry['name'] );
				if ( ! $fp ) {
					$result['partial'] = true;
					continue;
				}
				$content = stream_get_contents( $fp, GWQSH_Security_Runtime::LIMIT );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				fclose( $fp );
				$bytes   += strlen( $content );
				$analysis = GWQSH_Malware_Analyzer::analyze( $content, $entry['name'], 'Plugin' );
				if ( $analysis['score'] > $result['score'] ) {
					$result['score'] = $analysis['score'];
				}
				if ( $analysis['score'] >= 60 ) {
					$result['evidence'] = array_merge( $result['evidence'], $analysis['evidence'], array( 'archive_payload_behavior' ) );
				}
			}
		} finally {
			$zip->close();
		}
		$result['evidence'] = array_values( array_unique( $result['evidence'] ) );
		return $result;
	}

	/**
	 * Preserve old records. Update unresolved findings by path; never erase reviewed history.
	 *
	 * @param mixed $path Path.
	 * @param mixed $type Type.
	 * @param mixed $status Status.
	 * @param mixed $detail Detail.
	 * @param array $evidence Evidence.
	 */
	public static function finding( $path, $type, $status, $detail, array $evidence = array() ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gwqsh_scan_results';
		$data  = array(
			'file_path'   => $path,
			'file_type'   => $type,
			'status'      => $status,
			'details'     => $detail,
			'detected_at' => current_time( 'mysql' ),
			'is_resolved' => 0,
			'evidence'    => wp_json_encode( $evidence ),
		);
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed plugin-owned table; values prepared; fresh finding state.
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$id = $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE file_path = %s AND is_resolved = 0 LIMIT 1", $path ) );
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Plugin-owned findings, input values escaped by wpdb.
		return $id ? $wpdb->update( $table, $data, array( 'id' => $id ) ) : $wpdb->insert( $table, $data );
	}

	/**
	 * Start or resume a scan. Each request has a bounded work budget.
	 */
	public static function run() {
		clearstatcache();
		$lease = GWQSH_Enterprise_Store::lock( 'file-scan', 300 );
		if ( ! $lease ) {
			return new WP_Error( 'scan_busy', 'File inspection is already running. Retry shortly.' );
		}
		try {
			$deadline = microtime( true ) + (int) GWQSH_Settings::get( 'scan_budget', 3 );
			do {
				$result = self::batch( $deadline );
			} while ( is_array( $result ) && ! empty( $result['pending'] ) && microtime( true ) < $deadline );
			return $result;
		} catch ( Throwable $error ) {
			GWQSH_Activity_Logger::log( 'File scan failed', 'A scan batch could not be completed or persisted. Check available storage and resume the scan.', 'Security' );
			return new WP_Error( 'scan_unavailable', 'The scan batch could not be saved. Check storage and retry; existing baseline and saved progress are preserved.' );
		} finally {
			GWQSH_Enterprise_Store::unlock( 'file-scan', $lease );
		}
	}

	/**
	 * Process hashes and behaviors, preserving progress for cron continuation.
	 *
	 * @param float $deadline Request budget in seconds.
	 */
	private static function batch( $deadline ) {
		GWQSH_Guardian::events();
		GWQSH_Quarantine_Manager::reconcile();
		$updates = get_site_transient( 'update_core' );
		update_option( 'gwqsh_core_update_available', is_object( $updates ) && ! empty( $updates->updates ) && 'upgrade' === $updates->updates[0]->response, false );
		$start    = microtime( true );
		$state    = self::load( 'gwqsh_scan_progress' );
		$baseline = (array) self::load( 'gwqsh_file_baseline' );
		$cache    = (array) self::load( 'gwqsh_analysis_cache' );
		// Hydration must not starve the work budget as state grows on slower hosts.
		$deadline              = max( $deadline, microtime( true ) + (int) GWQSH_Settings::get( 'scan_budget', 3 ) );
		$mu_manifest           = array();
		$mu_baseline_file      = GWQSH_Guardian::state_dir() . '/mu-baseline.json';
		$mu_baseline_available = false;
		if ( GWQSH_Security_Runtime::safe_path( $mu_baseline_file, GWQSH_Guardian::state_dir() ) && filesize( $mu_baseline_file ) <= 131072 ) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Validated local guardian metadata bounded to 128 KiB.
			$mu_data = json_decode( file_get_contents( $mu_baseline_file ), true );
			if ( is_array( $mu_data ) && isset( $mu_data['files'] ) && is_array( $mu_data['files'] ) ) {
				$mu_manifest           = $mu_data['files'];
				$mu_baseline_available = true;
			}
		}

		if ( ! $state ) {
			$options = (array) get_option(
				'gwqsh_next_scan_options',
				array(
					'type'   => 'full',
					'scopes' => array( 'Core', 'Plugin', 'Theme', 'Uploads' ),
				)
			);
			delete_option( 'gwqsh_next_scan_options' );
			$checksums                      = in_array( 'Core', $options['scopes'], true ) ? GWQSH_File_Integrity::get_core_checksums() : array();
			$state                          = array(
				'files'              => array(),
				'offset'             => 0,
				'manifest'           => array(),
				'checksums'          => is_array( $checksums ) ? $checksums : array(),
				'checksum_available' => is_array( $checksums ),
				'total'              => 0,
				'modified'           => 0,
				'missing'            => 0,
				'suspicious'         => 0,
				'critical'           => 0,
				'errors'             => array(),
				'scopes'             => array(
					'Plugin'  => 0,
					'Theme'   => 0,
					'Uploads' => 0,
				),
				'started'            => time(),
				'options'            => $options,
			);
			$state['enumeration']           = array(
				'queue'   => array(),
				'entries' => 0,
				'done'    => false,
			);
			$state['uncovered_directories'] = array();
			if ( 'quick' === $options['type'] || count( $options['scopes'] ) < 4 ) {
				$state['errors']['partial_scan_scope'] = true; }
			$roots         = array();
			$default_roots = array_values( array_unique( self::roots() ) );
			$scan_roots    = apply_filters( 'gwqsh_scan_enumeration_roots', $default_roots );
			if ( ! is_array( $scan_roots ) || ! $scan_roots ) {
				$scan_roots = $default_roots; }
			if ( $scan_roots !== $default_roots ) {
				$state['errors']['custom_scan_roots'] = true; }
			foreach ( $scan_roots as $root ) {
				if ( ! is_string( $root ) || strpos( $root, '://' ) !== false ) {
					$state['errors']['invalid_scan_root'] = true;
					continue; }
				$real    = realpath( $root );
				$covered = false;
				foreach ( $roots as $parent ) {
					if ( $real === $parent || strpos( (string) $real, $parent . DIRECTORY_SEPARATOR ) === 0 ) {
						$covered = true;
						break; }
				}
				if ( $real && ! $covered && ! is_link( $root ) ) {
					$roots[]                         = $real;
					$state['enumeration']['queue'][] = array(
						'dir'    => $real,
						'root'   => $real,
						'depth'  => 0,
						'offset' => 0,
					); }
			}
			$state['enumeration_roots'] = $roots;
			$runtime                    = realpath( GWQSH_PATH . 'includes/vendor/webauthn/src' );
			if ( $runtime && in_array( 'Plugin', $options['scopes'], true ) ) {
				$state['enumeration']['queue'][] = array(
					'dir'    => $runtime,
					'root'   => $runtime,
					'depth'  => 0,
					'offset' => 0,
				); }
			if ( ! $state['checksum_available'] ) {
				$state['errors']['checksums_unavailable'] = true;
			}
		}
		if ( isset( $state['enumeration'] ) && ! $state['enumeration']['done'] ) {
			self::enumerate_batch( $state, $deadline );
			if ( ! $state['enumeration']['done'] ) {
				self::save( 'gwqsh_scan_progress', $state );
				if ( ! wp_next_scheduled( 'gwqsh_continue_integrity_scan' ) ) {
					wp_schedule_single_event( time() + 5, 'gwqsh_continue_integrity_scan' ); }
				return self::summary( $state, true );
			}
			$state['files'] = array_keys( $state['files'] );
		}
		$processed  = 0;
		$file_count = count( $state['files'] );
		while ( $state['offset'] < $file_count && microtime( true ) < $deadline && $processed < 1000 ) {
			$file = $state['files'][ $state['offset']++ ];
			++$processed;
			$label = self::label( $file );
			if ( ! $label ) {
				$state['errors']['file_disappeared'] = true;
				continue;
			}
			// Only exact metadata-bound sentinels are excluded; replacements are inspected.
			if ( GWQSH_Quarantine_Manager::is_owned_sentinel( $label ) ) {
				continue;
			}
			$scope = self::scope( $file );
			++$state['total'];
			if ( isset( $state['scopes'][ $scope ] ) ) {
				++$state['scopes'][ $scope ];
			}
			$result = self::inspect( $file, $scope, isset( $cache[ $label ] ) ? $cache[ $label ] : array() );
			if ( isset( $result['error'] ) ) {
				$state['errors'][ $result['error'] ] = true;
				continue;
			}
			$state['manifest'][ $label ] = array(
				'hash'  => $result['hash'],
				'size'  => $result['size'],
				'mtime' => $result['mtime'],
				'scope' => $scope,
			);
			$cache[ $label ]             = $result;
			$relative                    = ltrim( $label, '/' );
			$verified                    = isset( $state['checksums'][ $relative ] ) && md5_file( $file ) === $state['checksums'][ $relative ];
			$result['core_state']        = $verified ? 'verified' : ( isset( $state['checksums'][ $relative ] ) ? 'changed' : 'unknown' );
			if ( $verified ) {
				$result['score']      = 0;
				$result['severity']   = 'Informational';
				$result['confidence'] = 'Verified checksum';
				$result['evidence']   = array( 'verified_core' );
				$result['partial']    = false;
				$result['auto_block'] = false;
			}
			if ( $result['partial'] ) {
				$state['errors']['content_size_limit'] = true;
			}

			$status                   = '';
			$detail                   = '';
			$relative                 = ltrim( $label, '/' );
			$result['baseline_state'] = isset( $baseline[ $label ] ) ? ( $baseline[ $label ]['hash'] === $result['hash'] ? 'unchanged' : 'changed' ) : ( $baseline ? 'new' : 'unknown' );
			if ( isset( $state['checksums'][ $relative ] ) && md5_file( $file ) !== $state['checksums'][ $relative ] ) {
				$status               = 'Modified';
				$detail               = 'Modified core file: official checksum mismatch. ';
				$result['evidence'][] = 'core_checksum_mismatch';
			} elseif ( 'Core' === $scope && $state['checksum_available'] && preg_match( '#^/?wp-(?:admin|includes)/.*\.(?:php|phtml)$#i', $label ) && ! isset( $state['checksums'][ $relative ] ) ) {
				$status = 'Suspicious';
				$detail = 'Unexpected executable in a core directory. ';
			}
			if ( $mu_baseline_available && 'mu_plugin' === $result['component'] && GWQSH_Guardian::NAME !== basename( $file ) && realpath( dirname( $file ) ) === realpath( GWQSH_Guardian::root() ) ) {
				$known_mu                    = isset( $mu_manifest[ basename( $file ) ]['hash'] ) ? $mu_manifest[ basename( $file ) ]['hash'] : '';
				$result['mu_baseline_state'] = $known_mu ? ( $known_mu === $result['hash'] ? 'unchanged' : 'changed' ) : 'new';
				if ( 'unchanged' !== $result['mu_baseline_state'] ) {
					$status  = $status ? $status : 'Modified';
					$detail .= 'MU baseline: ' . $result['mu_baseline_state'] . '; review source. ';
				}
			}
			if ( ! $verified && in_array( $result['baseline_state'], array( 'changed', 'new' ), true ) && preg_match( '/\.(?:php[0-9]?|phtml|inc|js|ini)$|\/\.htaccess$/i', $file ) ) {
				$status  = $status ? $status : 'Modified';
				$detail .= 'Baseline: ' . $result['baseline_state'] . '. ';
			}
			if ( $result['score'] >= 40 || $result['partial'] ) {
				$status  = $result['score'] >= 60 ? 'Suspicious' : ( $status ? $status : 'Modified' );
				$detail .= $result['severity'] . ' (' . $result['score'] . '/100; ' . $result['confidence'] . '): ' . implode( ', ', $result['evidence'] );
			}
			if ( $result['score'] >= 80 ) {
				++$state['critical'];
			}
			if ( $status ) {
				++$state[ strtolower( $status ) ];
				self::finding( $label, $scope, $status, $detail, $result );
				if ( 'Suspicious' === $status ) {
					GWQSH_Activity_Logger::log( ! empty( $result['signature_ids'] ) ? 'Malware signature detected' : 'Suspicious file finding', 'A saved finding requires review; detection is not proof of malware.', 'Security' ); }
			}
		}
		self::save( 'gwqsh_analysis_cache', $cache );
		if ( $state['offset'] < count( $state['files'] ) ) {
			self::save( 'gwqsh_scan_progress', $state );
			if ( ! wp_next_scheduled( 'gwqsh_continue_integrity_scan' ) ) {
				wp_schedule_single_event( time() + 5, 'gwqsh_continue_integrity_scan' );
			}
			return self::summary( $state, true );
		}
		foreach ( $state['checksums'] as $relative => $hash ) {
			if ( ! self::covered_label( '/' . $relative, $state ) ) {
				continue; }
			if ( ! file_exists( ABSPATH . $relative ) ) {
				$quarantine = GWQSH_Quarantine_Manager::get_active_quarantine_for_path( '/' . $relative );
				if ( $quarantine ) {
					$state['errors']['quarantined_core_requires_restore'] = true;
					self::finding(
						'/' . $relative,
						'Core',
						'Modified',
						'Intentionally quarantined core file requires official restoration',
						array(
							'category' => 'core_integrity',
							'severity' => 'High',
						)
					);
					++$state['modified'];
					continue;
				}
				++$state['missing'];
				++$state['total'];
				self::finding( '/' . $relative, 'Core', 'Missing', 'Official WordPress core file is missing', array( 'category' => 'core_integrity' ) );
			}
		}
		foreach ( $baseline as $label => $record ) {
			if ( self::covered_label( $label, $state ) && in_array( $record['scope'], $state['options']['scopes'] ?? array( 'Core', 'Plugin', 'Theme', 'Uploads' ), true ) && ! isset( $state['manifest'][ $label ] ) && ! isset( $state['checksums'][ ltrim( $label, '/' ) ] ) && ! self::resolve_label( $label ) ) {
				$absence = GWQSH_Quarantine_Manager::absence_state( $label, $record['hash'] );
				if ( $absence ) {
					if ( 'Damaged' === $absence ) {
						$state['errors']['quarantine_evidence_missing'] = true;
					}
					continue;
				}
				++$state['total'];
				++$state['missing'];
				self::finding(
					$label,
					$record['scope'],
					'Missing',
					'Expected baseline file is missing',
					array(
						'baseline_state' => 'deleted',
						'hash'           => $record['hash'],
					)
				);
			}
		}
		$summary = self::summary( $state, false );
		self::save(
			'gwqsh_scan_candidate',
			array(
				'manifest' => $state['manifest'],
				'critical' => $state['critical'],
				'errors'   => array_merge( array_keys( $state['errors'] ), ( isset( $state['options'] ) && ( 'quick' === $state['options']['type'] || count( $state['options']['scopes'] ) < 4 ) ) ? array( 'partial_scan_scope' ) : array() ),
				'time'     => time(),
			)
		);
		$upload_php_total = 0;
		foreach ( $state['manifest'] as $path => $record ) {
			if ( 'Uploads' === $record['scope'] && preg_match( '/\.(?:php[0-9]?|phtml|phar)(?:\.|$)/i', $path ) ) {
				++$upload_php_total;
			}
		}
		update_option( 'gwqsh_last_scan_upload_php_total', $upload_php_total, false );
		update_option( 'gwqsh_scan_health', array_keys( $state['errors'] ), false );
		update_option( 'gwqsh_last_scan_scope_counts', $state['scopes'], false );
		update_option( 'gwqsh_last_scan_core_total', count( $state['checksums'] ), false );
		foreach ( array( 'total', 'duration', 'date' ) as $key ) {
			update_option( 'gwqsh_last_scan_' . ( 'date' === $key ? 'time' : $key ), $summary[ $key ], false );
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery -- Existing history model; preserve prior scan records.
		$wpdb->insert(
			$wpdb->prefix . 'gwqsh_scan_history',
			array(
				'scan_date'        => $summary['date'],
				'duration'         => $summary['duration'],
				'total_files'      => $summary['total'],
				'clean_files'      => $summary['clean'],
				'modified_files'   => $summary['modified'],
				'missing_files'    => $summary['missing'],
				'suspicious_files' => $summary['suspicious'],
			)
		);
		self::clear( 'gwqsh_scan_progress' );
		wp_clear_scheduled_hook( 'gwqsh_continue_integrity_scan' );
		if ( ! empty( $state['options']['scheduled'] ) ) {
			update_option( 'gwqsh_scheduled_scan_status', 'Completed', false );
			if ( $state['suspicious'] || $state['modified'] || $state['missing'] ) {
				GWQSH_Activity_Logger::log( 'Scheduled scan actionable findings', 'Review the saved scan findings and their confidence in File Integrity.', 'Security' ); }
			GWQSH_Activity_Logger::log( 'Scheduled scan completed', 'Background scan completed with ' . count( $state['errors'] ) . ' coverage limitations.', 'System' ); }
		GWQSH_Activity_Logger::log( 'File scan completed', 'Local file inspection completed; ' . count( $state['errors'] ) . ' coverage limitations recorded.', 'System' );
		return $summary;
	}

	/**
	 * Resume directory cursors across work deadlines instead of truncating coverage.
	 *
	 * @param array $state Persisted scan state.
	 * @param float $deadline Batch deadline.
	 */
	private static function enumerate_batch( &$state, $deadline ) {
		$enum =& $state['enumeration'];
		while ( $enum['queue'] && microtime( true ) < $deadline ) {
			$index  = count( $enum['queue'] ) - 1;
			$cursor = $enum['queue'][ $index ];
			try {
				if ( is_link( $cursor['dir'] ) || ( $cursor['dir'] !== $cursor['root'] && ! GWQSH_Security_Runtime::safe_path( $cursor['dir'], $cursor['root'] ) ) ) {
					array_pop( $enum['queue'] );
					$state['errors']['directory_changed'] = true;
					$state['uncovered_directories'][]     = $cursor['dir'];
					continue; }
				$iterator = new DirectoryIterator( $cursor['dir'] );
				$iterator->seek( $cursor['offset'] );
				$children = array();
				while ( $iterator->valid() && microtime( true ) < $deadline ) {
					++$enum['queue'][ $index ]['offset'];
					++$enum['entries'];
					if ( $enum['entries'] > 150000 || count( $state['files'] ) >= 50000 ) {
						$state['errors']['file_limit'] = true;
						foreach ( $enum['queue'] as $pending ) {
							$state['uncovered_directories'][] = $pending['dir'];
						} $enum['queue'] = array();
						$enum['done']    = true;
						return; }
					if ( ! $iterator->isDot() && ! $iterator->isLink() ) {
						$path = $iterator->getPathname();
						if ( $iterator->isDir() ) {
							$dirname  = $iterator->getFilename();
							$excluded = ! self::scan_directory( $path, $state['options']['scopes'] )
								|| in_array( $dirname, array( '.git', '.svn', '.hg', 'node_modules' ), true )
								|| ( 'dist' === $dirname && realpath( dirname( $path ) ) === realpath( ABSPATH ) )
								|| ( strpos( wp_normalize_path( $path ), rtrim( wp_normalize_path( GWQSH_PATH ), '/' ) . '/' ) === 0 && in_array( $dirname, array( 'vendor', 'tests', 'bin', 'docs' ), true ) );
							if ( ! $excluded ) {
								if ( $cursor['depth'] < 16 ) {
									$children[] = array(
										'dir'    => $path,
										'root'   => $cursor['root'],
										'depth'  => $cursor['depth'] + 1,
										'offset' => 0,
									);
								} else {
									$state['errors']['depth_limit']   = true;
									$state['uncovered_directories'][] = $path; }
							}
						} elseif ( $iterator->isFile() ) {
							$scope = self::scope( $path );
							if ( in_array( $scope, $state['options']['scopes'], true ) && ( 'quick' !== $state['options']['type'] || 'Core' === $scope || preg_match( '/\.(?:php[0-9]?|phtml|phar|js|htaccess)$/i', $path ) ) ) {
								$state['files'][ $path ] = true; }
						}
					}
					$iterator->next();
				}
				if ( ! $iterator->valid() ) {
					array_splice( $enum['queue'], $index, 1 ); }
				$enum['queue'] = array_merge( $enum['queue'], $children );
			} catch ( OutOfBoundsException $error ) {
				array_splice( $enum['queue'], $index, 1 ); } catch ( Throwable $error ) {
				array_splice( $enum['queue'], $index, 1 );
				$state['errors']['unreadable_directory'] = true;
				$state['uncovered_directories'][]        = $cursor['dir']; }
		}
		$enum['done'] = ! $enum['queue'];
	}

	/**
	 * Skip excluded scope subtrees, retaining parents of selected custom roots.
	 *
	 * @param string $directory Directory path.
	 * @param array  $scopes Selected scopes.
	 */
	private static function scan_directory( $directory, array $scopes ) {
		if ( in_array( self::scope( $directory ), $scopes, true ) ) {
			return true; }
		$roots     = self::roots();
		$types     = array(
			'root'    => 'Core',
			'content' => 'Plugin',
			'plugin'  => 'Plugin',
			'mu'      => 'Plugin',
			'theme'   => 'Theme',
			'uploads' => 'Uploads',
		);
		$directory = rtrim( wp_normalize_path( $directory ), '/' );
		foreach ( $types as $key => $type ) {
			$root = rtrim( wp_normalize_path( $roots[ $key ] ), '/' );
			if ( in_array( $type, $scopes, true ) && ( $root === $directory || strpos( $root, $directory . '/' ) === 0 ) ) {
				return true; }
		}
		return false;
	}

	/**
	 * Restrict absence findings to paths actually covered by this scan.
	 *
	 * @param string $label Trusted baseline label.
	 * @param array  $state Scan configuration and covered roots.
	 */
	private static function covered_label( $label, array $state ) {
		if ( ! is_string( $label ) || strpos( $label, ':' ) !== false || strpos( $label, '\\' ) !== false || preg_match( '#(^|/)\.{1,2}(/|$)#', $label ) ) {
			return false; }
		$roots    = self::roots();
		$root     = $roots['root'];
		$relative = ltrim( $label, '/' );
		if ( preg_match( '#^@([a-z]+)/(.+)$#D', $relative, $matches ) ) {
			if ( ! isset( $roots[ $matches[1] ] ) ) {
				return false;
			} $root   = $roots[ $matches[1] ];
			$relative = $matches[2]; }
		$path = rtrim( wp_normalize_path( $root ), '/' ) . '/' . $relative;
		if ( ! isset( $state['uncovered_directories'] ) && array_intersect( array_keys( $state['errors'] ), array( 'depth_limit', 'file_limit', 'enumeration_limit', 'unreadable_directory' ) ) ) {
			return false; }
		foreach ( $state['uncovered_directories'] ?? array() as $directory ) {
			$directory = rtrim( wp_normalize_path( $directory ), '/' );
			if ( $path === $directory || strpos( $path, $directory . '/' ) === 0 ) {
				return false; }
		}
		if ( 'quick' === ( $state['options']['type'] ?? 'full' ) && strpos( $path, rtrim( wp_normalize_path( WP_CONTENT_DIR ), '/' ) . '/' ) === 0 && ! preg_match( '/\.(?:php[0-9]?|phtml|phar|js|htaccess)$/i', $path ) ) {
			return false; }
		if ( ! isset( $state['enumeration_roots'] ) ) {
			return true; }
		foreach ( $state['enumeration_roots'] as $covered ) {
			if ( strpos( $path, rtrim( wp_normalize_path( $covered ), '/' ) . '/' ) === 0 ) {
				return true; }
		}
		return false;
	}

	/**
	 * Existing UI fields remain stable; extra completion/coverage data stays internal.
	 *
	 * @param array $state State.
	 * @param mixed $pending Pending.
	 */
	private static function summary( array $state, $pending ) {
		return array(
			'total'      => $state['total'],
			'clean'      => max( 0, $state['total'] - $state['modified'] - $state['missing'] - $state['suspicious'] ),
			'modified'   => $state['modified'],
			'missing'    => $state['missing'],
			'suspicious' => $state['suspicious'],
			'duration'   => max( 1, time() - $state['started'] ),
			'date'       => current_time( 'mysql' ),
			'pending'    => $pending,
			'coverage'   => array_keys( $state['errors'] ),
		);
	}

	/**
	 * Explicit administrator trust action only; incomplete/Critical scans cannot become trusted.
	 */
	public static function trust_baseline() {
		$candidate = self::load( 'gwqsh_scan_candidate' );
		if ( get_option( 'gwqsh_scan_progress' ) || ! $candidate || $candidate['critical'] || $candidate['errors'] || time() - $candidate['time'] > 300 ) {
			return new WP_Error( 'unsafe_baseline', 'A complete recent scan without Critical findings or coverage errors is required.' );
		}
		foreach ( $candidate['manifest'] as $label => $record ) {
			$file = self::resolve_label( $label );
			if ( ! $file || hash_file( 'sha256', $file ) !== $record['hash'] ) {
				return new WP_Error( 'baseline_changed', 'Files changed after inspection. Scan again before trusting.' );
			}
		}
		foreach ( $candidate['manifest'] as $label => $record ) {
			$retained = GWQSH_Quarantine_Manager::retain_trusted_text( $label, $record['hash'] );
			if ( is_wp_error( $retained ) ) {
				return $retained;
			}
		}
		self::save( 'gwqsh_file_baseline', $candidate['manifest'] );
		update_option( 'gwqsh_baseline_time', time(), false );
		return true;
	}

	/**
	 * Resolve only plugin-generated aliases and relative WordPress paths.
	 *
	 * @param mixed $label Label.
	 */
	public static function resolve_label( $label ) {
		if ( ! is_string( $label ) || strpos( $label, "\0" ) !== false || strpos( $label, ':' ) !== false || strpos( $label, '\\' ) !== false || preg_match( '#(^|/)\.{1,2}(/|$)#', $label ) ) {
			return false;
		}
		$relative = ltrim( $label, '/' );
		$root     = ABSPATH;
		if ( preg_match( '#^@([a-z]+)/(.+)$#D', $relative, $matches ) ) {
			$roots = self::roots();
			if ( ! isset( $roots[ $matches[1] ] ) ) {
				return false;
			}
			$root     = $roots[ $matches[1] ];
			$relative = $matches[2];
		}
		return GWQSH_Security_Runtime::safe_path( rtrim( $root, '/\\' ) . '/' . $relative, $root );
	}
}
