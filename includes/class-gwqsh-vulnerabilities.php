<?php
/**
 * Signed, data-only advisories and narrowly scoped virtual patches.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** No advisory or production publisher is invented or bundled. */
final class GWQSH_Vulnerabilities {
	const STATE  = 'gwqsh_advisory_state';
	const HOOK   = 'gwqsh_update_advisories';
	const ENGINE = '1';
	const CORE   = 'core:wordpress';
	/** One request-local verified package, invalidated by bytes, trust or clock second. */
	private static $runtime_cache = array();

	/** Register asynchronous updates and REST inspection. */
	public static function init() {
		add_action( self::HOOK, array( __CLASS__, 'update' ) );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'inspect_rest' ), 11, 3 );
	}

	/** Operator-owned trust, never accepted from an HTTP request.
	 *
	 * @return array Publisher identity and independently configured public keys.
	 */
	public static function trust() {
		return (array) apply_filters(
			'gwqsh_advisory_trust',
			array(
				'publisher' => defined( 'GWQSH_ADVISORY_PUBLISHER' ) ? GWQSH_ADVISORY_PUBLISHER : '',
				'keys'      => defined( 'GWQSH_ADVISORY_KEYS' ) ? GWQSH_ADVISORY_KEYS : array(),
			)
		);
	}

	/** Validate the deliberately limited version grammar.
	 *
	 * @param mixed $version Component or boundary version.
	 * @return bool Whether PHP version_compare semantics are supported.
	 */
	public static function supported_version( $version ) {
		return is_string( $version ) && (bool) preg_match( '/^[0-9]{1,8}(?:\.[0-9]{1,8}){0,3}(?:[-.]?(?:dev|alpha|a|beta|b|RC|rc|pl|p)[0-9]{0,5})?$/D', $version );
	}

	/** Check explicitly bounded, inclusive-introduction/exclusive-fix ranges.
	 *
	 * @param string $version Installed version.
	 * @param array  $ranges Validated ranges.
	 * @return bool|null Null means an unsupported vendor version needs manual review.
	 */
	public static function affected( $version, array $ranges ) {
		if ( ! self::supported_version( $version ) ) {
			return null;
		}
		foreach ( $ranges as $range ) {
			if ( version_compare( $version, $range['introduced'], '>=' ) && ( null === $range['fixed'] || version_compare( $version, $range['fixed'], '<' ) ) && ( null === $range['last_affected'] || version_compare( $version, $range['last_affected'], '<=' ) ) ) {
				return true;
			}
		}
		return false;
	}

	/** Accept only exact technical component IDs, never product display names.
	 *
	 * @param mixed $id Component ID.
	 * @return bool Valid canonical identifier.
	 */
	private static function component_id( $id ) {
		return is_string( $id ) && strlen( $id ) <= 200 && ! preg_match( '~(?:^|[/:])\.{1,2}(?:/|$)~', $id ) && ( in_array( $id, array( self::CORE, 'core:WordPress' ), true ) || preg_match( '~^plugin:[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.php$~D', $id ) || preg_match( '~^mu-plugin:[A-Za-z0-9_.-]+\.php$~D', $id ) || preg_match( '~^theme:[A-Za-z0-9_-]+$~D', $id ) );
	}

	/** Validate a reference link without DNS or HTTP; advisory URLs are never fetched.
	 *
	 * @param mixed $url Analyst provenance URL.
	 * @return bool Whether a bounded HTTPS reference is usable.
	 */
	private static function provenance( $url ) {
		if ( ! is_string( $url ) || strlen( $url ) > 2048 || preg_match( '/[\x00-\x20\x7f]/', $url ) ) {
			return false;
		}
		$parts = wp_parse_url( $url );
		return is_array( $parts ) && 'https' === ( $parts['scheme'] ?? '' ) && ! empty( $parts['host'] ) && ! isset( $parts['user'] ) && ! isset( $parts['pass'] ) && ( ! isset( $parts['port'] ) || 443 === $parts['port'] );
	}

	/** Verify exact signed bytes, publisher, engine, timestamps and payload grammar.
	 *
	 * @param mixed $json Exact response body.
	 * @param mixed $signature Base64 detached Ed25519 signature.
	 * @param bool  $allow_retired_patches Permit elapsed patch TTLs when reading or rolling back an otherwise current signed feed. Scoped selection still retires each expired patch.
	 * @return array|WP_Error Validated package.
	 */
	public static function verify( $json, $signature, $allow_retired_patches = false ) {
		if ( ! function_exists( 'sodium_crypto_sign_verify_detached' ) || ! is_string( $json ) || strlen( $json ) > 1048576 || ! is_string( $signature ) || strlen( $signature ) > 128 ) {
			return new WP_Error( 'envelope', 'Ed25519 and a bounded signature envelope are required.' );
		}
		$data  = json_decode( $json, true, 16 );
		$trust = self::trust();
		$now   = time();
		if ( ! is_array( $data ) || ! is_string( $data['key_id'] ?? null ) || ! is_array( $trust['keys'] ?? null ) ) {
			return new WP_Error( 'trust', 'Missing signing identity.' );
		}
		$key = $trust['keys'][ $data['key_id'] ] ?? null;
		if ( ! is_array( $key ) || ! is_string( $key['public_key'] ?? null ) || ! is_int( $key['not_before'] ?? null ) || ! is_int( $key['not_after'] ?? null ) || $key['not_before'] > $now || $key['not_after'] <= $now ) {
			return new WP_Error( 'trust', 'Signing key is unknown, revoked or outside its trust window.' );
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Bounded public key and detached signature, never executable content.
		$public = base64_decode( $key['public_key'], true );
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Bounded detached signature.
		$sig = base64_decode( $signature, true );
		if ( ! GWQSH_Crypto::verify_ed25519( $sig, $json, $public ) ) {
			return new WP_Error( 'signature', 'Advisory authenticity verification failed.' );
		}
		$fields = array( 'schema', 'feed', 'publisher', 'key_id', 'version', 'issued_at', 'expires_at', 'min_engine', 'advisories', 'patches', 'revoked' );
		if ( array_diff( array_keys( $data ), $fields ) || array_diff( $fields, array_keys( $data ) ) || 2 !== $data['schema'] || 'vulnerabilities' !== $data['feed'] || empty( $trust['publisher'] ) || $data['publisher'] !== $trust['publisher'] || ! is_int( $data['version'] ) || $data['version'] < 1 || ! is_int( $data['issued_at'] ) || ! is_int( $data['expires_at'] ) || $data['issued_at'] < $key['not_before'] || $data['issued_at'] > $now + 300 || $data['expires_at'] <= $now || $data['expires_at'] <= $data['issued_at'] || $data['expires_at'] > min( $key['not_after'], $data['issued_at'] + 30 * DAY_IN_SECONDS ) || ! is_string( $data['min_engine'] ) || ! preg_match( '/^[1-9][0-9]{0,3}$/D', $data['min_engine'] ) || version_compare( $data['min_engine'], self::ENGINE, '>' ) ) {
			return new WP_Error( 'schema', 'Malformed, expired or incompatible advisory package.' );
		}
		if ( ! is_array( $data['advisories'] ) || count( $data['advisories'] ) > 1000 || ! is_array( $data['patches'] ) || count( $data['patches'] ) > 100 || ! is_array( $data['revoked'] ) || count( $data['revoked'] ) > 1000 ) {
			return new WP_Error( 'bounds', 'Advisory package limits exceeded.' );
		}
		$ids = array();
		foreach ( $data['advisories'] as $advisory ) {
			if ( ! is_array( $advisory ) || array_diff( array_keys( $advisory ), array( 'id', 'component', 'ranges', 'severity', 'url', 'published_at', 'summary', 'cve' ) ) || ! self::identifier( $advisory['id'] ?? null ) || isset( $ids[ $advisory['id'] ] ) || ! self::component_id( $advisory['component'] ?? null ) || ! in_array( $advisory['severity'] ?? null, array( 'Low', 'Medium', 'High', 'Critical' ), true ) || ! is_string( $advisory['summary'] ?? null ) || strlen( $advisory['summary'] ) > 512 || ! is_int( $advisory['published_at'] ?? null ) || $advisory['published_at'] < 0 || $advisory['published_at'] > $data['issued_at'] + 300 || ! self::provenance( $advisory['url'] ?? null ) || ( isset( $advisory['cve'] ) && ( ! is_string( $advisory['cve'] ) || ! preg_match( '/^CVE-[0-9]{4}-[0-9]{4,10}$/D', $advisory['cve'] ) ) ) || ! is_array( $advisory['ranges'] ?? null ) || ! $advisory['ranges'] || count( $advisory['ranges'] ) > 20 ) {
				return new WP_Error( 'advisory', 'Invalid advisory or provenance.' );
			}
			foreach ( $advisory['ranges'] as $range ) {
				if ( ! is_array( $range ) || count( $range ) !== 3 || ! array_key_exists( 'introduced', $range ) || ! array_key_exists( 'fixed', $range ) || ! array_key_exists( 'last_affected', $range ) || ! self::supported_version( $range['introduced'] ) || ( null !== $range['fixed'] && ! self::supported_version( $range['fixed'] ) ) || ( null !== $range['last_affected'] && ! self::supported_version( $range['last_affected'] ) ) || ( null === $range['fixed'] && null === $range['last_affected'] ) || ( null !== $range['fixed'] && version_compare( $range['fixed'], $range['introduced'], '<=' ) ) || ( null !== $range['last_affected'] && version_compare( $range['last_affected'], $range['introduced'], '<' ) ) ) {
					return new WP_Error( 'range', 'Unsupported or unbounded affected-version constraint.' );
				}
			}
			$ids[ $advisory['id'] ] = true;
		}
		$patch_ids = array();
		foreach ( $data['patches'] as $patch ) {
			if ( ! is_array( $patch ) || array_diff( array_keys( $patch ), array( 'id', 'advisory', 'method', 'path', 'parameter', 'operator', 'value', 'expires_at', 'action' ) ) || ! self::identifier( $patch['id'] ?? null ) || isset( $patch_ids[ $patch['id'] ] ) || ! is_string( $patch['advisory'] ?? null ) || ! isset( $ids[ $patch['advisory'] ] ) || ! in_array( $patch['method'] ?? null, array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) || ! is_string( $patch['path'] ?? null ) || ! preg_match( '~^/(?:wp-json/[A-Za-z0-9_/-]{1,180}|wp-admin/admin-ajax\.php)$~D', $patch['path'] ) || ! is_string( $patch['parameter'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_-]{1,64}$/D', $patch['parameter'] ) || ! in_array( $patch['operator'] ?? null, array( 'equals', 'contains' ), true ) || ! is_string( $patch['value'] ?? null ) || strlen( $patch['value'] ) < 1 || strlen( $patch['value'] ) > 256 || ! is_int( $patch['expires_at'] ?? null ) || $patch['expires_at'] <= 0 || ( ! $allow_retired_patches && $patch['expires_at'] <= $now ) || $patch['expires_at'] > $data['expires_at'] ) {
				return new WP_Error( 'patch', 'Invalid advisory-bound virtual patch.' );
			}
			if ( '/wp-admin/admin-ajax.php' === $patch['path'] && ( ! is_string( $patch['action'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_-]{1,64}$/D', $patch['action'] ) ) ) {
				return new WP_Error( 'patch_action', 'AJAX patches require an exact action identifier.' );
			}
			$patch_ids[ $patch['id'] ] = true;
		}
		foreach ( $data['revoked'] as $id ) {
			if ( ! self::identifier( $id ) ) {
				return new WP_Error( 'revocation', 'Invalid revocation identifier.' );
			}
		}
		return $data;
	}

	/** Fixed identifier grammar.
	 *
	 * @param mixed $id Identifier.
	 * @return bool Valid identifier.
	 */
	private static function identifier( $id ) {
		return is_string( $id ) && (bool) preg_match( '/^[A-Za-z0-9_.-]{1,64}$/D', $id );
	}

	/** Atomic current/previous/watermark activation under an owned lease.
	 *
	 * @param string $json Signed bytes.
	 * @param string $signature Detached signature.
	 * @return true|WP_Error Result.
	 */
	public static function accept( $json, $signature ) {
		$data = self::verify( $json, $signature );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		$lock = GWQSH_Enterprise_Store::lock( 'advisory-update', 60 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Another advisory activation is running.' );
		}
		try {
			$state = (array) get_option( self::STATE, array() );
			if ( $data['version'] <= ( $state['high_water'] ?? 0 ) ) {
				return new WP_Error( 'replay', 'Replayed or downgraded advisory package rejected.' );
			}
			$next = array(
				'current'     => array(
					'json'            => $json,
					'signature'       => $signature,
					'data'            => $data,
					'key_fingerprint' => hash( 'sha256', self::trust()['keys'][ $data['key_id'] ]['public_key'] ),
				),
				'previous'    => $state['current'] ?? array(),
				'high_water'  => $data['version'],
				'revoked'     => array_values( array_unique( array_merge( $state['revoked'] ?? array(), $data['revoked'] ) ) ),
				'verified_at' => time(),
			);
			if ( count( $next['revoked'] ) > 5000 ) {
				return new WP_Error( 'revocation_capacity', 'Revocation history requires an operator-reviewed migration.' );
			}
			update_option( self::STATE, $next, false );
			if ( get_option( self::STATE ) !== $next ) {
				return new WP_Error( 'storage', 'Advisory activation failed; inspect storage health.' );
			}
			GWQSH_Activity_Logger::log(
				'Vulnerability intelligence updated',
				wp_json_encode(
					array(
						'version'   => $data['version'],
						'publisher' => $data['publisher'],
					)
				),
				'Security'
			);
			return true;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'advisory-update', $lock );
		}
	}

	/** Currently valid installed data. Removed keys immediately cease being trusted.
	 *
	 * @return array Valid package or no current intelligence.
	 */
	public static function database() {
		$state = (array) get_option( self::STATE, array() );
		// Cached parsed metadata is not authenticated by a public-key fingerprint.
		// Derive every runtime rule from the exact signed bytes under current trust.
		$json      = $state['current']['json'] ?? null;
		$signature = $state['current']['signature'] ?? null;
		if ( ! is_string( $json ) || strlen( $json ) > 1048576 || ! is_string( $signature ) || strlen( $signature ) > 128 ) {
			return array();
		}
		$fingerprint = hash( 'sha256', $json . "\0" . $signature . "\0" . wp_json_encode( self::trust() ) . "\0" . time() );
		if ( ( self::$runtime_cache['fingerprint'] ?? '' ) !== $fingerprint ) {
			$data = self::verify( $json, $signature, true );
			self::$runtime_cache = array(
				'fingerprint' => $fingerprint,
				'data'        => is_wp_error( $data ) ? array() : $data,
			);
		}
		return self::$runtime_cache['data'];
	}

	/** Revert only to independently reverified bytes; keep downgrade watermark/revocations.
	 * Authorization belongs to the existing one-use enterprise controller.
	 *
	 * @param int $expected Expected active version, preventing stale UI operations.
	 * @return true|WP_Error Result.
	 */
	public static function rollback( $expected ) {
		$lock = GWQSH_Enterprise_Store::lock( 'advisory-update', 60 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Another advisory activation is running.' );
		}
		try {
			$state = (array) get_option( self::STATE, array() );
			if ( ( $state['current']['data']['version'] ?? 0 ) !== $expected || empty( $state['previous'] ) ) {
				return new WP_Error( 'changed', 'No previous package or advisory version changed.' );
			}
			$data = self::verify( $state['previous']['json'], $state['previous']['signature'], true );
			if ( is_wp_error( $data ) ) {
				return $data;
			}
			$prior             = $state['current'];
			$state['current']  = $state['previous'];
			$state['previous'] = $prior;
			update_option( self::STATE, $state, false );
			if ( get_option( self::STATE ) !== $state ) {
				return new WP_Error( 'storage', 'Rollback could not be committed.' );
			}
			GWQSH_Activity_Logger::log(
				'Vulnerability intelligence rollback',
				wp_json_encode(
					array(
						'from' => $expected,
						'to'   => $data['version'],
					)
				),
				'Security'
			);
			return true;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'advisory-update', $lock );
		}
	}

	/** Background-only fixed HTTPS fetch; never called by frontend inspection.
	 *
	 * @return true|WP_Error Update result.
	 */
	public static function update() {
		$result = new WP_Error( 'unconfigured', 'Configure an authorized advisory publisher, public keys and HTTPS URL first.' );
		if ( GWQSH_Enterprise_Config::get( 'advisories' )['enabled'] && defined( 'GWQSH_ADVISORY_FEED_URL' ) && ! empty( self::trust()['keys'] ) ) {
			$hits = GWQSH_Enterprise_Store::hit( 'advisory-fetch', 'site', HOUR_IN_SECONDS );
			if ( null === $hits || $hits > 6 ) {
				return new WP_Error( 'rate', 'Advisory update rate limit reached.' );
			}
			$response = GWQSH_Secure_HTTP::request( 'advisories', GWQSH_ADVISORY_FEED_URL );
			$result   = is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ? new WP_Error( 'transport', 'Advisory update unavailable; previous data retained.' ) : self::accept( wp_remote_retrieve_body( $response ), wp_remote_retrieve_header( $response, 'x-gwqsh-ed25519' ) );
		}
		update_option(
			'gwqsh_advisory_health',
			array(
				'at'     => time(),
				'status' => is_wp_error( $result ) ? $result->get_error_code() : 'verified',
			),
			false
		);
		if ( is_wp_error( $result ) && 1 === GWQSH_Enterprise_Store::hit( 'advisory-alert', $result->get_error_code(), DAY_IN_SECONDS ) ) {
			GWQSH_Activity_Logger::log( 'Vulnerability intelligence update failed', $result->get_error_code(), 'Security' );
		}
		return $result;
	}

	/** Inventory active/inactive components by technical identifier.
	 *
	 * @return array Local versions; no inventory is transmitted.
	 */
	public static function inventory() {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
		global $wp_version;
		$out = array(
			self::CORE => array(
				'version' => $wp_version,
				'active'  => true,
			),
		);
		foreach ( get_plugins() as $file => $plugin ) {
			$out[ 'plugin:' . $file ] = array(
				'version' => $plugin['Version'],
				'active'  => is_plugin_active( $file ) || is_plugin_active_for_network( $file ),
			);
		}
		// MU files have a separate identity: equal filenames in plugins/ must not collide.
		foreach ( get_mu_plugins() as $file => $plugin ) {
			$out[ 'mu-plugin:' . $file ] = array(
				'version' => $plugin['Version'],
				'active'  => true,
			);
		}
		foreach ( wp_get_themes() as $slug => $theme ) {
			$out[ 'theme:' . $slug ] = array(
				'version' => $theme->get( 'Version' ),
				'active'  => in_array( $slug, array( get_stylesheet(), get_template() ), true ),
			);
		}
		return $out;
	}

	/** Read a candidate's current header without stale inventory caches.
	 *
	 * @param string $component Verified component ID.
	 * @return string|null Version or missing component.
	 */
	private static function installed_version( $component ) {
		global $wp_version;
		if ( in_array( $component, array( self::CORE, 'core:WordPress' ), true ) ) {
			return $wp_version;
		}
		list( $type, $relative ) = explode( ':', $component, 2 );
		// Supported REST/AJAX predicates require an active component's registered handler.
		if ( 'plugin' === $type ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
			if ( ! is_plugin_active( $relative ) && ! is_plugin_active_for_network( $relative ) ) {
				return null;
			}
		} elseif ( 'theme' === $type && ! in_array( $relative, array( get_stylesheet(), get_template() ), true ) ) {
			return null;
		}
		$root = 'mu-plugin' === $type ? WPMU_PLUGIN_DIR : ( 'plugin' === $type ? WP_PLUGIN_DIR : get_theme_root( $relative ) );
		$file = GWQSH_Security_Runtime::safe_path( $root . '/' . $relative . ( 'theme' === $type ? '/style.css' : '' ), $root );
		if ( ! $file || ! is_file( $file ) ) {
			return null;
		}
		return get_file_data( $file, array( 'version' => 'Version' ) )['version'];
	}

	/** Explicit status, including unsupported versions and inactive components.
	 *
	 * @return array|WP_Error Manager-only inventory and matching advisories.
	 */
	public static function report() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		$data      = self::database();
		$state     = (array) get_option( self::STATE, array() );
		$installed = $data;
		$inventory = self::inventory();
		$findings  = array();
		$assessments = array();
		$coverage    = array_fill_keys( array_keys( $inventory ), $data ? 'unknown' : 'intelligence_unavailable' );
		foreach ( $data['advisories'] ?? array() as $advisory ) {
			// Preserve exact signed bytes and historical packages; normalize lookup only.
			$key = 'core:WordPress' === $advisory['component'] ? self::CORE : $advisory['component'];
			if ( ! isset( $inventory[ $key ] ) ) {
				continue;
			}
			$component = $inventory[ $key ];
			$affected  = self::affected( $component['version'], $advisory['ranges'] );
			$revoked   = in_array( $advisory['id'], $state['revoked'] ?? array(), true );
			$status    = $revoked ? 'revoked' : ( null === $affected ? 'potentially_affected' : ( $affected ? 'confirmed_vulnerable' : 'not_affected' ) );
			if ( ! $revoked && false === $affected ) {
				// A version below introduction is not a fixed installation.
				$fixed = true;
				foreach ( $advisory['ranges'] as $range ) {
					if ( null === $range['fixed'] || version_compare( $component['version'], $range['fixed'], '<' ) ) {
						$fixed = false;
					}
				}
				$status = $fixed ? 'fixed' : 'not_affected';
			}
			$assessment = array(
				'advisory'    => $advisory,
				'installed'   => $component,
				'status_code' => $status,
				'status'      => $revoked ? 'Advisory revoked by publisher' : ( null === $affected ? 'Version requires manual review' : ( $affected ? 'Affected; update the component' : 'Outside the known affected ranges' ) ),
			);
			$assessments[] = $assessment;
			if ( ! $revoked ) {
				$coverage[ $key ] = 'advisories_available';
				if ( false !== $affected ) {
					$findings[] = $assessment;
				}
			}
		}
		return array(
			'status'      => $data ? 'Verified feed within validity window' : 'No current verified advisory coverage',
			'version'     => $installed['version'] ?? 0,
			'expires_at'  => $installed['expires_at'] ?? 0,
			'verified_at' => $state['verified_at'] ?? 0,
			'publisher'   => $installed['publisher'] ?? '',
			'inventory'   => $inventory,
			'findings'    => $findings,
			'assessments' => $assessments,
			'coverage'    => $coverage,
			'health'      => get_option( 'gwqsh_advisory_health', array() ),
		);
	}

	/** Select active patches only for this exact endpoint, method and affected version.
	 * No generic body-size policy may deny unrelated endpoints.
	 *
	 * @param string $path Exact endpoint.
	 * @param string $method HTTP method.
	 * @return array Applicable verified patch definitions.
	 */
	public static function scoped_patches( $path, $method ) {
		$data     = self::database();
		$state    = (array) get_option( self::STATE, array() );
		$rules    = array_column( $data['advisories'] ?? array(), null, 'id' );
		$disabled = array_merge( $state['revoked'] ?? array(), explode( "\n", GWQSH_Enterprise_Config::get( 'advisories' )['disabled'] ) );
		$versions = array();
		$matches  = array();
		foreach ( $data['patches'] ?? array() as $patch ) {
			if ( $patch['path'] !== $path || $patch['method'] !== $method || $patch['expires_at'] <= time() || in_array( $patch['id'], $disabled, true ) || in_array( $patch['advisory'], $disabled, true ) || ! isset( $rules[ $patch['advisory'] ] ) ) {
				continue;
			}
			$advisory  = $rules[ $patch['advisory'] ];
			$component = $advisory['component'];
			if ( ! array_key_exists( $component, $versions ) ) {
				$versions[ $component ] = self::installed_version( $component );
			}
			if ( null !== $versions[ $component ] && true === self::affected( $versions[ $component ], $advisory['ranges'] ) ) {
				$matches[] = $patch;
			}
		}
		return $matches;
	}

	/** Evaluate exact patch inputs without silently truncating protected parameters.
	 *
	 * @param array $patches Applicable verified patches.
	 * @param array $input Parsed input, never logged.
	 * @return array Verdict, ID and explicit coverage reason.
	 */
	public static function evaluate( array $patches, array $input, array $limited_parameters = array() ) {
		$until = microtime( true ) + 0.015;
		foreach ( $patches as $patch ) {
			if ( microtime( true ) > $until ) {
				return array(
					'status' => 'budget_exceeded',
					'id'     => $patch['id'],
					'reason' => 'patch_time_budget',
				);
			}
			if ( isset( $patch['action'] ) ) {
				$action = $input['action'] ?? null;
				if ( is_array( $action ) && ( count( $action ) > 8 || in_array( $patch['action'], $action, true ) ) ) {
					return array( 'status' => 'unsupported_type', 'id' => $patch['id'], 'reason' => 'protected_action_conflict' );
				}
				if ( $action !== $patch['action'] ) { continue; }
			}
			if ( ! array_key_exists( $patch['parameter'], $input ) ) {
				continue;
			}
			if ( isset( $limited_parameters[ $patch['parameter'] ] ) ) {
				return array( 'status' => 'budget_exceeded', 'id' => $patch['id'], 'reason' => 'protected_parameter_bounds' );
			}
			$value = $input[ $patch['parameter'] ];
			if ( ! is_string( $value ) || strlen( $value ) > 65536 ) {
				return array(
					'status' => is_string( $value ) ? 'budget_exceeded' : 'unsupported_type',
					'id'     => $patch['id'],
					'reason' => 'protected_parameter_bounds',
				);
			}
			if ( 'equals' === $patch['operator'] ? $value === $patch['value'] : false !== strpos( $value, $patch['value'] ) ) {
				return array(
					'status' => 'malicious_match',
					'id'     => $patch['id'],
					'reason' => '',
				);
			}
		}
		return array(
			'status' => 'fully_inspected',
			'id'     => '',
			'reason' => '',
		);
	}

	/** Do not silently overwrite conflicting evidence from independent request sources. */
	public static function merge_input( array $query, array $body ) {
		foreach ( $body as $key => $value ) {
			$query[ $key ] = array_key_exists( $key, $query ) && $query[ $key ] !== $value ? array( $query[ $key ], $value ) : $value;
		}
		return $query;
	}

	/** Compatibility adapter: incomplete protected inputs follow patch rollout policy.
	 *
	 * @param string $path Endpoint.
	 * @param string $method Method.
	 * @param array  $input Parsed inputs.
	 * @return string Matched or incomplete protected patch ID.
	 */
	public static function match( $path, $method, array $input ) {
		$verdict = self::evaluate( self::scoped_patches( $path, $method ), $input );
		if ( $verdict['reason'] ) {
			self::coverage( $verdict['reason'] );
		}
		return $verdict['id'];
	}

	/** Disclose bounded inspection gaps without persisting request content.
	 *
	 * @param string $reason Fixed internal coverage code.
	 */
	private static function coverage( $reason ) {
		if ( 1 === GWQSH_Enterprise_Store::hit( 'virtual-patch-coverage', $reason, 60 ) ) {
			GWQSH_Activity_Logger::log( 'Virtual patch inspection incomplete', $reason, 'Security' );
		}
	}

	/** Apply existing WAF rollout/exclusions to advisory-bound REST patches.
	 *
	 * @param mixed           $result Prior dispatch/authentication result.
	 * @param WP_REST_Server  $server REST server.
	 * @param WP_REST_Request $request REST request.
	 * @return mixed Original result or denied request.
	 */
	public static function inspect_rest( $result, $server, $request ) {
		$policy = GWQSH_Enterprise_Config::get( 'waf' );
		$mode   = GWQSH_Firewall::rollout( is_user_logged_in(), $policy );
		$path   = '/wp-json' . $request->get_route();
		if ( null !== $result || ! GWQSH_Settings::is_active() || ! GWQSH_Firewall::settings()['enabled'] || in_array( $policy['mode'], array( 'disabled', 'recovery' ), true ) || 'disabled' === $mode || GWQSH_Country_Access::emergency() || GWQSH_Login_Protection::is_ip_allowlisted( GWQSH_Settings::get_client_ip() ) || in_array( $path, explode( "\n", $policy['exclusions'] ), true ) ) {
			return $result;
		}
		$patches = self::scoped_patches( $path, $request->get_method() );
		if ( ! $patches ) {
			return $result;
		}
		$input  = $request->get_query_params();
		$reason = '';
		$limited_parameters = array();
		if ( strlen( $request->get_body() ) > 1048576 ) {
			$reason = 'budget_exceeded';
		} elseif ( $request->get_header( 'content-encoding' ) && 'identity' !== strtolower( $request->get_header( 'content-encoding' ) ) ) {
			$reason = 'unsupported_type';
		} elseif ( $request->is_json_content_type() ) {
			$body = json_decode( $request->get_body(), true, 32 );
			if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $body ) ) {
				$reason = 'parse_error';
			} else {
				$input = self::merge_input( $input, $body );
			}
		} else {
			$type  = strtolower( trim( explode( ';', $request->get_header( 'content-type' ) )[0] ) );
			if ( 'multipart/form-data' === $type ) {
				$multipart = GWQSH_Firewall::multipart_request( $request );
				if ( $multipart['error'] ) {
					$reason = 'inspection_budget_exceeded' === $multipart['state'] ? 'budget_exceeded' : ( 'unsupported_request_format' === $multipart['state'] ? 'unsupported_type' : 'parse_error' );
				} else {
					$input = self::merge_input( $input, $multipart['input'] );
					$limited_parameters = $multipart['limited_parameters'];
				}
			} elseif ( in_array( $type, array( '', 'application/x-www-form-urlencoded' ), true ) ) {
				$request->get_params(); // Trigger WordPress lazy parsing for non-POST form methods.
				$input = self::merge_input( $input, $request->get_body_params() );
			} elseif ( $request->get_body() ) {
				$reason = 'unsupported_type';
			}
		}
		$verdict = $reason ? array(
			'status' => $reason,
			'reason' => $reason,
			'id'     => '',
		) : self::evaluate( $patches, $input, $limited_parameters );
		if ( $verdict['reason'] ) {
			self::coverage( $verdict['reason'] );
			if ( 'block' === $policy['mode'] && 'block' === $mode && ! empty( GWQSH_Enterprise_Config::get( 'advisories' )['enforce'] ) ) {
				return new WP_Error(
					'gwqsh_virtual_patch_incomplete',
					'The protected endpoint could not be inspected within its security policy.',
					array(
						'status'   => 'budget_exceeded' === $verdict['status'] ? 413 : 400,
						'coverage' => $verdict['status'],
					)
				);
			}
			return $result;
		}
		$id = $verdict['id'];
		if ( ! $id ) {
			return $result;
		}
		$report = 'report' === $policy['mode'] || 'report' === $mode || ! GWQSH_Enterprise_Config::get( 'advisories' )['enforce'];
		if ( 1 === GWQSH_Enterprise_Store::hit( 'virtual-patch-audit', GWQSH_Settings::get_client_ip() . $id, 60 ) ) {
			GWQSH_Activity_Logger::log(
				$report ? 'Virtual patch detected' : 'Virtual patch blocked',
				wp_json_encode(
					array(
						'id'           => $id,
						'feed_version' => self::database()['version'] ?? 0,
					)
				),
				'Security'
			);
		}
		return $report ? $result : new WP_Error( 'gwqsh_virtual_patch', 'This request matched an advisory-specific security rule.', array( 'status' => 403 ) );
	}

	/** Audit installed plugins against WordPress.org API to detect abandoned or closed plugins.
	 *
	 * @return array Findings for outdated, abandoned, or closed plugins.
	 */
	public static function audit_installed_plugins() {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		$plugins  = get_plugins();
		$findings = array();
		foreach ( $plugins as $file => $meta ) {
			$slug = dirname( $file );
			if ( '.' === $slug || ! $slug ) {
				$slug = sanitize_title( $meta['Name'] ?? basename( $file, '.php' ) );
			}
			$cache_key = 'gwqsh_plug_info_v2_' . md5( $slug );
			$info      = get_transient( $cache_key );
			if ( false === $info ) {
				$url      = sprintf( 'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=%s', rawurlencode( $slug ) );
				$response = wp_remote_get( $url, array( 'timeout' => 3, 'limit_response_size' => 1048576 ) );
				if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
					$info = array( 'status' => 'unknown' );
				} else {
					$body = json_decode( wp_remote_retrieve_body( $response ), true );
					if ( is_array( $body ) && isset( $body['error'] ) ) {
						// Private/premium/missing slugs have the same not-found response.
						// This API result cannot prove closure or a vulnerability.
						$info = array( 'status' => 'repository_unavailable' );
					} elseif ( ! is_array( $body ) || ! is_string( $body['version'] ?? null ) || '' === $body['version'] ) {
						$info = array( 'status' => 'unknown' );
					} else {
						$last_updated = isset( $body['last_updated'] ) ? strtotime( $body['last_updated'] ) : 0;
						$abandoned    = ( $last_updated > 0 && ( time() - $last_updated ) > 730 * DAY_IN_SECONDS );
						$info         = array(
							'status'       => $abandoned ? 'abandoned' : 'active',
							'version'      => $body['version'] ?? '',
							'last_updated' => $body['last_updated'] ?? '',
							'abandoned'    => $abandoned,
						);
					}
				}
				set_transient( $cache_key, $info, DAY_IN_SECONDS );
			}
			if ( 'abandoned' === ( $info['status'] ?? '' ) ) {
				$findings[] = array(
					'plugin'   => $file,
					'name'     => $meta['Name'] ?? $slug,
					'version'  => $meta['Version'] ?? '',
					'type'     => 'abandoned',
					'severity' => 'Medium',
					'message'  => sprintf( 'Plugin "%s" has not been updated in over 2 years (last updated %s). It may lack modern security maintenance.', $meta['Name'] ?? $slug, $info['last_updated'] ?? 'unknown' ),
				);
			} elseif ( 'repository_unavailable' === ( $info['status'] ?? '' ) ) {
				$findings[] = array(
					'plugin'   => $file,
					'name'     => $meta['Name'] ?? $slug,
					'version'  => $meta['Version'] ?? '',
					'type'     => 'repository_unavailable',
					'severity' => 'Low',
					'message'  => sprintf( 'WordPress.org metadata for "%s" is unavailable. Private or premium plugins may not be listed; this does not confirm closure or a vulnerability. Check the plugin publisher.', $meta['Name'] ?? $slug ),
				);
			}
		}
		return $findings;
	}
}
