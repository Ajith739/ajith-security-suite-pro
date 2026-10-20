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
	 * @return array|WP_Error Validated package.
	 */
	public static function verify( $json, $signature ) {
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
			if ( ! is_array( $patch ) || array_diff( array_keys( $patch ), array( 'id', 'advisory', 'method', 'path', 'parameter', 'operator', 'value', 'expires_at', 'action' ) ) || ! self::identifier( $patch['id'] ?? null ) || isset( $patch_ids[ $patch['id'] ] ) || ! is_string( $patch['advisory'] ?? null ) || ! isset( $ids[ $patch['advisory'] ] ) || ! in_array( $patch['method'] ?? null, array( 'GET', 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) || ! is_string( $patch['path'] ?? null ) || ! preg_match( '~^/(?:wp-json/[A-Za-z0-9_/-]{1,180}|wp-admin/admin-ajax\.php)$~D', $patch['path'] ) || ! is_string( $patch['parameter'] ?? null ) || ! preg_match( '/^[A-Za-z0-9_-]{1,64}$/D', $patch['parameter'] ) || ! in_array( $patch['operator'] ?? null, array( 'equals', 'contains' ), true ) || ! is_string( $patch['value'] ?? null ) || strlen( $patch['value'] ) < 1 || strlen( $patch['value'] ) > 256 || ! is_int( $patch['expires_at'] ?? null ) || $patch['expires_at'] <= $now || $patch['expires_at'] > $data['expires_at'] ) {
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
		$data  = $state['current']['data'] ?? array();
		$trust = self::trust();
		$key   = $trust['keys'][ $data['key_id'] ?? '' ] ?? array();
		return ( $data['expires_at'] ?? 0 ) > time() && ( $data['publisher'] ?? null ) === ( $trust['publisher'] ?? '' ) && ( $key['not_before'] ?? PHP_INT_MAX ) <= ( $data['issued_at'] ?? 0 ) && ( $key['not_after'] ?? 0 ) >= ( $data['expires_at'] ?? 0 ) && hash_equals( $state['current']['key_fingerprint'] ?? '', hash( 'sha256', $key['public_key'] ?? '' ) ) ? $data : array();
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
			$data = self::verify( $state['previous']['json'], $state['previous']['signature'] );
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
		$installed = $state['current']['data'] ?? array();
		$inventory = self::inventory();
		$findings  = array();
		foreach ( $data['advisories'] ?? array() as $advisory ) {
			// Preserve exact signed bytes and historical packages; normalize lookup only.
			$key = 'core:WordPress' === $advisory['component'] ? self::CORE : $advisory['component'];
			if ( ! isset( $inventory[ $key ] ) ) {
				continue;
			}
			$component = $inventory[ $key ];
			$affected  = self::affected( $component['version'], $advisory['ranges'] );
			if ( false !== $affected ) {
				$findings[] = array(
					'advisory'  => $advisory,
					'installed' => $component,
					'status'    => null === $affected ? 'Version requires manual review' : 'Affected; update the component',
				);
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
			'health'      => get_option( 'gwqsh_advisory_health', array() ),
		);
	}

	/** Match data-only predicates with fresh affected-version gating.
	 *
	 * @param string $path Exact normalized endpoint path.
	 * @param string $method HTTP method.
	 * @param array  $input Bounded request parameters, never logged.
	 * @return string Matched patch ID, or no match.
	 */
	public static function match( $path, $method, array $input ) {
		$data     = self::database();
		$state    = (array) get_option( self::STATE, array() );
		$rules    = array_column( $data['advisories'] ?? array(), null, 'id' );
		$until    = microtime( true ) + 0.015;
		$version  = array();
		$disabled = array_merge( $state['revoked'] ?? array(), explode( "\n", GWQSH_Enterprise_Config::get( 'advisories' )['disabled'] ) );
		foreach ( $data['patches'] ?? array() as $patch ) {
			if ( microtime( true ) > $until ) {
				self::coverage( 'patch_time_budget' );
				break;
			}
			if ( $patch['path'] !== $path || $patch['method'] !== $method || $patch['expires_at'] <= time() || in_array( $patch['id'], $disabled, true ) || in_array( $patch['advisory'], $disabled, true ) || ! isset( $rules[ $patch['advisory'] ], $input[ $patch['parameter'] ] ) || ! is_string( $input[ $patch['parameter'] ] ) || strlen( $input[ $patch['parameter'] ] ) > 2048 ) {
				continue;
			}
			if ( isset( $patch['action'] ) && ( $input['action'] ?? null ) !== $patch['action'] ) {
				continue;
			}
			$value = $input[ $patch['parameter'] ];
			if ( 'equals' === $patch['operator'] ? $value !== $patch['value'] : false === strpos( $value, $patch['value'] ) ) {
				continue;
			}
			$advisory  = $rules[ $patch['advisory'] ];
			$component = $advisory['component'];
			if ( ! array_key_exists( $component, $version ) ) {
				$version[ $component ] = self::installed_version( $component );
			}
			if ( null === $version[ $component ] || true !== self::affected( $version[ $component ], $advisory['ranges'] ) ) {
				continue;
			}
			return $patch['id'];
		}
		return '';
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
		$input = $request->get_query_params();
		if ( count( $input ) > 128 || strlen( $request->get_body() ) > 16384 || count( $request->get_body_params() ) > 128 ) {
			self::coverage( 'request_bounds' );
			if ( 'block' === $mode && ! empty( GWQSH_Enterprise_Config::get( 'advisories' )['enforce'] ) ) {
				return new WP_Error( 'gwqsh_virtual_patch_incomplete', 'This request exceeded the configured virtual-patch inspection limits.', array( 'status' => 413 ) );
			}
			return $result;
		}
		if ( $request->is_json_content_type() ) {
			$body = json_decode( $request->get_body(), true, 10 );
			if ( is_array( $body ) ) {
				$input = array_merge( $input, $body );
			}
		} else {
			$input = array_merge( $input, $request->get_body_params() );
		}
		$id = self::match( $path, $request->get_method(), $input );
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
}
