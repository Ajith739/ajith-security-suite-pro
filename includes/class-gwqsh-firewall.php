<?php
/** Bounded, opt-in public query protection and the Firewall screen adapter.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Opt-in query inspection and shared scanner statistics. */
final class GWQSH_Firewall {
	/** Read the current persisted query-rule settings. */
	public static function settings() {
		return wp_parse_args(
			(array) get_option( 'gwqsh_firewall', array() ),
			array(
				'enabled' => false,
				'sql'     => true,
				'xss'     => true,
				'bots'    => true,
			)
		);
	}
	/**
	 * Register the public request hook and, separately, the authenticated payload hook.
	 *
	 * The two hooks stay independent so an administrator can enable public query
	 * protection without also inspecting their own authenticated traffic.
	 */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'inspect' ), 2 );
		add_action( 'init', array( __CLASS__, 'inspect_privileged' ), 3 ); }
	/**
	 * Match bounded query evidence without executing it.
	 *
	 * @param array  $values Query values.
	 * @param string $agent Visitor agent.
	 * @param string $path Request path without its query.
	 * @param array  $settings Rule configuration.
	 * @return string Matched rule, or an empty string.
	 */
	public static function match( array $values, $agent, $path, array $settings ) {
		$budget   = 16384;
		$visited  = 0;
		$iterator = new RecursiveIteratorIterator( new RecursiveArrayIterator( $values ) );
		foreach ( $iterator as $value ) {
			if ( ++$visited > 64 || $budget <= 0 ) {
				break; }
			if ( ! is_scalar( $value ) ) {
				continue; }
			$value   = substr( (string) $value, 0, min( 2048, $budget ) );
			$budget -= strlen( $value );
			// One extra decoding pass covers encoded probes without exponential normalization.
			$value = rawurldecode( $value );
			if ( $settings['sql'] && ( preg_match( '/\bunion\s+(?:all\s+)?select\s+(?:null|[0-9]+)\s*,/i', $value ) || preg_match( '/[\'"]\s*(?:or|and)\s+[0-9]{1,8}\s*=\s*[0-9]{1,8}\s*(?:--|#|\/\*)/i', $value ) ) ) {
				return 'SQL Injection'; }
			if ( $settings['xss'] && preg_match( '/<\s*(?:script\b[^>]{0,256}>|(?:img|svg)\b[^>]{0,256}\bon(?:error|load)\s*=)/i', $value ) ) {
				return 'XSS Attempt'; }
		}
		// Correlate a scanner agent with an exploit-only path; agent alone never denies.
		if ( $settings['bots'] && preg_match( '/(?:sqlmap|nikto|nuclei)/i', substr( $agent, 0, 256 ) ) && preg_match( '~/(?:\.env(?:$|/)|\.git/|vendor/phpunit/|wp-config\.php$)~i', substr( $path, 0, 512 ) ) ) {
			return 'Bad Bot'; }
		return '';
	}

	/** Rule metadata is fixed source data, never executable downloaded patterns. */
	public static function rules() {
		return array(
			'GWQSH-1001' => array(
				'category'   => 'traversal',
				'severity'   => 'High',
				'confidence' => 'High',
				'version'    => 1,
			),
			'GWQSH-1002' => array(
				'category'   => 'inclusion',
				'severity'   => 'High',
				'confidence' => 'High',
				'version'    => 1,
			),
			'GWQSH-1003' => array(
				'category'   => 'uploads',
				'severity'   => 'High',
				'confidence' => 'Review',
				'version'    => 1,
			),
			'GWQSH-1004' => array(
				'category'   => 'post',
				'severity'   => 'High',
				'confidence' => 'Review',
				'version'    => 1,
			),
			'GWQSH-1005' => array(
				'category'   => 'rate',
				'severity'   => 'Medium',
				'confidence' => 'Measured',
				'version'    => 1,
			),
			'GWQSH-1006' => array(
				'category'   => 'authenticated',
				'severity'   => 'High',
				'confidence' => 'Review',
				'version'    => 1,
			),
			'GWQSH-1007' => array(
				'category'   => 'authenticated',
				'severity'   => 'High',
				'confidence' => 'Review',
				'version'    => 1,
			),
		);
	}
	/**
	 * Evaluate the configurable rule set against request inputs. Values are read as
	 * evidence for a denial decision and are never persisted or echoed back.
	 *
	 * @param array  $query    Query values.
	 * @param array  $post     Posted values.
	 * @param array  $files    Uploaded file descriptors.
	 * @param string $path     Request path.
	 * @param array  $settings Effective firewall settings.
	 * @return string Matched rule id, or an empty string.
	 */
	public static function advanced( array $query, array $post, array $files, $path, array $settings ) {
		$values  = array( $path );
		$budget  = 16384;
		$visited = 0;
		$iter    = new RecursiveIteratorIterator( new RecursiveArrayIterator( $query ) );
		foreach ( $iter as $value ) {
			if ( ++$visited > 64 || $budget <= 0 ) {
				break;
			}if ( ! is_scalar( $value ) ) {
				continue;
			}$v       = substr( (string) $value, 0, min( 2048, $budget ) );
			$budget  -= strlen( $v );
			$values[] = rawurldecode( $v );}
		foreach ( $values as $value ) {
			if ( $settings['traversal'] && preg_match( '~(?:\.\.[/\\\\]){2}|(?:%2e){2}(?:%2f|%5c)~i', $value ) ) {
				return 'GWQSH-1001';
			}
			if ( $settings['inclusion'] && preg_match( '~(?:php|expect|phar|data)://|(?:^|[= /])(?:/etc/passwd|/proc/self/environ)~i', $value ) ) {
				return 'GWQSH-1002';
			}
		}
		if ( $settings['uploads'] ) {
			foreach ( array_slice( $files, 0, 10 ) as $file ) {
				$name = $file['name'] ?? '';
				if ( is_string( $name ) && preg_match( '/\.(?:php[0-9]?|phtml|phar)(?:\.|$)/i', substr( $name, 0, 256 ) ) ) {
					return 'GWQSH-1003';
				}
			}
		}
		if ( $settings['post'] ) {
			// Never inspect password, authentication, checkout or session material as raw request bodies.
			$safe = array();
			foreach ( array_slice( $post, 0, 32, true ) as $key => $value ) {
				if ( ! preg_match( '/pass|token|nonce|secret|code|assert|cookie|session|credit|card|payment/i', (string) $key ) && is_string( $value ) ) {
					$safe[ $key ] = substr( $value, 0, 1024 );
				}
			}
			if ( self::match(
				$safe,
				'',
				'',
				array(
					'sql'  => true,
					'xss'  => true,
					'bots' => false,
				)
			) ) {
				return 'GWQSH-1004';
			}
		}
		return '';
	}
	/** Inspect unauthenticated public query requests only. */
	public static function inspect() {
		$settings = self::settings();
		if ( ! $settings['enabled'] || ! GWQSH_Settings::is_active() || is_user_logged_in() || ( is_admin() && ! wp_doing_ajax() ) || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return; }
		if ( GWQSH_Country_Access::emergency() ) {
			return; }
		$advanced = GWQSH_Enterprise_Config::get( 'waf' );
		if ( 'disabled' === $advanced['mode'] ) {
			return; }
		$ip = GWQSH_Settings::get_client_ip();
		if ( GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return; }
		$path = substr( (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/', PHP_URL_PATH ), 0, 200 );
		if ( in_array( $path, explode( "\n", $advanced['exclusions'] ), true ) ) {
			return; }
		// Query inputs only: editor/form HTML, REST bodies and password fields are untouched.
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Request evidence is inspected for denial, never accepted as a settings mutation.
		$rule = self::match( wp_unslash( $_GET ), isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', $path, $settings );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended -- Request evidence is inspected for denial, never accepted as a settings mutation.
		$new_rule = self::advanced( wp_unslash( $_GET ), wp_unslash( $_POST ), $_FILES, $path, $advanced );
		if ( ! $new_rule && $advanced['rate'] ) {
			$count = GWQSH_Enterprise_Store::hit( 'waf-rate', $ip, 60 );
			if ( null !== $count && $count > $advanced['requests'] ) {
				$new_rule = 'GWQSH-1005'; }
		}
		if ( ! $rule && ! $new_rule ) {
			return; }
		$detected = 'report' === $advanced['mode'] || ( ! $rule && ! $advanced['enforce_new'] );
		if ( ! $rule ) {
			$rule = $new_rule; }

		// Best-effort per-visitor/rule minute deduplication; existing log retention applies.
		$dedup = GWQSH_Enterprise_Store::hit( 'waf-audit', $ip . $rule, 60 );
		if ( 1 === $dedup ) {
			GWQSH_Activity_Logger::log(
				$detected ? 'Firewall request detected' : 'Firewall request blocked',
				wp_json_encode(
					array(
						'rule'          => $rule,
						'path'          => $path,
						'rule_metadata' => self::rules()[ $new_rule ] ?? array(
							'version'    => 1,
							'confidence' => 'High',
						),
					)
				),
				'Security',
				'—',
				$ip
			);
		}
		if ( $detected ) {
			return; }
		status_header( 'GWQSH-1005' === $rule ? 429 : 403 );
		nocache_headers();
		GWQSH_UI::error( 'GWQSH-1005' === $rule ? 429 : 403, 'Request blocked', 'This request matched a security rule. Contact the site administrator if you believe this is an error.' );
	}
	/**
	 * Paths whose payloads WordPress content authors legitimately fill with rich markup.
	 *
	 * Authenticated inspection still records findings on these paths, but they are never
	 * blocked: denying an editor's own save would be data loss, not protection.
	 *
	 * @return array Exact request paths.
	 */
	public static function content_writer_paths() {
		return array(
			'/wp-admin/post.php',
			'/wp-admin/post-new.php',
			'/wp-admin/admin-ajax.php',
			'/wp-json/wp/v2/posts',
			'/wp-json/wp/v2/pages',
		);
	}

	/**
	 * Collect the bounded, non-credential scalars of an authenticated request.
	 *
	 * Values are never stored: findings record the parameter name, rule and context only.
	 * Oversized values (rich content, uploaded files, serialized editor state), nested
	 * arrays, sensitive parameter names and file uploads are all skipped by design.
	 *
	 * @param array  $values Raw request values.
	 * @param string $source Label recorded with a finding ('post' or 'query').
	 * @return array Parameter name to inspected string.
	 */
	private static function privileged_values( array $values, $source ) {
		$safe      = array();
		$inspected = 0;
		$budget    = 8192;
		foreach ( $values as $key => $value ) {
			if ( $inspected >= 40 || $budget <= 0 ) {
				break;
			}
			if ( ! is_string( $key ) || ! is_scalar( $value ) || is_bool( $value ) ) {
				continue;
			}
			if ( preg_match( '/nonce|pass|pwd|secret|token|auth|cookie|session|credit|card|payment|_wp_http_referer/i', $key ) ) {
				continue;
			}
			$value = (string) $value;
			if ( strlen( $value ) > 1024 ) {
				// Long values are editor content, not attack parameters.
				continue;
			}
			$budget -= strlen( $value );
			++$inspected;
			$safe[ $source . ':' . sanitize_text_field( $key ) ] = rawurldecode( $value );
		}
		return $safe;
	}

	/**
	 * Decide what to do with an authenticated-context match. Pure policy, no request effects.
	 *
	 * @param string $rule     Matched rule id.
	 * @param string $path     Request path.
	 * @param array  $settings Authenticated-inspection configuration.
	 * @return string 'ignore', 'detect' or 'block'.
	 */
	public static function privileged_decision( $rule, $path, array $settings ) {
		if ( '' === $rule || empty( $settings['privileged'] ) ) {
			return 'ignore';
		}
		$excluded = isset( $settings['privileged_exclusions'] ) ? (string) $settings['privileged_exclusions'] : '';
		foreach ( preg_split( '/[\s,]+/', $excluded, -1, PREG_SPLIT_NO_EMPTY ) as $exclusion ) {
			if ( 0 === strpos( $rule, $exclusion ) ) {
				return 'ignore';
			}
		}
		if ( 'block' !== ( $settings['mode'] ?? 'block' ) || empty( $settings['privileged_enforce'] ) ) {
			return 'detect';
		}
		if ( in_array( $path, self::content_writer_paths(), true ) ) {
			return 'detect';
		}
		foreach ( preg_split( '/[\s,]+/', isset( $settings['exclusions'] ) ? (string) $settings['exclusions'] : '', -1, PREG_SPLIT_NO_EMPTY ) as $exclusion ) {
			if ( $path === $exclusion ) {
				return 'detect';
			}
		}
		return 'block';
	}

	/**
	 * Inspect authenticated request payloads when the administrator has opted in.
	 *
	 * Scope: logged-in requests only, one bounded pass over non-credential POST/query
	 * scalars. Detection is the default; enforcement requires both the blocking mode and
	 * the explicit enable switch, and content-authoring endpoints are never denied.
	 * Findings record the parameter name, rule and context — never the submitted value.
	 */
	public static function inspect_privileged() {
		if ( ! is_user_logged_in() || ! GWQSH_Settings::is_active() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		if ( GWQSH_Country_Access::emergency() ) {
			return;
		}
		$advanced = GWQSH_Enterprise_Config::get( 'waf' );
		if ( empty( $advanced['privileged'] ) || 'disabled' === $advanced['mode'] ) {
			return;
		}
		$importing = defined( 'WP_IMPORTING' ) && WP_IMPORTING;
		if ( $importing ) {
			return;
		}
		$path = substr( (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/', PHP_URL_PATH ), 0, 200 );
		$ip   = GWQSH_Settings::get_client_ip();
		if ( GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return;
		}
		$context = 'admin';
		if ( wp_doing_ajax() ) {
			$context = 'ajax';
		} elseif ( defined( 'REST_REQUEST' ) && REST_REQUEST ) {
			$context = 'rest';
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing,WordPress.Security.NonceVerification.Recommended -- Request evidence is inspected for denial; the dispatcher's own nonce and capability checks still authorize every action.
		$values = self::privileged_values( wp_unslash( $_POST ), 'post' );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Request evidence is inspected for denial, never accepted as a mutation.
		$values += self::privileged_values( wp_unslash( $_GET ), 'query' );
		if ( ! $values ) {
			return;
		}
		$rule      = '';
		$parameter = '';
		foreach ( $values as $name => $value ) {
			$matched = self::match(
				array( $name => $value ),
				'',
				'',
				array(
					'sql'  => true,
					'xss'  => true,
					'bots' => false,
				)
			);
			if ( $matched ) {
				$rule = 'GWQSH-1006';
			} elseif ( preg_match( '~(?:\.\.[/\\]){2}|(?:php|expect|phar|data)://~i', $value ) ) {
				$rule = 'GWQSH-1007';
			}
			if ( $rule ) {
				$parameter = substr( (string) $name, 0, 96 );
				break;
			}
		}
		$decision = self::privileged_decision( $rule, $path, $advanced );
		if ( 'ignore' === $decision ) {
			return;
		}
		$dedup = GWQSH_Enterprise_Store::hit( 'waf-privileged', get_current_user_id() . $rule . $parameter, 60 );
		if ( 1 === $dedup ) {
			GWQSH_Activity_Logger::log(
				'block' === $decision ? 'Firewall authenticated request blocked' : 'Firewall authenticated request detected',
				wp_json_encode(
					array(
						'rule'          => $rule,
						'path'          => $path,
						'context'       => $context,
						'parameter'     => $parameter,
						'rule_metadata' => self::rules()[ $rule ] ?? array(
							'version'    => 1,
							'confidence' => 'Review',
						),
					)
				),
				'Security',
				'—',
				$ip
			);
		}
		if ( 'block' !== $decision ) {
			return;
		}
		status_header( 403 );
		nocache_headers();
		GWQSH_UI::error( 403, 'Request blocked', 'This request matched a security rule. Review the plugin Firewall settings if this was part of your work.' );
	}

	/**
	 * Save after the existing controller verifies nonce and manage_options.
	 *
	 * @param array $input Explicit whitelisted on/off states.
	 * @return true|WP_Error Persistence result.
	 */
	public static function save( array $input ) {
		$current = self::settings();
		foreach ( array( 'enabled', 'sql', 'xss', 'bots', 'login' ) as $key ) {
			if ( ! isset( $input[ $key ] ) || ! is_scalar( $input[ $key ] ) || ! in_array( (string) $input[ $key ], array( '0', '1' ), true ) ) {
				return new WP_Error( 'invalid_state', 'Use explicit on/off states for every supported rule.' ); }
		}
		if ( ( ( $current['enabled'] && '0' === $input['enabled'] ) || ( GWQSH_Login_Protection::get_settings()['enabled'] && '0' === $input['login'] ) ) && '1' !== ( $input['confirmed'] ?? '' ) ) {
			return new WP_Error( 'confirmation_required', 'Confirm disabling query or login protection.' ); }
		foreach ( array( 'enabled', 'sql', 'xss', 'bots' ) as $key ) {
			$current[ $key ] = '1' === $input[ $key ]; }
		update_option( 'gwqsh_firewall', $current, false );
		if ( self::settings() !== $current ) {
			return new WP_Error( 'save_failed', 'Unable to persist firewall settings.' ); }
		if ( ( '1' === $input['login'] ) !== (bool) GWQSH_Login_Protection::get_settings()['enabled'] ) {
			GWQSH_Login_Protection::update_settings( array( 'enabled' => '1' === $input['login'] ) );
		}
		if ( ( '1' === $input['login'] ) !== (bool) GWQSH_Login_Protection::get_settings()['enabled'] ) {
			return new WP_Error( 'login_save_failed', 'Unable to save the shared login protection state.' );
		}
		GWQSH_Activity_Logger::log( 'Firewall settings changed', wp_json_encode( $current ), 'Security' );
		return true;
	}
	/**
	 * Provide real retained denials, active findings and safe progress metadata.
	 *
	 * @param int $page Denial log page.
	 * @return array Screen data; no secrets or source content.
	 */
	public static function data( $page = 1 ) {
		global $wpdb;
		$table = $wpdb->prefix . 'gwqsh_activity_log';
		$page  = max( 1, min( 10000, (int) $page ) );
		$where = "event_name IN ('Firewall request blocked','Login blocked by lockout','XML-RPC login blocked','XML-RPC access blocked','Manual IP request blocked','Country request blocked','Reputation request blocked')";
		// phpcs:ignore WordPress.DB -- Plugin-owned table identifiers and fixed event predicates; all variable values are prepared. Live aggregates avoid stale security state.
		// phpcs:ignore WordPress.DB,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table} WHERE {$where}" );
		// phpcs:ignore WordPress.DB -- Plugin-owned table identifiers and fixed event predicates; all variable values are prepared. Live aggregates avoid stale security state.
		// phpcs:ignore WordPress.DB,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT event_time,event_name,ip_address,details FROM {$table} WHERE {$where} ORDER BY id DESC LIMIT 5 OFFSET %d", ( $page - 1 ) * 5 ), ARRAY_A );
		foreach ( $rows as &$row ) {
			$details           = json_decode( $row['details'], true );
			$row['rule']       = 'Firewall request blocked' === $row['event_name'] ? ( $details['rule'] ?? 'Suspicious Request' ) : ( 'XML-RPC access blocked' === $row['event_name'] ? 'XML-RPC' : 'Login Lockout' );
			$row['path']       = 'Firewall request blocked' === $row['event_name'] ? ( $details['path'] ?? 'Not recorded' ) : ( 'XML-RPC access blocked' === $row['event_name'] || 'XML-RPC login blocked' === $row['event_name'] ? '/xmlrpc.php' : 'Authentication endpoint' );
			$row['country']    = GWQSH_Network::country( $row['ip_address'] )['country'];
			$row['time_label'] = GWQSH_Time::format( $row['event_time'] );
			if ( 'Manual IP request blocked' === $row['event_name'] ) {
				$row['rule'] = 'Manual IP restriction';
				$row['path'] = 'Requested resource'; }
			unset( $row['details'] );
		} unset( $row );
		$summary  = GWQSH_File_Integrity::get_summary();
		$progress = GWQSH_Scan_Engine::load( 'gwqsh_scan_progress' );
		// Aggregate in SQL rather than loading source evidence for every finding into memory.
		$scan_table    = $wpdb->prefix . 'gwqsh_scan_results';
		$critical_like = '%"severity":"Critical"%';
		// phpcs:ignore WordPress.DB -- Plugin-owned table identifiers and fixed event predicates; all variable values are prepared. Live aggregates avoid stale security state.
		// phpcs:ignore WordPress.DB,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$groups  = $wpdb->get_results( $wpdb->prepare( "SELECT status, (evidence LIKE %s) AS critical, COUNT(*) AS count FROM {$scan_table} WHERE is_resolved = 0 GROUP BY status, critical", $critical_like ), ARRAY_A );
		$results = array(
			'malware'    => 0,
			'suspicious' => 0,
			'unknown'    => 0,
			'clean'      => (int) $summary['clean'],
		);
		foreach ( $groups as $group ) {
			$key              = $group['critical'] ? 'malware' : ( 'Suspicious' === $group['status'] ? 'suspicious' : 'unknown' );
			$results[ $key ] += (int) $group['count'];
		}
		// phpcs:ignore WordPress.DB -- Plugin-owned table identifiers and fixed event predicates; all variable values are prepared. Live aggregates avoid stale security state.
		// phpcs:ignore WordPress.DB,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$month      = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$scan_table} WHERE evidence LIKE %s AND detected_at >= %s", $critical_like, current_time( 'Y-m-01 00:00:00' ) ) );
		$quarantine = GWQSH_Quarantine_Manager::list_quarantined();
		$isolated   = count(
			array_filter(
				$quarantine,
				static function ( $record ) {
					return 'Quarantined' === $record['status'];
				}
			)
		);
		// phpcs:ignore WordPress.DB -- Fixed plugin-owned table and constant resolution status; no visitor SQL.
		// phpcs:ignore WordPress.DB,PluginCheck.Security.DirectDB.UnescapedDBParameter -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$cleaned = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$scan_table} WHERE is_resolved = 1 AND status = 'Resolved — Removed'" );
		$health  = (array) get_option( 'gwqsh_scan_health', array() );
		return array(
			'settings'         => self::settings(),
			'active'           => GWQSH_Settings::is_active(),
			'login'            => GWQSH_Login_Protection::get_settings(),
			'lockouts'         => array_slice( GWQSH_Login_Protection::get_currently_locked_ips(), 0, 25 ),
			'allowlist'        => array_slice( GWQSH_Login_Protection::get_allowlist(), 0, 50 ),
			'blocked'          => $count,
			'events'           => $rows,
			'page'             => $page,
			'pages'            => max( 1, (int) ceil( $count / 5 ) ),
			'summary'          => $summary,
			'results'          => $results,
			'month'            => $month,
			'isolated'         => $isolated,
			'cleaned'          => $cleaned,
			'quarantine_count' => count( $quarantine ),
			'health'           => $health,
			'progress'         => $progress ? array(
				'offset' => $progress['offset'],
				'total'  => count( $progress['files'] ),
				'errors' => array_keys( $progress['errors'] ),
				'phase'  => isset( $progress['files'][ $progress['offset'] ] ) ? GWQSH_Scan_Engine::scope( $progress['files'][ $progress['offset'] ] ) : 'Finishing',
			) : null,
		);
	}
}
