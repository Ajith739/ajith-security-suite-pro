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
				'enabled' => true,
				'sql'     => true,
				'xss'     => true,
				'bots'    => true,
			)
		);
	}
	/** Register one public request hook; no duplicate authentication hooks. */
	public static function init() {
		add_action( 'init', array( __CLASS__, 'inspect' ), 2 );
		add_filter( 'rest_pre_dispatch', array( __CLASS__, 'inspect_rest' ), 10, 3 );
	}
	/** Preserve explicitly authorized authored fields while inspecting other inputs.
	 *
	 * @param array  $body Parsed body fields.
	 * @param string $route REST route, or empty for a native editor request.
	 * @return array Non-authored evidence.
	 */
	public static function editing_evidence( array $body, $route = '' ) {
		if ( ! current_user_can( 'unfiltered_html' ) ) {
			return $body;
		}
		$editing = false;
		if ( $route && preg_match( '~^/wp/v2/(posts|pages|blocks)(?:/([0-9]+))?/?$~D', $route, $matches ) ) {
			$type       = array(
				'posts'  => 'post',
				'pages'  => 'page',
				'blocks' => 'wp_block',
			)[ $matches[1] ];
			$definition = get_post_type_object( $type );
			$editing    = ! empty( $matches[2] ) ? current_user_can( 'edit_post', (int) $matches[2] ) : ( $definition && current_user_can( $definition->cap->create_posts ) );
		} elseif ( ! $route && is_admin() && in_array( $GLOBALS['pagenow'] ?? '', array( 'post.php', 'post-new.php' ), true ) && in_array( $body['action'] ?? '', array( 'editpost', 'post' ), true ) ) {
			$editing = ! empty( $body['post_ID'] ) ? current_user_can( 'edit_post', absint( $body['post_ID'] ) ) : current_user_can( 'edit_posts' );
		}
		if ( $editing ) {
			foreach ( array( 'content', 'title', 'excerpt', 'post_content', 'post_title', 'post_excerpt' ) as $key ) {
				unset( $body[ $key ] );
			}
		}
		return $body;
	}

	/** Inspect opt-in bounded REST JSON after WordPress authentication.
	 * Authentication/controller authorization remains owned by WordPress.
	 *
	 * @param mixed           $result Prior short-circuit result.
	 * @param WP_REST_Server  $server REST server.
	 * @param WP_REST_Request $request Authenticated REST request.
	 * @return mixed Prior result, or a structured denial.
	 */
	public static function inspect_rest( $result, $server, $request ) {
		$legacy   = self::settings();
		$settings = GWQSH_Enterprise_Config::get( 'waf' );
		if ( null !== $result || ! $legacy['enabled'] || ! GWQSH_Settings::is_active() || empty( $settings['rest_json'] ) || in_array( $settings['mode'], array( 'disabled', 'recovery' ), true ) || GWQSH_Country_Access::emergency() || ! $request->is_json_content_type() ) {
			return $result;
		}
		$mode = self::rollout( is_user_logged_in(), $settings );
		$ip   = GWQSH_Settings::get_client_ip();
		$path = '/wp-json' . $request->get_route();
		if ( 'disabled' === $mode || GWQSH_Login_Protection::is_ip_allowlisted( $ip ) || in_array( $path, explode( "\n", $settings['exclusions'] ), true ) ) {
			return $result;
		}
		$body   = $request->get_body();
		$reason = '';
		if ( strlen( $body ) > 16384 ) {
			$reason = 'rest_body_size';
		} elseif ( $request->get_header( 'content-encoding' ) && 'identity' !== strtolower( $request->get_header( 'content-encoding' ) ) ) {
			$reason = 'rest_body_encoding';
		} else {
			$parsed = json_decode( $body, true, 10 );
			if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $parsed ) ) {
				$reason = 'rest_body_format';
			}
		}
		if ( $reason ) {
			if ( 1 === GWQSH_Enterprise_Store::hit( 'waf-coverage', $ip . $reason, 60 ) ) {
				GWQSH_Activity_Logger::log( 'Firewall inspection incomplete', wp_json_encode( array( 'coverage' => $reason ) ), 'Security' );
			}
			if ( 'block' === $mode ) {
				return new WP_Error( 'gwqsh_firewall_incomplete', 'This request could not be inspected within the configured security limits.', array( 'status' => 413 ) );
			}
			return $result;
		}
		$evidence = self::editing_evidence( $parsed, $request->get_route() );
		if ( self::evidence( $evidence )['limits'] && 1 === GWQSH_Enterprise_Store::hit( 'waf-coverage', $ip . 'rest_value_bounds', 60 ) ) {
			GWQSH_Activity_Logger::log( 'Firewall inspection incomplete', wp_json_encode( array( 'coverage' => 'rest_value_bounds' ) ), 'Security' );
		}
		$rule = self::advanced( $evidence, array(), array(), $path, $settings );
		if ( ( ! $rule || 'GWQSH-1006' === $rule ) && self::match( $evidence, '', '', $legacy ) ) {
			$rule = 'GWQSH-1004';
		}
		if ( ! $rule ) {
			return $result;
		}
		$report = self::decision( '', $rule, '', $settings, $mode, false )['report'];
		if ( 1 === GWQSH_Enterprise_Store::hit( 'waf-rest-audit', $ip . $rule, 60 ) ) {
			GWQSH_Activity_Logger::log(
				$report ? 'Firewall request detected' : 'Firewall request blocked',
				wp_json_encode(
					array(
						'rule'          => $rule,
						'transport'     => 'rest_json',
						'authenticated' => is_user_logged_in(),
						'version'       => 1,
					)
				),
				'Security'
			);
		}
		return $report ? $result : new WP_Error( 'gwqsh_firewall', 'This request matched a security rule.', array( 'status' => 403 ) );
	}
	/**
	 * Collect request evidence with shared byte, node and nesting limits.
	 * Credential subtrees are excluded before traversal, including nested values.
	 *
	 * @param array $input Untrusted parsed request values.
	 * @return array Values and explicit coverage limitations; never persisted as content.
	 */
	public static function evidence( array $input ) {
		$result = array(
			'values' => array(),
			'limits' => array(),
		);
		$nodes  = 128;
		$bytes  = 16384;
		$until  = microtime( true ) + 0.01;
		self::collect( $input, 0, $nodes, $bytes, $until, $result );
		$result['limits'] = array_values( array_unique( $result['limits'] ) );
		return $result;
	}

	/** Bounded tree walk: count containers too, so empty arrays cannot evade budgets.
	 *
	 * @param array $input Parsed values.
	 * @param int   $depth Current depth.
	 * @param int   $nodes Remaining nodes.
	 * @param int   $bytes Remaining bytes.
	 * @param float $until Deadline.
	 * @param array $result Collected evidence.
	 */
	private static function collect( array $input, $depth, &$nodes, &$bytes, $until, &$result ) {
		foreach ( $input as $key => $value ) {
			if ( --$nodes < 0 || $bytes <= 0 || microtime( true ) > $until ) {
				$result['limits'][] = 'request_budget';
				return;
			}
			// Match credential components, not substrings such as postcode, passage or shortcode.
			if ( is_string( $key ) && preg_match( '/(?:^|[_-])(?:pass|password|passwd|pwd|token|nonce|wpnonce|secret|code|assert|assertion|cookie|session|credit|card|payment|authorization|log|user_login|user_email)(?:$|[_-])/i', substr( $key, 0, 256 ) ) ) {
				continue;
			}
			if ( is_array( $value ) ) {
				if ( $depth >= 8 ) {
					$result['limits'][] = 'request_depth';
					continue;
				}
				self::collect( $value, $depth + 1, $nodes, $bytes, $until, $result );
			} elseif ( is_scalar( $value ) ) {
				$value = (string) $value;
				$size  = min( 2048, $bytes );
				if ( strlen( $value ) > $size ) {
					$result['limits'][] = 'value_size';
				}
				$value              = substr( $value, 0, $size );
				$bytes             -= strlen( $value );
				$result['values'][] = rawurldecode( $value );
			}
		}
	}

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
		foreach ( self::evidence( $values )['values'] as $value ) {
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
		return require __DIR__ . '/waf/rules.php';
	}

	/** Additional SQL correlations remain report-only until enforce_new is approved.
	 * This is a lexical detector, not a SQL parser or proof of exploitation.
	 *
	 * @param string $value Already bounded request evidence.
	 * @return bool Whether a correlation matched.
	 */
	public static function extended_sql( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '~(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)(?:;\s*(?:drop\s+table|truncate\s+table|delete\s+from)\s+[a-z_][a-z0-9_]{0,63}|\bunion\s+(?:all\s+)?select\s+[^;\r\n]{1,100}\s+from\s+[a-z_]|\b(?:and|or)\s+(?:sleep\s*\(\s*[0-9]{1,3}\s*\)|benchmark\s*\(\s*[0-9]{1,8}\s*,))~i', $value );
	}

	/** Match additional report-first request rules.
	 *
	 * @param array  $query Query parameters.
	 * @param array  $post Parsed form fields.
	 * @param array  $files Uploaded file metadata.
	 * @param string $path Request path.
	 * @param array  $settings Validated additional rule settings.
	 */
	public static function advanced( array $query, array $post, array $files, $path, array $settings ) {
		$sql_enabled = self::settings()['sql'];
		$sql_match   = false;
		$values = array_merge( array( rawurldecode( substr( $path, 0, 2048 ) ) ), self::evidence( $query )['values'] );
		if ( $settings['post'] ) {
			$values = array_merge( $values, self::evidence( $post )['values'] );
		}
		foreach ( $values as $value ) {
			if ( $sql_enabled && self::extended_sql( $value ) ) {
				$sql_match = true;
			}
			if ( $settings['traversal'] && preg_match( '~(?:\.\.[/\\\\]){2}|(?:%2e){2}(?:%2f|%5c)~i', $value ) ) {
				return 'GWQSH-1001';
			}
			if ( $settings['inclusion'] && preg_match( '~(?:php|expect|phar|data)://|(?:^|[= /])(?:/etc/passwd|/proc/self/environ)~i', $value ) ) {
				return 'GWQSH-1002';
			}
		}
		if ( $settings['uploads'] ) {
			foreach ( array_slice( $files, 0, 10 ) as $file ) {
				if ( ! is_array( $file ) ) {
					continue;
				}
				$names = self::evidence( array( $file['name'] ?? '' ) );
				foreach ( $names['values'] as $name ) {
					if ( preg_match( '/\.(?:php[0-9]?|phtml|phar)(?:\.|$)/i', substr( $name, 0, 256 ) ) ) {
						return 'GWQSH-1003';
					}
				}
			}
		}
		if ( $settings['post'] ) {
			// Never inspect password, authentication, checkout or session material as raw request bodies.
			if ( self::match(
				$post,
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
		return $sql_match ? 'GWQSH-1006' : '';
	}
	/** Decide rollout policy without exempting all authenticated users.
	 *
	 * @param bool  $authenticated Whether this request has an authenticated user.
	 * @param array $advanced Validated rollout settings.
	 */
	public static function rollout( $authenticated, array $advanced ) {
		return $authenticated ? ( $advanced['authenticated'] ?? 'report' ) : $advanced['mode'];
	}

	/** Inspect permitted requests; authenticated inspection starts report-only. */
	public static function inspect() {
		$settings = self::settings();
		if ( ! $settings['enabled'] || ! GWQSH_Settings::is_active() || wp_doing_cron() || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return; }
		if ( GWQSH_Country_Access::emergency() ) {
			return; }
		$advanced = GWQSH_Enterprise_Config::get( 'waf' );
		if ( in_array( $advanced['mode'], array( 'disabled', 'recovery' ), true ) ) {
			return; }
		$authenticated = is_user_logged_in();
		$mode          = self::rollout( $authenticated, $advanced );
		if ( 'disabled' === $mode ) {
			return;
		}
		$ip = GWQSH_Settings::get_client_ip();
		if ( GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return; }
		$path = substr( (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/', PHP_URL_PATH ), 0, 200 );
		if ( in_array( $path, explode( "\n", $advanced['exclusions'] ), true ) ) {
			return; }
		$query_evidence = self::evidence( wp_unslash( $_GET ) );
		$post_evidence  = self::evidence( self::editing_evidence( wp_unslash( $_POST ) ) );
		$coverage_gap   = array_values( array_unique( array_merge( $query_evidence['limits'], $post_evidence['limits'] ) ) );
		if ( $coverage_gap && 'block' === $mode ) {
			$coverage_key = $ip . implode( ',', $coverage_gap );
			if ( 1 === GWQSH_Enterprise_Store::hit( 'waf-coverage-block', $coverage_key, 60 ) ) {
				GWQSH_Activity_Logger::log( 'Firewall inspection incomplete', wp_json_encode( array( 'coverage' => $coverage_gap ) ), 'Security', '—', $ip );
			}
			status_header( 413 );
			nocache_headers();
			GWQSH_UI::error( 413, 'Request not inspected', 'This request exceeded the configured security inspection limits.' );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Request evidence is inspected for denial, never accepted as a settings mutation.
		$rule = self::match( wp_unslash( $_GET ), isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', $path, $settings );
		// phpcs:ignore WordPress.Security.NonceVerification -- Inspect untrusted evidence for denial only; this hook never accepts a state mutation.
		$new_rule = self::advanced( wp_unslash( $_GET ), self::editing_evidence( wp_unslash( $_POST ) ), $_FILES, $path, $advanced );
		$patch    = '';
		if ( wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH ) === $path ) {
			// phpcs:ignore WordPress.Security.NonceVerification -- Data-only rejection predicates; no authorization or settings mutation.
			$patch = GWQSH_Vulnerabilities::match( '/wp-admin/admin-ajax.php', isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET', array_merge( wp_unslash( $_GET ), wp_unslash( $_POST ) ) );
		}
		if ( ( ! $new_rule || 'GWQSH-1006' === $new_rule ) && ! $authenticated && $advanced['rate'] ) {
			$count = GWQSH_Enterprise_Store::hit( 'waf-rate', $ip, 60 );
			if ( null !== $count && $count > $advanced['requests'] ) {
				$new_rule = 'GWQSH-1005'; }
		}
		if ( ! $rule && ! $new_rule && ! $patch ) {
			return; }
		$decision = self::decision( $rule, $new_rule, $patch, $advanced, $mode, GWQSH_Enterprise_Config::get( 'advisories' )['enforce'] );
		$detected = $decision['report'];
		$rule     = $decision['rule'];

		// Best-effort per-visitor/rule minute deduplication; existing log retention applies.
		$dedup = GWQSH_Enterprise_Store::hit( 'waf-audit', $ip . $rule, 60 );
		if ( 1 === $dedup ) {
			GWQSH_Activity_Logger::log(
				$detected ? 'Firewall request detected' : 'Firewall request blocked',
				wp_json_encode(
					array(
						'rule'          => $rule,
						'authenticated' => $authenticated,
						'path'          => $path,
						'rule_metadata' => self::rules()[ $rule ] ?? array(
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

	/** Resolve independent protections without allowing a report-only rule to shadow a block.
	 *
	 * @param string $legacy Reviewed baseline match.
	 * @param string $generic Additional heuristic match.
	 * @param string $patch Advisory-specific match.
	 * @param array  $policy WAF rollout policy.
	 * @param string $mode Effective authenticated/guest mode.
	 * @param bool   $enforce_patch Operator-approved patch enforcement.
	 * @return array Selected rule and report-only decision.
	 */
	public static function decision( $legacy, $generic, $patch, array $policy, $mode, $enforce_patch ) {
		$block = '';
		if ( $legacy ) {
			$block = $legacy;
		} elseif ( $patch && $enforce_patch ) {
			$block = $patch;
		} elseif ( $generic && $policy['enforce_new'] && ( 'GWQSH-1006' !== $generic || ! empty( $policy['enforce_sql_extended'] ) ) ) {
			$block = $generic;
		}
		return array(
			'rule'   => $block ? $block : ( $generic ? $generic : $patch ),
			'report' => 'report' === $policy['mode'] || 'report' === $mode || ! $block,
		);
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
