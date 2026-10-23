<?php
/** Bounded, opt-in public query protection and the Firewall screen adapter.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Opt-in query inspection and shared scanner statistics. */
final class GWQSH_Firewall {
	/** Bounded, request-local raw multipart parsing cache; never persisted. */
	private static $multipart_cache;
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

		// XML-RPC abuse protection.
		add_filter( 'xmlrpc_methods', array( __CLASS__, 'filter_xmlrpc_methods' ) );
		add_filter( 'xmlrpc_enabled', array( __CLASS__, 'maybe_disable_xmlrpc' ) );
		add_filter( 'wp_headers', array( __CLASS__, 'remove_xmlrpc_pingback_header' ) );

		// Wordfence-grade 404 scan rate limiting.
		add_action( 'template_redirect', array( __CLASS__, 'track_404_rate' ), 1 );
	}

	/**
	 * XML-RPC restrictions are actual blocking decisions, so respect report-only,
	 * disabled and emergency-recovery modes. Separately enabled hardening rules
	 * are intentionally not changed by this WAF policy decision.
	 *
	 * @return bool Whether WAF-owned XML-RPC restrictions may be enforced.
	 */
	public static function xmlrpc_enforcement_active() {
		if ( ! GWQSH_Settings::is_active() || empty( self::settings()['enabled'] ) || GWQSH_Country_Access::emergency() ) {
			return false;
		}
		$policy = GWQSH_Enterprise_Config::get( 'waf' );
		return 'block' === ( $policy['mode'] ?? 'disabled' );
	}

	/** Filter XML-RPC methods to block abuse vectors.
	 *
	 * @param array $methods Available XML-RPC methods.
	 * @return array Filtered methods.
	 */
	public static function filter_xmlrpc_methods( $methods ) {
		if ( ! self::xmlrpc_enforcement_active() ) {
			return $methods;
		}

		// Always remove system.multicall to prevent amplification attacks.
		// This method allows bundling hundreds of login attempts into a single request,
		// bypassing per-request rate limits.
		unset( $methods['system.multicall'] );

		// Remove pingback.ping to prevent DDoS amplification.
		unset( $methods['pingback.ping'] );
		unset( $methods['pingback.extensions.getPingbacks'] );

		return $methods;
	}

	/** Conditionally disable XML-RPC entirely based on enterprise config.
	 *
	 * @param bool $enabled Whether XML-RPC is enabled.
	 * @return bool Modified state.
	 */
	public static function maybe_disable_xmlrpc( $enabled ) {
		// Check if hardening rule disables XML-RPC.
		if ( GWQSH_Settings::is_active() && GWQSH_Hardening::is_enabled( 'xmlrpc' ) ) {
			return false;
		}
		return $enabled;
	}

	/** Remove the X-Pingback header to reduce attack surface.
	 *
	 * @param array $headers Response headers.
	 * @return array Filtered headers.
	 */
	public static function remove_xmlrpc_pingback_header( $headers ) {
		if ( ! self::xmlrpc_enforcement_active() ) {
			return $headers;
		}
		unset( $headers['X-Pingback'] );
		return $headers;
	}

	/** Track and throttle excessive 404 scans (e.g. automated directory or vulnerability scanners).
	 */
	public static function track_404_rate() {
		if ( ! is_404() || is_admin() || ( defined( 'DOING_AJAX' ) && DOING_AJAX ) || ( defined( 'WP_CLI' ) && WP_CLI ) ) {
			return;
		}
		$policy = GWQSH_Enterprise_Config::get( 'waf' );
		$mode   = self::rollout( is_user_logged_in(), $policy );
		if ( ! GWQSH_Settings::is_active() || ! self::settings()['enabled'] || GWQSH_Country_Access::emergency() || in_array( $policy['mode'], array( 'disabled', 'recovery' ), true ) || 'disabled' === $mode ) {
			return;
		}
		$path = substr( (string) wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '/', PHP_URL_PATH ), 0, 200 );
		if ( in_array( $path, explode( "\n", $policy['exclusions'] ), true ) ) {
			return;
		}
		$ip = GWQSH_Settings::get_client_ip();
		if ( GWQSH_Login_Protection::is_ip_allowlisted( $ip ) ) {
			return;
		}
		$count = GWQSH_Enterprise_Store::hit( 'waf-404-scan', $ip, 60 );
		$limit = max( 1, (int) apply_filters( 'gwqsh_404_rate_limit_per_minute', 30 ) );
		if ( null !== $count && $count > $limit ) {
			$report = 'report' === $policy['mode'] || 'report' === $mode;
			if ( 1 === GWQSH_Enterprise_Store::hit( 'waf-404-audit', $ip, 60 ) ) {
				GWQSH_Activity_Logger::log(
					$report ? 'Firewall request detected' : 'Firewall request blocked',
					wp_json_encode(
						array(
							'rule'     => 'GWQSH-1016',
							'path'     => $path,
							'requests' => $count,
							'limit'    => $limit,
						)
					),
					'Security',
					'—',
					$ip
				);
			}
			if ( $report ) {
				return;
			}
			status_header( 429 );
			nocache_headers();
			GWQSH_UI::error( 429, 'Rate limit exceeded', 'Too many non-existent page requests detected from your IP address. Access temporarily restricted to protect server resources.' );
			exit;
		}
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

	/** Endpoint-aware body size limits. WooCommerce/Gutenberg/media endpoints use higher thresholds.
	 *
	 * @param string $path Request path.
	 * @param bool   $authenticated Whether the request is authenticated.
	 * @return int Maximum inspection body size in bytes.
	 */
	public static function endpoint_body_limit( $path, $authenticated = false ) {
		// WooCommerce checkout and order endpoints can contain large product/shipping JSON.
		if ( preg_match( '~^/wp-json/wc/(?:v[1-3]/|store/)~', $path ) ) {
			return 524288; // 512 KiB.
		}
		// Gutenberg block editor sends full post content as JSON.
		if ( $authenticated && preg_match( '~^/wp-json/wp/v2/(?:posts|pages|blocks|widgets|templates|navigation)~', $path ) ) {
			return 1048576; // 1 MiB for authorized content editing.
		}
		// Media/upload REST endpoints.
		if ( preg_match( '~^/wp-json/wp/v2/media~', $path ) ) {
			return 262144; // 256 KiB.
		}
		// Contact forms, comments, and custom endpoints.
		if ( preg_match( '~^/wp-json/contact-form-7/|^/wp-json/wp/v2/comments~', $path ) ) {
			return 65536; // 64 KiB.
		}
		// Default generic REST endpoints.
		return $authenticated ? 65536 : 16384;
	}

	/** Inspect opt-in bounded REST JSON and form bodies after authentication.
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
		if ( null !== $result || ! $legacy['enabled'] || ! GWQSH_Settings::is_active() || in_array( $settings['mode'], array( 'disabled', 'recovery' ), true ) || GWQSH_Country_Access::emergency() ) {
			return $result;
		}
		$is_json = $request->is_json_content_type();
		$type = strtolower( trim( explode( ';', $request->get_header( 'content-type' ) )[0] ) );
		$is_xml = in_array( $type, array( 'application/xml', 'text/xml' ), true ) || str_ends_with( $type, '+xml' );
		$is_multipart = 'multipart/form-data' === $type;
		$inspect_body = $is_json ? ! empty( $settings['rest_json'] ) : ! empty( $settings['post'] );
		$files = $request->get_file_params();
		if ( ! $inspect_body && ( ! $settings['uploads'] || ( ! $files && ! $is_multipart ) ) ) {
			return $result;
		}
		$mode = self::rollout( is_user_logged_in(), $settings );
		$ip   = GWQSH_Settings::get_client_ip();
		$path = '/wp-json' . $request->get_route();
		if ( 'disabled' === $mode || GWQSH_Login_Protection::is_ip_allowlisted( $ip ) || in_array( $path, explode( "\n", $settings['exclusions'] ), true ) ) {
			return $result;
		}
		$body       = $request->get_body();
		$reason     = '';
		$body_state = 'fully_inspected';
		$parsed     = array();
		$body_limit = self::endpoint_body_limit( $path, is_user_logged_in() );
		if ( ! $inspect_body && ! $is_multipart ) {
			$body_state = 'partially_inspected';
		} elseif ( strlen( $body ) > $body_limit ) {
			$reason = 'rest_body_size';
		} elseif ( $request->get_header( 'content-encoding' ) && 'identity' !== strtolower( $request->get_header( 'content-encoding' ) ) ) {
			$reason = 'rest_body_encoding';
		} elseif ( $is_json ) {
			$parsed = json_decode( $body, true, 10 );
			if ( JSON_ERROR_NONE !== json_last_error() || ! is_array( $parsed ) ) {
				$reason = 'rest_body_format';
			}
		} elseif ( $is_xml ) {
			$xml = self::native_body( $body, $body_limit, $type );
			$parsed = $xml['data'];
			$body_state = $xml['state'];
			if ( ! in_array( $body_state, array( 'fully_inspected', 'partially_inspected' ), true ) ) {
				$reason = 'rest_body_xml';
			}
		} elseif ( $is_multipart ) {
			$multipart = self::multipart_request( $request );
			$parsed = $inspect_body ? $multipart['fields'] : array();
			$files = $multipart['files'];
			$body_state = $multipart['state'];
			if ( ! $inspect_body && $multipart['fields'] ) { $body_state = self::inspection_state( $body_state, 'partially_inspected' ); }
			if ( $multipart['error'] ) { $reason = 'rest_body_multipart'; }
		} else {
			if ( in_array( $type, array( '', 'application/x-www-form-urlencoded' ), true ) ) {
				// WordPress owns PHP-compatible parsing, including non-POST methods.
				// get_body_params alone does not trigger its lazy URL-encoded parser.
				$request->get_params();
				$parsed = $request->get_body_params();
			} else {
				$reason = 'rest_body_unsupported';
			}
		}
		if ( $reason ) {
			if ( 'rest_body_size' === $reason && $is_multipart && $settings['uploads'] ) {
				// Payload and framing/metadata have separate budgets. Do not let file
				// padding hide an inspectable filename, or deny ordinary files by size.
				$multipart = self::multipart_request( $request );
				if ( ! $multipart['error'] ) { $files = $multipart['files']; }
			}
			$body_state = in_array( $reason, array( 'rest_body_xml', 'rest_body_multipart' ), true ) ? $body_state : ( 'rest_body_size' === $reason ? 'inspection_budget_exceeded' : ( 'rest_body_format' === $reason ? 'parsing_error' : 'unsupported_request_format' ) );
			if ( 1 === GWQSH_Enterprise_Store::hit( 'waf-coverage', $ip . $reason, 60 ) ) {
				GWQSH_Activity_Logger::log(
					'Firewall inspection incomplete',
					wp_json_encode(
						array(
							'coverage' => $reason,
							'inspection_state' => $body_state,
							'status'   => $body_state,
							'policy'   => 'endpoint_aware',
							'limit'    => $body_limit,
						)
					),
					'Security'
				);
			}
			// Generic heuristics do not establish a malicious request from size alone.
			// Exact advisory-bound endpoints apply their own fail-closed policy.
			if ( ! $files || ! $settings['uploads'] ) { return $result; }
			$parsed = array(); // Body failure must not suppress independently available upload metadata.
		}
		if ( $settings['uploads'] ) { $body_state = self::inspection_state( $body_state, self::upload_evidence( $files )['state'] ); }
		$evidence = self::editing_evidence( $parsed, $request->get_route() );
		$value_limits = self::evidence( $evidence )['limits'];
		$coverage_reason = $value_limits ? 'rest_value_bounds' : 'rest_body_partial';
		if ( ! $reason && ( $value_limits || 'fully_inspected' !== $body_state ) && 1 === GWQSH_Enterprise_Store::hit( 'waf-coverage', $ip . $coverage_reason, 60 ) ) {
			GWQSH_Activity_Logger::log( 'Firewall inspection incomplete', wp_json_encode( array( 'coverage' => $coverage_reason, 'inspection_state' => self::inspection_state( $body_state, $value_limits ? 'inspection_budget_exceeded' : 'fully_inspected' ) ) ), 'Security' );
		}
		$rule = self::advanced( $evidence, array(), $files, $path, $settings );
		if ( ( ! $rule || 'GWQSH-1006' === $rule ) && self::match( $evidence, '', '', $legacy ) ) {
			$rule = 'GWQSH-1004';
		}
		$normalized = self::normalized_request( $evidence, array(), $path, $settings );
		$normalized['state'] = self::inspection_state( $body_state, $normalized['state'] );
		if ( ! $rule || 'GWQSH-1006' === $rule ) {
			$rule = $normalized['rule'] ?: $rule;
		}
		if ( ! $rule ) {
			return $result;
		}
		$report = self::decision( '', $rule, '', $settings, $mode, false )['report'];
		if ( 1 === self::audit_hit( $ip, $rule, $report ) ) {
			GWQSH_Activity_Logger::log(
				$report ? 'Firewall request detected' : 'Firewall request blocked',
				wp_json_encode(
					array(
						'rule'          => $rule,
						'transport'     => $is_json ? 'rest_json' : ( $is_xml ? 'rest_xml' : ( $is_multipart ? 'rest_multipart' : 'rest_form' ) ),
						'inspection_state' => $normalized['state'],
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
	 *
	 * Values whose parameter name identifies credential material (password, token,
	 * nonce, session, ...) are not treated as ordinary evidence, but they are no
	 * longer an inspection blind spot: they are collected separately as
	 * "credential values" and evaluated only against high-confidence detectors
	 * that do not depend on markup interpretation. A parameter named "password"
	 * must not be able to carry a SQL injection or traversal payload past the
	 * firewall, and no credential value is ever written to the audit log.
	 *
	 * @param array $input Untrusted parsed request values.
	 * @return array Values and explicit coverage limitations; never persisted as content.
	 */
	public static function evidence( array $input ) {
		$result = array(
			'values'             => array(),
			'credential_values'  => array(),
			'limits'             => array(),
			'excluded'           => 0,
			'status'             => 'fully_inspected',
		);
		$nodes  = 128;
		$bytes  = 16384;
		$until  = microtime( true ) + 0.01;
		self::collect( $input, 0, $nodes, $bytes, $until, $result, false );
		$result['limits'] = array_values( array_unique( $result['limits'] ) );
		// A credential-scope sample is intentionally evaluated by a narrower rule
		// set, so coverage is reported as partial for that scope only.
		$result['status'] = $result['limits'] ? 'budget_exceeded' : ( $result['excluded'] ? 'intentionally_partial' : 'fully_inspected' );
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
	 * @param bool  $credential_scope Whether this subtree is credential material.
	 */
	private static function collect( array $input, $depth, &$nodes, &$bytes, $until, &$result, $credential_scope = false ) {
		foreach ( $input as $key => $value ) {
			if ( --$nodes < 0 || $bytes <= 0 || microtime( true ) > $until ) {
				$result['limits'][] = 'request_budget';
				return;
			}
			// Match credential components, not substrings such as postcode, passage or shortcode.
			$credential_key = is_string( $key ) && preg_match( self::credential_key_pattern(), substr( $key, 0, 256 ) );
			if ( $credential_key ) {
				++$result['excluded'];
			}
			$scope = $credential_scope || $credential_key;
			if ( is_array( $value ) ) {
				if ( $depth >= 8 ) {
					$result['limits'][] = 'request_depth';
					continue;
				}
				self::collect( $value, $depth + 1, $nodes, $bytes, $until, $result, $scope );
			} elseif ( is_scalar( $value ) ) {
				$value = (string) $value;
				$size  = min( 2048, $bytes );
				if ( strlen( $value ) > $size ) {
					$result['limits'][] = 'value_size';
				}
				$value  = substr( $value, 0, $size );
				$bytes -= strlen( $value );
				if ( $scope ) {
					if ( count( $result['credential_values'] ) < 32 ) {
						$result['credential_values'][] = rawurldecode( $value );
					} else {
						$result['limits'][] = 'credential_value_count';
					}
				} else {
					$result['values'][] = rawurldecode( $value );
				}
			}
		}
	}

	/**
	 * Parameter-name grammar for credential material.
	 *
	 * @return string Regular expression.
	 */
	private static function credential_key_pattern() {
		return '/(?:^|[_-])(?:pass|password|passwd|pwd|token|nonce|wpnonce|secret|code|assert|assertion|cookie|session|credit|card|payment|authorization|log|user_login|user_email)(?:$|[_-])/i';
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
		$evidence = self::evidence( $values );
		foreach ( $evidence['values'] as $value ) {
			if ( $settings['sql'] && self::sql_high_confidence( $value ) ) {
				return 'SQL Injection';
			}
			if ( $settings['xss'] && self::xss_high_confidence( $value ) ) {
				return 'XSS Attempt';
			}
		}
		// Credential-named parameters are evaluated for injection only. Markup rules
		// are skipped here because a literal "<script>" inside a passphrase is not
		// evidence of an injection attempt, while "' OR 1=1" always is.
		if ( $settings['sql'] ) {
			foreach ( $evidence['credential_values'] as $value ) {
				if ( self::sql_high_confidence( $value ) ) {
					return 'SQL Injection';
				}
			}
		}
		// Correlate a scanner agent with an exploit-only path; agent alone never denies.
		if ( $settings['bots'] && preg_match( '/(?:sqlmap|nikto|nuclei|dirsearch|gobuster|wpscan|masscan|nmap|acunetix|acunetrix|burpsuite)/i', substr( (string) $agent, 0, 256 ) ) && preg_match( '~/(?:\.env(?:$|/)|\\.git/|vendor/phpunit/|wp-config\.php$|\.aws/|wp-config\.bak$|wp-config\.old$)~i', substr( (string) $path, 0, 512 ) ) ) {
			return 'Bad Bot';
		}
		return '';
	}

	/**
	 * High-confidence SQL injection shapes, safe to evaluate in every scope.
	 *
	 * These are lexical correlations, not a SQL parser and not proof of
	 * exploitation. Every pattern is bounded to the already-truncated value.
	 *
	 * @param string $value Bounded request evidence.
	 * @return bool Whether a blocking-family correlation matched.
	 */
	public static function sql_high_confidence( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '/\bunion\s+(?:all\s+)?select\s+(?:null|[0-9]+)\s*,/i', $value )
			|| preg_match( '/[\'"]\s*(?:or|and)\s+[0-9]{1,8}\s*=\s*[0-9]{1,8}\s*(?:--|#|\/\*)/i', $value )
			|| ( preg_match( '/(?:--|#|\/\*)\s*$/m', $value ) && preg_match( '/\bunion\b.*\bselect\b/is', $value ) )
			|| preg_match( '/\bselect\b[^;]{1,200}\bfrom\b[^;]{1,200}\binformation_schema\b/i', $value )
			|| preg_match( '/(?:0x[0-9a-f]{8,}|char\s*\(\s*[0-9]+(?:\s*,\s*[0-9]+){3,}\s*\))/i', $value )
			// Tautology families: ' OR 'x'='x, " OR ""=", 1' OR 1=1, 'or'1'='1, OR 1 LIKE 1.
			// Operands are restricted to quoted strings, integers or quoted/numeric
			// comparisons so ordinary prose and arithmetic text are not flagged.
			|| preg_match( '/(?<![\w.\/-])(?:or|and)\s+\'[^\']{0,32}\'\s*(?:=|like|is)\s*(?:\'[^\']{0,32}\'?|[0-9]{1,8}|")/i', $value )
			|| preg_match( '/(?<![\w.\/-])(?:or|and)\s+"[^"]{0,32}"\s*(?:=|like|is)\s*(?:"[^"]{0,32}"?|[0-9]{1,8}|\')/i', $value )
			|| preg_match( '/(?<![\w.\/-])(?:or|and)\s*\(?\s*[0-9]{1,8}\s*\)?\s*(?:=|like|is)\s*\(?\s*[0-9]{1,8}\s*\)?(?![\w.])/i', $value )
			// Quote-wrapped conjunction: 'or'1'='1 (the closing quote of the keyword
			// is reused as the opening quote of the operand).
			|| preg_match( '/(?<![\w.\/-])(?:or|and)[\x27"]?\s*[0-9]{1,8}[\x27"]?\s*(?:=|like|is)\s*[\x27"]?[0-9]{1,8}/i', $value )
			|| preg_match( '/(?<![\w.\/-])(?:or|and)\s+([\'"])[^\'"]{0,32}\1\s*(?:=|like)\s*[0-9]{1,8}(?![\w.])/i', $value )
			|| preg_match( '/(?<![\w.\/-])(?:or|and)\s+[0-9]{1,8}\s*(?:=|like)\s*([\'"])[^\'"]{0,32}\1/i', $value )
			// Comment-obfuscated keyword pairs: UNION/**/SELECT, /*!50000UNION*/ SELECT.
			|| preg_match( '/\bunion(?:\s|\/\*[^*]{0,64}\*\/)+(?:all(?:\s|\/\*[^*]{0,64}\*\/)+)?select\b/i', $value )
			|| preg_match( '/\/\*!\s*[0-9]{0,6}\s*(?:union|select|sleep|benchmark|updatexml|extractvalue|outfile)/i', $value )
			// Time-based, error-based and file-access functions in parameter context.
			|| preg_match( '/\b(?:sleep|pg_sleep|benchmark)\s*\(\s*[0-9]{1,8}\s*[,)]/i', $value )
			|| preg_match( '/\bwaitfor\s+delay\b/i', $value )
			|| preg_match( '/\b(?:extractvalue|updatexml)\s*\(/i', $value )
			|| preg_match( '/\binto\s+(?:out|dump)file\s/i', $value )
			|| preg_match( '/\bload_file\s*\(/i', $value )
			|| preg_match( '/;\s*(?:drop|truncate|alter)\s+table\b/i', $value );
	}

	/**
	 * High-confidence XSS shapes. Applied to ordinary request values only.
	 *
	 * @param string $value Bounded request evidence.
	 * @return bool Whether an XSS correlation matched.
	 */
	public static function xss_high_confidence( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '/<\s*(?:script\b[^>]{0,256}>|(?:img|svg|body|iframe|object|embed|details|math|video|audio|source|input|select|textarea|button|form)\b[^>]{0,256}\bon(?:error|load|click|mouse(?:over|enter|move)|focus|blur|change|submit|key(?:up|down|press)|input|animationend|toggle|pointerover)\s*=)/i', $value )
			|| preg_match( '/(?:javascript|vbscript|livescript)\s*:/i', $value )
			|| preg_match( '/<\s*(?:svg|math)\b[^>]{0,256}>.*<\s*(?:script|handler|set|animate)/is', $value )
			|| preg_match( '/data\s*:\s*(?:text\/html|application\/xhtml)[^,]{0,64};?base64\s*,/i', $value );
	}

	/** Rule metadata is fixed source data, never executable downloaded patterns. */
	public static function rules() {
		return require __DIR__ . '/waf/rules.php';
	}

	/** One visitor/rule/outcome audit across native and REST inspection phases. */
	private static function audit_hit( $ip, $rule, $report ) {
		return GWQSH_Enterprise_Store::hit( 'waf-audit', $ip . '|' . $rule . '|' . ( $report ? 'report' : 'block' ), 60 );
	}

	/** Inspect upload names independently of credential field names, with shared bounds. */
	public static function upload_evidence( array $files ) {
		$input = array();
		$limits = count( $files ) > 64 ? array( 'upload_groups' ) : array();
		foreach ( array_slice( $files, 0, 64 ) as $file ) {
			if ( ! is_array( $file ) || ! isset( $file['name'] ) || ( ! is_string( $file['name'] ) && ! is_array( $file['name'] ) ) ) {
				$limits[] = 'upload_metadata';
				continue;
			}
			$input[] = $file['name'];
		}
		$evidence = self::evidence( $input );
		$limits = array_values( array_unique( array_merge( $limits, $evidence['limits'] ) ) );
		return array( 'names' => $evidence['values'], 'limits' => $limits, 'state' => $limits ? 'inspection_budget_exceeded' : ( $files ? 'partially_inspected' : 'fully_inspected' ) );
	}

	/** Reuse one bounded raw parser result across native generic and scoped REST rules.
	 * PHP-parsed POST values and file metadata remain authoritative where raw input
	 * is unavailable. Cache invalidates on content/type mutation and holds at most
	 * four weak request objects, not raw bodies or persistent credentials.
	 */
	public static function multipart_request( $request ) {
		$body = (string) $request->get_body();
		$php_fields = $request->get_body_params();
		$php_files = $request->get_file_params();
		if ( '' === $body ) {
			$state = self::inspection_state( 'partially_inspected', self::php_post_state( $_SERVER ) );
			return array( 'fields' => $php_fields, 'input' => $php_fields, 'limited_parameters' => array(), 'files' => $php_files, 'error' => in_array( $state, array( 'inspection_budget_exceeded', 'unsupported_request_format' ), true ), 'state' => $state );
		}
		$type = (string) $request->get_header( 'content-type' );
		// Reject framing beyond the parser cap before hashing/copying a large body.
		if ( strlen( $body ) > 1048576 || strlen( $type ) > 1024 ) {
			return array( 'fields' => $php_fields, 'input' => $php_fields, 'limited_parameters' => array(), 'files' => $php_files, 'error' => true, 'state' => 'inspection_budget_exceeded' );
		}
		$fingerprint = hash( 'sha256', strlen( $type ) . ':' . $type . $body );
		if ( null === self::$multipart_cache ) { self::$multipart_cache = new WeakMap(); }
		$cached = self::$multipart_cache[ $request ] ?? null;
		if ( ! $cached || ! hash_equals( $cached['fingerprint'], $fingerprint ) ) {
			if ( count( self::$multipart_cache ) >= 4 ) { self::$multipart_cache = new WeakMap(); }
			$parsed = ( new \Gracewell\SecurityPro\WAF\Gracewell_WAF_Inspector() )->parse_multipart( $body, $type, 1048576 );
			self::$multipart_cache[ $request ] = array( 'fingerprint' => $fingerprint, 'parsed' => $parsed );
		} else {
			$parsed = $cached['parsed'];
		}
		$input = $php_fields;
		foreach ( self::multipart_input( $parsed['fields'] ) as $key => $value ) {
			$input[ $key ] = array_key_exists( $key, $input ) && $input[ $key ] !== $value ? array( $input[ $key ], $value ) : $value;
		}
		$limited_parameters = array();
		foreach ( $parsed['incomplete_fields'] as $name ) {
			foreach ( array_keys( self::multipart_input( array( $name => array( '' ) ) ) ) as $key ) { $limited_parameters[ $key ] = 'budget_exceeded'; }
		}
		return array( 'fields' => $input, 'input' => $input, 'limited_parameters' => $limited_parameters, 'files' => array_merge( $php_files, $parsed['files'] ), 'error' => $parsed['error'], 'state' => $parsed['state'] );
	}

	/** A PHP-discarded POST is an inspection gap, never an empty safe form. */
	public static function php_post_state( array $server ) {
		if ( 'POST' !== ( $server['REQUEST_METHOD'] ?? '' ) ) { return 'fully_inspected'; }
		$length = $server['CONTENT_LENGTH'] ?? '';
		if ( '' !== $length && ( ! is_scalar( $length ) || ! ctype_digit( (string) $length ) ) ) { return 'unsupported_request_format'; }
		if ( ! empty( $server['HTTP_TRANSFER_ENCODING'] ) ) { return '' === $length ? 'partially_inspected' : 'unsupported_request_format'; }
		$limit = wp_convert_hr_to_bytes( (string) ini_get( 'post_max_size' ) );
		return $limit > 0 && '' !== $length && (float) $length > $limit ? 'inspection_budget_exceeded' : 'fully_inspected';
	}

	/** Preserve duplicates, bracket arrays and PHP name aliases for scalar patch predicates. */
	public static function multipart_input( array $fields ) {
		$input = array();
		foreach ( $fields as $name => $values ) {
			// Probe only the name, never interpret values or create global variables.
			$probe_name = substr_count( (string) $name, '[' ) > 8 ? explode( '[', (string) $name, 2 )[0] . '[]' : (string) $name;
			parse_str( rawurlencode( $probe_name ) . '=field', $probe );
			if ( 1 !== count( $probe ) ) { continue; }
			$key = array_key_first( $probe );
			$value = self::multipart_value( $probe[ $key ], 1 === count( $values ) ? $values[0] : $values );
			$input[ $key ] = array_key_exists( $key, $input ) ? array( $input[ $key ], $value ) : $value;
		}
		return $input;
	}

	/** Keep semantic bracket keys so credential and authored-field scope survives parsing. */
	private static function multipart_value( $shape, $value ) {
		if ( ! is_array( $shape ) ) { return $value; }
		foreach ( $shape as $key => $child ) { $shape[ $key ] = self::multipart_value( $child, $value ); }
		return $shape;
	}

	/** Use the bounded inspector as a parser adapter; native policy owns enforcement.
	 * New normalization matches inherit enforce_new and authenticated report mode.
	 * No downloaded patterns, process-local counters or second hooks are involved.
	 *
	 * @param array $query Query evidence without raw credentials.
	 * @param array $post Non-authored form or REST evidence.
	 * @param string $path Path only, never the raw credential-bearing query string.
	 * @param array $policy Existing validated WAF policy.
	 * @return array Rule and coverage state; no input values leave this adapter.
	 */
	public static function normalized_request( array $query, array $post, $path, array $policy ) {
		$inspector = new \Gracewell\SecurityPro\WAF\Gracewell_WAF_Inspector();
		$inspection = $inspector->inspect_request(
			array( 'REQUEST_URI' => $path ), $query, $policy['post'] ? $post : array(), '', array(), array(), true
		);
		$inputs = $inspection['inputs'];
		$rule = self::advanced( $inputs, array(), array(), '', $policy );
		if ( ( ! $rule || 'GWQSH-1006' === $rule ) && self::match( $inputs, '', '', self::settings() ) ) {
			$rule = 'GWQSH-1004';
		}
		// The downstream native matcher has tighter bounds than the parser.
		$state = self::evidence( $inputs )['limits'] ? 'inspection_budget_exceeded' : $inspection['state'];
		return array( 'rule' => $rule, 'state' => $state );
	}

	/** Additional SQL correlations remain report-only until enforce_new is approved.
	 * This is a lexical detector, not a SQL parser or proof of exploitation.
	 *
	 * @param string $value Already bounded request evidence.
	 * @return bool Whether a correlation matched.
	 */
	public static function extended_sql( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '~(*LIMIT_MATCH=10000)(*LIMIT_DEPTH=100)(?:;\s*(?:drop\s+table|truncate\s+table|delete\s+from|alter\s+table|create\s+(?:table|function|procedure))\s+[a-z_][a-z0-9_]{0,63}|\bunion\s+(?:all\s+)?select\s+[^;\r\n]{1,100}\s+from\s+[a-z_]|\b(?:and|or)\s+(?:sleep\s*\(\s*[0-9]{1,3}\s*\)|benchmark\s*\(\s*[0-9]{1,8}\s*,|waitfor\s+delay\s|pg_sleep\s*\()|\binto\s+(?:out|dump)file\s|\bload_file\s*\(|\b(?:extractvalue|updatexml)\s*\()~i', $value );
	}

	/**
	 * Detect a path-traversal sequence, including a single "../" segment.
	 *
	 * The previous expression required two segments, so a lone "../wp-config.php"
	 * was never correlated. A parent-directory segment inside request data is not
	 * required by WordPress core, REST, WooCommerce or the block editor.
	 *
	 * @param string $value Bounded request evidence (URL-decoded once already).
	 * @return bool Whether a traversal shape matched.
	 */
	public static function traversal( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '~(?:^|[\s=;&|(,\x27"])[.][.](?:\x2f|\x5c)|(?:\x2f|\x5c)[.][.](?:\x2f|\x5c)~', $value )
			|| preg_match( '~(?:%2e){2}(?:%2f|%5c)|%252e%252e~i', $value );
	}

	/**
	 * Detect a serialized PHP object in any value position.
	 *
	 * Objects can start a value or be nested inside arrays, for example
	 * a:1:{i:0;O:7:"WP_User":1:{...}}. Only the object shape is correlated; the
	 * payload is never unserialized.
	 *
	 * @param string $value Bounded request evidence.
	 * @return bool Whether an object-injection shape matched.
	 */
	public static function serialized_object( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '/(?:^|[=&{;|,(])\s*(?:O|C):[0-9]{1,6}:"[A-Za-z_\x5c][A-Za-z0-9_\x5c]{0,100}":[0-9]{1,6}:\{/', $value );
	}

	/**
	 * Detect executable PHP source in a request value.
	 *
	 * Report-first rule (GWQSH-1017): sites that accept code snippets in forms
	 * exist, so enforcement requires explicit operator approval via enforce_new.
	 *
	 * @param string $value Bounded request evidence.
	 * @return bool Whether a PHP code shape matched.
	 */
	public static function php_code_in_request( $value ) {
		$value = substr( (string) $value, 0, 2048 );
		return (bool) preg_match( '/<\?(?:php\b|=)/i', $value )
			|| preg_match( '/\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|gzinflate|\$_)/i', $value )
			|| preg_match( '/\b(?:shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\(/i', $value );
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
		// One bounded evidence walk per collection; credential-scoped values are
		// included here because traversal, inclusion, command, SSRF and
		// deserialization shapes stay unambiguous inside credential material.
		$query_evidence = self::evidence( $query );
		$values         = array_merge( array( rawurldecode( substr( (string) $path, 0, 2048 ) ) ), $query_evidence['values'], $query_evidence['credential_values'] );
		if ( $settings['post'] ) {
			$post_evidence = self::evidence( $post );
			$values        = array_merge( $values, $post_evidence['values'], $post_evidence['credential_values'] );
		}
		foreach ( $values as $value ) {
			if ( $sql_enabled && self::extended_sql( $value ) ) {
				$sql_match = true;
			}
			if ( $settings['traversal'] && self::traversal( $value ) ) {
				return 'GWQSH-1001';
			}
			if ( $settings['inclusion'] && preg_match( '~(?:php|expect|phar|data|zip|glob|rar|compress\.zlib|ogg)://|(?:^|[= /])(?:/etc/passwd|/proc/self/environ|/etc/shadow|/var/log)~i', $value ) ) {
				return 'GWQSH-1002';
			}
			// Command injection: shell metacharacters in parameter values.
			if ( preg_match( '~(?:;|\||`|\$\(|\${)\s*(?:cat|ls|id|whoami|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php|powershell)\b~i', $value ) ) {
				return 'GWQSH-1007';
			}
			// SSRF: internal network/cloud metadata targets in parameter values.
			if ( preg_match( '~(?:https?://(?:127\.0\.0\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|169\.254\.169\.254|0\.0\.0\.0|localhost|metadata\.google\.internal|\[::1?\]|0x[0-9a-f]{8}))|(?:gopher|dict|file|ldap)://~i', $value ) ) {
				return 'GWQSH-1008';
			}
			// Executable PHP code in request data (webshell/dropper attempt).
			// Report-first: new rule, requires enforce_new approval to block.
			if ( self::php_code_in_request( $value ) ) {
				return 'GWQSH-1017';
			}
			// PHP object deserialization: serialized object anywhere in a value,
			// including nested array/object payloads (a:1:{i:0;O:7:"WP_User"...}).
			if ( self::serialized_object( $value ) ) {
				return 'GWQSH-1009';
			}
		}
		if ( $settings['uploads'] ) {
			foreach ( self::upload_evidence( $files )['names'] as $name ) {
				if ( preg_match( '/\.(?:php[0-9]?|phtml|phar)(?:\.|$)/i', $name ) ) {
					return 'GWQSH-1003';
				}
				// Double extension uploads (e.g., shell.php.jpg).
				if ( preg_match( '/\.(?:php[0-9]?|phtml|phar|asp|aspx|jsp|cgi|pl)\.[a-z]{2,4}$/i', $name ) ) {
					return 'GWQSH-1013';
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
					'sql'  => self::settings()['sql'],
					'xss'  => self::settings()['xss'],
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

	/** Defer only verified front-controller REST traffic, never direct PHP endpoints. */
	public static function rest_transport( $path ) {
		$script = isset( $_SERVER['SCRIPT_FILENAME'] ) && is_string( $_SERVER['SCRIPT_FILENAME'] ) ? realpath( $_SERVER['SCRIPT_FILENAME'] ) : false;
		$front = realpath( ABSPATH . 'index.php' );
		if ( ! $script || ! $front || ( 'Windows' === PHP_OS_FAMILY ? 0 !== strcasecmp( $script, $front ) : $script !== $front ) || wp_doing_ajax() || is_admin() ) {
			return false;
		}
		// rest_route is request evidence, not proof that a direct entrypoint dispatches REST.
		if ( isset( $_GET['rest_route'] ) && is_string( $_GET['rest_route'] ) && str_starts_with( $_GET['rest_route'], '/' ) ) {
			return true;
		}
		$url = rest_url();
		// With plain permalinks, the base path is the site root, not a REST-only path.
		if ( wp_parse_url( $url, PHP_URL_QUERY ) ) {
			return false;
		}
		$base = rtrim( (string) wp_parse_url( $url, PHP_URL_PATH ), '/' );
		return '' !== $base && ( $path === $base || str_starts_with( $path, $base . '/' ) );
	}

	/** Decode bounded native JSON; incomplete parsing never creates an attack verdict.
	 *
	 * @param string $body Bounded bytes, at most endpoint limit plus one sentinel.
	 * @param int $limit Endpoint-aware byte limit.
	 * @return array Parsed data and separate inspection state.
	 */
	public static function native_json( $body, $limit ) {
		$data = array();
		$state = 'fully_inspected';
		if ( false === $body ) {
			$state = 'parsing_error';
		} elseif ( strlen( $body ) > $limit ) {
			$state = 'inspection_budget_exceeded';
		} elseif ( '' !== $body ) {
			$parsed = json_decode( $body, true, 10 );
			if ( JSON_ERROR_NONE !== json_last_error() ) {
				$state = 'parsing_error';
			} elseif ( ! is_array( $parsed ) ) {
				$state = 'unsupported_request_format';
			} else {
				$data = $parsed;
			}
		}
		return array( 'data' => $data, 'state' => $state );
	}

	/** Reuse the existing inspector for XML while preserving native JSON compatibility. */
	public static function native_body( $body, $limit, $type, $xmlrpc_credentials = false ) {
		if ( false === $body || strlen( $body ) > $limit ) {
			return array( 'data' => array(), 'state' => false === $body ? 'parsing_error' : 'inspection_budget_exceeded' );
		}
		if ( in_array( $type, array( 'application/xml', 'text/xml' ), true ) || str_ends_with( $type, '+xml' ) ) {
			return ( new \Gracewell\SecurityPro\WAF\Gracewell_WAF_Inspector() )->parse_xml( $body, $xmlrpc_credentials );
		}
		return self::native_json( $body, $limit );
	}

	/** Preserve the strongest limitation when parser and native matcher bounds differ. */
	public static function inspection_state( ...$states ) {
		foreach ( array( 'inspection_budget_exceeded', 'parsing_error', 'unsupported_request_format', 'partially_inspected' ) as $state ) {
			if ( in_array( $state, $states, true ) ) { return $state; }
		}
		return 'fully_inspected';
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
		// REST body inspection belongs to rest_pre_dispatch after authentication.
		$is_rest = self::rest_transport( $path );
		$post = $is_rest ? array() : self::editing_evidence( wp_unslash( $_POST ) );
		$body_state = 'fully_inspected';
		$type = strtolower( trim( explode( ';', substr( (string) ( $_SERVER['CONTENT_TYPE'] ?? '' ), 0, 256 ) )[0] ) );
		$is_structured = in_array( $type, array( 'application/json', 'application/xml', 'text/xml' ), true ) || str_ends_with( $type, '+json' ) || str_ends_with( $type, '+xml' );
		if ( ! $is_rest && $advanced['post'] && $is_structured ) {
			$limit = self::endpoint_body_limit( $path, $authenticated );
			if ( ! empty( $_SERVER['HTTP_CONTENT_ENCODING'] ) && 'identity' !== strtolower( (string) $_SERVER['HTTP_CONTENT_ENCODING'] ) ) {
				$body_state = 'unsupported_request_format';
			} else {
				// Bounded read; php://input remains available to the endpoint controller.
				$xmlrpc_credentials = false;
				if ( in_array( $type, array( 'application/xml', 'text/xml' ), true ) || str_ends_with( $type, '+xml' ) ) {
					$script = isset( $_SERVER['SCRIPT_FILENAME'] ) && is_string( $_SERVER['SCRIPT_FILENAME'] ) ? realpath( $_SERVER['SCRIPT_FILENAME'] ) : false;
					$xmlrpc_script = realpath( ABSPATH . 'xmlrpc.php' );
					$xmlrpc_credentials = $script && $xmlrpc_script && ( 'Windows' === PHP_OS_FAMILY ? 0 === strcasecmp( $script, $xmlrpc_script ) : $script === $xmlrpc_script );
				}
				$body = self::native_body( file_get_contents( 'php://input', false, null, 0, $limit + 1 ), $limit, $type, $xmlrpc_credentials );
				$post = self::editing_evidence( $body['data'] );
				$body_state = $body['state'];
			}
		} elseif ( ! $is_rest && $advanced['post'] && ! in_array( $type, array( '', 'application/x-www-form-urlencoded', 'multipart/form-data' ), true ) ) {
			$body_state = 'unsupported_request_format';
		}
		// PHP upload metadata stays covered even when REST body inspection is disabled.
		$files = $_FILES;
		if ( ! $is_rest && in_array( $type, array( 'application/x-www-form-urlencoded', 'multipart/form-data' ), true ) ) { $body_state = self::inspection_state( $body_state, self::php_post_state( $_SERVER ) ); }
		if ( $advanced['uploads'] ) { $body_state = self::inspection_state( $body_state, self::upload_evidence( $files )['state'] ); }
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Read-only WAF inspection precedes controller CSRF checks; no privileged mutation is authorized.
		$post_evidence  = self::evidence( $post );
		$coverage_gap   = array_values( array_unique( array_merge( $query_evidence['limits'], $post_evidence['limits'] ) ) );
		if ( 'fully_inspected' !== $body_state ) {
			$coverage_gap[] = 'native_body:' . $body_state;
		}
		if ( $coverage_gap ) {
			$coverage_key = $ip . implode( ',', $coverage_gap );
			if ( 1 === GWQSH_Enterprise_Store::hit( 'waf-coverage-block', $coverage_key, 60 ) ) {
				GWQSH_Activity_Logger::log( 'Firewall inspection incomplete', wp_json_encode( array( 'coverage' => $coverage_gap ) ), 'Security', '—', $ip );
			}
			// A generic inspection budget is coverage evidence, not an attack verdict.
		}
		// Evaluate the raw URL path: WordPress sanitizers can strip encoded octets.
		// Keep this scoped to anonymous requests and existing WAF allowlists/exclusions.
		$raw_uri = isset( $_SERVER['REQUEST_URI'] ) && is_string( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';
		$raw_bot_path = wp_parse_url( substr( $raw_uri, 0, 4096 ), PHP_URL_PATH );
		$bot_probe = ! $authenticated && ! empty( $settings['bots'] ) && ! empty( $advanced['bot_probe'] )
			? GWQSH_Bot_Shield::path_rule( $raw_bot_path ) : '';
		$bot_enforce = GWQSH_Bot_Shield::can_enforce( ! $authenticated, $settings, $advanced, $mode );
		$bot_hold = $bot_enforce && ! empty( $advanced['bot_auto_hold'] ) ? GWQSH_Bot_Shield::held_rule( $ip ) : '';
		if ( $bot_probe && $bot_enforce && ! empty( $advanced['bot_auto_hold'] ) ) {
			GWQSH_Bot_Shield::record_probe( $ip, $advanced );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Request evidence is inspected for denial, never accepted as a settings mutation.
		$rule = self::match( wp_unslash( $_GET ), isset( $_SERVER['HTTP_USER_AGENT'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ) ) : '', $path, $settings );
		// phpcs:ignore WordPress.Security.NonceVerification -- Inspect untrusted evidence for denial only; this hook never accepts a state mutation.
		$new_rule = self::advanced( wp_unslash( $_GET ), $post, $files, $path, $advanced );
		$normalized = self::normalized_request( wp_unslash( $_GET ), $post, $path, $advanced );
		$normalized['state'] = self::inspection_state( $body_state, $normalized['state'] );
		if ( ! $new_rule || 'GWQSH-1006' === $new_rule ) {
			$new_rule = $normalized['rule'] ?: $new_rule;
		}
		$patch    = '';
		if ( wp_parse_url( admin_url( 'admin-ajax.php' ), PHP_URL_PATH ) === $path ) {
			// phpcs:ignore WordPress.Security.NonceVerification -- Data-only rejection predicates; no authorization or settings mutation.
			$patch = GWQSH_Vulnerabilities::match( '/wp-admin/admin-ajax.php', isset( $_SERVER['REQUEST_METHOD'] ) ? sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) : 'GET', GWQSH_Vulnerabilities::merge_input( wp_unslash( $_GET ), wp_unslash( $_POST ) ) );
		}
		if ( ( ! $new_rule || 'GWQSH-1006' === $new_rule ) && ! $authenticated && $advanced['rate'] ) {
			$count = GWQSH_Enterprise_Store::hit( 'waf-rate', $ip, 60 );
			if ( null !== $count && $count > $advanced['requests'] ) {
				$new_rule = 'GWQSH-1005'; }
		}
		if ( ! $rule && ! $new_rule && ! $patch && ! $bot_probe && ! $bot_hold ) {
			return; }
		$decision = self::decision( $rule, $new_rule, $patch, $advanced, $mode, GWQSH_Enterprise_Config::get( 'advisories' )['enforce'] );
		$detected = $decision['report'];
		$rule     = $decision['rule'];
		if ( $bot_hold || $bot_probe ) {
			// A confirmed bot match enforces independently of optional heuristic rules.
			$rule = $bot_hold ? $bot_hold : $bot_probe;
			$detected = ! $bot_enforce;
		}

		// Best-effort per-visitor/rule minute deduplication; existing log retention applies.
		$dedup = self::audit_hit( $ip, $rule, $detected );
		if ( 1 === $dedup ) {
			GWQSH_Activity_Logger::log(
				$detected ? 'Firewall request detected' : 'Firewall request blocked',
				wp_json_encode(
					array(
						'rule'          => $rule,
						'authenticated' => $authenticated,
						'path'          => $path,
						'inspection_state' => $normalized['state'],
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
		$throttled = in_array( $rule, array( 'GWQSH-1005', 'GWQSH-1021' ), true );
		status_header( $throttled ? 429 : 403 );
		if ( 'GWQSH-1021' === $rule ) {
			header( 'Retry-After: ' . max( 60, min( 3600, (int) ( $advanced['bot_hold_seconds'] ?? 600 ) ) ) );
		}
		nocache_headers();
		GWQSH_UI::error( $throttled ? 429 : 403, 'Request blocked', 'This request matched a security rule. Contact the site administrator if you believe this is an error.' );
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
