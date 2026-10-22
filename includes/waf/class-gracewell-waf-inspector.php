<?php
declare(strict_types=1);

namespace Gracewell\SecurityPro\WAF;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Enterprise WAF Inspector with explicit coverage states across GET, POST, JSON,
 * multipart/form-data, REST, AJAX, nested arrays, encoded, and Unicode inputs.
 */
final class Gracewell_WAF_Inspector {
	public const STATE_FULLY_INSPECTED     = 'fully_inspected';
	public const STATE_PARTIALLY_INSPECTED = 'partially_inspected';
	public const STATE_BUDGET_EXCEEDED     = 'inspection_budget_exceeded';
	public const STATE_UNSUPPORTED_FORMAT  = 'unsupported_request_format';
	public const STATE_PARSE_ERROR         = 'parsing_error';
	public const STATE_MALICIOUS           = 'malicious';
	public const STATE_ALLOWED             = 'allowed';

	private int $max_body_bytes = 262144; // 256 KB bounded inspection budget
	private int $max_depth      = 8;
	private int $max_nodes      = 256;
	private int $remaining_bytes = 262144;
	private bool $truncated = false;
	private bool $excluded = false;

	/** @var array<string, list<int>> In-memory rate limiting tracking */
	private static array $rate_limit_store = [];

	/** @var array<string, list<array{user: string, time: int}>> In-memory credential stuffing tracking */
	private static array $login_attempts_store = [];

	/**
	 * Inspect incoming HTTP request with explicit budget and coverage tracking.
	 *
	 * @param array  $server            $_SERVER superglobal array.
	 * @param array  $get               $_GET query parameters.
	 * @param array  $post              $_POST form parameters.
	 * @param string $raw_body          Raw request body.
	 * @param array  $rules             Array of WAF rule definitions.
	 * @param array  $active_components Active component versions for virtual patch matching.
	 * @return array Inspection verdict and explicit state metadata.
	 */
	public function inspect_request(
		array $server,
		array $get,
		array $post,
		string $raw_body,
		array $rules,
		array $active_components = [],
		bool $include_inputs = false
	): array {
		$inspection_state = self::STATE_FULLY_INSPECTED;
		$uri              = (string) ( $server['REQUEST_URI'] ?? '/' );
		$content_type_raw = (string) ( $server['CONTENT_TYPE'] ?? '' );
		$content_type = strtolower( trim( explode( ';', $content_type_raw, 2 )[0] ) );
		$this->remaining_bytes = $this->max_body_bytes;
		$this->truncated = false;
		$this->excluded = false;
		$parsed_body      = [];
		$upload_metadata  = [];

		// 1. Enforce body inspection budget
		if ( strlen( $raw_body ) > $this->max_body_bytes ) {
			$inspection_state = self::STATE_BUDGET_EXCEEDED;
			$raw_body         = substr( $raw_body, 0, $this->max_body_bytes );

		}

		// 2. Parse body according to Content-Type
		if ( '' !== $raw_body && self::STATE_BUDGET_EXCEEDED !== $inspection_state ) {
			if ( ( 'application/json' === $content_type || str_ends_with( $content_type, '+json' ) ) ) {
				$decoded = json_decode( $raw_body, true, $this->max_depth );
				if ( JSON_ERROR_NONE !== json_last_error() ) {
					$inspection_state = self::STATE_PARSE_ERROR;
				} elseif ( is_array( $decoded ) ) {
					$parsed_body = $decoded;
				} else {
					$inspection_state = self::STATE_UNSUPPORTED_FORMAT;
				}
			} elseif ( in_array( $content_type, [ 'application/xml', 'text/xml' ], true ) || str_ends_with( $content_type, '+xml' ) ) {
				$xml = $this->parse_xml( $raw_body, 'xmlrpc.php' === basename( (string) parse_url( $uri, PHP_URL_PATH ) ) );
				$parsed_body = $xml['data'];
				$inspection_state = $xml['state'];
			} elseif ( 'multipart/form-data' === $content_type ) {
				$mp_result = $this->parse_multipart( $raw_body, $content_type_raw );
				$inspection_state = $mp_result['state'];
				if ( ! $mp_result['error'] ) {
					$parsed_body = $mp_result['fields'];
					$upload_metadata = $mp_result['files'];
				}
			} elseif ( str_contains( $content_type, 'application/x-www-form-urlencoded' ) || '' === $content_type ) {
				// Standard POST already parsed by PHP in $post; also parse raw body if $post is empty
				if ( empty( $post ) && str_contains( $raw_body, '=' ) ) {
					parse_str( $raw_body, $parsed_body );
				}
			} else {
				// Non-standard binary or unsupported format
				$inspection_state = self::STATE_UNSUPPORTED_FORMAT;
			}
		}

		// 3. Normalize and flatten inputs with node and depth bounding
		$node_count = 0;
		$normalized_inputs = $this->flatten_and_normalize(
			[
				'uri'       => $uri,
				'get'       => $get,
				'post'      => $post,
				'body_data' => $parsed_body,
				'files'     => $upload_metadata,
			],
			'',
			0,
			$node_count
		);

		if ( $this->truncated ) {
			$inspection_state = self::STATE_BUDGET_EXCEEDED;
		}

		if ( $this->excluded && self::STATE_FULLY_INSPECTED === $inspection_state ) {
			$inspection_state = self::STATE_PARTIALLY_INSPECTED;
		}
		$detected = null;

		// 4. Evaluate scoped rules against normalized inputs
		foreach ( array_slice( $rules, 0, 256 ) as $rule ) {
			if ( ! is_array( $rule ) || ! is_string( $rule['pattern'] ?? null ) || strlen( $rule['pattern'] ) > 4096 || empty( $rule['id'] ) ) {
				continue;
			}
			if ( ! $this->is_rule_applicable( $rule, $uri, $active_components ) ) {
				continue;
			}

			foreach ( $normalized_inputs as $key => $val ) {
				if ( $this->is_excluded_field( $rule, $key ) ) {
					continue;
				}

				if ( @preg_match( $rule['pattern'], $val ) === 1 ) {
					$mode = $rule['mode'] ?? 'report';
					$match = [
						'verdict'    => ( 'block' === $mode ) ? self::STATE_MALICIOUS : self::STATE_ALLOWED,
						'state'      => $inspection_state,
						'rule_id'    => $rule['id'],
						'mode'       => $mode,
						'category'   => $rule['category'] ?? 'generic',
						'severity'   => $rule['severity'] ?? 'high',
						'confidence' => $rule['confidence'] ?? 90,
						'matched'    => $key,
					];
					if ( 'block' === $mode ) { return $match; }
					$detected = $detected ?? $match;
					break;
				}
			}
		}

		if ( null !== $detected ) { return $detected; }
		return ( $include_inputs ? [ 'inputs' => $normalized_inputs ] : [] ) + [
			'verdict' => self::STATE_ALLOWED,
			'state'   => $inspection_state,
			'rule_id' => null,
		];
	}

	/**
	 * Rate limiting sliding-window check.
	 *
	 * @param string $ip               Client IP.
	 * @param string $action           Action key.
	 * @param int    $limit_per_minute Request limit within window.
	 * @param int    $window_seconds   Time window in seconds.
	 * @return array Rate limit status and current count.
	 */
	public function check_rate_limit( string $ip, string $action, int $limit_per_minute, int $window_seconds = 60 ): array {
		$now = time();
		$key = $ip . ':' . $action;
		if ( ! isset( self::$rate_limit_store[ $key ] ) ) {
			self::$rate_limit_store[ $key ] = [];
		}

		self::$rate_limit_store[ $key ] = array_values(
			array_filter(
				self::$rate_limit_store[ $key ],
				static fn( $ts ) => ( $now - $ts ) < $window_seconds
			)
		);
		self::$rate_limit_store[ $key ][] = $now;
		$count = count( self::$rate_limit_store[ $key ] );

		return [
			'limited'       => $count > $limit_per_minute,
			'current_count' => $count,
			'limit'         => $limit_per_minute,
			'window'        => $window_seconds,
		];
	}

	/**
	 * Credential stuffing detection: tracks distinct usernames targeted by a single IP.
	 *
	 * @param string $ip             Client IP.
	 * @param string $username       Targeted username.
	 * @param int    $max_usernames  Maximum distinct usernames before flagging.
	 * @param int    $window_seconds Time window in seconds.
	 * @return array Credential stuffing check result.
	 */
	public function check_credential_stuffing( string $ip, string $username, int $max_usernames = 5, int $window_seconds = 300 ): array {
		$now = time();
		if ( ! isset( self::$login_attempts_store[ $ip ] ) ) {
			self::$login_attempts_store[ $ip ] = [];
		}

		self::$login_attempts_store[ $ip ] = array_values(
			array_filter(
				self::$login_attempts_store[ $ip ],
				static fn( $entry ) => ( $now - $entry['time'] ) < $window_seconds
			)
		);
		self::$login_attempts_store[ $ip ][] = [
			'user' => strtolower( trim( $username ) ),
			'time' => $now,
		];

		$distinct_users = array_unique( array_column( self::$login_attempts_store[ $ip ], 'user' ) );
		$count          = count( $distinct_users );

		return [
			'stuffing_detected' => $count > $max_usernames,
			'distinct_users'    => $count,
			'threshold'         => $max_usernames,
			'window'            => $window_seconds,
		];
	}

	/**
	 * Reset internal rate limiting and credential tracking (useful for unit tests).
	 */
	public static function reset_tracking(): void {
		self::$rate_limit_store     = [];
		self::$login_attempts_store = [];
	}

	private function is_high_risk_endpoint( string $uri ): bool {
		$high_risk = [ 'wp-login.php', 'xmlrpc.php', 'wp-admin/admin-ajax.php', 'wp-json/wp/v2/users' ];
		foreach ( $high_risk as $target ) {
			if ( str_contains( $uri, $target ) ) {
				return true;
			}
		}
		return false;
	}

	private function is_rule_applicable( array $rule, string $uri, array $active_components ): bool {
		if ( ! empty( $rule['revoked'] ) ) { return false; }
		$path = (string) parse_url( $uri, PHP_URL_PATH );
		// 1. Expiry check
		if ( ! empty( $rule['expiry'] ) && time() >= (int) $rule['expiry'] ) {
			return false;
		}

		// 2. Rollback check
		if ( ! empty( $rule['rollback'] ) && true === $rule['rollback'] ) {
			return false;
		}

		// 3. Endpoint scope matching
		if ( ! empty( $rule['endpoint_scope'] ) && '*' !== $rule['endpoint_scope'] ) {
			$scopes = is_array( $rule['endpoint_scope'] ) ? $rule['endpoint_scope'] : [ (string) $rule['endpoint_scope'] ];
			$matched_scope = false;
			foreach ( $scopes as $scope ) {
				if ( '*' === $scope || $path === rtrim( $scope, '/' ) || str_starts_with( $path, rtrim( $scope, '/' ) . '/' ) ) {
					$matched_scope = true;
					break;
				}
			}
			if ( ! $matched_scope ) {
				return false;
			}
		}

		// 4. Component version constraints (virtual patches)
		if ( ! empty( $rule['component_versions'] ) && is_array( $rule['component_versions'] ) ) {
			foreach ( $rule['component_versions'] as $component => $constraint ) {
				$active_ver = $active_components[ $component ]['version'] ?? null;
				if ( null === $active_ver ) {
					return false;
				}
				if ( preg_match( '/^(<=|>=|==|!=|<|>|=)\s*([0-9a-zA-Z\.\-]+)$/', trim( (string) $constraint ), $m ) ) {
					$op         = ( '==' === $m[1] ) ? '=' : $m[1];
					$target_ver = $m[2];
					if ( ! version_compare( (string) $active_ver, $target_ver, $op ) ) {
						return false;
					}
				} else {
					return false;
				}
			}
		}

		return true;
	}

	private function is_excluded_field( array $rule, string $field_key ): bool {
		// Global credential component exclusions
		$credential_path = str_replace( [ '[', ']' ], '.', $field_key );
		if ( preg_match( '/(?:^|[._-])(?:pass|password|passwd|pwd|token|nonce|wpnonce|secret|assert|assertion|cookie|session|credit|card|payment|authorization)(?:$|[._-])/i', $credential_path ) ) {
			return true;
		}

		return in_array( $field_key, $rule['exclusions'] ?? [], true );
	}

	/** Parse bounded UTF-8 XML without DTD/entity substitution or external access.
	 * XML-RPC positional parameters remain intentionally partial: they contain
	 * credentials without semantic field names. Native authentication owns them.
	 *
	 * @return array{data: array<string,string>, state: string}
	 */
	public function parse_xml( string $body, bool $xmlrpc_credentials = false ): array {
		$result = [ 'data' => [], 'state' => self::STATE_FULLY_INSPECTED ];
		if ( strlen( $body ) > $this->max_body_bytes ) {
			$result['state'] = self::STATE_BUDGET_EXCEEDED;
			return $result;
		}
		if ( '' === trim( $body ) ) {
			$result['state'] = self::STATE_PARSE_ERROR;
			return $result;
		}
		// Do not let an encoding declaration hide declarations from the lexical gate.
		if ( ! class_exists( '\DOMDocument' ) || str_contains( $body, "\0" ) || 1 !== preg_match( '//u', $body ) || preg_match( '/<!\s*(?:DOCTYPE|ENTITY)\b/i', $body ) || ( preg_match( '/^\s*(?:\xEF\xBB\xBF)?<\?xml\b[^?]*\bencoding\s*=\s*[\'"]([^\'"]+)/i', $body, $encoding ) && ! in_array( strtolower( $encoding[1] ), [ 'utf-8', 'us-ascii' ], true ) ) ) {
			$result['state'] = self::STATE_UNSUPPORTED_FORMAT;
			return $result;
		}
		$document = new \DOMDocument();
		$document->resolveExternals = false;
		$document->substituteEntities = false;
		$document->validateOnParse = false;
		// No NOENT, DTDLOAD, DTDATTR or PARSEHUGE; no process-global libxml changes.
		if ( ! @$document->loadXML( $body, LIBXML_NONET | LIBXML_COMPACT ) || ! $document->documentElement ) {
			$result['state'] = self::STATE_PARSE_ERROR;
			return $result;
		}
		if ( $document->doctype ) {
			$result['state'] = self::STATE_UNSUPPORTED_FORMAT;
			return $result;
		}
		$nodes = 0;
		$bytes = $this->max_body_bytes;
		$xmlrpc = $xmlrpc_credentials && 'methodCall' === $document->documentElement->localName;
		$this->collect_xml( $document->documentElement, '', 0, $nodes, $bytes, $xmlrpc, $result );
		return $result;
	}

	/** Walk every XML container/attribute/text node under shared inspection limits. */
	private function collect_xml( \DOMNode $node, string $path, int $depth, int &$nodes, int &$bytes, bool $xmlrpc, array &$result ): void {
		if ( ++$nodes > $this->max_nodes || $depth > $this->max_depth || $bytes <= 0 ) {
			$result['state'] = self::STATE_BUDGET_EXCEEDED;
			return;
		}
		$name = (string) ( $node->localName ?? $node->nodeName );
		if ( strlen( $name ) > 128 ) {
			$result['state'] = self::STATE_BUDGET_EXCEEDED;
			return;
		}
		$path .= '.' . $name;
		if ( $this->is_excluded_field( [], $path ) || ( $xmlrpc && 'params' === $name ) ) {
			if ( self::STATE_FULLY_INSPECTED === $result['state'] ) { $result['state'] = self::STATE_PARTIALLY_INSPECTED; }
			return;
		}
		if ( in_array( $node->nodeType, [ XML_TEXT_NODE, XML_CDATA_SECTION_NODE, XML_ATTRIBUTE_NODE ], true ) ) {
			$value = (string) $node->nodeValue;
			$size = min( 8192, $bytes );
			if ( strlen( $value ) > $size ) { $result['state'] = self::STATE_BUDGET_EXCEEDED; }
			$value = substr( $value, 0, $size );
			$bytes -= strlen( $value );
			// A unique traversal index preserves repeated siblings and mixed content.
			$result['data'][ 'xml.' . $nodes . $path ] = $value;
			return;
		}
		if ( $node->attributes ) {
			foreach ( $node->attributes as $attribute ) {
				$this->collect_xml( $attribute, $path, $depth + 1, $nodes, $bytes, $xmlrpc, $result );
				if ( self::STATE_BUDGET_EXCEEDED === $result['state'] ) { return; }
			}
		}
		$text = '';
		foreach ( $node->childNodes as $child ) {
			if ( XML_COMMENT_NODE === $child->nodeType || XML_PI_NODE === $child->nodeType ) { continue; }
			if ( in_array( $child->nodeType, [ XML_TEXT_NODE, XML_CDATA_SECTION_NODE ], true ) ) {
				if ( ++$nodes > $this->max_nodes ) { $result['state'] = self::STATE_BUDGET_EXCEEDED; return; }
				$available = min( 8192, $bytes ) - strlen( $text );
				if ( strlen( (string) $child->nodeValue ) > $available ) { $result['state'] = self::STATE_BUDGET_EXCEEDED; }
				$text .= substr( (string) $child->nodeValue, 0, max( 0, $available ) );
				continue;
			}
			if ( '' !== $text ) {
				$result['data'][ 'xml.' . $nodes . $path . '.text' ] = $text;
				$bytes -= strlen( $text );
				$text = '';
			}
			$this->collect_xml( $child, $path, $depth + 1, $nodes, $bytes, $xmlrpc, $result );
			if ( self::STATE_BUDGET_EXCEEDED === $result['state'] ) { return; }
		}
		if ( '' !== $text ) {
			$result['data'][ 'xml.' . $nodes . $path . '.text' ] = $text;
			$bytes -= strlen( $text );
		}
	}

	/**
	 * Parse multipart/form-data payload safely without disk I/O.
	 *
	 * @param string $raw_body     Raw body bytes.
	 * @param string $content_type Content-Type header.
	 * @param int|null $body_limit Optional framing cap, clamped to 1 MiB.
	 * @return array{fields: array, files: array, incomplete_fields: array, error: bool, state: string}
	 */
	public function parse_multipart( string $raw_body, string $content_type, ?int $body_limit = null ): array {
		$failure = [ 'fields' => [], 'files' => [], 'incomplete_fields' => [], 'error' => true, 'state' => self::STATE_PARSE_ERROR ];
		$body_limit = min( 1048576, max( 1, $body_limit ?? $this->max_body_bytes ) );
		if ( strlen( $raw_body ) > $body_limit || strlen( $content_type ) > 1024 ) {
			return array_replace( $failure, [ 'state' => self::STATE_BUDGET_EXCEEDED ] );
		}
		$parameters = $this->multipart_parameters( $content_type );
		if ( null === $parameters || 'multipart/form-data' !== $parameters['type'] || ! isset( $parameters['parameters']['boundary'] ) ) { return $failure; }
		$boundary = $parameters['parameters']['boundary'];
		if ( '' === $boundary || strlen( $boundary ) > 70 || ' ' === substr( $boundary, -1 ) || ! preg_match( "~^[0-9A-Za-z'()+_,./:=? -]+$~D", $boundary ) ) { return $failure; }
		$delimiter = '~(?:\A|\r\n)--' . preg_quote( $boundary, '~' ) . '(--)?[ \t]*(?:\r\n|$)~';
		if ( 1 !== preg_match( $delimiter, $raw_body, $opening, PREG_OFFSET_CAPTURE | PREG_UNMATCHED_AS_NULL ) ) { return $failure; }
		if ( $opening[0][1] && preg_match( '~(?:\A|\r\n)--' . preg_quote( $boundary, '~' ) . '~', substr( $raw_body, 0, $opening[0][1] ) ) ) { return $failure; }
		$result = [ 'fields' => [], 'files' => [], 'incomplete_fields' => [], 'error' => false, 'state' => 0 === $opening[0][1] ? self::STATE_FULLY_INSPECTED : self::STATE_PARTIALLY_INSPECTED ];
		$offset = $opening[0][1] + strlen( $opening[0][0] );
		if ( '--' === ( $opening[1][0] ?? '' ) ) { return $offset === strlen( $raw_body ) ? $result : array_replace( $result, [ 'state' => self::STATE_PARTIALLY_INSPECTED ] ); }
		for ( $parts = 0; $parts < 128; ++$parts ) {
			$header_end = strpos( $raw_body, "\r\n\r\n", $offset );
			if ( false === $header_end ) { return $failure; }
			if ( $header_end - $offset > 8192 ) { return array_replace( $failure, [ 'state' => self::STATE_BUDGET_EXCEEDED ] ); }
			$headers = [];
			foreach ( explode( "\r\n", substr( $raw_body, $offset, $header_end - $offset ) ) as $line ) {
				if ( count( $headers ) >= 32 || ! preg_match( '/^([a-z0-9-]+):[ \t]*([^\r\n\x00]*)$/iD', $line, $header ) ) { return $failure; }
				$key = strtolower( $header[1] );
				if ( isset( $headers[ $key ] ) ) { return $failure; }
				$headers[ $key ] = $header[2];
			}
			$disposition = $this->multipart_parameters( $headers['content-disposition'] ?? '' );
			if ( null === $disposition || 'form-data' !== $disposition['type'] || ! array_key_exists( 'name', $disposition['parameters'] ) ) { return $failure; }
			$params = $disposition['parameters'];
			if ( isset( $params['name*'] ) || isset( $params['filename*'] ) ) { return $failure; }
			if ( isset( $headers['content-transfer-encoding'] ) && ! in_array( strtolower( trim( $headers['content-transfer-encoding'] ) ), [ 'binary', '8bit', '7bit' ], true ) ) { return array_replace( $failure, [ 'state' => self::STATE_UNSUPPORTED_FORMAT ] ); }
			if ( isset( $headers['content-type'] ) ) {
				$part_type = $this->multipart_parameters( $headers['content-type'] );
				if ( null === $part_type || str_starts_with( $part_type['type'], 'multipart/' ) || ( isset( $part_type['parameters']['charset'] ) && ! in_array( strtolower( $part_type['parameters']['charset'] ), [ 'utf-8', 'us-ascii' ], true ) ) ) { return array_replace( $failure, [ 'state' => self::STATE_UNSUPPORTED_FORMAT ] ); }
			}
			$body_start = $header_end + 4;
			if ( 1 !== preg_match( $delimiter, $raw_body, $next, PREG_OFFSET_CAPTURE | PREG_UNMATCHED_AS_NULL, $body_start ) ) { return $failure; }
			$body = substr( $raw_body, $body_start, $next[0][1] - $body_start );
			// A line beginning with the delimiter but having an invalid suffix is ambiguous.
			if ( str_contains( $body, "\r\n--" . $boundary ) ) { return $failure; }
			$name = $params['name'];
			if ( array_key_exists( 'filename', $params ) ) {
				$result['files'][] = [ 'name' => $params['filename'], 'type' => $headers['content-type'] ?? 'application/octet-stream', 'size' => strlen( $body ) ];
				if ( self::STATE_FULLY_INSPECTED === $result['state'] ) { $result['state'] = self::STATE_PARTIALLY_INSPECTED; } // Metadata only; file content is not scanned.
			} else {
				if ( '_charset_' === $name && ! in_array( strtolower( trim( $body ) ), [ 'utf-8', 'us-ascii' ], true ) ) { return array_replace( $failure, [ 'state' => self::STATE_UNSUPPORTED_FORMAT ] ); }
				if ( strlen( $body ) > 65536 ) {
					$result['state'] = self::STATE_BUDGET_EXCEEDED;
					$result['incomplete_fields'][] = $name;
					$body = substr( $body, 0, 65536 );
				}
				$result['fields'][ $name ][] = $body; // Never collapse repeated values.
				if ( $this->is_excluded_field( [], $name ) && self::STATE_FULLY_INSPECTED === $result['state'] ) { $result['state'] = self::STATE_PARTIALLY_INSPECTED; }
			}
			$offset = $next[0][1] + strlen( $next[0][0] );
			if ( '--' === ( $next[1][0] ?? '' ) ) {
				if ( $offset < strlen( $raw_body ) && self::STATE_FULLY_INSPECTED === $result['state'] ) { $result['state'] = self::STATE_PARTIALLY_INSPECTED; }
				return $result;
			}
		}
		return array_replace( $failure, [ 'state' => self::STATE_BUDGET_EXCEEDED ] );
	}

	/** Bounded MIME parameter lexer: exact names, quoted pairs and no duplicate keys. */
	private function multipart_parameters( string $header ): ?array {
		if ( strlen( $header ) > 8192 || preg_match( '/[\x00-\x08\x0A-\x1F\x7F]/', $header ) ) { return null; }
		$separator = strpos( $header, ';' );
		$type = strtolower( trim( false === $separator ? $header : substr( $header, 0, $separator ) ) );
		if ( '' === $type ) { return null; }
		$params = [];
		$offset = false === $separator ? strlen( $header ) : $separator;
		while ( $offset < strlen( $header ) ) {
			if ( ';' !== $header[ $offset++ ] ) { return null; }
			while ( isset( $header[ $offset ] ) && str_contains( " \t", $header[ $offset ] ) ) { ++$offset; }
			$equals = strpos( $header, '=', $offset );
			if ( false === $equals ) { return null; }
			$key = strtolower( trim( substr( $header, $offset, $equals - $offset ) ) );
			if ( ! preg_match( '/^[a-z0-9_*-]{1,64}$/iD', $key ) || array_key_exists( $key, $params ) ) { return null; }
			$offset = $equals + 1;
			while ( isset( $header[ $offset ] ) && str_contains( " \t", $header[ $offset ] ) ) { ++$offset; }
			$value = '';
			if ( isset( $header[ $offset ] ) && '"' === $header[ $offset ] ) {
				++$offset;
				$closed = false;
				while ( isset( $header[ $offset ] ) ) {
					$char = $header[ $offset++ ];
					if ( '"' === $char ) { $closed = true; break; }
					if ( '\\' === $char && isset( $header[ $offset ] ) && in_array( $header[ $offset ], [ '"', '\\' ], true ) ) { $char = $header[ $offset++ ]; }
					$value .= $char;
				}
				if ( ! $closed ) { return null; }
				while ( isset( $header[ $offset ] ) && str_contains( " \t", $header[ $offset ] ) ) { ++$offset; }
				if ( isset( $header[ $offset ] ) && ';' !== $header[ $offset ] ) { return null; }
			} else {
				$end = strpos( $header, ';', $offset );
				$end = false === $end ? strlen( $header ) : $end;
				$value = trim( substr( $header, $offset, $end - $offset ) );
				if ( '' === $value || preg_match( '/[\s"\\\\]/', $value ) ) { return null; }
				$offset = $end;
			}
			$params[ $key ] = $value;
		}
		return [ 'type' => $type, 'parameters' => $params ];
	}

	/**
	 * Recursively flatten and normalize inputs with depth and node bounding.
	 *
	 * @param array  $data       Data array.
	 * @param string $prefix     Current key path.
	 * @param int    $depth      Current depth.
	 * @param int    $node_count Running node counter.
	 * @return array<string, string> Flattened normalized inputs.
	 */
	private function flatten_and_normalize( array $data, string $prefix, int $depth, int &$node_count ): array {
		$result = [];
		if ( $depth > $this->max_depth || $node_count >= $this->max_nodes ) {
			$this->truncated = true;
			return $result;
		}

		foreach ( $data as $key => $value ) {
			++$node_count;
			if ( $node_count >= $this->max_nodes ) {
				$this->truncated = true;
				break;
			}

			$full_key = '' === $prefix ? (string) $key : $prefix . '.' . $key;
			if ( $this->is_excluded_field( [], $full_key ) ) {
				$this->excluded = true;
				continue;
			}
			if ( is_array( $value ) ) {
				$result = array_merge( $result, $this->flatten_and_normalize( $value, $full_key, $depth + 1, $node_count ) );
			} elseif ( is_scalar( $value ) ) {
				$value = (string) $value;
				$size = min( 8192, $this->remaining_bytes );
				if ( strlen( $value ) > $size ) { $this->truncated = true; }
				$value = substr( $value, 0, $size );
				$this->remaining_bytes -= strlen( $value );
				$result[ $full_key ] = $this->normalize_string( $value );
			}
		}

		return $result;
	}

	/**
	 * Multi-pass normalization: recursive URL decode, HTML entity decode,
	 * control character removal, fullwidth ASCII conversion, and Unicode NFKC normalization.
	 *
	 * @param string $str Input string.
	 * @return string Normalized string.
	 */
	private function normalize_string( string $str ): string {
		// 1. Recursive URL decoding (up to 3 passes to unwrap nested/double URL encoding)
		for ( $i = 0; $i < 3; $i++ ) {
			$decoded = rawurldecode( $str );
			if ( $decoded === $str ) {
				break;
			}
			$str = $decoded;
		}

		// 2. HTML entity decode
		$str = html_entity_decode( $str, ENT_QUOTES | ENT_HTML5, 'UTF-8' );

		// 3. Null-byte and dangerous control character stripping
		$str = preg_replace( '/[\x00\x08\x0B\x0C\x0E-\x1F]/', '', $str ) ?? $str;

		// 4. Unicode fullwidth ASCII conversion (\uFF01 - \uFF5E -> \x21 - \x7E)
		// e.g., ＜script＞ (\uFF1C\uFF53\uFF43\uFF52\uFF49\uFF50\uFF54\uFF1E) -> <script>
		$str = preg_replace_callback(
			'/[\x{FF01}-\x{FF5E}]/u',
			static function ( array $match ): string {
				return chr( ( ( ord( $match[0][0] ) & 15 ) << 12 | ( ord( $match[0][1] ) & 63 ) << 6 | ( ord( $match[0][2] ) & 63 ) ) - 0xFEE0 );
			},
			$str
		) ?? $str;

		// 5. NFKC normalization if Normalizer class is present
		if ( class_exists( 'Normalizer' ) ) {
			$normalized = \Normalizer::normalize( $str, \Normalizer::FORM_KC );
			if ( false !== $normalized ) {
				$str = $normalized;
			}
		}

		return $str;
	}
}
