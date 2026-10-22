<?php
/**
 * Dependency-free, bounded early analysis and evidence preservation.
 * This source is embedded in the installed Guardian, never loaded from a scanned file.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'GWQSH_Security_Runtime', false ) ) {
	/** Minimal common security primitives. No database, network or WordPress functions. */
	final class GWQSH_Security_Runtime {
		const VERSION = '2';
		const LIMIT   = 524288;

		/**
		 * Reject wrappers, traversal and every symlink component, including broken links.
		 *
		 * @param mixed $path Path.
		 * @param mixed $root Root.
		 */
		public static function safe_path( $path, $root ) {
			if ( ! is_string( $path ) || strpos( $path, "\0" ) !== false || strpos( $path, '://' ) !== false || preg_match( '#(^|[/\\\\])\.{1,2}([/\\\\]|$)#', $path ) ) {
				return false;
			}
			$root = realpath( $root );
			$real = realpath( $path );
			if ( ! $root || ! $real || strpos( $real, $root . DIRECTORY_SEPARATOR ) !== 0 ) {
				return false;
			}
			$cursor = $path;
			while ( dirname( $cursor ) !== $cursor ) {
				if ( is_link( $cursor ) ) {
					return false;
				}
				$cursor = dirname( $cursor );
			}
			return $real;
		}

		/**
		 * Estimate lexical complexity before allocating PHP token arrays.
		 *
		 * @param string $content Bounded untrusted content.
		 */
		public static function token_budget( $content ) {
			if ( strpos( $content, '<?' ) === false ) {
				return true;
			}
			if ( ! ini_get( 'short_open_tag' ) && ! preg_match( '/<\?(?:php(?:\s|$)|=)/i', $content ) ) {
				return true;
			}
			return preg_match_all( '/[A-Za-z0-9_$]+|[^\sA-Za-z0-9_$]/', $content ) <= 16000;
		}

		/**
		 * Remove PHP comments, keeping strings as data; never parse with TOKEN_PARSE or execute.
		 *
		 * @param mixed $content Content.
		 */
		public static function code( $content ) {
			$out = '';
			foreach ( token_get_all( $content ) as $token ) {
				if ( is_array( $token ) ) {
					$out .= in_array( $token[0], array( T_COMMENT, T_DOC_COMMENT ), true ) ? ' ' : $token[1];
				} else {
					$out .= $token;
				}
			}
			return $out;
		}

		/**
		 * Code positions only: quoted examples and comments cannot be executable calls.
		 *
		 * @param mixed $content Content.
		 */
		public static function syntax( $content ) {
			$out = '';
			foreach ( token_get_all( $content ) as $token ) {
				if ( is_array( $token ) ) {
					$out .= in_array( $token[0], array( T_COMMENT, T_DOC_COMMENT, T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE, T_INLINE_HTML ), true ) ? str_repeat( ' ', strlen( $token[1] ) ) : $token[1];
				} else {
					$out .= $token;
				}
			}
			return $out;
		}

		/**
		 * Return actual free-function calls with bounded arguments, excluding quoted examples,
		 * declarations and object/static method calls. Tokenization never executes input.
		 *
		 * @param string $content Untrusted PHP source.
		 */
		public static function calls( $content ) {
			$content = substr( $content, 0, self::LIMIT );
			if ( ! self::token_budget( $content ) ) {
				return array(
					array(
						'name'   => '__analysis_limit',
						'raw'    => '',
						'syntax' => '',
					),
				);
			}
			$tokens = array();
			foreach ( token_get_all( $content ) as $token ) {
				if ( ! is_array( $token ) || ! in_array( $token[0], array( T_WHITESPACE, T_COMMENT, T_DOC_COMMENT ), true ) ) {
					$tokens[] = $token;
				}
			}
			$calls          = array();
			$argument_bytes = 0;
			$count          = count( $tokens );
			for ( $i = 0; $i < $count - 1; $i++ ) {
				$token = $tokens[ $i ];
				if ( ! is_array( $token ) || ! in_array( token_name( $token[0] ), array( 'T_STRING', 'T_EVAL', 'T_NAME_FULLY_QUALIFIED' ), true ) || '(' !== $tokens[ $i + 1 ] ) {
					continue;
				}
				$previous = $i ? $tokens[ $i - 1 ] : null;
				if ( is_array( $previous ) && in_array( $previous[0], array( T_FUNCTION, T_OBJECT_OPERATOR, T_DOUBLE_COLON, T_NEW ), true ) ) {
					continue;
				}
				$depth  = 1;
				$raw    = '';
				$syntax = '';
				for ( $j = $i + 2; $j < $count; $j++ ) {
					if ( strlen( $raw ) >= 8192 ) {
						$calls[] = array(
							'name'   => '__analysis_limit',
							'raw'    => '',
							'syntax' => '',
						);
						break;
					}
					$part = $tokens[ $j ];
					if ( '(' === $part ) {
						++$depth;
					} elseif ( ')' === $part && 0 === --$depth ) {
						break;
					}
					$text    = is_array( $part ) ? $part[1] : $part;
					$raw    .= $text;
					$syntax .= is_array( $part ) && in_array( $part[0], array( T_CONSTANT_ENCAPSED_STRING, T_ENCAPSED_AND_WHITESPACE ), true ) ? str_repeat( ' ', strlen( $text ) ) : $text;
				}
				$argument_bytes += strlen( $raw );
				if ( $argument_bytes > 4194304 || count( $calls ) >= 512 ) {
					$calls[] = array(
						'name'   => '__analysis_limit',
						'raw'    => '',
						'syntax' => '',
					);
					break;
				}
				$calls[] = array(
					'name'   => strtolower( ltrim( $token[1], '\\' ) ),
					'raw'    => $raw,
					'syntax' => $syntax,
				);
			}
			return $calls;
		}

		/**
		 * Explicit combinations. These are signals, not a full PHP data-flow proof.
		 *
		 * @param mixed $content Content.
		 */
		public static function analyze( $content ) {
			$truncated = strlen( $content ) > self::LIMIT;
			$content   = substr( $content, 0, self::LIMIT );
			if ( ! self::token_budget( $content ) ) {
				return array(
					'score'      => 0,
					'rules'      => array( 'token_budget_limit' ),
					'auto_block' => false,
					'partial'    => true,
				);
			}
			$code  = self::code( substr( $content, 0, self::LIMIT ) );
			$rules = array();
			$calls = self::calls( $content );
			$names = array_column( $calls, 'name' );
			foreach ( $calls as $call ) {
				if ( in_array( $call['name'], array( 'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru', 'proc_open', 'popen' ), true ) ) {
					if ( preg_match( '/\$_(?:GET|POST|REQUEST|COOKIE)\b/', $call['syntax'] ) ) {
						$rules['request_execution'] = 100;
					}
					if ( in_array( $call['name'], array( 'eval', 'assert' ), true ) && preg_match( '/^\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(/i', $call['syntax'] ) ) {
						$rules['encoded_execution'] = 95;
					}
				}
				if ( 'file_put_contents' === $call['name'] && preg_match( '/^[^,]{0,250}\.php[\'\"][^;]{0,250}\b(?:file_get_contents|wp_remote_retrieve_body|curl_exec)\s*\(/i', $call['raw'] ) && preg_match( '~https?://~i', $code ) ) {
					$rules['remote_php_write'] = 95;
				}
				if ( in_array( $call['name'], array( 'file_put_contents', 'copy' ), true ) && preg_match( '/(?:index\.php|\.htaccess)/i', $call['raw'] ) && preg_match( '/[\'\"]\.[a-z0-9_-]{1,100}[^\'\"\r\n]{0,80}(?:bak|backup)/i', $code ) ) {
					foreach ( $calls as $permission ) {
						if ( 'chmod' === $permission['name'] && preg_match( '/(?:index\.php|\.htaccess)[^,]{0,100},0?444$/i', $permission['raw'] ) ) {
							$rules['locked_root_restoration'] = 100;
						}
					}
				}
			}
			// Bot + redirect is reported by the main engine. Early blocking additionally needs
			// a remote .txt destination and template_redirect, avoiding ordinary SEO redirects.
			if ( stripos( $code, 'HTTP_USER_AGENT' ) !== false && preg_match( '/googlebot|bingbot/i', $code ) && stripos( $code, 'template_redirect' ) !== false && array_intersect( $names, array( 'wp_redirect', 'header' ) ) && preg_match( '~https?://[^\s\'\"]{1,250}\.txt\b~i', $code ) && array_intersect( $names, array( 'curl_exec', 'wp_remote_get', 'file_get_contents' ) ) ) {
				$rules['remote_bot_gate'] = 100;
			}
			return array(
				'score'      => $rules ? max( $rules ) : 0,
				'rules'      => array_keys( $rules ),
				'auto_block' => ! empty( $rules ),
				'partial'    => $truncated || in_array( '__analysis_limit', $names, true ),
			);
		}

		/**
		 * Atomic write to a fresh random sibling. Existing symlinks are never accepted.
		 *
		 * @param mixed $path Path.
		 * @param mixed $content Content.
		 */
		public static function atomic_write( $path, $content ) {
			if ( ! self::safe_path( dirname( $path ) . DIRECTORY_SEPARATOR . 'index.php', dirname( $path ) ) ) {
				return false;
			}
			$temp = dirname( $path ) . '/.' . bin2hex( random_bytes( 12 ) ) . '.tmp';
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			$fp = @fopen( $temp, 'xb' );
			if ( ! $fp ) {
				return false;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			$ok = fwrite( $fp, $content ) === strlen( $content ) && fflush( $fp );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			fclose( $fp );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@chmod( $temp, 0600 );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			clearstatcache( true, $path );
				$ok = $ok && ! is_link( $path ) && @rename( $temp, $path );
			if ( is_file( $temp ) ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				@unlink( $temp );
			}
			return $ok;
		}

		/**
		 * Storage guards must be installed before evidence is written.
		 *
		 * @param mixed $dir Dir.
		 */
		public static function protect( $dir ) {
			if ( ! is_string( $dir ) || strpos( $dir, "\0" ) !== false || strpos( $dir, '://' ) !== false || preg_match( '#(^|[/\\\\])\.{1,2}([/\\\\]|$)#', $dir ) ) {
				return false;
			}
			$cursor = $dir;
			while ( dirname( $cursor ) !== $cursor ) {
				if ( is_link( $cursor ) ) {
					return false;
				}
				$cursor = dirname( $cursor );
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			if ( ! is_dir( $dir ) && ! @mkdir( $dir, 0700, true ) ) {
				return false;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			if ( ! @chmod( $dir, 0700 ) ) {
				return false;
			}
			foreach ( array(
				'index.php'  => "<?php\nreturn;\n",
				'.htaccess'  => "Options -Indexes\n<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nOrder deny,allow\nDeny from all\n</IfModule>\n",
				'web.config' => '<configuration><system.webServer><security><authorization><remove users="*" roles="" verbs=""/><add accessType="Deny" users="*"/></authorization></security></system.webServer></configuration>',
			) as $name => $body ) {
				$file = $dir . '/' . $name;
				if ( is_link( $file ) || ( is_file( $file ) && ! self::safe_path( $file, $dir ) ) || @file_put_contents( $file, $body, LOCK_EX ) !== strlen( $body ) ) {
					return false;
				}
			}
			return true;
		}

		/**
		 * Copy, verify, record, then atomically replace. Failures preserve the original.
		 *
		 * @param mixed $file File.
		 * @param mixed $root Root.
		 * @param mixed $dir Dir.
		 * @param array $rules Rules.
		 * @param mixed $stub Stub.
		 * @param mixed $expected Expected.
		 */
		public static function preserve( $file, $root, $dir, array $rules, $stub = false, $expected = '' ) {
			$file = self::safe_path( $file, $root );
			if ( ! $file || ! is_file( $file ) || ! is_readable( $file ) || ! is_dir( $dir ) || ! self::safe_path( $dir . '/index.php', $dir ) ) {
				return false;
			}
			$hash = @hash_file( 'sha256', $file );
			if ( ! $hash || ( $expected && ! hash_equals( $expected, $hash ) ) ) {
				return false;
			}
			$id   = bin2hex( random_bytes( 16 ) );
			$dest = $dir . '/' . $id . '.quarantine';
			if ( ! @copy( $file, $dest ) || @hash_file( 'sha256', $dest ) !== $hash ) {
				return false;
			}
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			@chmod( $dest, 0600 );
			$meta = array(
				'original' => str_replace( '\\', '/', substr( $file, strlen( realpath( $root ) ) + 1 ) ),
				'hash'     => $hash,
				'time'     => time(),
				'rules'    => $rules,
				'decision' => 'preserved',
				'id'       => $id,
			);
			if ( ! self::atomic_write( $dir . '/' . $id . '.json', json_encode( $meta ) ) || @hash_file( 'sha256', $file ) !== $hash ) {
				return false;
			}
			if ( $stub ) {
				// A precomputed WordPress MU list will include this original pathname next.
				$temp = dirname( $file ) . '/.' . $id . '.tmp';
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				$fp = @fopen( $temp, 'xb' );
				if ( ! $fp ) {
					return false;
				}
				$body = "<?php\n// Gracewell-blocked; evidence " . $id . ".\nreturn;\n";
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				$ok = fwrite( $fp, $body ) === strlen( $body ) && fflush( $fp );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				fclose( $fp );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				@chmod( $temp, 0644 );
				// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				$ok = $ok && self::safe_path( $file, $root ) && @hash_file( 'sha256', $file ) === $hash && @rename( $temp, $file );
				if ( is_file( $temp ) ) {
					// phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
					@unlink( $temp );
				}
				if ( ! $ok ) {
					$meta['decision'] = 'block_failed';
					self::atomic_write( $dir . '/' . $id . '.json', json_encode( $meta ) );
					return false;
				}
			}
			if ( $stub ) {
				$meta['decision'] = 'blocked';
				if ( ! self::atomic_write( $dir . '/' . $id . '.json', json_encode( $meta ) ) ) {
					return false;
				}
			}
			return $meta;
		}
	}
}
