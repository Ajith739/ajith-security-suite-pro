<?php
/**
 * Conservative abuse protection informed by the uploaded WP firewall/bot products.
 * Original Gracewell implementation: no third-party signatures or vendor code copied.
 *
 * A user-agent is never sufficient evidence. A small set of sensitive, nonpublic
 * file paths is protected in block mode and repeated high-confidence probes may
 * temporarily restrict an anonymous IP. Report/recovery/disabled modes never
 * enforce restrictions. This is a WordPress-layer control, not edge DDoS defense.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

final class GWQSH_Bot_Shield {
	const PROBE_RULE = 'GWQSH-1020';
	const HOLD_RULE = 'GWQSH-1021';

	/**
	 * Match narrowly defined attempts to read private configuration/metadata.
	 * URI path only, never query arguments or User-Agent. WordPress permalinks,
	 * WooCommerce checkout, REST routes and assets are otherwise unaffected.
	 *
	 * @param mixed $raw_path Absolute request URI path, not a filesystem path.
	 * @return string Fixed rule identifier or empty string.
	 */
	public static function path_rule( $raw_path ) {
		if ( ! is_string( $raw_path ) || strlen( $raw_path ) > 2048 || strpos( $raw_path, "\0" ) !== false || '' === $raw_path || '/' !== $raw_path[0] ) {
			return '';
		}
		$path = explode( '?', $raw_path, 2 )[0];
		// Decode at most twice to cover common double-encoding without loops.
		for ( $i = 0; $i < 2; ++$i ) {
			$next = rawurldecode( $path );
			if ( $next === $path ) {
				break;
			}
			$path = $next;
		}
		// Backslashes are sometimes interpreted as separators by downstream servers.
		$path = str_replace( '\\', '/', $path );
		if ( strlen( $path ) > 2048 || preg_match( '/[\x00-\x1f\x7f]/', $path ) ) {
			return '';
		}
		// Protect private files only. Never block from a purported bot User-Agent.
		$private = '~(?:^|/)(?:
			\\.env(?:\\.[a-z0-9_-]{1,32})?(?:/|$)
			|\\.git/(?:config|head|index|packed-refs|objects/[^/]+/[^/]+)(?:/|$)
			|\\.svn/(?:entries|wc\\.db)(?:/|$)
			|\\.hg/(?:hgrc|requires)(?:/|$)
			|\\.aws/credentials(?:/|$)
			|wp-config\\.php(?:\\.(?:bak|old|orig|save|swp|txt|dist)|\~)?(?:/|$)
			|wp-content/debug\\.log(?:/|$)
			|vendor/phpunit/phpunit/(?:src/util/php/eval-stdin\\.php|phpunit)(?:/|$)
			|\\.htpasswd(?:/|$)
			)~ixD';
		return preg_match( $private, $path ) ? self::PROBE_RULE : '';
	}

	/** Determine if an anonymous request may create/enforce bot holds. */
	public static function can_enforce( $anonymous, $legacy, $policy, $mode ) {
		return $anonymous && ! empty( $legacy['enabled'] ) && ! empty( $legacy['bots'] )
			&& ! empty( $policy['bot_probe'] ) && 'block' === ( $policy['mode'] ?? '' ) && 'block' === $mode;
	}

	/** Return active held-IP rule, without creating any state. */
	public static function held_rule( $ip ) {
		if ( ! is_string( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return '';
		}
		$record = GWQSH_Enterprise_Store::get( 'bot-hold', $ip );
		return is_array( $record ) && true === ( $record['active'] ?? false ) ? self::HOLD_RULE : '';
	}

	/**
	 * Count only confirmed sensitive-path probes. A missing DB/capacity fails open.
	 * Cumulative count is within a 2-minute fixed window; expiry of a hold is
	 * enforced by the existing database's expires_at column. Never store raw URL,
	 * authentication material or the User-Agent in the hold state.
	 */
	public static function record_probe( $ip, $policy ) {
		if ( ! is_string( $ip ) || ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
			return false;
		}
		$count = GWQSH_Enterprise_Store::hit( 'bot-probe', $ip, 120 );
		if ( null === $count || $count < max( 3, min( 50, (int) ( $policy['bot_threshold'] ?? 5 ) ) ) ) {
			return false;
		}
		$seconds = max( 60, min( 3600, (int) ( $policy['bot_hold_seconds'] ?? 600 ) ) );
		return (bool) GWQSH_Enterprise_Store::put( 'bot-hold', $ip, array( 'active' => true ), $seconds );
	}
}
