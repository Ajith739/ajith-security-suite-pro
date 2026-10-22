<?php
/** Bounded, site-scoped state and atomic counters for enterprise services.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed site-owned tables and prepared values; atomic security state and privacy erasure must bypass object caches.
/** Enterprise store service. */
final class GWQSH_Enterprise_Store {
	/**
	 * Install.
	 *
	 * @return mixed Operation result.
	 */
	public static function install() {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$table   = $wpdb->prefix . 'gwqsh_security_state';
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$table} (
 state_key char(64) NOT NULL,
 kind varchar(24) NOT NULL,
 payload longtext NOT NULL,
 counter bigint(20) unsigned NOT NULL DEFAULT 0,
 expires_at bigint(20) unsigned NOT NULL,
 PRIMARY KEY  (state_key),
 KEY expiry (expires_at),
 KEY kind_expiry (kind,expires_at)
) {$charset};"
		);
		$table = $wpdb->prefix . 'gwqsh_delivery_queue';
		dbDelta(
			"CREATE TABLE {$table} (
 id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
 delivery_key char(64) NOT NULL,
 channel varchar(24) NOT NULL,
 payload text NOT NULL,
 status varchar(16) NOT NULL DEFAULT 'pending',
 attempts smallint(5) unsigned NOT NULL DEFAULT 0,
 available_at bigint(20) unsigned NOT NULL,
 created_at bigint(20) unsigned NOT NULL,
 last_error varchar(100) NOT NULL DEFAULT '',
 lease_token char(32) NOT NULL DEFAULT '',
 PRIMARY KEY  (id),
 UNIQUE KEY delivery_key (delivery_key),
 KEY pending (status,available_at),
 KEY created_at (created_at)
) {$charset};"
		);
		foreach ( array(
			'gwqsh_security_state' => array( 'state_key', 'kind', 'payload', 'counter', 'expires_at' ),
			'gwqsh_delivery_queue' => array( 'id', 'delivery_key', 'channel', 'payload', 'status', 'attempts', 'available_at', 'created_at', 'last_error', 'lease_token' ),
		) as $suffix => $required ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared -- Suffix is from the fixed internal table allowlist above; wpdb prefix is trusted.
			$columns = $wpdb->get_col( 'SHOW COLUMNS FROM ' . $wpdb->prefix . $suffix );
			if ( array_diff( $required, (array) $columns ) ) {
				return new WP_Error( 'schema', 'Security service tables could not be installed completely.' ); }
		}
		return true;
	}
	/**
	 * Key.
	 *
	 * @param mixed $kind Kind.
	 * @param mixed $key Key.
	 * @return mixed Operation result.
	 */
	public static function key( $kind, $key ) {
		return hash( 'sha256', $kind . '|' . $key ); }
	/**
	 * Get.
	 *
	 * @param mixed $kind Kind.
	 * @param mixed $key Key.
	 * @return mixed Operation result.
	 */
	public static function get( $kind, $key ) {
		global $wpdb;
		$raw = $wpdb->get_var( $wpdb->prepare( "SELECT payload FROM {$wpdb->prefix}gwqsh_security_state WHERE state_key=%s AND expires_at>%d", self::key( $kind, $key ), time() ) );
		return null === $raw ? null : json_decode( $raw, true );
	}
	/**
	 * Put.
	 *
	 * @param mixed $kind Kind.
	 * @param mixed $key Key.
	 * @param mixed $value Value.
	 * @param mixed $ttl Ttl.
	 * @return mixed Operation result.
	 */
	public static function put( $kind, $key, $value, $ttl = 3600 ) {
		global $wpdb;
		$hash    = self::key( $kind, $key );
		$payload = wp_json_encode( $value );
		if ( false === $payload || strlen( $payload ) > 1048576 ) {
			return false;
		}
		self::prune();
		// Admission is serialized to bound storage even when many new visitor IPs arrive together.
		$lock = self::lock( 'admission', 5 );
		if ( ! $lock ) {
			return false;
		}
		try {
			$count    = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}gwqsh_security_state" );
			$existing = $wpdb->get_var( $wpdb->prepare( "SELECT state_key FROM {$wpdb->prefix}gwqsh_security_state WHERE state_key=%s", $hash ) );
			if ( ! $existing && $count >= 5000 ) {
				return false;
			}
			return false !== $wpdb->replace(
				$wpdb->prefix . 'gwqsh_security_state',
				array(
					'state_key'  => $hash,
					'kind'       => substr( $kind, 0, 24 ),
					'payload'    => $payload,
					'counter'    => 0,
					'expires_at' => time() + max( 1, min( 604800, (int) $ttl ) ),
				)
			);
		} finally {
			self::unlock( 'admission', $lock );}
	}
	/**
	 * Lock.
	 *
	 * @param mixed $name Name.
	 * @param mixed $ttl Ttl.
	 * @return mixed Operation result.
	 */
	public static function lock( $name, $ttl = 60 ) {
		global $wpdb;
		$key   = self::key( 'lease', $name );
		$token = bin2hex( random_bytes( 16 ) );
		$now   = time();
		$wpdb->query( $wpdb->prepare( "INSERT INTO {$wpdb->prefix}gwqsh_security_state (state_key,kind,payload,expires_at) VALUES (%s,'lease',%s,%d) ON DUPLICATE KEY UPDATE payload=IF(expires_at<%d,VALUES(payload),payload),expires_at=IF(expires_at<%d,VALUES(expires_at),expires_at)", $key, $token, $now + $ttl, $now, $now ) );
		$actual = $wpdb->get_var( $wpdb->prepare( "SELECT payload FROM {$wpdb->prefix}gwqsh_security_state WHERE state_key=%s", $key ) );
		if ( ! is_string( $actual ) || ! hash_equals( $token, $actual ) ) {
			return false; }
		return $token;
	}
	/** Read an active owner lease without an object-cache dependency.
	 *
	 * @param string $name Lease identifier.
	 * @return bool Whether the lease is active.
	 */
	public static function lease_active( $name ) {
		global $wpdb;
		return (bool) $wpdb->get_var( $wpdb->prepare( "SELECT 1 FROM {$wpdb->prefix}gwqsh_security_state WHERE state_key=%s AND expires_at>=%d", self::key( 'lease', $name ), time() ) );
	}
	/**
	 * Unlock.
	 *
	 * @param mixed $name Name.
	 * @param mixed $token Token.
	 * @return mixed Operation result.
	 */
	public static function unlock( $name, $token ) {
		global $wpdb;
		return $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_security_state WHERE state_key=%s AND payload=%s", self::key( 'lease', $name ), $token ) );}
	/**
	 * Hit.
	 *
	 * @param mixed $name Name.
	 * @param mixed $identity Identity.
	 * @param mixed $seconds Seconds.
	 * @param int|null $issued_at Server-issued challenge time for a stable window across retries.
	 * @return mixed Operation result.
	 */
	public static function hit( $name, $identity, $seconds = 60, $issued_at = null ) {
		global $wpdb;
		$seconds = max( 1, (int) $seconds );
		$key     = self::key( 'counter', $name . '|' . $identity . '|' . intdiv( null === $issued_at ? time() : (int) $issued_at, $seconds ) );
		$table   = $wpdb->prefix . 'gwqsh_security_state';
		$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET counter=LAST_INSERT_ID(counter+1) WHERE state_key=%s", $key ) );
		if ( false === $changed ) {
			return null;
		}
		if ( 0 === $changed ) {
			// New counter admission uses the same capacity gate; increment itself is atomic SQL.
			$lock = self::lock( 'admission', 5 );
			// A concurrent caller may be admitting this very counter. Give it a
			// bounded chance to finish, then increment the existing row atomically.
			// Never insert without the capacity lock or wait for its full lease.
			for ( $retry = 0; ! $lock && $retry < 8; ++$retry ) {
				usleep( 1000 );
				$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET counter=LAST_INSERT_ID(counter+1) WHERE state_key=%s", $key ) );
				if ( false === $changed ) {
					return null;
				}
				if ( $changed ) {
					$count = $wpdb->get_var( 'SELECT LAST_INSERT_ID()' );
					return null === $count ? null : (int) $count;
				}
				$lock = self::lock( 'admission', 5 );
			}
			if ( ! $lock ) {
				return null;
			}
			try {
				if ( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) >= 5000 ) {
							self::prune();
					if ( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) >= 5000 ) {
						return null;
					}
				}
				$changed = $wpdb->query( $wpdb->prepare( "INSERT INTO {$table} (state_key,kind,payload,counter,expires_at) VALUES (%s,'counter','',LAST_INSERT_ID(1),%d) ON DUPLICATE KEY UPDATE counter=LAST_INSERT_ID(counter+1)", $key, time() + $seconds + 60 ) );
			} finally {
				self::unlock( 'admission', $lock );}
		}
		if ( false === $changed ) {
			return null;
		}
		$count = $wpdb->get_var( 'SELECT LAST_INSERT_ID()' );
		return null === $count ? null : (int) $count;
	}
	/**
	 * Prune.
	 *
	 * @return mixed Operation result.
	 */
	public static function prune() {
		global $wpdb;
		return $wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_security_state WHERE expires_at<%d LIMIT 500", time() ) );}
}
