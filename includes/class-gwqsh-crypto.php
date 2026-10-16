<?php
/**
 * Authenticated encryption for per-user secrets.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Crypto implementation.
 */
final class GWQSH_Crypto {
	/**
	 * Record the old Pro key scheme before upgrading its database version.
	 * Free 1.0.x already uses a site salt; never replace its missing encryption key.
	 */
	public static function prepare_upgrade() {
		if ( get_option( 'gwqsh_pro_crypto_initialized', false ) ) {
			return;
		}
		$version = get_option( 'gwqsh_db_version', '0' );
		if ( false === get_option( 'gwqsh_site_salt', false ) && version_compare( $version, '1.1.0', '>=' ) ) {
			add_option( 'gwqsh_legacy_pro_crypto', true, '', false );
		}
		add_option( 'gwqsh_pro_crypto_initialized', true, '', false );
	}

	/**
	 * Get dedicated plugin site salt, independent of WordPress auth keys.
	 *
	 * @return string
	 * @throws RuntimeException When the existing encryption key is unavailable.
	 */
	public static function get_site_salt() {
		$salt = get_option( 'gwqsh_site_salt', false );
		if ( false === $salt ) {
			global $wpdb;
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Pre-generation database check for existing user ciphertext.
			$existing         = $wpdb->get_var( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE (meta_key IN (%s, %s) AND (meta_value LIKE %s OR meta_value LIKE %s)) OR (meta_key IN (%s, %s) AND (meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s OR meta_value LIKE %s)) LIMIT 1", 'gwqsh_2fa_secret', 'gqs_2fa_secret', 'gwqsh1:%', 'gqs1:%', 'gwqsh_backup_codes', 'gqs_backup_codes', '%sha256:%', '%sha256-site:%', '%gwqsh1:%', '%gqs1:%' ) );
			$backups          = get_option( 'gwqsh_quarantine_metadata', array() );
			$encrypted_backup = false;
			foreach ( (array) $backups as $backup ) {
				if ( is_array( $backup ) && ! empty( $backup['encrypted'] ) ) {
					$encrypted_backup = true;
					break;
				}
			}
			if ( $wpdb->last_error || ( ( $existing || $encrypted_backup ) && ! get_option( 'gwqsh_legacy_pro_crypto', false ) ) ) {
				throw new RuntimeException( 'Restore the existing plugin encryption key from backup.' );
			}
			// Unique option insertion avoids concurrent requests replacing an encryption key.
			add_option( 'gwqsh_site_salt', bin2hex( random_bytes( 32 ) ), '', false );
			wp_cache_delete( 'gwqsh_site_salt', 'options' );
			$salt = get_option( 'gwqsh_site_salt', '' );
			if ( is_string( $salt ) && strlen( $salt ) >= 32 ) {
				delete_option( 'gwqsh_legacy_pro_crypto' );
			}
		}
		if ( ! is_string( $salt ) || strlen( $salt ) < 32 ) {
			throw new RuntimeException( 'Plugin encryption key is unavailable. Restore the existing key from backup.' );
		}
		return $salt;
	}

	/**
	 * Derive primary encryption key.
	 * Supports optional out-of-database GWQSH_ENCRYPTION_KEY constant in wp-config.php.
	 *
	 * @return string Binary 32-byte key.
	 */
	private static function key() {
		if ( defined( 'GWQSH_ENCRYPTION_KEY' ) && is_string( GWQSH_ENCRYPTION_KEY ) && strlen( GWQSH_ENCRYPTION_KEY ) >= 32 ) {
			return hash( 'sha256', GWQSH_ENCRYPTION_KEY, true );
		}
		return hash( 'sha256', self::get_site_salt(), true );
	}

	/**
	 * Derive database salt key for fallback decryption.
	 *
	 * @return string Binary 32-byte key.
	 */
	private static function fallback_key() {
		return hash( 'sha256', self::get_site_salt(), true );
	}

	/**
	 * Encrypt.
	 *
	 * @param mixed $plain Plain.
	 */
	public static function encrypt( $plain ) {
		if ( ! is_string( $plain ) || '' === $plain ) {
			return false;
		}
		try {
			if ( function_exists( 'sodium_crypto_secretbox' ) ) {
				$nonce = random_bytes( SODIUM_CRYPTO_SECRETBOX_NONCEBYTES );
				return 'gwqsh1:s:' . base64_encode( $nonce . sodium_crypto_secretbox( $plain, $nonce, self::key() ) );
			}
			if ( function_exists( 'openssl_encrypt' ) ) {
				$nonce  = random_bytes( 12 );
				$tag    = '';
				$cipher = openssl_encrypt( $plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $nonce, $tag );
				return false === $cipher ? false : 'gwqsh1:o:' . base64_encode( $nonce . $tag . $cipher );
			}
		} catch ( Throwable $e ) {
			return false;
		}
		return false;
	}

	/**
	 * Decrypt.
	 *
	 * @param mixed $payload Payload.
	 */
	public static function decrypt( $payload ) {
		if ( ! is_string( $payload ) || ! preg_match( '/^(?:gwqsh1|gqs1):([so]):(.+)$/', $payload, $matches ) ) {
			return false;
		}
		$raw = base64_decode( $matches[2], true );
		if ( false === $raw ) {
			return false;
		}

		$keys = array();
		try {
			$keys[] = self::key();
		} catch ( Throwable $error ) {
			// A legacy development payload can still be read without generating a replacement key.
			$keys = array();
		}
		try {
			$fallback = self::fallback_key();
			if ( ! in_array( $fallback, $keys, true ) ) {
				$keys[] = $fallback; }
		} catch ( Throwable $error ) {
			// A configured external key can still decrypt without a database fallback key.
			$fallback = false;
		}

		// Preserve ciphertext from the previous Pro build and its development-prefix aliases.
		$keys[] = hash( 'sha256', wp_salt( 'auth' ) . '|' . wp_salt( 'secure_auth' ) . '|' . wp_salt( 'logged_in' ), true );
		foreach ( array_unique( $keys ) as $k ) {
			if ( 's' === $matches[1] && function_exists( 'sodium_crypto_secretbox_open' ) && strlen( $raw ) > SODIUM_CRYPTO_SECRETBOX_NONCEBYTES ) {
				$n   = SODIUM_CRYPTO_SECRETBOX_NONCEBYTES;
				$res = sodium_crypto_secretbox_open( substr( $raw, $n ), substr( $raw, 0, $n ), $k );
				if ( false !== $res ) {
					return $res;
				}
			}
			if ( 'o' === $matches[1] && function_exists( 'openssl_decrypt' ) && strlen( $raw ) > 28 ) {
				$res = openssl_decrypt( substr( $raw, 28 ), 'aes-256-gcm', $k, OPENSSL_RAW_DATA, substr( $raw, 0, 12 ), substr( $raw, 12, 16 ) );
				if ( false !== $res ) {
					return $res;
				}
			}
		}
		return false;
	}
}
