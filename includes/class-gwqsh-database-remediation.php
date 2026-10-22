<?php
/** Explicit, reversible post-content repair; never execute SQL supplied by a caller.
 *
 * @package GracewellSecuritySuitePro
 */
defined( 'ABSPATH' ) || exit;

/** Bounded reviewed replacements with encrypted evidence and byte-exact stale checks. */
final class GWQSH_Database_Remediation {
	/** Authorize the site and exact post, excluding revisions and non-content records.
	 * @param int $id Post ID.
	 * @return array|WP_Error Current bounded row.
	 */
	private static function row( $id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! current_user_can( 'edit_post', $id ) ) {
			return new WP_Error( 'permission', 'Permission to manage security and edit this post is required.' );
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB -- Fixed site-owned table, prepared exact ID and bounded value; stale checks must bypass caches.
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT ID,post_type,OCTET_LENGTH(post_content) AS bytes,LEFT(CAST(post_content AS BINARY),65536) AS content FROM {$wpdb->posts} WHERE ID=%d", $id ), ARRAY_A );
		if ( $wpdb->last_error || ! $row || ! in_array( $row['post_type'], array( 'post', 'page' ), true ) || (int) $row['bytes'] > 65536 || is_serialized( $row['content'] ) ) {
			return new WP_Error( 'record', 'Only complete, nonserialized post/page content up to 64 KiB can be repaired here.' );
		}
		return $row;
	}

	/** Session-bound opaque review ticket; the diff is HTML-escaped by WordPress.
	 * @param string $job_id Completed reviewed investigation.
	 * @param int $id Exact post ID.
	 * @param string $replacement Administrator-reviewed content.
	 * @return array|WP_Error Review metadata and escaped diff.
	 */
	public static function preview( $job_id, $id, $replacement ) {
		$row = self::row( $id );
		if ( is_wp_error( $row ) ) {
			return $row;
		}
		if ( ! is_string( $replacement ) || strlen( $replacement ) > 65536 || wp_check_invalid_utf8( $replacement, true ) !== $replacement || false !== strpos( $replacement, "\0" ) || is_serialized( $replacement ) || $replacement === $row['content'] ) {
			return new WP_Error( 'replacement', 'Provide different, nonserialized replacement content up to 64 KiB.' );
		}
		if ( ! current_user_can( 'unfiltered_html' ) && wp_kses_post( $replacement ) !== $replacement ) {
			return new WP_Error( 'content_permission', 'The replacement includes markup this account cannot publish.' );
		}
		$state = GWQSH_Database_Scanner::status();
		$found = false;
		if ( ! is_wp_error( $state ) && ( $state['id'] ?? '' ) === $job_id && ( $state['blog_id'] ?? 0 ) === get_current_blog_id() && 'complete' === ( $state['state'] ?? '' ) ) {
			foreach ( $state['findings'] ?? array() as $finding ) {
				if ( 'posts' === $finding['source'] && (int) $finding['id'] === (int) $id && empty( $finding['partial'] ) && hash_equals( $finding['sample_sha256'], hash( 'sha256', $row['content'] ) ) ) {
					$found = true;
				}
			}
		}
		if ( ! $found ) {
			return new WP_Error( 'finding', 'A completed current-site finding matching the exact current content is required.' );
		}
		$ticket = bin2hex( random_bytes( 16 ) );
		$record = array( 'schema' => 1, 'blog_id' => get_current_blog_id(), 'post_id' => (int) $id, 'post_type' => $row['post_type'], 'before' => $row['content'], 'after' => $replacement, 'user_id' => get_current_user_id(), 'session' => hash( 'sha256', wp_get_session_token() ), 'created_at' => time() );
		$cipher = GWQSH_Crypto::encrypt( wp_json_encode( $record ) );
		if ( ! $cipher || ! GWQSH_Enterprise_Store::put( 'db-repair-review', $ticket, array( 'ciphertext' => $cipher ), 600 ) ) {
			return new WP_Error( 'storage', 'The encrypted review could not be saved.' );
		}
		// Whole-value escaped diff is linear in bytes; avoid quadratic word/line diff work on hostile records.
		$diff = '<div class="gwqsh-record-diff"><del><pre>' . esc_html( $row['content'] ) . '</pre></del><ins><pre>' . esc_html( $replacement ) . '</pre></ins></div>';
		return array( 'ticket' => $ticket, 'post_id' => (int) $id, 'expires_in' => 600, 'confirmation' => 'REPAIR ' . $id, 'diff_html' => $diff, 'before_sha256' => hash( 'sha256', $row['content'] ), 'after_sha256' => hash( 'sha256', $replacement ), 'replacement_findings' => GWQSH_Database_Scanner::analyze( $replacement, 'posts', $row['post_type'] ) );
	}

	/** Read authenticated bounded backup payloads, never deserialize arbitrary PHP.
	 * @param string $cipher Authenticated ciphertext.
	 * @return array|WP_Error Valid record.
	 */
	private static function decode( $cipher ) {
		$plain = is_string( $cipher ) && strlen( $cipher ) < 400000 ? GWQSH_Crypto::decrypt( $cipher ) : false;
		$data = is_string( $plain ) ? json_decode( $plain, true, 8 ) : null;
		if ( ! is_array( $data ) || 1 !== ( $data['schema'] ?? 0 ) || get_current_blog_id() !== ( $data['blog_id'] ?? 0 ) || ! is_int( $data['post_id'] ?? null ) || ! is_string( $data['before'] ?? null ) || ! is_string( $data['after'] ?? null ) || strlen( $data['before'] ) > 65536 || strlen( $data['after'] ) > 65536 ) {
			return new WP_Error( 'backup', 'Recovery data is unavailable, altered or belongs to another site.' );
		}
		return $data;
	}

	/** Apply only after review, recent factor proof and explicit target confirmation.
	 * @param string $ticket Opaque review ticket.
	 * @param string $confirmation Target-bound phrase.
	 * @param string $proof Current-session one-use proof.
	 * @return array|WP_Error Result.
	 */
	public static function apply( $ticket, $confirmation, $proof ) {
		$verified = GWQSH_Enterprise_UI::consume_proof( $proof );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		if ( ! is_string( $ticket ) || ! preg_match( '/^[a-f0-9]{32}$/D', $ticket ) ) {
			return new WP_Error( 'ticket', 'Invalid review ticket.' );
		}
		$review = GWQSH_Enterprise_Store::get( 'db-repair-review', $ticket );
		$data = self::decode( $review['ciphertext'] ?? '' );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		if ( $data['user_id'] !== get_current_user_id() || ! hash_equals( $data['session'], hash( 'sha256', wp_get_session_token() ) ) || $confirmation !== 'REPAIR ' . $data['post_id'] ) {
			return new WP_Error( 'confirmation', 'Review and confirmation must belong to this administrator session and post.' );
		}
		return self::mutate( $ticket, $data, $review['ciphertext'], false );
	}

	/** Restore a verified encrypted original only if the repaired bytes remain unchanged.
	 * @param string $ticket Backup identifier.
	 * @param string $confirmation Target-bound phrase.
	 * @param string $proof Current-session one-use proof.
	 * @return array|WP_Error Result.
	 */
	public static function rollback( $ticket, $confirmation, $proof ) {
		$verified = GWQSH_Enterprise_UI::consume_proof( $proof );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		if ( ! is_string( $ticket ) || ! preg_match( '/^[a-f0-9]{32}$/D', $ticket ) ) {
			return new WP_Error( 'ticket', 'Invalid backup identifier.' );
		}
		$dir = GWQSH_Quarantine_Manager::ensure_quarantine_dir();
		if ( is_wp_error( $dir ) ) {
			return $dir;
		}
		$file = $dir . '/db-repair-' . $ticket . '.enc';
		if ( ! GWQSH_Security_Runtime::safe_path( $file, $dir ) || ! is_file( $file ) || filesize( $file ) > 400000 ) {
			return new WP_Error( 'backup', 'The private recovery file is unavailable.' );
		}
		$cipher = file_get_contents( $file );
		$data = self::decode( $cipher );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		if ( $confirmation !== 'RESTORE ' . $data['post_id'] ) {
			return new WP_Error( 'confirmation', 'Confirm the exact post to restore.' );
		}
		return self::mutate( $ticket, $data, $cipher, true );
	}

	/** Serialize plugin writers and use a single byte-exact SQL compare-and-swap.
	 * @param string $ticket Backup identifier.
	 * @param array $data Authenticated original and replacement.
	 * @param string $cipher Encrypted recovery payload.
	 * @param bool $rollback Restore original bytes.
	 * @return array|WP_Error Outcome.
	 */
	private static function mutate( $ticket, array $data, $cipher, $rollback ) {
		return GWQSH_Quarantine_Manager::synchronize( static function () use ( $ticket, $data, $cipher, $rollback ) {
			$row = self::row( $data['post_id'] );
			if ( is_wp_error( $row ) ) {
				return $row;
			}
			$before = $rollback ? $data['after'] : $data['before'];
			$after = $rollback ? $data['before'] : $data['after'];
			if ( $row['content'] !== $before || $row['post_type'] !== $data['post_type'] ) {
				return new WP_Error( 'stale', 'Content or post type changed after review. No data was modified.' );
			}
			$file = GWQSH_Guardian::state_dir() . '/db-repair-' . $ticket . '.enc';
			if ( ! $rollback ) {
				if ( file_exists( $file ) || is_link( $file ) || ! GWQSH_Security_Runtime::atomic_write( $file, $cipher ) || ! chmod( $file, 0600 ) || hash_file( 'sha256', $file ) !== hash( 'sha256', $cipher ) || is_wp_error( self::decode( file_get_contents( $file ) ) ) ) {
					return new WP_Error( 'backup', 'Verified private recovery data could not be created; content is unchanged.' );
				}
			}
			global $wpdb;
			// phpcs:ignore WordPress.DB -- Fixed current-site table/columns and prepared values. Exact byte CAS prevents overwriting concurrent editor changes; only nonserialized content is supported.
			$changed = $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->posts} SET post_content=%s WHERE ID=%d AND post_type=%s AND BINARY post_content=BINARY %s", $after, $data['post_id'], $data['post_type'], $before ) );
			if ( 1 !== $changed ) {
				return new WP_Error( 'stale', 'The exact replacement was not applied. Recovery evidence was retained.' );
			}
			clean_post_cache( $data['post_id'] );
			$check = self::row( $data['post_id'] );
			if ( is_wp_error( $check ) || $check['content'] !== $after ) {
				return new WP_Error( 'verification', 'The database write could not be verified. Retain the recovery identifier: ' . $ticket );
			}
			GWQSH_Activity_Logger::log( $rollback ? 'Database repair rolled back' : 'Database content repaired', 'Post #' . $data['post_id'] . '; evidence ' . $ticket . '; before ' . hash( 'sha256', $before ) . '; after ' . hash( 'sha256', $after ), 'Security' );
			return array( 'post_id' => $data['post_id'], 'backup_id' => $ticket, 'state' => $rollback ? 'restored' : 'repaired', 'rescan' => GWQSH_Database_Scanner::analyze( $after, 'posts', $data['post_type'] ), 'verification' => 'Exact content verified. A full database and file investigation is still required.' );
		} );
	}

	/* ─── Options Table Remediation ─────────────────────────────────────── */

	/** Authorize and read a bounded option value for remediation.
	 * Critical options (siteurl, home, active_plugins, etc.) cannot be bulk-deleted.
	 *
	 * @param int $option_id Option table primary key.
	 * @return array|WP_Error Current bounded row.
	 */
	private static function option_row( $option_id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Permission to manage security is required.' );
		}
		global $wpdb;
		// phpcs:ignore WordPress.DB -- Fixed site-owned table, prepared exact ID and bounded value; stale checks must bypass caches.
		$row = $wpdb->get_row( $wpdb->prepare(
			"SELECT option_id, option_name, OCTET_LENGTH(option_value) AS bytes, LEFT(CAST(option_value AS BINARY), 65536) AS content FROM {$wpdb->options} WHERE option_id = %d",
			$option_id
		), ARRAY_A );
		if ( $wpdb->last_error || ! $row ) {
			return new WP_Error( 'record', 'Option record not found.' );
		}
		// Protect critical WordPress options from remediation — these should be fixed manually.
		$protected = array( 'siteurl', 'home', 'blogname', 'blogdescription', 'admin_email',
			'active_plugins', 'template', 'stylesheet', 'db_version', 'initial_db_version' );
		if ( in_array( $row['option_name'], $protected, true ) ) {
			return new WP_Error( 'protected', 'This critical WordPress option cannot be remediated through automated cleanup. Edit it manually.' );
		}
		// Exclude plugin's own options.
		if ( 0 === strpos( $row['option_name'], 'gwqsh_' ) ) {
			return new WP_Error( 'excluded', 'Plugin-owned options are not eligible for database remediation.' );
		}
		if ( (int) $row['bytes'] > 65536 ) {
			return new WP_Error( 'size', 'Option value exceeds the 64 KiB remediation limit.' );
		}
		return $row;
	}

	/** Preview an option value replacement with an escaped diff.
	 *
	 * @param string $job_id Completed database scan job ID.
	 * @param int    $option_id Option primary key.
	 * @param string $replacement Administrator-reviewed replacement value.
	 * @return array|WP_Error Review metadata and escaped diff.
	 */
	public static function preview_option( $job_id, $option_id, $replacement ) {
		$row = self::option_row( $option_id );
		if ( is_wp_error( $row ) ) {
			return $row;
		}
		if ( ! is_string( $replacement ) || strlen( $replacement ) > 65536 || false !== strpos( $replacement, "\0" ) || $replacement === $row['content'] ) {
			return new WP_Error( 'replacement', 'Provide different replacement content up to 64 KiB.' );
		}
		// Validate serialized data round-trips safely.
		if ( is_serialized( $row['content'] ) ) {
			$unserialized = maybe_unserialize( $replacement );
			if ( is_string( $unserialized ) && $unserialized === $replacement && is_serialized( $row['content'] ) && ! is_serialized( $replacement ) ) {
				return new WP_Error( 'serialization', 'The original value is serialized. The replacement must also be valid serialized data or the option may break.' );
			}
		}
		// Verify finding exists in current scan.
		$state = GWQSH_Database_Scanner::status();
		$found = false;
		if ( ! is_wp_error( $state ) && ( $state['id'] ?? '' ) === $job_id && ( $state['blog_id'] ?? 0 ) === get_current_blog_id() && 'complete' === ( $state['state'] ?? '' ) ) {
			foreach ( $state['findings'] ?? array() as $finding ) {
				if ( 'options' === $finding['source'] && (int) $finding['id'] === (int) $option_id && empty( $finding['partial'] ) && hash_equals( $finding['sample_sha256'], hash( 'sha256', $row['content'] ) ) ) {
					$found = true;
				}
			}
		}
		if ( ! $found ) {
			return new WP_Error( 'finding', 'A completed current-site finding matching the exact current content is required.' );
		}
		$ticket = bin2hex( random_bytes( 16 ) );
		$record = array(
			'schema'      => 2,
			'type'        => 'option',
			'blog_id'     => get_current_blog_id(),
			'option_id'   => (int) $option_id,
			'option_name' => $row['option_name'],
			'before'      => $row['content'],
			'after'       => $replacement,
			'user_id'     => get_current_user_id(),
			'session'     => hash( 'sha256', wp_get_session_token() ),
			'created_at'  => time(),
		);
		$cipher = GWQSH_Crypto::encrypt( wp_json_encode( $record ) );
		if ( ! $cipher || ! GWQSH_Enterprise_Store::put( 'db-repair-review', $ticket, array( 'ciphertext' => $cipher ), 600 ) ) {
			return new WP_Error( 'storage', 'The encrypted review could not be saved.' );
		}
		$diff = '<div class="gwqsh-record-diff"><del><pre>' . esc_html( $row['content'] ) . '</pre></del><ins><pre>' . esc_html( $replacement ) . '</pre></ins></div>';
		return array(
			'ticket'               => $ticket,
			'option_id'            => (int) $option_id,
			'option_name'          => $row['option_name'],
			'expires_in'           => 600,
			'confirmation'         => 'REPAIR-OPTION ' . $option_id,
			'diff_html'            => $diff,
			'before_sha256'        => hash( 'sha256', $row['content'] ),
			'after_sha256'         => hash( 'sha256', $replacement ),
			'replacement_findings' => GWQSH_Database_Scanner::analyze( $replacement, 'options', $row['option_name'] ),
		);
	}

	/** Apply a reviewed option repair with encrypted backup and stale-content CAS.
	 *
	 * @param string $ticket Opaque review ticket.
	 * @param string $confirmation Target-bound phrase.
	 * @param string $proof Current-session one-use proof.
	 * @return array|WP_Error Result.
	 */
	public static function apply_option( $ticket, $confirmation, $proof ) {
		$verified = GWQSH_Enterprise_UI::consume_proof( $proof );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		if ( ! is_string( $ticket ) || ! preg_match( '/^[a-f0-9]{32}$/D', $ticket ) ) {
			return new WP_Error( 'ticket', 'Invalid review ticket.' );
		}
		$review = GWQSH_Enterprise_Store::get( 'db-repair-review', $ticket );
		$data   = self::decode_option( $review['ciphertext'] ?? '' );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		if ( $data['user_id'] !== get_current_user_id() || ! hash_equals( $data['session'], hash( 'sha256', wp_get_session_token() ) ) || $confirmation !== 'REPAIR-OPTION ' . $data['option_id'] ) {
			return new WP_Error( 'confirmation', 'Review and confirmation must belong to this administrator session and option.' );
		}
		return self::mutate_option( $ticket, $data, $review['ciphertext'], false );
	}

	/** Restore a verified encrypted original option value.
	 *
	 * @param string $ticket Backup identifier.
	 * @param string $confirmation Target-bound phrase.
	 * @param string $proof Current-session one-use proof.
	 * @return array|WP_Error Result.
	 */
	public static function rollback_option( $ticket, $confirmation, $proof ) {
		$verified = GWQSH_Enterprise_UI::consume_proof( $proof );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		if ( ! is_string( $ticket ) || ! preg_match( '/^[a-f0-9]{32}$/D', $ticket ) ) {
			return new WP_Error( 'ticket', 'Invalid backup identifier.' );
		}
		$dir = GWQSH_Quarantine_Manager::ensure_quarantine_dir();
		if ( is_wp_error( $dir ) ) {
			return $dir;
		}
		$file = $dir . '/db-option-repair-' . $ticket . '.enc';
		if ( ! GWQSH_Security_Runtime::safe_path( $file, $dir ) || ! is_file( $file ) || filesize( $file ) > 400000 ) {
			return new WP_Error( 'backup', 'The private recovery file is unavailable.' );
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Validated local encrypted recovery file, bounded size.
		$cipher = file_get_contents( $file );
		$data   = self::decode_option( $cipher );
		if ( is_wp_error( $data ) ) {
			return $data;
		}
		if ( $confirmation !== 'RESTORE-OPTION ' . $data['option_id'] ) {
			return new WP_Error( 'confirmation', 'Confirm the exact option to restore.' );
		}
		return self::mutate_option( $ticket, $data, $cipher, true );
	}

	/** Decode an encrypted option remediation record.
	 *
	 * @param string $cipher Authenticated ciphertext.
	 * @return array|WP_Error Valid record.
	 */
	private static function decode_option( $cipher ) {
		$plain = is_string( $cipher ) && strlen( $cipher ) < 400000 ? GWQSH_Crypto::decrypt( $cipher ) : false;
		$data  = is_string( $plain ) ? json_decode( $plain, true, 8 ) : null;
		if ( ! is_array( $data ) || 2 !== ( $data['schema'] ?? 0 ) || 'option' !== ( $data['type'] ?? '' ) || get_current_blog_id() !== ( $data['blog_id'] ?? 0 ) || ! is_int( $data['option_id'] ?? null ) || ! is_string( $data['before'] ?? null ) || ! is_string( $data['after'] ?? null ) || strlen( $data['before'] ) > 65536 || strlen( $data['after'] ) > 65536 ) {
			return new WP_Error( 'backup', 'Recovery data is unavailable, altered or belongs to another site.' );
		}
		return $data;
	}

	/** Execute the option mutation with CAS protection and audit.
	 *
	 * @param string $ticket Backup identifier.
	 * @param array  $data Authenticated original and replacement.
	 * @param string $cipher Encrypted recovery payload.
	 * @param bool   $rollback Restore original bytes.
	 * @return array|WP_Error Outcome.
	 */
	private static function mutate_option( $ticket, array $data, $cipher, $rollback ) {
		return GWQSH_Quarantine_Manager::synchronize( static function () use ( $ticket, $data, $cipher, $rollback ) {
			$row = self::option_row( $data['option_id'] );
			if ( is_wp_error( $row ) ) {
				return $row;
			}
			$before = $rollback ? $data['after'] : $data['before'];
			$after  = $rollback ? $data['before'] : $data['after'];
			if ( $row['content'] !== $before || $row['option_name'] !== $data['option_name'] ) {
				return new WP_Error( 'stale', 'Content or option name changed after review. No data was modified.' );
			}
			$file = GWQSH_Guardian::state_dir() . '/db-option-repair-' . $ticket . '.enc';
			if ( ! $rollback ) {
				if ( file_exists( $file ) || is_link( $file ) || ! GWQSH_Security_Runtime::atomic_write( $file, $cipher ) || ! chmod( $file, 0600 ) || hash_file( 'sha256', $file ) !== hash( 'sha256', $cipher ) || is_wp_error( self::decode_option( file_get_contents( $file ) ) ) ) {
					return new WP_Error( 'backup', 'Verified private recovery data could not be created; content is unchanged.' );
				}
			}
			global $wpdb;
			// phpcs:ignore WordPress.DB -- Fixed current-site table/columns and prepared values. Exact byte CAS prevents overwriting concurrent changes.
			$changed = $wpdb->query( $wpdb->prepare(
				"UPDATE {$wpdb->options} SET option_value = %s WHERE option_id = %d AND option_name = %s AND BINARY option_value = BINARY %s",
				$after,
				$data['option_id'],
				$data['option_name'],
				$before
			) );
			if ( 1 !== $changed ) {
				return new WP_Error( 'stale', 'The exact replacement was not applied. Recovery evidence was retained.' );
			}
			wp_cache_delete( $data['option_name'], 'options' );
			wp_cache_delete( 'alloptions', 'options' );
			// Verify the write.
			$check = self::option_row( $data['option_id'] );
			if ( is_wp_error( $check ) || $check['content'] !== $after ) {
				return new WP_Error( 'verification', 'The database write could not be verified. Retain the recovery identifier: ' . $ticket );
			}
			GWQSH_Activity_Logger::log(
				$rollback ? 'Option repair rolled back' : 'Option content repaired',
				'Option #' . $data['option_id'] . ' (' . $data['option_name'] . '); evidence ' . $ticket . '; before ' . hash( 'sha256', $before ) . '; after ' . hash( 'sha256', $after ),
				'Security'
			);
			return array(
				'option_id'    => $data['option_id'],
				'option_name'  => $data['option_name'],
				'backup_id'    => $ticket,
				'state'        => $rollback ? 'restored' : 'repaired',
				'rescan'       => GWQSH_Database_Scanner::analyze( $after, 'options', $data['option_name'] ),
				'verification' => 'Exact content verified. A full database and file investigation is still required.',
			);
		} );
	}
}
