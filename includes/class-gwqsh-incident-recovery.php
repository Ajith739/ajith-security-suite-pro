<?php
/**
 * Read-only incident overview, linking existing verified recovery services.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Investigation evidence is never promoted to a claim of a clean website. */
final class GWQSH_Incident_Recovery {
	/** Check both incident access and authority over the selected account.
	 *
	 * @param int $user_id Selected current-site user.
	 * @return true|WP_Error Authorization result.
	 */
	private static function account_permission( $user_id ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! get_userdata( $user_id ) || ! current_user_can( 'edit_user', $user_id ) || ! is_user_member_of_blog( $user_id, get_current_blog_id() ) ) {
			return new WP_Error( 'permission', 'Permission to manage this site account is required.' );
		}
		return true;
	}

	/** Bounded session/credential metadata; never expose tokens, verifiers or password hashes.
	 *
	 * @param int $user_id Selected current-site user.
	 * @return array|WP_Error Account investigation.
	 */
	public static function account_security( $user_id ) {
		$permission = self::account_permission( $user_id );
		if ( is_wp_error( $permission ) ) {
			return $permission;
		}
		$all      = WP_Session_Tokens::get_instance( $user_id )->get_all();
		$sessions = array();
		foreach ( array_slice( $all, 0, 50 ) as $session ) {
			$sessions[] = array(
				'login'   => (int) ( $session['login'] ?? 0 ),
				'expires' => (int) ( $session['expiration'] ?? 0 ),
				'device'  => sanitize_text_field( substr( $session['ua'] ?? '', 0, 160 ) ),
			);
		}
		$credentials = class_exists( 'WP_Application_Passwords' ) && current_user_can( 'list_app_passwords', $user_id ) ? WP_Application_Passwords::get_user_application_passwords( $user_id ) : array();
		$apps        = array();
		foreach ( array_slice( $credentials, 0, 50 ) as $credential ) {
			$apps[] = array(
				'uuid'      => $credential['uuid'],
				'name'      => sanitize_text_field( substr( $credential['name'], 0, 100 ) ),
				'created'   => (int) $credential['created'],
				'last_used' => (int) ( $credential['last_used'] ?? 0 ),
			);
		}
		return array(
			'user_id'                    => $user_id,
			'sessions'                   => $sessions,
			'session_count'              => count( $all ),
			'application_passwords'      => $apps,
			'application_password_count' => count( $credentials ),
			'display_limit'              => 50,
			'scope'                      => is_multisite() ? 'WordPress sessions and application passwords affect this account across the network.' : 'WordPress sessions and application passwords for this account.',
		);
	}

	/** Explicit containment, using the existing one-use verification boundary.
	 *
	 * @param int    $user_id Target account.
	 * @param string $kind Sessions or a selected application password.
	 * @param string $uuid Selected nonsecret application credential identifier.
	 * @param string $confirmation Target-bound confirmation phrase.
	 * @param string $proof Recent password/factor authorization.
	 * @return array|WP_Error Updated metadata or failure.
	 */
	public static function contain_account( $user_id, $kind, $uuid, $confirmation, $proof ) {
		$permission = self::account_permission( $user_id );
		if ( is_wp_error( $permission ) ) {
			return $permission;
		}
		if ( ! hash_equals( 'REVOKE ' . $user_id, $confirmation ) || ! in_array( $kind, array( 'sessions', 'application_password' ), true ) ) {
			return new WP_Error( 'confirmation', 'Enter the exact account confirmation phrase.' );
		}
		if ( 'application_password' === $kind && ( ! class_exists( 'WP_Application_Passwords' ) || ! wp_is_uuid( $uuid ) || ! current_user_can( 'delete_app_password', $user_id, $uuid ) ) ) {
			return new WP_Error( 'credential', 'The selected application credential cannot be revoked.' );
		}
		$verified = GWQSH_Enterprise_UI::consume_proof( $proof );
		if ( is_wp_error( $verified ) ) {
			return $verified;
		}
		if ( 'sessions' === $kind ) {
			$manager = WP_Session_Tokens::get_instance( $user_id );
			if ( get_current_user_id() === $user_id ) {
				if ( ! wp_get_session_token() ) {
					return new WP_Error( 'session', 'A current browser session is required to preserve administrator access.' );
				}
				$manager->destroy_others( wp_get_session_token() );
			} else {
				$manager->destroy_all();
			}
		} else {
			$result = WP_Application_Passwords::delete_application_password( $user_id, $uuid );
			if ( is_wp_error( $result ) || ! $result ) {
				return is_wp_error( $result ) ? $result : new WP_Error( 'storage', 'Application credential revocation could not be stored.' );
			}
		}
		GWQSH_Activity_Logger::log( 'Incident account containment', 'Account #' . $user_id . ': ' . $kind . ' revoked after explicit verification.', 'Security' );
		return self::account_security( $user_id );
	}

	/** Obtain current, site-scoped metadata without source bytes or account secrets. */
	public static function snapshot() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		global $wpdb;
		$files    = GWQSH_File_Integrity::get_summary();
		$database = GWQSH_Database_Scanner::status();
		$baseline = (array) get_option( GWQSH_Database_Context::BASELINE, array() );
		$accounts = get_users(
			array(
				'role'   => 'administrator',
				'number' => 100,
				'fields' => array( 'ID', 'user_login', 'user_registered' ),
			)
		);
		// phpcs:ignore WordPress.DB -- Fixed site-owned log identifier and constant predicate, no external SQL. Live incident evidence must bypass caches.
		$timeline = $wpdb->get_results( "SELECT event_time,event_name FROM {$wpdb->prefix}gwqsh_activity_log WHERE event_type='Security' ORDER BY id DESC LIMIT 20", ARRAY_A );
		return array(
			'generated_at'      => time(),
			'blog_id'           => get_current_blog_id(),
			'state'             => 'Verification incomplete',
			'files'             => $files,
			'database'          => $database,
			'database_baseline' => array(
				'configured'  => ! empty( $baseline['id'] ),
				'approved_at' => $baseline['approved_at'] ?? 0,
				'members'     => count( $baseline['members'] ?? array() ),
			),
			'accounts'          => $accounts,
			'accounts_limit'    => 100,
			'guardian'          => (array) get_option( 'gwqsh_guardian_status', array() ),
			'firewall'          => array(
				'enabled' => (bool) GWQSH_Firewall::settings()['enabled'],
				'policy'  => GWQSH_Enterprise_Config::get( 'waf' ),
			),
			'signatures'        => array(
				'configured'   => GWQSH_Signatures::available(),
				'version'      => GWQSH_Signatures::version(),
				'last_attempt' => get_option( 'gwqsh_signature_update_status', array() ),
			),
			'timeline'          => $timeline,
			'limitations'       => array(
				'This overview does not certify recovery or remove database records.',
				'Administrator membership, external scripts and redirects require context and review; they are not automatically malware.',
				'Database inspection excludes credential records, gwqsh_ options, custom tables and network sitemeta; values beyond 64 KiB are partial.',
				'Finding and omission locators are capped at 100 each; totals may exceed displayed records. At most 100 administrators and 20 recent security events are shown.',
				'Hosting compromise requires independent verification and potentially a rebuild in a trusted environment.',
			),
		);
	}
}
