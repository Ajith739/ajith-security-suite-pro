<?php
/**
 * AJAX controller for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Ajax implementation.
 */
final class GWQSH_Ajax {
	/** Decode bounded structured configuration without lossy text sanitization.
	 * All callers subsequently validate the decoded fields against their existing schema.
	 *
	 * @param array  $request Centrally shape-checked, unslashed request.
	 * @param string $key Fixed controller field name.
	 * @param int    $limit Maximum raw JSON bytes.
	 * @return array|null Parsed structure or invalid input.
	 */
	private static function json_input( array $request, $key, $limit = 20000 ) {
		$raw = isset( $request[ $key ] ) && is_string( $request[ $key ] ) ? $request[ $key ] : '';
		if ( strlen( $raw ) > $limit ) {
			return null;
		}
		$value = json_decode( $raw, true, 32 );
		return is_array( $value ) && JSON_ERROR_NONE === json_last_error() ? $value : null;
	}
	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'wp_ajax_gwqsh_action', array( __CLASS__, 'handle_request' ) );
	}
	/**
	 * Handle request.
	 */
	public static function handle_request() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Shape validation only; the central nonce/capability checks immediately below authorize dispatch.
		foreach ( $_POST as $value ) {
			if ( ! is_scalar( $value ) ) {
				wp_send_json_error( array( 'message' => 'Invalid request format.' ), 400 ); }
		}
		if ( false === check_ajax_referer( 'gwqsh_nonce', 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => 'Your session expired. Reload the page and try again.' ), 403 ); }
		$subaction = isset( $_POST['subaction'] ) ? sanitize_key( wp_unslash( $_POST['subaction'] ) ) : '';

		if ( ! current_user_can( GWQSH_Admin::management_capability() ) && ! ( current_user_can( 'read' ) && in_array( $subaction, GWQSH_Two_Factor::self_service_actions(), true ) ) ) {
			wp_send_json_error( array( 'message' => __( 'Permission denied.', 'gracewell-security-suite-pro' ) ), 403 );
		}
		$request = wp_unslash( $_POST );

		if ( in_array( $subaction, array( 'passkey_list', 'passkey_create_options', 'passkey_create_verify', 'passkey_rename', 'passkey_remove', 'recovery_data', 'recovery_setup_send', 'recovery_setup_verify', 'recovery_remove' ), true ) ) {
			$result = strpos( $subaction, 'passkey_' ) === 0 ? GWQSH_Passkeys::management( $subaction, wp_unslash( $_POST ) ) : GWQSH_Recovery::management( $subaction, wp_unslash( $_POST ) );
			if ( is_wp_error( $result ) ) {
				wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
			wp_send_json_success( $result );
		}
		$high_risk = array( 'restore_file', 'restore_trusted', 'restore_quarantine', 'bulk_restore_quarantine', 'delete_quarantine', 'bulk_delete_quarantine', 'clear_all_quarantine', 'accept_current', 'rebuild_baseline', 'config_import' );
		if ( in_array( $subaction, $high_risk, true ) ) {
			$verification = GWQSH_Enterprise_UI::consume_proof( sanitize_text_field( wp_unslash( $_POST['operation_token'] ?? '' ) ) );
			if ( is_wp_error( $verification ) ) {
				wp_send_json_error( array( 'message' => $verification->get_error_message() ), 403 ); }
		}
		if ( 'enterprise_wizard' === $subaction ) {
			$input  = self::json_input( $request, 'settings' );
			$result = is_array( $input ) ? GWQSH_Setup_Wizard::save( $input ) : new WP_Error( 'wizard', 'Invalid setup checkpoint.' );
			if ( is_wp_error( $result ) ) {
				wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
			wp_send_json_success( $result );
		}
		if ( 'enterprise_authorize' === $subaction ) {
			try {
				$result = GWQSH_Enterprise_UI::authorize( $request['password'] ?? '', sanitize_text_field( $request['code'] ?? '' ) ); } catch ( Throwable $error ) {
				$result = new WP_Error( 'verification', 'Unable to verify this operation.' ); }
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( array( 'token' => $result ) );
		}
		if ( 'enterprise_execute' === $subaction ) {
			if ( ! empty( $request['settings'] ) && null === self::json_input( $request, 'settings' ) ) {
				wp_send_json_error( array( 'message' => 'Configuration payload too large.' ), 400 ); }
			$result = GWQSH_Enterprise_UI::execute( wp_unslash( $_POST ) );
			if ( is_wp_error( $result ) ) {
				wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
			wp_send_json_success( $result );
		}
		switch ( $subaction ) {
			case 'security_report':
				$result = GWQSH_Security_Report::collect( $request );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
				}
				wp_send_json_success( $result );
				break;
			case 'recovery_account_security':
			case 'recovery_revoke_sessions':
			case 'recovery_revoke_application_password':
				$user_id = absint( wp_unslash( $_POST['user_id'] ?? '' ) );
				$result  = 'recovery_account_security' === $subaction ? GWQSH_Incident_Recovery::account_security( $user_id ) : GWQSH_Incident_Recovery::contain_account(
					$user_id,
					'recovery_revoke_sessions' === $subaction ? 'sessions' : 'application_password',
					sanitize_text_field( wp_unslash( $_POST['uuid'] ?? '' ) ),
					sanitize_text_field( wp_unslash( $_POST['confirmed'] ?? '' ) ),
					sanitize_text_field( wp_unslash( $_POST['operation_token'] ?? '' ) )
				);
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
				}
				wp_send_json_success( $result );
				break;
			case 'database_baseline_rollback':
				$result = GWQSH_Database_Context::rollback( sanitize_text_field( wp_unslash( $_POST['confirmed'] ?? '' ) ), sanitize_text_field( wp_unslash( $_POST['operation_token'] ?? '' ) ) );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
				}
				wp_send_json_success( $result );
				break;
			case 'database_baseline_approve':
				$result = GWQSH_Database_Context::approve( sanitize_text_field( wp_unslash( $_POST['job_id'] ?? '' ) ), sanitize_text_field( wp_unslash( $_POST['confirmed'] ?? '' ) ), sanitize_text_field( wp_unslash( $_POST['operation_token'] ?? '' ) ) );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
				}
				wp_send_json_success( $result );
				break;
			case 'recovery_center_status':
				wp_send_json_success( GWQSH_Incident_Recovery::snapshot() );
				break;
			case 'database_scan_status':
			case 'database_scan_start':
			case 'database_scan_continue':
			case 'database_scan_cancel':
				if ( 'database_scan_start' === $subaction ) {
					$result = GWQSH_Database_Scanner::start();
				} elseif ( 'database_scan_status' === $subaction ) {
					$result = GWQSH_Database_Scanner::status();
				} elseif ( 'database_scan_cancel' === $subaction ) {
					$result = GWQSH_Database_Scanner::cancel( sanitize_text_field( wp_unslash( $_POST['job_id'] ?? '' ) ) );
				} else {
					$result = GWQSH_Database_Scanner::step( sanitize_text_field( wp_unslash( $_POST['job_id'] ?? '' ) ) );
				}
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
				}
				wp_send_json_success( $result );
				break;
			case 'config_export':
				wp_send_json_success( GWQSH_Customization::export() );
				break;
			case 'config_save':
				$input  = self::json_input( $request, 'settings' );
				$result = is_array( $input ) ? GWQSH_Customization::save( sanitize_key( $_POST['section'] ?? '' ), $input ) : new WP_Error( 'format', 'Invalid settings.' );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success(
					array(
						'values'      => $result,
						'preferences' => GWQSH_Settings::get_all(),
					)
				);
				break;
			case 'config_reset':
				$section = sanitize_key( $_POST['section'] ?? '' );
				if ( 'all' === $section ) {
					$defaults = GWQSH_Settings::get_defaults();
					if ( ! GWQSH_Settings::can_manage_updates() ) {
						unset( $defaults['autoupdate'] );
					} GWQSH_Settings::update_all( $defaults );
					update_option(
						'gwqsh_two_factor_settings',
						array(
							'require_admin'     => false,
							'allow_roles'       => true,
							'remember_device'   => true,
							'allow_admin_reset' => true,
							'enforce_roles'     => false,
							'required_roles'    => array(),
						),
						false
					); }
				$sections = 'all' === $section ? array_merge( array_keys( GWQSH_Customization::schema() ), array( 'scan_schedule' ) ) : array( $section );
				foreach ( $sections as $key ) {
					$result = GWQSH_Customization::reset( $key );
					if ( is_wp_error( $result ) ) {
						wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				}
				wp_send_json_success( GWQSH_Customization::export() );
				break;
			case 'config_import':
				$input  = self::json_input( $request, 'payload', 1048576 );
				$result = is_array( $input ) ? GWQSH_Customization::import( $input ) : new WP_Error( 'format', 'Invalid configuration export.' );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( $result );
				break;
			case 'ip_block_data':
				wp_send_json_success( GWQSH_IP_Blocks::history( absint( $_POST['page_num'] ?? 1 ) ) );
				break;
			case 'ip_block_save':
				$result = GWQSH_IP_Blocks::save( filter_var( wp_unslash( $_POST['ip'] ?? '' ), FILTER_VALIDATE_IP ), sanitize_text_field( wp_unslash( $_POST['reason'] ?? '' ) ), filter_var( wp_unslash( $_POST['minutes'] ?? '0' ), FILTER_VALIDATE_INT ) );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( GWQSH_IP_Blocks::history() );
				break;
			case 'ip_block_remove':
				$result = GWQSH_IP_Blocks::remove( filter_var( wp_unslash( $_POST['ip'] ?? '' ), FILTER_VALIDATE_IP ) );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( GWQSH_IP_Blocks::history() );
				break;
			case 'scan_schedule_data':
				wp_send_json_success( GWQSH_Scheduler::data() );
				break;
			case 'scan_schedule_save':
				$input  = self::json_input( $request, 'settings' );
				$result = is_array( $input ) ? GWQSH_Scheduler::save( $input ) : new WP_Error( 'invalid_input', 'Invalid schedule.' );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( GWQSH_Scheduler::data() );
				break;
			case 'scan_schedule_now':
				if ( GWQSH_Scan_Engine::load( 'gwqsh_scan_progress' ) || wp_next_scheduled( 'gwqsh_run_integrity_now' ) ) {
					wp_send_json_error( array( 'message' => 'A scan is already running or queued.' ), 409 ); }
				$result = wp_schedule_single_event( time() + 1, 'gwqsh_run_integrity_now', array(), true );
				if ( true !== $result ) {
					wp_send_json_error( array( 'message' => 'Unable to queue the scan.' ), 500 ); }
				wp_send_json_success( array( 'message' => 'Scan queued for background processing.' ) );
				break;
			case 'get_firewall_data':
				wp_send_json_success( GWQSH_Firewall::data( isset( $_POST['page_num'] ) ? absint( $_POST['page_num'] ) : 1 ) );
				break;
			case 'save_firewall_settings':
				$result = GWQSH_Firewall::save( wp_unslash( $_POST ) );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( GWQSH_Firewall::data() );
				break;
			case 'save_2fa_settings':
				self::save_2fa_settings();
				break;
			case 'disable_own_2fa':
				self::disable_own_2fa();
				break;
			case 'require_user_2fa':
				self::require_user_2fa();
				break;
			// Dashboard.
			case 'get_dashboard_data':
				self::get_dashboard_data();
				break;

			// Login Protection.
			case 'get_login_data':
				self::get_login_data();
				break;
			case 'toggle_login_protection':
				self::toggle_login_protection();
				break;
			case 'save_login_access':
				self::save_login_access();
				break;
			case 'save_login_settings':
				self::save_login_settings();
				break;
			case 'unlock_ip':
				self::unlock_ip();
				break;
			case 'add_allow_ip':
				self::add_allow_ip();
				break;
			case 'remove_allow_ip':
				self::remove_allow_ip();
				break;
			case 'clear_allowlist':
				self::clear_allowlist();
				break;
			case 'save_login_slug':
				self::save_login_slug();
				break;

			// Two-Factor.
			case 'get_user_2fa_devices':
				self::get_user_2fa_devices();
				break;
			case 'get_2fa_data':
				self::get_2fa_data();
				break;
			case 'generate_2fa_secret':
				self::generate_2fa_secret();
				break;
			case 'generate_backup_codes':
				self::generate_backup_codes();
				break;
			case 'confirm_2fa_secret':
				self::confirm_2fa_secret();
				break;
			case 'enable_user_2fa':
				self::enable_user_2fa();
				break;
			case 'reset_user_2fa':
				self::reset_user_2fa();
				break;
			case 'remove_trusted_device':
				self::remove_trusted_device();
				break;

			// File Integrity.
			case 'get_scan_data':
				self::get_scan_data();
				break;
			case 'run_scan':
				self::run_scan();
				break;
			case 'restore_file':
				self::restore_file();
				break;
			case 'quarantine_file':
				self::quarantine_file();
				break;
			case 'quarantine_finding':
				self::quarantine_finding();
				break;
			case 'bulk_quarantine':
				self::bulk_quarantine();
				break;
			case 'restore_quarantine':
				self::restore_quarantine();
				break;
			case 'delete_quarantine':
				self::delete_quarantine();
				break;
			case 'bulk_restore_quarantine':
				self::bulk_restore_quarantine();
				break;
			case 'bulk_delete_quarantine':
				self::bulk_delete_quarantine();
				break;
			case 'clear_all_quarantine':
				self::clear_all_quarantine();
				break;
			case 'get_quarantine_list':
				self::get_quarantine_list();
				break;
			case 'accept_current':
				self::accept_current();
				break;
			case 'restore_trusted':
				self::restore_trusted();
				break;
			case 'get_diff':
				self::get_diff();
				break;
			case 'bulk_mark_reviewed':
				self::bulk_mark_reviewed();
				break;
			case 'mark_reviewed':
				self::mark_reviewed();
				break;

			// Hardening.
			case 'verify_hardening':
				if ( ! isset( $_POST['confirmed'] ) || '1' !== sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) ) {
					wp_send_json_error( array( 'message' => 'Confirm same-site HTTP and temporary inert uploads probes.' ), 400 ); }
				$result = GWQSH_Hardening_Data::verify();
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( GWQSH_Hardening_Data::get() );
				break;
			case 'save_hardening_csp':
				$mode      = isset( $_POST['mode'] ) ? sanitize_key( wp_unslash( $_POST['mode'] ) ) : '';
				$policy    = isset( $_POST['policy'] ) ? wp_unslash( $_POST['policy'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- The raw bounded policy must be validated before sanitization to reject CRLF/header injection.
				$confirmed = isset( $_POST['confirmed'] ) ? sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) : '';
				$result    = GWQSH_Hardening_Data::save_csp( $mode, $policy, $confirmed );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( GWQSH_Hardening_Data::get() );
				break;
			case 'get_hardening_data':
				self::get_hardening_data();
				break;
			case 'toggle_hardening':
				self::toggle_hardening();
				break;
			case 'reset_hardening':
				self::reset_hardening();
				break;
			case 'revert_hardening':
				self::revert_hardening();
				break;

			// Activity Log.
			case 'activity_data':
				$result = GWQSH_Activity_View_Data::get( wp_unslash( $_POST ) );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( $result );
				break;
			case 'activity_cleanup_preview':
				$result = GWQSH_Activity_View_Data::cleanup_preview();
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( $result );
				break;
			case 'activity_cleanup':
				$result = GWQSH_Activity_View_Data::cleanup( isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '', isset( $_POST['confirmed'] ) ? sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) : '' );
				if ( is_wp_error( $result ) ) {
					wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
				wp_send_json_success( $result );
				break;
			case 'get_activity_logs':
				self::get_activity_logs();
				break;
			case 'clear_activity_logs':
				self::clear_activity_logs();
				break;

			// Settings.
			case 'save_settings':
				self::save_settings();
				break;
			case 'reset_settings':
				self::reset_settings();
				break;
			case 'rebuild_baseline':
				self::rebuild_baseline();
				break;

			default:
				wp_send_json_error( array( 'message' => __( 'Unknown subaction.', 'gracewell-security-suite-pro' ) ), 400 );
				break;
		}
	}

	/*
	-------------------------------------------------------------
		Dashboard handlers
		-------------------------------------------------------------
	 */
	/**
	 * Get dashboard data.
	 */
	private static function get_dashboard_data() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified by the central handle_request() gate.
		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 7;
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Verified by the central handle_request() gate.
		$overview_days = isset( $_POST['overview_days'] ) ? absint( $_POST['overview_days'] ) : 30;
		wp_send_json_success( GWQSH_Dashboard_Data::get( $days, $overview_days ) );
	}

	/**
	 * Get login data.
	 */
	private static function get_login_data() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$days = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 7;
		wp_send_json_success( GWQSH_Login_View_Data::get( $days ) );
	}
	/**
	 * Toggle login protection.
	 */
	private static function toggle_login_protection() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$on = ! empty( $_POST['on'] );
		GWQSH_Login_Protection::update_settings( array( 'enabled' => $on ) );
		GWQSH_Activity_Logger::log(
			$on ? 'Settings changed' : 'Setting disabled',
			'Brute-force login protection ' . ( $on ? 'enabled' : 'paused' ),
			'Security'
		);
		wp_send_json_success( array( 'enabled' => $on ) );
	}
	/**
	 * Save login settings.
	 */
	private static function save_login_settings() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$settings = array();
		$ranges   = array(
			'max_attempts'     => array( 1, 100 ),
			'time_window'      => array( 1, 1440 ),
			'lockout_duration' => array( 1, 10080 ),
			'repeat_lockouts'  => array( 1, 100 ),
			'repeat_duration'  => array( 1, 720 ),
		);
		foreach ( $ranges as $key => $range ) {
			if ( ! isset( $_POST[ $key ] ) ) {
				continue; }
			$value = sanitize_text_field( wp_unslash( $_POST[ $key ] ) );
			if ( ! ctype_digit( $value ) || (int) $value < $range[0] || (int) $value > $range[1] ) {
				wp_send_json_error( array( 'message' => 'Enter a valid positive value for ' . str_replace( '_', ' ', $key ) . '.' ), 400 ); }
			$settings[ $key ] = (int) $value;
		}
		foreach ( array( 'enabled', 'generic_errors', 'track_username', 'email_lockout' ) as $key ) {
			if ( isset( $_POST[ $key ] ) ) {
				if ( ! in_array( $_POST[ $key ], array( '0', '1' ), true ) ) {
					wp_send_json_error( array( 'message' => 'Invalid switch value.' ), 400 ); }
				$settings[ $key ] = '1' === $_POST[ $key ];
			}
		}
		if ( isset( $_POST['xmlrpc'] ) && ! in_array( $_POST['xmlrpc'], array( '0', '1' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Invalid XML-RPC setting.' ), 400 ); }
		GWQSH_Login_Protection::update_settings( $settings );
		$saved = GWQSH_Login_Protection::get_settings();
		foreach ( $settings as $key => $value ) {
			if ( $saved[ $key ] !== $value ) {
				wp_send_json_error( array( 'message' => 'Unable to persist login settings.' ), 500 ); }
		}
		if ( isset( $_POST['xmlrpc'] ) ) {
			GWQSH_Hardening::set( 'xmlrpc', '1' === $_POST['xmlrpc'] );
			if ( GWQSH_Hardening::is_enabled( 'xmlrpc' ) !== ( '1' === $_POST['xmlrpc'] ) ) {
				wp_send_json_error( array( 'message' => 'Unable to persist XML-RPC protection.' ), 500 ); }
		}
		GWQSH_Activity_Logger::log( 'Settings changed', 'Login protection parameters updated', 'System' );
		wp_send_json_success(
			array(
				'settings' => $saved,
				'data'     => GWQSH_Login_View_Data::get(),
			)
		);
	}
	/**
	 * Unlock ip.
	 */
	private static function unlock_ip() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => 'Invalid IP' ) );
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => 'Enter a valid IP address.' ), 400 ); }
		if ( ! GWQSH_Login_Protection::unlock_ip( $ip ) ) {
			wp_send_json_error( array( 'message' => 'This IP is no longer locked, or the unlock could not be saved.' ), 409 ); }
		wp_send_json_success( array( 'ip' => $ip ) );
	}
	/**
	 * Add allow ip.
	 */
	private static function add_allow_ip() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( empty( $ip ) ) {
			wp_send_json_error( array( 'message' => 'Please enter an IP address.' ) );
		}
		if ( ! filter_var( $ip, FILTER_VALIDATE_IP ) ) {
			wp_send_json_error( array( 'message' => 'Enter a valid IPv4 or IPv6 address.' ), 400 ); }
		$res = GWQSH_Login_Protection::add_to_allowlist( $ip );
		if ( $res ) {
			wp_send_json_success( array( 'allow_ips' => GWQSH_Login_Protection::get_allowlist() ) );
		} else {
			wp_send_json_error( array( 'message' => 'IP is already in the allowlist, or the change could not be saved.' ) );
		}
	}
	/**
	 * Remove allow ip.
	 */
	private static function remove_allow_ip() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$ip = isset( $_POST['ip'] ) ? sanitize_text_field( wp_unslash( $_POST['ip'] ) ) : '';
		if ( ! in_array( $ip, GWQSH_Login_Protection::get_allowlist(), true ) ) {
			wp_send_json_error( array( 'message' => 'This address is not on the allowlist.' ), 409 ); }
		if ( ! GWQSH_Login_Protection::remove_from_allowlist( $ip ) ) {
			wp_send_json_error( array( 'message' => 'Unable to remove this trusted IP.' ), 500 ); }
		wp_send_json_success( array( 'allow_ips' => GWQSH_Login_Protection::get_allowlist() ) );
	}
	/**
	 * Clear allowlist.
	 */
	private static function clear_allowlist() {
		GWQSH_Login_Protection::clear_allowlist();
		wp_send_json_success( array( 'allow_ips' => GWQSH_Login_Protection::get_allowlist() ) );
	}
	/**
	 * Save login slug.
	 */
	private static function save_login_slug() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$slug    = isset( $_POST['slug'] ) ? sanitize_text_field( wp_unslash( $_POST['slug'] ) ) : GWQSH_Login_Protection::get_settings()['custom_slug'];
		$enabled = isset( $_POST['enabled'] ) ? '1' === sanitize_text_field( wp_unslash( $_POST['enabled'] ) ) : true;
		if ( ! GWQSH_Login_Protection::valid_slug( $slug ) ) {
			wp_send_json_error( array( 'message' => 'Use 3–40 lowercase letters, numbers or hyphens. Reserved routes and existing page slugs are not allowed.' ), 400 );
		}
		GWQSH_Login_Protection::update_settings(
			array(
				'custom_slug'         => $slug,
				'custom_slug_enabled' => $enabled,
			)
		);
		$recovery_url = GWQSH_Login_Protection::rotate_recovery_key();
		GWQSH_Activity_Logger::log( 'Settings changed', "Custom login URL set to /{$slug}", 'Security' );
		wp_send_json_success(
			array(
				'enabled'      => $enabled,
				'message'      => $enabled ? 'Custom Login URL enabled' : 'Custom Login URL disabled',
				'slug'         => $slug,
				'login_url'    => GWQSH_Login_Protection::custom_login_url( $slug ),
				'recovery_url' => $recovery_url,
			)
		);
	}

	/** Save access preferences through the existing nonce/capability gate. */
	private static function save_login_access() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$settings = array();
		foreach ( array(
			'guest_login_behavior' => array( 'home', '404' ),
			'guest_admin_behavior' => array( 'home', 'login' ),
		) as $key => $allowed ) {
			if ( isset( $_POST[ $key ] ) ) {
				$value = sanitize_key( wp_unslash( $_POST[ $key ] ) );
				if ( ! in_array( $value, $allowed, true ) ) {
					wp_send_json_error( array( 'message' => 'Invalid guest access behavior.' ), 400 ); }
				$settings[ $key ] = $value;
			}
		}
		if ( isset( $_POST['slug'] ) ) {
			$slug = sanitize_text_field( wp_unslash( $_POST['slug'] ) );
			if ( ! GWQSH_Login_Protection::valid_slug( $slug ) ) {
				wp_send_json_error( array( 'message' => 'Use a unique 3–40 character lowercase login slug. Reserved WordPress routes are not allowed.' ), 400 ); }
			if ( ! isset( $_POST['custom_enabled'] ) || ! in_array( $_POST['custom_enabled'], array( '0', '1' ), true ) ) {
				wp_send_json_error( array( 'message' => 'Invalid custom login switch.' ), 400 ); }
			$settings['custom_slug']         = $slug;
			$settings['custom_slug_enabled'] = '1' === $_POST['custom_enabled'];
		}
		if ( isset( $_POST['trusted_proxies'] ) ) {
			$raw = sanitize_textarea_field( wp_unslash( $_POST['trusted_proxies'] ) );
			foreach ( preg_split( '/[\s,]+/', $raw, -1, PREG_SPLIT_NO_EMPTY ) as $range ) {
				if ( ! GWQSH_Network::matches( explode( '/', $range )[0], $range ) ) {
					wp_send_json_error( array( 'message' => 'Enter valid trusted proxy IP addresses or CIDRs.' ), 400 ); }
			}
			GWQSH_Settings::update_all( array( 'trusted_proxies' => $raw ) );
		}
		if ( isset( $_POST['proxy_mode'] ) ) {
			$mode = sanitize_key( wp_unslash( $_POST['proxy_mode'] ) );
			if ( ! in_array( $mode, array( 'remote', 'xff', 'cf', 'xreal', 'trueclient' ), true ) ) {
				wp_send_json_error( array( 'message' => 'Invalid IP detection mode.' ), 400 ); }
			$trusted = GWQSH_Network::trusted();
			if ( 'remote' !== $mode && ! $trusted ) {
				wp_send_json_error( array( 'message' => 'Enter trusted proxy IPs or CIDRs before enabling forwarded headers.' ), 400 ); }
			GWQSH_Settings::update_all(
				array(
					'proxy'       => 'remote' !== $mode,
					'proxyheader' => 'remote' === $mode ? 'xff' : $mode,
				)
			);
			$global = GWQSH_Settings::get_all();
			if ( ( 'remote' !== $mode ) !== $global['proxy'] || ( 'remote' === $mode ? 'xff' : $mode ) !== $global['proxyheader'] ) {
				wp_send_json_error( array( 'message' => 'Unable to persist proxy detection settings.' ), 500 ); }
		}
		if ( isset( $_POST['role_protection'] ) ) {
			$rules = self::json_input( wp_unslash( $_POST ), 'role_protection' );
			if ( ! is_array( $rules ) ) {
				wp_send_json_error( array( 'message' => 'Invalid role protection rules.' ), 400 ); }
			foreach ( $rules as $role => $state ) {
				if ( ! isset( wp_roles()->roles[ $role ] ) || ! is_bool( $state ) ) {
					wp_send_json_error( array( 'message' => 'Invalid role protection rule.' ), 400 ); }
			}
			$settings['role_protection'] = $rules;
		}
		$previous = GWQSH_Login_Protection::get_settings();
		GWQSH_Login_Protection::update_settings( $settings );
		$saved = GWQSH_Login_Protection::get_settings();
		foreach ( $settings as $key => $value ) {
			if ( $saved[ $key ] !== $value ) {
				wp_send_json_error( array( 'message' => 'Unable to persist access settings.' ), 500 ); }
		}
		if ( isset( $settings['custom_slug'] ) && ( $previous['custom_slug'] !== $saved['custom_slug'] || $previous['custom_slug_enabled'] !== $saved['custom_slug_enabled'] ) ) {
			GWQSH_Login_Protection::rotate_recovery_key(); }
		GWQSH_Activity_Logger::log( 'Settings changed', 'Login access preferences updated', 'System' );
		wp_send_json_success( array( 'data' => GWQSH_Login_View_Data::get() ) );
	}

	/*
	-------------------------------------------------------------
		Two-Factor handlers
		-------------------------------------------------------------
	 */
	/**
	 * Get 2fa data.
	 */
	private static function get_2fa_data() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$filters = array();
		foreach ( array( 'search', 'role', 'status', 'page' ) as $key ) {
			$filters[ $key ] = isset( $_POST[ $key ] ) ? sanitize_text_field( wp_unslash( $_POST[ $key ] ) ) : '';
		}
		wp_send_json_success( GWQSH_Two_Factor_View_Data::get( $filters ) );
	}
	/**
	 * Generate 2fa secret.
	 */
	private static function generate_2fa_secret() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$current_user = wp_get_current_user();
		$new_secret   = GWQSH_Two_Factor::generate_secret();
		$enabled      = GWQSH_Two_Factor::is_user_2fa_enabled( $current_user->ID );
		$encrypted    = GWQSH_Crypto::encrypt( $new_secret );
		if ( $enabled && ( ! isset( $_POST['confirmed'] ) || '1' !== sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) ) ) {
			wp_send_json_error( array( 'message' => 'Confirm authenticator replacement first.' ), 400 ); }
		$saved = false !== $encrypted && false !== update_user_meta( $current_user->ID, 'gwqsh_2fa_pending_secret', $encrypted );
		if ( ! $saved ) {
			wp_send_json_error( array( 'message' => 'Secure secret storage is unavailable.' ), 500 );
		}
		update_user_meta( $current_user->ID, 'gwqsh_2fa_pending_created', time() );
		$uri = GWQSH_Two_Factor::get_totp_uri( $current_user->user_login, $new_secret );
		GWQSH_Activity_Logger::log( '2FA setup started', 'Authenticator QR code generated', 'Security', $current_user->user_login );
		wp_send_json_success(
			array(
				'secret'  => $new_secret,
				'qr_uri'  => $uri,
				'pending' => $enabled,
			)
		);
	}
	/**
	 * Confirm 2fa secret.
	 */
	private static function confirm_2fa_secret() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$user_id = get_current_user_id();
		self::factor_attempt( $user_id );
		if ( ! GWQSH_Two_Factor::is_user_2fa_enabled( $user_id ) ) {
			wp_send_json_error( array( 'message' => 'Enroll your authenticator first.' ), 400 ); }
		$stored  = get_user_meta( $user_id, 'gwqsh_2fa_pending_secret', true );
		$pending = GWQSH_Two_Factor::get_pending_secret( $user_id );
		$code    = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$slice   = GWQSH_Two_Factor::matching_totp_slice( $pending, $code );
		if ( false === $slice ) {
			wp_send_json_error( array( 'message' => 'Invalid authenticator code.' ), 400 );
		}
		if ( ! delete_user_meta( $user_id, 'gwqsh_2fa_pending_secret', $stored ) ) {
			wp_send_json_error( array( 'message' => 'The setup key changed. Refresh and try again.' ), 409 ); }
		if ( ! GWQSH_Two_Factor::save_user_secret( $user_id, $pending ) ) {
			add_user_meta( $user_id, 'gwqsh_2fa_pending_secret', $stored, true );
			wp_send_json_error( array( 'message' => 'Secure secret storage is unavailable.' ), 500 );
		}
		update_user_meta( $user_id, 'gwqsh_2fa_last_slice', $slice );
		delete_user_meta( $user_id, 'gwqsh_trusted_devices' );
		update_user_meta( $user_id, 'gwqsh_2fa_last_verified', current_time( 'mysql' ) );
		GWQSH_Activity_Logger::log( '2FA secret regenerated', 'Authenticator secret replaced after verification', 'Security' );
		wp_send_json_success();
	}
	/**
	 * Generate backup codes.
	 */
	private static function generate_backup_codes() {
		$current_user = wp_get_current_user();
		if ( ! GWQSH_Two_Factor::is_user_2fa_enabled( $current_user->ID ) ) {
			wp_send_json_error( array( 'message' => 'Verify your authenticator setup before generating backup codes.' ), 400 ); }
		$new_codes = GWQSH_Two_Factor::generate_backup_codes();
		$records   = GWQSH_Two_Factor::save_user_backup_codes( $current_user->ID, $new_codes );
		if ( false === $records ) {
			wp_send_json_error( array( 'message' => 'Could not save backup codes.' ), 500 ); }
		update_user_meta( $current_user->ID, 'gwqsh_backup_generated', current_time( 'mysql' ) );
		GWQSH_Activity_Logger::log( 'Backup codes regenerated', '10 new backup codes generated', 'Security', $current_user->user_login );
		wp_send_json_success( array( 'backup_codes' => $records ) );
	}
	/**
	 * Enable user 2fa.
	 */
	private static function enable_user_2fa() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$user_id = self::two_factor_user_id( get_current_user_id() );
		if ( get_current_user_id() !== $user_id ) {
			wp_send_json_error( array( 'message' => 'Users must enroll their own authenticator.' ), 403 );
		}
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) && empty( GWQSH_Two_Factor::get_settings()['allow_roles'] ) && ! GWQSH_Two_Factor::required( $user_id ) ) {
			wp_send_json_error( array( 'message' => 'Optional enrollment for other roles is disabled.' ), 403 ); }
		if ( GWQSH_Two_Factor::is_user_2fa_enabled( $user_id ) ) {
			wp_send_json_error( array( 'message' => 'Your authenticator is already enabled. Use the replacement flow.' ), 409 ); }
		self::factor_attempt( $user_id );
		$code   = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		$stored = get_user_meta( $user_id, 'gwqsh_2fa_pending_secret', true );
		$secret = GWQSH_Two_Factor::get_pending_secret( $user_id );
		$slice  = GWQSH_Two_Factor::matching_totp_slice( $secret, $code );
		if ( false === $slice ) {
			wp_send_json_error( array( 'message' => 'Enter a valid authenticator code to enable 2FA.' ), 400 );
		}
		if ( ! $stored || ! delete_user_meta( $user_id, 'gwqsh_2fa_pending_secret', $stored ) ) {
			wp_send_json_error( array( 'message' => 'The setup key changed. Refresh and try again.' ), 409 ); }
		if ( ! GWQSH_Two_Factor::enable_user_2fa( $user_id, $secret ) ) {
			add_user_meta( $user_id, 'gwqsh_2fa_pending_secret', $stored, true );
			wp_send_json_error( array( 'message' => 'Could not enable 2FA securely.' ), 500 );
		}
		update_user_meta( $user_id, 'gwqsh_2fa_last_slice', $slice );
		wp_send_json_success( array( 'message' => 'Two-factor state updated.' ) );
	}
	/**
	 * Reset user 2fa.
	 */
	private static function reset_user_2fa() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$user_id = self::two_factor_user_id();
		if ( ! $user_id || ! get_userdata( $user_id ) || ! current_user_can( 'edit_user', $user_id ) ) {
			wp_send_json_error( array( 'message' => 'Invalid user ID' ) );
		}
		if ( get_current_user_id() === $user_id ) {
			wp_send_json_error( array( 'message' => 'Self-service reset requires identity verification.' ), 403 );
		}
		if ( empty( GWQSH_Two_Factor::get_settings()['allow_admin_reset'] ) || sanitize_text_field( wp_unslash( $_POST['confirmed'] ?? '' ) ) !== '1' ) {
			wp_send_json_error( array( 'message' => 'Admin reset must be allowed and explicitly confirmed.' ), 403 ); }
		GWQSH_Two_Factor::reset_user_2fa( $user_id );
		WP_Session_Tokens::get_instance( $user_id )->destroy_all();
		wp_send_json_success( array( 'message' => 'Two-factor state updated.' ) );
	}
	/**
	 * Save 2fa settings.
	 */
	private static function save_2fa_settings() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$settings = GWQSH_Two_Factor::get_settings();
		foreach ( array( 'require_admin', 'allow_roles', 'remember_device', 'allow_admin_reset', 'enforce_roles' ) as $key ) {
			if ( isset( $_POST[ $key ] ) ) {
				if ( ! in_array( $_POST[ $key ], array( '0', '1' ), true ) ) {
					wp_send_json_error( array( 'message' => 'Invalid policy value.' ), 400 ); }
				$settings[ $key ] = '1' === $_POST[ $key ];
			}
		}
		if ( isset( $_POST['required_roles'] ) ) {
			// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- Decoded array is strictly validated against registered role keys below.
			$roles = json_decode( wp_unslash( $_POST['required_roles'] ), true );
			if ( ! is_array( $roles ) || count( $roles ) > count( wp_roles()->roles ) ) {
				wp_send_json_error( array( 'message' => 'Invalid role selection.' ), 400 ); }
			foreach ( $roles as $role ) {
				if ( ! is_string( $role ) || ! isset( wp_roles()->roles[ $role ] ) ) {
					wp_send_json_error( array( 'message' => 'Unknown role.' ), 400 ); }
			}
			$settings['required_roles'] = array_values( array_unique( $roles ) );
		}
		update_option( 'gwqsh_two_factor_settings', $settings, false );
		if ( GWQSH_Two_Factor::get_settings() !== $settings ) {
			wp_send_json_error( array( 'message' => 'Unable to save policy.' ), 500 ); }
		GWQSH_Activity_Logger::log( '2FA policy updated', 'Two-factor enrollment and recovery policy updated', 'Security' );
		wp_send_json_success(
			array(
				'settings' => $settings,
				'message'  => '2FA policy saved.',
			)
		);
	}
	/**
	 * Validate an explicit target without converting malformed IDs into another user.
	 *
	 * @param int $fallback Default owner.
	 */
	private static function two_factor_user_id( $fallback = 0 ) {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		if ( ! isset( $_POST['user_id'] ) ) {
			return $fallback; }
		$raw = sanitize_text_field( wp_unslash( $_POST['user_id'] ) );
		if ( ! preg_match( '/^[1-9][0-9]*$/D', $raw ) || strlen( $raw ) > 18 ) {
			wp_send_json_error( array( 'message' => 'Invalid user ID.' ), 400 ); }
		return (int) $raw;
	}

	/**
	 * Reserve an account-scoped verification attempt.
	 *
	 * @param int $user_id Account.
	 */
	private static function factor_attempt( $user_id ) {
		if ( ! GWQSH_Two_Factor::reserve_factor_attempt( $user_id ) ) {
			wp_send_json_error( array( 'message' => 'Too many verification attempts. Try again in five minutes.' ), 429 ); }
	}
	/**
	 * Disable own 2fa.
	 */
	private static function disable_own_2fa() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$id = get_current_user_id();
		if ( GWQSH_Two_Factor::required( $id ) ) {
			wp_send_json_error( array( 'message' => 'Your account is required to use 2FA. Ask an administrator to change the requirement.' ), 400 ); }
		self::factor_attempt( $id );
		$code = isset( $_POST['code'] ) ? sanitize_text_field( wp_unslash( $_POST['code'] ) ) : '';
		if ( GWQSH_Two_Factor::is_user_2fa_enabled( $id ) && ! GWQSH_Two_Factor::consume_totp( $id, $code ) && ! GWQSH_Two_Factor::verify_and_burn_backup_code( $id, $code ) ) {
			wp_send_json_error( array( 'message' => 'Enter a valid authentication or backup code.' ), 400 );
		}
		GWQSH_Two_Factor::reset_user_2fa( $id );
		wp_send_json_success( array( 'message' => '2FA disabled successfully.' ) );
	}
	/**
	 * Require user 2fa.
	 */
	private static function require_user_2fa() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$id = self::two_factor_user_id();
		if ( ! $id || ! get_userdata( $id ) || ! current_user_can( 'edit_user', $id ) ) {
			wp_send_json_error( array( 'message' => 'You cannot manage this user.' ), 403 ); }
		$required = isset( $_POST['required'] ) ? sanitize_text_field( wp_unslash( $_POST['required'] ) ) : '';
		if ( ! in_array( $required, array( '0', '1' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Invalid enrollment requirement.' ), 400 ); }
		update_user_meta( $id, 'gwqsh_2fa_required', '1' === $required ? 1 : 0 );
		wp_send_json_success(
			array(
				'updated' => true,
				'message' => 'User 2FA requirement saved.',
			)
		);
	}
	/**
	 * Remove trusted device.
	 */
	private static function remove_trusted_device() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$id = self::two_factor_user_id( get_current_user_id() );
		if ( ! $id || ! get_userdata( $id ) || ( get_current_user_id() !== $id && ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! current_user_can( 'edit_user', $id ) ) ) ) {
			wp_send_json_error( array( 'message' => 'You cannot manage these devices.' ), 403 ); }
		$device = isset( $_POST['device_id'] ) ? sanitize_text_field( wp_unslash( $_POST['device_id'] ) ) : '';
		if ( ! GWQSH_Two_Factor::remove_trusted_device( $id, $device ) ) {
			wp_send_json_error( array( 'message' => 'This device is no longer available. Refresh the list.' ), 409 ); }
		wp_send_json_success( array( 'devices' => GWQSH_Two_Factor::get_trusted_devices( $id ) ) );
	}
	/** Get an authorized user's safe remembered-device list. */
	private static function get_user_2fa_devices() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$id = self::two_factor_user_id( get_current_user_id() );
		if ( ! $id || ! get_userdata( $id ) || ( get_current_user_id() !== $id && ( ! current_user_can( GWQSH_Admin::management_capability() ) || ! current_user_can( 'edit_user', $id ) ) ) ) {
			wp_send_json_error( array( 'message' => 'You cannot manage these devices.' ), 403 ); }
		wp_send_json_success( array( 'devices' => GWQSH_Two_Factor::get_trusted_devices( $id ) ) );
	}

	/*
	-------------------------------------------------------------
		File Integrity handlers
		-------------------------------------------------------------
	 */
	/**
	 * Get scan data.
	 */
	private static function get_scan_data() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		GWQSH_Quarantine_Manager::reconcile();
		$filters             = array(
			'type'     => isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '',
			'status'   => isset( $_POST['status'] ) ? sanitize_text_field( wp_unslash( $_POST['status'] ) ) : '',
			'search'   => isset( $_POST['search'] ) ? sanitize_text_field( wp_unslash( $_POST['search'] ) ) : '',
			'severity' => isset( $_POST['severity'] ) ? sanitize_text_field( wp_unslash( $_POST['severity'] ) ) : '',
			'sort'     => isset( $_POST['sort'] ) ? sanitize_key( wp_unslash( $_POST['sort'] ) ) : 'date',
			'order'    => isset( $_POST['order'] ) ? sanitize_key( wp_unslash( $_POST['order'] ) ) : 'DESC',
			'page'     => isset( $_POST['page_num'] ) ? absint( $_POST['page_num'] ) : 1,
			'per_page' => isset( $_POST['per_page'] ) ? (int) $_POST['per_page'] : GWQSH_Quarantine_Manager::DEFAULT_PAGE_SIZE,
		);
		$filters['per_page'] = GWQSH_Quarantine_Manager::validate_page_size( $filters['per_page'] );
		update_user_meta( get_current_user_id(), 'gwqsh_integrity_per_page', $filters['per_page'] );
		$summary = GWQSH_File_Integrity::get_summary();
		$issues  = GWQSH_File_Integrity::get_scan_issues_paged( $filters );

		wp_send_json_success(
			array(
				'summary'    => $summary,
				'issues'     => $issues['items'],
				'total'      => $issues['total'],
				'page'       => $issues['page'],
				'pages'      => $issues['pages'],
				'per_page'   => $issues['per_page'],
				'history'    => GWQSH_File_Integrity::get_scan_history(),
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Run scan.
	 */
	private static function run_scan() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$resume      = ! empty( $_POST['resume'] );
		$lock        = (int) get_option( 'gwqsh_scan_lock', 0 );
		$engine_lock = GWQSH_Enterprise_Store::lease_active( 'file-scan' );
		if ( $lock && $lock < time() - 300 ) {
			delete_option( 'gwqsh_scan_lock' );
			$lock = 0;
		}
		// A continuation cannot start a second scan after cron finished the first.
		if ( $resume && ! get_option( 'gwqsh_scan_progress' ) && ! $lock && ! $engine_lock ) {
			wp_send_json_success(
				array(
					'result'  => array( 'pending' => false ),
					'summary' => GWQSH_File_Integrity::get_summary(),
				)
			);
		}
		// Cron and AJAX share the existing engine lock. Busy is progress, not failure.
		if ( $lock || $engine_lock ) {
			wp_send_json_success(
				array(
					'result' => array(
						'pending' => true,
						'busy'    => true,
					),
				)
			);
		}
		if ( ! add_option( 'gwqsh_scan_lock', time(), '', false ) ) {
			wp_send_json_success(
				array(
					'result' => array(
						'pending' => true,
						'busy'    => true,
					),
				)
			);
		}
		try {
			$result = GWQSH_File_Integrity::run_full_scan();
		} catch ( Throwable $e ) {
			$result = new WP_Error( 'scan_failed', 'The scan could not read all directories. Check permissions and try again.' );
		} finally {
			delete_option( 'gwqsh_scan_lock' );
		}
		if ( is_wp_error( $result ) && 'scan_busy' === $result->get_error_code() ) {
			wp_send_json_success(
				array(
					'result' => array(
						'pending' => true,
						'busy'    => true,
					),
				)
			);
		}
		if ( is_wp_error( $result ) ) {
			wp_send_json_error(
				array(
					'message' => $result->get_error_message(),
					'code'    => $result->get_error_code(),
				),
				503
			);
		}
		wp_send_json_success(
			array(
				'result'  => $result,
				'summary' => GWQSH_File_Integrity::get_summary(),
				'history' => GWQSH_File_Integrity::get_scan_history(),
			)
		);
	}

	/**
	 * Restore file (legacy path-based, kept for backward compat).
	 */
	private static function restore_file() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
		if ( empty( $path ) ) {
			wp_send_json_error( array( 'message' => 'Path missing.' ) );
		}
		$res = GWQSH_File_Integrity::restore_core_file( $path );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error( array( 'message' => $res->get_error_message() ) );
		}
		wp_send_json_success(
			array(
				'summary' => GWQSH_File_Integrity::get_summary(),
			)
		);
	}
	/**
	 * Quarantine file (legacy path-based, kept for backward compat but now uses finding lookup).
	 */
	private static function quarantine_file() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		// Accept finding_id (preferred) or path (legacy fallback).
		$finding_id = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;
		if ( ! $finding_id ) {
			// Legacy: look up finding by path.
			$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
			if ( empty( $path ) ) {
				wp_send_json_error(
					array(
						'message' => 'Finding ID or path is required.',
						'code'    => 'missing_input',
					)
				);
			}
			global $wpdb;
			$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
			$path1 = '/' . ltrim( $path, '/' );
			$path2 = ltrim( $path, '/' );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$finding_id = (int) $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE is_resolved = 0 AND (file_path = %s OR file_path = %s) LIMIT 1", $path1, $path2 ) );
			if ( ! $finding_id ) {
				wp_send_json_error(
					array(
						'message' => GWQSH_Quarantine_Manager::error_message( 'finding_not_found' ),
						'code'    => 'finding_not_found',
					),
					404
				);
			}
		}
		$res = GWQSH_Quarantine_Manager::quarantine_by_finding( $finding_id );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error(
				array(
					'message' => $res->get_error_message(),
					'code'    => $res->get_error_code(),
				),
				400
			);
		}
		wp_send_json_success(
			array(
				'summary'    => GWQSH_File_Integrity::get_summary(),
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Quarantine by finding ID (new preferred endpoint).
	 */
	private static function quarantine_finding() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$finding_id = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;
		if ( ! $finding_id ) {
			wp_send_json_error(
				array(
					'message' => 'Finding ID is required.',
					'code'    => 'missing_input',
				),
				400
			);
		}
		$res = GWQSH_Quarantine_Manager::quarantine_by_finding( $finding_id );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error(
				array(
					'message' => $res->get_error_message(),
					'code'    => $res->get_error_code(),
				),
				400
			);
		}
		wp_send_json_success(
			array(
				'summary'    => GWQSH_File_Integrity::get_summary(),
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Bulk quarantine multiple findings.
	 */
	private static function bulk_quarantine() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$ids_raw = isset( $_POST['finding_ids'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_ids'] ) ) : '';
		$ids     = array_filter( array_map( 'absint', explode( ',', $ids_raw ) ) );
		if ( empty( $ids ) || count( $ids ) > 500 ) {
			wp_send_json_error( array( 'message' => 'Provide 1–500 valid finding IDs.' ), 400 );
		}
		$results = array(
			'quarantined' => 0,
			'failed'      => 0,
			'errors'      => array(),
		);
		foreach ( $ids as $id ) {
			$res = GWQSH_Quarantine_Manager::quarantine_by_finding( $id );
			if ( is_wp_error( $res ) ) {
				++$results['failed'];
				$results['errors'][] = array(
					'id'      => $id,
					'code'    => $res->get_error_code(),
					'message' => $res->get_error_message(),
				);
			} else {
				++$results['quarantined'];
			}
		}
		GWQSH_Activity_Logger::log( 'Bulk quarantine', $results['quarantined'] . ' files quarantined, ' . $results['failed'] . ' failed.', 'Security' );
		wp_send_json_success(
			array(
				'results'    => $results,
				'summary'    => GWQSH_File_Integrity::get_summary(),
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Restore a quarantined file.
	 */
	private static function restore_quarantine() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$name = isset( $_POST['artifact'] ) ? sanitize_text_field( wp_unslash( $_POST['artifact'] ) ) : '';
		$res  = GWQSH_Quarantine_Manager::restore_quarantined( $name );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error(
				array(
					'message' => $res->get_error_message(),
					'code'    => $res->get_error_code(),
				),
				400
			);
		}
		wp_send_json_success(
			array(
				'restored'   => $res['restored'],
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Delete a quarantined file permanently.
	 */
	private static function delete_quarantine() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$name = isset( $_POST['artifact'] ) ? sanitize_text_field( wp_unslash( $_POST['artifact'] ) ) : '';
		$res  = GWQSH_Quarantine_Manager::delete_quarantined( $name );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error(
				array(
					'message' => $res->get_error_message(),
					'code'    => $res->get_error_code(),
				),
				400
			);
		}
		wp_send_json_success( array( 'quarantine' => GWQSH_Quarantine_Manager::list_quarantined() ) );
	}
	/**
	 * Bulk restore quarantined files.
	 */
	private static function bulk_restore_quarantine() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$names_raw = isset( $_POST['artifacts'] ) ? sanitize_text_field( wp_unslash( $_POST['artifacts'] ) ) : '';
		$names     = array_filter( explode( ',', $names_raw ) );
		if ( empty( $names ) || count( $names ) > 500 ) {
			wp_send_json_error( array( 'message' => 'Provide 1–500 artifact names.' ), 400 );
		}
		$results = array(
			'restored' => 0,
			'failed'   => 0,
			'errors'   => array(),
		);
		foreach ( $names as $name ) {
			$name = sanitize_text_field( $name );
			$res  = GWQSH_Quarantine_Manager::restore_quarantined( $name );
			if ( is_wp_error( $res ) ) {
				++$results['failed'];
				$results['errors'][] = array(
					'id'      => $name,
					'code'    => $res->get_error_code(),
					'message' => $res->get_error_message(),
				);
			} else {
				++$results['restored'];
			}
		}
		wp_send_json_success(
			array(
				'results'    => $results,
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Bulk delete quarantined files.
	 */
	private static function bulk_delete_quarantine() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$names_raw = isset( $_POST['artifacts'] ) ? sanitize_text_field( wp_unslash( $_POST['artifacts'] ) ) : '';
		$names     = array_filter( explode( ',', $names_raw ) );
		if ( empty( $names ) || count( $names ) > 500 ) {
			wp_send_json_error( array( 'message' => 'Provide 1–500 artifact names.' ), 400 );
		}
		$results = array(
			'deleted' => 0,
			'failed'  => 0,
			'errors'  => array(),
		);
		foreach ( $names as $name ) {
			$name = sanitize_text_field( $name );
			$res  = GWQSH_Quarantine_Manager::delete_quarantined( $name );
			if ( is_wp_error( $res ) ) {
				++$results['failed'];
				$results['errors'][] = array(
					'id'      => $name,
					'code'    => $res->get_error_code(),
					'message' => $res->get_error_message(),
				);
			} else {
				++$results['deleted'];
			}
		}
		wp_send_json_success(
			array(
				'results'    => $results,
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Clear all quarantine.
	 */
	private static function clear_all_quarantine() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$res = GWQSH_Quarantine_Manager::clear_all_quarantine();
		if ( is_wp_error( $res ) ) {
			wp_send_json_error( array( 'message' => $res->get_error_message() ), 409 );
		}
		wp_send_json_success(
			array(
				'results'    => $res,
				'quarantine' => GWQSH_Quarantine_Manager::list_quarantined(),
			)
		);
	}
	/**
	 * Get quarantine list.
	 */
	private static function get_quarantine_list() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		wp_send_json_success( array( 'quarantine' => GWQSH_Quarantine_Manager::list_quarantined() ) );
	}
	/**
	 * Accept current version as trusted baseline.
	 */
	private static function accept_current() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$finding_id = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;
		if ( ! $finding_id ) {
			wp_send_json_error( array( 'message' => 'Finding ID is required.' ), 400 );
		}
		$res = GWQSH_Quarantine_Manager::accept_current( $finding_id );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error(
				array(
					'message' => $res->get_error_message(),
					'code'    => $res->get_error_code(),
				),
				400
			);
		}
		wp_send_json_success(
			array(
				'summary' => GWQSH_File_Integrity::get_summary(),
			)
		);
	}
	/**
	 * Restore trusted baseline version.
	 */
	private static function restore_trusted() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$finding_id = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;
		if ( ! $finding_id ) {
			wp_send_json_error( array( 'message' => 'Finding ID is required.' ), 400 );
		}
		$res = GWQSH_Quarantine_Manager::restore_trusted( $finding_id );
		if ( is_wp_error( $res ) ) {
			wp_send_json_error(
				array(
					'message' => $res->get_error_message(),
					'code'    => $res->get_error_code(),
				),
				400
			);
		}
		wp_send_json_success(
			array(
				'summary' => GWQSH_File_Integrity::get_summary(),
			)
		);
	}
	/**
	 * Get diff.
	 */
	private static function get_diff() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		global $wpdb;
		$id = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Fixed plugin-owned table and whitelisted SQL clauses; dynamic values are prepared. Live security state must bypass caching.
		$finding = $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . $wpdb->prefix . 'gwqsh_scan_results WHERE id = %d AND is_resolved = 0', $id ), ARRAY_A );
		if ( ! $finding ) {
			wp_send_json_error( array( 'message' => 'This finding is no longer active.' ), 400 );
		}
		$path        = $finding['file_path'];
		$diff        = GWQSH_File_Integrity::get_file_diff( $path );
		$trusted     = GWQSH_Quarantine_Manager::trusted_copy( $path );
		$ev          = json_decode( $finding['evidence'] ?? '', true );
		$ev          = is_array( $ev ) ? $ev : array();
		$can_restore = 'Core' === $finding['file_type'] ? ! is_wp_error( $diff ) : (bool) $trusted;
		wp_send_json_success(
			array(
				'diff'        => is_wp_error( $diff ) ? '<p class="muted">' . esc_html( $diff->get_error_message() ) . '</p>' : $diff,
				'can_restore' => $can_restore,
				'can_accept'  => ( $ev['score'] ?? 0 ) < 80 && 'Critical' !== ( $ev['severity'] ?? '' ) && empty( $ev['auto_block'] ),
			)
		);
	}
	/**
	 * Mark reviewed (supports both finding_id and path).
	 */
	private static function mark_reviewed() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$finding_id = isset( $_POST['finding_id'] ) ? absint( $_POST['finding_id'] ) : 0;
		if ( $finding_id ) {
			global $wpdb;
			$table = esc_sql( $wpdb->prefix . 'gwqsh_scan_results' );
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching,WordPress.DB.PreparedSQL.InterpolatedNotPrepared,PluginCheck.Security.DirectDB.UnescapedDBParameter
			$updated = $wpdb->update(
				$table,
				array( 'is_resolved' => 1 ),
				array(
					'id'          => $finding_id,
					'is_resolved' => 0,
				)
			);
			if ( ! $updated ) {
				wp_send_json_error( array( 'message' => 'This finding is not an unresolved scan issue.' ), 400 );
			}
		} else {
			$path = isset( $_POST['path'] ) ? sanitize_text_field( wp_unslash( $_POST['path'] ) ) : '';
			if ( ! GWQSH_File_Integrity::mark_as_reviewed( $path ) ) {
				wp_send_json_error( array( 'message' => 'This file is not an unresolved scan finding.' ), 400 );
			}
		}
		wp_send_json_success(
			array(
				'summary' => GWQSH_File_Integrity::get_summary(),
			)
		);
	}

	/** Mark up to one page of findings reviewed in a single database operation. */
	private static function bulk_mark_reviewed() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$raw   = isset( $_POST['finding_ids'] ) ? sanitize_text_field( wp_unslash( $_POST['finding_ids'] ) ) : '';
		$parts = explode( ',', $raw );
		if ( ! $raw || count( $parts ) > 500 || preg_match( '/[^0-9,]/', $raw ) || in_array( '', $parts, true ) ) {
			wp_send_json_error( array( 'message' => 'Select 1–500 valid finding IDs.' ), 400 );
		}
		$result = GWQSH_File_Integrity::review_findings( array_map( 'absint', $parts ) );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 );
		}
		wp_send_json_success( array( 'results' => $result ) );
	}

	/*
	-------------------------------------------------------------
		Hardening handlers
		-------------------------------------------------------------
	 */
	/**
	 * Get hardening data.
	 */
	private static function get_hardening_data() {
		wp_send_json_success( GWQSH_Hardening_Data::get() ); }
	/** Apply a validated explicit state after central authorization. */
	private static function toggle_hardening() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$feature   = isset( $_POST['feature'] ) ? sanitize_key( wp_unslash( $_POST['feature'] ) ) : '';
		$on        = isset( $_POST['on'] ) ? sanitize_text_field( wp_unslash( $_POST['on'] ) ) : '';
		$confirmed = isset( $_POST['confirmed'] ) ? sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) : '';
		if ( ! array_key_exists( $feature, GWQSH_Hardening::get_defaults() ) || ! in_array( $on, array( '0', '1' ), true ) ) {
			wp_send_json_error( array( 'message' => 'Choose a supported control and explicit on/off state.' ), 400 ); }
		if ( '1' !== $confirmed ) {
			wp_send_json_error( array( 'message' => 'Confirm the affected protection and compatibility requirements.' ), 400 ); }
		if ( ! GWQSH_Hardening::set( $feature, '1' === $on ) ) {
			wp_send_json_error( array( 'message' => 'Could not safely apply this setting. Review ownership, permissions or filesystem configuration.' ), 400 ); }
		delete_transient( 'gwqsh_hardening_evidence' );
		wp_send_json_success( GWQSH_Hardening_Data::get() );
	}
	/** Restore documented defaults, distinct from disabling everything. */
	private static function reset_hardening() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		if ( ! isset( $_POST['confirmed'] ) || '1' !== sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) ) {
			wp_send_json_error( array( 'message' => 'Confirmation required.' ), 400 ); }
		if ( ! GWQSH_Hardening::reset_defaults() ) {
			wp_send_json_error( array( 'message' => 'Could not safely restore defaults. Existing ownership/configuration is preserved where possible.' ), 400 ); }
		delete_transient( 'gwqsh_hardening_evidence' );
		wp_send_json_success( GWQSH_Hardening_Data::get() );
	}
	/** Revert only plugin options and exact owned uploads directives. */
	private static function revert_hardening() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		if ( ! isset( $_POST['confirmed'] ) || '1' !== sanitize_text_field( wp_unslash( $_POST['confirmed'] ) ) ) {
			wp_send_json_error( array( 'message' => 'Confirmation required.' ), 400 ); }
		if ( ! GWQSH_Hardening::revert_all() ) {
			wp_send_json_error( array( 'message' => 'The revert did not complete. Review managed markers, write permissions and the refreshed assessment. Prior settings were restored where persistence allowed.' ), 400 ); }
		delete_transient( 'gwqsh_hardening_evidence' );
		wp_send_json_success( GWQSH_Hardening_Data::get() );
	}

	/*
	-------------------------------------------------------------
		Activity Log handlers
		-------------------------------------------------------------
	 */
	/**
	 * Get activity logs.
	 */
	private static function get_activity_logs() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$days   = isset( $_POST['days'] ) ? absint( $_POST['days'] ) : 7;
		$type   = isset( $_POST['type'] ) ? sanitize_text_field( wp_unslash( $_POST['type'] ) ) : '';
		$event  = isset( $_POST['event'] ) ? sanitize_text_field( wp_unslash( $_POST['event'] ) ) : '';
		$user   = isset( $_POST['user'] ) ? sanitize_text_field( wp_unslash( $_POST['user'] ) ) : '';
		$search = isset( $_POST['search'] ) ? sanitize_text_field( wp_unslash( $_POST['search'] ) ) : '';
		$order  = isset( $_POST['order'] ) ? sanitize_text_field( wp_unslash( $_POST['order'] ) ) : 'DESC';
		$page   = isset( $_POST['page_num'] ) ? max( 1, absint( $_POST['page_num'] ) ) : 1;
		$limit  = isset( $_POST['limit'] ) ? max( 1, absint( $_POST['limit'] ) ) : 10;
		$offset = ( $page - 1 ) * $limit;

		$res = GWQSH_Activity_Logger::query_logs(
			array(
				'days'   => $days,
				'type'   => $type,
				'event'  => $event,
				'user'   => $user,
				'search' => $search,
				'order'  => $order,
				'limit'  => $limit,
				'offset' => $offset,
			)
		);

		$breakdown = GWQSH_Activity_Logger::get_type_breakdown( $days );

		wp_send_json_success(
			array(
				'items'     => $res['items'],
				'total'     => $res['total'],
				'page'      => $page,
				'breakdown' => $breakdown,
			)
		);
	}
	/**
	 * Clear activity logs.
	 */
	private static function clear_activity_logs() {
		$result = GWQSH_Activity_Logger::clear_all();
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), 500 );
		}
		wp_send_json_success();
	}

	/*
	-------------------------------------------------------------
		Settings handlers
		-------------------------------------------------------------
	 */
	/**
	 * Save settings.
	 */
	private static function save_settings() {
		check_ajax_referer( 'gwqsh_nonce', 'nonce' );
		$settings_json = isset( $_POST['settings'] ) && is_string( $_POST['settings'] ) ? wp_unslash( $_POST['settings'] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized
		$settings      = json_decode( $settings_json, true );
		if ( is_array( $settings ) && $settings ) {
			$defaults = GWQSH_Settings::get_defaults();
			foreach ( $settings as $key => $value ) {
				if ( ! array_key_exists( $key, $defaults ) || ! is_scalar( $value ) || ( is_bool( $defaults[ $key ] ) && null === filter_var( $value, FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE ) ) ) {
					wp_send_json_error( array( 'message' => 'Invalid settings field or value.' ), 400 );
				}
			}
			if ( isset( $settings['theme'] ) && ! in_array( $settings['theme'], array( 'light', 'dark', 'system' ), true ) ) {
				wp_send_json_error( array( 'message' => 'Invalid color scheme.' ), 400 );
			}
			if ( isset( $settings['retention'] ) && ( ! ctype_digit( (string) $settings['retention'] ) || (int) $settings['retention'] < 0 || (int) $settings['retention'] > 3650 ) ) {
				wp_send_json_error( array( 'message' => 'Retention must be 0–3650 days; zero keeps logs indefinitely.' ), 400 );
			}
			if ( array_key_exists( 'autoupdate', $settings ) && ! GWQSH_Settings::can_manage_updates() ) {
				if ( filter_var( $settings['autoupdate'], FILTER_VALIDATE_BOOLEAN ) !== GWQSH_Settings::get( 'autoupdate' ) ) {
					wp_send_json_error( array( 'message' => 'You do not have permission to manage plugin updates.' ), 403 );
				}
				unset( $settings['autoupdate'] );
			}
			$expected = GWQSH_Settings::normalize( $settings );
			if ( isset( $settings['proxy'] ) && $expected['proxy'] && ( ! defined( 'GWQSH_TRUSTED_PROXIES' ) || ! is_array( GWQSH_TRUSTED_PROXIES ) || ! GWQSH_TRUSTED_PROXIES ) ) {
				wp_send_json_error( array( 'message' => 'Configure GWQSH_TRUSTED_PROXIES before enabling forwarded headers.' ), 400 );
			}
			GWQSH_Settings::update_all( $settings );
			if ( GWQSH_Settings::get_all() !== $expected ) {
				wp_send_json_error( array( 'message' => 'Settings could not be persisted. Reload and retry.' ), 500 );
			}
			GWQSH_Activity_Logger::log( 'Settings changed', 'Plugin configuration updated', 'System' );
			wp_send_json_success( array( 'settings' => GWQSH_Settings::get_all() ) );
		}
		wp_send_json_error( array( 'message' => 'Invalid settings payload' ) );
	}
	/**
	 * Reset settings.
	 */
	private static function reset_settings() {
		$defaults = GWQSH_Settings::get_defaults();
		$expected = $defaults;
		if ( ! GWQSH_Settings::can_manage_updates() ) {
			$expected['autoupdate'] = GWQSH_Settings::get( 'autoupdate' );
			unset( $defaults['autoupdate'] );
		}
		GWQSH_Settings::update_all( $defaults );
		if ( GWQSH_Settings::get_all() !== $expected ) {
			wp_send_json_error( array( 'message' => 'Defaults could not be persisted.' ), 500 );
		}
		GWQSH_Activity_Logger::log( 'Settings reset', 'All plugin settings reset to defaults', 'System' );
		wp_send_json_success( array( 'settings' => GWQSH_Settings::get_all() ) );
	}
	/**
	 * Rebuild baseline.
	 */
	private static function rebuild_baseline() {
		$result = GWQSH_Scan_Engine::trust_baseline();
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), 409 );
		}
		wp_send_json_success( array( 'message' => 'Inspected file baseline saved.' ) );
	}
}
