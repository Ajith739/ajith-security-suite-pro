<?php
/**
 * Password-bound backup delivery and extensible SMS providers.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Recovery service. */
final class GWQSH_Recovery {
	/** Return the normalized saved service configuration. */
	public static function settings() {
		return wp_parse_args(
			(array) get_option( 'gwqsh_recovery_settings', array() ),
			array(
				'passkeys'     => true,
				'email'        => false,
				'sms'          => false,
				'sms_provider' => 'twilio',
				'twilio_sid'   => '',
				'twilio_from'  => '',
				'twilio_token' => '',
			)
		);
	}
	/** Return provider settings with the encrypted token excluded. */
	public static function public_settings() {
		$settings                     = self::settings();
		$settings['token_configured'] = ! empty( $settings['twilio_token'] );
		unset( $settings['twilio_token'] );
		return $settings; }
	/**
	 * Validate and encrypt provider credentials before saving configuration.
	 *
	 * @param array $input input value.
	 */
	public static function save_settings( array $input ) {
		$current = self::settings();
		foreach ( array( 'passkeys', 'email', 'sms' ) as $key ) {
			if ( isset( $input[ $key ] ) && is_bool( $input[ $key ] ) ) {
				$current[ $key ] = $input[ $key ]; }
		}
		foreach ( array( 'sms_provider', 'twilio_sid', 'twilio_from' ) as $key ) {
			if ( isset( $input[ $key ] ) && is_string( $input[ $key ] ) ) {
				$current[ $key ] = sanitize_text_field( $input[ $key ] ); }
		}
		if ( 'twilio' !== $current['sms_provider'] && ! preg_match( '/^[a-z][a-z0-9_-]{0,39}$/D', $current['sms_provider'] ) ) {
			return new WP_Error( 'provider', 'Invalid provider identifier.' ); }
		if ( $current['twilio_sid'] && ! preg_match( '/^AC[a-fA-F0-9]{32}$/D', $current['twilio_sid'] ) ) {
			return new WP_Error( 'sid', 'Enter a valid Twilio account SID.' ); }
		if ( $current['twilio_from'] && ! preg_match( '/^\+[1-9][0-9]{7,14}$/D', $current['twilio_from'] ) ) {
			return new WP_Error( 'phone', 'Use an E.164 sender number, including the country code.' ); }
		if ( ! empty( $input['twilio_token'] ) ) {
			if ( ! is_string( $input['twilio_token'] ) || strlen( $input['twilio_token'] ) > 256 ) {
				return new WP_Error( 'token', 'Invalid provider token.' ); }
			$current['twilio_token'] = GWQSH_Crypto::encrypt( $input['twilio_token'] );
			if ( ! $current['twilio_token'] ) {
				return new WP_Error( 'encryption', 'Unable to protect the provider credential.' ); }
		}
		update_option( 'gwqsh_recovery_settings', $current, false );
		return self::public_settings();
	}
	/** Register the service hooks. */
	public static function init() {
		add_action( 'wp_ajax_gwqsh_recovery_send', array( __CLASS__, 'login_send' ) );
		add_action( 'wp_ajax_nopriv_gwqsh_recovery_send', array( __CLASS__, 'login_send' ) );
		add_action( 'gwqsh_daily_log_cleanup', array( __CLASS__, 'cleanup' ) );
		add_action( 'gwqsh_auth_cleanup', array( __CLASS__, 'cleanup' ) );
		if ( ! wp_next_scheduled( 'gwqsh_auth_cleanup' ) ) {
			wp_schedule_event( time() + HOUR_IN_SECONDS, 'hourly', 'gwqsh_auth_cleanup' ); }
	}
	/** Delete a bounded batch of expired authentication challenges. */
	public static function cleanup() {
		global $wpdb;
		// phpcs:ignore WordPress.DB -- Indexed bounded cleanup of expired, plugin-owned challenges.
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_auth_challenges WHERE expires_at < %d LIMIT 10000", time() ) );
		// phpcs:ignore WordPress.DB -- Fixed WordPress-owned identifiers and prepared values; live enforcement and atomic mutations must bypass stale caches.
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT option_name,option_value FROM {$wpdb->options} WHERE option_name LIKE %s LIMIT 500", $wpdb->esc_like( 'gwqsh_auth_' ) . '%' ), ARRAY_A );
		foreach ( $rows as $row ) {
			if ( ! preg_match( '/^gwqsh_auth_[a-f0-9]{64}$/D', $row['option_name'] ) ) {
				continue; }
			$data = is_serialized( $row['option_value'] ) ? unserialize( $row['option_value'], array( 'allowed_classes' => false ) ) : null;
			if ( ! is_array( $data ) || ( $data['expires'] ?? 0 ) < time() ) {
				delete_option( $row['option_name'] ); }
		}
		$cursor = (int) get_option( 'gwqsh_recovery_cleanup_cursor', 0 );
		$rows   = $wpdb->get_results( $wpdb->prepare( "SELECT umeta_id,user_id,meta_key,meta_value FROM {$wpdb->usermeta} WHERE umeta_id>%d AND meta_key IN ('gwqsh_recovery_setup_email','gwqsh_recovery_setup_sms','gwqsh_recovery_login_email','gwqsh_recovery_login_sms') ORDER BY umeta_id LIMIT 200", $cursor ), ARRAY_A );
		foreach ( $rows as $row ) {
			$data = is_serialized( $row['meta_value'] ) ? unserialize( $row['meta_value'], array( 'allowed_classes' => false ) ) : null;
			if ( is_array( $data ) && ( ( $data['expires'] ?? 0 ) < time() || ! empty( $data['used'] ) ) ) {
				delete_user_meta( (int) $row['user_id'], $row['meta_key'], $data ); }
			$cursor = (int) $row['umeta_id'];
		}
		update_option( 'gwqsh_recovery_cleanup_cursor', count( $rows ) < 200 ? 0 : $cursor, false );
	}
	/**
	 * Return public status fields without exposing credential material.
	 *
	 * @param mixed $user_id user id value.
	 */
	public static function data( $user_id ) {
		$user   = get_userdata( $user_id );
		$email  = (string) get_user_meta( $user_id, 'gwqsh_recovery_email_verified', true );
		$phone  = (string) get_user_meta( $user_id, 'gwqsh_recovery_phone_verified', true );
		$policy = self::public_settings();
		return array(
			'totp'               => GWQSH_Two_Factor::is_user_2fa_enabled( $user_id ) && (bool) GWQSH_Two_Factor::get_user_secret( $user_id ),
			'email_enrolled'     => (bool) $email,
			'sms_enrolled'       => (bool) $phone,
			'email'              => $policy['email'] && $user && $email && hash_equals( $email, $user->user_email ),
			'sms'                => $policy['sms'] && (bool) $phone,
			'phone'              => $phone ? str_repeat( '•', max( 0, strlen( $phone ) - 4 ) ) . substr( $phone, -4 ) : '',
			'policy'             => $policy,
			'passkeys'           => GWQSH_Passkeys::listing( $user_id ),
			'passkeys_available' => GWQSH_Passkeys::available(),
		);
	}
	/**
	 * Deliver through a registered provider or the configured Twilio adapter.
	 *
	 * @param mixed $phone phone value.
	 * @param mixed $message message value.
	 */
	private static function sms( $phone, $message ) {
		$settings  = self::settings();
		$providers = apply_filters( 'gwqsh_sms_providers', array() );
		if ( isset( $providers[ $settings['sms_provider'] ] ) && is_callable( $providers[ $settings['sms_provider'] ] ) ) {
			$result = call_user_func( $providers[ $settings['sms_provider'] ], $phone, $message );
			return true === $result ? true : new WP_Error( 'delivery', 'The SMS provider could not accept the message.' );
		}
		$token = GWQSH_Crypto::decrypt( $settings['twilio_token'] );
		if ( 'twilio' !== $settings['sms_provider'] || ! $settings['twilio_sid'] || ! $settings['twilio_from'] || ! $token ) {
			return new WP_Error( 'not_configured', 'Configure the SMS provider in Settings first.' ); }
		$response = wp_safe_remote_post(
			'https://api.twilio.com/2010-04-01/Accounts/' . rawurlencode( $settings['twilio_sid'] ) . '/Messages.json',
			array(
				'timeout'             => 8,
				'redirection'         => 0,
				'limit_response_size' => 8192,
				// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions -- Binary WebAuthn wire encoding or provider Basic authentication, never executable content.
				'headers'             => array( 'Authorization' => 'Basic ' . base64_encode( $settings['twilio_sid'] . ':' . $token ) ),
				'body'                => array(
					'To'   => $phone,
					'From' => $settings['twilio_from'],
					'Body' => $message,
				),
			)
		);
		$body     = is_wp_error( $response ) ? array() : json_decode( wp_remote_retrieve_body( $response ), true );
		return ! is_wp_error( $response ) && 201 === wp_remote_retrieve_response_code( $response ) && ! empty( $body['sid'] ) ? true : new WP_Error( 'delivery', 'SMS delivery was not accepted. Check your provider configuration.' );
	}
	/**
	 * Reserve cooldown and attempt budget, hash a code, and deliver it.
	 *
	 * @param mixed $user_id user id value.
	 * @param mixed $method method value.
	 * @param mixed $destination destination value.
	 * @param mixed $purpose purpose value.
	 * @param mixed $binding binding value.
	 */
	public static function send( $user_id, $method, $destination, $purpose, $binding = '' ) {
		$policy = self::settings();
		if ( ! in_array( $method, array( 'email', 'sms' ), true ) || ! $policy[ $method ] ) {
			return new WP_Error( 'disabled', 'This recovery method is disabled by the administrator.' ); }
		if ( 'email' === $method ? ! is_email( $destination ) : ! preg_match( '/^\+[1-9][0-9]{7,14}$/D', $destination ) ) {
			return new WP_Error( 'destination', 'Enter a valid destination (SMS uses international E.164 format).' ); }
		$key = 'gwqsh_recovery_' . $purpose . '_' . $method;
		$old = get_user_meta( $user_id, $key, true );
		if ( is_array( $old ) && ( $old['sent'] ?? 0 ) > time() - 60 ) {
			return new WP_Error( 'cooldown', 'Wait 60 seconds before requesting another code.' ); }
		if ( ! GWQSH_Two_Factor::reserve_factor_attempt( $user_id ) ) {
			return new WP_Error( 'rate_limit', 'Too many recovery requests. Retry in five minutes.' ); }
		$code    = (string) random_int( 100000, 999999 );
		$data    = array(
			'hash'        => hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ),
			'expires'     => time() + 300,
			'sent'        => time(),
			'used'        => false,
			'method'      => $method,
			'destination' => $destination,
			'binding'     => $binding,
		);
		$written = '' === $old ? add_user_meta( $user_id, $key, $data, true ) : GWQSH_Two_Factor::compare_and_swap_meta( $user_id, $key, $old, $data );
		if ( ! $written ) {
			return new WP_Error( 'busy', 'A recovery request is already being processed.' ); }
		$message = 'Your ' . wp_specialchars_decode( get_bloginfo( 'name' ), ENT_QUOTES ) . ' security verification code is ' . $code . '. It expires in 5 minutes.';
		$result  = 'email' === $method ? wp_mail( $destination, 'Security verification code', $message ) : self::sms( $destination, $message );
		if ( true !== $result ) {
			$failed         = $data;
			$failed['used'] = true;
			GWQSH_Two_Factor::compare_and_swap_meta( $user_id, $key, $data, $failed );
			return is_wp_error( $result ) ? $result : new WP_Error( 'delivery', 'The email could not be sent. Check WordPress mail delivery.' ); }
		return array(
			'message'  => 'Code sent. It expires in 5 minutes; resend is available in 60 seconds.',
			'cooldown' => 60,
		);
	}
	/**
	 * Consume a valid, expiring recovery code with an atomic compare-and-swap.
	 *
	 * @param mixed       $user_id user id value.
	 * @param mixed       $code code value.
	 * @param mixed       $purpose purpose value.
	 * @param mixed       $binding binding value.
	 * @param string|null $method Method, or null to accept either enrolled backup.
	 */
	public static function verify( $user_id, $code, $purpose, $binding = '', $method = null ) {
		if ( null === $method ) {
			foreach ( array( 'email', 'sms' ) as $candidate ) {
				$result = self::verify( $user_id, $code, $purpose, $binding, $candidate );
				if ( $result ) {
					return $result;
				}
			} return false; }
		if ( ! in_array( $method, array( 'email', 'sms' ), true ) ) {
			return false; }
		$key = 'gwqsh_recovery_' . $purpose . '_' . $method;
		$old = get_user_meta( $user_id, $key, true );
		if ( ! is_array( $old ) || ! empty( $old['used'] ) || $old['expires'] < time() || ! preg_match( '/^[0-9]{6}$/D', $code ) || ! hash_equals( $old['binding'], $binding ) || ! self::settings()[ $old['method'] ] || ! hash_equals( $old['hash'], hash_hmac( 'sha256', $code, wp_salt( 'auth' ) ) ) ) {
			return false; }
		if ( 'login' === $purpose && ( 'email' === $old['method'] ? ! hash_equals( $old['destination'], (string) get_user_meta( $user_id, 'gwqsh_recovery_email_verified', true ) ) || ! hash_equals( $old['destination'], get_userdata( $user_id )->user_email ) : ! hash_equals( $old['destination'], (string) get_user_meta( $user_id, 'gwqsh_recovery_phone_verified', true ) ) ) ) {
			return false; }
		$new         = $old;
		$new['used'] = true;
		return GWQSH_Two_Factor::compare_and_swap_meta( $user_id, $key, $old, $new ) ? $old : false;
	}
	/**
	 * Execute an owner-bound management action after central AJAX authorization.
	 *
	 * @param mixed $action action value.
	 * @param array $input input value.
	 */
	public static function management( $action, array $input ) {
		$user = wp_get_current_user();
		if ( 'recovery_data' === $action ) {
			return self::data( $user->ID ); }
		if ( ! $user->ID || ! GWQSH_Two_Factor::reserve_factor_attempt( $user->ID ) || ! wp_check_password( $input['password'] ?? '', $user->user_pass, $user->ID ) ) {
			return new WP_Error( 'password', 'Enter your current password to manage recovery methods, or retry after the attempt cooldown.' ); }
		$method = $input['method'] ?? '';
		if ( ! in_array( $method, array( 'email', 'sms' ), true ) ) {
			return new WP_Error( 'method', 'Invalid recovery method.' ); }
		if ( 'recovery_setup_send' === $action ) {
			return self::send( $user->ID, $method, 'email' === $method ? $user->user_email : sanitize_text_field( $input['phone'] ?? '' ), 'setup', hash( 'sha256', $user->user_pass ) ); }
		if ( 'recovery_setup_verify' === $action ) {
			$data = self::verify( $user->ID, (string) ( $input['code'] ?? '' ), 'setup', hash( 'sha256', $user->user_pass ), $method );
			if ( ! $data || $method !== $data['method'] ) {
				return new WP_Error( 'invalid_code', 'The recovery code is invalid or expired.' ); }
			update_user_meta( $user->ID, 'email' === $method ? 'gwqsh_recovery_email_verified' : 'gwqsh_recovery_phone_verified', $data['destination'] );
		} elseif ( 'recovery_remove' === $action ) {
			delete_user_meta( $user->ID, 'email' === $method ? 'gwqsh_recovery_email_verified' : 'gwqsh_recovery_phone_verified' );
		} else {
			return new WP_Error( 'action', 'Invalid recovery action.' ); }
		GWQSH_Activity_Logger::log( 'Recovery method changed', $method . ' backup ' . ( 'recovery_remove' === $action ? 'removed' : 'verified' ), 'Security', $user->user_login );
		return self::data( $user->ID );
	}
	/** Send a backup code only for a password-issued, client-bound challenge. */
	public static function login_send() {
		if ( false === check_ajax_referer( 'gwqsh_login_factor', 'nonce', false ) ) {
			wp_send_json_error( array( 'message' => 'Reload the login page.' ), 403 ); }
		$token  = isset( $_POST['challenge'] ) && is_string( $_POST['challenge'] ) ? sanitize_text_field( wp_unslash( $_POST['challenge'] ) ) : '';
		$method = isset( $_POST['method'] ) && is_string( $_POST['method'] ) ? sanitize_key( $_POST['method'] ) : '';
		$data   = preg_match( '/^[a-f0-9]{64}$/D', $token ) ? get_transient( 'gwqsh_2fa_challenge_' . hash( 'sha256', $token ) ) : false;
		if ( ! is_array( $data ) || $data['expires'] < time() || $data['attempts'] >= 5 || ! hash_equals( $data['ip'], hash( 'sha256', GWQSH_Settings::get_client_ip() ) ) || ! hash_equals( $data['factor'], hash( 'sha256', (string) get_user_meta( $data['user_id'], 'gwqsh_2fa_secret', true ) ) ) ) {
			wp_send_json_error( array( 'message' => 'Sign in with your password first.' ), 403 ); }
		$destination = 'email' === $method ? get_user_meta( $data['user_id'], 'gwqsh_recovery_email_verified', true ) : get_user_meta( $data['user_id'], 'gwqsh_recovery_phone_verified', true );
		if ( ! $destination || ( 'email' === $method && get_userdata( $data['user_id'] )->user_email !== $destination ) ) {
			wp_send_json_error( array( 'message' => 'This backup method has not been verified.' ), 400 ); }
		$result = self::send( $data['user_id'], $method, $destination, 'login', hash( 'sha256', $token ) );
		if ( is_wp_error( $result ) ) {
			wp_send_json_error( array( 'message' => $result->get_error_message() ), 400 ); }
		wp_send_json_success( $result );
	}
}
