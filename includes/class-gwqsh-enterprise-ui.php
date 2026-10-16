<?php
/** Existing-card disclosures and one-use authenticated enterprise administration.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Enterprise ui service. */
final class GWQSH_Enterprise_UI {
	/**
	 * Init.
	 *
	 * @return mixed Operation result.
	 */
	public static function init() {
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );}
	/**
	 * Assets.
	 *
	 * @return mixed Operation result.
	 */
	public static function assets() {
		if ( ! GWQSH_Admin::current_page() ) {
			return;
		}wp_enqueue_script( 'gwqsh-enterprise', GWQSH_URL . 'assets/js/enterprise.js', array( 'gwqsh-core' ), (string) filemtime( GWQSH_PATH . 'assets/js/enterprise.js' ), true );}
	/**
	 * Title.
	 *
	 * @param mixed $section Section.
	 * @return mixed Operation result.
	 */
	public static function title( $section ) {
		return array(
			'geo'        => 'Country restrictions',
			'reputation' => 'IP reputation',
			'alerts'     => 'Security alert delivery',
			'shipping'   => 'External audit log shipping',
			'privacy'    => 'Privacy & data minimization',
			'waf'        => 'Firewall mode & additional rules',
			'signatures' => 'Signed malware signature updates',
			'license'    => 'License connection',
		)[ $section ] ?? $section;}
	/**
	 * Render.
	 *
	 * @param mixed $section Section.
	 * @param mixed $context Context.
	 * @return mixed Operation result.
	 */
	public static function render( $section, $context = 'settings' ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return;
		}$schema = GWQSH_Enterprise_Config::schema()[ $section ] ?? null;
		if ( ! $schema ) {
			return;
		}$settings = GWQSH_Enterprise_Config::get( $section );
		if ( 'reputation' === $section ) {
			$schema = array_intersect_key( $schema, array_flip( 'login' === $context ? array( 'blocking', 'threshold' ) : array( 'enabled', 'key' ) ) );
		}
		if ( 'signatures' === $section && 'integrity' === $context ) {
			$schema = array();
		}
		echo '<details class="qs-enterprise"><summary>' . esc_html( self::title( $section ) ) . '</summary>';
		if ( 'reputation' === $section ) {
			echo '<p>Opt-in AbuseIPDB lookups send public visitor IPs. Uncached requests continue; only validated cached matches can be blocked. Credentials or a registered provider are required.</p>';
		}
		if ( 'geo' === $section ) {
			echo '<p>Rules apply after authentication. Country lookup requires consent in Settings. Use the existing visitor allowlist for trusted IP overrides. Emergency recovery: define GWQSH_DISABLE_ENTERPRISE as true in wp-config.php. Cloudflare headers require fresh verified Cloudflare ranges.</p>';
		}
		if ( 'waf' === $section ) {
			echo '<p>WordPress-level inspection only. Existing reviewed rules retain their behavior. Additional rules default to report-only until explicitly enforced. The existing firewall master switch must also be enabled.</p><p>Authenticated payload inspection is separate and defaults to detection only. It reads bounded, non-credential parameters of your own logged-in requests; findings record the parameter name and rule, never the submitted value. Enforcing blocks matching requests on ordinary endpoints only: post editors, media and other content-authoring endpoints are never denied, and an exempted rule stops being inspected entirely.</p>';
		}
		if ( 'signatures' === $section ) {
			$db = GWQSH_Signatures::database();
			echo '<p>' . esc_html( GWQSH_Signatures::available() ? 'Trusted feed configured.' : 'Inactive: configure an official HTTPS feed and trusted Ed25519 publisher key in wp-config.php. No live publisher is bundled.' ) . '</p><p>Verified database version: ' . esc_html( (string) ( $db['version'] ?? 0 ) ) . ' &middot; ' . esc_html( empty( $db['verified_at'] ) ? 'Never updated' : GWQSH_Time::format( $db['verified_at'] ) ) . '</p>';}
		if ( 'license' === $section ) {
			echo '<p>Status: ' . esc_html( GWQSH_License::status()['state'] ) . '. An official provider adapter is required. Expiry and outages never disable existing security protection.</p>';
		}
		if ( 'shipping' === $section ) {
			echo '<p>Production collector: Datadog Logs (US/EU). Only minimized structured events are sent. No raw request body, secrets or session material is shipped.</p>';
		}
		if ( 'alerts' === $section ) {
			echo '<p>Delivery is queued and deduplicated. Slack remains inactive without a valid incoming webhook. Live delivery may be tested only after configuration.</p>';
		}
		if ( in_array( $section, array( 'alerts', 'shipping' ), true ) ) {
			echo '<p>Delivery audit: ';
			foreach ( GWQSH_Events::status() as $row ) {
				echo esc_html( $row['status'] . ': ' . $row['count'] ) . ' ';
			}echo '</p>';}
		echo '<form data-enterprise-section="' . esc_attr( $section ) . '"><div class="gwqsh-form-grid">';
		foreach ( $schema as $key => $f ) {
			$id = 'gwqsh-enterprise-' . $section . '-' . $key;
			echo '<label for="' . esc_attr( $id ) . '">' . esc_html( $f[2] );
			if ( 'bool' === $f[0] || 'select' === $f[0] ) {
				$options = 'bool' === $f[0] ? array(
					'0' => 'Disabled',
					'1' => 'Enabled',
				) : $f[3];
				echo '<select id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" data-type="' . esc_attr( $f[0] ) . '">';
				foreach ( $options as $v => $label ) {
							echo '<option value="' . esc_attr( (string) $v ) . '" ' . selected( (string) $settings[ $key ], (string) $v, false ) . '>' . esc_html( $label ) . '</option>';
				}echo '</select>';} elseif ( 'secret' === $f[0] ) {
				echo '<input id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" type="password" autocomplete="new-password" value="" data-type="secret"><small>' . esc_html( GWQSH_Enterprise_Config::has_secret( $section, $key ) ? 'Stored securely. Leave blank to keep; use Revoke to remove.' : 'Not configured.' ) . '</small><span><input type="checkbox" data-clear-secret="' . esc_attr( $key ) . '" aria-label="' . esc_attr( 'Revoke ' . $f[2] ) . '"> Revoke credential</span>';} elseif ( in_array( $f[0], array( 'countries', 'events', 'paths', 'hashes' ), true ) ) {
						echo '<textarea id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" rows="2">' . esc_textarea( $settings[ $key ] ) . '</textarea>';
				} else {
					echo '<input id="' . esc_attr( $id ) . '" name="' . esc_attr( $key ) . '" type="' . esc_attr( $f[0] ) . '" value="' . esc_attr( (string) $settings[ $key ] ) . '" data-type="' . esc_attr( $f[0] ) . '"' . ( 'number' === $f[0] ? ' min="' . esc_attr( (string) $f[3][0] ) . '" max="' . esc_attr( (string) $f[3][1] ) . '"' : '' ) . '>';
				}
				echo '</label>';
		}
		echo '</div><div class="gwqsh-form-grid"><label>Current password<input type="password" autocomplete="current-password" data-enterprise-password required></label><label>Authenticator or backup code (if 2FA enrolled)<input autocomplete="one-time-code" data-enterprise-factor></label></div><div class="gwqsh-config-actions">' . ( $schema ? '<button type="submit" class="btn btn-primary btn-sm">Save configuration</button>' : '' ) . ' ';
		$actions = array(
			'alerts'     => array(
				'test_email' => 'Test email',
				'test_slack' => 'Test Slack',
			),
			'shipping'   => array( 'test_collector' => 'Test collector' ),
			'signatures' => array( 'signature_update' => 'Update verified signatures' ),
			'geo'        => array( 'refresh_cloudflare' => 'Refresh Cloudflare ranges' ),
			'license'    => array(
				'license_activate'   => 'Activate',
				'license_refresh'    => 'Refresh',
				'license_deactivate' => 'Deactivate',
			),
		);
		foreach ( $actions[ $section ] ?? array() as $action => $label ) {
			echo '<button type="button" class="btn btn-outline btn-sm" data-enterprise-action="' . esc_attr( $action ) . '">' . esc_html( $label ) . '</button>';
		}
		echo '</div><p data-enterprise-status role="status"></p></form></details>';
	}
	/**
	 * Authorize.
	 *
	 * @param mixed $password Password.
	 * @param mixed $code Code.
	 * @return mixed Operation result.
	 */
	public static function authorize( $password, $code ) {
		$user = wp_get_current_user();
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}$count = GWQSH_Enterprise_Store::hit( 'enterprise-verify', $user->ID, 300 );
		if ( ! $user->ID || null === $count || $count > 10 || ! wp_check_password( $password, $user->user_pass, $user->ID ) ) {
			return new WP_Error( 'verification', 'Verify your current password or wait for the verification cooldown.' );
		}
		if ( GWQSH_Two_Factor::effective_enabled( $user->ID ) && ! GWQSH_Two_Factor::consume_totp( $user->ID, $code ) && ! GWQSH_Two_Factor::verify_and_burn_backup_code( $user->ID, $code ) ) {
			return new WP_Error( 'factor', 'Enter a current authenticator code or unused backup code.' );
		}
		return GWQSH_Passkeys::issue(
			array(
				'purpose'     => 'enterprise-mutation',
				'user_id'     => $user->ID,
				'session'     => hash( 'sha256', wp_get_session_token() ),
				'fingerprint' => hash( 'sha256', $user->user_pass ),
			),
			120
		);
	}

	/** Validate one-use recent verification before high-risk state changes.
	 *
	 * @param mixed $token Password/factor-issued operation token.
	 * @return true|WP_Error Verification result.
	 */
	public static function consume_proof( $token ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' ); }
		try {
			$proof = GWQSH_Passkeys::consume( $token, 'enterprise-mutation' );
			$user  = wp_get_current_user();
			if ( $proof['user_id'] !== $user->ID || ! hash_equals( $proof['session'], hash( 'sha256', wp_get_session_token() ) ) || ! hash_equals( $proof['fingerprint'], hash( 'sha256', $user->user_pass ) ) ) {
				return new WP_Error( 'binding', 'Verification session changed.' );
			}
		} catch ( Throwable $error ) {
			return new WP_Error( 'verification', 'Verify again; the one-use authorization expired or was consumed.' );}
		return true;
	}
	/**
	 * Execute.
	 *
	 * @param mixed $input Input.
	 * @return mixed Operation result.
	 */
	public static function execute( $input ) {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return new WP_Error( 'permission', 'Administrative permission required.' );
		}
		$verified = self::consume_proof( $input['operation_token'] ?? '' );
		if ( is_wp_error( $verified ) ) {
			return $verified; }
		$action = $input['operation'] ?? '';
		if ( 'save' === $action ) {
			$data = json_decode( $input['settings'] ?? '', true );
			if ( ! is_array( $data ) ) {
				return new WP_Error( 'settings', 'Invalid settings.' );
			}$result = GWQSH_Enterprise_Config::save( $input['section'] ?? '', $data );
			if ( ! is_wp_error( $result ) && 'signatures' === ( $input['section'] ?? '' ) ) {
				wp_clear_scheduled_hook( 'gwqsh_update_signatures' );
				if ( $data['enabled'] && GWQSH_Signatures::available() ) {
					$scheduled = wp_schedule_event( time() + HOUR_IN_SECONDS, 'daily', 'gwqsh_update_signatures', array(), true );
					if ( is_wp_error( $scheduled ) || ! $scheduled ) {
						return new WP_Error( 'schedule', 'Settings saved, but signature scheduling failed. Retry or check WP-Cron.' ); }
				}
			}
			return $result;}
		if ( 'wizard' === $action ) {
			$data = json_decode( $input['settings'] ?? '', true );
			return is_array( $data ) ? GWQSH_Setup_Wizard::save( $data ) : new WP_Error( 'wizard', 'Invalid checkpoint.' );}
		if ( 'signature_update' === $action ) {
			return GWQSH_Signatures::update();
		}
		if ( 'refresh_cloudflare' === $action ) {
			return GWQSH_Country_Access::refresh_cloudflare();
		}
		if ( in_array( $action, array( 'license_activate', 'license_deactivate', 'license_refresh' ), true ) ) {
			return GWQSH_License::operate( substr( $action, 8 ) );
		}
		if ( in_array( $action, array( 'test_email', 'test_slack', 'test_collector' ), true ) ) {
			$channel = substr( $action, 5 );
			$cfg     = GWQSH_Enterprise_Config::get( 'collector' === $channel ? 'shipping' : 'alerts' );
			if ( ! $cfg['enabled'] || ( 'collector' !== $channel && empty( $cfg[ $channel ] ) ) || ( 'slack' === $channel && ! GWQSH_Enterprise_Config::has_secret( 'alerts', 'slack_url' ) ) || ( 'collector' === $channel && ! GWQSH_Enterprise_Config::has_secret( 'shipping', 'key' ) ) ) {
				return new WP_Error( 'inactive', 'Configure and enable this delivery channel before testing.' ); }
			return GWQSH_Events::enqueue(
				substr( $action, 5 ),
				array(
					'event_id'  => wp_generate_uuid4(),
					'event'     => 'Administrator-requested test notification',
					'timestamp' => gmdate( 'c' ),
					'category'  => 'configuration',
					'severity'  => 'Informational',
					'site_id'   => hash( 'sha256', home_url() ),
					'ip'        => '',
					'user'      => 'redacted',
				),
				60
			);
		}
		return new WP_Error( 'action', 'Unknown enterprise operation.' );
	}
	/**
	 * Wizard.
	 *
	 * @return mixed Operation result.
	 */
	public static function wizard() {
		if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
			return;
		}$s = GWQSH_Setup_Wizard::state();
		echo '<details class="qs-enterprise" id="gwqsh-setup-wizard"><summary>Optional security setup checklist</summary><p>Resume this guided checklist at any time. Existing configuration is never overwritten. Review and save each setting on its dedicated page.</p><form data-enterprise-wizard data-step="' . esc_attr( (string) $s['step'] ) . '"><div data-wizard-step></div><div class="gwqsh-config-actions"><button type="button" class="btn btn-outline btn-sm" data-wizard-prev>Previous</button><button type="submit" class="btn btn-primary btn-sm">Save &amp; next</button></div><p data-enterprise-status role="status">' . esc_html( $s['completed'] ? 'Checklist completed.' : 'Optional; no settings applied automatically.' ) . '</p></form></details>';
	}
}
