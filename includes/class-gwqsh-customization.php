<?php
/**
 * Explicit settings schemas, portable exports and section resets.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Customization service. */
final class GWQSH_Customization {
	/** Register the service hooks. */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'register' ) ); }
	/** Register the validated WordPress option schema. */
	public static function register() {
		register_setting(
			'gwqsh_settings_group',
			'gwqsh_settings',
			array(
				'type'              => 'array',
				'sanitize_callback' => array( 'GWQSH_Settings', 'normalize' ),
				'show_in_rest'      => false,
				'default'           => GWQSH_Settings::get_defaults(),
			)
		);
	}
	/** Describe supported settings fields and their validation constraints. */
	public static function schema() {
		$role_fields = array();
		foreach ( wp_roles()->roles as $role => $info ) {
			$role_fields[ 'role__' . $role ] = array( translate_user_role( $info['name'] ) . ' login protection', 'bool' ); }
		$factor_roles = array();
		foreach ( wp_roles()->roles as $role => $info ) {
			$factor_roles[ 'role__' . $role ] = array( translate_user_role( $info['name'] ) . ' authenticator requirement', 'bool' ); }
		$hardening_fields = array();
		foreach ( GWQSH_Hardening::get_defaults() as $key => $value ) {
			$hardening_fields[ $key ] = array(
				array(
					'xmlrpc'  => 'Disable XML-RPC',
					'editor'  => 'Disable file editor',
					'version' => 'Hide version metadata',
					'enum'    => 'Block user enumeration',
					'headers' => 'Enable security headers',
					'uploads' => 'Uploads execution protection',
				)[ $key ],
				'bool',
			); }
		return array(
			'access'          => array(
				'title'  => 'Login access & visitor trust',
				'fields' => array(
					'custom_slug'          => array( 'Custom login path', 'text' ),
					'custom_slug_enabled'  => array( 'Enable custom login URL', 'bool' ),
					'guest_login_behavior' => array(
						'Guest access to wp-login.php',
						'select',
						array(
							'home' => 'Redirect to homepage',
							'404'  => '404 — Not Found',
						),
					),
					'guest_admin_behavior' => array(
						'Guest access to wp-admin',
						'select',
						array(
							'home'  => 'Redirect to homepage',
							'login' => 'Require login',
						),
					),
					'allowlist'            => array( 'Trusted visitor IPs / CIDRs (one per line)', 'textarea' ),
				),
			),
			'roles'           => array(
				'title'  => 'Per-role login protection',
				'fields' => $role_fields,
			),
			'hardening'       => array(
				'title'  => 'WordPress hardening',
				'fields' => $hardening_fields,
			),
			'general'         => array(
				'title'  => 'General',
				'fields' => array(
					'status'    => array( 'Enable security engine', 'bool' ),
					'retention' => array( 'Log retention (days; 0 keeps logs)', 'number', 0, 3650 ),
				),
			),
			'security'        => array(
				'title'  => 'Security & trusted networks',
				'fields' => array(
					'proxy'           => array( 'Enable trusted forwarded headers', 'bool' ),
					'proxyheader'     => array(
						'Trusted header',
						'select',
						array(
							'xff'        => 'X-Forwarded-For',
							'cf'         => 'CF-Connecting-IP',
							'xreal'      => 'X-Real-IP',
							'trueclient' => 'True-Client-IP',
						),
					),
					'trusted_proxies' => array( 'Trusted proxy addresses / CIDRs (one per line)', 'textarea' ),
					'geo_enabled'     => array( 'Resolve public IP countries with ipwho.is (sends IPs to provider)', 'bool' ),
				),
			),
			'login'           => array(
				'title'  => 'Login Protection',
				'fields' => array(
					'enabled'          => array( 'Enable login rate limiting', 'bool' ),
					'max_attempts'     => array( 'Failed attempt threshold', 'number', 1, 100 ),
					'time_window'      => array( 'Attempt window (minutes)', 'number', 1, 1440 ),
					'lockout_duration' => array( 'Lockout duration (minutes)', 'number', 1, 10080 ),
					'repeat_lockouts'  => array( 'Repeat lockout threshold', 'number', 1, 100 ),
					'repeat_duration'  => array( 'Repeat lockout duration (hours)', 'number', 1, 720 ),
					'generic_errors'   => array( 'Use generic login errors', 'bool' ),
					'track_username'   => array( 'Record attempted usernames', 'bool' ),
				),
			),
			'twofactor'       => array(
				'title'  => 'Two-Factor policy',
				'fields' => array(
					'require_admin'     => array( 'Require administrator authenticator enrollment', 'bool' ),
					'remember_device'   => array( 'Allow verified remembered devices', 'bool' ),
					'allow_admin_reset' => array( 'Allow administrator enrollment resets', 'bool' ),
					'allow_roles'       => array( 'Allow optional enrollment for other roles', 'bool' ),
					'enforce_roles'     => array( 'Enforce the selected role enrollment requirements', 'bool' ),
				),
			),
			'twofactor_roles' => array(
				'title'  => 'Two-Factor role requirements',
				'fields' => $factor_roles,
			),
			'firewall'        => array(
				'title'  => 'Firewall',
				'fields' => array(
					'enabled' => array( 'Enable public query firewall', 'bool' ),
					'sql'     => array( 'SQL injection rules', 'bool' ),
					'xss'     => array( 'XSS rules', 'bool' ),
					'bots'    => array( 'Exploit scanner correlation', 'bool' ),
				),
			),
			'notifications'   => array(
				'title'  => 'Notifications',
				'fields' => array(
					'notice' => array( 'Show critical finding notices elsewhere in WordPress', 'bool' ),
					'tips'   => array( 'Show security help tips', 'bool' ),
				),
			),
			'appearance'      => array(
				'title'  => 'Appearance',
				'fields' => array(
					'theme'          => array(
						'Theme',
						'select',
						array(
							'light'  => 'Light',
							'dark'   => 'Dark',
							'system' => 'System',
						),
					),
					'compact'        => array( 'Compact density', 'bool' ),
					'anim'           => array( 'Enable interface motion', 'bool' ),
					'hero_animation' => array( 'Enable decorative WebGL birds (uses more resources)', 'bool' ),
				),
			),
			'performance'     => array(
				'title'  => 'Performance',
				'fields' => array( 'scan_budget' => array( 'Scan work budget per batch (seconds)', 'number', 1, 8 ) ),
			),
			'advanced'        => array(
				'title'  => 'Advanced',
				'fields' => array( 'uninstall' => array( 'Delete plugin data when uninstalling', 'bool' ) ),
			),
			'integrations'    => array(
				'title'  => 'Passkey, email & SMS integrations',
				'fields' => array(
					'passkeys'     => array( 'Allow passkeys (HTTPS required)', 'bool' ),
					'email'        => array( 'Allow verified account email backup codes', 'bool' ),
					'sms'          => array( 'Allow verified SMS backup codes', 'bool' ),
					'sms_provider' => array( 'SMS provider identifier (twilio or registered provider)', 'text' ),
					'twilio_sid'   => array( 'Twilio account SID', 'text' ),
					'twilio_from'  => array( 'Twilio sender number (E.164)', 'text' ),
					'twilio_token' => array( 'Twilio auth token (leave blank to keep stored token)', 'password' ),
				),
			),
		);
	}
	/**
	 * Return public settings for a known configuration section.
	 *
	 * @param mixed $section section value.
	 */
	public static function values( $section ) {
		if ( in_array( $section, array( 'roles', 'twofactor_roles' ), true ) ) {
			$values = array();
			$policy = GWQSH_Two_Factor::get_settings();
			$login  = GWQSH_Login_Protection::get_settings();
			foreach ( wp_roles()->roles as $role => $info ) {
				$values[ 'role__' . $role ] = 'roles' === $section ? ( $login['role_protection'][ $role ] ?? true ) : in_array( $role, $policy['required_roles'], true );
			}
		} elseif ( 'hardening' === $section ) {
			$values = GWQSH_Hardening::get_all();
		} elseif ( 'access' === $section ) {
			$values              = GWQSH_Login_Protection::get_settings();
			$values['allowlist'] = implode( "\n", GWQSH_Login_Protection::get_allowlist() );
		} elseif ( 'login' === $section ) {
			$values = GWQSH_Login_Protection::get_settings();
		} elseif ( 'twofactor' === $section ) {
			$values = GWQSH_Two_Factor::get_settings();
		} elseif ( 'firewall' === $section ) {
			$values = GWQSH_Firewall::settings();
		} elseif ( 'integrations' === $section ) {
			$values = GWQSH_Recovery::public_settings();
		} else {
			$values = GWQSH_Settings::get_all();
		}
		unset( $values['twilio_token'] );
		return array_intersect_key( $values, self::schema()[ $section ]['fields'] ?? array() );
	}

	/** Export portable configuration without credentials or user enrollment. */
	public static function export() {
		$sections = array();
		foreach ( self::schema() as $key => $schema ) {
			$sections[ $key ] = self::values( $key ); }
		$sections['scan_schedule'] = GWQSH_Scheduler::settings();
		foreach ( GWQSH_Enterprise_Config::schema() as $section => $fields ) {
			$values = GWQSH_Enterprise_Config::get( $section );
			foreach ( $fields as $key => $field ) { if ( 'secret' === $field[0] ) { unset( $values[ $key ] ); } }
			$sections[ 'enterprise__' . $section ] = $values;
		}
		return array(
			'plugin'   => 'gracewell-security-suite-pro',
			'format'   => 2,
			'version'  => GWQSH_VERSION,
			'exported' => gmdate( 'c' ),
			'sections' => $sections,
		);
	}
	/**
	 * Validate configuration without writing to storage.
	 *
	 * @param mixed $section section value.
	 * @param array $input input value.
	 */
	public static function validate( $section, array $input ) {
		$schema = self::schema();
		if ( ! isset( $schema[ $section ] ) ) {
			return new WP_Error( 'section', 'Unknown settings section.' ); }
		$out = array();
		foreach ( $input as $key => $value ) {
			if ( ! isset( $schema[ $section ]['fields'][ $key ] ) ) {
				continue; }
			$field = $schema[ $section ]['fields'][ $key ];
			if ( ! is_scalar( $value ) || strlen( (string) $value ) > 8192 ) {
				return new WP_Error( 'value', 'Invalid value for ' . $field[0] ); }
			if ( 'bool' === $field[1] ) {
				if ( ! is_bool( $value ) ) {
					return new WP_Error( 'value', 'Use a boolean for ' . $field[0] );
				} $out[ $key ] = $value; } elseif ( 'number' === $field[1] ) {
				if ( ! is_numeric( $value ) || floor( (float) $value ) !== (float) $value || $value < $field[2] || $value > $field[3] ) {
					return new WP_Error( 'value', 'Enter a value between ' . $field[2] . ' and ' . $field[3] . ' for ' . $field[0] );
				} $out[ $key ] = (int) $value; } elseif ( 'select' === $field[1] ) {
					if ( ! isset( $field[2][ $value ] ) ) {
						return new WP_Error( 'value', 'Invalid selection for ' . $field[0] );
					} $out[ $key ] = $value; } elseif ( 'password' === $field[1] ) {
					$out[ $key ] = (string) $value; } else {
						$out[ $key ] = 'textarea' === $field[1] ? sanitize_textarea_field( $value ) : sanitize_text_field( $value ); }
		}
		if ( isset( $out['trusted_proxies'] ) ) {
			foreach ( preg_split( '/[\s,]+/', $out['trusted_proxies'], -1, PREG_SPLIT_NO_EMPTY ) as $range ) {
				if ( ! GWQSH_Network::matches( explode( '/', $range )[0], $range ) ) {
					return new WP_Error( 'proxy', 'Invalid trusted proxy address or CIDR.' ); }
			}
		}
		if ( ! empty( $out['proxy'] ) && empty( $out['trusted_proxies'] ) && ! GWQSH_Network::trusted() ) {
			return new WP_Error( 'proxy', 'Configure trusted proxies before enabling forwarded headers.' ); }
		if ( 'access' === $section ) {
			if ( isset( $out['custom_slug'] ) && ! GWQSH_Login_Protection::valid_slug( $out['custom_slug'] ) ) {
				return new WP_Error( 'slug', 'Choose an unused, valid custom login path.' ); }
			if ( isset( $out['allowlist'] ) ) {
				foreach ( preg_split( '/[\s,]+/', $out['allowlist'], -1, PREG_SPLIT_NO_EMPTY ) as $range ) {
					if ( ! GWQSH_Network::matches( explode( '/', $range )[0], $range ) ) {
						return new WP_Error( 'allowlist', 'Invalid trusted visitor IP or CIDR.' ); }
				}
			}
		}
		if ( 'integrations' === $section ) {
			if ( ! empty( $out['twilio_sid'] ) && ! preg_match( '/^AC[a-fA-F0-9]{32}$/D', $out['twilio_sid'] ) ) {
				return new WP_Error( 'sid', 'Invalid Twilio account SID.' ); }
			if ( ! empty( $out['twilio_from'] ) && ! preg_match( '/^\+[1-9][0-9]{7,14}$/D', $out['twilio_from'] ) ) {
				return new WP_Error( 'phone', 'Invalid sender number.' ); }
			if ( isset( $out['sms_provider'] ) && ! preg_match( '/^[a-z][a-z0-9_-]{0,39}$/D', $out['sms_provider'] ) ) {
				return new WP_Error( 'provider', 'Invalid provider identifier.' ); }
		}
		return $out;
	}
	/**
	 * Persist validated service configuration.
	 *
	 * @param mixed $section section value.
	 * @param array $input input value.
	 */
	public static function save( $section, array $input ) {
		$data = self::validate( $section, $input );
		if ( is_wp_error( $data ) ) {
			return $data; }
		if ( 'twofactor_roles' === $section ) {
			$policy                   = GWQSH_Two_Factor::get_settings();
			$policy['required_roles'] = array();
			foreach ( $data as $key => $state ) {
				if ( $state ) {
					$policy['required_roles'][] = substr( $key, 6 ); }
			}
			update_option( 'gwqsh_two_factor_settings', $policy, false );
		} elseif ( 'roles' === $section ) {
			$rules = array();
			foreach ( $data as $key => $state ) {
				$rules[ substr( $key, 6 ) ] = $state; }
			GWQSH_Login_Protection::update_settings( array( 'role_protection' => $rules ) );
		} elseif ( 'hardening' === $section ) {
			foreach ( $data as $key => $state ) {
				if ( ! GWQSH_Hardening::set( $key, $state ) && GWQSH_Hardening::get_all()[ $key ] !== $state ) {
					return new WP_Error( 'hardening', 'Unable to apply a hardening rule. Check server permissions.' ); }
			}
		} elseif ( 'access' === $section ) {
			$prior  = GWQSH_Login_Protection::get_settings();
			$access = $data;
			unset( $access['allowlist'] );
			GWQSH_Login_Protection::update_settings( $access );
			if ( isset( $data['allowlist'] ) ) {
				update_option( 'gwqsh_allowlist', preg_split( '/[\s,]+/', $data['allowlist'], -1, PREG_SPLIT_NO_EMPTY ), false );
				$data['allowlist'] = implode( "\n", GWQSH_Login_Protection::get_allowlist() );
			}
			if ( ( $access['custom_slug'] ?? $prior['custom_slug'] ) !== $prior['custom_slug'] || ( $access['custom_slug_enabled'] ?? $prior['custom_slug_enabled'] ) !== $prior['custom_slug_enabled'] ) {
				GWQSH_Login_Protection::rotate_recovery_key(); }
		} elseif ( 'login' === $section ) {
			GWQSH_Login_Protection::update_settings( $data );
		} elseif ( 'twofactor' === $section ) {
			update_option( 'gwqsh_two_factor_settings', array_merge( GWQSH_Two_Factor::get_settings(), $data ), false );
		} elseif ( 'firewall' === $section ) {
			update_option( 'gwqsh_firewall', array_merge( GWQSH_Firewall::settings(), $data ), false );
		} elseif ( 'integrations' === $section ) {
			$result = GWQSH_Recovery::save_settings( $data );
			if ( is_wp_error( $result ) ) {
				return $result; }
		} else {
			GWQSH_Settings::update_all( $data );
		}
		$saved = self::values( $section );
		foreach ( $data as $key => $value ) {
			if ( 'twilio_token' !== $key && ( ! array_key_exists( $key, $saved ) || (string) $saved[ $key ] !== (string) $value ) ) {
				return new WP_Error( 'save_failed', 'Unable to persist ' . self::schema()[ $section ]['title'] . '. Reload and retry.' ); }
		}
		GWQSH_Activity_Logger::log( 'Settings section changed', self::schema()[ $section ]['title'], 'System' );
		return $saved;
	}

	/**
	 * Reset the selected configuration to safe defaults.
	 *
	 * @param mixed $section section value.
	 */
	public static function reset( $section ) {
		if ( 'scan_schedule' === $section ) {
			return GWQSH_Scheduler::save(
				array(
					'enabled'   => false,
					'frequency' => 'daily',
					'type'      => 'full',
					'scopes'    => array( 'Core', 'Plugin', 'Theme', 'Uploads' ),
				)
			); }
		$schema = self::schema();
		if ( ! isset( $schema[ $section ] ) ) {
			return new WP_Error( 'section', 'Unknown section.' ); }
		if ( 'roles' === $section ) {
			$defaults = array_fill_keys( array_keys( $schema[ $section ]['fields'] ), true ); } elseif ( 'hardening' === $section ) {
			$defaults = GWQSH_Hardening::get_defaults(); } elseif ( 'access' === $section ) {
				$defaults              = GWQSH_Login_Protection::get_defaults();
				$defaults['allowlist'] = ''; } elseif ( 'login' === $section ) {
				$defaults = GWQSH_Login_Protection::get_defaults(); } elseif ( 'twofactor' === $section ) {
					$defaults = array(
						'require_admin'     => false,
						'remember_device'   => true,
						'allow_admin_reset' => true,
						'enforce_roles'     => false,
						'allow_roles'       => true,
					); } elseif ( 'firewall' === $section ) {
					$defaults = array(
						'enabled' => false,
						'sql'     => true,
						'xss'     => true,
						'bots'    => true,
					); } elseif ( 'integrations' === $section ) {
						$defaults = array(
							'passkeys'     => true,
							'email'        => false,
							'sms'          => false,
							'sms_provider' => 'twilio',
							'twilio_sid'   => '',
							'twilio_from'  => '',
						); } else {
						$defaults = GWQSH_Settings::get_defaults(); }
						$result = self::save( $section, array_intersect_key( $defaults, $schema[ $section ]['fields'] ) );
						if ( 'integrations' === $section && ! is_wp_error( $result ) ) {
							$saved = self::settings_without_token();
							update_option( 'gwqsh_recovery_settings', $saved, false ); }
						return $result;
	}
	/** Clear the provider token for an explicit section reset. */
	private static function settings_without_token() {
		$settings                 = GWQSH_Recovery::settings();
		$settings['twilio_token'] = '';
		return $settings; }
	/**
	 * Validate and apply a portable configuration export.
	 *
	 * @param array $payload payload value.
	 */
	public static function import( array $payload ) {
		if ( 'gracewell-security-suite-pro' !== ( $payload['plugin'] ?? '' ) || 2 !== ( $payload['format'] ?? 0 ) || ! is_array( $payload['sections'] ?? null ) ) {
			return new WP_Error( 'format', 'Choose a version 2 plugin configuration export.' ); }
		// Validate every section before writing; unknown keys are ignored and secrets excluded.
		foreach ( $payload['sections'] as $key => $values ) {
			if ( ! is_array( $values ) ) {
				return new WP_Error( 'format', 'Invalid section data.' ); }
			if ( 0 === strpos( $key, 'enterprise__' ) ) {
				$section = substr( $key, 12 );
				foreach ( $values as $field => $value ) { if ( '_clear' === $field || 'secret' === ( GWQSH_Enterprise_Config::schema()[ $section ][ $field ][0] ?? '' ) ) { return new WP_Error( 'credentials', 'Enterprise credentials cannot be imported.' ); } }
				$result = GWQSH_Enterprise_Config::validate( $section, $values, $payload['sections']['security']['geo_enabled'] ?? GWQSH_Settings::get( 'geo_enabled', false ) );
				if ( is_wp_error( $result ) ) { return $result; }
				continue;
			}
			if ( 'scan_schedule' === $key ) {
				$result = GWQSH_Scheduler::validate( $values );
				if ( is_wp_error( $result ) ) {
					return $result;
				} continue; }
			unset( $values['twilio_token'] );
			$result = self::validate( $key, $values );
			if ( is_wp_error( $result ) ) {
				return $result; }
		}
		foreach ( $payload['sections'] as $key => $values ) {
			unset( $values['twilio_token'] );
			$result = 0 === strpos( $key, 'enterprise__' ) ? GWQSH_Enterprise_Config::save( substr( $key, 12 ), $values ) : ( 'scan_schedule' === $key ? GWQSH_Scheduler::save( $values ) : self::save( $key, $values ) );
			if ( is_wp_error( $result ) ) {
				return $result; }
		}
		return self::export();
	}
}
