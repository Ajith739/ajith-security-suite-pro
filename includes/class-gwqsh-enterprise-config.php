<?php
/** Explicit enterprise settings schemas and encrypted service credentials.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Enterprise config service. */
final class GWQSH_Enterprise_Config {
	/**
	 * Schema.
	 *
	 * @return mixed Operation result.
	 */
	public static function schema() {
		return array(
			'geo'        => array(
				'enabled'   => array( 'bool', false, 'Enable country restrictions' ),
				'mode'      => array(
					'select',
					'deny',
					'Country policy',
					array(
						'deny'  => 'Block listed countries',
						'allow' => 'Allow listed countries',
					),
				),
				'countries' => array( 'countries', '', 'ISO country codes (comma separated)' ),
				'unknown'   => array(
					'select',
					'allow',
					'Unknown locations',
					array(
						'allow' => 'Allow and log',
						'deny'  => 'Deny guests; allow verified administrators',
					),
				),
				'public'    => array( 'bool', false, 'Also restrict unauthenticated public requests' ),
			),
			'reputation' => array(
				'enabled'   => array( 'bool', false, 'Enable AbuseIPDB lookups (sends public visitor IPs)' ),
				'blocking'  => array( 'bool', false, 'Block cached high-confidence matches' ),
				'threshold' => array( 'number', 90, 'Abuse confidence threshold', array( 50, 100 ) ),
				'key'       => array( 'secret', '', 'AbuseIPDB API key' ),
			),
			'alerts'     => array(
				'enabled'            => array( 'bool', false, 'Enable queued security alerts' ),
				'email'              => array( 'bool', false, 'Deliver email alerts' ),
				'recipient'          => array( 'email', '', 'Administrator recipient email' ),
				'slack'              => array( 'bool', false, 'Deliver Slack alerts' ),
				'slack_url'          => array( 'secret', '', 'Slack incoming webhook URL' ),
				'events'             => array( 'events', 'lockout,admin,role,file,malware,firewall,scan_failure,scan_findings,configuration,critical', 'Event categories (comma separated)' ),
				'minimum'            => array(
					'select',
					'High',
					'Minimum severity',
					array(
						'Informational' => 'Informational',
						'Low'           => 'Low',
						'Medium'        => 'Medium',
						'High'          => 'High',
						'Critical'      => 'Critical',
					),
				),
				'cooldown'           => array( 'number', 300, 'Deduplication cooldown (seconds)', array( 60, 86400 ) ),
				'firewall_threshold' => array( 'number', 20, 'Firewall events per minute before alerting', array( 1, 10000 ) ),
			),
			'shipping'   => array(
				'enabled' => array( 'bool', false, 'Ship minimized events to Datadog Logs' ),
				'region'  => array(
					'select',
					'us',
					'Datadog region',
					array(
						'us' => 'US',
						'eu' => 'EU',
					),
				),
				'key'     => array( 'secret', '', 'Datadog API key' ),
				'minimum' => array(
					'select',
					'High',
					'Minimum severity',
					array(
						'Informational' => 'Informational',
						'Low'           => 'Low',
						'Medium'        => 'Medium',
						'High'          => 'High',
						'Critical'      => 'Critical',
					),
				),
				'events'  => array( 'events', 'lockout,admin,role,file,malware,firewall,scan_failure,scan_findings,configuration,critical', 'Event categories (comma separated)' ),
			),
			'privacy'    => array(
				'anonymize'          => array( 'bool', false, 'Anonymize new recorded IPs and remote events' ),
				'remote_identity'    => array( 'bool', false, 'Include account name in remote audit events' ),
				'erase'              => array( 'bool', true, 'Allow personal audit data anonymization through WordPress erasure tools' ),
				'delivery_retention' => array( 'number', 7, 'Delivery audit retention (days)', array( 1, 30 ) ),
			),
			'waf'        => array(
				'mode'        => array(
					'select',
					'block',
					'Firewall operation mode',
					array(
						'disabled' => 'Disabled',
						'report'   => 'Detection / report only',
						'block'    => 'Blocking / enforcement',
					),
				),
				'enforce_new' => array( 'bool', false, 'Enforce new rules (otherwise report only)' ),
				'traversal'   => array( 'bool', true, 'Path traversal detection' ),
				'inclusion'   => array( 'bool', true, 'File inclusion detection' ),
				'uploads'     => array( 'bool', true, 'Unauthenticated executable upload attempts' ),
				'post'        => array( 'bool', false, 'Inspect bounded noncredential POST values' ),
				'rate'        => array( 'bool', false, 'Enable unauthenticated request rate limit' ),
				'requests'    => array( 'number', 120, 'Requests per minute per IP', array( 10, 10000 ) ),
				'exclusions'  => array( 'paths', '', 'Excluded exact paths (one per line)' ),
			),
			'signatures' => array(
				'enabled'         => array( 'bool', false, 'Enable configured signed-feed updates' ),
				'excluded_hashes' => array( 'hashes', '', 'SHA-256 exclusions for signature rules only (one per line; heuristics continue)' ),
			),
			'license'    => array( 'key' => array( 'secret', '', 'License token (provider required)' ) ),
		);
	}
	/**
	 * Get.
	 *
	 * @param mixed $section Section.
	 * @return mixed Operation result.
	 */
	public static function get( $section ) {
		$all = (array) get_option( 'gwqsh_enterprise', array() );
		$out = array();
		foreach ( self::schema()[ $section ] ?? array() as $key => $field ) {
			$out[ $key ] = 'secret' === $field[0] ? '' : ( $all[ $section ][ $key ] ?? $field[1] );}
		return $out;
	}
	/**
	 * Secret.
	 *
	 * @param mixed $section Section.
	 * @param mixed $key Key.
	 * @return mixed Operation result.
	 */
	public static function secret( $section, $key ) {
		$all   = (array) get_option( 'gwqsh_enterprise_credentials', array() );
		$raw   = GWQSH_Crypto::decrypt( $all[ $section . '.' . $key ] ?? '' );
		$value = is_string( $raw ) ? json_decode( $raw, true ) : null;
		return is_array( $value ) && ( $value['purpose'] ?? '' ) === $section . '.' . $key ? (string) $value['secret'] : '';
	}
	/**
	 * Has secret.
	 *
	 * @param mixed $section Section.
	 * @param mixed $key Key.
	 * @return mixed Operation result.
	 */
	public static function has_secret( $section, $key ) {
		$all = (array) get_option( 'gwqsh_enterprise_credentials', array() );
		return ! empty( $all[ $section . '.' . $key ] );}
	/**
	 * Country codes.
	 *
	 * @return mixed Operation result.
	 */
	public static function country_codes() {
		return explode( ' ', 'AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW' );}
	/**
	 * Validate.
	 *
	 * @param mixed $section Section.
	 * @param array $input Input.
	 * @param mixed $geo_consent Prospective country lookup consent during an import.
	 * @return mixed Operation result.
	 */
	public static function validate( $section, array $input, $geo_consent = null ) {
		$schema = self::schema()[ $section ] ?? null;
		if ( ! $schema || array_diff( array_keys( $input ), array_merge( array_keys( $schema ), array( '_clear' ) ) ) ) {
			return new WP_Error( 'schema', 'Unknown configuration field.' );
		}
		$out = self::get( $section );
		foreach ( $input as $key => $value ) {
			if ( '_clear' === $key ) {
				continue;
			}$f   = $schema[ $key ];
			$type = $f[0];
			if ( 'bool' === $type ) {
				if ( ! is_bool( $value ) ) {
							return new WP_Error( 'type', 'Use explicit boolean settings.' );
				}
			} elseif ( 'number' === $type ) {
				if ( ! is_int( $value ) || $value < $f[3][0] || $value > $f[3][1] ) {
					return new WP_Error( 'range', 'Numeric setting is out of range.' );
				}
			} elseif ( ! is_string( $value ) || strlen( $value ) > 4096 ) {
				return new WP_Error( 'type', 'Invalid setting value.' );
			}
			if ( 'select' === $type && ! array_key_exists( $value, $f[3] ) ) {
				return new WP_Error( 'selection', 'Choose a supported option.' );
			}
			if ( 'email' === $type && $value ) {
				$id = email_exists( $value );
				if ( ! is_email( $value ) || ! $id || ! user_can( $id, 'manage_options' ) ) {
							return new WP_Error( 'recipient', 'Choose an existing site administrator email address.' );
				}
			}
			if ( 'hashes' === $type ) {
				$hashes = array_values( array_unique( preg_split( '/[\s,]+/', trim( $value ), -1, PREG_SPLIT_NO_EMPTY ) ) );
				if ( count( $hashes ) > 100 ) {
							return new WP_Error( 'hashes', 'At most 100 signature exclusions are supported.' );
				}foreach ( $hashes as $hash ) {
					if ( ! preg_match( '/^[a-f0-9]{64}$/D', $hash ) ) {
								return new WP_Error( 'hashes', 'Use full lowercase SHA-256 hashes.' );
					}
				}$value = implode( "\n", $hashes );}
			if ( 'countries' === $type ) {
				$codes = array_values( array_unique( preg_split( '/[\s,]+/', strtoupper( trim( $value ) ), -1, PREG_SPLIT_NO_EMPTY ) ) );
				if ( array_diff( $codes, self::country_codes() ) ) {
							return new WP_Error( 'country', 'Use valid ISO 3166-1 country codes.' );
				}$value = implode( ',', $codes );}
			if ( 'events' === $type ) {
				$events = array_values( array_unique( preg_split( '/[\s,]+/', $value, -1, PREG_SPLIT_NO_EMPTY ) ) );
				if ( array_diff( $events, array( 'login', 'lockout', 'admin', 'role', 'file', 'malware', 'firewall', 'scan_failure', 'scan_findings', 'configuration', 'critical' ) ) ) {
							return new WP_Error( 'events', 'Unknown event category.' );
				}$value = implode( ',', $events );}
			if ( 'paths' === $type ) {
				$paths = preg_split( '/\r?\n/', trim( $value ), -1, PREG_SPLIT_NO_EMPTY );
				if ( count( $paths ) > 30 ) {
							return new WP_Error( 'paths', 'Use at most 30 exact paths.' );
				}foreach ( $paths as $path ) {
					if ( ! preg_match( '~^/[A-Za-z0-9_./-]{0,200}$~D', $path ) || strpos( $path, '..' ) !== false ) {
								return new WP_Error( 'paths', 'Use exact absolute URL paths without traversal or query strings.' );
					}
				}$value = implode( "\n", $paths );}
			if ( 'secret' === $type && $value && 'slack_url' === $key && ! GWQSH_Secure_HTTP::allowed( $value, 'slack' ) ) {
				return new WP_Error( 'webhook', 'Use a Slack hooks.slack.com/services incoming webhook.' );
			}
			$out[ $key ] = $value;
		}
		if ( 'geo' === $section && $out['enabled'] && ( ! ( null === $geo_consent ? GWQSH_Settings::get( 'geo_enabled', false ) : $geo_consent ) || ! $out['countries'] ) ) {
			return new WP_Error( 'geo', 'Enable country lookup with consent and choose at least one country first.' );
		}
		if ( 'alerts' === $section && $out['enabled'] && $out['email'] && ! $out['recipient'] ) {
			return new WP_Error( 'recipient', 'Select an administrator recipient.' );
		}
		return $out;
	}
	/**
	 * Save.
	 *
	 * @param mixed $section Section.
	 * @param array $input Input.
	 * @return mixed Operation result.
	 */
	public static function save( $section, array $input ) {
		$value = self::validate( $section, $input );
		if ( is_wp_error( $value ) ) {
			return $value;
		}
		$all         = (array) get_option( 'gwqsh_enterprise', array() );
		$secrets     = (array) get_option( 'gwqsh_enterprise_credentials', array() );
		$old_secrets = $secrets;
		$clear       = $input['_clear'] ?? array();
		if ( ! is_array( $clear ) ) {
			return new WP_Error( 'secret', 'Invalid credential revocation.' );
		}
		foreach ( $clear as $key ) {
			if ( ! isset( self::schema()[ $section ][ $key ] ) || 'secret' !== self::schema()[ $section ][ $key ][0] ) {
				return new WP_Error( 'secret', 'Unknown credential.' );
			}unset( $secrets[ $section . '.' . $key ] );}
		foreach ( self::schema()[ $section ] as $key => $field ) {
			if ( 'secret' !== $field[0] ) {
				continue;
			}if ( $value[ $key ] ) {
				$encrypted = GWQSH_Crypto::encrypt(
					wp_json_encode(
						array(
							'purpose' => $section . '.' . $key,
							'secret'  => $value[ $key ],
						)
					)
				);
				if ( ! $encrypted ) {
					return new WP_Error( 'encryption', 'Unable to protect credentials.' );
				}$secrets[ $section . '.' . $key ] = $encrypted;
			}unset( $value[ $key ] );}
		update_option( 'gwqsh_enterprise_credentials', $secrets, false );
		if ( get_option( 'gwqsh_enterprise_credentials', array() ) !== $secrets ) {
			return new WP_Error( 'storage', 'Unable to store protected credentials.' );
		}
		$all[ $section ] = $value;
		update_option( 'gwqsh_enterprise', $all, false );
		if ( get_option( 'gwqsh_enterprise', array() ) !== $all ) {
			update_option( 'gwqsh_enterprise_credentials', $old_secrets, false );
			return new WP_Error( 'storage', 'Unable to store settings.' );}
		GWQSH_Activity_Logger::log( 'Security configuration changed', 'Enterprise section updated: ' . $section, 'Security' );
		return self::get( $section );
	}
}
