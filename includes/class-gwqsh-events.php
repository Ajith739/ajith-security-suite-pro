<?php
/** Minimized security event projection and bounded asynchronous alert/log delivery.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
// phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Fixed site-owned tables and prepared values; atomic security state and privacy erasure must bypass object caches.

/** Events service. */
final class GWQSH_Events {
	const SEVERITY = array(
		'Informational' => 0,
		'Low'           => 1,
		'Medium'        => 2,
		'High'          => 3,
		'Critical'      => 4,
	);
	/**
	 * Init.
	 *
	 * @return mixed Operation result.
	 */
	public static function init() {
		add_action( 'gwqsh_event_logged', array( __CLASS__, 'logged' ) );
		add_action( 'gwqsh_deliver_events', array( __CLASS__, 'work' ) );
		add_action( 'gwqsh_daily_log_cleanup', array( __CLASS__, 'cleanup' ) );
		add_action( 'wp_login', array( __CLASS__, 'login' ), 20, 2 );
		self::schedule();
	}
	/** Recover a missing cron wakeup after insertion/worker crashes.
	 * Scheduling is advisory; durable queue rows remain the source of truth.
	 */
	private static function schedule() {
		global $wpdb;
		if ( wp_next_scheduled( 'gwqsh_deliver_events' ) ) { return; }
		$next = $wpdb->get_var( "SELECT MIN(available_at) FROM {$wpdb->prefix}gwqsh_delivery_queue WHERE status IN ('pending','processing')" );
		if ( null !== $next ) {
			wp_schedule_single_event( max( time() + 10, (int) $next ), 'gwqsh_deliver_events' );
		}
	}
	/**
	 * Classify.
	 *
	 * @param mixed $name Name.
	 * @return mixed Operation result.
	 */
	public static function classify( $name ) {
		$rules = array(
			'critical'      => array( '/protection failed|critical|guardian.*fail/i', 'Critical' ),
			'admin'         => array( '/new administrator/i', 'Critical' ),
			'role'          => array( '/role changed|role escalation/i', 'High' ),
			'scan_failure'  => array( '/scan failed|scan skipped|intelligence update failed/i', 'High' ),
			'scan_findings' => array( '/scheduled scan.*findings/i', 'High' ),
			'malware'       => array( '/malware signature|malware detected/i', 'Critical' ),
			'file'          => array( '/file finding|suspicious file|quarantin/i', 'High' ),
			'lockout'       => array( '/locked out|lockout|login country changed|country request blocked|reputation request blocked/i', 'High' ),
			'login'         => array( '/login attempt blocked|2FA verification failed/i', 'Medium' ),
			'firewall'      => array( '/firewall request (blocked|detected)|request rate limit|virtual patch/i', 'Medium' ),
			'configuration' => array( '/settings changed|configuration changed|schedule changed|hardening|incident account containment/i', 'High' ),
		);
		foreach ( $rules as $category => $rule ) {
			if ( preg_match( $rule[0], $name ) ) {
				return array( $category, $rule[1] );
			}
		}
		return array( 'login', 'Informational' );
	}
	/**
	 * Logged.
	 *
	 * @param array $record Record.
	 * @return mixed Operation result.
	 */
	public static function logged( array $record ) {
		$alerts   = GWQSH_Enterprise_Config::get( 'alerts' );
		$shipping = GWQSH_Enterprise_Config::get( 'shipping' );
		if ( ! $alerts['enabled'] && ! $shipping['enabled'] ) {
			return;
		}
		list($category, $severity) = self::classify( $record['event_name'] );
		if ( 'login' === $category && preg_match( '/login attempt blocked|verification failed/i', $record['event_name'] ) ) {
			$hits = GWQSH_Enterprise_Store::hit( 'login-alert', $record['user_login'] . '|' . $record['ip_address'], 300 );
			if ( null === $hits || $hits < 5 ) {
				return;
			}$severity = 'High';}
		if ( 'firewall' === $category ) {
			$hits = GWQSH_Enterprise_Store::hit( 'firewall-alert', 'site', 60 );
			if ( null === $hits || $hits < $alerts['firewall_threshold'] ) {
				return;
			}$severity = 'High';}
		$privacy = GWQSH_Enterprise_Config::get( 'privacy' );
		$event   = array(
			'event_id'  => (int) $record['id'],
			'timestamp' => gmdate( 'c' ),
			'event'     => substr( $record['event_name'], 0, 100 ),
			'category'  => $category,
			'severity'  => $severity,
			'site_id'   => hash( 'sha256', home_url() ),
			'ip'        => GWQSH_Privacy::ip( $record['ip_address'], $privacy['anonymize'] ),
			'user'      => $privacy['remote_identity'] ? substr( $record['user_login'], 0, 60 ) : 'redacted',
		);
		// No details, raw request bodies, URLs, cookies, passwords, OTPs or authentication assertions leave this projection.
		foreach ( array( 'email', 'slack', 'collector' ) as $channel ) {
			$cfg = 'collector' === $channel ? $shipping : $alerts;
			if ( ! $cfg['enabled'] || ( 'collector' !== $channel && empty( $cfg[ $channel ] ) ) || ! in_array( $category, explode( ',', $cfg['events'] ), true ) || self::SEVERITY[ $severity ] < self::SEVERITY[ $cfg['minimum'] ] ) {
				continue;
			}
			self::enqueue( $channel, $event, (int) $alerts['cooldown'] );
		}
	}
	/**
	 * Enqueue.
	 *
	 * @param mixed $channel Channel.
	 * @param array $event Event.
	 * @param mixed $cooldown Cooldown.
	 * @return mixed Operation result.
	 */
	public static function enqueue( $channel, array $event, $cooldown = 300 ) {
		global $wpdb;
		if ( ! in_array( $channel, array( 'email', 'slack', 'collector' ), true ) ) {
			return new WP_Error( 'channel', 'Unsupported delivery channel.' );
		}
		$lock = GWQSH_Enterprise_Store::lock( 'queue-admission', 10 );
		if ( ! $lock ) {
			return new WP_Error( 'busy', 'Delivery queue is busy.' );
		}
		try {
			$table = $wpdb->prefix . 'gwqsh_delivery_queue';
			$bucket = intdiv( time(), max( 60, $cooldown ) );
			$key = hash( 'sha256', $channel . '|' . ( $event['delivery_identity'] ?? ( $event['category'] . '|' . $event['event'] . '|' . $event['ip'] . '|' . $bucket ) ) );
			if ( $wpdb->get_var( $wpdb->prepare( "SELECT id FROM {$table} WHERE delivery_key=%s", $key ) ) ) { return true; }
			if ( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) >= 1000 ) {
				$wpdb->query( "DELETE FROM {$table} WHERE status IN ('delivered','failed') ORDER BY id LIMIT 100" );}
			if ( (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$table}" ) >= 1000 ) {
				return new WP_Error( 'capacity', 'Delivery queue is full; local audit logging is retained.' );
			}
			$insert = $wpdb->query( $wpdb->prepare( "INSERT IGNORE INTO {$table} (delivery_key,channel,payload,available_at,created_at) VALUES (%s,%s,%s,%d,%d)", $key, $channel, wp_json_encode( $event ), time(), time() ) );
			if ( false === $insert ) {
				return new WP_Error( 'storage', 'Unable to queue delivery.' );
			}
			if ( ! wp_next_scheduled( 'gwqsh_deliver_events' ) ) {
				wp_schedule_single_event( time() + 10, 'gwqsh_deliver_events' );
			}
			return true;
		} finally {
			GWQSH_Enterprise_Store::unlock( 'queue-admission', $lock );}
	}
	/**
	 * Deliver.
	 *
	 * @param mixed $channel Channel.
	 * @param array $event Event.
	 * @return mixed Operation result.
	 */
	public static function deliver( $channel, array $event ) {
		$custom = apply_filters( 'gwqsh_delivery_provider', null, $channel );
		if ( $custom instanceof GWQSH_Delivery_Provider ) {
			return $custom->deliver( $event );
		}
		if ( 'email' === $channel ) {
			$cfg = GWQSH_Enterprise_Config::get( 'alerts' );
			$id  = email_exists( $cfg['recipient'] );
			if ( ! $cfg['enabled'] || ! $cfg['email'] || ! $id || ! user_can( $id, 'manage_options' ) ) {
				return new WP_Error( 'inactive', 'Email alert channel is inactive.' );
			}
			return wp_mail( $cfg['recipient'], 'Security Suite Pro: ' . $event['severity'] . ' - ' . $event['event'], 'Event: ' . $event['event'] . "\nSeverity: " . $event['severity'] . "\nTime (UTC): " . $event['timestamp'] . "\nReview the local security audit log for evidence." );}
		if ( 'slack' === $channel ) {
			$cfg = GWQSH_Enterprise_Config::get( 'alerts' );
			$url = GWQSH_Enterprise_Config::secret( 'alerts', 'slack_url' );
			if ( ! $cfg['enabled'] || ! $cfg['slack'] || ! $url ) {
				return new WP_Error( 'inactive', 'Slack is inactive until configured.' );
			}$body    = array( 'text' => 'Security Suite Pro | ' . $event['severity'] . ' | ' . $event['event'] . ' | ' . $event['timestamp'] );
			$response = GWQSH_Secure_HTTP::request(
				'slack',
				$url,
				array(
					'method'  => 'POST',
					'headers' => array( 'Content-Type' => 'application/json' ),
					'body'    => wp_json_encode( $body ),
				)
			);} elseif ( 'collector' === $channel ) {
			$cfg = GWQSH_Enterprise_Config::get( 'shipping' );
			$key = GWQSH_Enterprise_Config::secret( 'shipping', 'key' );
			if ( ! $cfg['enabled'] || ! $key ) {
				return new WP_Error( 'inactive', 'Datadog Logs is inactive until configured.' );
			}$response = GWQSH_Secure_HTTP::request(
				'collector',
				'https://http-intake.logs.datadoghq.' . ( 'eu' === $cfg['region'] ? 'eu' : 'com' ) . '/api/v2/logs',
				array(
					'method'  => 'POST',
					'headers' => array(
						'Content-Type' => 'application/json',
						'DD-API-KEY'   => $key,
					),
					'body'    => wp_json_encode(
						array(
							array(
								'ddsource' => 'wordpress',
								'service'  => 'gracewell-security-suite-pro',
								'message'  => wp_json_encode( $event ),
								'event_id' => $event['event_id'],
							),
						)
					),
				)
			);} else {
				return new WP_Error( 'channel', 'Unsupported delivery channel.' );
			}
			if ( is_wp_error( $response ) ) {
				return new WP_Error( 'transport', 'Remote delivery failed.' );
			}$code = wp_remote_retrieve_response_code( $response );
				return $code >= 200 && $code < 300 ? true : new WP_Error( 'http_' . $code, 'Remote service rejected delivery.' );
	}
	/**
	 * Work.
	 *
	 * @return mixed Operation result.
	 */
	public static function work() {
		global $wpdb;
		$lock = GWQSH_Enterprise_Store::lock( 'delivery-worker', 300 );
		if ( ! $lock ) {
			// Cron consumes its event before calling us. Preserve recovery if the
			// current owner dies after this contending invocation returns.
			if ( ! wp_next_scheduled( 'gwqsh_deliver_events' ) ) {
				wp_schedule_single_event( time() + 301, 'gwqsh_deliver_events' );
			}
			return;
		}
		$table = $wpdb->prefix . 'gwqsh_delivery_queue';
		$start = microtime( true );
		try {
			// Attempts are charged when claimed, so repeated crashes cannot retry forever.
			$wpdb->query( $wpdb->prepare( "UPDATE {$table} SET status=IF(attempts>=5,'failed','pending'),last_error='lease_expired' WHERE status='processing' AND available_at<=%d", time() ) );
			$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$table} WHERE status='pending' AND available_at<=%d ORDER BY id LIMIT 20", time() ), ARRAY_A );
			foreach ( $rows as $row ) {
				if ( microtime( true ) - $start >= 15 ) { break; }
				$token = 'lease:' . bin2hex( random_bytes( 16 ) );
				if ( 1 !== $wpdb->query( $wpdb->prepare( "UPDATE {$table} SET status='processing',available_at=%d,attempts=attempts+1,last_error=%s,lease_token=%s WHERE id=%d AND status='pending' AND available_at<=%d", time() + 300, $token, substr( $token, 6 ), $row['id'], time() ) ) ) { continue; }
				// Never enter provider I/O without a durable recovery wakeup.
				if ( ! wp_next_scheduled( 'gwqsh_deliver_events' ) && true !== wp_schedule_single_event( time() + 301, 'gwqsh_deliver_events', array(), true ) ) {
					break;
				}
				try {
					$event = json_decode( $row['payload'], true );
					$result = is_array( $event ) ? self::deliver( $row['channel'], $event ) : new WP_Error( 'payload', 'Invalid queued payload.' );
				} catch ( Throwable $error ) {
					$result = new WP_Error( 'delivery', 'Delivery provider failed.' );
				}
				$attempts = (int) $row['attempts'] + 1;
				$ok = true === $result;
				$code = is_wp_error( $result ) ? sanitize_key( $result->get_error_code() ) : 'delivery';
				// Compare-and-swap prevents an expired worker overwriting a newer claim.
				// "delivered" is legacy storage vocabulary: provider accepted, not recipient read.
				$wpdb->query( $wpdb->prepare(
					"UPDATE {$table} SET status=%s,available_at=%d,last_error=%s,lease_token='' WHERE id=%d AND status='processing' AND last_error=%s AND lease_token=%s AND available_at>%d",
					$ok ? 'delivered' : ( $attempts >= 5 ? 'failed' : 'pending' ),
					time() + min( 3600, 30 * ( 2 ** $attempts ) ),
					$ok ? 'provider_accepted' : substr( $code, 0, 100 ),
					$row['id'], $token, substr( $token, 6 ), time()
				) );
			}
			$next = $wpdb->get_var( "SELECT MIN(available_at) FROM {$table} WHERE status IN ('pending','processing')" );
			if ( $next && ! wp_next_scheduled( 'gwqsh_deliver_events' ) ) {
				wp_schedule_single_event( max( time() + 10, (int) $next ), 'gwqsh_deliver_events' );
			}
		} finally {
			GWQSH_Enterprise_Store::unlock( 'delivery-worker', $lock );
		}
	}

	/**
	 * Cleanup.
	 *
	 * @return mixed Operation result.
	 */
	public static function cleanup() {
		global $wpdb;
		$days = GWQSH_Enterprise_Config::get( 'privacy' )['delivery_retention'];
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_delivery_queue WHERE status IN ('delivered','failed') AND created_at<%d LIMIT 500", time() - $days * DAY_IN_SECONDS ) );
		GWQSH_Enterprise_Store::prune();
		$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->prefix}gwqsh_auth_challenges WHERE expires_at<%d LIMIT 500", time() ) );}
	/**
	 * Status.
	 *
	 * @return mixed Operation result.
	 */
	public static function status() {
		global $wpdb;
		return $wpdb->get_results( "SELECT status,COUNT(*) AS count FROM {$wpdb->prefix}gwqsh_delivery_queue GROUP BY status", ARRAY_A );}
	/**
	 * Login.
	 *
	 * @param mixed $login Login.
	 * @param mixed $user User.
	 * @return mixed Operation result.
	 */
	public static function login( $login, $user ) {
		if ( ! user_can( $user, 'manage_options' ) || ! GWQSH_Enterprise_Config::get( 'alerts' )['enabled'] ) {
			return;
		}
		$geo  = GWQSH_Network::country( GWQSH_Settings::get_client_ip() );
		$last = get_user_meta( $user->ID, 'gwqsh_last_login_country', true );
		if ( ! empty( $geo['code'] ) ) {
			if ( $last && $last !== $geo['code'] ) {
				GWQSH_Activity_Logger::log( 'Administrator login country changed', 'Cached country differs from the preceding verified administrator login. Review; this is not proof of compromise.', 'Security', $login );
			}update_user_meta( $user->ID, 'gwqsh_last_login_country', $geo['code'] );}
	}
}
