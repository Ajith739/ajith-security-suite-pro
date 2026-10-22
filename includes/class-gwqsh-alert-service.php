<?php
/** Compatibility adapter into the single durable security delivery queue.
 *
 * @package GracewellSecuritySuitePro
 */
defined( 'ABSPATH' ) || exit;

/** Existing alert producers share GWQSH_Events admission and delivery. */
final class GWQSH_Alert_Service {
	const HOOK = 'gwqsh_deliver_alerts';

	/** Keep old scheduled hooks operational during upgrade. */
	public static function init() {
		add_action( self::HOOK, array( __CLASS__, 'deliver_queued' ) );
		add_action( 'gwqsh_deliver_events', array( __CLASS__, 'migrate_legacy' ), 5 );
		if ( ( get_transient( 'gwqsh_alert_queue' ) || get_option( 'gwqsh_legacy_alert_backlog' ) ) && ! wp_next_scheduled( self::HOOK ) ) {
			wp_schedule_single_event( time() + 5, self::HOOK );
		}
	}

	/** Queue a minimized event; returns persistence failures to the producer.
	 *
	 * @param string $category Event category.
	 * @param string $severity Severity label.
	 * @param string $message Summary, never a request body.
	 * @param array $extra Legacy context, deliberately not transmitted.
	 * @return true|WP_Error Admission result.
	 */
	public static function dispatch( $category, $severity, $message, array $extra = array() ) {
		return self::queue( array( 'category' => $category, 'severity' => $severity, 'message' => $message, 'created_at' => time() ) );
	}

	/** Project one alert through the existing delivery channels.
	 *
	 * @param array $alert Legacy or current alert.
	 * @param bool $migration Preserve records until at least one configured channel persists.
	 * @return true|WP_Error Admission result.
	 */
	private static function queue( array $alert, $migration = false ) {
		$alerts = GWQSH_Enterprise_Config::get( 'alerts' );
		$shipping = GWQSH_Enterprise_Config::get( 'shipping' );
		$severity = $alert['severity'] ?? 'Informational';
		$category = $alert['category'] ?? 'critical';
		if ( ! isset( GWQSH_Events::SEVERITY[ $severity ] ) ) {
			return new WP_Error( 'severity', 'Unsupported alert severity.' );
		}
		$event = array(
			'event_id' => isset( $alert['id'] ) ? 'legacy-' . substr( (string) $alert['id'], 0, 64 ) : 'alert-' . wp_generate_uuid4(),
			'timestamp' => gmdate( 'c', (int) ( $alert['created_at'] ?? time() ) ),
			'event' => substr( sanitize_text_field( $alert['message'] ?? '' ), 0, 100 ),
			'category' => sanitize_key( $category ),
			'severity' => $severity,
			'site_id' => hash( 'sha256', home_url() ),
			'ip' => 'redacted',
			'user' => 'redacted',
		);
		if ( $migration ) {
			// Stable across retries and cooldown windows, including records without an old ID.
			$event['delivery_identity'] = 'legacy-' . hash( 'sha256', wp_json_encode( $alert ) );
		}
		$queued = 0;
		foreach ( array( 'email', 'slack', 'collector' ) as $channel ) {
			$config = 'collector' === $channel ? $shipping : $alerts;
			$categories = array_map( 'trim', explode( ',', $config['events'] ?? '' ) );
			if ( empty( $config['enabled'] ) || ( 'collector' !== $channel && empty( $config[ $channel ] ) ) || ( ! in_array( $category, $categories, true ) && ! ( 'Critical' === $severity && in_array( 'critical', $categories, true ) ) ) || GWQSH_Events::SEVERITY[ $severity ] < ( GWQSH_Events::SEVERITY[ $config['minimum'] ] ?? 3 ) ) {
				continue;
			}
			$result = GWQSH_Events::enqueue( $channel, $event, (int) ( $alerts['cooldown'] ?? 300 ) );
			if ( is_wp_error( $result ) ) {
				return $result;
			}
			++$queued;
		}
		return $migration && ! $queued ? new WP_Error( 'inactive', 'Legacy alert retained until a matching channel is configured.' ) : true;
	}

	/** Migrate without deleting the only copy before durable admission succeeds. */
	public static function migrate_legacy() {
		$lock = GWQSH_Enterprise_Store::lock( 'legacy-alert-migration', 60 );
		if ( ! $lock ) { return; }
		try {
			$queue = get_transient( 'gwqsh_alert_queue' );
			if ( ! is_array( $queue ) ) { $queue = array(); }
			// Persist the old expiring queue before processing any channel.
			$backup = (array) get_option( 'gwqsh_legacy_alert_backlog', array() );
			foreach ( $queue as $alert ) {
				if ( is_array( $alert ) ) { $backup[ hash( 'sha256', wp_json_encode( $alert ) ) ] = $alert; }
			}
			update_option( 'gwqsh_legacy_alert_backlog', $backup, false );
			if ( get_option( 'gwqsh_legacy_alert_backlog' ) !== $backup ) { return; }
			delete_transient( 'gwqsh_alert_queue' );
		} finally {
			GWQSH_Enterprise_Store::unlock( 'legacy-alert-migration', $lock );
		}
		self::drain_legacy();
	}

	/** Retry the durable migration backlog using stable per-channel identities. */
	private static function drain_legacy() {
		$lock = GWQSH_Enterprise_Store::lock( 'legacy-alert-migration', 60 );
		if ( ! $lock ) { return; }
		try {
			$queue = (array) get_option( 'gwqsh_legacy_alert_backlog', array() );
			foreach ( array_slice( $queue, 0, 100, true ) as $key => $alert ) {
				if ( true === self::queue( $alert, true ) ) { unset( $queue[ $key ] ); }
			}
			update_option( 'gwqsh_legacy_alert_backlog', $queue, false );
			if ( $queue && ! wp_next_scheduled( self::HOOK ) ) { wp_schedule_single_event( time() + 60, self::HOOK ); }
		} finally {
			GWQSH_Enterprise_Store::unlock( 'legacy-alert-migration', $lock );
		}
	}

	/** Old cron hook forwards into the existing single delivery worker. */
	public static function deliver_queued() {
		self::migrate_legacy();
		self::drain_legacy();
		GWQSH_Events::work();
	}
}
