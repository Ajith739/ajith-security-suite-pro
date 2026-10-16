<?php
/**
 * WP-Cron scheduling over the bounded, resumable scan engine.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Scheduler service. */
final class GWQSH_Scheduler {
	const HOOK = 'gwqsh_scheduled_integrity_scan';
	/** Register the service hooks. */
	public static function init() {
		add_filter( 'cron_schedules', array( __CLASS__, 'intervals' ) );
		add_action( self::HOOK, array( __CLASS__, 'run' ) );
		add_action( 'gwqsh_run_integrity_now', array( __CLASS__, 'run' ) );
		$settings = self::settings();
		if ( $settings['enabled'] && ! wp_next_scheduled( self::HOOK ) ) {
			self::save( $settings ); }
	}
	/**
	 * Register the supported weekly cron recurrence.
	 *
	 * @param mixed $schedules schedules value.
	 */
	public static function intervals( $schedules ) {
		$schedules['gwqsh_weekly'] = array(
			'interval' => WEEK_IN_SECONDS,
			'display'  => 'Weekly',
		);
		$schedules['gwqsh_monthly'] = array(
			'interval' => 30 * DAY_IN_SECONDS,
			'display'  => 'Monthly',
		);
		$schedules['gwqsh_custom'] = array(
			'interval' => (int) self::settings()['custom_minutes'] * MINUTE_IN_SECONDS,
			'display'  => 'Custom integrity interval',
		);
		return $schedules; }
	/** Return the normalized saved service configuration. */
	public static function settings() {
		return wp_parse_args(
			(array) get_option( 'gwqsh_scan_schedule', array() ),
			array(
				'enabled'        => false,
				'frequency'      => 'daily',
				'time'           => '02:00',
				'custom_minutes' => 60,
				'type'           => 'full',
				'scopes'         => array( 'Core', 'Plugin', 'Theme', 'Uploads' ),
			)
		); }
	/**
	 * Validate configuration without writing to storage.
	 *
	 * @param array $input input value.
	 */
	public static function validate( array $input ) {
		$frequency = $input['frequency'] ?? 'daily';
		$type      = $input['type'] ?? 'full';
		$scopes    = $input['scopes'] ?? array( 'Core', 'Plugin', 'Theme', 'Uploads' );
		if ( ! in_array( $frequency, array( 'hourly', 'twicedaily', 'daily', 'gwqsh_weekly', 'gwqsh_monthly', 'weekly', 'monthly', 'gwqsh_custom' ), true ) || ! in_array( $type, array( 'quick', 'full' ), true ) || ! is_array( $scopes ) || ! $scopes || array_diff( $scopes, array( 'Core', 'Plugin', 'Theme', 'Uploads' ) ) ) {
			return new WP_Error( 'invalid_schedule', 'Choose a valid interval, scan type and at least one scan scope.' ); }
		if ( 'weekly' === $frequency ) {
			$frequency = 'gwqsh_weekly';
		}
		if ( 'monthly' === $frequency ) {
			$frequency = 'gwqsh_monthly';
		}
		if ( isset( $input['enabled'] ) && ! is_bool( $input['enabled'] ) ) {
			return new WP_Error( 'invalid_schedule', 'Schedule enabled must be a boolean.' ); }
		if ( isset( $input['time'] ) && ( ! is_string( $input['time'] ) || ! preg_match( '/^([01][0-9]|2[0-3]):[0-5][0-9]$/D', $input['time'] ) ) ) {
			return new WP_Error( 'invalid_time', 'Choose a valid scan time (HH:MM).' );
		}
		$time = isset( $input['time'] ) && preg_match( '/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/', trim( $input['time'] ) ) ? trim( $input['time'] ) : '02:00';
		$minutes = $input['custom_minutes'] ?? 60;
		if ( ! is_numeric( $minutes ) || floor( (float) $minutes ) !== (float) $minutes || $minutes < 5 || $minutes > 10080 ) {
			return new WP_Error( 'invalid_interval', 'Choose a custom interval between 5 and 10080 minutes.' ); }
		return array(
			'enabled'        => ! empty( $input['enabled'] ),
			'frequency'      => $frequency,
			'time'           => $time,
			'custom_minutes' => (int) $minutes,
			'type'           => $type,
			'scopes'         => array_values( array_unique( $scopes ) ),
		);
	}
	/**
	 * Persist validated service configuration.
	 *
	 * @param array $input input value.
	 */
	public static function save( array $input ) {
		$data = self::validate( $input );
		if ( is_wp_error( $data ) ) {
			return $data; }
		$frequency = $data['frequency'];
		$old       = self::settings();
		$previous_event = wp_get_scheduled_event( self::HOOK );
		update_option( 'gwqsh_scan_schedule', $data, false );
		if ( self::settings() !== $data ) {
			return new WP_Error( 'save_failed', 'Unable to save scan schedule.' ); }
		if ( $old !== $data || ! $data['enabled'] || ! wp_next_scheduled( self::HOOK ) ) {
			$cleared = wp_clear_scheduled_hook( self::HOOK, array(), true );
			if ( is_wp_error( $cleared ) || false === $cleared ) {
				update_option( 'gwqsh_scan_schedule', $old, false );
				return new WP_Error( 'unschedule_failed', 'Unable to replace the existing WordPress cron event.' );
			}
			if ( $data['enabled'] ) {
				$time = $data['time'] ?? '02:00';
				list( $hours, $mins ) = explode( ':', $time );
				try {
					$now = new DateTimeImmutable( 'now', wp_timezone() );
					$first_event = $now->setTime( (int) $hours, (int) $mins, 0 );
					if ( $first_event->getTimestamp() <= time() ) {
						$first_event = $first_event->modify( '+1 day' );
					}
					$start_ts = $first_event->getTimestamp();
				} catch ( Exception $e ) {
					$start_ts = time() + 60;
				}
				$result = wp_schedule_event( $start_ts, $frequency, self::HOOK, array(), true );
				if ( true !== $result ) {
					update_option( 'gwqsh_scan_schedule', $old, false );
					if ( $previous_event ) {
						wp_schedule_event( $previous_event->timestamp, $previous_event->schedule, self::HOOK, $previous_event->args );
					}
					return is_wp_error( $result ) ? $result : new WP_Error( 'schedule_failed', 'Unable to create the WordPress cron event.' ); }
			}
		}
		GWQSH_Activity_Logger::log( 'Scan schedule changed', $data['enabled'] ? $frequency . ' at ' . ( $data['time'] ?? '02:00' ) . ' / ' . $data['type'] : 'Scheduling disabled', 'System' );
		return true;
	}
	/** Return public status fields without exposing credential material. */
	public static function data() {
		$next = wp_next_scheduled( self::HOOK );
		$last = (int) get_option( 'gwqsh_scheduled_scan_last', 0 );
		$freq_map = array(
			'hourly'        => 'Hourly',
			'twicedaily'    => 'Twice daily',
			'daily'         => 'Daily',
			'gwqsh_weekly'  => 'Weekly',
			'weekly'        => 'Weekly',
			'gwqsh_monthly' => 'Monthly',
			'monthly'       => 'Monthly',
		);
		$settings = self::settings();
		$freq_label = 'gwqsh_custom' === $settings['frequency'] ? 'Every ' . $settings['custom_minutes'] . ' minutes' : ( $freq_map[ $settings['frequency'] ] ?? 'Daily' );
		return array(
			'settings'        => $settings,
			'frequency_label' => $freq_label,
			'next'            => $next ? GWQSH_Time::format( $next ) : 'Not scheduled',
			'last'            => $last ? GWQSH_Time::format( $last ) : 'Never',
			'status'          => get_option( 'gwqsh_scheduled_scan_status', 'Not run' ),
		);
	}
	/** Start a bounded background scan unless an existing scan is running. */
	public static function run() {
		if ( self::HOOK === current_action() && ! self::settings()['enabled'] ) {
			return; }
		if ( ! GWQSH_Settings::is_active() ) {
			return; }
		if ( GWQSH_Scan_Engine::load( 'gwqsh_scan_progress' ) || GWQSH_Enterprise_Store::lease_active( 'file-scan' ) ) {
			update_option( 'gwqsh_scheduled_scan_status', 'Skipped: another scan is running', false );
			GWQSH_Activity_Logger::log( 'Scheduled scan skipped', 'An existing scan is still running.', 'System' );
			return; }
		$settings = self::settings();
		update_option(
			'gwqsh_next_scan_options',
			array(
				'type'      => $settings['type'],
				'scopes'    => $settings['scopes'],
				'scheduled' => true,
			),
			false
		);
		update_option( 'gwqsh_scheduled_scan_last', time(), false );
		GWQSH_Activity_Logger::log( 'Scheduled scan started', $settings['type'] . ' scan: ' . implode( ', ', $settings['scopes'] ), 'System' );
		$result = GWQSH_Scan_Engine::run();
		update_option( 'gwqsh_scheduled_scan_status', is_wp_error( $result ) ? 'Unable to start; retry at next interval' : ( ! empty( $result['pending'] ) ? 'Running in background' : 'Completed' ), false );
	}
}
