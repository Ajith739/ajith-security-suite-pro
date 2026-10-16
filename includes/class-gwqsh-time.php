<?php
/**
 * Existing SQL dates are site-local; Unix epochs always represent absolute time.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Time service. */
final class GWQSH_Time {
	/**
	 * Interpret historical SQL wall time using the site timezone.
	 *
	 * @param mixed $value value value.
	 */
	public static function timestamp( $value ) {
		if ( is_int( $value ) || is_float( $value ) ) {
			return (int) $value; }
		if ( ! is_string( $value ) || ! $value || '0000-00-00 00:00:00' === $value ) {
			return 0; }
		try {
			return ( new DateTimeImmutable( $value, wp_timezone() ) )->getTimestamp();
		} catch ( Exception $error ) {
			return 0; }
	}
	/**
	 * Render an absolute timestamp in the site timezone.
	 *
	 * @param mixed $value value value.
	 * @param mixed $format format value.
	 */
	public static function format( $value, $format = 'M j, Y, g:i A' ) {
		$timestamp = self::timestamp( $value );
		return $timestamp ? wp_date( $format, $timestamp, wp_timezone() ) : '—';
	}
}
