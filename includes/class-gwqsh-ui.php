<?php
/**
 * Escaped empty and error state rendering.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** UI service. */
final class GWQSH_UI {
	/**
	 * Return markup with individually escaped text, URLs and illustration paths.
	 *
	 * @param mixed $title title value.
	 * @param mixed $description description value.
	 * @param mixed $kind kind value.
	 * @param mixed $url url value.
	 * @param mixed $label label value.
	 */
	public static function empty_state( $title, $description, $kind = 'logs', $url = '', $label = '' ) {
		$images = array(
			'logs'        => 'timeline.png',
			'clean'       => 'auth.png',
			'setup'       => 'auth.png',
			'unavailable' => 'earth-plane.png',
			'403'         => '403-illustration.png',
			'404'         => '404-illustration.png',
			'500'         => '500-illustration.png',
		);
		$html   = '<div class="gwqsh-empty"><img width="112" height="96" loading="lazy" alt="" src="' . esc_url( GWQSH_URL . 'assets/img/spot-illustrations/' . ( $images[ $kind ] ?? $images['logs'] ) ) . '"><h3>' . esc_html( $title ) . '</h3><p>' . esc_html( $description ) . '</p>';
		if ( $url && $label ) {
			$html .= '<a class="button" href="' . esc_url( $url ) . '">' . esc_html( $label ) . '</a>'; }
		return $html . '</div>';
	}
	/**
	 * Render an illustrated HTTP error response.
	 *
	 * @param mixed $code code value.
	 * @param mixed $title title value.
	 * @param mixed $description description value.
	 */
	public static function error( $code, $title, $description ) {
		nocache_headers();
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- empty_state individually escapes all interpolated values and returns reviewed component markup.
		wp_die( self::empty_state( $title, $description, (string) $code, home_url( '/' ), 'Return to the website' ), esc_html( $title ), array( 'response' => (int) $code ) );
	}
}
