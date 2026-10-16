<?php
/** Enterprise service contract.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Setup wizard service. */
final class GWQSH_Setup_Wizard {
	/**
	 * State.
	 *
	 * @return mixed Operation result.
	 */
	public static function state() {
		return wp_parse_args(
			(array) get_option( 'gwqsh_setup_wizard', array() ),
			array(
				'step'      => 0,
				'completed' => false,
			)
		);}
	/**
	 * Save.
	 *
	 * @param array $input Input.
	 * @return mixed Operation result.
	 */
	public static function save( array $input ) {
		if ( ! isset( $input['step'], $input['completed'] ) || ! is_int( $input['step'] ) || $input['step'] < 0 || $input['step'] > 6 || ! is_bool( $input['completed'] ) ) {
			return new WP_Error( 'wizard', 'Invalid setup checkpoint.' );
		}
		$state = array(
			'step'      => $input['step'],
			'completed' => $input['completed'],
		);
		update_option( 'gwqsh_setup_wizard', $state, false );
		return $state;
	}
}
