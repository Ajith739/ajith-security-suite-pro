<?php
/** Provider-neutral licensing state; never disables established protection.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** License service. */
final class GWQSH_License {
	/**
	 * Status.
	 *
	 * @return mixed Operation result.
	 */
	public static function status() {
		$state = (array) get_option(
			'gwqsh_license_state',
			array(
				'state'      => 'unconfigured',
				'expires_at' => 0,
				'checked_at' => 0,
			)
		);
		if ( ! apply_filters( 'gwqsh_license_provider', null ) instanceof GWQSH_License_Provider ) {
			$state['state'] = 'unconfigured';
		} elseif ( 'active' === ( $state['state'] ?? '' ) && ! empty( $state['expires_at'] ) && $state['expires_at'] < time() ) {
			$state['state'] = 'expired';
		}
		return $state;
	}
	/**
	 * Operate.
	 *
	 * @param mixed $action Action.
	 * @return mixed Operation result.
	 */
	public static function operate( $action ) {
		if ( ! in_array( $action, array( 'activate', 'deactivate', 'refresh' ), true ) ) {
			return new WP_Error( 'action', 'Invalid license operation.' );
		}
		$provider = apply_filters( 'gwqsh_license_provider', null );
		$token    = GWQSH_Enterprise_Config::secret( 'license', 'key' );
		if ( ! $provider instanceof GWQSH_License_Provider || ! $token ) {
			return new WP_Error( 'unconfigured', 'Supply an official licensing provider adapter and token first.' );
		}
		$hit = GWQSH_Enterprise_Store::hit( 'license', get_current_user_id(), 60 );
		if ( null === $hit || $hit > 3 ) {
			return new WP_Error( 'rate', 'Retry the license action in one minute.' );
		}
		try {
			$result = $provider->$action( $token, hash( 'sha256', home_url() ) );
		} catch ( Throwable $error ) {
			$result = new WP_Error( 'unavailable', 'Licensing service unavailable. Existing protection continues.' );}
		if ( is_wp_error( $result ) ) {
			return $result;
		}
		if ( ! is_array( $result ) || ! in_array( $result['state'] ?? null, array( 'active', 'inactive', 'expired', 'renewal' ), true ) || ! is_int( $result['expires_at'] ?? null ) || $result['expires_at'] < 0 ) {
			return new WP_Error( 'response', 'Invalid authenticated license response.' );
		}
		$state = array(
			'state'      => $result['state'],
			'expires_at' => $result['expires_at'],
			'checked_at' => time(),
		);
		update_option( 'gwqsh_license_state', $state, false );
		return $state;
	}
}
