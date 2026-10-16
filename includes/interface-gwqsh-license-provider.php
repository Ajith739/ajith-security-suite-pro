<?php
/** Enterprise service contract.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** License provider service. */
interface GWQSH_License_Provider {
	/**
	 * Activate.
	 *
	 * @param mixed $token Token.
	 * @param mixed $site_id Site id.
	 * @return mixed Operation result.
	 */
	public function activate( $token, $site_id );
	/**
	 * Deactivate.
	 *
	 * @param mixed $token Token.
	 * @param mixed $site_id Site id.
	 * @return mixed Operation result.
	 */
	public function deactivate( $token, $site_id );
	/**
	 * Refresh.
	 *
	 * @param mixed $token Token.
	 * @param mixed $site_id Site id.
	 * @return mixed Operation result.
	 */
	public function refresh( $token, $site_id );
}
