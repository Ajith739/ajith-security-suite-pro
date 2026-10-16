<?php
/** Enterprise service contract.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Reputation provider service. */
interface GWQSH_Reputation_Provider {
	/**
	 * Lookup.
	 *
	 * @param mixed $ip Ip.
	 * @return mixed Operation result.
	 */
	public function lookup( $ip );
}
