<?php
/** Enterprise service contract.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
/** Delivery provider service. */
interface GWQSH_Delivery_Provider {
	/**
	 * Deliver.
	 *
	 * @param array $event Event.
	 * @return mixed Operation result.
	 */
	public function deliver( array $event );
}
