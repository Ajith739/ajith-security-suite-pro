<?php
/**
 * Settings validation and persistence.
 *
 * Every security feature reads these options, so a silently accepted bad value
 * (unknown proxy header, unbounded retention, non-boolean toggle) becomes a
 * configuration defect at runtime.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'settings' );

$GLOBALS['gw_test_options'] = array(
	'gwqsh_settings' => array(
		'status'    => '1',
		'retention' => '30',
		'evil'      => 'injected',
	),
);

$all = GWQSH_Settings::get_all();
gw_same( 'Unknown keys are discarded on read', false, array_key_exists( 'evil', $all ) );
gw_same( 'Defaults fill missing keys', true, $all['https'] );
gw_same( 'Plugin active state honoured', true, GWQSH_Settings::is_active() );

$normalized = GWQSH_Settings::normalize(
	array(
		'retention'       => '99999',
		'scan_budget'     => '99',
		'theme'           => 'neon',
		'proxyheader'     => 'x-made-up',
		'notice'          => 'off',
		'debug'           => 'on',
		'trusted_proxies' => "10.0.0.0/8 203.0.113.7\nnot-an-ip\n10.0.0.0/8\n::1",
	)
);
gw_same( 'Retention is clamped to the maximum', '3650', $normalized['retention'] );
gw_same( 'Scan budget is clamped to the maximum', '8', $normalized['scan_budget'] );
gw_same( 'Unknown theme falls back to light', 'light', $normalized['theme'] );
gw_same( 'Unknown proxy header falls back to xff', 'xff', $normalized['proxyheader'] );
gw_same( 'Boolean false is honoured', false, $normalized['notice'] );
gw_same( 'Boolean true is honoured', true, $normalized['debug'] );

$ranges = array_values( array_filter( preg_split( '/\n/', $normalized['trusted_proxies'] ) ) );
gw_same( 'Trusted proxies keep CIDR and IPv6', true, in_array( '10.0.0.0/8', $ranges, true ) && in_array( '::1', $ranges, true ) );
gw_same( 'Trusted proxies drop invalid entries', false, in_array( 'not-an-ip', $ranges, true ) );

$negative = GWQSH_Settings::normalize( array( 'retention' => '-40', 'scan_budget' => '0' ) );
gw_same( 'Negative retention clamps to zero', '0', $negative['retention'] );
gw_same( 'Zero scan budget clamps to one', '1', $negative['scan_budget'] );

$booleanish = GWQSH_Settings::normalize( array( 'proxy' => 'yes', 'https' => '0', 'compact' => 'true' ) );
gw_same( 'Truthy string becomes true', true, $booleanish['proxy'] );
gw_same( 'Zero becomes false', false, $booleanish['https'] );
gw_same( 'String true becomes true', true, $booleanish['compact'] );

$array_value = GWQSH_Settings::normalize( array( 'theme' => array( 'dark' ) ) );
gw_same( 'Non-scalar values are ignored rather than coerced', 'light', $array_value['theme'] );

$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'status' => '0' );
gw_same( 'Inactive status disables the suite gate', false, GWQSH_Settings::is_active() );
$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'status' => '1' );
