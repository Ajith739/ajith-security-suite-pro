<?php
/**
 * XML-RPC abuse protection must follow the WAF policy, not ignore it.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'xmlrpc' );

$methods = array(
	'system.multicall'                   => 'x',
	'pingback.ping'                      => 'x',
	'pingback.extensions.getPingbacks'   => 'x',
	'wp.getPosts'                        => 'x',
	'metaWeblog.newPost'                 => 'x',
);

$set_policy = static function ( array $waf ): void {
	$GLOBALS['gw_test_options']['gwqsh_enterprise'] = array( 'waf' => $waf );
	$GLOBALS['gw_test_options']['gwqsh_settings']   = array( 'status' => '1' );
	$GLOBALS['gw_test_options']['gwqsh_firewall']   = array( 'enabled' => true );
};

$set_policy( array( 'mode' => 'block' ) );
gw_same( 'Enforcement active in block mode', true, GWQSH_Firewall::xmlrpc_enforcement_active() );
$filtered = GWQSH_Firewall::filter_xmlrpc_methods( $methods );
gw_same( 'system.multicall is removed (amplification)', false, isset( $filtered['system.multicall'] ) );
gw_same( 'pingback.ping is removed (DDoS amplification)', false, isset( $filtered['pingback.ping'] ) );
gw_same( 'pingback getPingbacks is removed', false, isset( $filtered['pingback.extensions.getPingbacks'] ) );
gw_same( 'Legitimate publishing methods are kept', true, isset( $filtered['wp.getPosts'] ) && isset( $filtered['metaWeblog.newPost'] ) );

$headers = GWQSH_Firewall::remove_xmlrpc_pingback_header( array( 'X-Pingback' => 'https://example.test/xmlrpc.php', 'Content-Type' => 'text/xml' ) );
gw_same( 'X-Pingback header removed in block mode', false, isset( $headers['X-Pingback'] ) );
gw_same( 'Other headers untouched', true, isset( $headers['Content-Type'] ) );

$set_policy( array( 'mode' => 'report' ) );
gw_same( 'Enforcement inactive in report mode', false, GWQSH_Firewall::xmlrpc_enforcement_active() );
gw_same( 'Methods untouched in report mode', $methods, GWQSH_Firewall::filter_xmlrpc_methods( $methods ) );
$report_headers = GWQSH_Firewall::remove_xmlrpc_pingback_header( array( 'X-Pingback' => 'x' ) );
gw_same( 'Pingback header kept in report mode', true, isset( $report_headers['X-Pingback'] ) );

$set_policy( array( 'mode' => 'disabled' ) );
gw_same( 'Enforcement inactive when the WAF is disabled', false, GWQSH_Firewall::xmlrpc_enforcement_active() );

$set_policy( array( 'mode' => 'block' ) );
$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'status' => '0' );
gw_same( 'Enforcement inactive when the suite is switched off', false, GWQSH_Firewall::xmlrpc_enforcement_active() );

$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'status' => '1' );
$GLOBALS['gw_test_options']['gwqsh_firewall'] = array( 'enabled' => false );
gw_same( 'Enforcement inactive when the firewall toggle is off', false, GWQSH_Firewall::xmlrpc_enforcement_active() );

$GLOBALS['gw_test_options']['gwqsh_firewall'] = array( 'enabled' => true );
$GLOBALS['gw_test_options']['gwqsh_hardening'] = array( 'xmlrpc' => true );
gw_same( 'Hardening rule disables XML-RPC entirely', false, GWQSH_Firewall::maybe_disable_xmlrpc( true ) );
$GLOBALS['gw_test_options']['gwqsh_hardening'] = array( 'xmlrpc' => false );
gw_same( 'XML-RPC stays enabled when hardening is off', true, GWQSH_Firewall::maybe_disable_xmlrpc( true ) );
