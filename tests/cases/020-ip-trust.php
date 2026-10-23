<?php
/**
 * Client IP, trusted proxy and CIDR handling.
 *
 * These paths decide lockout, rate-limit and block identity, so spoofing
 * resistance is a security property, not a convenience.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'ip-trust' );

gw_same( 'IPv4 exact match', true, GWQSH_Network::matches( '203.0.113.9', '203.0.113.9' ) );
gw_same( 'IPv4 CIDR /24 inside', true, GWQSH_Network::matches( '203.0.113.9', '203.0.113.0/24' ) );
gw_same( 'IPv4 CIDR /24 outside', false, GWQSH_Network::matches( '203.0.114.9', '203.0.113.0/24' ) );
gw_same( 'IPv4 CIDR /0 matches all', true, GWQSH_Network::matches( '8.8.8.8', '0.0.0.0/0' ) );
gw_same( 'IPv4 non-octet boundary /33 rejected', false, GWQSH_Network::matches( '203.0.113.9', '203.0.113.0/33' ) );
gw_same( 'IPv6 CIDR inside', true, GWQSH_Network::matches( '2001:db8::1', '2001:db8::/32' ) );
gw_same( 'IPv6 CIDR outside', false, GWQSH_Network::matches( '2001:db9::1', '2001:db8::/32' ) );
gw_same( 'Mixed-family comparison rejected', false, GWQSH_Network::matches( '203.0.113.9', '2001:db8::/32' ) );
gw_same( 'Malformed range rejected', false, GWQSH_Network::matches( '203.0.113.9', '203.0.113.0/24/8' ) );
gw_same( 'Non-numeric prefix rejected', false, GWQSH_Network::matches( '203.0.113.9', '203.0.113.0/abc' ) );
gw_same( 'Canonical IPv4-mapped IPv6', '203.0.113.9', GWQSH_Network::canonical( '::ffff:203.0.113.9' ) );
gw_same( 'Canonical rejects garbage', '', GWQSH_Network::canonical( 'not-an-ip' ) );

$trusted = array( '10.0.0.0/8' );

gw_same(
	'XFF rightmost untrusted hop is the visitor',
	'198.51.100.7',
	GWQSH_Settings::forwarded_ip( '192.0.2.9, 198.51.100.7, 10.0.0.4', $trusted )
);
gw_same(
	'Client-supplied left entries cannot choose identity',
	'198.51.100.7',
	GWQSH_Settings::forwarded_ip( '1.1.1.1, 198.51.100.7, 10.0.0.4', $trusted )
);
gw_same(
	'All-trusted chain returns empty (use peer address)',
	'',
	GWQSH_Settings::forwarded_ip( '10.0.0.4, 10.0.0.5', $trusted )
);
gw_same(
	'Malformed chain element returns empty',
	'',
	GWQSH_Settings::forwarded_ip( '198.51.100.7, not-an-ip, 10.0.0.4', $trusted )
);
gw_same(
	'Oversized chain rejected',
	'',
	GWQSH_Settings::forwarded_ip( str_repeat( '10.0.0.1,', 40 ), $trusted )
);
gw_same(
	'Credential-like header value is not accepted as an IP',
	'',
	GWQSH_Settings::forwarded_ip( 'evil.test', $trusted )
);

gw_group( 'ip-trust-client' );

$original = array(
	'REMOTE_ADDR'          => '203.0.113.50',
	'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
);
$_SERVER  = array_merge( $_SERVER, $original );

$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'proxy' => false, 'proxyheader' => 'xff', 'trusted_proxies' => "10.0.0.0/8\n" );
gw_same( 'Proxy disabled ignores forged X-Forwarded-For', '203.0.113.50', GWQSH_Settings::get_client_ip() );

$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'proxy' => true, 'proxyheader' => 'xff', 'trusted_proxies' => "10.0.0.0/8\n" );
gw_same( 'Untrusted peer cannot inject X-Forwarded-For', '203.0.113.50', GWQSH_Settings::get_client_ip() );

$_SERVER['REMOTE_ADDR'] = '10.0.0.4';
gw_same( 'Trusted peer proxy header accepted', '1.2.3.4', GWQSH_Settings::get_client_ip() );

$_SERVER['HTTP_X_FORWARDED_FOR'] = '9.9.9.9, 1.2.3.4';
gw_same( 'Trusted peer chain resolved to nearest visitor', '1.2.3.4', GWQSH_Settings::get_client_ip() );

$GLOBALS['gw_test_options']['gwqsh_settings'] = array( 'proxy' => true, 'proxyheader' => 'cf', 'trusted_proxies' => "10.0.0.0/8\n" );
$_SERVER['HTTP_CF_CONNECTING_IP']            = '198.51.100.20';
// A forged CF-Connecting-IP is ignored when the peer is not a Cloudflare edge,
// so the identity falls back to the trusted peer address itself.
gw_same( 'Forged Cloudflare header ignored for non-Cloudflare peer', '10.0.0.4', GWQSH_Settings::get_client_ip() );

$_SERVER = array_merge( $_SERVER, $original );
unset( $_SERVER['HTTP_CF_CONNECTING_IP'] );
$GLOBALS['gw_test_options']['gwqsh_settings'] = array();
