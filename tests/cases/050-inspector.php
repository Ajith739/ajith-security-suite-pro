<?php
/**
 * Bounded request parsers used by the active firewall.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'inspector-parsers' );

$inspector = new Gracewell\SecurityPro\WAF\Gracewell_WAF_Inspector();

$json = $inspector->inspect_request(
	array( 'REQUEST_URI' => '/wp-json/example/v1/items', 'CONTENT_TYPE' => 'application/json' ),
	array(),
	array(),
	'{"title":"hello","meta":{"nested":{"deep":"' . str_repeat( 'a', 50 ) . '"}}}',
	array(),
	array(),
	true
);
gw_same( 'Nested JSON is fully inspected', 'fully_inspected', $json['state'] );
gw_same( 'Nested JSON values reach the input list', true, count( $json['inputs'] ) >= 3 );

$bad_json = $inspector->inspect_request(
	array( 'REQUEST_URI' => '/wp-json/example/v1/items', 'CONTENT_TYPE' => 'application/json' ),
	array(),
	array(),
	'{"title":',
	array(),
	array(),
	true
);
gw_same( 'Malformed JSON is reported as a parsing error', 'parsing_error', $bad_json['state'] );

$big = $inspector->inspect_request(
	array( 'REQUEST_URI' => '/', 'CONTENT_TYPE' => 'application/json' ),
	array(),
	array(),
	str_repeat( 'a', 300000 ),
	array(),
	array(),
	true
);
gw_same( 'Oversized body is reported as a budget limit', 'inspection_budget_exceeded', $big['state'] );

$binary = $inspector->inspect_request(
	array( 'REQUEST_URI' => '/', 'CONTENT_TYPE' => 'application/octet-stream' ),
	array(),
	array(),
	"\x00\x01binary",
	array(),
	array(),
	true
);
gw_same( 'Unsupported content types are reported honestly', 'unsupported_request_format', $binary['state'] );

$boundary = 'gwBoundary123';
$multipart = "--{$boundary}\r\nContent-Disposition: form-data; name=\"comment\"\r\n\r\nhello\r\n"
	. "--{$boundary}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"shell.php\"\r\nContent-Type: application/x-php\r\n\r\n<?php echo 1;\r\n"
	. "--{$boundary}--\r\n";
$parsed = $inspector->parse_multipart( $multipart, 'multipart/form-data; boundary=' . $boundary );
gw_same( 'Multipart fields parsed', 'hello', $parsed['fields']['comment'][0] ?? '' );
gw_same( 'Multipart filename captured as metadata', 'shell.php', $parsed['files'][0]['name'] ?? '' );
gw_same( 'Multipart parsing reported success', false, $parsed['error'] );

$no_boundary = $inspector->parse_multipart( $multipart, 'multipart/form-data' );
gw_same( 'Missing boundary fails closed', true, $no_boundary['error'] );

$bad_boundary = $inspector->parse_multipart( $multipart, 'multipart/form-data; boundary="bad boundary with quotes"' );
gw_same( 'Invalid boundary grammar fails closed', true, $bad_boundary['error'] );

$huge = $inspector->parse_multipart( $multipart, 'multipart/form-data; boundary=' . $boundary, 10 );
gw_same( 'Oversized multipart body hits the budget state', 'inspection_budget_exceeded', $huge['state'] );

$truncated = $inspector->parse_multipart( "--{$boundary}\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nvalue", 'multipart/form-data; boundary=' . $boundary );
gw_same( 'Truncated multipart body fails closed', true, $truncated['error'] );

if ( class_exists( '\DOMDocument' ) ) {
	$xml = $inspector->parse_xml( '<methodCall><methodName>x</methodName><params><param><value>abc</value></param></params></methodCall>' );
	gw_same( 'XML parsed with explicit state', true, in_array( $xml['state'], array( 'fully_inspected', 'partially_inspected' ), true ) );

	$doctype = $inspector->parse_xml( '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>' );
	gw_same( 'DTD/entity declarations are refused', 'unsupported_request_format', $doctype['state'] );

	$broken = $inspector->parse_xml( '<x><y></x>' );
	gw_same( 'Malformed XML is a parsing error', 'parsing_error', $broken['state'] );
} else {
	gw_skip( 'XML parser tests', 'DOM extension is unavailable in this PHP runtime' );
}

gw_group( 'inspector-rate' );

$rate = $inspector->check_rate_limit( '198.51.100.10', 'login', 2 );
gw_same( 'First request within the limit', false, (bool) ( $rate['limited'] ?? false ) );
$inspector->check_rate_limit( '198.51.100.10', 'login', 2 );
$rate = $inspector->check_rate_limit( '198.51.100.10', 'login', 2 );
gw_same( 'Third request exceeds a limit of two', true, (bool) ( $rate['limited'] ?? false ) );

$stuffing = $inspector->check_credential_stuffing( '198.51.100.11', 'user-a', 2 );
foreach ( array( 'user-b', 'user-c' ) as $user ) {
	$stuffing = $inspector->check_credential_stuffing( '198.51.100.11', $user, 2 );
}
gw_same( 'Credential stuffing across usernames detected', true, (bool) ( $stuffing['stuffing_detected'] ?? false ) );
gw_same( 'Distinct username count is reported', 3, (int) ( $stuffing['distinct_users'] ?? 0 ) );
