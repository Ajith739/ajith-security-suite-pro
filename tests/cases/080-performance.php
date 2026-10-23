<?php
/**
 * In-harness timing of the active WAF evaluation path.
 *
 * This measures CPU cost inside a WASM PHP runtime, which is slower than the
 * production runtime; absolute numbers are not production latency. The figures
 * are useful for relative regression detection and for catching accidental
 * algorithmic blow-ups.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'performance' );

$settings = array( 'sql' => true, 'xss' => true, 'bots' => true );
$policy   = array( 'traversal' => true, 'inclusion' => true, 'post' => true, 'uploads' => false );

$typical = array(
	's'         => 'red shoes',
	'page'      => '2',
	'orderby'   => 'date',
	'utm_source'=> 'newsletter',
	'filter'    => 'color:red',
);

$start = microtime( true );
for ( $i = 0; $i < 300; $i++ ) {
	GWQSH_Firewall::match( $typical, 'Mozilla/5.0', '/product/red-shoes/', $settings );
	GWQSH_Firewall::advanced( $typical, array(), array(), '/product/red-shoes/', $policy );
}
$typical_us = ( microtime( true ) - $start ) / 300 * 1000000;
gw_assert( 'Typical request evaluation stays bounded', $typical_us < 8000, sprintf( '%.1f µs/request (WASM)', $typical_us ) );

$heavy = array(
	'payload' => str_repeat( 'lorem ipsum dolor sit amet ', 600 ),
	'second'  => str_repeat( 'consectetur adipiscing elit ', 500 ),
);
$start = microtime( true );
for ( $i = 0; $i < 20; $i++ ) {
	GWQSH_Firewall::match( $heavy, 'Mozilla/5.0', '/search/', $settings );
	GWQSH_Firewall::advanced( $heavy, array(), array(), '/search/', $policy );
}
$heavy_us = ( microtime( true ) - $start ) / 20 * 1000000;
gw_assert( 'Worst-case budgeted body stays bounded', $heavy_us < 200000, sprintf( '%.1f µs/request for ~30KB values (WASM)', $heavy_us ) );

$arrays = array();
for ( $i = 0; $i < 60; $i++ ) {
	$arrays[ 'item_' . $i ] = array( 'name' => 'value ' . $i, 'qty' => (string) $i );
}
$start = microtime( true );
for ( $i = 0; $i < 50; $i++ ) {
	GWQSH_Firewall::advanced( $arrays, array(), array(), '/wp-json/wc/store/v1/cart', $policy );
}
$list_us = ( microtime( true ) - $start ) / 50 * 1000000;
gw_assert( 'Nested cart-like payloads stay bounded', $list_us < 60000, sprintf( '%.1f µs/request for 120 nested values (WASM)', $list_us ) );

gw_record(
	'WAF timing summary',
	true,
	sprintf(
		'typical=%.1fµs, heavy=%.1fµs, nested=%.1fµs (PHP %s, WASM runtime)',
		$typical_us,
		$heavy_us,
		$list_us,
		PHP_VERSION
	)
);
