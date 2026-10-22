<?php
/**
 * Documented false-positive behaviour.
 *
 * These assertions record, rather than hide, cases where heuristic correlation
 * is more aggressive than a human reviewer. Sites that legitimately need the
 * flagged shape must add a path exclusion or an IP allowlist, and the rule is
 * reported (not blocked) until the operator approves it where noted.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'false-positives' );

$detect = static function ( string $payload ): bool {
	$settings = array( 'sql' => true, 'xss' => true, 'bots' => true );
	$legacy   = GWQSH_Firewall::match( array( 'q' => $payload ), '', '', $settings );
	$adv      = GWQSH_Firewall::advanced(
		array( 'q' => $payload ),
		array(),
		array(),
		'/',
		array( 'traversal' => true, 'inclusion' => true, 'post' => false, 'uploads' => false )
	);
	return '' !== $legacy || '' !== $adv;
};

// Legitimate content that the original rules must continue to allow.
$must_allow = array(
	'gutenberg block markup'   => '<!-- wp:paragraph --><p>Hello</p><!-- /wp:paragraph -->',
	'figure with image'        => '<figure class="wp-block-image"><img src="/a.jpg" alt="A"></figure>',
	'woocommerce cart json'    => '{"items":[{"key":"abc","quantity":2}],"coupons":[]}',
	'serialized array'         => 'a:2:{s:4:"name";s:4:"Test";s:4:"list";a:1:{i:0;s:3:"one";}}',
	'sql keyword prose'        => 'how to select from a database',
	'html in support ticket'   => '<p>My page shows <b>nothing</b> after update.</p>',
	'url with dots'            => 'https://example.com/2026/03/post.html',
	'price comparison'         => 'price >= 100 and price <= 200',
	'emoji + quotes'           => 'It’s “fine” — no issues',
	'contract text'            => 'party A and party B agree to the terms; governing law applies.',
	'css gradient'             => 'background: linear-gradient(#fff, #000)',
	'path-like plugin value'   => '/wp-content/plugins/woocommerce/templates/cart.php',
	'wc ajax endpoint'         => 'update_order_review',
	'base64 attachment'        => 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==',
);
gw_expect_all( 'Legitimate content remains allowed', $must_allow, static fn( string $p ) => ! $detect( $p ) );

// Heuristics that are deliberately aggressive. Recorded so operators can review
// them instead of discovering them in production.
$known_aggressive = array(
	'prose containing sleep() call'   => 'Is sleep(8) enough between retries?',
	'prose with quoted equality'      => 'compare and \'alpha\' = \'beta\' values',
	'prose with numeric comparison'   => 'if count or 1 = 1 then reset',
	'code snippet in a support form'  => '<?php echo "hello"; ?>',
	'file copy command prose'         => 'run ;cat /etc/hosts to inspect it',
);
gw_expect_all(
	'Aggressive heuristics are explicit and documented',
	$known_aggressive,
	static fn( string $p ) => $detect( $p )
);
