<?php
/**
 * Bot Shield sensitive-file probe detection.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'bot-shield' );

$probes = array(
	'dotenv'            => '/.env',
	'dotenv backup'     => '/.env.local',
	'dotenv nested'     => '/config/.env',
	'git config'        => '/.git/config',
	'git objects'       => '/.git/objects/ab/cdef0123',
	'git head'          => '/.git/HEAD',
	'svn entries'       => '/.svn/entries',
	'aws credentials'   => '/.aws/credentials',
	'wp-config backup'  => '/wp-config.php.bak',
	'wp-config old'     => '/wp-config.php.old',
	'wp-config tilde'   => '/wp-config.php~',
	'debug log'         => '/wp-content/debug.log',
	'htpasswd'          => '/.htpasswd',
	'phpunit eval'      => '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php',
	'url-encoded env'   => '/%2eenv',
	'double-encoded'    => '/%252eenv',
	'backslash variant' => '/foo\\\\..\\\\.env',
);
gw_expect_all( 'Sensitive-file probes detected', $probes, static fn( string $p ) => '' !== GWQSH_Bot_Shield::path_rule( $p ) );

$normal = array(
	'home'               => '/',
	'post permalink'     => '/2026/03/hello-world/',
	'wp admin'           => '/wp-admin/admin.php',
	'admin ajax'         => '/wp-admin/admin-ajax.php',
	'rest route'         => '/wp-json/wp/v2/posts',
	'upload image'       => '/wp-content/uploads/2026/03/photo.jpg',
	'theme asset'        => '/wp-content/themes/twentytwentyfive/style.css',
	'plugin asset'       => '/wp-content/plugins/woocommerce/assets/js/frontend/cart.js',
	'envelope name'      => '/envelope.php',
	'dotenv-like name'   => '/private.env/index.php',
	'checkout'           => '/checkout/',
	'product'            => '/product/red-shoes/',
	'wc store api'       => '/wp-json/wc/store/v1/cart',
	'search'             => '/?s=hello',
	'cart update'        => '/?wc-ajax=update_order_review',
	'gitignore only'     => '/.gitignore',
	'empty path'         => '',
	'query only'         => '?s=test',
	'control characters' => "/.env\x00.php",
	'oversized path'     => '/' . str_repeat( 'a', 3000 ),
);
gw_expect_none( 'Ordinary requests are not treated as probes', $normal, static fn( string $p ) => '' !== GWQSH_Bot_Shield::path_rule( $p ) );

gw_same(
	'Hold requires block mode, enabled Bot Shield and anonymous traffic',
	false,
	GWQSH_Bot_Shield::can_enforce( false, array( 'enabled' => true, 'bots' => true ), array( 'bot_probe' => true, 'mode' => 'block' ), 'block' )
);
gw_same(
	'Hold allowed for anonymous traffic in block mode',
	true,
	GWQSH_Bot_Shield::can_enforce( true, array( 'enabled' => true, 'bots' => true ), array( 'bot_probe' => true, 'mode' => 'block' ), 'block' )
);
gw_same(
	'Hold refused in report mode',
	false,
	GWQSH_Bot_Shield::can_enforce( true, array( 'enabled' => true, 'bots' => true ), array( 'bot_probe' => true, 'mode' => 'report' ), 'report' )
);
gw_same(
	'Hold refused for private/reserved addresses',
	'',
	GWQSH_Bot_Shield::held_rule( '127.0.0.1' )
);
