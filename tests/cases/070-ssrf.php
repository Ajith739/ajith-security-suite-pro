<?php
/**
 * SSRF-safe webhook destination validation.
 *
 * DNS resolution is unavailable/undesirable in this harness, so hostname-based
 * cases are skipped rather than faked.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'ssrf' );

$dispatcher = new Gracewell\SecurityPro\Alerts\Gracewell_SSRF_Safe_Dispatcher();

$throws = static function ( callable $callback ): bool {
	try {
		$callback();
		return false;
	} catch ( Throwable $error ) {
		return true;
	}
};

gw_same( 'Plain HTTP webhook rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'http://hooks.example.test/abc' ) ) );
gw_same( 'Missing scheme rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'hooks.example.test/abc' ) ) );
gw_same( 'Empty host rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'https:///abc' ) ) );
gw_same( 'Loopback IP literal rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'https://127.0.0.1/hook' ) ) );
gw_same( 'Private range IP literal rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'https://10.1.2.3/hook' ) ) );
gw_same( 'Link-local metadata IP rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'https://169.254.169.254/latest/meta-data/' ) ) );
gw_same( 'IPv6 loopback rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'https://[::1]/hook' ) ) );
gw_same( 'IPv6 unique-local rejected', true, $throws( static fn() => $dispatcher->validate_webhook_destination( 'https://[fd00::1]/hook' ) ) );

if ( function_exists( 'dns_get_record' ) && false !== @dns_get_record( 'example.com', DNS_A ) ) {
	gw_same( 'Public HTTPS host accepted', 'https://example.com/hook', $dispatcher->validate_webhook_destination( 'https://example.com/hook' ) );
} else {
	gw_skip( 'Public hostname acceptance', 'DNS resolution unavailable in this runtime' );
}
