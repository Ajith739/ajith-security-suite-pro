<?php
/**
 * Authentication guards: TOTP replay and WebAuthn ceremony validation.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'auth-guard' );

$guard = new Gracewell\SecurityPro\Auth\Gracewell_Auth_Guard();

gw_same( 'First TOTP use in a window is accepted', true, $guard->assert_totp_not_replayed( 7, 1000 ) );
gw_same( 'Same TOTP window cannot be replayed', false, $guard->assert_totp_not_replayed( 7, 1000 ) );
gw_same( 'Older TOTP window is rejected', false, $guard->assert_totp_not_replayed( 7, 999 ) );
gw_same( 'Newer TOTP window is accepted', true, $guard->assert_totp_not_replayed( 7, 1001 ) );
gw_same( 'Replay state is per user', true, $guard->assert_totp_not_replayed( 8, 1001 ) );

$challenge = 'Zm9vYmFyLWNoYWxsZW5nZQ';
$origin    = 'https://example.test';

$valid = static function ( array $overrides = array() ) use ( $challenge, $origin ): string {
	return json_encode(
		array_merge(
			array(
				'type'        => 'webauthn.get',
				'challenge'   => $challenge,
				'origin'      => $origin,
				'crossOrigin' => false,
			),
			$overrides
		)
	);
};

$threw = static function ( callable $callback ): bool {
	try {
		$callback();
		return false;
	} catch ( Throwable $error ) {
		return true;
	}
};

gw_same( 'Valid assertion accepted', true, $guard->validate_webauthn_client_data( $valid(), $challenge, $origin, 6, 5 ) );
gw_same(
	'Origin mismatch rejected',
	true,
	$threw( static fn() => $guard->validate_webauthn_client_data( $valid( array( 'origin' => 'https://evil.test' ) ), $challenge, $origin, 6, 5 ) )
);
gw_same(
	'Wrong ceremony type rejected',
	true,
	$threw( static fn() => $guard->validate_webauthn_client_data( $valid( array( 'type' => 'webauthn.create' ) ), $challenge, $origin, 6, 5 ) )
);
gw_same(
	'Challenge mismatch rejected',
	true,
	$threw( static fn() => $guard->validate_webauthn_client_data( $valid(), 'ZGlyZmVyZW50', $origin, 6, 5 ) )
);
gw_same(
	'Cloned-authenticator counter regression rejected',
	true,
	$threw( static fn() => $guard->validate_webauthn_client_data( $valid(), $challenge, $origin, 5, 5 ) )
);
gw_same(
	'Malformed clientDataJSON rejected',
	true,
	$threw( static fn() => $guard->validate_webauthn_client_data( 'not json', $challenge, $origin, 6, 5 ) )
);
gw_same(
	'Zero counter authenticators remain usable',
	true,
	$guard->validate_webauthn_client_data( $valid(), $challenge, $origin, 0, 0 )
);
gw_same(
	'Trailing slash origin is normalized',
	true,
	$guard->validate_webauthn_client_data( $valid( array( 'origin' => 'https://example.test/' ) ), $challenge, $origin, 6, 5 )
);
