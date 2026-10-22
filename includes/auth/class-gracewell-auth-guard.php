<?php

declare(strict_types=1);

namespace Gracewell\SecurityPro\Auth;

use RuntimeException;

if (! defined('ABSPATH')) {
    exit;
}

final class Gracewell_Auth_Guard
{

    /**
     * Verify that a TOTP code has not already been consumed in the current or adjacent 30s time window.
     */
    public function assert_totp_not_replayed(int $user_id, int $time_slice): bool
    {
        $last_slice = (int) get_user_meta($user_id, '_gracewell_last_totp_slice', true);
        if ($time_slice <= $last_slice) {
            return false; // Replay or older time-step rejected
        }
        update_user_meta($user_id, '_gracewell_last_totp_slice', $time_slice);
        return true;
    }

    /**
     * Validate WebAuthn clientDataJSON ceremony parameters (type, challenge, origin, and cloned-authenticator counter).
     */
    public function validate_webauthn_client_data(
        string $client_data_json,
        string $expected_challenge_b64url,
        string $expected_origin,
        int $incoming_sign_count,
        int $stored_sign_count
    ): bool {
        $data = json_decode($client_data_json, true);
        if (! is_array($data)) {
            throw new RuntimeException('Malformed WebAuthn clientDataJSON.');
        }

        if (($data['type'] ?? '') !== 'webauthn.get') {
            throw new RuntimeException('Invalid WebAuthn ceremony type.');
        }

        if (! hash_equals($expected_challenge_b64url, (string) ($data['challenge'] ?? ''))) {
            throw new RuntimeException('WebAuthn challenge mismatch.');
        }

        $actual_origin = rtrim(strtolower((string) ($data['origin'] ?? '')), '/');
        $target_origin = rtrim(strtolower($expected_origin), '/');
        if (! hash_equals($target_origin, $actual_origin)) {
            throw new RuntimeException('WebAuthn origin mismatch.');
        }

        // Cloned authenticator detection when signature counter is supported (> 0)
        if (($stored_sign_count > 0 || $incoming_sign_count > 0) && $incoming_sign_count <= $stored_sign_count) {
            throw new RuntimeException('WebAuthn signature counter anomaly detected (possible cloned credential).');
        }

        return true;
    }
}
