<?php

declare(strict_types=1);

namespace Gracewell\SecurityPro\Intelligence;

use RuntimeException;

if (! defined('ABSPATH')) {
    exit;
}

final class Gracewell_Signed_Feed_Verifier
{
    private string $trusted_public_key_hex;
    private string $expected_publisher;

    public function __construct(string $trusted_public_key_hex, string $expected_publisher = 'gracewell-threat-intel-authority')
    {
        if (! function_exists('sodium_crypto_sign_verify_detached')) {
            throw new RuntimeException('Libsodium extension is required for signed threat feed verification.');
        }
        $this->trusted_public_key_hex = $trusted_public_key_hex;
        $this->expected_publisher     = $expected_publisher;
    }

    /**
     * Verify a signed threat feed bundle before staging or activation.
     *
     * @param array  $envelope      Decoded JSON envelope containing metadata, signature_hex, and payload_json.
     * @param string $expected_type Expected feed type (e.g., 'waf_rules', 'malware_signatures', 'virtual_patches').
     * @param int    $current_ver   Currently active feed version to prevent rollback attacks.
     * @param string $engine_ver    Current Gracewell plugin version.
     * @return array Verified decoded payload.
     */
    public function verify_and_extract(array $envelope, string $expected_type, int $current_ver, string $engine_ver): array
    {
        $required_fields = ['publisher', 'feed_type', 'version', 'expires_at', 'min_engine_version', 'sha256', 'signature', 'payload'];
        foreach ($required_fields as $field) {
            if (! isset($envelope[$field])) {
                throw new RuntimeException(sprintf('Missing required feed envelope field: %s', $field));
            }
        }

        if ($envelope['publisher'] !== $this->expected_publisher) {
            throw new RuntimeException('Untrusted feed publisher.');
        }

        if ($envelope['feed_type'] !== $expected_type) {
            throw new RuntimeException('Feed type mismatch.');
        }

        // Anti-rollback protection
        $incoming_version = (int) $envelope['version'];
        if ($incoming_version <= $current_ver) {
            throw new RuntimeException(sprintf('Anti-rollback triggered: incoming version (%d) is not newer than active version (%d).', $incoming_version, $current_ver));
        }

        // Expiration check
        if (time() >= (int) $envelope['expires_at']) {
            throw new RuntimeException('Signed threat feed has expired.');
        }

        // Engine compatibility check
        if (version_compare($engine_ver, (string) $envelope['min_engine_version'], '<')) {
            throw new RuntimeException('Feed requires a newer Gracewell engine version.');
        }

        $raw_payload = (string) $envelope['payload'];

        // Content digest verification
        $actual_hash = hash('sha256', $raw_payload);
        if (! hash_equals((string) $envelope['sha256'], $actual_hash)) {
            throw new RuntimeException('Feed payload SHA-256 digest mismatch.');
        }

        // Canonical message signing verification (Type + Version + Expiration + SHA256)
        $canonical_message = implode('|', [
            $envelope['publisher'],
            $envelope['feed_type'],
            (string) $incoming_version,
            (string) $envelope['expires_at'],
            $actual_hash,
        ]);

        $signature_bin  = sodium_hex2bin((string) $envelope['signature']);
        $public_key_bin = sodium_hex2bin($this->trusted_public_key_hex);

        if (! sodium_crypto_sign_verify_detached($signature_bin, $canonical_message, $public_key_bin)) {
            throw new RuntimeException('Ed25519 cryptographic signature verification failed.');
        }

        $decoded_payload = json_decode($raw_payload, true);
        if (! is_array($decoded_payload) || json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException('Verified payload is not valid JSON.');
        }

        return $decoded_payload;
    }
}
