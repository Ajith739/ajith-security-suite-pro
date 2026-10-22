<?php

declare(strict_types=1);

namespace Gracewell\SecurityPro\Intelligence;

use InvalidArgumentException;
use RuntimeException;

if (! defined('ABSPATH')) {
    exit;
}

/**
 * Manages the lifecycle of signed threat feeds:
 * client fetch -> verify -> stage -> activate -> rollback, plus emergency revocation.
 */
final class Gracewell_Threat_Feed_Manager
{
    private string $storage_dir;
    private Gracewell_Signed_Feed_Verifier $verifier;
    private string $engine_version;

    public function __construct(string $storage_dir, Gracewell_Signed_Feed_Verifier $verifier, string $engine_version = '1.3.0')
    {
        $normalized = rtrim(str_replace('\\', '/', $storage_dir), '/');
        if ('' === $normalized) {
            throw new InvalidArgumentException('Storage directory path cannot be empty.');
        }

        if (! is_dir($normalized)) {
            if (! @mkdir($normalized, 0700, true) && ! is_dir($normalized)) {
                throw new RuntimeException(sprintf('Failed to create threat feed storage directory: %s', $normalized));
            }
        }

        $real = realpath($normalized);
        if (false === $real) {
            throw new RuntimeException(sprintf('Storage directory path is invalid: %s', $normalized));
        }

        $this->storage_dir    = str_replace('\\', '/', $real);
        $this->verifier       = $verifier;
        $this->engine_version = $engine_version;
    }

    /**
     * Stage an incoming signed feed envelope after cryptographic verification.
     *
     * @param array  $envelope  Signed envelope.
     * @param string $feed_type Feed type identifier.
     * @return array Verified payload data.
     */
    public function stage(array $envelope, string $feed_type): array
    {
        $this->validate_feed_type($feed_type);

        $state = $this->load_state();
        $incoming_version = (int) ($envelope['version'] ?? 0);

        if (in_array($incoming_version, $state['revoked'][$feed_type] ?? [], true)) {
            throw new RuntimeException(sprintf('Feed version %d for %s has been revoked.', $incoming_version, $feed_type));
        }

        $active_version = (int) ($state['active_versions'][$feed_type] ?? 0);

        // Verify cryptographic integrity, anti-rollback, expiration, and engine version.
        $payload = $this->verifier->verify_and_extract($envelope, $feed_type, $active_version, $this->engine_version);

        $staged_file = $this->get_feed_path($feed_type, 'staged');
        $this->atomic_write_json($staged_file, $envelope);

        return $payload;
    }

    /**
     * Atomically activate a verified staged feed, backing up the current active feed to rollback.
     *
     * @param string $feed_type Feed type identifier.
     * @return int Activated version number.
     */
    public function activate(string $feed_type): int
    {
        $this->validate_feed_type($feed_type);

        $staged_file = $this->get_feed_path($feed_type, 'staged');
        if (! is_file($staged_file)) {
            throw new RuntimeException(sprintf('No staged feed found for %s to activate.', $feed_type));
        }

        $staged_data = $this->read_json_file($staged_file);
        $version     = (int) ($staged_data['version'] ?? 0);

        $active_file   = $this->get_feed_path($feed_type, 'active');
        $rollback_file = $this->get_feed_path($feed_type, 'rollback');

        // If an active feed exists, promote it to rollback.
        if (is_file($active_file)) {
            if (is_file($rollback_file)) {
                @unlink($rollback_file);
            }
            if (! @rename($active_file, $rollback_file)) {
                throw new RuntimeException(sprintf('Failed to rotate current active feed to rollback for %s.', $feed_type));
            }
        }

        // Promote staged to active.
        if (! @rename($staged_file, $active_file)) {
            throw new RuntimeException(sprintf('Failed to promote staged feed to active for %s.', $feed_type));
        }

        $state = $this->load_state();
        $state['active_versions'][$feed_type] = $version;
        $state['updated_at'][$feed_type]      = time();
        $this->save_state($state);

        return $version;
    }

    /**
     * Rollback the active feed to the previous rollback snapshot.
     *
     * @param string $feed_type Feed type identifier.
     * @return int Rolled-back version number.
     */
    public function rollback(string $feed_type): int
    {
        $this->validate_feed_type($feed_type);

        $rollback_file = $this->get_feed_path($feed_type, 'rollback');
        if (! is_file($rollback_file)) {
            throw new RuntimeException(sprintf('No rollback snapshot available for %s.', $feed_type));
        }

        $rollback_data = $this->read_json_file($rollback_file);
        $version       = (int) ($rollback_data['version'] ?? 0);

        $state = $this->load_state();
        if (in_array($version, $state['revoked'][$feed_type] ?? [], true)) {
            throw new RuntimeException(sprintf('Cannot rollback: version %d for %s is revoked.', $version, $feed_type));
        }

        $active_file = $this->get_feed_path($feed_type, 'active');
        if (is_file($active_file)) {
            @unlink($active_file);
        }

        if (! @rename($rollback_file, $active_file)) {
            throw new RuntimeException(sprintf('Failed to restore rollback feed for %s.', $feed_type));
        }

        $state['active_versions'][$feed_type] = $version;
        $state['updated_at'][$feed_type]      = time();
        $this->save_state($state);

        return $version;
    }

    /**
     * Emergency revocation of a specific feed version.
     * If the revoked version is currently active, triggers rollback or deactivation.
     *
     * @param string $feed_type Feed type identifier.
     * @param int    $version   Version to revoke.
     */
    public function emergency_revoke(string $feed_type, int $version): void
    {
        $this->validate_feed_type($feed_type);

        $state = $this->load_state();
        if (! isset($state['revoked'][$feed_type])) {
            $state['revoked'][$feed_type] = [];
        }

        if (! in_array($version, $state['revoked'][$feed_type], true)) {
            $state['revoked'][$feed_type][] = $version;
        }

        $current_active = (int) ($state['active_versions'][$feed_type] ?? 0);

        if ($current_active === $version) {
            // Check if rollback exists and is not revoked.
            $rollback_file = $this->get_feed_path($feed_type, 'rollback');
            $can_rollback  = false;

            if (is_file($rollback_file)) {
                $rb_data = $this->read_json_file($rollback_file);
                $rb_ver  = (int) ($rb_data['version'] ?? 0);
                if (! in_array($rb_ver, $state['revoked'][$feed_type], true)) {
                    $can_rollback = true;
                }
            }

            if ($can_rollback) {
                $this->save_state($state);
                $this->rollback($feed_type);
                return;
            }

            // Deactivate and remove active feed.
            $active_file = $this->get_feed_path($feed_type, 'active');
            if (is_file($active_file)) {
                @unlink($active_file);
            }
            $state['active_versions'][$feed_type] = 0;
        }

        // Also purge staged file if it matches the revoked version.
        $staged_file = $this->get_feed_path($feed_type, 'staged');
        if (is_file($staged_file)) {
            $staged_data = $this->read_json_file($staged_file);
            if ((int) ($staged_data['version'] ?? 0) === $version) {
                @unlink($staged_file);
            }
        }

        $this->save_state($state);
    }

    /**
     * Retrieve the active verified payload for a feed type, checking for expiration.
     *
     * @param string $feed_type Feed type identifier.
     * @return array|null Verified payload array or null if inactive/expired.
     */
    public function get_active_payload(string $feed_type): ?array
    {
        $this->validate_feed_type($feed_type);

        $active_file = $this->get_feed_path($feed_type, 'active');
        if (! is_file($active_file)) {
            return null;
        }

        $envelope = $this->read_json_file($active_file);
        if (time() >= (int) ($envelope['expires_at'] ?? 0)) {
            return null;
        }

        $raw_payload = (string) ($envelope['payload'] ?? '');
        $decoded     = json_decode($raw_payload, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * Retrieve the current state map.
     *
     * @return array State map.
     */
    public function get_state(): array
    {
        return $this->load_state();
    }

    private function validate_feed_type(string $feed_type): void
    {
        if (! preg_match('/^[a-z0-9_-]+$/', $feed_type)) {
            throw new InvalidArgumentException(sprintf('Invalid feed type identifier: %s', $feed_type));
        }
    }

    private function get_feed_path(string $feed_type, string $stage): string
    {
        return sprintf('%s/%s.%s.json', $this->storage_dir, $feed_type, $stage);
    }

    private function load_state(): array
    {
        $state_file = $this->storage_dir . '/state.json';
        if (! is_file($state_file)) {
            return [
                'active_versions' => [],
                'revoked'         => [],
                'updated_at'      => [],
            ];
        }

        return $this->read_json_file($state_file);
    }

    private function save_state(array $state): void
    {
        $state_file = $this->storage_dir . '/state.json';
        $this->atomic_write_json($state_file, $state);
    }

    private function read_json_file(string $path): array
    {
        $contents = @file_get_contents($path);
        if (false === $contents) {
            throw new RuntimeException(sprintf('Failed to read file: %s', $path));
        }

        $data = json_decode($contents, true);
        if (! is_array($data) || json_last_error() !== JSON_ERROR_NONE) {
            throw new RuntimeException(sprintf('Malformed JSON in file: %s', $path));
        }

        return $data;
    }

    private function atomic_write_json(string $path, array $data): void
    {
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if (false === $json) {
            throw new RuntimeException('Failed to JSON encode data.');
        }

        $temp_file = $path . '.tmp.' . bin2hex(random_bytes(8));
        $written   = @file_put_contents($temp_file, $json);

        if (false === $written || strlen($json) !== $written) {
            if (is_file($temp_file)) {
                @unlink($temp_file);
            }
            throw new RuntimeException(sprintf('Failed to write temporary file: %s', $temp_file));
        }

        @chmod($temp_file, 0600);

        if (! @rename($temp_file, $path)) {
            if (is_file($temp_file)) {
                @unlink($temp_file);
            }
            throw new RuntimeException(sprintf('Failed to atomically rename %s to %s', $temp_file, $path));
        }
    }
}
