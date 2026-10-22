<?php

declare(strict_types=1);

namespace Gracewell\SecurityPro\Recovery;

use wpdb;
use RuntimeException;

if (! defined('ABSPATH')) {
    exit;
}

final class Gracewell_Safe_DB_Restore
{
    private wpdb $db;

    public function __construct(wpdb $db)
    {
        $this->db = $db;
    }

    /**
     * Perform an atomic, recoverable table cutover after staging import validation.
     *
     * @param array $table_manifest Map of [ 'wp_posts' => [ 'staging' => '_gw_stage_wp_posts', 'expected_rows' => 150 ] ]
     */
    public function verify_and_cutover(array $table_manifest): array
    {
        $rename_pairs  = [];
        $rollback_map  = [];
        $timestamp_tag = gmdate('YmdHis');

        // 1. Pre-cutover verification of all staged tables
        foreach ($table_manifest as $live_table => $meta) {
            $staging_table = $this->sanitize_identifier($meta['staging']);
            $live_clean    = $this->sanitize_identifier($live_table);
            $expected_rows = (int)$meta['expected_rows'];

            $exists = $this->db->get_var($this->db->prepare('SHOW TABLES LIKE \%s', $staging_table));
            if ($exists !== $staging_table) {
                throw new RuntimeException(sprintf('Staging table %s is missing; aborting cutover.', $staging_table));
            }

            $actual_rows = (int)$this->db->get_var("SELECT COUNT(*) FROM `{$staging_table}`");
            if ($actual_rows !== $expected_rows) {
                throw new RuntimeException(sprintf(
                    'Row count mismatch on %s: expected %d, found %d. Live database untouched.',
                    $staging_table,
                    $expected_rows,
                    $actual_rows
                ));
            }

            $backup_table           = "_gw_old_{$timestamp_tag}_{$live_clean}";
            $rename_pairs[]         = "`{$live_clean}` TO `{$backup_table}`, `{$staging_table}` TO `{$live_clean}`";
            $rollback_map[$live_clean] = $backup_table;
        }

        // 2. Atomic MySQL RENAME TABLE cutover (single statement, transactional metadata lock)
        $rename_sql = 'RENAME TABLE ' . implode(', ', $rename_pairs);
        $result     = $this->db->query($rename_sql);

        if ($result === false) {
            throw new RuntimeException('Atomic RENAME TABLE cutover failed: ' . $this->db->last_error);
        }

        return [
            'status'       => 'completed',
            'rollback_map' => $rollback_map,
            'timestamp'    => $timestamp_tag,
        ];
    }

    /**
     * Rollback to the previous live tables if post-restore health checks fail.
     */
    public function rollback_cutover(array $rollback_map): bool
    {
        $pairs = [];
        foreach ($rollback_map as $live_table => $backup_table) {
            $live_clean   = $this->sanitize_identifier($live_table);
            $backup_clean = $this->sanitize_identifier($backup_table);
            $failed_table = "_gw_failed_{$live_clean}";
            $pairs[]      = "`{$live_clean}` TO `{$failed_table}`, `{$backup_clean}` TO `{$live_clean}`";
        }

        $sql = 'RENAME TABLE ' . implode(', ', $pairs);
        return $this->db->query($sql) !== false;
    }

    private function sanitize_identifier(string $identifier): string
    {
        $clean = preg_replace('/[^a-zA-Z0-9_]/', '', $identifier);
        if (! $clean || $clean !== $identifier) {
            throw new RuntimeException('Invalid SQL table identifier: ' . $identifier);
        }
        return $clean;
    }
}
