<?php

declare(strict_types=1);

namespace Gracewell\SecurityPro\Vulnerabilities;

if (! defined('ABSPATH')) {
    exit;
}

final class Gracewell_Virtual_Patch_Engine
{

    /**
     * Build canonical inventory of core, plugins, themes, and MU-plugins.
     *
     * @return array<string, array{type: string, slug: string, version: string}>
     */
    public function get_component_inventory(): array
    {
        global $wp_version;

        $inventory = [
            'core:wordpress' => [
                'type'    => 'core',
                'slug'    => 'wordpress',
                'version' => (string) $wp_version,
            ],
        ];

        if (! function_exists('get_plugins') && defined('ABSPATH')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }

        if (function_exists('get_plugins')) {
            $active_plugins = (array) get_option('active_plugins', []);
            if (is_multisite()) {
                $network_plugins = array_keys((array) get_site_option('active_sitewide_plugins', []));
                $active_plugins  = array_unique(array_merge($active_plugins, $network_plugins));
            }

            foreach (get_plugins() as $plugin_file => $data) {
                if (! in_array($plugin_file, $active_plugins, true)) {
                    continue;
                }
                $slug = dirname($plugin_file);
                if ($slug === '.') {
                    $slug = basename($plugin_file, '.php');
                }
                $inventory['plugin:' . $slug] = [
                    'type'    => 'plugin',
                    'slug'    => $slug,
                    'version' => (string) ($data['Version'] ?? '0.0.0'),
                ];
            }
        }

        if (function_exists('wp_get_themes')) {
            $active_theme = get_stylesheet();
            $themes       = wp_get_themes();
            if (isset($themes[$active_theme])) {
                $inventory['theme:' . $active_theme] = [
                    'type'    => 'theme',
                    'slug'    => $active_theme,
                    'version' => (string) $themes[$active_theme]->get('Version'),
                ];
            }
        }

        return $inventory;
    }

    /**
     * Filter virtual patches so only those matching currently vulnerable installed components remain active.
     * Automatically retires patches when a plugin/theme/core is updated.
     */
    public function get_applicable_patches(array $signed_patches, array $inventory): array
    {
        $applicable = [];

        foreach ($signed_patches as $patch) {
            $component_id = (string) ($patch['component_id'] ?? '');
            if (! isset($inventory[$component_id])) {
                continue;
            }

            $installed_ver = $inventory[$component_id]['version'];
            $min_affected  = (string) ($patch['min_version'] ?? '0.0.0');
            $fixed_in      = (string) ($patch['fixed_in'] ?? '');

            $is_vulnerable = version_compare($installed_ver, $min_affected, '>=')
                && ($fixed_in === '' || version_compare($installed_ver, $fixed_in, '<'));

            if ($is_vulnerable) {
                $applicable[] = $patch;
            }
        }

        return $applicable;
    }

    /**
     * Evaluate incoming request against active CVE-specific virtual patches.
     */
    public function evaluate_request(array $applicable_patches, string $uri, string $method, array $params): array
    {
        // Endpoint scope must be evaluated against the actual URL path, not the
        // query string (which the attacker controls). An empty endpoint is invalid.
        $request_path = parse_url($uri, PHP_URL_PATH);
        if (! is_string($request_path) || ! str_starts_with($request_path, '/')) {
            return ['matched' => false, 'action' => 'allow', 'patch_id' => null];
        }
        $request_path = rtrim($request_path, '/') ?: '/';
        $method = strtoupper($method);

        foreach ($applicable_patches as $patch) {
            if (! is_array($patch) || empty($patch['id'])) {
                continue;
            }
            $methods = array_map('strtoupper', array_filter((array) ($patch['methods'] ?? []), 'is_string'));
            if ($methods !== [] && ! in_array($method, $methods, true)) {
                continue;
            }

            $endpoint = (string) ($patch['endpoint'] ?? '');
            if ($endpoint === '' || $endpoint[0] !== '/') {
                continue;
            }
            $endpoint = rtrim($endpoint, '/') ?: '/';
            // Permit children of a specifically named endpoint (e.g. /orders/42),
            // but never /orders-other or /?next=/orders.
            if ($request_path !== $endpoint && ! str_starts_with($request_path, rtrim($endpoint, '/') . '/')) {
                continue;
            }

            if (! empty($patch['exclude_if_cap']) && function_exists('current_user_can') && current_user_can((string) $patch['exclude_if_cap'])) {
                continue;
            }

            $target = (string) ($patch['target_param'] ?? '');
            $regex = (string) ($patch['condition_regex'] ?? '');
            if ($target === '' || $regex === '' || ! array_key_exists($target, $params)) {
                continue;
            }
            // Arrays/objects must not be coerced to the string "Array" or "Object".
            // Leave nested request matching to an explicitly scoped signed rule.
            $value = $params[$target];
            if (! is_scalar($value) || strlen((string) $value) > 8192) {
                continue;
            }
            if (@preg_match($regex, (string) $value) !== 1) {
                continue;
            }

            return [
                'matched'  => true,
                'action'   => ($patch['mode'] ?? 'detect') === 'block' ? 'block' : 'detect',
                'patch_id' => $patch['id'],
                'cve'      => $patch['cve'] ?? 'UNASSIGNED',
                'severity' => $patch['severity'] ?? 'high',
            ];
        }

        return ['matched' => false, 'action' => 'allow', 'patch_id' => null];
    }
}
