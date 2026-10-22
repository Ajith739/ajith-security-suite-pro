<?php

declare(strict_types=1);

namespace Gracewell\SecurityPro\Alerts;

use RuntimeException;

if (! defined('ABSPATH')) {
    exit;
}

final class Gracewell_SSRF_Safe_Dispatcher
{

    /**
     * Validate a webhook URL against SSRF vectors (HTTPS-only, public non-reserved IP resolution).
     */
    public function validate_webhook_destination(string $url): string
    {
        $parts = parse_url($url);
        if (! is_array($parts) || strtolower((string) ($parts['scheme'] ?? '')) !== 'https') {
            throw new RuntimeException('Webhook URL must use HTTPS.');
        }

        $host = (string) ($parts['host'] ?? '');
        if ($host === '') {
            throw new RuntimeException('Webhook URL is missing a valid hostname.');
        }

        $raw_host = trim($host, '[]');
        if (filter_var($raw_host, FILTER_VALIDATE_IP)) {
            $ips = [$raw_host];
        } else {
            $records = @dns_get_record($host, DNS_A + DNS_AAAA);
            if (empty($records)) {
                $ip = gethostbyname($host);
                $ips = ($ip !== $host) ? [$ip] : [];
            } else {
                $ips = array_filter(array_map(static fn(array $r) => $r['ip'] ?? $r['ipv6'] ?? null, $records));
            }
        }

        if (empty($ips)) {
            throw new RuntimeException('Unable to resolve webhook hostname.');
        }

        foreach ($ips as $ip) {
            $valid_public_ip = filter_var(
                $ip,
                FILTER_VALIDATE_IP,
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            );
            if ($valid_public_ip === false) {
                throw new RuntimeException(sprintf('SSRF blocked: webhook host resolves to private or reserved IP (%s).', $ip));
            }
        }

        return $url;
    }
}
