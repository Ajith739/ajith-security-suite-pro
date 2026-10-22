<?php
/**
 * Read-only operational security readiness checks.
 *
 * This is a configuration and hook health check, NOT an exploit test,
 * malware-detection score, penetration test, or verification of external services.
 * No secrets, IP addresses, backup paths, or configuration values are disclosed.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Diagnose visible enforcement and prerequisites without changing site state. */
final class GWQSH_Security_Doctor {

    /** Strict schema for UI and CLI consumers: no untrusted configuration strings. */
    private static function item( $id, $title, $state, $detail ) {
        return array(
            'id'     => $id,
            'title'  => $title,
            'state'  => $state,
            'detail' => $detail,
        );
    }

    /**
     * Read-only site-local diagnostic. Requires a security administrator.
     *
     * @return array|WP_Error Checks and explicit validation limitations.
     */
    public static function collect() {
        if ( ! current_user_can( GWQSH_Admin::management_capability() ) ) {
            return new WP_Error( 'forbidden', 'Security administrator permission required.' );
        }

        $checks = array();
        $active = GWQSH_Settings::is_active();
        $checks[] = self::item(
            'enforcement', 'Plugin enforcement', $active ? 'ok' : 'attention',
            $active ? 'Global security enforcement is enabled.' : 'Global enforcement is disabled. Enable protection when it is safe to do so.'
        );

        $waf    = GWQSH_Firewall::settings();
        $policy = GWQSH_Enterprise_Config::get( 'waf' );
        $mode   = $policy['mode'] ?? 'disabled';
        $hooked = false !== has_action( 'init', array( 'GWQSH_Firewall', 'inspect' ) )
            && false !== has_filter( 'rest_pre_dispatch', array( 'GWQSH_Firewall', 'inspect_rest' ) );
        $blocking = $active && ! empty( $waf['enabled'] ) && $hooked && ! in_array( $mode, array( 'disabled', 'recovery', 'report' ), true );
        $checks[] = self::item(
            'waf', 'WordPress WAF hooks and policy', $blocking ? 'ok' : 'attention',
            $blocking
                ? 'WAF hooks are registered and blocking mode is configured. This does not verify the server-level loader or attack detection.'
                : 'WAF may be disabled, in reporting/recovery mode, or missing required runtime hooks. Check Firewall & Cleanup.'
        );

        $bot_control = ! empty( $waf['bots'] ) && ! empty( $policy['bot_probe'] );
        $checks[] = self::item(
            'bot_probes', 'Sensitive-file bot protection',
            $blocking && $bot_control ? 'ok' : 'attention',
            $blocking && $bot_control
                ? ( ! empty( $policy['bot_auto_hold'] ) ? 'Anonymous private-file probes are blocked; the optional repeated-probe IP hold is enabled.' : 'Anonymous private-file probes are blocked; the optional repeated-probe IP hold is disabled (safer on shared networks).' )
                : 'Private-file probe protection is not enforcing (firewall block mode, bot switch and bot-probe switch are required).'
        );

        $scan = GWQSH_Scheduler::settings();
        $scheduled = (bool) wp_next_scheduled( GWQSH_Scheduler::HOOK );
        $checks[] = self::item(
            'integrity_schedule', 'Scheduled file integrity checks',
            $active && ! empty( $scan['enabled'] ) && $scheduled ? 'ok' : 'attention',
            $active && ! empty( $scan['enabled'] ) && $scheduled
                ? 'An integrity-scan event is scheduled; actual execution and scan results still require checking.'
                : 'No enabled, scheduled integrity scan was confirmed. Configure a regular scan.'
        );

        $auditing = (bool) wp_next_scheduled( 'gwqsh_daily_log_cleanup' );
        $checks[] = self::item(
            'audit_retention', 'Audit retention maintenance', $auditing ? 'ok' : 'attention',
            $auditing ? 'Audit-log maintenance is scheduled; event completeness is not verified.' : 'Audit-log retention maintenance is not scheduled.'
        );

        $sig = GWQSH_Signatures::health();
        $valid_sig = ! empty( $sig['configured'] ) && ! empty( $sig['verified_at'] )
            && is_numeric( $sig['expires_at'] ?? null ) && (int) $sig['expires_at'] > time()
            && 'Installed signatures within validity window' === ( $sig['coverage'] ?? '' );
        $checks[] = self::item(
            'signatures', 'Signed malware intelligence', $valid_sig ? 'ok' : 'attention',
            $valid_sig
                ? 'Verified signature data is present and not expired; this does not prove comprehensive detection.'
                : 'No currently configured, trusted, unexpired signature data was confirmed. Configure a licensed publisher and signing keys.'
        );

        $advisories = GWQSH_Vulnerabilities::database();
        $valid_advisory = is_array( $advisories ) && ! empty( $advisories['version'] )
            && isset( $advisories['expires_at'] ) && (int) $advisories['expires_at'] > time();
        $checks[] = self::item(
            'advisories', 'Signed vulnerability advisories', $valid_advisory ? 'ok' : 'attention',
            $valid_advisory
                ? 'A signed, currently valid advisory package was accepted. Coverage depends on the publisher.'
                : 'No trusted, current advisory package was confirmed. Virtual patch feeds must be separately configured.'
        );

        $uploads = GWQSH_Hardening::active( 'uploads' );
        $checks[] = self::item(
            'uploads', 'Uploads PHP hardening', $uploads ? 'ok' : 'attention',
            $uploads
                ? 'Upload hardening is enabled; verify server-specific rewrite/PHP execution behavior separately.'
                : 'Upload PHP hardening is disabled; review your web-server policy.'
        );

        $checks[] = self::item(
            'crypto', 'Signature-verification support',
            function_exists( 'sodium_crypto_sign_verify_detached' ) ? 'ok' : 'attention',
            function_exists( 'sodium_crypto_sign_verify_detached' )
                ? 'PHP sodium Ed25519 verification is available.'
                : 'PHP sodium/Ed25519 verification is unavailable. Signed intelligence cannot be verified.'
        );

        $cron_disabled = defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON;
        $checks[] = self::item(
            'cron', 'WordPress background task trigger', $cron_disabled ? 'info' : 'ok',
            $cron_disabled
                ? 'WP-Cron page triggers are disabled; verify that a separate system cron runs wp-cron.php.'
                : 'WP-Cron page triggering is enabled; actual job completion is not guaranteed.'
        );

        $ssl = 'https' === wp_parse_url( home_url( '/' ), PHP_URL_SCHEME );
        $checks[] = self::item(
            'https', 'HTTPS site configuration', $ssl ? 'ok' : 'attention',
            $ssl ? 'The configured home URL uses HTTPS.' : 'The configured site home URL is not HTTPS; check TLS and reverse-proxy settings.'
        );

        $debug_visible = defined( 'WP_DEBUG_DISPLAY' ) && WP_DEBUG_DISPLAY;
        $checks[] = self::item(
            'debug_display', 'Public PHP error display', $debug_visible ? 'attention' : 'ok',
            $debug_visible ? 'WP_DEBUG_DISPLAY is enabled; error output may disclose sensitive details.' : 'WP_DEBUG_DISPLAY is not explicitly enabled.'
        );

        $counts = array( 'ok' => 0, 'attention' => 0, 'info' => 0 );
        foreach ( $checks as $check ) {
            ++$counts[ $check['state'] ];
        }
        return array(
            'plugin_version' => GWQSH_VERSION,
            'generated_at'   => gmdate( 'c' ),
            'checks'         => $checks,
            'summary'        => $counts,
            'limitations'    => array(
                'Read-only configuration and runtime-hook inspection; not a security score or attack simulation.',
                'Scheduled does not mean a task ran successfully. Verify recent logs and scan timestamps.',
                'Active signed feeds require a legitimate publisher and keys; no external service is bundled.',
                'Filesystem hardening, backups, remediation and malware detection need independent end-to-end acceptance tests.',
            ),
        );
    }

    /** Escaped, admin-only display suitable for Settings page. */
    public static function render() {
        $report = self::collect();
        if ( is_wp_error( $report ) ) {
            return;
        }
        echo '<section class="card qs-card qs-set-card" id="gwqsh-security-doctor">';
        echo '<div class="card-head"><div class="ttl"><h2>Security Readiness Diagnostics</h2><p>Read-only, live configuration checks — not a protection score.</p></div></div>';
        echo '<p><strong>' . esc_html( (string) $report['summary']['ok'] ) . ' configured checks</strong> · ' . esc_html( (string) $report['summary']['attention'] ) . ' need attention · ' . esc_html( (string) $report['summary']['info'] ) . ' informational</p>';
        echo '<dl class="info-list qs-info-table">';
        foreach ( $report['checks'] as $check ) {
            $label = 'ok' === $check['state'] ? 'Configured' : ( 'info' === $check['state'] ? 'Review' : 'Attention' );
            echo '<div><dt><strong>' . esc_html( $check['title'] ) . '</strong><small style="display:block">' . esc_html( $check['detail'] ) . '</small></dt><dd>' . esc_html( $label ) . '</dd></div>';
        }
        echo '</dl><p><small>Passing a configuration check does not establish effective threat blocking or malware removal. Run integration and recovery tests in staging.</small></p>';
        echo '</section>';
    }
}
