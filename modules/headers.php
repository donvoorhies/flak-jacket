<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_send_security_headers(): void
{
    // Bail early once output starts to avoid PHP header warnings.
    if (headers_sent()) {
        return;
    }

    $settings = fj_get_settings();

    // HSTS must only be sent for HTTPS responses.
    if (!empty($settings['headers_hsts_enabled']) && is_ssl()) {
        $max_age = max(0, (int) $settings['headers_hsts_max_age']);
        $parts = ['max-age=' . $max_age];
        if (!empty($settings['headers_hsts_include_subdomains'])) {
            $parts[] = 'includeSubDomains';
        }
        if (!empty($settings['headers_hsts_preload'])) {
            $parts[] = 'preload';
        }
        header('Strict-Transport-Security: ' . implode('; ', $parts));
    }

    if (!empty($settings['headers_xfo_enabled'])) {
        $xfo = in_array($settings['headers_xfo_value'], ['SAMEORIGIN', 'DENY'], true)
            ? $settings['headers_xfo_value']
            : 'SAMEORIGIN';
        header('X-Frame-Options: ' . $xfo);
    }

    if (!empty($settings['headers_xcto_enabled'])) {
        header('X-Content-Type-Options: nosniff');
    }

    if (!empty($settings['headers_referrer_enabled'])) {
        $allowed = [
            'no-referrer',
            'same-origin',
            'strict-origin',
            'strict-origin-when-cross-origin',
            'no-referrer-when-downgrade',
        ];
        $value = in_array($settings['headers_referrer_policy'], $allowed, true)
            ? $settings['headers_referrer_policy']
            : 'strict-origin-when-cross-origin';
        header('Referrer-Policy: ' . $value);
    }

    if (!empty($settings['headers_permissions_enabled'])) {
        $policy = fj_normalize_permissions_policy((string) $settings['headers_permissions_policy']);
        if ($policy !== '') {
            header('Permissions-Policy: ' . $policy);
        }
    }

    if (!empty($settings['headers_csp_enabled'])) {
        $csp = trim((string) $settings['headers_csp_value']);
        if ($csp !== '') {
            header('Content-Security-Policy: ' . $csp);
        }
    }
}
add_action('send_headers', 'fj_send_security_headers');

function fj_normalize_permissions_policy(string $input): string
{
    $lines = preg_split('/\r\n|\r|\n/', $input) ?: [];
    $normalized = [];

    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '') {
            continue;
        }
        $normalized[] = preg_replace('/\s+/', ' ', $line);
    }

    return implode(', ', array_filter($normalized));
}
