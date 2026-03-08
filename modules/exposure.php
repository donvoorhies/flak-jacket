<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_maybe_harden_exposure(): void
{
    $settings = fj_get_settings();
    $compat = fj_get_compatibility();

    // Avoid duplicating behavior when another plugin already owns this hardening.
    if (!empty($settings['exposure_remove_version']) && empty($compat['handled']['remove_version'])) {
        add_filter('the_generator', '__return_empty_string');
        add_filter('style_loader_src', 'fj_strip_version_query', 9999);
        add_filter('script_loader_src', 'fj_strip_version_query', 9999);
    }

    if (!empty($settings['exposure_disable_xmlrpc']) && empty($compat['handled']['disable_xmlrpc'])) {
        add_filter('xmlrpc_enabled', '__return_false');
    }

    if (!empty($settings['exposure_disable_login_hints'])) {
        add_filter('login_errors', 'fj_exposure_generic_login_error', 9999);
    }
}
add_action('plugins_loaded', 'fj_maybe_harden_exposure', 30);

function fj_strip_version_query(string $src): string
{
    // Keep non-version query arguments intact while removing only the ver marker.
    $parts = wp_parse_url($src);
    if (empty($parts['query'])) {
        return $src;
    }

    parse_str($parts['query'], $query);
    if (!isset($query['ver'])) {
        return $src;
    }

    unset($query['ver']);
    $base = strtok($src, '?');

    if (empty($query)) {
        return (string) $base;
    }

    return (string) $base . '?' . http_build_query($query);
}

function fj_exposure_generic_login_error(string $error): string
{
    return __('Login failed. Please check your credentials.', FJ_TEXT_DOMAIN);
}
