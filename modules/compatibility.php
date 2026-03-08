<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_get_compatibility(): array
{
    static $result = null;

    // Cache once per request because plugin state does not change mid-request.
    if ($result !== null) {
        return $result;
    }

    if (!function_exists('is_plugin_active')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $active_plugins = (array) get_option('active_plugins', []);
    $network_plugins = is_multisite() ? array_keys((array) get_site_option('active_sitewide_plugins', [])) : [];
    $all_active = array_merge($active_plugins, $network_plugins);

    $is_oap_active = fj_plugin_is_active_by_slug($all_active, ['oap', 'optimization-anthology-plugin']);
    $is_cccp_active = fj_plugin_is_active_by_slug($all_active, ['cccp', 'clean-cookie-consent']);
    $is_cpcss_active = fj_plugin_is_active_by_slug($all_active, ['critical-path-css-v2']);

    // handled flags gate settings/UI so we do not duplicate protections provided elsewhere.
    $result = [
        'oap' => $is_oap_active,
        'cccp' => $is_cccp_active,
        'critical_path_css_v2' => $is_cpcss_active,
        'handled' => [
            'remove_version' => $is_oap_active,
            'disable_xmlrpc' => $is_oap_active,
            'remove_header_info' => $is_oap_active,
        ],
    ];

    return $result;
}

function fj_plugin_is_active_by_slug(array $active_plugins, array $slugs): bool
{
    foreach ($active_plugins as $plugin_path) {
        foreach ($slugs as $slug) {
            if (stripos($plugin_path, $slug . '/') !== false || stripos($plugin_path, '/' . $slug . '.php') !== false) {
                return true;
            }
        }
    }

    return false;
}
