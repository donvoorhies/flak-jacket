<?php
/**
 * Plugin Name: Flak Jacket
 * Plugin URI: https://github.com/donvoorhies/mcht_app
 * Description: Lightweight WordPress protection. No bloat, no cloud, no monthly fee.
 * Version: 1.0.0
 * Author: donvoorhies
 * License: GPL-2.0+
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: flak-jacket
 * Requires at least: 5.9
 * Requires PHP: 8.0
 */

if (!defined('ABSPATH')) {
    exit;
}

define('FJ_VERSION', '1.0.0');
define('FJ_PLUGIN_FILE', __FILE__);
define('FJ_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('FJ_PLUGIN_URL', plugin_dir_url(__FILE__));
define('FJ_OPTION_KEY', 'fj_settings');
define('FJ_TEXT_DOMAIN', 'flak-jacket');
define('FJ_LOGIN_TABLE', $GLOBALS['wpdb']->prefix . 'fj_login_attempts');

require_once FJ_PLUGIN_DIR . 'modules/compatibility.php';
require_once FJ_PLUGIN_DIR . 'modules/files.php';
require_once FJ_PLUGIN_DIR . 'modules/headers.php';
require_once FJ_PLUGIN_DIR . 'modules/login.php';
require_once FJ_PLUGIN_DIR . 'modules/exposure.php';
require_once FJ_PLUGIN_DIR . 'modules/dashboard.php';
require_once FJ_PLUGIN_DIR . 'modules/admin.php';

register_activation_hook(__FILE__, 'fj_activate');
function fj_activate()
{
    // Preserve any existing saved options while ensuring new defaults are added.
    $existing = get_option('fj_settings', []);
    update_option('fj_settings', array_merge(fj_defaults(), is_array($existing) ? $existing : []));

    // Create persistence needed by login lockout telemetry before first request handling.
    fj_create_login_attempts_table();

    // Keep file protections in sync on activation when file features are already enabled.
    fj_files_sync_htaccess();
}

register_deactivation_hook(__FILE__, 'fj_deactivate');
function fj_deactivate()
{
    set_transient('fj_deactivated_notice', true, 30);
}

function fj_defaults(): array
{
    return [
        'login_limit_enabled' => true,
        'login_max_attempts' => 5,
        'login_lockout_minutes' => 30,
        'login_rename_enabled' => false,
        'login_custom_slug' => 'login',
        'login_allowed_ips' => '',
        'login_two_factor_enabled' => true,

        'headers_hsts_enabled' => false,
        'headers_hsts_max_age' => 31536000,
        'headers_hsts_include_subdomains' => true,
        'headers_hsts_preload' => false,
        'headers_xfo_enabled' => false,
        'headers_xfo_value' => 'SAMEORIGIN',
        'headers_xcto_enabled' => false,
        'headers_referrer_enabled' => false,
        'headers_referrer_policy' => 'strict-origin-when-cross-origin',
        'headers_permissions_enabled' => false,
        'headers_permissions_policy' => "camera=()\nmicrophone=()\ngeolocation=()",
        'headers_csp_enabled' => false,
        'headers_csp_value' => '',

        'files_protect_wp_config' => false,
        'files_protect_htaccess' => false,
        'files_disable_indexes' => false,
        'files_block_meta_files' => false,

        'exposure_remove_version' => false,
        'exposure_disable_xmlrpc' => false,
        'exposure_disable_login_hints' => false,
    ];
}

function fj_get_settings(): array
{
    $saved = get_option(FJ_OPTION_KEY, []);
    if (!is_array($saved)) {
        $saved = [];
    }
    // Defaults are always merged so downstream reads can treat keys as present.
    return array_merge(fj_defaults(), $saved);
}

function fj_update_settings(array $settings): bool
{
    return update_option(FJ_OPTION_KEY, $settings);
}

function fj_sanitize_checkbox($value): bool
{
    return (bool) $value;
}

function fj_admin_notice_deactivated(): void
{
    if (!is_admin() || !current_user_can('manage_options')) {
        return;
    }

    if (get_transient('fj_deactivated_notice')) {
        delete_transient('fj_deactivated_notice');
        echo '<div class="notice notice-info"><p>' . esc_html__(
            'Flak Jacket was deactivated. Any existing .htaccess rules were left in place intentionally to avoid breaking your site. If you want them removed, reactivate Flak Jacket and use Flak Jacket → Settings → Files.',
            FJ_TEXT_DOMAIN
        ) . '</p></div>';
    }
}
add_action('admin_notices', 'fj_admin_notice_deactivated');

function fj_load_textdomain(): void
{
    load_plugin_textdomain(FJ_TEXT_DOMAIN, false, dirname(plugin_basename(FJ_PLUGIN_FILE)) . '/languages');
}
add_action('plugins_loaded', 'fj_load_textdomain');
