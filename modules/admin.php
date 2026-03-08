<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_register_settings_submenu(): void
{
    add_submenu_page(
        'flak-jacket',
        __('Flak Jacket Settings', FJ_TEXT_DOMAIN),
        __('Settings', FJ_TEXT_DOMAIN),
        'manage_options',
        'flak-jacket-settings',
        'fj_render_settings_page'
    );
}
add_action('admin_menu', 'fj_register_settings_submenu');

function fj_get_tab_labels(): array
{
    return [
        'login' => __('Login', FJ_TEXT_DOMAIN),
        'headers' => __('Headers', FJ_TEXT_DOMAIN),
        'files' => __('Files', FJ_TEXT_DOMAIN),
        'exposure' => __('Exposure', FJ_TEXT_DOMAIN),
    ];
}

function fj_handle_settings_save(): void
{
    // Only process settings writes from privileged wp-admin requests.
    if (!is_admin() || !current_user_can('manage_options')) {
        return;
    }

    if (empty($_POST['fj_save_settings'])) {
        return;
    }

    check_admin_referer('fj_save_settings', 'fj_settings_nonce');

    // Keep posted tab constrained to known tabs to avoid arbitrary branch execution.
    $tab = isset($_POST['fj_current_tab']) ? sanitize_key(wp_unslash($_POST['fj_current_tab'])) : 'login';
    $tabs = fj_get_tab_labels();
    if (!isset($tabs[$tab])) {
        $tab = 'login';
    }

    $settings = fj_get_settings();

    if ($tab === 'login') {
        $settings['login_limit_enabled'] = !empty($_POST['login_limit_enabled']);
        $settings['login_max_attempts'] = max(1, (int) ($_POST['login_max_attempts'] ?? 5));
        $settings['login_lockout_minutes'] = max(1, (int) ($_POST['login_lockout_minutes'] ?? 30));
        $settings['login_rename_enabled'] = !empty($_POST['login_rename_enabled']) && !is_multisite();
        $settings['login_custom_slug'] = sanitize_title((string) ($_POST['login_custom_slug'] ?? 'login'));
        $settings['login_allowed_ips'] = sanitize_textarea_field((string) ($_POST['login_allowed_ips'] ?? ''));
        $settings['login_two_factor_enabled'] = !empty($_POST['login_two_factor_enabled']);
    }

    if ($tab === 'headers') {
        $settings['headers_hsts_enabled'] = !empty($_POST['headers_hsts_enabled']);
        $settings['headers_hsts_max_age'] = max(0, (int) ($_POST['headers_hsts_max_age'] ?? 31536000));
        $settings['headers_hsts_include_subdomains'] = !empty($_POST['headers_hsts_include_subdomains']);
        $settings['headers_hsts_preload'] = !empty($_POST['headers_hsts_preload']);

        $settings['headers_xfo_enabled'] = !empty($_POST['headers_xfo_enabled']);
        $xfo = sanitize_text_field((string) ($_POST['headers_xfo_value'] ?? 'SAMEORIGIN'));
        $settings['headers_xfo_value'] = in_array($xfo, ['SAMEORIGIN', 'DENY'], true) ? $xfo : 'SAMEORIGIN';

        $settings['headers_xcto_enabled'] = !empty($_POST['headers_xcto_enabled']);

        $settings['headers_referrer_enabled'] = !empty($_POST['headers_referrer_enabled']);
        $ref = sanitize_text_field((string) ($_POST['headers_referrer_policy'] ?? 'strict-origin-when-cross-origin'));
        $allowed_ref = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin', 'no-referrer-when-downgrade'];
        $settings['headers_referrer_policy'] = in_array($ref, $allowed_ref, true) ? $ref : 'strict-origin-when-cross-origin';

        $settings['headers_permissions_enabled'] = !empty($_POST['headers_permissions_enabled']);
        $settings['headers_permissions_policy'] = sanitize_textarea_field((string) ($_POST['headers_permissions_policy'] ?? ''));

        $settings['headers_csp_enabled'] = !empty($_POST['headers_csp_enabled']);
        $settings['headers_csp_value'] = sanitize_textarea_field((string) ($_POST['headers_csp_value'] ?? ''));
    }

    if ($tab === 'files') {
        // These flags drive .htaccess marker generation in fj_files_sync_htaccess().
        $settings['files_protect_wp_config'] = !empty($_POST['files_protect_wp_config']);
        $settings['files_protect_htaccess'] = !empty($_POST['files_protect_htaccess']);
        $settings['files_disable_indexes'] = !empty($_POST['files_disable_indexes']);
        $settings['files_block_meta_files'] = !empty($_POST['files_block_meta_files']);

        // Rebuild managed rules immediately after changing any file-protection setting.
        fj_files_sync_htaccess();
    }

    if ($tab === 'exposure') {
        $compat = fj_get_compatibility();
        $settings['exposure_remove_version'] = !empty($_POST['exposure_remove_version']) && empty($compat['handled']['remove_version']);
        $settings['exposure_disable_xmlrpc'] = !empty($_POST['exposure_disable_xmlrpc']) && empty($compat['handled']['disable_xmlrpc']);
        $settings['exposure_disable_login_hints'] = !empty($_POST['exposure_disable_login_hints']);
    }

    update_option('fj_settings', $settings);

    $url = add_query_arg([
        'page' => 'flak-jacket-settings',
        'tab' => $tab,
        'updated' => '1',
    ], admin_url('admin.php'));

    wp_safe_redirect($url);
    exit;
}
add_action('admin_init', 'fj_handle_settings_save');

function fj_render_settings_page(): void
{
    if (!current_user_can('manage_options')) {
        return;
    }

    $tabs = fj_get_tab_labels();
    $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'login';
    if (!isset($tabs[$tab])) {
        $tab = 'login';
    }

    $settings = fj_get_settings();
    $compat = fj_get_compatibility();

    ?>
    <div class="wrap fj-wrap">
        <h1><?php esc_html_e('Flak Jacket Settings', FJ_TEXT_DOMAIN); ?></h1>

        <?php if (!empty($_GET['updated'])) : ?>
            <div class="notice notice-success"><p><?php esc_html_e('Settings updated.', FJ_TEXT_DOMAIN); ?></p></div>
        <?php endif; ?>

        <h2 class="nav-tab-wrapper">
            <?php foreach ($tabs as $slug => $label) : ?>
                <a class="nav-tab <?php echo $tab === $slug ? 'nav-tab-active' : ''; ?>" href="<?php echo esc_url(add_query_arg(['page' => 'flak-jacket-settings', 'tab' => $slug], admin_url('admin.php'))); ?>"><?php echo esc_html($label); ?></a>
            <?php endforeach; ?>
        </h2>

        <form method="post">
            <?php wp_nonce_field('fj_save_settings', 'fj_settings_nonce'); ?>
            <input type="hidden" name="fj_save_settings" value="1" />
            <input type="hidden" name="fj_current_tab" value="<?php echo esc_attr($tab); ?>" />

            <table class="form-table" role="presentation">
                <?php if ($tab === 'login') : ?>
                    <tr><th><?php esc_html_e('Limit login attempts', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="login_limit_enabled" value="1" <?php checked(!empty($settings['login_limit_enabled'])); ?>> <?php esc_html_e('Enable lockout logic', FJ_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php esc_html_e('Max attempts', FJ_TEXT_DOMAIN); ?></th><td><input type="number" min="1" name="login_max_attempts" value="<?php echo esc_attr((string) $settings['login_max_attempts']); ?>"></td></tr>
                    <tr><th><?php esc_html_e('Lockout duration (minutes)', FJ_TEXT_DOMAIN); ?></th><td><input type="number" min="1" name="login_lockout_minutes" value="<?php echo esc_attr((string) $settings['login_lockout_minutes']); ?>"></td></tr>
                    <tr>
                        <th><?php esc_html_e('Rename login URL', FJ_TEXT_DOMAIN); ?></th>
                        <td>
                            <?php if (is_multisite()) : ?>
                                <p><strong><?php esc_html_e('Multisite detected:', FJ_TEXT_DOMAIN); ?></strong> <?php esc_html_e('This feature is intentionally disabled by default.', FJ_TEXT_DOMAIN); ?></p>
                            <?php endif; ?>
                            <label><input type="checkbox" name="login_rename_enabled" value="1" <?php checked(!empty($settings['login_rename_enabled']) && !is_multisite()); ?> <?php disabled(is_multisite()); ?>> <?php esc_html_e('Enable custom login slug', FJ_TEXT_DOMAIN); ?></label>
                            <p><input type="text" name="login_custom_slug" value="<?php echo esc_attr((string) $settings['login_custom_slug']); ?>"> <span class="description">/<?php esc_html_e('your-slug', FJ_TEXT_DOMAIN); ?></span></p>
                            <p class="description"><?php esc_html_e('Requests to /wp-login.php from non-admin IPs will return 404.', FJ_TEXT_DOMAIN); ?></p>
                        </td>
                    </tr>
                    <tr><th><?php esc_html_e('Admin IP allowlist', FJ_TEXT_DOMAIN); ?></th><td><textarea name="login_allowed_ips" rows="4" cols="40"><?php echo esc_textarea((string) $settings['login_allowed_ips']); ?></textarea><p class="description"><?php esc_html_e('One IP per line or comma-separated. Used for /wp-login.php access when rename is enabled.', FJ_TEXT_DOMAIN); ?></p></td></tr>
                    <tr><th><?php esc_html_e('Enable TOTP module', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="login_two_factor_enabled" value="1" <?php checked(!empty($settings['login_two_factor_enabled'])); ?>> <?php esc_html_e('Allow users to enable 2FA in profile', FJ_TEXT_DOMAIN); ?></label></td></tr>
                <?php endif; ?>

                <?php if ($tab === 'headers') : ?>
                    <tr><th>HSTS</th><td><label><input type="checkbox" name="headers_hsts_enabled" value="1" <?php checked(!empty($settings['headers_hsts_enabled'])); ?>> <?php esc_html_e('Enable Strict-Transport-Security', FJ_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php esc_html_e('HSTS max-age', FJ_TEXT_DOMAIN); ?></th><td><input type="number" min="0" name="headers_hsts_max_age" value="<?php echo esc_attr((string) $settings['headers_hsts_max_age']); ?>"></td></tr>
                    <tr><th><?php esc_html_e('HSTS flags', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="headers_hsts_include_subdomains" value="1" <?php checked(!empty($settings['headers_hsts_include_subdomains'])); ?>> includeSubDomains</label><br><label><input type="checkbox" name="headers_hsts_preload" value="1" <?php checked(!empty($settings['headers_hsts_preload'])); ?>> preload</label></td></tr>
                    <tr><th>X-Frame-Options</th><td><label><input type="checkbox" name="headers_xfo_enabled" value="1" <?php checked(!empty($settings['headers_xfo_enabled'])); ?>> <?php esc_html_e('Enable', FJ_TEXT_DOMAIN); ?></label><br><select name="headers_xfo_value"><option value="SAMEORIGIN" <?php selected($settings['headers_xfo_value'], 'SAMEORIGIN'); ?>>SAMEORIGIN</option><option value="DENY" <?php selected($settings['headers_xfo_value'], 'DENY'); ?>>DENY</option></select></td></tr>
                    <tr><th>X-Content-Type-Options</th><td><label><input type="checkbox" name="headers_xcto_enabled" value="1" <?php checked(!empty($settings['headers_xcto_enabled'])); ?>> nosniff</label></td></tr>
                    <tr><th>Referrer-Policy</th><td><label><input type="checkbox" name="headers_referrer_enabled" value="1" <?php checked(!empty($settings['headers_referrer_enabled'])); ?>> <?php esc_html_e('Enable', FJ_TEXT_DOMAIN); ?></label><br><select name="headers_referrer_policy">
                        <?php foreach (['no-referrer','same-origin','strict-origin','strict-origin-when-cross-origin','no-referrer-when-downgrade'] as $policy) : ?>
                            <option value="<?php echo esc_attr($policy); ?>" <?php selected($settings['headers_referrer_policy'], $policy); ?>><?php echo esc_html($policy); ?></option>
                        <?php endforeach; ?>
                    </select></td></tr>
                    <tr><th>Permissions-Policy</th><td><label><input type="checkbox" name="headers_permissions_enabled" value="1" <?php checked(!empty($settings['headers_permissions_enabled'])); ?>> <?php esc_html_e('Enable', FJ_TEXT_DOMAIN); ?></label><br><textarea name="headers_permissions_policy" rows="6" cols="60"><?php echo esc_textarea((string) $settings['headers_permissions_policy']); ?></textarea><p class="description"><?php esc_html_e("One directive per line. The 'ambient-light-sensor' feature may produce browser warnings in some configurations.", FJ_TEXT_DOMAIN); ?></p></td></tr>
                    <tr><th>Content-Security-Policy</th><td><label><input type="checkbox" name="headers_csp_enabled" value="1" <?php checked(!empty($settings['headers_csp_enabled'])); ?>> <?php esc_html_e('Enable', FJ_TEXT_DOMAIN); ?></label><br><textarea name="headers_csp_value" rows="8" cols="60"><?php echo esc_textarea((string) $settings['headers_csp_value']); ?></textarea><p class="description"><?php esc_html_e('CSP is powerful but complex — configure carefully.', FJ_TEXT_DOMAIN); ?> <a href="https://content-security-policy.com" target="_blank" rel="noopener">content-security-policy.com</a></p></td></tr>
                <?php endif; ?>

                <?php if ($tab === 'files') : ?>
                    <tr><th><?php esc_html_e('Protect wp-config.php', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="files_protect_wp_config" value="1" <?php checked(!empty($settings['files_protect_wp_config'])); ?>> <?php esc_html_e('Deny direct access in .htaccess', FJ_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php esc_html_e('Protect .htaccess', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="files_protect_htaccess" value="1" <?php checked(!empty($settings['files_protect_htaccess'])); ?>> <?php esc_html_e('Deny direct access in .htaccess', FJ_TEXT_DOMAIN); ?></label></td></tr>
                    <tr><th><?php esc_html_e('Disable directory browsing', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="files_disable_indexes" value="1" <?php checked(!empty($settings['files_disable_indexes'])); ?>> Options -Indexes</label></td></tr>
                    <tr><th><?php esc_html_e('Block metadata files', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="files_block_meta_files" value="1" <?php checked(!empty($settings['files_block_meta_files'])); ?>> <?php esc_html_e('readme.html, license.txt, wp-config-sample.php, install.php', FJ_TEXT_DOMAIN); ?></label></td></tr>
                    <tr>
                        <th><?php esc_html_e('Cleanup', FJ_TEXT_DOMAIN); ?></th>
                        <td>
                            <p><?php esc_html_e('Flak Jacket only writes inside # BEGIN Flak Jacket / # END Flak Jacket markers.', FJ_TEXT_DOMAIN); ?></p>
                            <?php // File action posts are handled by fj_files_handle_admin_actions() on admin_init. ?>
                            <?php wp_nonce_field('fj_files_action', 'fj_files_nonce'); ?>
                            <button type="submit" class="button" name="fj_action" value="remove_htaccess_rules" formnovalidate><?php esc_html_e('Remove Flak Jacket .htaccess rules', FJ_TEXT_DOMAIN); ?></button>
                            <button type="submit" class="button button-secondary" name="fj_action" value="delete_sensitive_files" formnovalidate><?php esc_html_e('Delete sensitive files', FJ_TEXT_DOMAIN); ?></button>
                            <p class="description"><?php esc_html_e('Nginx users: apply equivalent deny/location directives in server config.', FJ_TEXT_DOMAIN); ?></p>
                        </td>
                    </tr>
                <?php endif; ?>

                <?php if ($tab === 'exposure') : ?>
                    <tr>
                        <th><?php esc_html_e('Remove WordPress version', FJ_TEXT_DOMAIN); ?></th>
                        <td>
                            <?php if (!empty($compat['handled']['remove_version'])) : ?>
                                <p><strong><?php esc_html_e('Handled by OAP', FJ_TEXT_DOMAIN); ?></strong></p>
                            <?php else : ?>
                                <label><input type="checkbox" name="exposure_remove_version" value="1" <?php checked(!empty($settings['exposure_remove_version'])); ?>> <?php esc_html_e('Enable', FJ_TEXT_DOMAIN); ?></label>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <th><?php esc_html_e('Disable XML-RPC', FJ_TEXT_DOMAIN); ?></th>
                        <td>
                            <?php if (!empty($compat['handled']['disable_xmlrpc'])) : ?>
                                <p><strong><?php esc_html_e('Handled by OAP', FJ_TEXT_DOMAIN); ?></strong></p>
                            <?php else : ?>
                                <label><input type="checkbox" name="exposure_disable_xmlrpc" value="1" <?php checked(!empty($settings['exposure_disable_xmlrpc'])); ?>> <?php esc_html_e('Enable', FJ_TEXT_DOMAIN); ?></label>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr><th><?php esc_html_e('Disable login error hints', FJ_TEXT_DOMAIN); ?></th><td><label><input type="checkbox" name="exposure_disable_login_hints" value="1" <?php checked(!empty($settings['exposure_disable_login_hints'])); ?>> <?php esc_html_e('Use generic login failure message', FJ_TEXT_DOMAIN); ?></label></td></tr>
                <?php endif; ?>
            </table>

            <?php submit_button(__('Save settings', FJ_TEXT_DOMAIN)); ?>
        </form>
    </div>
    <?php
}
