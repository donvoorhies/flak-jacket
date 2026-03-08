<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_register_admin_menu(): void
{
    add_menu_page(
        __('Flak Jacket', FJ_TEXT_DOMAIN),
        __('Flak Jacket', FJ_TEXT_DOMAIN),
        'manage_options',
        'flak-jacket',
        'fj_render_dashboard_page',
        'dashicons-shield',
        58
    );
}
add_action('admin_menu', 'fj_register_admin_menu');

function fj_get_dashboard_items(): array
{
    $settings = fj_get_settings();
    $compat = fj_get_compatibility();

    $file_status = fj_files_sensitive_files_status();
    $any_sensitive_exists = in_array(true, $file_status, true);

    $items = [
        'login' => [
            [
                'id' => 'login_limit_enabled',
                'name' => __('Limit login attempts', FJ_TEXT_DOMAIN),
                'description' => __('Locks abusive IPs after repeated failures.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['login_limit_enabled'],
                'details' => __('Tracks failed logins per IP in a dedicated table. Repeated failures trigger timed lockouts and are logged for review.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'login_rename_enabled',
                'name' => __('Rename /wp-login.php', FJ_TEXT_DOMAIN),
                'description' => __('Moves login behind a custom slug and returns 404 for blocked requests.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['login_rename_enabled'],
                'details' => is_multisite()
                    ? __('Multisite detected: keep this off unless you have tested every site in the network.', FJ_TEXT_DOMAIN)
                    : __('Custom login path reduces trivial attack traffic. Keep the URL documented before enabling.', FJ_TEXT_DOMAIN),
                'error' => !empty($settings['login_rename_enabled']) && trim((string) $settings['login_custom_slug']) === '',
            ],
            [
                'id' => 'login_two_factor_enabled',
                'name' => __('Two-factor authentication (TOTP)', FJ_TEXT_DOMAIN),
                'description' => __('Adds a second login step with authenticator or backup code.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['login_two_factor_enabled'],
                'details' => __('Users enable 2FA in their profile. Backup codes are generated once and can be regenerated at any time.', FJ_TEXT_DOMAIN),
            ],
        ],
        'headers' => [
            [
                'id' => 'headers_hsts_enabled',
                'name' => __('Strict-Transport-Security (HSTS)', FJ_TEXT_DOMAIN),
                'description' => __('Forces HTTPS on supporting browsers.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['headers_hsts_enabled'],
                'details' => is_ssl()
                    ? __('Use only when HTTPS is consistently available across this domain and subdomains.', FJ_TEXT_DOMAIN)
                    : __('Warning: site is not currently detected as HTTPS. Do not enable HSTS until HTTPS is stable.', FJ_TEXT_DOMAIN),
                'error' => !is_ssl() && !empty($settings['headers_hsts_enabled']),
            ],
            [
                'id' => 'headers_xfo_enabled',
                'name' => __('X-Frame-Options', FJ_TEXT_DOMAIN),
                'description' => __('Reduces clickjacking risk by controlling framing.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['headers_xfo_enabled'],
                'details' => __('Use SAMEORIGIN for normal admin/embed compatibility, or DENY for stricter blocking.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'headers_xcto_enabled',
                'name' => __('X-Content-Type-Options', FJ_TEXT_DOMAIN),
                'description' => __('Stops MIME sniffing with nosniff.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['headers_xcto_enabled'],
                'details' => __('Simple and low-risk header. Recommended baseline hardening.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'headers_referrer_enabled',
                'name' => __('Referrer-Policy', FJ_TEXT_DOMAIN),
                'description' => __('Controls referrer data leakage across origins.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['headers_referrer_enabled'],
                'details' => __('Default strict-origin-when-cross-origin balances privacy and analytics.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'headers_permissions_enabled',
                'name' => __('Permissions-Policy', FJ_TEXT_DOMAIN),
                'description' => __('Restricts browser feature access.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['headers_permissions_enabled'],
                'details' => __('Set one directive per line. Omit ambient-light-sensor unless you specifically need it.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'headers_csp_enabled',
                'name' => __('Content-Security-Policy', FJ_TEXT_DOMAIN),
                'description' => __('Powerful script/style source control.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['headers_csp_enabled'] && trim((string) $settings['headers_csp_value']) !== '',
                'details' => __('CSP is powerful but complex — configure carefully.', FJ_TEXT_DOMAIN),
                'note' => __('CSP is powerful but complex — configure carefully', FJ_TEXT_DOMAIN),
            ],
        ],
        'files' => [
            [
                'id' => 'files_protect_wp_config',
                'name' => __('Protect wp-config.php', FJ_TEXT_DOMAIN),
                'description' => __('Denies direct HTTP access via .htaccess.', FJ_TEXT_DOMAIN),
                'enabled' => fj_files_has_rule('wp-config.php') && (bool) $settings['files_protect_wp_config'],
                'details' => __('Adds a deny rule inside # BEGIN Flak Jacket markers only.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'files_protect_htaccess',
                'name' => __('Protect .htaccess', FJ_TEXT_DOMAIN),
                'description' => __('Blocks direct web access to .htaccess itself.', FJ_TEXT_DOMAIN),
                'enabled' => fj_files_has_rule('<Files ".htaccess">') && (bool) $settings['files_protect_htaccess'],
                'details' => __('Self-referential by design: this protects accidental exposure of rewrite rules.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'files_disable_indexes',
                'name' => __('Disable directory browsing', FJ_TEXT_DOMAIN),
                'description' => __('Prevents public directory listing where indexes are missing.', FJ_TEXT_DOMAIN),
                'enabled' => fj_files_has_rule('Options -Indexes') && (bool) $settings['files_disable_indexes'],
                'details' => __('Uses Apache Options -Indexes in Flak Jacket block.', FJ_TEXT_DOMAIN),
            ],
            [
                'id' => 'files_block_meta_files',
                'name' => __('Block readme/license/install files', FJ_TEXT_DOMAIN),
                'description' => __('Denies direct HTTP access to common metadata files.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['files_block_meta_files'],
                'details' => $any_sensitive_exists
                    ? __('Some files still exist on disk. You can delete them with one click below.', FJ_TEXT_DOMAIN)
                    : __('No tracked metadata files found on disk.', FJ_TEXT_DOMAIN),
            ],
        ],
        'exposure' => [
            [
                'id' => 'exposure_remove_version',
                'name' => __('Remove WordPress version', FJ_TEXT_DOMAIN),
                'description' => __('Hides version from head, feeds, and asset query strings.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['exposure_remove_version'],
                'details' => __('Reduces passive fingerprinting. Avoid duplicate logic with OAP.', FJ_TEXT_DOMAIN),
                'handled_externally' => !empty($compat['handled']['remove_version']),
            ],
            [
                'id' => 'exposure_disable_xmlrpc',
                'name' => __('Disable XML-RPC', FJ_TEXT_DOMAIN),
                'description' => __('Disables the XML-RPC endpoint globally.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['exposure_disable_xmlrpc'],
                'details' => __('Blocks XML-RPC attack surface unless explicitly required by your stack.', FJ_TEXT_DOMAIN),
                'handled_externally' => !empty($compat['handled']['disable_xmlrpc']),
            ],
            [
                'id' => 'exposure_disable_login_hints',
                'name' => __('Disable login error hints', FJ_TEXT_DOMAIN),
                'description' => __('Shows one generic login failure message.', FJ_TEXT_DOMAIN),
                'enabled' => (bool) $settings['exposure_disable_login_hints'],
                'details' => __('Prevents user enumeration via detailed login error messages.', FJ_TEXT_DOMAIN),
            ],
        ],
    ];

    return $items;
}

function fj_get_item_status(array $item): string
{
    if (!empty($item['handled_externally'])) {
        return 'external';
    }
    if (!empty($item['error'])) {
        return 'error';
    }
    if (!empty($item['enabled'])) {
        return 'active';
    }
    return 'inactive';
}

function fj_dashboard_score(array $items): array
{
    $total = 0;
    $active = 0;

    foreach ($items as $group) {
        foreach ($group as $item) {
            $total++;
            $status = fj_get_item_status($item);
            if (in_array($status, ['active', 'external'], true)) {
                $active++;
            }
        }
    }

    $percent = $total > 0 ? (int) round(($active / $total) * 100) : 0;
    return ['active' => $active, 'total' => $total, 'percent' => $percent];
}

function fj_handle_quick_toggle(): void
{
    // Quick toggles are intentionally lightweight but still require admin capability + nonce.
    if (!is_admin() || !current_user_can('manage_options')) {
        return;
    }

    if (empty($_POST['fj_quick_toggle']) || empty($_POST['fj_item']) || empty($_POST['fj_toggle_nonce'])) {
        return;
    }

    if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['fj_toggle_nonce'])), 'fj_quick_toggle')) {
        return;
    }

    $item = sanitize_text_field(wp_unslash($_POST['fj_item']));
    $allowed = array_keys(fj_defaults());
    if (!in_array($item, $allowed, true)) {
        return;
    }

    // Prevent enabling options that compatibility checks mark as externally handled.
    $compat = fj_get_compatibility();
    if (
        ($item === 'exposure_remove_version' && !empty($compat['handled']['remove_version']))
        || ($item === 'exposure_disable_xmlrpc' && !empty($compat['handled']['disable_xmlrpc']))
    ) {
        wp_safe_redirect(add_query_arg('fj_notice', rawurlencode(__('Setting is managed by another plugin.', FJ_TEXT_DOMAIN)), menu_page_url('flak-jacket', false)));
        exit;
    }

    $settings = fj_get_settings();
    $settings[$item] = !empty($_POST['fj_enabled']) ? true : false;
    update_option('fj_settings', $settings);

    // File protections are backed by .htaccess and must be re-synced on each toggle.
    if (str_starts_with($item, 'files_')) {
        fj_files_sync_htaccess();
    }

    wp_safe_redirect(add_query_arg('fj_notice', rawurlencode(__('Setting updated.', FJ_TEXT_DOMAIN)), menu_page_url('flak-jacket', false)));
    exit;
}
add_action('admin_init', 'fj_handle_quick_toggle');

function fj_render_dashboard_page(): void
{
    if (!current_user_can('manage_options')) {
        return;
    }

    $items = fj_get_dashboard_items();
    $score = fj_dashboard_score($items);
    $compat = fj_get_compatibility();
    $lockout_stats = fj_login_lockout_stats();
    $two_fa_users = fj_dashboard_2fa_users();
    $sensitive = fj_files_sensitive_files_status();

    ?>
    <div class="wrap fj-wrap">
        <h1><?php esc_html_e('Flak Jacket', FJ_TEXT_DOMAIN); ?></h1>
        <p><?php esc_html_e('Lightweight WordPress protection. No bloat, no cloud, no monthly fee.', FJ_TEXT_DOMAIN); ?></p>
        <p><em><?php esc_html_e('Flak Jacket shows the threats — you decide how to respond.', FJ_TEXT_DOMAIN); ?></em></p>

        <?php if (!empty($_GET['fj_notice'])) : ?>
            <div class="notice notice-success"><p><?php echo esc_html(wp_unslash($_GET['fj_notice'])); ?></p></div>
        <?php endif; ?>

        <div class="fj-score-card">
            <div class="fj-score-top">
                <strong><?php esc_html_e('Hardening Score', FJ_TEXT_DOMAIN); ?></strong>
                <span><?php echo esc_html($score['percent']); ?>%</span>
            </div>
            <div class="fj-progress"><span style="width: <?php echo esc_attr((string) $score['percent']); ?>%;"></span></div>
            <p><?php printf(esc_html__('%1$d of %2$d protections active or handled externally', FJ_TEXT_DOMAIN), (int) $score['active'], (int) $score['total']); ?></p>
        </div>

        <div class="fj-compat-grid">
            <div><strong>OAP:</strong> <?php echo !empty($compat['oap']) ? esc_html__('Detected', FJ_TEXT_DOMAIN) : esc_html__('Not detected', FJ_TEXT_DOMAIN); ?></div>
            <div><strong>CCCP:</strong> <?php echo !empty($compat['cccp']) ? esc_html__('Detected', FJ_TEXT_DOMAIN) : esc_html__('Not detected', FJ_TEXT_DOMAIN); ?></div>
            <div><strong>critical-path-css-v2:</strong> <?php echo !empty($compat['critical_path_css_v2']) ? esc_html__('Detected', FJ_TEXT_DOMAIN) : esc_html__('Not detected', FJ_TEXT_DOMAIN); ?></div>
        </div>

        <?php
        fj_render_dashboard_section(__('Login Protection', FJ_TEXT_DOMAIN), $items['login']);
        ?>

        <div class="fj-panel">
            <h3><?php esc_html_e('Lockout telemetry', FJ_TEXT_DOMAIN); ?></h3>
            <p><?php printf(esc_html__('Lockouts (last 7 days): %d', FJ_TEXT_DOMAIN), (int) $lockout_stats['last_7_days']); ?></p>
            <?php if (!empty($lockout_stats['currently_locked'])) : ?>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('IP', FJ_TEXT_DOMAIN); ?></th><th><?php esc_html_e('Locked until (UTC)', FJ_TEXT_DOMAIN); ?></th><th><?php esc_html_e('Action', FJ_TEXT_DOMAIN); ?></th></tr></thead>
                    <tbody>
                        <?php foreach ($lockout_stats['currently_locked'] as $row) : ?>
                            <tr>
                                <td><?php echo esc_html($row['ip_address']); ?></td>
                                <td><?php echo esc_html((string) $row['locked_until']); ?></td>
                                <td><button class="button fj-unlock-ip" data-ip="<?php echo esc_attr($row['ip_address']); ?>"><?php esc_html_e('Unlock IP', FJ_TEXT_DOMAIN); ?></button></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else : ?>
                <p><?php esc_html_e('No IPs currently locked.', FJ_TEXT_DOMAIN); ?></p>
            <?php endif; ?>

            <h3><?php esc_html_e('Users with 2FA enabled', FJ_TEXT_DOMAIN); ?></h3>
            <?php if (!empty($two_fa_users)) : ?>
                <table class="widefat striped">
                    <thead><tr><th><?php esc_html_e('User', FJ_TEXT_DOMAIN); ?></th><th><?php esc_html_e('Email', FJ_TEXT_DOMAIN); ?></th><th><?php esc_html_e('Action', FJ_TEXT_DOMAIN); ?></th></tr></thead>
                    <tbody>
                        <?php foreach ($two_fa_users as $user) : ?>
                            <tr>
                                <td><?php echo esc_html($user->display_name . ' (' . $user->user_login . ')'); ?></td>
                                <td><?php echo esc_html($user->user_email); ?></td>
                                <td><button class="button fj-disable-2fa" data-user="<?php echo esc_attr((string) $user->ID); ?>"><?php esc_html_e('Disable 2FA', FJ_TEXT_DOMAIN); ?></button></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            <?php else : ?>
                <p><?php esc_html_e('No users currently have 2FA enabled.', FJ_TEXT_DOMAIN); ?></p>
            <?php endif; ?>
        </div>

        <?php
        fj_render_dashboard_section(__('Security Headers', FJ_TEXT_DOMAIN), $items['headers']);
        fj_render_dashboard_section(__('File & Directory Protection', FJ_TEXT_DOMAIN), $items['files']);
        fj_render_dashboard_section(__('WordPress Exposure', FJ_TEXT_DOMAIN), $items['exposure']);
        ?>

        <div class="fj-panel">
            <h3><?php esc_html_e('Sensitive file status', FJ_TEXT_DOMAIN); ?></h3>
            <ul>
                <?php foreach ($sensitive as $file => $exists) : ?>
                    <li><?php echo esc_html($file); ?>: <?php echo $exists ? esc_html__('Exists', FJ_TEXT_DOMAIN) : esc_html__('Not present', FJ_TEXT_DOMAIN); ?></li>
                <?php endforeach; ?>
            </ul>
            <form method="post">
                <?php wp_nonce_field('fj_files_action', 'fj_files_nonce'); ?>
                <input type="hidden" name="fj_action" value="delete_sensitive_files" />
                <button class="button button-secondary" type="submit"><?php esc_html_e('Delete sensitive files from disk', FJ_TEXT_DOMAIN); ?></button>
            </form>
        </div>
    </div>

    <style>
        .fj-wrap .fj-score-card{background:#fff;border:1px solid #dcdcde;padding:16px;max-width:720px}
        .fj-wrap .fj-score-top{display:flex;justify-content:space-between;font-size:16px;margin-bottom:8px}
        .fj-wrap .fj-progress{height:12px;background:#f0f0f1;border-radius:99px;overflow:hidden}
        .fj-wrap .fj-progress span{display:block;height:100%;background:#2271b1}
        .fj-wrap .fj-compat-grid{display:flex;gap:24px;margin:14px 0 20px}
        .fj-wrap .fj-section{background:#fff;border:1px solid #dcdcde;margin:16px 0;padding:0}
        .fj-wrap .fj-section h2{margin:0;padding:12px 16px;border-bottom:1px solid #dcdcde}
        .fj-wrap .fj-row{display:grid;grid-template-columns:180px 1.4fr 1fr 180px;gap:12px;padding:12px 16px;border-top:1px solid #f0f0f1;align-items:start}
        .fj-wrap .fj-row:first-of-type{border-top:none}
        .fj-wrap .fj-status{display:inline-flex;align-items:center;gap:8px;font-weight:600}
        .fj-wrap .fj-dot{width:10px;height:10px;border-radius:50%}
        .fj-wrap .fj-active{background:#00a32a}
        .fj-wrap .fj-inactive{background:#dba617}
        .fj-wrap .fj-external{background:#6c7781}
        .fj-wrap .fj-error{background:#d63638}
        .fj-wrap .fj-panel{background:#fff;border:1px solid #dcdcde;padding:16px;margin:16px 0}
        .fj-wrap details summary{cursor:pointer}
        @media(max-width:1100px){.fj-wrap .fj-row{grid-template-columns:1fr}}
    </style>

    <script>
        (function(){
            const ajax = "<?php echo esc_js(admin_url('admin-ajax.php')); ?>";
            const unlockNonce = "<?php echo esc_js(wp_create_nonce('fj_unlock_ip')); ?>";
            const disable2faNonce = "<?php echo esc_js(wp_create_nonce('fj_disable_user_2fa')); ?>";

            document.querySelectorAll('.fj-unlock-ip').forEach(function(btn){
                btn.addEventListener('click', function(){
                    const ip = btn.getAttribute('data-ip');
                    btn.disabled = true;
                    fetch(ajax, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                        body: new URLSearchParams({action:'fj_unlock_ip', nonce: unlockNonce, ip: ip})
                    }).then(function(r){return r.json();}).then(function(json){
                        alert(json.data && json.data.message ? json.data.message : 'Done');
                        location.reload();
                    }).catch(function(){
                        alert('Request failed.');
                        btn.disabled = false;
                    });
                });
            });

            document.querySelectorAll('.fj-disable-2fa').forEach(function(btn){
                btn.addEventListener('click', function(){
                    const userId = btn.getAttribute('data-user');
                    btn.disabled = true;
                    fetch(ajax, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'},
                        body: new URLSearchParams({action:'fj_disable_user_2fa', nonce: disable2faNonce, user_id: userId})
                    }).then(function(r){return r.json();}).then(function(json){
                        alert(json.data && json.data.message ? json.data.message : 'Done');
                        location.reload();
                    }).catch(function(){
                        alert('Request failed.');
                        btn.disabled = false;
                    });
                });
            });
        })();
    </script>
    <?php
}

function fj_render_dashboard_section(string $title, array $rows): void
{
    ?>
    <section class="fj-section">
        <h2><?php echo esc_html($title); ?></h2>
        <?php foreach ($rows as $row) :
            $status = fj_get_item_status($row);
            $status_label = [
                'active' => __('🟢 Active', FJ_TEXT_DOMAIN),
                'inactive' => __('🟡 Inactive', FJ_TEXT_DOMAIN),
                'external' => __('🔵 Handled externally', FJ_TEXT_DOMAIN),
                'error' => __('🔴 Error', FJ_TEXT_DOMAIN),
            ][$status];
            ?>
            <div class="fj-row">
                <div class="fj-status"><span class="fj-dot fj-<?php echo esc_attr($status); ?>"></span><?php echo esc_html($status_label); ?></div>
                <div>
                    <strong><?php echo esc_html($row['name']); ?></strong>
                    <p><?php echo esc_html($row['description']); ?></p>
                    <?php if (!empty($row['note'])) : ?><p><em><?php echo esc_html($row['note']); ?></em></p><?php endif; ?>
                </div>
                <details>
                    <summary><?php esc_html_e('Details', FJ_TEXT_DOMAIN); ?></summary>
                    <p><?php echo esc_html($row['details']); ?></p>
                </details>
                <div>
                    <?php if (empty($row['handled_externally'])) : ?>
                        <form method="post" action="">
                            <?php wp_nonce_field('fj_quick_toggle', 'fj_toggle_nonce'); ?>
                            <input type="hidden" name="fj_quick_toggle" value="1" />
                            <input type="hidden" name="fj_item" value="<?php echo esc_attr($row['id']); ?>" />
                            <label style="display:flex;gap:8px;align-items:center;">
                                <input type="checkbox" name="fj_enabled" value="1" <?php checked(!empty($row['enabled'])); ?> onchange="this.form.submit()" />
                                <?php esc_html_e('Enabled', FJ_TEXT_DOMAIN); ?>
                            </label>
                        </form>
                    <?php else : ?>
                        <span><?php esc_html_e('Handled by OAP', FJ_TEXT_DOMAIN); ?></span>
                    <?php endif; ?>
                </div>
            </div>
        <?php endforeach; ?>
    </section>
    <?php
}
