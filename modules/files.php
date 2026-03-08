<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_files_get_htaccess_path(): string
{
    return trailingslashit(ABSPATH) . '.htaccess';
}

function fj_files_get_marked_block(array $settings = null): string
{
    if ($settings === null) {
        $settings = fj_get_settings();
    }

    $rules = [];

    if (!empty($settings['files_protect_wp_config'])) {
        $rules[] = '<Files "wp-config.php">';
        $rules[] = '    Require all denied';
        $rules[] = '</Files>';
    }

    if (!empty($settings['files_protect_htaccess'])) {
        $rules[] = '<Files ".htaccess">';
        $rules[] = '    Require all denied';
        $rules[] = '</Files>';
    }

    if (!empty($settings['files_disable_indexes'])) {
        $rules[] = 'Options -Indexes';
    }

    if (!empty($settings['files_block_meta_files'])) {
        $rules[] = '<FilesMatch "^(readme\\.html|license\\.txt|wp-config-sample\\.php|install\\.php)$">';
        $rules[] = '    Require all denied';
        $rules[] = '</FilesMatch>';
    }

    // Keep all managed rules inside explicit markers for predictable cleanup/rewrite.
    $content = "# BEGIN Flak Jacket\n";
    if (!empty($rules)) {
        $content .= implode("\n", $rules) . "\n";
    }
    $content .= "# END Flak Jacket\n";

    return $content;
}

function fj_files_sync_htaccess(): bool
{
    $path = fj_files_get_htaccess_path();
    $settings = fj_get_settings();

    if (!file_exists($path)) {
        if (!is_writable(ABSPATH)) {
            return false;
        }
        file_put_contents($path, "# BEGIN WordPress\n# END WordPress\n");
    }

    if (!is_writable($path)) {
        return false;
    }

    $current = file_get_contents($path);
    if ($current === false) {
        return false;
    }

    // Remove only our managed block; leave unrelated WordPress/custom directives untouched.
    $clean = preg_replace('/\n?# BEGIN Flak Jacket.*?# END Flak Jacket\n?/s', "\n", $current);
    if ($clean === null) {
        $clean = $current;
    }

    $new_block = fj_files_get_marked_block($settings);
    $has_any_file_feature = !empty($settings['files_protect_wp_config'])
        || !empty($settings['files_protect_htaccess'])
        || !empty($settings['files_disable_indexes'])
        || !empty($settings['files_block_meta_files']);

    $updated = rtrim($clean) . "\n\n";
    if ($has_any_file_feature) {
        $updated .= $new_block;
    }

    return file_put_contents($path, $updated) !== false;
}

function fj_files_remove_marked_rules(): bool
{
    $path = fj_files_get_htaccess_path();

    if (!file_exists($path) || !is_writable($path)) {
        return false;
    }

    $current = file_get_contents($path);
    if ($current === false) {
        return false;
    }

    $clean = preg_replace('/\n?# BEGIN Flak Jacket.*?# END Flak Jacket\n?/s', "\n", $current);
    if ($clean === null) {
        return false;
    }

    return file_put_contents($path, rtrim($clean) . "\n") !== false;
}

function fj_files_has_rule(string $needle): bool
{
    $path = fj_files_get_htaccess_path();
    if (!file_exists($path)) {
        return false;
    }

    $content = file_get_contents($path);
    if ($content === false) {
        return false;
    }

    return stripos($content, $needle) !== false;
}

function fj_files_sensitive_files_status(): array
{
    $files = [
        'readme.html',
        'license.txt',
        'wp-config-sample.php',
        'install.php',
    ];

    $result = [];
    foreach ($files as $file) {
        $result[$file] = file_exists(trailingslashit(ABSPATH) . $file);
    }

    return $result;
}

function fj_files_delete_sensitive_files(): array
{
    $files = fj_files_sensitive_files_status();
    $deleted = [];
    $failed = [];

    foreach ($files as $file => $exists) {
        if (!$exists) {
            continue;
        }

        $path = trailingslashit(ABSPATH) . $file;
        if (is_writable($path) && @unlink($path)) {
            $deleted[] = $file;
        } else {
            $failed[] = $file;
        }
    }

    return [
        'deleted' => $deleted,
        'failed' => $failed,
    ];
}

function fj_files_handle_admin_actions(): void
{
    if (!is_admin() || !current_user_can('manage_options')) {
        return;
    }

    if (empty($_POST['fj_action'])) {
        return;
    }

    // All destructive file operations require a dedicated nonce.
    check_admin_referer('fj_files_action', 'fj_files_nonce');

    $action = sanitize_text_field(wp_unslash($_POST['fj_action']));

    if ($action === 'delete_sensitive_files') {
        $result = fj_files_delete_sensitive_files();
        $message = sprintf(
            __('Flak Jacket deleted %1$d file(s). %2$d failed.', FJ_TEXT_DOMAIN),
            count($result['deleted']),
            count($result['failed'])
        );

        wp_safe_redirect(add_query_arg('fj_notice', rawurlencode($message), wp_get_referer() ?: admin_url()));
        exit;
    }

    if ($action === 'remove_htaccess_rules') {
        $removed = fj_files_remove_marked_rules();
        $message = $removed
            ? __('Flak Jacket .htaccess rules removed.', FJ_TEXT_DOMAIN)
            : __('Could not remove .htaccess rules. Check file permissions.', FJ_TEXT_DOMAIN);

        wp_safe_redirect(add_query_arg('fj_notice', rawurlencode($message), wp_get_referer() ?: admin_url()));
        exit;
    }
}
add_action('admin_init', 'fj_files_handle_admin_actions');
