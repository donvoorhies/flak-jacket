<?php
if (!defined('ABSPATH')) {
    exit;
}

function fj_create_login_attempts_table(): void
{
    global $wpdb;

    $table = $wpdb->prefix . 'fj_login_attempts';
    $charset_collate = $wpdb->get_charset_collate();

    $sql = "CREATE TABLE {$table} (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ip_address VARCHAR(64) NOT NULL,
        username VARCHAR(60) NULL,
        event_type VARCHAR(20) NOT NULL,
        locked_until DATETIME NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY ip_address (ip_address),
        KEY event_type (event_type),
        KEY created_at (created_at)
    ) {$charset_collate};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    dbDelta($sql);
}

function fj_get_client_ip(): string
{
    $remote = fj_get_remote_addr();
    if ($remote === '0.0.0.0') {
        return $remote;
    }

    // Trust forwarded headers only when request originates from a trusted proxy.
    $trusted_proxies = fj_get_trusted_proxy_ips();
    if (empty($trusted_proxies) || !fj_ip_matches_trusted_proxy($remote, $trusted_proxies)) {
        return $remote;
    }

    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        $candidate = sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_CONNECTING_IP']));
        $candidate = trim($candidate);
        if (filter_var($candidate, FILTER_VALIDATE_IP)) {
            return $candidate;
        }
    }

    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwarded = sanitize_text_field(wp_unslash($_SERVER['HTTP_X_FORWARDED_FOR']));
        $candidate = fj_extract_forwarded_ip($forwarded);
        if ($candidate !== null) {
            return $candidate;
        }
    }

    return $remote;
}

function fj_get_remote_addr(): string
{
    if (empty($_SERVER['REMOTE_ADDR'])) {
        return '0.0.0.0';
    }

    $remote = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
    $remote = trim($remote);

    return filter_var($remote, FILTER_VALIDATE_IP) ? $remote : '0.0.0.0';
}

function fj_extract_forwarded_ip(string $header_value): ?string
{
    $parts = explode(',', $header_value);

    foreach ($parts as $part) {
        $ip = trim($part);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            return $ip;
        }
    }

    return null;
}

function fj_get_trusted_proxy_ips(): array
{
    // Integrators can supply trusted reverse-proxy IPs/CIDRs: add_filter('fj_trusted_proxy_ips', fn() => ['203.0.113.10', '203.0.113.0/24']);
    $configured = apply_filters('fj_trusted_proxy_ips', []);
    if (!is_array($configured)) {
        return [];
    }

    $trusted = [];
    foreach ($configured as $value) {
        $entry = trim((string) $value);
        if (fj_is_valid_ip_or_cidr($entry)) {
            $trusted[] = $entry;
        }
    }

    return array_values(array_unique($trusted));
}

function fj_ip_matches_trusted_proxy(string $ip, array $trusted_entries): bool
{
    foreach ($trusted_entries as $entry) {
        if (strpos($entry, '/') === false) {
            if ($ip === $entry) {
                return true;
            }
            continue;
        }

        if (fj_ip_in_cidr($ip, $entry)) {
            return true;
        }
    }

    return false;
}

function fj_is_valid_ip_or_cidr(string $value): bool
{
    if ($value === '') {
        return false;
    }

    if (strpos($value, '/') === false) {
        return (bool) filter_var($value, FILTER_VALIDATE_IP);
    }

    [$network, $prefix] = array_pad(explode('/', $value, 2), 2, '');
    if (!is_numeric($prefix)) {
        return false;
    }

    $network = trim($network);
    $prefix = (int) $prefix;
    if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return $prefix >= 0 && $prefix <= 32;
    }
    if (filter_var($network, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        return $prefix >= 0 && $prefix <= 128;
    }

    return false;
}

function fj_ip_in_cidr(string $ip, string $cidr): bool
{
    [$network, $prefix] = explode('/', $cidr, 2);
    $network = trim($network);
    $prefix = (int) $prefix;

    $ip_bin = @inet_pton($ip);
    $network_bin = @inet_pton($network);

    if ($ip_bin === false || $network_bin === false || strlen($ip_bin) !== strlen($network_bin)) {
        return false;
    }

    $bytes = intdiv($prefix, 8);
    $bits = $prefix % 8;

    if ($bytes > 0 && substr($ip_bin, 0, $bytes) !== substr($network_bin, 0, $bytes)) {
        return false;
    }

    if ($bits === 0) {
        return true;
    }

    $mask = 0xFF << (8 - $bits);
    $ip_byte = ord($ip_bin[$bytes]);
    $network_byte = ord($network_bin[$bytes]);

    return (($ip_byte & $mask) === ($network_byte & $mask));
}

function fj_login_record_event(string $event_type, string $ip, string $username = '', ?string $locked_until = null): void
{
    global $wpdb;

    $table = $wpdb->prefix . 'fj_login_attempts';
    $wpdb->insert(
        $table,
        [
            'ip_address' => $ip,
            'username' => $username,
            'event_type' => $event_type,
            'locked_until' => $locked_until,
            'created_at' => gmdate('Y-m-d H:i:s'),
        ],
        ['%s', '%s', '%s', '%s', '%s']
    );

    if ($event_type === 'lockout') {
        fj_login_prune_lockouts();
    }
}

function fj_login_prune_lockouts(): void
{
    global $wpdb;

    $table = $wpdb->prefix . 'fj_login_attempts';
    $ids = $wpdb->get_col("SELECT id FROM {$table} WHERE event_type = 'lockout' ORDER BY id DESC LIMIT 100, 10000");
    if (!empty($ids)) {
        $ids = array_map('intval', $ids);
        $wpdb->query("DELETE FROM {$table} WHERE id IN (" . implode(',', $ids) . ")");
    }
}

function fj_login_is_locked(string $ip): bool
{
    global $wpdb;

    $table = $wpdb->prefix . 'fj_login_attempts';
    $now = gmdate('Y-m-d H:i:s');

    $count = (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$table}
         WHERE ip_address = %s
         AND event_type = 'lockout'
         AND locked_until IS NOT NULL
         AND locked_until > %s",
        $ip,
        $now
    ));

    return $count > 0;
}

function fj_login_count_recent_failures(string $ip, int $window_minutes): int
{
    global $wpdb;

    $table = $wpdb->prefix . 'fj_login_attempts';
    $window_minutes = max(1, $window_minutes);
    $since = gmdate('Y-m-d H:i:s', time() - ($window_minutes * 60));

    return (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$table}
         WHERE ip_address = %s
         AND event_type = 'failed'
         AND created_at >= %s",
        $ip,
        $since
    ));
}

function fj_auth_limit_attempts($user, string $username)
{
    $settings = fj_get_settings();
    if (empty($settings['login_limit_enabled'])) {
        return $user;
    }

    // Stop auth before password validation when an active lockout exists.
    $ip = fj_get_client_ip();
    if (fj_login_is_locked($ip)) {
        return new WP_Error('invalid_credentials', __('Login failed. Please check your credentials.', FJ_TEXT_DOMAIN));
    }

    return $user;
}
add_filter('authenticate', 'fj_auth_limit_attempts', 30, 2);

function fj_handle_failed_login(string $username): void
{
    $settings = fj_get_settings();
    if (empty($settings['login_limit_enabled'])) {
        return;
    }

    $ip = fj_get_client_ip();
    fj_login_record_event('failed', $ip, $username);

    $max_attempts = max(1, (int) $settings['login_max_attempts']);
    $lockout_minutes = max(1, (int) $settings['login_lockout_minutes']);

    // Count failures inside lockout window; reaching threshold issues a timed lockout event.
    $failures = fj_login_count_recent_failures($ip, $lockout_minutes);
    if ($failures >= $max_attempts) {
        $locked_until = gmdate('Y-m-d H:i:s', time() + ($lockout_minutes * 60));
        fj_login_record_event('lockout', $ip, $username, $locked_until);
    }
}
add_action('wp_login_failed', 'fj_handle_failed_login');

function fj_handle_successful_login(string $user_login): void
{
    global $wpdb;

    $ip = fj_get_client_ip();
    $table = $wpdb->prefix . 'fj_login_attempts';

    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$table} WHERE ip_address = %s AND event_type = 'failed'",
        $ip
    ));
}
add_action('wp_login', 'fj_handle_successful_login', 10, 1);

function fj_login_lockout_stats(): array
{
    global $wpdb;

    $table = $wpdb->prefix . 'fj_login_attempts';
    $seven_days_ago = gmdate('Y-m-d H:i:s', time() - (7 * DAY_IN_SECONDS));

    $lockouts_last_7 = (int) $wpdb->get_var($wpdb->prepare(
        "SELECT COUNT(*) FROM {$table} WHERE event_type = 'lockout' AND created_at >= %s",
        $seven_days_ago
    ));

    $now = gmdate('Y-m-d H:i:s');
    $locked_ips = $wpdb->get_results($wpdb->prepare(
        "SELECT ip_address, MAX(locked_until) AS locked_until
         FROM {$table}
         WHERE event_type = 'lockout' AND locked_until > %s
         GROUP BY ip_address
         ORDER BY locked_until DESC",
        $now
    ), ARRAY_A);

    return [
        'last_7_days' => $lockouts_last_7,
        'currently_locked' => $locked_ips,
    ];
}

function fj_ajax_unlock_ip(): void
{
    check_ajax_referer('fj_unlock_ip', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', FJ_TEXT_DOMAIN)], 403);
    }

    $ip = isset($_POST['ip']) ? sanitize_text_field(wp_unslash($_POST['ip'])) : '';
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        wp_send_json_error(['message' => __('Invalid IP address.', FJ_TEXT_DOMAIN)], 400);
    }

    global $wpdb;
    $table = $wpdb->prefix . 'fj_login_attempts';
    $now = gmdate('Y-m-d H:i:s');

    $wpdb->query($wpdb->prepare(
        "DELETE FROM {$table} WHERE ip_address = %s AND event_type = 'lockout' AND locked_until > %s",
        $ip,
        $now
    ));

    fj_login_record_event('unlocked', $ip);

    wp_send_json_success(['message' => __('IP unlocked.', FJ_TEXT_DOMAIN)]);
}
add_action('wp_ajax_fj_unlock_ip', 'fj_ajax_unlock_ip');

function fj_is_admin_ip(string $ip): bool
{
    if (in_array($ip, ['127.0.0.1', '::1'], true)) {
        return true;
    }

    $settings = fj_get_settings();
    $list = preg_split('/\r\n|\r|\n|,/', (string) $settings['login_allowed_ips']) ?: [];
    $list = array_filter(array_map('trim', $list));

    return in_array($ip, $list, true);
}

function fj_handle_login_rename(): void
{
    if (is_admin() && !wp_doing_ajax()) {
        return;
    }

    $settings = fj_get_settings();
    if (is_multisite() && !empty($settings['login_rename_enabled'])) {
        return;
    }

    if (empty($settings['login_rename_enabled'])) {
        return;
    }

    $slug = trim((string) $settings['login_custom_slug'], '/');
    if ($slug === '') {
        return;
    }

    $request_path = trim((string) parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH), '/');

    if ($request_path === $slug) {
        require ABSPATH . 'wp-login.php';
        exit;
    }

    if ($request_path === 'wp-login.php') {
        $ip = fj_get_client_ip();
        if (!fj_is_admin_ip($ip)) {
            status_header(404);
            nocache_headers();
            include get_404_template();
            exit;
        }
    }
}
add_action('init', 'fj_handle_login_rename', 1);

function fj_maybe_override_login_error(string $error): string
{
    $settings = fj_get_settings();
    if (!empty($settings['login_limit_enabled']) || !empty($settings['exposure_disable_login_hints'])) {
        return __('Login failed. Please check your credentials.', FJ_TEXT_DOMAIN);
    }

    return $error;
}
add_filter('login_errors', 'fj_maybe_override_login_error');

function fj_generate_totp_secret(int $length = 32): string
{
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $secret = '';
    $bytes = random_bytes($length);

    for ($i = 0; $i < $length; $i++) {
        $secret .= $chars[ord($bytes[$i]) % 32];
    }

    return $secret;
}

function fj_base32_decode(string $input): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    $input = strtoupper(preg_replace('/[^A-Z2-7]/', '', $input) ?? '');
    $buffer = 0;
    $bits_left = 0;
    $output = '';

    foreach (str_split($input) as $char) {
        $value = strpos($alphabet, $char);
        if ($value === false) {
            continue;
        }

        $buffer = ($buffer << 5) | $value;
        $bits_left += 5;

        if ($bits_left >= 8) {
            $bits_left -= 8;
            $output .= chr(($buffer >> $bits_left) & 0xFF);
        }
    }

    return $output;
}

function fj_generate_totp_code(string $secret, ?int $time = null): string
{
    $time = $time ?? time();
    $counter = (int) floor($time / 30);

    $binary_counter = pack('N*', 0) . pack('N*', $counter);
    $key = fj_base32_decode($secret);
    $hash = hash_hmac('sha1', $binary_counter, $key, true);
    $offset = ord(substr($hash, -1)) & 0x0F;
    $binary = ((ord($hash[$offset]) & 0x7F) << 24)
        | ((ord($hash[$offset + 1]) & 0xFF) << 16)
        | ((ord($hash[$offset + 2]) & 0xFF) << 8)
        | (ord($hash[$offset + 3]) & 0xFF);

    $code = $binary % 1000000;
    return str_pad((string) $code, 6, '0', STR_PAD_LEFT);
}

function fj_verify_totp_code(string $secret, string $code, int $window = 1): bool
{
    $code = preg_replace('/\D/', '', $code) ?? '';
    if (strlen($code) !== 6) {
        return false;
    }

    // Allow small clock drift by validating previous/current/next time window.
    $current_time = time();
    for ($i = -$window; $i <= $window; $i++) {
        $candidate = fj_generate_totp_code($secret, $current_time + ($i * 30));
        if (hash_equals($candidate, $code)) {
            return true;
        }
    }

    return false;
}

function fj_generate_backup_codes(int $count = 8): array
{
    $codes = [];
    for ($i = 0; $i < $count; $i++) {
        $codes[] = strtoupper(substr(bin2hex(random_bytes(4)), 0, 8));
    }
    return $codes;
}

function fj_hash_backup_codes(array $codes): array
{
    $hashed = [];
    foreach ($codes as $code) {
        $hashed[] = wp_hash_password($code);
    }
    return $hashed;
}

function fj_use_backup_code(WP_User $user, string $code): bool
{
    $code = strtoupper(trim($code));
    $hashes = get_user_meta($user->ID, 'fj_2fa_backup_hashes', true);
    if (!is_array($hashes) || empty($hashes)) {
        return false;
    }

    foreach ($hashes as $index => $hash) {
        if (wp_check_password($code, $hash, $user->ID)) {
            unset($hashes[$index]);
            update_user_meta($user->ID, 'fj_2fa_backup_hashes', array_values($hashes));
            return true;
        }
    }

    return false;
}

function fj_get_totp_otpauth_uri(WP_User $user, string $secret): string
{
    $issuer = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
    $account = $user->user_login . '@' . wp_parse_url(home_url(), PHP_URL_HOST);

    return sprintf(
        'otpauth://totp/%s?secret=%s&issuer=%s&algorithm=SHA1&digits=6&period=30',
        rawurlencode($issuer . ':' . $account),
        rawurlencode($secret),
        rawurlencode($issuer)
    );
}

function fj_render_fake_qr_svg(string $content): string
{
    $hash = hash('sha256', $content);
    $bits = '';
    foreach (str_split($hash) as $hex) {
        $bits .= str_pad(base_convert($hex, 16, 2), 4, '0', STR_PAD_LEFT);
    }

    $size = 29;
    $cell = 6;
    $padding = 4;
    $svg = '<svg xmlns="http://www.w3.org/2000/svg" width="' . (($size + $padding * 2) * $cell) . '" height="' . (($size + $padding * 2) * $cell) . '" viewBox="0 0 ' . (($size + $padding * 2) * $cell) . ' ' . (($size + $padding * 2) * $cell) . '">';
    $svg .= '<rect width="100%" height="100%" fill="#fff"/>';

    $bit_index = 0;
    for ($y = 0; $y < $size; $y++) {
        for ($x = 0; $x < $size; $x++) {
            $is_finder = ($x < 7 && $y < 7) || ($x >= $size - 7 && $y < 7) || ($x < 7 && $y >= $size - 7);
            if ($is_finder) {
                $in_outer = ($x % 7 === 0 || $x % 7 === 6 || $y % 7 === 0 || $y % 7 === 6);
                $in_inner = ($x % 7 >= 2 && $x % 7 <= 4 && $y % 7 >= 2 && $y % 7 <= 4);
                if ($in_outer || $in_inner) {
                    $svg .= '<rect x="' . (($x + $padding) * $cell) . '" y="' . (($y + $padding) * $cell) . '" width="' . $cell . '" height="' . $cell . '" fill="#000"/>';
                }
                continue;
            }

            if ($bits[$bit_index % strlen($bits)] === '1') {
                $svg .= '<rect x="' . (($x + $padding) * $cell) . '" y="' . (($y + $padding) * $cell) . '" width="' . $cell . '" height="' . $cell . '" fill="#000"/>';
            }
            $bit_index++;
        }
    }

    $svg .= '</svg>';
    return $svg;
}

function fj_user_has_2fa(int $user_id): bool
{
    return (bool) get_user_meta($user_id, 'fj_2fa_enabled', true);
}

function fj_profile_2fa_fields(WP_User $user): void
{
    $settings = fj_get_settings();
    if (empty($settings['login_two_factor_enabled'])) {
        return;
    }

    $enabled = fj_user_has_2fa($user->ID);
    $secret = (string) get_user_meta($user->ID, 'fj_2fa_secret', true);

    if ($enabled && $secret === '') {
        $secret = fj_generate_totp_secret();
        update_user_meta($user->ID, 'fj_2fa_secret', $secret);
    }

    $otpauth = $secret !== '' ? fj_get_totp_otpauth_uri($user, $secret) : '';

    ?>
    <h2><?php esc_html_e('Flak Jacket Two-Factor Authentication', FJ_TEXT_DOMAIN); ?></h2>
    <table class="form-table" role="presentation">
        <tr>
            <th scope="row"><?php esc_html_e('Enable TOTP 2FA', FJ_TEXT_DOMAIN); ?></th>
            <td>
                <?php wp_nonce_field('fj_profile_2fa', 'fj_profile_2fa_nonce'); ?>
                <label>
                    <input type="checkbox" name="fj_2fa_enabled" value="1" <?php checked($enabled); ?> />
                    <?php esc_html_e('Require a 6-digit authenticator code after password login.', FJ_TEXT_DOMAIN); ?>
                </label>
                <p class="description"><?php esc_html_e('Flak Jacket does not send codes by email or SMS. Bring your own authenticator app.', FJ_TEXT_DOMAIN); ?></p>
            </td>
        </tr>
        <?php if ($enabled && $secret !== '') : ?>
        <tr>
            <th scope="row"><?php esc_html_e('Manual entry key', FJ_TEXT_DOMAIN); ?></th>
            <td>
                <code><?php echo esc_html($secret); ?></code>
                <p class="description"><?php esc_html_e('If QR scan fails, enter this key manually in your authenticator app.', FJ_TEXT_DOMAIN); ?></p>
            </td>
        </tr>
        <tr>
            <th scope="row"><?php esc_html_e('QR code', FJ_TEXT_DOMAIN); ?></th>
            <td>
                <div style="display:inline-block;border:1px solid #ccd0d4;padding:8px;background:#fff;">
                    <?php echo fj_render_fake_qr_svg($otpauth); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>
                </div>
                <p class="description"><?php esc_html_e('Scan this code with your authenticator app.', FJ_TEXT_DOMAIN); ?></p>
            </td>
        </tr>
        <?php endif; ?>
    </table>
    <?php

    if ($enabled) {
        $backup_codes = get_user_meta($user->ID, 'fj_2fa_backup_plain', true);
        if (is_array($backup_codes) && !empty($backup_codes)) {
            echo '<h3>' . esc_html__('New backup codes (save now)', FJ_TEXT_DOMAIN) . '</h3>';
            echo '<p>' . esc_html__('These are shown once. Store them somewhere safe.', FJ_TEXT_DOMAIN) . '</p><ul>';
            foreach ($backup_codes as $code) {
                echo '<li><code>' . esc_html($code) . '</code></li>';
            }
            echo '</ul>';
            delete_user_meta($user->ID, 'fj_2fa_backup_plain');
        }

        echo '<p><button type="submit" class="button" name="fj_regenerate_backup" value="1">' . esc_html__('Regenerate backup codes', FJ_TEXT_DOMAIN) . '</button></p>';
    }
}
add_action('show_user_profile', 'fj_profile_2fa_fields');
add_action('edit_user_profile', 'fj_profile_2fa_fields');

function fj_save_profile_2fa_fields(int $user_id): void
{
    if (!current_user_can('edit_user', $user_id)) {
        return;
    }

    if (empty($_POST['fj_profile_2fa_nonce']) || !wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['fj_profile_2fa_nonce'])), 'fj_profile_2fa')) {
        return;
    }

    $enabled = !empty($_POST['fj_2fa_enabled']);
    update_user_meta($user_id, 'fj_2fa_enabled', $enabled ? '1' : '0');

    if ($enabled) {
        $secret = (string) get_user_meta($user_id, 'fj_2fa_secret', true);
        if ($secret === '') {
            $secret = fj_generate_totp_secret();
            update_user_meta($user_id, 'fj_2fa_secret', $secret);
            $codes = fj_generate_backup_codes(8);
            update_user_meta($user_id, 'fj_2fa_backup_hashes', fj_hash_backup_codes($codes));
            update_user_meta($user_id, 'fj_2fa_backup_plain', $codes);
        }

        if (!empty($_POST['fj_regenerate_backup'])) {
            $codes = fj_generate_backup_codes(8);
            update_user_meta($user_id, 'fj_2fa_backup_hashes', fj_hash_backup_codes($codes));
            update_user_meta($user_id, 'fj_2fa_backup_plain', $codes);
        }
    } else {
        delete_user_meta($user_id, 'fj_2fa_secret');
        delete_user_meta($user_id, 'fj_2fa_backup_hashes');
        delete_user_meta($user_id, 'fj_2fa_backup_plain');
    }
}
add_action('personal_options_update', 'fj_save_profile_2fa_fields');
add_action('edit_user_profile_update', 'fj_save_profile_2fa_fields');

function fj_authenticate_2fa($user, string $username, string $password)
{
    if (is_wp_error($user) || !$user instanceof WP_User) {
        return $user;
    }

    $settings = fj_get_settings();
    if (empty($settings['login_two_factor_enabled'])) {
        return $user;
    }

    if (!fj_user_has_2fa($user->ID)) {
        return $user;
    }

    if (!empty($_POST['fj_2fa_step']) && $_POST['fj_2fa_step'] === '1') {
        return $user;
    }

    // Primary credential check succeeded; begin short-lived second-factor challenge.
    $token = wp_generate_password(32, false, false);
    $remember = !empty($_POST['rememberme']);
    $redirect_to = isset($_REQUEST['redirect_to']) ? esc_url_raw(wp_unslash($_REQUEST['redirect_to'])) : admin_url();

    set_transient('fj_2fa_' . $token, [
        'user_id' => $user->ID,
        'remember' => $remember,
        'redirect_to' => $redirect_to,
        'created' => time(),
    ], 10 * MINUTE_IN_SECONDS);

    // Store only a random challenge token in cookie; challenge details stay server-side in transient.
    setcookie('fj_2fa_token', $token, [
        'expires' => time() + (10 * MINUTE_IN_SECONDS),
        'path' => COOKIEPATH ?: '/',
        'domain' => COOKIE_DOMAIN,
        'secure' => is_ssl(),
        'httponly' => true,
        'samesite' => 'Lax',
    ]);

    wp_safe_redirect(add_query_arg('fj-2fa', '1', wp_login_url()));
    exit;
}
add_filter('authenticate', 'fj_authenticate_2fa', 90, 3);

function fj_login_2fa_screen(): void
{
    if (!isset($_GET['fj-2fa'])) {
        return;
    }

    // Challenge state is keyed by token and expires automatically after a short window.
    $token = $_COOKIE['fj_2fa_token'] ?? '';
    $challenge = $token ? get_transient('fj_2fa_' . $token) : null;

    if (!is_array($challenge) || empty($challenge['user_id'])) {
        wp_die(esc_html__('2FA session expired. Please sign in again.', FJ_TEXT_DOMAIN));
    }

    $user = get_user_by('id', (int) $challenge['user_id']);
    if (!$user instanceof WP_User) {
        wp_die(esc_html__('Invalid login challenge.', FJ_TEXT_DOMAIN));
    }

    $error = '';

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_admin_referer('fj_2fa_verify', 'fj_2fa_nonce');

        $code = isset($_POST['fj_2fa_code']) ? sanitize_text_field(wp_unslash($_POST['fj_2fa_code'])) : '';
        $secret = (string) get_user_meta($user->ID, 'fj_2fa_secret', true);
        $valid = $secret !== '' && fj_verify_totp_code($secret, $code);

        if (!$valid) {
            $valid = fj_use_backup_code($user, $code);
        }

        if ($valid) {
            wp_set_auth_cookie($user->ID, !empty($challenge['remember']));
            wp_set_current_user($user->ID);
            do_action('wp_login', $user->user_login, $user);

            // Challenge is single-use: clear both transient and browser token once accepted.
            delete_transient('fj_2fa_' . $token);
            setcookie('fj_2fa_token', '', time() - 3600, COOKIEPATH ?: '/', COOKIE_DOMAIN, is_ssl(), true);

            $redirect_to = !empty($challenge['redirect_to']) ? $challenge['redirect_to'] : admin_url();
            wp_safe_redirect($redirect_to);
            exit;
        }

        $error = __('Invalid authentication code.', FJ_TEXT_DOMAIN);
    }

    login_header(__('Two-Factor Authentication', FJ_TEXT_DOMAIN), '<p>' . esc_html__('Enter your 6-digit authenticator code or a backup code.', FJ_TEXT_DOMAIN) . '</p>', null);
    if ($error) {
        echo '<div id="login_error"><strong>' . esc_html($error) . '</strong></div>';
    }

    echo '<form method="post" action="">';
    wp_nonce_field('fj_2fa_verify', 'fj_2fa_nonce');
    echo '<p><label for="fj_2fa_code">' . esc_html__('Authentication code', FJ_TEXT_DOMAIN) . '</label>';
    echo '<input type="text" name="fj_2fa_code" id="fj_2fa_code" class="input" autocomplete="one-time-code" required></p>';
    echo '<p class="submit"><button class="button button-primary button-large" type="submit">' . esc_html__('Verify', FJ_TEXT_DOMAIN) . '</button></p>';
    echo '</form>';
    login_footer();
    exit;
}
add_action('login_init', 'fj_login_2fa_screen');

function fj_dashboard_2fa_users(): array
{
    $users = get_users([
        'meta_key' => 'fj_2fa_enabled',
        'meta_value' => '1',
        'fields' => ['ID', 'user_login', 'display_name', 'user_email'],
    ]);

    return is_array($users) ? $users : [];
}

function fj_ajax_disable_user_2fa(): void
{
    check_ajax_referer('fj_disable_user_2fa', 'nonce');

    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => __('Permission denied.', FJ_TEXT_DOMAIN)], 403);
    }

    $user_id = isset($_POST['user_id']) ? (int) $_POST['user_id'] : 0;
    if ($user_id <= 0) {
        wp_send_json_error(['message' => __('Invalid user.', FJ_TEXT_DOMAIN)], 400);
    }

    update_user_meta($user_id, 'fj_2fa_enabled', '0');
    delete_user_meta($user_id, 'fj_2fa_secret');
    delete_user_meta($user_id, 'fj_2fa_backup_hashes');
    delete_user_meta($user_id, 'fj_2fa_backup_plain');

    wp_send_json_success(['message' => __('2FA disabled for user.', FJ_TEXT_DOMAIN)]);
}
add_action('wp_ajax_fj_disable_user_2fa', 'fj_ajax_disable_user_2fa');
