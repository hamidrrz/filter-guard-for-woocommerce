<?php
/**
 * Plugin Name: FacetFence Product Filters
 * Description: Protects WooCommerce filtered archive URLs from crawl floods, adds SEO noindex controls, event logging, signed human cookies, rate limits, rollback, and server rule generators.
 * Version: 1.6
 * Requires at least: 6.5
 * Requires PHP: 7.4
 * Requires Plugins: woocommerce
 * WC requires at least: 8.0
 * WC tested up to: 10.8
 * Author: Hamidreza Rezaei
 * Author URI: https://hrezaei.ir
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: facetfence-product-filters
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) {
    exit;
}

final class FacetFence_Plugin
{
    private const VERSION = '1.6';
    private const DB_VERSION = '1.4.8';
    private const DB_VERSION_OPTION = 'facetfence_db_version';
    private const OPTION = 'facetfence_options';
    private const OLD_OPTION = 'facetfence_legacy_options';
    private const TEST_OPTION = 'facetfence_last_test_results';
    private const OLD_TEST_OPTION = 'facetfence_legacy_last_test_results';
    private const NOTICE_TRANSIENT_PREFIX = 'facetfence_admin_notice_';
    private const BOT_TRANSIENT_PREFIX = 'facetfence_bot_';
    private const HTACCESS_BEGIN = '# BEGIN FACETFENCE_PRODUCT_FILTERS';
    private const HTACCESS_END = '# END FACETFENCE_PRODUCT_FILTERS';
    private const LEGACY_HTACCESS_BEGIN = '# BEGIN FACETFENCE_LEGACY';
    private const LEGACY_HTACCESS_END = '# END FACETFENCE_LEGACY';
    private const ROBOTS_BEGIN = '# BEGIN FACETFENCE_PRODUCT_FILTERS_ROBOTS';
    private const ROBOTS_END = '# END FACETFENCE_PRODUCT_FILTERS_ROBOTS';
    private const LEGACY_ROBOTS_BEGIN = '# BEGIN FACETFENCE_LEGACY_ROBOTS';
    private const LEGACY_ROBOTS_END = '# END FACETFENCE_LEGACY_ROBOTS';
    private const CRON_HOOK = 'facetfence_cleanup_runtime';
    private const HEALTH_CHECK_TOKEN_TRANSIENT = 'facetfence_health_check_token';
    private const HTACCESS_DIAG_OPTION = 'facetfence_htaccess_diagnostics';

    private static $instance = null;
    private $filesystem = null;
    private $request_context = null;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct()
    {
        add_action('init', [$this, 'maybe_upgrade_schema'], 0);
        add_action('init', [$this, 'maybe_set_human_cookie'], 0);
        add_action('init', [$this, 'maybe_block_xmlrpc'], 0);
        add_action('template_redirect', [$this, 'guard_request'], 0);
        add_filter('wp_robots', [$this, 'filter_wp_robots'], 99);
        add_filter('wp_headers', [$this, 'filter_wp_headers'], 99);
        add_action('wp_head', [$this, 'output_filtered_canonical'], 1);
        add_filter('robots_txt', [$this, 'filter_virtual_robots_txt'], 99, 2);
        add_action(self::CRON_HOOK, [$this, 'cleanup_runtime_and_logs']);

        if (is_admin()) {
            add_action('admin_menu', [$this, 'register_admin_page']);
            add_action('admin_init', [$this, 'handle_admin_actions']);
            add_action('admin_init', [$this, 'maybe_seed_health_check_test_path'], 20);
            add_action('admin_notices', [$this, 'admin_notices']);
            add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_assets']);
            add_filter('plugin_action_links_' . plugin_basename(__FILE__), [$this, 'plugin_action_links']);
        }
    }


    public static function defaults(): array
    {
        return [
            'protection_mode' => 'monitor', // off, seo_only, monitor, cookie, cookie_referer, strict, emergency.
            'base_recovery_mode' => 'cookie_referer',
            'set_cookie' => 1,
            'cookie_name' => 'facetfence_human',
            'cookie_ttl' => 7200,
            'signed_cookie' => 1,
            'rotate_cookie_name' => 1,
            'bind_cookie_ua' => 0,
            'bind_cookie_ip_prefix' => 0,
            'seo_noindex' => 1,
            'canonical_clean' => 1,
            'output_canonical_tag' => 1,
            'seo_soft_max_score' => 8,
            'seo_soft_high_score_action' => 'redirect_clean', // redirect_clean, block.
            'manage_htaccess' => 0,
            'block_xmlrpc' => 0,
            'manage_robots_txt' => 0,
            'protected_paths_regex' => '^/(product-category|shop)/',
            'query_keys_regex' => 'filter_[^=]+|query_type_[^=]+|orderby|per_page|shop_view|stock_status|min_price|max_price|rating_filter',
            'allowed_cookie_regex' => '',
            'allow_ips' => '',
            'allow_user_agent_regex' => '',
            'allow_roles' => 'administrator,shop_manager',
            'trusted_proxy_mode' => 'off', // off, cloudflare, custom.
            'trusted_proxy_cidrs' => '',
            'max_filter_params' => 4,
            'max_query_length' => 700,
            'complexity_cookie_score' => 4,
            'complexity_block_score' => 12,
            'complexity_emergency_score' => 18,
            'block_response' => '403',
            'event_log_enabled' => 1,
            'event_log_storage' => 'database', // database, ndjson, both.
            'event_log_retention_days' => 14,
            'event_log_sample_after_per_minute' => 300,
            'event_log_sample_rate' => 10,
            'event_log_disable_per_request_in_emergency' => 1,
            'ip_logging_mode' => 'hash', // full, anonymized, hash.
            'auto_emergency_enabled' => 0,
            'auto_window_minutes' => 5,
            'auto_strict_threshold' => 300,
            'auto_emergency_threshold' => 1000,
            'auto_distinct_ip_threshold' => 100,
            'auto_recovery_minutes' => 30,
            'rate_limit_enabled' => 0,
            'rate_limit_ip_threshold' => 20,
            'rate_limit_range_threshold' => 200,
            'rate_limit_window_seconds' => 60,
            'rate_limit_block_seconds' => 600,
            'verify_googlebot' => 0,
            'verify_bingbot' => 0,
            'block_fake_search_bots' => 1,
            'verified_bot_cache_ttl' => 86400,
            'verified_bot_max_score' => 6,
            'health_check_after_changes' => 0,
            'rollback_on_health_failure' => 1,
            'health_check_test_path' => '',
            'remove_file_rules_on_uninstall' => 0,
        ];
    }

    public static function activate(bool $network_wide = false): void
    {
        $self = self::instance();
        if (is_multisite() && $network_wide) {
            foreach (self::network_site_ids() as $site_id) {
                switch_to_blog((int) $site_id);
                $self->activate_current_site();
                restore_current_blog();
            }
            return;
        }

        $self->activate_current_site();
    }

    private static function network_site_ids(): array
    {
        if (!function_exists('get_sites')) {
            return [];
        }
        $site_ids = get_sites(['fields' => 'ids', 'number' => 0]);
        return is_array($site_ids) ? $site_ids : [];
    }

    private function activate_current_site(): void
    {
        $this->migrate_legacy_options();
        $opts = get_option(self::OPTION);
        if (!is_array($opts)) {
            $opts = self::defaults();
        }
        update_option(self::OPTION, array_merge(self::defaults(), $opts), false);
        $this->create_event_table();
        update_option(self::DB_VERSION_OPTION, self::DB_VERSION, false);
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + HOUR_IN_SECONDS, 'hourly', self::CRON_HOOK);
        }
        $this->apply_file_rules($this->options(), 'activation');
    }

    public static function deactivate(bool $network_wide = false): void
    {
        if (is_multisite() && $network_wide) {
            foreach (self::network_site_ids() as $site_id) {
                switch_to_blog((int) $site_id);
                wp_clear_scheduled_hook(self::CRON_HOOK);
                restore_current_blog();
            }
            return;
        }

        wp_clear_scheduled_hook(self::CRON_HOOK);
        // Managed server rules are intentionally kept on deactivation for active crawl-flood incidents.
        // Use the settings page or uninstall option to remove them when the site is stable.
    }

    private function migrate_legacy_options(): void
    {
        $new = get_option(self::OPTION);
        $old = get_option(self::OLD_OPTION);
        if (!is_array($new) && is_array($old)) {
            update_option(self::OPTION, array_merge(self::defaults(), $old), false);
        }

        $new_tests = get_option(self::TEST_OPTION);
        $old_tests = get_option(self::OLD_TEST_OPTION);
        if (!is_array($new_tests) && is_array($old_tests)) {
            update_option(self::TEST_OPTION, $old_tests, false);
        }
    }

    public function options(): array
    {
        $this->migrate_legacy_options();
        $opts = get_option(self::OPTION, []);
        if (!is_array($opts)) {
            $opts = [];
        }
        $opts = array_merge(self::defaults(), $opts);
        if (!isset($opts['protection_mode']) || !array_key_exists($opts['protection_mode'], $this->modes())) {
            $opts['protection_mode'] = self::defaults()['protection_mode'];
        }
        return $opts;
    }

    private function update_options(array $new): void
    {
        update_option(self::OPTION, array_merge(self::defaults(), $new), false);
    }

    public function maybe_seed_health_check_test_path(): void
    {
        if (!current_user_can('manage_options') || !$this->is_plugin_settings_page()) {
            return;
        }
        if ($this->server_value('REQUEST_METHOD') === 'POST') {
            return;
        }

        $opts = $this->options();
        if ($this->sanitize_health_check_test_path((string) ($opts['health_check_test_path'] ?? '')) !== '') {
            return;
        }

        $path = $this->auto_detect_health_check_test_path();
        if ($path === '') {
            return;
        }

        $opts['health_check_test_path'] = $path;
        $this->update_options($opts);
    }

    private function is_plugin_settings_page(): bool
    {
        $page = filter_input(INPUT_GET, 'page', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        return sanitize_key((string) $page) === 'facetfence-product-filters';
    }

    private function modes(): array
    {
        return [
            'off' => __('Off - no SEO or protection changes', 'facetfence-product-filters'),
            'seo_only' => __('SEO Soft Mode - noindex/canonical with optional high-score redirect/block', 'facetfence-product-filters'),
            'monitor' => __('Monitor Only - log and score only, no SEO tags/cookies/robots/blocking', 'facetfence-product-filters'),
            'cookie' => __('Protection - require signed human cookie', 'facetfence-product-filters'),
            'cookie_referer' => __('Protection - require signed human cookie + internal referer', 'facetfence-product-filters'),
            'strict' => __('Strict - block protected filtered URLs except allowlists', 'facetfence-product-filters'),
            'emergency' => __('Emergency - lightweight block for protected filtered URLs', 'facetfence-product-filters'),
        ];
    }

    public function enqueue_admin_assets(string $hook_suffix): void
    {
        if ($hook_suffix !== 'settings_page_facetfence-product-filters') {
            return;
        }
        wp_enqueue_style('dashicons');
        wp_enqueue_style('facetfence-product-filters-admin', plugin_dir_url(__FILE__) . 'assets/admin.css', [], self::VERSION);
        wp_enqueue_script('facetfence-product-filters-admin', plugin_dir_url(__FILE__) . 'assets/admin.js', [], self::VERSION, true);
        wp_localize_script('facetfence-product-filters-admin', 'FacetFenceAdmin', [
            'expandAll' => __('Expand all settings', 'facetfence-product-filters'),
            'collapseAdvanced' => __('Collapse advanced settings', 'facetfence-product-filters'),
            'collapsed' => __('Collapsed', 'facetfence-product-filters'),
            'expanded' => __('Expanded', 'facetfence-product-filters'),
        ]);
    }

    public function plugin_action_links(array $links): array
    {
        $settings = '<a href="' . esc_url(admin_url('options-general.php?page=facetfence-product-filters')) . '">' . esc_html__('Settings', 'facetfence-product-filters') . '</a>';
        array_unshift($links, $settings);
        return $links;
    }

    private function table_name(): string
    {
        global $wpdb;
        return $wpdb->prefix . 'facetfence_events';
    }

    private function create_event_table(): void
    {
        global $wpdb;
        $table = $this->table_name();
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            event_type VARCHAR(80) NOT NULL,
            created_at DATETIME NOT NULL,
            ip VARCHAR(80) NULL,
            ip_hash CHAR(64) NULL,
            method VARCHAR(12) NULL,
            uri TEXT NULL,
            query_string TEXT NULL,
            query_length INT UNSIGNED NOT NULL DEFAULT 0,
            filter_count INT UNSIGNED NOT NULL DEFAULT 0,
            query_type_count INT UNSIGNED NOT NULL DEFAULT 0,
            user_agent TEXT NULL,
            user_agent_hash CHAR(64) NULL,
            referer_present TINYINT(1) NOT NULL DEFAULT 0,
            cookie_present TINYINT(1) NOT NULL DEFAULT 0,
            matched_rule VARCHAR(120) NULL,
            action_taken VARCHAR(80) NULL,
            response_status SMALLINT UNSIGNED NULL,
            protection_mode VARCHAR(40) NULL,
            complexity_score INT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY  (id),
            KEY event_created (event_type, created_at),
            KEY created_at (created_at),
            KEY ip_hash_created (ip_hash, created_at),
            KEY score_created (complexity_score, created_at)
        ) {$charset_collate};";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
    }

    public function maybe_upgrade_schema(): void
    {
        $installed = get_option(self::DB_VERSION_OPTION, '');
        if ($installed === self::DB_VERSION) {
            return;
        }

        $this->create_event_table();
        update_option(self::DB_VERSION_OPTION, self::DB_VERSION, false);
    }

    public function cleanup_runtime_and_logs(): void
    {
        $opts = $this->options();
        $days = max(1, min(90, (int) $opts['event_log_retention_days']));
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table cleanup requires a direct delete query.
        $wpdb->query($wpdb->prepare('DELETE FROM %i WHERE created_at < %s', $this->table_name(), gmdate('Y-m-d H:i:s', time() - ($days * DAY_IN_SECONDS))));
        $this->cleanup_old_runtime_files();
        $this->cleanup_old_ndjson_files($days);
    }

    public function maybe_set_human_cookie(): void
    {
        $opts = $this->options();
        if (empty($opts['set_cookie']) || !in_array((string) $opts['protection_mode'], ['cookie', 'cookie_referer'], true) || is_admin() || headers_sent()) {
            return;
        }
        $cookie_name = $this->current_cookie_name($opts);
        if ($cookie_name === '') {
            return;
        }
        $cookie_value = $this->cookie_value($cookie_name);
        if ($cookie_value !== '' && $this->validate_human_cookie($cookie_value, $opts)) {
            return;
        }
        $ttl = max(300, min(86400, (int) $opts['cookie_ttl']));
        setcookie($cookie_name, $this->make_human_cookie_value($opts), [
            'expires' => time() + $ttl,
            'path' => '/',
            'domain' => '',
            'secure' => is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    public function maybe_block_xmlrpc(): void
    {
        $opts = $this->options();
        if (empty($opts['block_xmlrpc']) || in_array($opts['protection_mode'], ['off', 'monitor'], true)) {
            return;
        }
        $path = (string) wp_parse_url($this->server_value('REQUEST_URI'), PHP_URL_PATH);
        if (strtolower(basename($path)) !== 'xmlrpc.php') {
            return;
        }
        $this->log_event('xmlrpc_blocked', ['action_taken' => 'block', 'response_status' => 403, 'matched_rule' => 'xmlrpc']);
        status_header(403);
        nocache_headers();
        echo esc_html__('403', 'facetfence-product-filters');
        exit;
    }

    public function guard_request(): void
    {
        $opts = $this->options();
        if ($opts['protection_mode'] === 'off' || is_admin() || !$this->is_expensive_filtered_request()) {
            return;
        }

        $context = $this->request_context($opts);
        $this->increment_filtered_request_window_counter($context);
        $this->maybe_auto_emergency($opts, $context);
        $opts = $this->options();
        $context['protection_mode'] = $opts['protection_mode'];

        if ($opts['protection_mode'] === 'monitor') {
            $this->log_event('allowed_filter_request', ['action_taken' => 'monitor_only', 'response_status' => 200, 'matched_rule' => 'monitor'] + $context);
            return;
        }

        if ($this->current_request_is_allowlisted()) {
            $this->log_event('allowed_filter_request', ['action_taken' => 'allow_allowlist', 'response_status' => 200, 'matched_rule' => 'allowlist'] + $context);
            return;
        }

        $bot_decision = $this->search_bot_decision($opts, $context);
        if ($bot_decision === 'fake_block') {
            $this->block_request(403, 'fake_search_bot_blocked', 'fake_search_bot', $context);
        }
        if ($bot_decision === 'verified_allow') {
            $this->log_event('allowed_filter_request', ['action_taken' => 'allow_verified_bot', 'response_status' => 200, 'matched_rule' => 'verified_bot'] + $context);
            return;
        }
        if ($bot_decision === 'verified_block') {
            $this->block_request(403, 'blocked_filter_request', 'verified_bot_complexity_limit', $context);
        }

        if (!empty($opts['rate_limit_enabled']) && $this->rate_limit_exceeded($opts, $context)) {
            $this->block_request(429, 'blocked_filter_request', 'local_rate_limit', $context);
        }

        if ($opts['protection_mode'] === 'seo_only') {
            $limit = max(0, (int) $opts['seo_soft_max_score']);
            if ($limit > 0 && $context['complexity_score'] > $limit) {
                if ($opts['seo_soft_high_score_action'] === 'block') {
                    $this->block_request(403, 'blocked_filter_request', 'seo_soft_complexity_limit', $context);
                }
                $this->redirect_to_clean_url('seo_soft_complexity_redirect', $context);
            }
            $this->log_event('allowed_filter_request', ['action_taken' => 'seo_soft_allow', 'response_status' => 200, 'matched_rule' => 'seo_soft'] + $context);
            return;
        }

        if ($opts['protection_mode'] === 'emergency') {
            $this->block_request(503, 'blocked_filter_request', 'emergency_mode', $context);
        }

        if ($context['complexity_score'] >= (int) $opts['complexity_emergency_score'] && (int) $opts['complexity_emergency_score'] > 0) {
            $this->block_request(403, 'blocked_filter_request', 'complexity_emergency_score', $context);
        }

        if ($opts['protection_mode'] === 'strict' || $context['complexity_score'] >= (int) $opts['complexity_block_score']) {
            $this->block_request(403, 'blocked_filter_request', 'strict_or_complexity_block', $context);
        }

        $requires_cookie = in_array($opts['protection_mode'], ['cookie', 'cookie_referer'], true) || $context['complexity_score'] >= (int) $opts['complexity_cookie_score'];
        if ($requires_cookie && !$this->request_has_valid_human_cookie($opts)) {
            $this->block_request(403, 'blocked_filter_request', 'missing_or_invalid_signed_cookie', $context);
        }

        if ($opts['protection_mode'] === 'cookie_referer' && !$this->has_internal_referer()) {
            $this->block_request(403, 'blocked_filter_request', 'missing_internal_referer', $context);
        }

        $this->log_event('allowed_filter_request', ['action_taken' => 'allow_after_checks', 'response_status' => 200, 'matched_rule' => 'php_guard_pass'] + $context);
    }

    public function filter_wp_robots(array $robots): array
    {
        $opts = $this->options();
        if (!$this->seo_controls_available($opts) || empty($opts['seo_noindex']) || !$this->is_expensive_filtered_request()) {
            return $robots;
        }
        $robots['noindex'] = true;
        $robots['nofollow'] = true;
        $robots['noarchive'] = true;
        $robots['nosnippet'] = true;
        unset($robots['index'], $robots['follow']);
        $this->log_event('seo_noindex_applied', ['action_taken' => 'wp_robots', 'response_status' => 200] + $this->request_context($opts));
        return $robots;
    }

    public function filter_wp_headers(array $headers): array
    {
        $opts = $this->options();
        if ($this->seo_controls_available($opts) && !empty($opts['seo_noindex']) && $this->is_expensive_filtered_request()) {
            $headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive, nosnippet';
        }
        return $headers;
    }

    public function output_filtered_canonical(): void
    {
        $opts = $this->options();
        if (!$this->seo_controls_available($opts) || empty($opts['canonical_clean']) || empty($opts['output_canonical_tag']) || !$this->is_expensive_filtered_request()) {
            return;
        }
        $canonical = $this->clean_current_archive_url();
        if ($canonical) {
            echo "\n" . '<link rel="canonical" href="' . esc_url($canonical) . '">' . "\n";
        }
    }

    private function is_expensive_filtered_request(): bool
    {
        if (is_admin()) {
            return false;
        }
        $opts = $this->options();
        $uri = $this->server_value('REQUEST_URI');
        $query = $this->server_value('QUERY_STRING');
        if ($query === '') {
            return false;
        }
        $path = (string) wp_parse_url($uri, PHP_URL_PATH);
        $relative_path = $this->site_relative_path($path);
        $paths_regex = trim((string) $opts['protected_paths_regex']);
        $query_regex = trim((string) $opts['query_keys_regex']);
        $path_match = $paths_regex !== '' && ($this->regex_match($paths_regex, $relative_path, 'i') === 1 || $this->regex_match($paths_regex, $path, 'i') === 1);
        if (!$path_match && function_exists('is_product_category') && is_product_category()) {
            $path_match = true;
        }
        if (!$path_match && function_exists('is_shop') && is_shop()) {
            $path_match = true;
        }
        if (!$path_match || $query_regex === '') {
            return false;
        }
        return $this->regex_match('(^|&)(' . $query_regex . ')=', $query, 'i') === 1;
    }

    private function request_context(array $opts): array
    {
        if ($this->request_context !== null) {
            return array_merge($this->request_context, ['protection_mode' => $opts['protection_mode']]);
        }
        $query = $this->server_value('QUERY_STRING');
        $counts = $this->count_query_key_types($query);
        $score = $this->query_complexity_score($query, $opts, $counts);
        $this->request_context = [
            'ip' => $this->logged_ip_value($opts),
            'ip_hash' => $this->hash_value($this->remote_ip()),
            'method' => $this->server_value('REQUEST_METHOD'),
            'uri' => $this->server_value('REQUEST_URI'),
            'query_string' => $query,
            'query_length' => strlen($query),
            'filter_count' => $counts['filter_count'],
            'query_type_count' => $counts['query_type_count'],
            'user_agent' => substr($this->server_value('HTTP_USER_AGENT'), 0, 600),
            'user_agent_hash' => $this->hash_value($this->server_value('HTTP_USER_AGENT')),
            'referer_present' => $this->server_value('HTTP_REFERER') !== '' ? 1 : 0,
            'cookie_present' => $this->server_value('HTTP_COOKIE') !== '' ? 1 : 0,
            'complexity_score' => $score,
            'protection_mode' => $opts['protection_mode'],
        ];
        return $this->request_context;
    }

    private function count_query_key_types(string $query): array
    {
        $out = ['filter_count' => 0, 'query_type_count' => 0, 'multi_value_count' => 0, 'total_params' => 0];
        if ($query === '') {
            return $out;
        }
        parse_str($query, $params);
        foreach ((array) $params as $key => $value) {
            $out['total_params']++;
            if (strpos((string) $key, 'filter_') === 0) {
                $out['filter_count']++;
                if (is_string($value) && strpos($value, ',') !== false) {
                    $out['multi_value_count']++;
                }
            }
            if (strpos((string) $key, 'query_type_') === 0) {
                $out['query_type_count']++;
            }
        }
        return $out;
    }

    private function query_complexity_score(string $query, array $opts, array $counts = null): int
    {
        if ($counts === null) {
            $counts = $this->count_query_key_types($query);
        }
        $score = 0;
        $score += (int) $counts['filter_count'] * 2;
        $score += (int) $counts['query_type_count'];
        $score += (int) $counts['multi_value_count'];
        parse_str($query, $params);
        foreach (['stock_status' => 1, 'orderby' => 1, 'per_page' => 2, 'shop_view' => 1, 'min_price' => 1, 'max_price' => 1, 'rating_filter' => 1] as $key => $weight) {
            if (array_key_exists($key, (array) $params)) {
                $score += $weight;
            }
        }
        $length = strlen($query);
        if ($length > 700) {
            $score += 8;
        } elseif ($length > 300) {
            $score += 3;
        }
        if ((int) $counts['filter_count'] > 3) {
            $score += 5;
        }
        $max_params = max(0, (int) $opts['max_filter_params']);
        $max_length = max(0, (int) $opts['max_query_length']);
        if ($max_params > 0 && ((int) $counts['filter_count'] + (int) $counts['query_type_count']) > $max_params) {
            $score += 4;
        }
        if ($max_length > 0 && $length > $max_length) {
            $score += 4;
        }
        return max(0, $score);
    }

    private function current_request_is_allowlisted(): bool
    {
        $opts = $this->options();
        $ip = $this->remote_ip();
        if ($ip !== '' && $this->ip_in_allowlist($ip, (string) $opts['allow_ips'])) {
            return true;
        }
        $ua_regex = trim((string) $opts['allow_user_agent_regex']);
        $ua = $this->server_value('HTTP_USER_AGENT');
        if ($ua_regex !== '' && $this->regex_match($ua_regex, $ua, 'i') === 1) {
            return true;
        }
        if (is_user_logged_in()) {
            $roles = array_filter(array_map('trim', explode(',', (string) $opts['allow_roles'])));
            if ($roles) {
                $user = wp_get_current_user();
                foreach ((array) $user->roles as $role) {
                    if (in_array($role, $roles, true)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private function remote_ip(): string
    {
        $remote = $this->sanitize_ip($this->server_value('REMOTE_ADDR'));
        $opts = $this->options();
        $mode = (string) ($opts['trusted_proxy_mode'] ?? 'off');
        if ($mode === 'off' || $remote === '' || !$this->remote_addr_is_trusted_proxy($remote, $opts)) {
            return $remote;
        }

        if ($mode === 'cloudflare') {
            $cf = $this->sanitize_ip($this->server_value('HTTP_CF_CONNECTING_IP'));
            if ($cf !== '') {
                return $cf;
            }
        }

        $xff = $this->server_value('HTTP_X_FORWARDED_FOR');
        if ($xff !== '') {
            $parts = array_map('trim', explode(',', $xff));
            foreach ($parts as $part) {
                $candidate = $this->sanitize_ip($part);
                if ($candidate !== '') {
                    return $candidate;
                }
            }
        }

        return $remote;
    }

    private function sanitize_ip(string $ip): string
    {
        $ip = trim($ip);
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }

    private function remote_addr_is_trusted_proxy(string $remote, array $opts): bool
    {
        $mode = (string) ($opts['trusted_proxy_mode'] ?? 'off');
        if ($mode === 'cloudflare') {
            foreach ($this->cloudflare_proxy_cidrs() as $cidr) {
                if ($this->ip_in_cidr($remote, $cidr)) {
                    return true;
                }
            }
            return false;
        }
        if ($mode === 'custom') {
            foreach (preg_split('/[\r\n,]+/', (string) ($opts['trusted_proxy_cidrs'] ?? '')) ?: [] as $cidr) {
                $cidr = trim((string) $cidr);
                if ($cidr !== '' && $this->ip_in_cidr($remote, $cidr)) {
                    return true;
                }
            }
        }
        return false;
    }

    private function cloudflare_proxy_cidrs(): array
    {
        return [
            '173.245.48.0/20','103.21.244.0/22','103.22.200.0/22','103.31.4.0/22','141.101.64.0/18','108.162.192.0/18','190.93.240.0/20','188.114.96.0/20','197.234.240.0/22','198.41.128.0/17','162.158.0.0/15','104.16.0.0/13','104.24.0.0/14','172.64.0.0/13','131.0.72.0/22',
            '2400:cb00::/32','2606:4700::/32','2803:f800::/32','2405:b500::/32','2405:8100::/32','2a06:98c0::/29','2c0f:f248::/32',
        ];
    }

    private function server_value(string $key): string
    {
        if (!isset($_SERVER[$key]) || !is_scalar($_SERVER[$key])) {
            return '';
        }
        return sanitize_text_field(wp_unslash($_SERVER[$key]));
    }

    private function cookie_value(string $key): string
    {
        if ($key === '' || !isset($_COOKIE[$key]) || !is_scalar($_COOKIE[$key])) {
            return '';
        }
        return sanitize_text_field(wp_unslash($_COOKIE[$key]));
    }

    private function ip_in_allowlist(string $ip, string $allowlist): bool
    {
        $items = preg_split('/[\r\n,]+/', $allowlist);
        if (!$items) {
            return false;
        }
        foreach ($items as $item) {
            $item = trim($item);
            if ($item === '') {
                continue;
            }
            if ($item === $ip) {
                return true;
            }
            if (substr($item, -1) === '*' && strpos($ip, rtrim($item, '*')) === 0) {
                return true;
            }
            if (strpos($item, '/') !== false && $this->ip_in_cidr($ip, $item)) {
                return true;
            }
        }
        return false;
    }

    private function ip_in_cidr(string $ip, string $cidr): bool
    {
        [$network, $prefix] = array_pad(explode('/', trim($cidr), 2), 2, null);
        $ip_bin = @inet_pton($ip);
        $net_bin = @inet_pton((string) $network);
        if ($ip_bin === false || $net_bin === false || strlen($ip_bin) !== strlen($net_bin)) {
            return false;
        }
        $prefix = (int) $prefix;
        $max_bits = strlen($ip_bin) * 8;
        if ($prefix < 0 || $prefix > $max_bits) {
            return false;
        }
        $full_bytes = intdiv($prefix, 8);
        $remaining_bits = $prefix % 8;
        if ($full_bytes > 0 && substr($ip_bin, 0, $full_bytes) !== substr($net_bin, 0, $full_bytes)) {
            return false;
        }
        if ($remaining_bits === 0) {
            return true;
        }
        $mask = (0xff << (8 - $remaining_bits)) & 0xff;
        return (ord($ip_bin[$full_bytes]) & $mask) === (ord($net_bin[$full_bytes]) & $mask);
    }

    public function filter_virtual_robots_txt(string $output, bool $public): string
    {
        $opts = $this->options();
        if (!$this->robots_file_rules_available($opts) || empty($opts['manage_robots_txt'])) {
            return $output;
        }
        $output = $this->remove_managed_block($output, self::ROBOTS_BEGIN, self::ROBOTS_END);
        return rtrim($output) . "\n\n" . $this->robots_block() . "\n";
    }

    private function robots_block(): string
    {
        return self::ROBOTS_BEGIN . "\n" .
            "User-agent: *\n" .
            "Disallow: /*?filter_\n" .
            "Disallow: /*&filter_\n" .
            "Disallow: /*?query_type_\n" .
            "Disallow: /*&query_type_\n" .
            "Disallow: /*?per_page=\n" .
            "Disallow: /*&per_page=\n" .
            "Disallow: /*?shop_view=\n" .
            "Disallow: /*&shop_view=\n" .
            "Disallow: /*?orderby=\n" .
            "Disallow: /*&orderby=\n" .
            "Disallow: /*?min_price=\n" .
            "Disallow: /*&min_price=\n" .
            "Disallow: /*?max_price=\n" .
            "Disallow: /*&max_price=\n" .
            self::ROBOTS_END;
    }

    public function register_admin_page(): void
    {
        add_options_page(__('FacetFence Product Filters', 'facetfence-product-filters'), __('FacetFence Product Filters', 'facetfence-product-filters'), 'manage_options', 'facetfence-product-filters', [$this, 'render_admin_page']);
    }

    public function handle_admin_actions(): void
    {
        $raw_action = '';
        $posted_action = filter_input(INPUT_POST, 'facetfence_action', FILTER_UNSAFE_RAW);
        if ($posted_action === null || $posted_action === false || !is_scalar($posted_action)) {
            $posted_action = filter_input(INPUT_POST, 'facetfence_legacy_action', FILTER_UNSAFE_RAW);
        }
        if ($posted_action !== null && $posted_action !== false && is_scalar($posted_action)) {
            $raw_action = sanitize_text_field((string) $posted_action);
        }
        if (!current_user_can('manage_options') || $raw_action === '') {
            return;
        }
        check_admin_referer('facetfence_save_settings');
        $action = sanitize_key($raw_action);

        if ($action === 'save') {
            $this->handle_save_action();
        }
        if ($action === 'rewrite_htaccess') {
            $opts = $this->options();
            if (!$this->htaccess_managed_rules_needed($opts)) {
                $ok = $this->remove_htaccess_guard('manual_rewrite_safe_mode');
                $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('.htaccess managed block removed for the current protection mode. Cookie modes are enforced in WordPress/PHP.', 'facetfence-product-filters') : __('Could not remove the managed .htaccess guard. Check file permissions or remove the managed block manually.', 'facetfence-product-filters'));
                $this->redirect_with_message('htaccess_safe_mode_removed');
            }
            $blocked_light_ok = $this->blocking_server_rules_available($opts) ? $this->write_blocked_light_file() : true;
            $guard_ok = $this->write_htaccess_guard('manual_rewrite');
            $ok = $blocked_light_ok && $guard_ok;
            $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('.htaccess guard written.', 'facetfence-product-filters') : __('Could not write .htaccess guard. Validate regex settings and file permissions.', 'facetfence-product-filters'));
            $this->redirect_with_message('htaccess_written');
        }
        if ($action === 'remove_htaccess') {
            $ok = $this->remove_htaccess_guard('manual_remove');
            $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('.htaccess guard removed.', 'facetfence-product-filters') : __('Could not remove .htaccess guard. Check file permissions.', 'facetfence-product-filters'));
            $this->redirect_with_message('htaccess_removed');
        }
        if ($action === 'rewrite_robots') {
            $opts = $this->options();
            if (!$this->robots_file_rules_available($opts)) {
                $this->set_admin_notice('error', __('robots.txt rules are not written while protection mode is Off or Monitor. Use SEO Soft Mode or a blocking mode first.', 'facetfence-product-filters'));
                $this->redirect_with_message('robots_safe_mode');
            }
            $ok = $this->write_robots_txt_rules('manual_rewrite');
            $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('robots.txt rules written.', 'facetfence-product-filters') : __('Could not write robots.txt rules. Check file permissions.', 'facetfence-product-filters'));
            $this->redirect_with_message('robots_written');
        }
        if ($action === 'remove_robots') {
            $ok = $this->remove_robots_txt_rules('manual_remove');
            $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('robots.txt rules removed.', 'facetfence-product-filters') : __('Could not remove robots.txt rules. Check file permissions.', 'facetfence-product-filters'));
            $this->redirect_with_message('robots_removed');
        }
        if ($action === 'run_tests') {
            $this->run_self_tests();
            $tests = get_option(self::TEST_OPTION, []);
            $ok = $this->tests_are_ok($tests);
            $this->log_event($ok ? 'self_test_passed' : 'self_test_failed', ['action_taken' => 'manual_self_test', 'response_status' => $ok ? 200 : 500]);
            $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('Self-tests completed successfully.', 'facetfence-product-filters') : __('Self-tests completed, but at least one policy check failed. Review the Health Check table before enabling stricter modes.', 'facetfence-product-filters'));
            $this->redirect_with_message('tests_run');
        }
        if ($action === 'restore_latest_backup') {
            $ok = $this->restore_latest_backup();
            $this->set_admin_notice($ok ? 'success' : 'error', $ok ? __('Latest backup restored.', 'facetfence-product-filters') : __('Could not restore latest backup.', 'facetfence-product-filters'));
            $this->redirect_with_message('backup_restored');
        }
        if ($action === 'rotate_cookie_secret') {
            update_option('facetfence_cookie_secret_version', wp_generate_password(24, false, false), false);
            $this->log_event('cookie_secret_rotated', ['action_taken' => 'manual_rotate_cookie_secret', 'response_status' => 200]);
            $this->set_admin_notice('success', __('Cookie secret rotated. Existing human cookies are invalidated.', 'facetfence-product-filters'));
            $this->redirect_with_message('cookie_rotated');
        }
        if ($action === 'export_events_csv') {
            $this->export_events_csv();
        }
    }

    private function current_post_nonce_is_valid(): bool
    {
        $nonce = filter_input(INPUT_POST, '_wpnonce', FILTER_UNSAFE_RAW);
        if ($nonce === null || $nonce === false || !is_scalar($nonce)) {
            return false;
        }
        return (bool) wp_verify_nonce(sanitize_text_field((string) $nonce), 'facetfence_save_settings');
    }

    private function post_raw(string $key, string $default = ''): string
    {
        if (!$this->current_post_nonce_is_valid()) {
            return $default;
        }
        $value = filter_input(INPUT_POST, $key, FILTER_UNSAFE_RAW);
        if ($value === null || $value === false || !is_scalar($value)) {
            return $default;
        }
        return sanitize_textarea_field((string) $value);
    }

    private function post_flag(string $key): bool
    {
        if (!$this->current_post_nonce_is_valid()) {
            return false;
        }
        $value = filter_input(INPUT_POST, $key, FILTER_UNSAFE_RAW);
        return $value !== null && $value !== false;
    }

    private function post_text(string $key, string $default = ''): string
    {
        $value = $this->post_raw($key, $default);
        return sanitize_text_field($value);
    }

    private function post_textarea(string $key, string $default = ''): string
    {
        $value = $this->post_raw($key, $default);
        return sanitize_textarea_field($value);
    }

    private function post_regex(string $key, string $default = ''): string
    {
        return $this->sanitize_regex_fragment($this->post_raw($key, $default));
    }

    private function post_key(string $key, string $default = ''): string
    {
        return sanitize_key($this->post_text($key, $default));
    }

    private function post_int(string $key, int $default = 0): int
    {
        return absint($this->post_text($key, (string) $default));
    }

    private function handle_save_action(): void
    {
        if (!$this->current_post_nonce_is_valid()) {
            return;
        }
        $old_opts = $this->options();
        $opts = $old_opts;
        $mode = $this->post_key('protection_mode', self::defaults()['protection_mode']);
        $opts['protection_mode'] = array_key_exists($mode, $this->modes()) ? $mode : self::defaults()['protection_mode'];
        $opts['base_recovery_mode'] = $this->post_key('base_recovery_mode', 'cookie_referer');
        if (!array_key_exists($opts['base_recovery_mode'], $this->modes()) || in_array($opts['base_recovery_mode'], ['off', 'emergency'], true)) {
            $opts['base_recovery_mode'] = 'cookie_referer';
        }
        foreach (['set_cookie','signed_cookie','rotate_cookie_name','bind_cookie_ua','bind_cookie_ip_prefix','seo_noindex','canonical_clean','output_canonical_tag','manage_htaccess','block_xmlrpc','manage_robots_txt','event_log_enabled','event_log_disable_per_request_in_emergency','auto_emergency_enabled','rate_limit_enabled','verify_googlebot','verify_bingbot','block_fake_search_bots','health_check_after_changes','rollback_on_health_failure','remove_file_rules_on_uninstall'] as $flag) {
            $opts[$flag] = $this->post_flag($flag) ? 1 : 0;
        }
        $opts['cookie_name'] = $this->sanitize_cookie_name($this->post_text('cookie_name', self::defaults()['cookie_name']));
        $opts['cookie_ttl'] = max(300, min(86400, $this->post_int('cookie_ttl', 7200)));
        $opts['protected_paths_regex'] = $this->post_regex('protected_paths_regex', self::defaults()['protected_paths_regex']);
        $opts['query_keys_regex'] = $this->post_regex('query_keys_regex', self::defaults()['query_keys_regex']);
        $opts['allowed_cookie_regex'] = $this->post_regex('allowed_cookie_regex', self::defaults()['allowed_cookie_regex']);
        $opts['allow_ips'] = $this->sanitize_multiline($this->post_raw('allow_ips', ''));
        $opts['allow_user_agent_regex'] = $this->post_regex('allow_user_agent_regex', '');
        $opts['allow_roles'] = $this->sanitize_roles($this->post_text('allow_roles', self::defaults()['allow_roles']));
        $opts['trusted_proxy_mode'] = $this->post_key('trusted_proxy_mode', self::defaults()['trusted_proxy_mode']);
        if (!in_array($opts['trusted_proxy_mode'], ['off', 'cloudflare', 'custom'], true)) {
            $opts['trusted_proxy_mode'] = 'off';
        }
        $opts['trusted_proxy_cidrs'] = $this->sanitize_multiline($this->post_raw('trusted_proxy_cidrs', ''));
        $opts['max_filter_params'] = max(0, min(50, $this->post_int('max_filter_params', 4)));
        $opts['max_query_length'] = max(0, min(8000, $this->post_int('max_query_length', 700)));
        $opts['complexity_cookie_score'] = max(0, min(50, $this->post_int('complexity_cookie_score', 4)));
        $opts['complexity_block_score'] = max(0, min(80, $this->post_int('complexity_block_score', 12)));
        $opts['complexity_emergency_score'] = max(0, min(100, $this->post_int('complexity_emergency_score', 18)));
        $opts['seo_soft_max_score'] = max(0, min(80, $this->post_int('seo_soft_max_score', 8)));
        $opts['seo_soft_high_score_action'] = $this->post_key('seo_soft_high_score_action', 'redirect_clean');
        if (!in_array($opts['seo_soft_high_score_action'], ['redirect_clean','block'], true)) {
            $opts['seo_soft_high_score_action'] = 'redirect_clean';
        }
        $opts['block_response'] = $this->post_key('block_response', '403');
        $opts['block_response'] = in_array($opts['block_response'], ['403', '404'], true) ? $opts['block_response'] : '403';
        $opts['event_log_storage'] = $this->post_key('event_log_storage', 'database');
        if (!in_array($opts['event_log_storage'], ['database','ndjson','both'], true)) {
            $opts['event_log_storage'] = 'database';
        }
        $opts['event_log_retention_days'] = max(1, min(90, $this->post_int('event_log_retention_days', 14)));
        $opts['event_log_sample_after_per_minute'] = max(0, min(100000, $this->post_int('event_log_sample_after_per_minute', 300)));
        $opts['event_log_sample_rate'] = max(1, min(1000, $this->post_int('event_log_sample_rate', 10)));
        $opts['ip_logging_mode'] = $this->post_key('ip_logging_mode', 'hash');
        if (!in_array($opts['ip_logging_mode'], ['full','anonymized','hash'], true)) {
            $opts['ip_logging_mode'] = 'hash';
        }
        $opts['auto_window_minutes'] = max(1, min(60, $this->post_int('auto_window_minutes', 5)));
        $opts['auto_strict_threshold'] = max(1, min(100000, $this->post_int('auto_strict_threshold', 300)));
        $opts['auto_emergency_threshold'] = max(1, min(100000, $this->post_int('auto_emergency_threshold', 1000)));
        $opts['auto_distinct_ip_threshold'] = max(1, min(50000, $this->post_int('auto_distinct_ip_threshold', 100)));
        $opts['auto_recovery_minutes'] = max(1, min(1440, $this->post_int('auto_recovery_minutes', 30)));
        $opts['rate_limit_ip_threshold'] = max(1, min(10000, $this->post_int('rate_limit_ip_threshold', 20)));
        $opts['rate_limit_range_threshold'] = max(1, min(100000, $this->post_int('rate_limit_range_threshold', 200)));
        $opts['rate_limit_window_seconds'] = max(10, min(3600, $this->post_int('rate_limit_window_seconds', 60)));
        $opts['rate_limit_block_seconds'] = max(60, min(86400, $this->post_int('rate_limit_block_seconds', 600)));
        $opts['verified_bot_cache_ttl'] = max(300, min(604800, $this->post_int('verified_bot_cache_ttl', 86400)));
        $opts['verified_bot_max_score'] = max(0, min(80, $this->post_int('verified_bot_max_score', 6)));
        $health_check_test_path = $this->sanitize_health_check_test_path($this->post_text('health_check_test_path', ''));
        if ($health_check_test_path === '') {
            $health_check_test_path = $this->auto_detect_health_check_test_path();
        }
        $opts['health_check_test_path'] = $health_check_test_path;

        $errors = $this->validate_options($opts);
        if ($errors) {
            $this->set_admin_notice('error', implode(' ', $errors));
            $this->redirect_with_message('invalid_settings');
        }

        $this->update_options($opts);
        if ($old_opts['protection_mode'] !== $opts['protection_mode']) {
            $this->log_event('mode_changed', ['action_taken' => 'manual_mode_change', 'matched_rule' => $old_opts['protection_mode'] . '->' . $opts['protection_mode'], 'response_status' => 200]);
        }
        $files_ok = $this->apply_file_rules($opts, 'settings_saved');
        $this->set_admin_notice($files_ok ? 'success' : 'warning', $files_ok ? __('Settings saved and rules regenerated.', 'facetfence-product-filters') : __('Settings saved, but at least one filesystem operation failed. Check file permissions or remove/rewrite rules manually.', 'facetfence-product-filters'));
        $this->redirect_with_message('saved');
    }

    private function apply_file_rules(array $opts, string $reason = 'apply_rules'): bool
    {
        $ok = true;
        if (!empty($opts['manage_htaccess']) && $this->htaccess_managed_rules_needed($opts)) {
            $blocked_light_ok = $this->blocking_server_rules_available($opts) ? $this->write_blocked_light_file() : true;
            $htaccess_ok = $this->write_htaccess_guard($reason);
            $ok = $blocked_light_ok && $htaccess_ok && $ok;
        } else {
            // Cookie and Cookie + Referer modes must not leave stale pre-PHP filtered-URL blocks in .htaccess.
            // Removal is executed even when blocked-light.html cannot be written, so stale 403 rules are not preserved accidentally.
            $ok = $this->remove_htaccess_guard($reason . '_safe_mode') && $ok;
        }
        if (!empty($opts['manage_robots_txt']) && $this->robots_file_rules_available($opts)) {
            $ok = $this->write_robots_txt_rules($reason) && $ok;
        } elseif (empty($opts['manage_robots_txt']) || !$this->robots_file_rules_available($opts)) {
            $ok = $this->remove_robots_txt_rules($reason) && $ok;
        }
        if ($ok && !empty($opts['health_check_after_changes'])) {
            $this->run_self_tests();
            $tests = get_option(self::TEST_OPTION, []);
            if (!$this->tests_are_ok($tests)) {
                $this->log_event('self_test_failed', ['action_taken' => 'health_check_after_changes', 'response_status' => 500]);
                if (!empty($opts['rollback_on_health_failure'])) {
                    $this->restore_latest_backup();
                    $this->log_event('rollback_auto', ['action_taken' => 'rollback_on_health_failure', 'response_status' => 200]);
                }
                return false;
            }
            $this->log_event('self_test_passed', ['action_taken' => 'health_check_after_changes', 'response_status' => 200]);
        }
        return $ok;
    }

    private function redirect_with_message(string $message): void
    {
        wp_safe_redirect(add_query_arg(['page' => 'facetfence-product-filters', 'facetfence_message' => $message], admin_url('options-general.php')));
        exit;
    }

    private function set_admin_notice(string $type, string $message): void
    {
        $type = in_array($type, ['success', 'warning', 'error', 'info'], true) ? $type : 'info';
        set_transient(self::NOTICE_TRANSIENT_PREFIX . get_current_user_id(), ['type' => $type, 'message' => $message], 60);
    }

    public function admin_notices(): void
    {
        $page = filter_input(INPUT_GET, 'page', FILTER_SANITIZE_FULL_SPECIAL_CHARS);
        if (sanitize_key((string) $page) !== 'facetfence-product-filters') {
            return;
        }
        $notice = get_transient(self::NOTICE_TRANSIENT_PREFIX . get_current_user_id());
        if (!is_array($notice) || empty($notice['message'])) {
            return;
        }
        delete_transient(self::NOTICE_TRANSIENT_PREFIX . get_current_user_id());
        $type = sanitize_html_class((string) ($notice['type'] ?? 'info'));
        echo '<div class="notice notice-' . esc_attr($type) . ' is-dismissible"><p>' . esc_html((string) $notice['message']) . '</p></div>';
    }

    public function render_admin_page(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }
        $opts = $this->options();
        $htaccess = $this->htaccess_path();
        $robots = $this->robots_path();
        $htaccess_present = $this->file_contains($htaccess, self::HTACCESS_BEGIN) || $this->file_contains($htaccess, self::LEGACY_HTACCESS_BEGIN);
        $htaccess_needed = $this->htaccess_managed_rules_needed($opts);
        $pre_php_block_needed = $this->blocking_server_rules_available($opts);
        $robots_present = $this->file_contains($robots, self::ROBOTS_BEGIN) || $this->file_contains($robots, self::LEGACY_ROBOTS_BEGIN);
        $blocked_present = $this->path_exists($this->blocked_light_path());
        $tests = get_option(self::TEST_OPTION, []);
        $stats = $this->dashboard_stats();
        $events = $this->recent_events(20);
        $backups = $this->list_backups(8);
        ?>
        <div class="wrap facetfence-product-filters-wrap">
            <h1><?php esc_html_e('FacetFence Product Filters', 'facetfence-product-filters'); ?> <span class="facetfence-product-filters-version">v<?php echo esc_html(self::VERSION); ?></span></h1>
            <p><?php esc_html_e('Crawl-flood protection, SEO soft control, signed human cookies, event logging, local rate limiting, rollback, and server rule generation for WooCommerce filtered archive URLs.', 'facetfence-product-filters'); ?></p>
            <?php if ($htaccess_present && $this->blocking_server_rules_available($opts)): ?>
                <div class="notice notice-info inline facetfence-product-filters-pre-php-notice"><p><strong><?php esc_html_e('Server guard is active:', 'facetfence-product-filters'); ?></strong> <?php esc_html_e('Strict or Emergency server rules can block requests before WordPress loads. Cookie mode intentionally avoids filtered-URL pre-PHP blocking so normal shoppers can be validated by PHP.', 'facetfence-product-filters'); ?></p></div>
            <?php endif; ?>
            <?php $this->render_mode_guidance($opts); ?>

            <?php $this->render_section_heading(__('Live Dashboard', 'facetfence-product-filters'), 'section_live_dashboard'); ?>
            <div class="facetfence-product-filters-cards">
                <?php $this->stat_card(__('PHP blocked 10m', 'facetfence-product-filters'), (string) $stats['blocked_10m']); ?>
                <?php $this->stat_card(__('PHP allowed 10m', 'facetfence-product-filters'), (string) $stats['allowed_10m']); ?>
                <?php $this->stat_card(__('PHP distinct IPs 10m', 'facetfence-product-filters'), (string) $stats['distinct_ips_10m']); ?>
                <?php $this->stat_card(__('Mode', 'facetfence-product-filters'), $opts['protection_mode']); ?>
                <?php $this->stat_card(__('Server guard', 'facetfence-product-filters'), ($htaccess_present && $this->blocking_server_rules_available($opts)) ? __('Pre-PHP active', 'facetfence-product-filters') : __('PHP only / inactive', 'facetfence-product-filters')); ?>
                <?php $this->stat_card(__('Average score 10m', 'facetfence-product-filters'), (string) $stats['avg_score_10m']); ?>
            </div>
            <p class="description facetfence-product-filters-dashboard-scope"><strong><?php esc_html_e('Dashboard scope:', 'facetfence-product-filters'); ?></strong> <?php esc_html_e('These counters are based on WordPress/PHP event-log entries. They cannot count requests stopped by Apache/LiteSpeed before WordPress starts.', 'facetfence-product-filters'); ?></p>

            <table class="widefat striped facetfence-product-filters-table">
                <tbody>
                <tr><th><?php esc_html_e('Protection mode', 'facetfence-product-filters'); ?></th><td><strong><?php echo esc_html($this->modes()[$opts['protection_mode']] ?? $opts['protection_mode']); ?></strong></td></tr>
                <tr><th><?php esc_html_e('Current human cookie name', 'facetfence-product-filters'); ?></th><td><code><?php echo esc_html($this->current_cookie_name($opts)); ?></code></td></tr>
                <tr><th><?php esc_html_e('.htaccess guard', 'facetfence-product-filters'); ?></th><td><?php if ($htaccess_present): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('Present', 'facetfence-product-filters'); ?></strong><?php elseif ($htaccess_needed): ?><strong class="facetfence-product-filters-bad"><?php esc_html_e('Not present', 'facetfence-product-filters'); ?></strong><?php else: ?><span class="facetfence-product-filters-muted"><?php esc_html_e('Not required for current mode', 'facetfence-product-filters'); ?></span><?php endif; ?></td></tr>
                <tr><th><?php esc_html_e('Light block page', 'facetfence-product-filters'); ?></th><td><?php if ($blocked_present): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('Present', 'facetfence-product-filters'); ?></strong><?php elseif ($pre_php_block_needed): ?><strong class="facetfence-product-filters-bad"><?php esc_html_e('Missing', 'facetfence-product-filters'); ?></strong><?php else: ?><span class="facetfence-product-filters-muted"><?php esc_html_e('Not required for current mode', 'facetfence-product-filters'); ?></span><?php endif; ?></td></tr>
                <tr><th><?php esc_html_e('robots.txt block', 'facetfence-product-filters'); ?></th><td><?php if ($robots_present): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('Present', 'facetfence-product-filters'); ?></strong><?php else: ?><strong class="facetfence-product-filters-bad"><?php esc_html_e('Not present / virtual only', 'facetfence-product-filters'); ?></strong><?php endif; ?></td></tr>
                </tbody>
            </table>

            <?php $this->render_htaccess_diagnostics($opts); ?>
            <?php $this->render_last_self_test($tests); ?>
            <?php $this->render_recent_events($events); ?>
            <?php $this->render_settings_form($opts); ?>
            <?php $this->render_rule_generators($opts); ?>
            <?php $this->render_backups($backups); ?>
            <?php $this->render_action_tools(); ?>
        </div>
        <?php
    }

    private function stat_card(string $label, string $value): void
    {
        echo '<div class="facetfence-product-filters-card"><span>' . esc_html($label) . '</span><strong>' . esc_html($value) . '</strong></div>';
    }

    private function tooltip_texts(): array
    {
        return [
            'section_live_dashboard' => __('Quick operational snapshot for the last 10 minutes. These counters are PHP-level event-log counters. If Apache/LiteSpeed .htaccess guard blocks a request before WordPress loads, the request is protected but cannot be counted here; use server access logs for those pre-PHP hits.', 'facetfence-product-filters'),
            'section_last_self_test' => __('Shows the latest internal health checks. These tests verify the homepage, the configured WooCommerce shop/category test path, protected filtered URLs, cookie behavior, XML-RPC blocking, and robots.txt availability.', 'facetfence-product-filters'),
            'section_recent_events' => __('Recent allow/block/noindex/mode/test events. This section helps you confirm which URLs matched the policy, which action was taken, and whether traffic looks like normal filtering or automated crawling.', 'facetfence-product-filters'),
            'section_htaccess_diagnostics' => __('Shows the exact root .htaccess path, whether the file is readable and writable, whether a managed FacetFence block is present, the current file hash, and the last write/remove result. Use this when server rules do not appear to save.', 'facetfence-product-filters'),
            'section_protection' => __('Controls the main protection policy and the server-level guard. Start with Monitor Only to learn traffic patterns, use SEO Soft for indexing control, use Cookie mode for normal protection, and reserve Cookie + Referer, Strict, or Emergency for active floods.', 'facetfence-product-filters'),
            'section_complexity' => __('Defines how expensive a filtered archive URL is. More filter parameters, longer queries, and configured query keys increase the score. The score decides when cookies are required, when requests are blocked, and when emergency behavior should apply.', 'facetfence-product-filters'),
            'section_cookie' => __('Configures the lightweight first-party human cookie. Signed and rotating cookies make simple bot replay harder while keeping real visitors fast after their first valid page view. Very strict binding can affect visitors behind changing networks.', 'facetfence-product-filters'),
            'section_event_log' => __('Controls what the plugin records and how much personally identifiable data is stored. Hash or anonymize IPs for privacy, keep retention short, and enable sampling to avoid database pressure during large crawl floods.', 'facetfence-product-filters'),
            'section_auto_emergency' => __('Automatically escalates protection when traffic volume crosses configured thresholds, then returns to the base recovery mode after the site is quiet. Tune thresholds carefully so seasonal traffic spikes do not trigger aggressive blocking.', 'facetfence-product-filters'),
            'section_rate_limit' => __('Optional PHP-level rate limiting using WordPress transients or object cache. It is useful as a safety net, but high-volume attacks are better handled with .htaccess, Nginx, Cloudflare, or other edge/server rules.', 'facetfence-product-filters'),
            'section_verified_bots' => __('Validates declared search bots before trusting their user-agent names. This protects against fake Googlebot/Bingbot strings while allowing verified crawlers to receive gentler handling where appropriate.', 'facetfence-product-filters'),
            'section_health' => __('Safety controls for rule deployment and cleanup. Health checks catch broken server rules after saving; rollback can restore the latest backup; uninstall cleanup controls whether generated files are removed when deleting the plugin.', 'facetfence-product-filters'),
            'section_rule_generators' => __('Copy-ready Apache/LiteSpeed, Nginx, and Cloudflare rules for environments where automatic file writing is not possible or where edge blocking is preferred. Apply only the rule set that matches your server/CDN.', 'facetfence-product-filters'),
            'section_backups' => __('Lists backups created before the plugin changes managed files such as .htaccess, robots.txt, or blocked-light.html. Use these backups to recover quickly from a bad rule deployment.', 'facetfence-product-filters'),
            'section_manual_actions' => __('Manual maintenance tools for tests, rewriting/removing managed rules, restoring the latest backup, rotating cookie secrets, and exporting event logs. Use destructive actions carefully on production sites.', 'facetfence-product-filters'),
            'protection_mode' => __('Main behavior switch. Monitor Only is safest for observation; SEO Soft adds indexing controls; Cookie mode protects filtered URLs while allowing real visitors; Cookie + Referer is stricter; Strict/Emergency are high-impact blocking modes.', 'facetfence-product-filters'),
            'base_recovery_mode' => __('The mode Auto Emergency returns to after the recovery period. Choose a stable everyday mode such as Monitor, SEO Soft, or Cookie; do not use Emergency as the recovery target.', 'facetfence-product-filters'),
            'manage_htaccess' => __('When enabled on Apache/LiteSpeed, the plugin can write server-level rules. Filtered-URL pre-PHP blocking is intentionally limited to Strict and Emergency modes to avoid false blocking real shoppers in Cookie modes.', 'facetfence-product-filters'),
            'block_xmlrpc' => __('Blocks xmlrpc.php at PHP and managed .htaccess levels. Enable this when XML-RPC is not needed for Jetpack, mobile publishing, or legacy integrations.', 'facetfence-product-filters'),
            'block_response' => __('HTTP response used for blocked requests. 403 clearly means forbidden; 404 hides the route from basic bots. Keep behavior consistent with your SEO and monitoring expectations.', 'facetfence-product-filters'),
            'protected_paths_regex' => __('Regular expression for URL paths that should be protected, usually WooCommerce shop/category archives. Keep it narrow, for example product-category and shop paths, so normal pages are not affected.', 'facetfence-product-filters'),
            'query_keys_regex' => __('Regular expression for expensive query parameter names such as filter_*, query_type_*, price filters, ordering, stock status, and view changes. These keys identify layered-navigation crawl targets.', 'facetfence-product-filters'),
            'allowed_cookie_regex' => __('Optional PHP-only compatible cookie-name regex. Matching cookie names still require the normal signed HMAC value, so arbitrary cookie values are not trusted.', 'facetfence-product-filters'),
            'allow_ips' => __('IPs or CIDR/range patterns that bypass PHP-level checks. Use only for trusted admins, monitoring systems, or known internal networks. This does not bypass pre-PHP .htaccess blocking.', 'facetfence-product-filters'),
            'allow_user_agent_regex' => __('Optional PHP-level bypass for trusted user agents. Keep this very narrow because user-agent strings are easy to spoof unless combined with verified-bot checks.', 'facetfence-product-filters'),
            'allow_roles' => __('Comma-separated WordPress role slugs allowed through PHP-level protection. This is useful for admins/shop managers, but server-level .htaccess rules run before WordPress knows the user role.', 'facetfence-product-filters'),
            'max_filter_params' => __('Number of filter/query parameters allowed before the URL is considered too complex. Lower values are stricter; higher values allow deeper customer filtering but may increase crawl load.', 'facetfence-product-filters'),
            'max_query_length' => __('Maximum full query-string length before extra score is added. Very long query strings often indicate crawler-generated combinations or attack traffic.', 'facetfence-product-filters'),
            'complexity_cookie_score' => __('Score level where the plugin starts requiring a valid human cookie in cookie-based modes. Set below the block score so real users can be challenged before being blocked.', 'facetfence-product-filters'),
            'complexity_block_score' => __('Score level where the plugin blocks a request in blocking modes. Increase this if legitimate filter combinations are being blocked; decrease it during severe floods.', 'facetfence-product-filters'),
            'complexity_emergency_score' => __('Very high score threshold that marks a request as emergency-level complexity. Use this to catch extreme filter combinations even before volume-based thresholds trigger.', 'facetfence-product-filters'),
            'seo_soft_max_score' => __('In SEO Soft Mode, filter URLs up to this score can receive noindex/canonical handling while higher-score URLs can be redirected to a clean URL or blocked, depending on the selected action.', 'facetfence-product-filters'),
            'set_cookie' => __('Sets a lightweight first-party HttpOnly cookie for real visitors. Cookie-based protection depends on this unless another trusted flow sets a compatible cookie.', 'facetfence-product-filters'),
            'cookie_name' => __('Base name for the human cookie. Keep the default unless you have a naming conflict or need to coordinate with existing server/CDN rules.', 'facetfence-product-filters'),
            'cookie_ttl' => __('Cookie lifetime in seconds. Shorter TTLs reduce replay window; longer TTLs reduce repeat challenges for real shoppers.', 'facetfence-product-filters'),
            'cookie_hardening' => __('Adds HMAC signing, optional daily name rotation, and optional binding to User-Agent or IP prefix. Stronger binding improves abuse resistance but can affect visitors whose browser/network changes frequently.', 'facetfence-product-filters'),
            'enable_event_log' => __('Enables recording of important plugin events such as blocked requests, allowed filtered requests, noindex decisions, mode changes, and self-tests.', 'facetfence-product-filters'),
            'event_log_storage' => __('Where events are stored. Database is easiest to review in WordPress; NDJSON file is useful for server-side analysis; Both gives redundancy but writes more data.', 'facetfence-product-filters'),
            'ip_logging_mode' => __('Controls IP privacy in logs. Hash only is privacy-friendly, anonymized keeps partial troubleshooting value, and full IP should be used only when you need exact forensic data.', 'facetfence-product-filters'),
            'retention_days' => __('Number of days to keep logs before cleanup. Short retention reduces database size and privacy exposure; longer retention helps investigate recurring crawl patterns.', 'facetfence-product-filters'),
            'log_throttling' => __('Sampling rule for high traffic. After the configured events-per-minute threshold, the plugin records only one out of every N repetitive events while counters still drive protection decisions.', 'facetfence-product-filters'),
            'emergency_log_pressure' => __('Reduces repetitive per-request logging while Emergency mode is active. This protects the database and filesystem when the site is already under heavy crawl pressure.', 'facetfence-product-filters'),
            'enable_auto_emergency' => __('Turns on automatic escalation to Strict/Emergency based on request volume and IP diversity. Keep disabled if you prefer manual mode changes only.', 'facetfence-product-filters'),
            'auto_window_minutes' => __('Rolling time window used to count filtered and blocked requests for Auto Emergency decisions. Shorter windows react faster; longer windows are smoother but slower.', 'facetfence-product-filters'),
            'strict_threshold' => __('Number of matched requests within the window required to move into Strict mode. Set above normal peak traffic but below flood levels.', 'facetfence-product-filters'),
            'emergency_threshold' => __('Number of matched or blocked requests within the window required to move into Emergency mode. This should be higher than the Strict threshold.', 'facetfence-product-filters'),
            'distinct_ip_threshold' => __('Minimum number of different IPs seen in the window before emergency escalation. Helps distinguish distributed crawl floods from one aggressive visitor or tool.', 'facetfence-product-filters'),
            'recovery_minutes' => __('Quiet period before Auto Emergency returns to the base recovery mode. Increase it if attacks come in waves; decrease it if you want faster recovery.', 'facetfence-product-filters'),
            'enable_rate_limit' => __('Enables PHP-level rate limits. Useful for moderate abuse, but not a replacement for server/CDN protection during high-volume floods because WordPress must still load.', 'facetfence-product-filters'),
            'rate_limit_ip_threshold' => __('Maximum matching requests from one IP within the rate-limit window before temporary blocking starts.', 'facetfence-product-filters'),
            'range_threshold' => __('Maximum matching requests from the same approximate network range within the window. Helps slow small bot clusters that rotate nearby IPs.', 'facetfence-product-filters'),
            'window_seconds' => __('Length of the rate-limit counting window in seconds. Shorter windows are more responsive; longer windows are more tolerant but less immediate.', 'facetfence-product-filters'),
            'block_seconds' => __('Temporary block duration after a rate limit is exceeded. Keep it long enough to cool down abuse but not so long that accidental blocks persist for hours.', 'facetfence-product-filters'),
            'bot_verification' => __('Select which search bot families to verify and whether failed verification should be blocked. Verification is important because bot user-agent names can be forged.', 'facetfence-product-filters'),
            'verified_bot_cache_ttl' => __('How long successful bot verification is cached. Higher values reduce DNS/verification overhead; lower values refresh identity checks more often.', 'facetfence-product-filters'),
            'verified_bot_max_score' => __('Maximum complexity score allowed for verified bots before normal protection applies. Use this to keep legitimate crawlers from exploring extremely expensive filter combinations.', 'facetfence-product-filters'),
            'health_check_after_changes' => __('Runs self-tests after writing managed files. If rollback is enabled and tests fail, the plugin restores the latest backup to avoid leaving broken blocking rules active.', 'facetfence-product-filters'),
            'health_check_test_path' => __('Clean WooCommerce shop or category path used for tests before filter parameters are added. It must return 200 so the plugin can distinguish real rule problems from missing pages.', 'facetfence-product-filters'),
            'remove_file_rules_on_uninstall' => __('Controls cleanup on plugin deletion. Enable when you want .htaccess, robots.txt, and blocked-light.html changes removed automatically during uninstall.', 'facetfence-product-filters'),
        ];
    }

    private function tooltip_text(string $key): string
    {
        $texts = $this->tooltip_texts();
        return isset($texts[$key]) ? (string) $texts[$key] : '';
    }

    private function render_help_tip(string $key, string $context = ''): void
    {
        static $counter = 0;
        $text = $this->tooltip_text($key);
        if ($text === '') {
            return;
        }

        $counter++;
        $id = 'facetfence-product-filters-tooltip-' . sanitize_html_class($key) . '-' . $counter;
        /* translators: %s: setting or section label. */
        $label = $context !== '' ? sprintf(__('Help: %s', 'facetfence-product-filters'), $context) : __('More information', 'facetfence-product-filters');

        echo '<span class="facetfence-product-filters-help">';
        echo '<button type="button" class="facetfence-product-filters-help-button" aria-label="' . esc_attr($label) . '" aria-describedby="' . esc_attr($id) . '">';
        echo '<span class="dashicons dashicons-editor-help" aria-hidden="true"></span>';
        echo '</button>';
        echo '<span id="' . esc_attr($id) . '" class="facetfence-product-filters-tooltip" role="tooltip">' . esc_html($text) . '</span>';
        echo '</span>';
    }

    private function render_section_heading(string $title, string $tooltip_key): void
    {
        echo '<h2 class="facetfence-product-filters-section-heading"><span>' . esc_html($title) . '</span>';
        $this->render_help_tip($tooltip_key, $title);
        echo '</h2>';
    }

    private function render_setting_label(string $label, string $tooltip_key): void
    {
        echo '<span class="facetfence-product-filters-setting-label"><span>' . esc_html($label) . '</span>';
        $this->render_help_tip($tooltip_key, $label);
        echo '</span>';
    }

    private function render_setting_th(string $label, string $tooltip_key): void
    {
        echo '<th scope="row">';
        $this->render_setting_label($label, $tooltip_key);
        echo '</th>';
    }

    private function render_mode_guidance(array $opts): void
    {
        $mode = (string) ($opts['protection_mode'] ?? 'monitor');
        if ($mode === 'cookie_referer') {
            ?>
            <div class="notice notice-warning inline facetfence-product-filters-mode-notice">
                <p><strong><?php esc_html_e('Cookie + Referer mode is very strict.', 'facetfence-product-filters'); ?></strong> <?php esc_html_e('Direct visits from Google, external links, messaging apps, or browsers that omit the Referer header may receive 403 on protected filtered URLs until a valid FacetFence cookie and internal referer exist. Use this mode mainly during active crawl floods; Cookie or SEO Soft is usually safer for normal operation.', 'facetfence-product-filters'); ?></p>
            </div>
            <?php
            return;
        }
        if (in_array($mode, ['strict', 'emergency'], true)) {
            ?>
            <div class="notice notice-error inline facetfence-product-filters-mode-notice">
                <p><strong><?php esc_html_e('High-impact blocking mode is active.', 'facetfence-product-filters'); ?></strong> <?php esc_html_e('Review Health Check results and generated server/CDN rules before leaving this mode enabled for long periods.', 'facetfence-product-filters'); ?></p>
            </div>
            <?php
        }
    }


    private function render_htaccess_diagnostics(array $opts): void
    {
        $diag = $this->htaccess_diagnostics();
        $last = get_option(self::HTACCESS_DIAG_OPTION, []);
        if (!is_array($last)) {
            $last = [];
        }
        ?>
        <?php $this->render_section_heading(__('.htaccess Diagnostics', 'facetfence-product-filters'), 'section_htaccess_diagnostics'); ?>
        <table class="widefat striped facetfence-product-filters-table">
            <tbody>
            <tr><th><?php esc_html_e('Path', 'facetfence-product-filters'); ?></th><td><code><?php echo esc_html($diag['path']); ?></code></td></tr>
            <tr><th><?php esc_html_e('Exists', 'facetfence-product-filters'); ?></th><td><?php if (!empty($diag['exists'])): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('Yes', 'facetfence-product-filters'); ?></strong><?php else: ?><strong class="facetfence-product-filters-bad"><?php esc_html_e('No', 'facetfence-product-filters'); ?></strong><?php endif; ?></td></tr>
            <tr><th><?php esc_html_e('Readable / writable', 'facetfence-product-filters'); ?></th><td><?php echo esc_html((!empty($diag['readable']) ? __('readable', 'facetfence-product-filters') : __('not readable', 'facetfence-product-filters')) . ' / ' . (!empty($diag['writable']) ? __('writable', 'facetfence-product-filters') : __('not writable', 'facetfence-product-filters'))); ?></td></tr>
            <tr><th><?php esc_html_e('Managed block', 'facetfence-product-filters'); ?></th><td><?php if (!empty($diag['has_managed_block'])): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('Present', 'facetfence-product-filters'); ?></strong><?php else: ?><?php esc_html_e('Not present', 'facetfence-product-filters'); ?><?php endif; ?></td></tr>
            <tr><th><?php esc_html_e('Current SHA-256', 'facetfence-product-filters'); ?></th><td><code><?php echo esc_html($diag['sha256']); ?></code></td></tr>
            <tr><th><?php esc_html_e('Filesystem method', 'facetfence-product-filters'); ?></th><td><code><?php echo esc_html($diag['filesystem_method']); ?></code></td></tr>
            <?php if (!empty($last)): ?>
                <tr><th><?php esc_html_e('Last write result', 'facetfence-product-filters'); ?></th><td><?php echo esc_html((string) ($last['operation'] ?? '')); ?> — <?php if (!empty($last['success'])): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('Success', 'facetfence-product-filters'); ?></strong><?php else: ?><strong class="facetfence-product-filters-bad"><?php esc_html_e('Failed', 'facetfence-product-filters'); ?></strong><?php endif; ?> <?php if (!empty($last['error'])): ?><br><code><?php echo esc_html((string) $last['error']); ?></code><?php endif; ?></td></tr>
                <tr><th><?php esc_html_e('Last hash before / after', 'facetfence-product-filters'); ?></th><td><code><?php echo esc_html((string) ($last['hash_before'] ?? '')); ?></code><br><code><?php echo esc_html((string) ($last['hash_after'] ?? '')); ?></code></td></tr>
            <?php endif; ?>
            </tbody>
        </table>
        <p class="description"><?php esc_html_e('Cookie modes are PHP-level modes; filtered URL pre-PHP blocking is generated only for Strict/Emergency. XML-RPC .htaccess blocking is independent when enabled.', 'facetfence-product-filters'); ?></p>
        <?php
    }

    private function render_last_self_test($tests): void
    {
        if (!is_array($tests) || !$tests) {
            return;
        }
        ?>
        <?php $this->render_section_heading(__('Last Health Check / Self-Test', 'facetfence-product-filters'), 'section_last_self_test'); ?>
        <p><?php esc_html_e('Run at:', 'facetfence-product-filters'); ?> <code><?php echo esc_html($tests['time'] ?? ''); ?></code> <?php if (!empty($tests['mode'])): ?><?php esc_html_e('Mode:', 'facetfence-product-filters'); ?> <code><?php echo esc_html((string) $tests['mode']); ?></code><?php endif; ?></p>
        <table class="widefat striped facetfence-product-filters-table">
            <thead><tr><th><?php esc_html_e('Test', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('URL', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Status', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('X-Robots-Tag', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Result', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Note', 'facetfence-product-filters'); ?></th></tr></thead>
            <tbody>
            <?php foreach (($tests['items'] ?? []) as $item): ?>
                <tr><td><?php echo esc_html($item['label'] ?? ''); ?></td><td><code><?php echo esc_html($item['url'] ?? ''); ?></code></td><td><?php echo esc_html((string) ($item['status'] ?? '')); ?></td><td><?php echo esc_html((string) ($item['x_robots'] ?? '')); ?></td><td><?php if (!empty($item['ok'])): ?><strong class="facetfence-product-filters-ok"><?php esc_html_e('PASS', 'facetfence-product-filters'); ?></strong><?php else: ?><strong class="facetfence-product-filters-bad"><?php esc_html_e('CHECK', 'facetfence-product-filters'); ?></strong><?php endif; ?></td><td><?php echo esc_html((string) ($item['note'] ?? '')); ?></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    private function render_recent_events(array $events): void
    {
        ?>
        <?php $this->render_section_heading(__('Recent Events', 'facetfence-product-filters'), 'section_recent_events'); ?>
        <p class="description facetfence-product-filters-dashboard-scope"><?php esc_html_e('Recent Events shows only requests that reached WordPress/PHP. Requests blocked by generated .htaccess rules before PHP are visible in server access logs, not in this table.', 'facetfence-product-filters'); ?></p>
        <table class="widefat striped facetfence-product-filters-table">
            <thead><tr><th><?php esc_html_e('Time', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Event', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Action', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Status', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Score', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('URI', 'facetfence-product-filters'); ?></th></tr></thead>
            <tbody>
            <?php if (!$events): ?>
                <tr><td colspan="6"><?php esc_html_e('No events logged yet.', 'facetfence-product-filters'); ?></td></tr>
            <?php endif; ?>
            <?php foreach ($events as $event): ?>
                <tr><td><?php echo esc_html($event['created_at']); ?></td><td><?php echo esc_html($event['event_type']); ?></td><td><?php echo esc_html($event['action_taken']); ?></td><td><?php echo esc_html((string) $event['response_status']); ?></td><td><?php echo esc_html((string) $event['complexity_score']); ?></td><td><code><?php echo esc_html($this->truncate((string) $event['uri'], 120)); ?></code></td></tr>
            <?php endforeach; ?>
            </tbody>
        </table>
        <?php
    }

    private function render_settings_form(array $opts): void
    {
        $effective_health_check_test_path = $this->sanitize_health_check_test_path((string) ($opts['health_check_test_path'] ?? ''));
        if ($effective_health_check_test_path === '') {
            $effective_health_check_test_path = $this->auto_detect_health_check_test_path();
        }
        ?>
        <form method="post" class="facetfence-product-filters-settings-form">
            <?php wp_nonce_field('facetfence_save_settings'); ?>
            <input type="hidden" name="facetfence_action" value="save">

            <?php $this->render_section_heading(__('Protection Settings', 'facetfence-product-filters'), 'section_protection'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Protection mode', 'facetfence-product-filters'), 'protection_mode'); ?><td><select name="protection_mode"><?php foreach ($this->modes() as $key => $label): ?><option value="<?php echo esc_attr($key); ?>" <?php selected($opts['protection_mode'], $key); ?>><?php echo esc_html($label); ?></option><?php endforeach; ?></select><p class="description"><?php esc_html_e('Default is Monitor Only; it logs and scores only and does not modify SEO tags, cookies, robots, rate limits, XML-RPC, or server blocking.', 'facetfence-product-filters'); ?></p></td></tr>
                <tr><?php $this->render_setting_th(__('Base recovery mode', 'facetfence-product-filters'), 'base_recovery_mode'); ?><td><select name="base_recovery_mode"><?php foreach ($this->modes() as $key => $label): if (in_array($key, ['off','emergency'], true)) { continue; } ?><option value="<?php echo esc_attr($key); ?>" <?php selected($opts['base_recovery_mode'], $key); ?>><?php echo esc_html($label); ?></option><?php endforeach; ?></select><p class="description"><?php esc_html_e('Auto Emergency returns to this mode after the recovery period.', 'facetfence-product-filters'); ?></p></td></tr>
                <tr><?php $this->render_setting_th(__('Manage .htaccess guard', 'facetfence-product-filters'), 'manage_htaccess'); ?><td><label><input type="checkbox" name="manage_htaccess" value="1" <?php checked($opts['manage_htaccess']); ?>> <?php esc_html_e('Write Apache/LiteSpeed rewrite rules for server-level protection when the selected mode supports safe pre-PHP blocking.', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Block XML-RPC', 'facetfence-product-filters'), 'block_xmlrpc'); ?><td><label><input type="checkbox" name="block_xmlrpc" value="1" <?php checked($opts['block_xmlrpc']); ?>> <?php esc_html_e('Block xmlrpc.php at PHP and .htaccess levels when enabled.', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Block response', 'facetfence-product-filters'), 'block_response'); ?><td><select name="block_response"><option value="403" <?php selected($opts['block_response'], '403'); ?>><?php esc_html_e('403 Forbidden', 'facetfence-product-filters'); ?></option><option value="404" <?php selected($opts['block_response'], '404'); ?>><?php esc_html_e('404 Not Found', 'facetfence-product-filters'); ?></option></select></td></tr>
                <tr><?php $this->render_setting_th(__('Protected path regex', 'facetfence-product-filters'), 'protected_paths_regex'); ?><td><input type="text" name="protected_paths_regex" value="<?php echo esc_attr($opts['protected_paths_regex']); ?>" class="large-text code"></td></tr>
                <tr><?php $this->render_setting_th(__('Query key regex', 'facetfence-product-filters'), 'query_keys_regex'); ?><td><input type="text" name="query_keys_regex" value="<?php echo esc_attr($opts['query_keys_regex']); ?>" class="large-text code"></td></tr>
                <tr><?php $this->render_setting_th(__('Compatible cookie-name regex', 'facetfence-product-filters'), 'allowed_cookie_regex'); ?><td><input type="text" name="allowed_cookie_regex" value="<?php echo esc_attr($opts['allowed_cookie_regex']); ?>" class="large-text code"><p class="description"><?php esc_html_e('Optional PHP-only compatibility for additional FacetFence cookie names. The cookie value must still pass signed HMAC validation.', 'facetfence-product-filters'); ?></p></td></tr>
                <tr><?php $this->render_setting_th(__('Allowlisted IPs', 'facetfence-product-filters'), 'allow_ips'); ?><td><textarea name="allow_ips" rows="4" class="large-text code" placeholder="93.117.22.77&#10;185.235.245.0/24&#10;192.0.2.*"><?php echo esc_textarea($opts['allow_ips']); ?></textarea></td></tr>
                <tr><?php $this->render_setting_th(__('Allow User-Agent regex', 'facetfence-product-filters'), 'allow_user_agent_regex'); ?><td><input type="text" name="allow_user_agent_regex" value="<?php echo esc_attr($opts['allow_user_agent_regex']); ?>" class="large-text code"></td></tr>
                <tr><?php $this->render_setting_th(__('Allow roles', 'facetfence-product-filters'), 'allow_roles'); ?><td><input type="text" name="allow_roles" value="<?php echo esc_attr($opts['allow_roles']); ?>" class="regular-text"><p class="description"><?php esc_html_e('Comma-separated role slugs for PHP-level guard only.', 'facetfence-product-filters'); ?></p></td></tr>
                <tr><?php $this->render_setting_th(__('Trusted proxy / real IP', 'facetfence-product-filters'), 'trusted_proxy'); ?><td><select name="trusted_proxy_mode"><option value="off" <?php selected($opts['trusted_proxy_mode'], 'off'); ?>><?php esc_html_e('Off - use REMOTE_ADDR only', 'facetfence-product-filters'); ?></option><option value="cloudflare" <?php selected($opts['trusted_proxy_mode'], 'cloudflare'); ?>><?php esc_html_e('Cloudflare - trust CF-Connecting-IP from Cloudflare IP ranges', 'facetfence-product-filters'); ?></option><option value="custom" <?php selected($opts['trusted_proxy_mode'], 'custom'); ?>><?php esc_html_e('Custom trusted proxy CIDRs', 'facetfence-product-filters'); ?></option></select><p class="description"><?php esc_html_e('Use this only when REMOTE_ADDR is a trusted proxy. This affects rate limiting, IP allowlists, IP logging, bot verification, and optional IP-prefix cookie binding.', 'facetfence-product-filters'); ?></p><textarea name="trusted_proxy_cidrs" rows="4" class="large-text code" placeholder="203.0.113.0/24&#10;2001:db8::/32"><?php echo esc_textarea($opts['trusted_proxy_cidrs']); ?></textarea></td></tr>
            </table>

            <?php $this->render_section_heading(__('Query Complexity Scoring', 'facetfence-product-filters'), 'section_complexity'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Max filter/query params', 'facetfence-product-filters'), 'max_filter_params'); ?><td><input type="number" name="max_filter_params" value="<?php echo esc_attr((string) $opts['max_filter_params']); ?>" min="0" max="50"></td></tr>
                <tr><?php $this->render_setting_th(__('Max query length', 'facetfence-product-filters'), 'max_query_length'); ?><td><input type="number" name="max_query_length" value="<?php echo esc_attr((string) $opts['max_query_length']); ?>" min="0" max="8000"></td></tr>
                <tr><?php $this->render_setting_th(__('Require cookie at score', 'facetfence-product-filters'), 'complexity_cookie_score'); ?><td><input type="number" name="complexity_cookie_score" value="<?php echo esc_attr((string) $opts['complexity_cookie_score']); ?>" min="0" max="50"></td></tr>
                <tr><?php $this->render_setting_th(__('Block at score', 'facetfence-product-filters'), 'complexity_block_score'); ?><td><input type="number" name="complexity_block_score" value="<?php echo esc_attr((string) $opts['complexity_block_score']); ?>" min="0" max="80"></td></tr>
                <tr><?php $this->render_setting_th(__('Emergency score', 'facetfence-product-filters'), 'complexity_emergency_score'); ?><td><input type="number" name="complexity_emergency_score" value="<?php echo esc_attr((string) $opts['complexity_emergency_score']); ?>" min="0" max="100"></td></tr>
                <tr><?php $this->render_setting_th(__('SEO Soft max score', 'facetfence-product-filters'), 'seo_soft_max_score'); ?><td><input type="number" name="seo_soft_max_score" value="<?php echo esc_attr((string) $opts['seo_soft_max_score']); ?>" min="0" max="80"> <select name="seo_soft_high_score_action"><option value="redirect_clean" <?php selected($opts['seo_soft_high_score_action'], 'redirect_clean'); ?>><?php esc_html_e('Redirect high-score filters to clean URL', 'facetfence-product-filters'); ?></option><option value="block" <?php selected($opts['seo_soft_high_score_action'], 'block'); ?>><?php esc_html_e('Block high-score filters', 'facetfence-product-filters'); ?></option></select></td></tr>
            </table>

            <?php $this->render_section_heading(__('Signed / Rotating Human Cookie', 'facetfence-product-filters'), 'section_cookie'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Set human cookie', 'facetfence-product-filters'), 'set_cookie'); ?><td><label><input type="checkbox" name="set_cookie" value="1" <?php checked($opts['set_cookie']); ?>> <?php esc_html_e('Set a lightweight first-party HttpOnly cookie.', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Cookie base name', 'facetfence-product-filters'), 'cookie_name'); ?><td><input type="text" name="cookie_name" value="<?php echo esc_attr($opts['cookie_name']); ?>" class="regular-text"></td></tr>
                <tr><?php $this->render_setting_th(__('Cookie TTL seconds', 'facetfence-product-filters'), 'cookie_ttl'); ?><td><input type="number" name="cookie_ttl" value="<?php echo esc_attr((string) $opts['cookie_ttl']); ?>" min="300" max="86400"></td></tr>
                <tr><?php $this->render_setting_th(__('Cookie hardening', 'facetfence-product-filters'), 'cookie_hardening'); ?><td><label><input type="checkbox" name="signed_cookie" value="1" <?php checked($opts['signed_cookie']); ?>> <?php esc_html_e('HMAC-sign cookie value', 'facetfence-product-filters'); ?></label><br><label><input type="checkbox" name="rotate_cookie_name" value="1" <?php checked($opts['rotate_cookie_name']); ?>> <?php esc_html_e('Rotate cookie name daily', 'facetfence-product-filters'); ?></label><br><label><input type="checkbox" name="bind_cookie_ua" value="1" <?php checked($opts['bind_cookie_ua']); ?>> <?php esc_html_e('Bind signature to User-Agent', 'facetfence-product-filters'); ?></label><br><label><input type="checkbox" name="bind_cookie_ip_prefix" value="1" <?php checked($opts['bind_cookie_ip_prefix']); ?>> <?php esc_html_e('Bind signature to IP prefix', 'facetfence-product-filters'); ?></label></td></tr>
            </table>

            <?php $this->render_section_heading(__('Event Log / Privacy', 'facetfence-product-filters'), 'section_event_log'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Enable event log', 'facetfence-product-filters'), 'enable_event_log'); ?><td><label><input type="checkbox" name="event_log_enabled" value="1" <?php checked($opts['event_log_enabled']); ?>> <?php esc_html_e('Record blocked/allowed/noindex/mode/test events.', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Storage', 'facetfence-product-filters'), 'event_log_storage'); ?><td><select name="event_log_storage"><option value="database" <?php selected($opts['event_log_storage'], 'database'); ?>>Database</option><option value="ndjson" <?php selected($opts['event_log_storage'], 'ndjson'); ?>>NDJSON file</option><option value="both" <?php selected($opts['event_log_storage'], 'both'); ?>>Both</option></select></td></tr>
                <tr><?php $this->render_setting_th(__('IP logging mode', 'facetfence-product-filters'), 'ip_logging_mode'); ?><td><select name="ip_logging_mode"><option value="hash" <?php selected($opts['ip_logging_mode'], 'hash'); ?>>Hash only</option><option value="anonymized" <?php selected($opts['ip_logging_mode'], 'anonymized'); ?>>Anonymized</option><option value="full" <?php selected($opts['ip_logging_mode'], 'full'); ?>>Full IP</option></select></td></tr>
                <tr><?php $this->render_setting_th(__('Retention days', 'facetfence-product-filters'), 'retention_days'); ?><td><input type="number" name="event_log_retention_days" value="<?php echo esc_attr((string) $opts['event_log_retention_days']); ?>" min="1" max="90"></td></tr>
                <tr><?php $this->render_setting_th(__('High-traffic log throttling', 'facetfence-product-filters'), 'log_throttling'); ?><td><label><?php esc_html_e('Start sampling after', 'facetfence-product-filters'); ?> <input type="number" name="event_log_sample_after_per_minute" value="<?php echo esc_attr((string) $opts['event_log_sample_after_per_minute']); ?>" min="0" max="100000"> <?php esc_html_e('events per minute; keep one event out of', 'facetfence-product-filters'); ?> <input type="number" name="event_log_sample_rate" value="<?php echo esc_attr((string) $opts['event_log_sample_rate']); ?>" min="1" max="1000"></label><p class="description"><?php esc_html_e('Set threshold to 0 to disable sampling. Sampling protects the database during crawl floods while runtime attack counters still drive Auto Emergency.', 'facetfence-product-filters'); ?></p></td></tr>
                <tr><?php $this->render_setting_th(__('Emergency log pressure guard', 'facetfence-product-filters'), 'emergency_log_pressure'); ?><td><label><input type="checkbox" name="event_log_disable_per_request_in_emergency" value="1" <?php checked($opts['event_log_disable_per_request_in_emergency']); ?>> <?php esc_html_e('Skip repetitive per-request block/allow/noindex logs while Emergency mode is active.', 'facetfence-product-filters'); ?></label></td></tr>
            </table>

            <?php $this->render_section_heading(__('Auto Emergency Mode', 'facetfence-product-filters'), 'section_auto_emergency'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Enable Auto Emergency', 'facetfence-product-filters'), 'enable_auto_emergency'); ?><td><label><input type="checkbox" name="auto_emergency_enabled" value="1" <?php checked($opts['auto_emergency_enabled']); ?>> <?php esc_html_e('Automatically switch to strict/emergency when filtered-request or blocked-request thresholds are exceeded.', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Window minutes', 'facetfence-product-filters'), 'auto_window_minutes'); ?><td><input type="number" name="auto_window_minutes" value="<?php echo esc_attr((string) $opts['auto_window_minutes']); ?>" min="1" max="60"></td></tr>
                <tr><?php $this->render_setting_th(__('Strict threshold', 'facetfence-product-filters'), 'strict_threshold'); ?><td><input type="number" name="auto_strict_threshold" value="<?php echo esc_attr((string) $opts['auto_strict_threshold']); ?>" min="1"></td></tr>
                <tr><?php $this->render_setting_th(__('Emergency threshold', 'facetfence-product-filters'), 'emergency_threshold'); ?><td><input type="number" name="auto_emergency_threshold" value="<?php echo esc_attr((string) $opts['auto_emergency_threshold']); ?>" min="1"></td></tr>
                <tr><?php $this->render_setting_th(__('Distinct IP threshold', 'facetfence-product-filters'), 'distinct_ip_threshold'); ?><td><input type="number" name="auto_distinct_ip_threshold" value="<?php echo esc_attr((string) $opts['auto_distinct_ip_threshold']); ?>" min="1"></td></tr>
                <tr><?php $this->render_setting_th(__('Recovery minutes', 'facetfence-product-filters'), 'recovery_minutes'); ?><td><input type="number" name="auto_recovery_minutes" value="<?php echo esc_attr((string) $opts['auto_recovery_minutes']); ?>" min="1"></td></tr>
            </table>

            <?php $this->render_section_heading(__('Rate Limit', 'facetfence-product-filters'), 'section_rate_limit'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Enable rate limit', 'facetfence-product-filters'), 'enable_rate_limit'); ?><td><label><input type="checkbox" name="rate_limit_enabled" value="1" <?php checked($opts['rate_limit_enabled']); ?>> <?php esc_html_e('Use best-effort short-lived WordPress transients/object-cache counters. Disabled by default so Monitor mode never blocks unexpectedly; use server/CDN rate limits for high-volume attacks.', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('IP threshold', 'facetfence-product-filters'), 'rate_limit_ip_threshold'); ?><td><input type="number" name="rate_limit_ip_threshold" value="<?php echo esc_attr((string) $opts['rate_limit_ip_threshold']); ?>" min="1"></td></tr>
                <tr><?php $this->render_setting_th(__('Range threshold', 'facetfence-product-filters'), 'range_threshold'); ?><td><input type="number" name="rate_limit_range_threshold" value="<?php echo esc_attr((string) $opts['rate_limit_range_threshold']); ?>" min="1"></td></tr>
                <tr><?php $this->render_setting_th(__('Window seconds', 'facetfence-product-filters'), 'window_seconds'); ?><td><input type="number" name="rate_limit_window_seconds" value="<?php echo esc_attr((string) $opts['rate_limit_window_seconds']); ?>" min="10"></td></tr>
                <tr><?php $this->render_setting_th(__('Block seconds', 'facetfence-product-filters'), 'block_seconds'); ?><td><input type="number" name="rate_limit_block_seconds" value="<?php echo esc_attr((string) $opts['rate_limit_block_seconds']); ?>" min="60"></td></tr>
            </table>

            <?php $this->render_section_heading(__('Verified Search Bots', 'facetfence-product-filters'), 'section_verified_bots'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Bot verification', 'facetfence-product-filters'), 'bot_verification'); ?><td><label><input type="checkbox" name="verify_googlebot" value="1" <?php checked($opts['verify_googlebot']); ?>> Googlebot</label><br><label><input type="checkbox" name="verify_bingbot" value="1" <?php checked($opts['verify_bingbot']); ?>> Bingbot</label><br><label><input type="checkbox" name="block_fake_search_bots" value="1" <?php checked($opts['block_fake_search_bots']); ?>> <?php esc_html_e('Block fake search bot user agents when verification fails', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Verified bot cache TTL', 'facetfence-product-filters'), 'verified_bot_cache_ttl'); ?><td><input type="number" name="verified_bot_cache_ttl" value="<?php echo esc_attr((string) $opts['verified_bot_cache_ttl']); ?>" min="300"></td></tr>
                <tr><?php $this->render_setting_th(__('Verified bot max filter score', 'facetfence-product-filters'), 'verified_bot_max_score'); ?><td><input type="number" name="verified_bot_max_score" value="<?php echo esc_attr((string) $opts['verified_bot_max_score']); ?>" min="0"></td></tr>
            </table>

            <?php $this->render_section_heading(__('Health Check / Rollback / Uninstall', 'facetfence-product-filters'), 'section_health'); ?>
            <table class="form-table" role="presentation">
                <tr><?php $this->render_setting_th(__('Health check after changes', 'facetfence-product-filters'), 'health_check_after_changes'); ?><td><label><input type="checkbox" name="health_check_after_changes" value="1" <?php checked($opts['health_check_after_changes']); ?>> <?php esc_html_e('Run lightweight self-tests after writing server files.', 'facetfence-product-filters'); ?></label><br><label><input type="checkbox" name="rollback_on_health_failure" value="1" <?php checked($opts['rollback_on_health_failure']); ?>> <?php esc_html_e('Rollback latest backup if health check fails', 'facetfence-product-filters'); ?></label></td></tr>
                <tr><?php $this->render_setting_th(__('Health check test path', 'facetfence-product-filters'), 'health_check_test_path'); ?><td><input type="text" class="regular-text code" name="health_check_test_path" value="<?php echo esc_attr($effective_health_check_test_path); ?>" placeholder="/shop/"><p class="description"><?php esc_html_e('Use a real WooCommerce category or shop path that returns 200 before query parameters are added. If left empty, FacetFence auto-detects and saves the shop/category path when possible.', 'facetfence-product-filters'); ?></p><?php if ($effective_health_check_test_path !== ''): ?><p class="description"><?php esc_html_e('Current effective test path:', 'facetfence-product-filters'); ?> <code><?php echo esc_html($effective_health_check_test_path); ?></code></p><?php endif; ?></td></tr>
                <tr><?php $this->render_setting_th(__('Remove file rules on uninstall', 'facetfence-product-filters'), 'remove_file_rules_on_uninstall'); ?><td><label><input type="checkbox" name="remove_file_rules_on_uninstall" value="1" <?php checked($opts['remove_file_rules_on_uninstall']); ?>> <?php esc_html_e('When uninstalling, remove managed .htaccess/robots.txt blocks and blocked-light.html.', 'facetfence-product-filters'); ?></label><p class="description"><strong><?php esc_html_e('Important:', 'facetfence-product-filters'); ?></strong> <?php esc_html_e('If this remains disabled, managed .htaccess and robots.txt blocks may remain after plugin uninstall. Enable it before deleting the plugin when you want full cleanup.', 'facetfence-product-filters'); ?></p></td></tr>
            </table>
            <div class="facetfence-product-filters-settings-actions">
                <?php submit_button(__('Save Settings & Regenerate Rules', 'facetfence-product-filters'), 'primary', 'submit', false); ?>
            </div>
        </form>
        <?php
    }

    private function render_rule_generators(array $opts): void
    {
        $blocking_available = $this->blocking_server_rules_available($opts);
        ?>
        <?php $this->render_section_heading(__('Server Rule Generators', 'facetfence-product-filters'), 'section_rule_generators'); ?>
        <p><?php esc_html_e('Use these generated rules for environments where the plugin cannot safely write server configuration directly.', 'facetfence-product-filters'); ?></p>
        <p class="description"><?php esc_html_e('Server/CDN rules only pre-check FacetFence cookie-name presence; the signed HMAC cookie is still validated in PHP. Prefer the regex Cloudflare expression when your plan supports it; use the fallback expression when regex matching is unavailable.', 'facetfence-product-filters'); ?></p>
        <h3>Apache / LiteSpeed</h3><textarea readonly class="large-text code" rows="12"><?php echo esc_textarea($this->htaccess_block($opts)); ?></textarea>
        <h3>Nginx</h3><textarea readonly class="large-text code" rows="14"><?php echo esc_textarea($this->nginx_rules($opts)); ?></textarea>
        <h3><?php esc_html_e('Cloudflare Expression - Regex / stricter', 'facetfence-product-filters'); ?></h3>
        <p class="description facetfence-product-filters-rule-note"><?php esc_html_e('Copy only this expression when the Cloudflare rule editor accepts the regex matches operator. Do not paste the fallback expression together with this one.', 'facetfence-product-filters'); ?></p>
        <textarea readonly class="large-text code" rows="4"><?php echo esc_textarea($this->cloudflare_expression($opts, true)); ?></textarea>
        <h3><?php esc_html_e('Cloudflare Expression - No-regex fallback', 'facetfence-product-filters'); ?></h3>
        <p class="description facetfence-product-filters-rule-note"><?php esc_html_e('Use only this fallback expression if your Cloudflare plan or rules UI rejects regex matching.', 'facetfence-product-filters'); ?></p>
        <textarea readonly class="large-text code" rows="4"><?php echo esc_textarea($this->cloudflare_expression($opts, false)); ?></textarea>
        <?php
    }

    private function render_backups(array $backups): void
    {
        ?>
        <?php $this->render_section_heading(__('Rollback Backups', 'facetfence-product-filters'), 'section_backups'); ?>
        <table class="widefat striped facetfence-product-filters-table"><thead><tr><th><?php esc_html_e('Backup', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Files', 'facetfence-product-filters'); ?></th><th><?php esc_html_e('Reason', 'facetfence-product-filters'); ?></th></tr></thead><tbody>
        <?php if (!$backups): ?><tr><td colspan="3"><?php esc_html_e('No backups yet.', 'facetfence-product-filters'); ?></td></tr><?php endif; ?>
        <?php foreach ($backups as $backup): ?><tr><td><code><?php echo esc_html($backup['name']); ?></code></td><td><?php echo esc_html(implode(', ', $backup['files'])); ?></td><td><?php echo esc_html($backup['reason']); ?></td></tr><?php endforeach; ?>
        </tbody></table>
        <?php
    }

    private function render_action_tools(): void
    {
        ?>
        <?php $this->render_section_heading(__('Manual Actions / Test Tools', 'facetfence-product-filters'), 'section_manual_actions'); ?>
        <?php $this->action_form('run_tests', __('Run Health Check / Self-Tests', 'facetfence-product-filters'), 'primary'); ?>
        <?php $this->action_form('rewrite_htaccess', __('Rewrite .htaccess Guard', 'facetfence-product-filters'), 'secondary'); ?>
        <?php $this->action_form('remove_htaccess', __('Remove .htaccess Guard', 'facetfence-product-filters'), 'delete'); ?>
        <?php $this->action_form('rewrite_robots', __('Rewrite robots.txt Rules', 'facetfence-product-filters'), 'secondary'); ?>
        <?php $this->action_form('remove_robots', __('Remove robots.txt Rules', 'facetfence-product-filters'), 'delete'); ?>
        <?php $this->action_form('restore_latest_backup', __('Restore Latest Backup', 'facetfence-product-filters'), 'secondary'); ?>
        <?php $this->action_form('rotate_cookie_secret', __('Rotate Cookie Secret / Invalidate Cookies', 'facetfence-product-filters'), 'secondary'); ?>
        <?php $this->action_form('export_events_csv', __('Export Events CSV', 'facetfence-product-filters'), 'secondary'); ?>
        <?php
    }

    private function action_form(string $action, string $label, string $class): void
    {
        echo '<form method="post" class="facetfence-product-filters-action-form">';
        wp_nonce_field('facetfence_save_settings');
        echo '<input type="hidden" name="facetfence_action" value="' . esc_attr($action) . '">';
        submit_button($label, $class, 'submit', false);
        echo '</form>';
    }

    private function public_root_path(): string
    {
        if (!function_exists('get_home_path')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        if (function_exists('get_home_path')) {
            $home_path = get_home_path();
            if (is_string($home_path) && $home_path !== '') {
                return trailingslashit(wp_normalize_path($home_path));
            }
        }

        return trailingslashit(wp_normalize_path(ABSPATH));
    }

    private function htaccess_path(): string
    {
        return $this->public_root_path() . '.htaccess';
    }

    private function robots_path(): string
    {
        return $this->public_root_path() . 'robots.txt';
    }

    private function blocked_light_path(): string
    {
        return $this->public_root_path() . 'blocked-light.html';
    }

    private function uploads_base_url_path(): string
    {
        $uploads = wp_upload_dir();
        $baseurl = empty($uploads['baseurl']) ? content_url('uploads') : (string) $uploads['baseurl'];
        $path = (string) wp_parse_url($baseurl, PHP_URL_PATH);
        $path = '/' . trim($path, '/');
        return $path === '/' ? '/wp-content/uploads' : untrailingslashit($path);
    }

    private function filesystem()
    {
        if ($this->filesystem !== null) {
            return $this->filesystem;
        }
        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        if (!WP_Filesystem()) {
            return null;
        }
        global $wp_filesystem;
        $this->filesystem = $wp_filesystem;
        return $this->filesystem;
    }

    private function fs_chmod_file(): int
    {
        return defined('FS_CHMOD_FILE') ? (int) FS_CHMOD_FILE : 0644;
    }

    private function uploads_storage_root(): string
    {
        $uploads = wp_upload_dir();
        if (!empty($uploads['error']) || empty($uploads['basedir'])) {
            return '';
        }

        return trailingslashit((string) $uploads['basedir']) . 'facetfence-product-filters';
    }

    private function uploads_storage_dir(string $subdir): string
    {
        $root = $this->uploads_storage_root();
        if ($root === '') {
            return '';
        }

        return trailingslashit($root) . ltrim($subdir, '/');
    }

    private function backup_root(): string
    {
        return $this->uploads_storage_dir('backups');
    }

    private function runtime_dir(): string
    {
        return $this->uploads_storage_dir('runtime');
    }

    private function log_dir(): string
    {
        return $this->uploads_storage_dir('events');
    }

    private function ensure_dir(string $dir): bool
    {
        if ($dir === '') {
            return false;
        }

        if (!wp_mkdir_p($dir)) {
            return false;
        }

        $ok = true;
        $index = trailingslashit($dir) . 'index.php';
        if (!$this->local_file_exists($index)) {
            $ok = $this->write_local_text_file($index, "<?php\n// Silence is golden.\n") && $ok;
        }

        $deny = trailingslashit($dir) . '.htaccess';
        if (!$this->local_file_exists($deny)) {
            $deny_rules = "# FacetFence: deny direct web access to plugin-generated runtime files.\n" .
                "<IfModule mod_authz_core.c>\n" .
                "    Require all denied\n" .
                "</IfModule>\n" .
                "<IfModule !mod_authz_core.c>\n" .
                "    Deny from all\n" .
                "</IfModule>\n";
            $ok = $this->write_local_text_file($deny, $deny_rules) && $ok;
        }

        return $ok;
    }

    private function path_exists(string $path): bool
    {
        $fs = $this->filesystem();
        return $fs ? $fs->exists($path) : false;
    }

    private function path_is_file(string $path): bool
    {
        $fs = $this->filesystem();
        return $fs ? $fs->is_file($path) : false;
    }

    private function path_is_dir(string $path): bool
    {
        $fs = $this->filesystem();
        return $fs ? $fs->is_dir($path) : false;
    }

    private function directory_entries(string $dir, string $type = 'all'): array
    {
        $fs = $this->filesystem();
        if (!$fs || !$fs->is_dir($dir)) {
            return [];
        }

        $entries = $fs->dirlist($dir, false);
        if (!is_array($entries)) {
            return [];
        }

        $out = [];
        foreach ($entries as $name => $data) {
            $entry_type = is_array($data) ? (string) ($data['type'] ?? '') : '';
            if ($type === 'files' && $entry_type !== 'f') {
                continue;
            }
            if ($type === 'dirs' && $entry_type !== 'd') {
                continue;
            }
            $out[] = trailingslashit($dir) . $name;
        }

        return $out;
    }

    private function path_mtime(string $path): int
    {
        $fs = $this->filesystem();
        if (!$fs) {
            return 0;
        }

        $entries = $fs->dirlist(dirname($path), false);
        $name = basename($path);
        if (!is_array($entries) || !isset($entries[$name]) || !is_array($entries[$name])) {
            return 0;
        }

        return (int) ($entries[$name]['lastmodunix'] ?? 0);
    }

    private function backup_file(string $path, string $reason = 'file_change'): bool
    {
        $fs = $this->filesystem();
        if (!$fs || !$fs->exists($path) || !$fs->is_readable($path)) {
            return false;
        }
        $dir = trailingslashit($this->backup_root()) . gmdate('Ymd_His') . '_' . wp_generate_password(6, false, false);
        if (!$this->ensure_dir($dir)) {
            return false;
        }
        $name = basename($path) === '.htaccess' ? 'htaccess.bak' : basename($path) . '.bak';
        $ok = (bool) $fs->copy($path, trailingslashit($dir) . $name, true, $this->fs_chmod_file());
        $meta = [
            'created_at' => gmdate('c'),
            'reason' => $reason,
            'plugin_version' => self::VERSION,
            'site_url' => home_url('/'),
            'protection_mode' => $this->options()['protection_mode'],
            'source_path' => $path,
        ];
        $fs->put_contents(trailingslashit($dir) . 'meta.json', wp_json_encode($meta, JSON_PRETTY_PRINT), $this->fs_chmod_file());
        return $ok;
    }

    private function file_contains(string $path, string $needle): bool
    {
        $fs = $this->filesystem();
        if (!$fs || !$fs->exists($path) || !$fs->is_readable($path)) {
            return false;
        }
        $content = $fs->get_contents($path);
        return is_string($content) && strpos($content, $needle) !== false;
    }

    private function remove_managed_block(string $content, string $begin, string $end): string
    {
        $pattern = '/' . preg_quote($begin, '/') . '.*?' . preg_quote($end, '/') . "\s*/s";
        return (string) preg_replace($pattern, '', $content);
    }


    private function local_file_exists(string $path): bool
    {
        $fs = $this->filesystem();
        if ($fs && $fs->exists($path)) {
            return true;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_exists -- Required fallback for .htaccess diagnostics when WP_Filesystem cannot initialize on some hosts.
        return file_exists($path);
    }

    private function local_file_is_writable(string $path): bool
    {
        $fs = $this->filesystem();
        if ($fs && $fs->exists($path)) {
            return (bool) $fs->is_writable($path);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Required fallback for .htaccess writeability checks when WP_Filesystem is unavailable.
        return is_writable($path);
    }

    private function local_directory_is_writable(string $path): bool
    {
        $fs = $this->filesystem();
        if ($fs && $fs->exists($path)) {
            return (bool) $fs->is_writable($path);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_writable -- Required fallback for root directory writeability diagnostics when WP_Filesystem is unavailable.
        return is_writable($path);
    }

    private function ensure_local_file_for_write(string $path): bool
    {
        if ($this->local_file_exists($path)) {
            return $this->local_file_is_writable($path);
        }

        $fs = $this->filesystem();
        if ($fs && $fs->put_contents($path, '', $this->fs_chmod_file())) {
            return true;
        }

        if (!$this->local_directory_is_writable(dirname($path))) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Required fallback for creating root .htaccess in cPanel/Apache environments.
        if (file_put_contents($path, '') === false) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Keep created .htaccess at WordPress' configured file mode.
        @chmod($path, $this->fs_chmod_file());
        return true;
    }

    private function read_local_text_file(string $path): ?string
    {
        $fs = $this->filesystem();
        if ($fs && $fs->exists($path) && $fs->is_readable($path)) {
            $content = $fs->get_contents($path);
            return is_string($content) ? $content : null;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_is_readable -- Required fallback for .htaccess reads when WP_Filesystem cannot initialize.
        if (!is_readable($path)) {
            return null;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Required fallback for .htaccess reads when WP_Filesystem cannot initialize.
        $content = file_get_contents($path);
        return is_string($content) ? $content : null;
    }

    private function write_local_text_file(string $path, string $content): bool
    {
        $fs = $this->filesystem();
        if ($fs && $fs->put_contents($path, $content, $this->fs_chmod_file())) {
            return true;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_file_put_contents -- Required fallback for .htaccess writes in cPanel/Apache environments where WP_Filesystem cannot initialize.
        $bytes = file_put_contents($path, $content, LOCK_EX);
        if ($bytes === false) {
            return false;
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- Keep .htaccess at WordPress' configured file mode after fallback write.
        @chmod($path, $this->fs_chmod_file());
        return true;
    }


    private function hash_file_contents(string $path): string
    {
        $content = $this->read_local_text_file($path);
        return is_string($content) ? hash('sha256', $content) : '';
    }

    private function htaccess_diagnostics(): array
    {
        $path = $this->htaccess_path();
        $content = $this->read_local_text_file($path);
        $fs = $this->filesystem();
        $method = defined('FS_METHOD') ? (string) FS_METHOD : (is_object($fs) ? get_class($fs) : 'unavailable');
        return [
            'path' => $path,
            'exists' => $this->local_file_exists($path),
            'readable' => is_string($content),
            'writable' => $this->local_file_exists($path) ? $this->local_file_is_writable($path) : $this->local_directory_is_writable(dirname($path)),
            'has_managed_block' => is_string($content) && (strpos($content, self::HTACCESS_BEGIN) !== false || strpos($content, self::LEGACY_HTACCESS_BEGIN) !== false),
            'sha256' => is_string($content) ? hash('sha256', $content) : '',
            'filesystem_method' => $method,
        ];
    }

    private function record_htaccess_diagnostics(string $reason, string $operation, bool $success, string $error = '', string $hash_before = '', string $hash_after = ''): void
    {
        $diag = $this->htaccess_diagnostics();
        update_option(self::HTACCESS_DIAG_OPTION, [
            'created_at' => current_time('mysql'),
            'reason' => $reason,
            'operation' => $operation,
            'success' => $success ? 1 : 0,
            'error' => $error,
            'hash_before' => $hash_before,
            'hash_after' => $hash_after,
            'path' => $diag['path'],
            'exists' => $diag['exists'] ? 1 : 0,
            'readable' => $diag['readable'] ? 1 : 0,
            'writable' => $diag['writable'] ? 1 : 0,
            'has_managed_block' => $diag['has_managed_block'] ? 1 : 0,
            'filesystem_method' => $diag['filesystem_method'],
        ], false);
    }

    private function write_blocked_light_file(): bool
    {
        $fs = $this->filesystem();
        if (!$fs) {
            return false;
        }
        $path = $this->blocked_light_path();
        if ($fs->exists($path)) {
            $this->backup_file($path, 'blocked_light_rewrite');
        }
        $html = '<!doctype html><html><head><meta charset="utf-8"><meta name="robots" content="noindex,nofollow"><title>Temporarily blocked</title></head><body>Request temporarily blocked.</body></html>' . "\n";
        return (bool) $fs->put_contents($path, $html, $this->fs_chmod_file());
    }

    private function blocking_server_rules_available(array $opts): bool
    {
        return in_array((string) ($opts['protection_mode'] ?? 'off'), ['strict', 'emergency'], true);
    }

    private function htaccess_managed_rules_needed(array $opts): bool
    {
        if (empty($opts['manage_htaccess'])) {
            return false;
        }

        return $this->blocking_server_rules_available($opts) || !empty($opts['block_xmlrpc']);
    }

    private function robots_file_rules_available(array $opts): bool
    {
        return !in_array((string) ($opts['protection_mode'] ?? 'off'), ['off', 'monitor'], true);
    }

    private function seo_controls_available(array $opts): bool
    {
        return !in_array((string) ($opts['protection_mode'] ?? 'off'), ['off', 'monitor'], true);
    }

    private function home_path_prefix(): string
    {
        $path = (string) wp_parse_url(home_url('/'), PHP_URL_PATH);
        $path = '/' . trim($path, '/');
        return $path === '/' ? '' : $path;
    }

    private function site_relative_path(string $path): string
    {
        $path = '/' . ltrim($path, '/');
        $prefix = $this->home_path_prefix();
        if ($prefix !== '' && ($path === $prefix || strpos($path, $prefix . '/') === 0)) {
            $path = substr($path, strlen($prefix));
            $path = '/' . ltrim((string) $path, '/');
        }
        return $path === '' ? '/' : $path;
    }

    private function server_path_regex(array $opts): string
    {
        $fragment = trim((string) ($opts['protected_paths_regex'] ?? ''));
        $prefix = $this->home_path_prefix();
        if ($fragment !== '' && $prefix !== '' && strpos($fragment, '^/') === 0) {
            return '^' . preg_quote($prefix, '/') . substr($fragment, 1);
        }
        return $fragment;
    }

    private function blocked_light_url_path(): string
    {
        $prefix = $this->home_path_prefix();
        return ($prefix === '' ? '' : $prefix) . '/blocked-light.html';
    }

    private function internal_referer_regex(): string
    {
        $host = (string) wp_parse_url(home_url('/'), PHP_URL_HOST);
        $host = $host !== '' ? preg_quote(preg_replace('/^www\./i', '', $host), '/') : '';
        $path = (string) wp_parse_url(home_url('/'), PHP_URL_PATH);
        $path = $path === '' ? '/' : $path;
        return '^https?://(www\.)?' . $host . preg_quote($path, '/');
    }

    private function cloudflare_path_expression(): string
    {
        $prefix = $this->home_path_prefix();
        $base = $prefix === '' ? '' : $prefix;
        return '(starts_with(http.request.uri.path, "' . $this->cloudflare_escape($base . '/product-category/') . '") or starts_with(http.request.uri.path, "' . $this->cloudflare_escape($base . '/shop/') . '"))';
    }

    private function cloudflare_escape(string $value): string
    {
        return str_replace(['\\', '"'], ['\\\\', '\"'], $value);
    }

    private function cloudflare_referer_expression(): string
    {
        $host = strtolower((string) wp_parse_url(home_url('/'), PHP_URL_HOST));
        $host = $host !== '' ? preg_replace('/^www\./i', '', $host) : 'example.com';
        $prefix = strtolower($this->home_path_prefix());
        $path = $prefix === '' ? '/' : trailingslashit($prefix);

        $plain_https = 'https://' . $host . $path;
        $plain_http = 'http://' . $host . $path;
        $www_https = 'https://www.' . $host . $path;
        $www_http = 'http://www.' . $host . $path;

        return '(starts_with(lower(http.referer), "' . $this->cloudflare_escape($plain_https) . '") or starts_with(lower(http.referer), "' . $this->cloudflare_escape($plain_http) . '") or starts_with(lower(http.referer), "' . $this->cloudflare_escape($www_https) . '") or starts_with(lower(http.referer), "' . $this->cloudflare_escape($www_http) . '"))';
    }

    private function safe_mode_server_rules_message(array $opts): string
    {
        return '# No pre-PHP filtered-URL blocking rule is generated for mode: ' . (string) ($opts['protection_mode'] ?? 'off') . "\n" .
            '# Cookie and Cookie + Referer modes are enforced in WordPress/PHP to avoid false blocking real shoppers.' . "\n" .
            '# Server-level filtered-URL blocking is generated only for Strict and Emergency modes.' . "\n";
    }

    public function write_htaccess_guard(string $reason = 'htaccess_write'): bool
    {
        $opts = $this->options();
        if (!$this->htaccess_managed_rules_needed($opts)) {
            return $this->remove_htaccess_guard($reason . '_safe_mode');
        }
        $errors = $this->blocking_server_rules_available($opts) ? $this->validate_options($opts) : [];
        if ($errors) {
            $this->record_htaccess_diagnostics($reason, 'write', false, 'Validation failed: ' . implode(' ', $errors));
            return false;
        }
        $path = $this->htaccess_path();
        $hash_before = $this->hash_file_contents($path);
        if (!$this->ensure_local_file_for_write($path)) {
            $this->record_htaccess_diagnostics($reason, 'write', false, 'File is not writable or could not be created.', $hash_before, $this->hash_file_contents($path));
            return false;
        }
        $this->backup_file($path, $reason);
        $content = $this->read_local_text_file($path);
        if ($content === null) {
            $this->record_htaccess_diagnostics($reason, 'write', false, 'File could not be read before writing.', $hash_before, $this->hash_file_contents($path));
            return false;
        }
        $content = $this->remove_managed_block($content, self::HTACCESS_BEGIN, self::HTACCESS_END);
        $content = $this->remove_managed_block($content, self::LEGACY_HTACCESS_BEGIN, self::LEGACY_HTACCESS_END);
        $block = $this->htaccess_block($opts);
        $ok = $this->write_local_text_file($path, $block . "
" . ltrim($content));
        $hash_after = $this->hash_file_contents($path);
        $this->record_htaccess_diagnostics($reason, 'write', $ok, $ok ? '' : 'Write failed through WP_Filesystem and local fallback.', $hash_before, $hash_after);
        if ($ok) {
            $this->log_event('htaccess_rule_regenerated', ['action_taken' => $reason, 'response_status' => 200]);
        }
        return $ok;
    }

    public function remove_htaccess_guard(string $reason = 'htaccess_remove'): bool
    {
        $path = $this->htaccess_path();
        $hash_before = $this->hash_file_contents($path);
        if (!$this->local_file_exists($path)) {
            $this->record_htaccess_diagnostics($reason, 'remove', true, 'File does not exist.', $hash_before, '');
            return true;
        }
        if (!$this->local_file_is_writable($path)) {
            $this->record_htaccess_diagnostics($reason, 'remove', false, 'File exists but is not writable.', $hash_before, $this->hash_file_contents($path));
            return false;
        }
        $this->backup_file($path, $reason);
        $content = $this->read_local_text_file($path);
        if ($content === null) {
            $this->record_htaccess_diagnostics($reason, 'remove', false, 'File could not be read before removing managed block.', $hash_before, $this->hash_file_contents($path));
            return false;
        }
        $clean = $this->remove_managed_block($content, self::HTACCESS_BEGIN, self::HTACCESS_END);
        $clean = $this->remove_managed_block($clean, self::LEGACY_HTACCESS_BEGIN, self::LEGACY_HTACCESS_END);
        if ($clean === $content) {
            $this->record_htaccess_diagnostics($reason, 'remove', true, 'No managed block was present.', $hash_before, $hash_before);
            return true;
        }
        $ok = $this->write_local_text_file($path, ltrim($clean));
        $hash_after = $this->hash_file_contents($path);
        $this->record_htaccess_diagnostics($reason, 'remove', $ok, $ok ? '' : 'Remove write failed through WP_Filesystem and local fallback.', $hash_before, $hash_after);
        if ($ok) {
            $this->log_event('htaccess_rule_removed', ['action_taken' => $reason, 'response_status' => 200]);
        }
        return $ok;
    }

    private function htaccess_block(array $opts): string
    {
        if ($opts['protection_mode'] === 'emergency') {
            return $this->emergency_htaccess_block($opts);
        }
        $path_regex = $this->server_path_regex($opts);
        $query_regex = trim((string) $opts['query_keys_regex']);
        $block_response = $opts['block_response'] === '404' ? 'R=404,L' : 'F,L';
        $lines = [];
        $lines[] = self::HTACCESS_BEGIN;
        if ($this->blocking_server_rules_available($opts)) {
            $lines[] = 'ErrorDocument 403 ' . $this->blocked_light_url_path();
            $lines[] = 'ErrorDocument 404 ' . $this->blocked_light_url_path();
            $lines[] = '';
        }
        $lines[] = '<IfModule mod_rewrite.c>';
        $lines[] = 'RewriteEngine On';
        $lines[] = '';
        if ($this->blocking_server_rules_available($opts)) {
            $lines[] = '# Block expensive WooCommerce layered-filter crawl/flood before PHP.';
            $lines[] = '# WordPress/PHP cannot log requests stopped by this pre-PHP server block.';
            $lines[] = '# WordPress role allowlists cannot bypass this pre-PHP server block.';
            $lines[] = '# Strict/Emergency modes intentionally do not trust cookies at the Apache layer.';
            $lines[] = 'RewriteCond %{REQUEST_URI} ' . $path_regex . ' [NC]';
            $lines[] = 'RewriteCond %{QUERY_STRING} (^|&)(' . $query_regex . ')= [NC]';
            $lines[] = 'RewriteRule ^ - [' . $block_response . ']';
        } else {
            $lines[] = '# Cookie-based filtered URL blocking is intentionally handled by WordPress/PHP.';
            $lines[] = '# This managed block contains only independent non-filter rules enabled below.';
        }
        if (!empty($opts['block_xmlrpc'])) {
            $lines[] = '';
            $lines[] = '# Optional XML-RPC abuse block.';
            $lines[] = 'RewriteRule ^xmlrpc\.php$ - [F,L]';
        }
        $lines[] = '</IfModule>';
        if (!empty($opts['block_xmlrpc'])) {
            $lines[] = '';
            $lines[] = '<Files "xmlrpc.php">';
            $lines[] = '    Require all denied';
            $lines[] = '</Files>';
        }
        $lines[] = self::HTACCESS_END;
        return implode("
", $lines) . "
";
    }

    private function emergency_htaccess_block(array $opts): string
    {
        $blocked = preg_quote($this->blocked_light_url_path(), '/');
        $prefix = $this->home_path_prefix();
        $base = $prefix === '' ? '' : preg_quote($prefix, '/');
        $query_regex = trim((string) ($opts['query_keys_regex'] ?? ''));
        if ($query_regex === '') {
            $query_regex = self::defaults()['query_keys_regex'];
        }
        return self::HTACCESS_BEGIN . "
" .
            'ErrorDocument 503 ' . $this->blocked_light_url_path() . "

" .
            "<IfModule mod_rewrite.c>
" .
            "RewriteEngine On
" .
            "RewriteCond %{REQUEST_URI} !^" . $blocked . "$ [NC]
" .
            "RewriteCond %{REQUEST_URI} !^" . $base . "/wp-admin/ [NC]
" .
            "RewriteCond %{REQUEST_URI} !^" . $base . "/wp-login\.php$ [NC]
" .
            "RewriteCond %{REQUEST_URI} !^" . $base . "/cart/ [NC]
" .
            "RewriteCond %{REQUEST_URI} !^" . $base . "/checkout/ [NC]
" .
            "RewriteCond %{REQUEST_URI} !^" . $base . "/my-account/ [NC]
" .
            "RewriteCond %{REQUEST_URI} !\.(css|js|png|jpg|jpeg|gif|webp|svg|ico|woff|woff2|ttf|eot)$ [NC]
" .
            "RewriteCond %{QUERY_STRING} (^|&)(" . $query_regex . ")= [NC]
" .
            "RewriteRule ^ - [R=503,L]
" .
            "</IfModule>
" .
            (!empty($opts['block_xmlrpc']) ? "
<Files \"xmlrpc.php\">
    Require all denied
</Files>
" : '') .
            self::HTACCESS_END . "
";
    }

    private function nginx_rules(array $opts): string
    {
        if (!$this->blocking_server_rules_available($opts)) {
            return $this->safe_mode_server_rules_message($opts);
        }
        $cookie = $this->server_cookie_regex($opts);
        $uploads_path = $this->uploads_base_url_path();
        $host = (string) wp_parse_url(home_url('/'), PHP_URL_HOST);
        $host_no_www = preg_replace('/^www\\./i', '', $host ?: 'example.com');
        $home_path = (string) wp_parse_url(home_url('/'), PHP_URL_PATH);
        $referer = '^https?://(www\\.)?' . preg_quote($host_no_www, '/') . preg_quote($home_path ?: '/', '/');
        $path_regex = $this->server_path_regex($opts);
        $query_regex = trim((string) ($opts['query_keys_regex'] ?? 'filter_[^=]+|query_type_[^=]+'));
        $status = $opts['protection_mode'] === 'emergency' ? '503' : '403';
        $lines = [];
        $lines[] = 'map $http_cookie $facetfence_has_cookie {';
        $lines[] = '    default 0;';
        $lines[] = '    ~*(^|;\\s*)(' . $cookie . ')= 1;';
        $lines[] = '}';
        $lines[] = '';
        $lines[] = 'map $http_referer $facetfence_has_internal_referer {';
        $lines[] = '    default 0;';
        $lines[] = '    ~*' . $referer . ' 1;';
        $lines[] = '}';
        $lines[] = '';
        $lines[] = '# Review this snippet with your server administrator before applying it.';
        $lines[] = '# Place the following location block in the matching server context.';
        $lines[] = '# Optional but recommended internal-data deny rules:';
        $lines[] = 'location ^~ ' . $uploads_path . '/facetfence-product-filters/ { deny all; }';
        $lines[] = 'location ^~ ' . $uploads_path . '/cache/facetfence-product-filters/ { deny all; }';
        $lines[] = '';
        $lines[] = 'location ~* ' . $path_regex . ' {';
        $lines[] = '    set $facetfence_filtered 0;';
        $lines[] = '    if ($args ~* "(^|&)(' . $query_regex . ')=") { set $facetfence_filtered 1; }';
        if ($opts['protection_mode'] === 'cookie') {
            $lines[] = '    if ($facetfence_filtered$facetfence_has_cookie = 10) { return ' . $status . '; }';
        } elseif ($opts['protection_mode'] === 'cookie_referer') {
            $lines[] = '    if ($facetfence_filtered$facetfence_has_cookie = 10) { return ' . $status . '; }';
            $lines[] = '    if ($facetfence_filtered$facetfence_has_internal_referer = 10) { return ' . $status . '; }';
        } elseif (in_array($opts['protection_mode'], ['strict', 'emergency'], true)) {
            $lines[] = '    if ($facetfence_filtered = 1) { return ' . $status . '; }';
        }
        $lines[] = '    try_files $uri $uri/ /index.php?$args;';
        $lines[] = '}';
        return implode("\n", $lines) . "\n";
    }

    private function cloudflare_expression(array $opts, bool $use_regex_cookie = true): string
    {
        if (!$this->blocking_server_rules_available($opts)) {
            return trim($this->safe_mode_server_rules_message($opts));
        }
        $cookie_expr = $this->cloudflare_cookie_presence_expression($opts, $use_regex_cookie);
        $path_expr = $this->cloudflare_path_expression();
        $query_expr = $this->cloudflare_query_expression($opts);
        $filtered = '(' . $path_expr . ' and ' . $query_expr . ')';
        if ($opts['protection_mode'] === 'cookie') {
            return $filtered . ' and not ' . $cookie_expr;
        }
        if ($opts['protection_mode'] === 'cookie_referer') {
            return $filtered . ' and (not ' . $cookie_expr . ' or not ' . $this->cloudflare_referer_expression() . ')';
        }
        return $filtered;
    }

    private function cloudflare_query_expression(array $opts): string
    {
        $patterns = $this->query_key_rule_patterns($opts);
        $parts = [];

        foreach ($patterns['exact'] as $key) {
            $key = strtolower($key);
            $parts[] = 'any(lower(http.request.uri.args.names[*]) == "' . $this->cloudflare_escape($key) . '")';
        }
        foreach ($patterns['prefix'] as $prefix) {
            $prefix = strtolower($prefix);
            $parts[] = 'any(starts_with(lower(http.request.uri.args.names[*]), "' . $this->cloudflare_escape($prefix) . '"))';
        }

        if (!$parts) {
            $parts[] = 'any(starts_with(lower(http.request.uri.args.names[*]), "filter_"))';
            $parts[] = 'any(starts_with(lower(http.request.uri.args.names[*]), "query_type_"))';
        }

        return '(' . implode(' or ', array_values(array_unique($parts))) . ')';
    }

    private function query_key_rule_patterns(array $opts): array
    {
        $regex = trim((string) ($opts['query_keys_regex'] ?? ''));
        $tokens = $regex !== '' ? preg_split('/\|/', $regex) : [];
        $exact = [];
        $prefix = [];

        if (is_array($tokens)) {
            foreach ($tokens as $token) {
                $token = trim((string) $token);
                if ($token === '') {
                    continue;
                }
                if (preg_match('/^([a-zA-Z0-9_\-]+)_\[\^=\]\+$/', $token, $matches)) {
                    $prefix[] = $matches[1] . '_';
                    continue;
                }
                if (preg_match('/^([a-zA-Z0-9_\-]+)\[\^=\]\+$/', $token, $matches)) {
                    $prefix[] = $matches[1];
                    continue;
                }
                if (preg_match('/^[a-zA-Z0-9_\-]+$/', $token)) {
                    $exact[] = $token;
                }
            }
        }

        return [
            'exact' => array_values(array_unique($exact)),
            'prefix' => array_values(array_unique($prefix)),
        ];
    }

    public function write_robots_txt_rules(string $reason = 'robots_write'): bool
    {
        if (!$this->robots_file_rules_available($this->options())) {
            return $this->remove_robots_txt_rules($reason . '_safe_mode');
        }
        $fs = $this->filesystem();
        if (!$fs) {
            return false;
        }
        $path = $this->robots_path();
        if (!$fs->exists($path) && !$fs->put_contents($path, '', $this->fs_chmod_file())) {
            return false;
        }
        if (!$fs->is_writable($path)) {
            return false;
        }
        $this->backup_file($path, $reason);
        $content = (string) $fs->get_contents($path);
        $content = $this->remove_managed_block($content, self::ROBOTS_BEGIN, self::ROBOTS_END);
        $content = $this->remove_managed_block($content, self::LEGACY_ROBOTS_BEGIN, self::LEGACY_ROBOTS_END);
        $ok = (bool) $fs->put_contents($path, rtrim($content) . "\n\n" . $this->robots_block() . "\n", $this->fs_chmod_file());
        if ($ok) {
            $this->log_event('robots_rule_regenerated', ['action_taken' => $reason, 'response_status' => 200]);
        }
        return $ok;
    }

    public function remove_robots_txt_rules(string $reason = 'robots_remove'): bool
    {
        $fs = $this->filesystem();
        if (!$fs) {
            return false;
        }
        $path = $this->robots_path();
        if (!$fs->exists($path)) {
            return true;
        }
        if (!$fs->is_writable($path)) {
            return false;
        }
        $this->backup_file($path, $reason);
        $content = (string) $fs->get_contents($path);
        $content = $this->remove_managed_block($content, self::ROBOTS_BEGIN, self::ROBOTS_END);
        $content = $this->remove_managed_block($content, self::LEGACY_ROBOTS_BEGIN, self::LEGACY_ROBOTS_END);
        return (bool) $fs->put_contents($path, rtrim($content) . "\n", $this->fs_chmod_file());
    }

    private function run_self_tests(): void
    {
        $opts = $this->options();
        $test_path = $this->health_check_test_path($opts);
        $configured_path = $this->sanitize_health_check_test_path((string) ($opts['health_check_test_path'] ?? ''));
        $auto_detected = $configured_path === '' && $test_path !== '';
        $has_test_path = $test_path !== '';
        $expected = $this->self_test_expected_statuses($opts);
        $items = [];
        $items[] = $this->test_head(__('Homepage', 'facetfence-product-filters'), home_url('/'), [], [200]);
        $items[] = [
            'label' => __('Policy test URL available', 'facetfence-product-filters'),
            'url' => $has_test_path ? home_url($test_path) : '',
            'status' => $has_test_path ? ($auto_detected ? 'auto-detected' : 'configured') : 'missing',
            'x_robots' => '',
            'ok' => $has_test_path,
            'note' => $has_test_path ? ($auto_detected ? __('Auto-detected a WooCommerce shop/category path. Saving an explicit path is still recommended.', 'facetfence-product-filters') : '') : __('Set a real WooCommerce category/shop path to avoid false PASS results from 404 pages.', 'facetfence-product-filters'),
        ];

        if ($has_test_path) {
            $url = add_query_arg(['filter_poe' => 'donthave', 'query_type_poe' => 'or'], home_url($test_path));
            $cookie_name = $this->current_cookie_name($opts);
            $cookie_value = $this->make_human_cookie_value($opts);
            $referer = home_url($test_path);
            $health_token = $this->create_health_check_token();
            $cookie_headers = ['Cookie' => $cookie_name . '=' . $cookie_value];
            $cookie_referer_headers = ['Cookie' => $cookie_name . '=' . $cookie_value, 'Referer' => $referer];
            $bypass_headers = ['Referer' => $referer, 'X-Filter-Guard-Health-Check' => $health_token];

            $items[] = $this->test_head(__('Configured clean test URL', 'facetfence-product-filters'), home_url($test_path), [], [200]);
            $items[] = $this->test_head(__('No cookie / no referer', 'facetfence-product-filters'), $url, [], $expected['no_cookie']);
            $items[] = $this->test_head(__('Cookie only', 'facetfence-product-filters'), $url, ['headers' => $cookie_headers], $expected['cookie_only']);
            $items[] = $this->test_head(__('Cookie + internal referer', 'facetfence-product-filters'), $url, ['headers' => $cookie_referer_headers], $expected['cookie_referer']);
            $items[] = $this->test_head(__('Health-check bypass token', 'facetfence-product-filters'), $url, ['headers' => $bypass_headers], $expected['cookie_referer']);
        }

        $xmlrpc_expected = !empty($opts['block_xmlrpc']) && !in_array($opts['protection_mode'], ['off', 'monitor'], true) ? [403, 404, 405] : [200, 301, 302, 403, 404, 405];
        $items[] = $this->test_head(__('XML-RPC', 'facetfence-product-filters'), home_url('/xmlrpc.php'), [], $xmlrpc_expected);
        $items[] = $this->test_head(__('robots.txt', 'facetfence-product-filters'), home_url('/robots.txt'), [], [200]);
        update_option(self::TEST_OPTION, ['time' => current_time('mysql'), 'mode' => $opts['protection_mode'], 'test_path' => $test_path, 'items' => $items], false);
    }

    private function create_health_check_token(): string
    {
        $token = wp_generate_password(32, false, false);
        set_transient(self::HEALTH_CHECK_TOKEN_TRANSIENT, $token, 5 * MINUTE_IN_SECONDS);
        return $token;
    }

    private function request_has_valid_health_check_token(): bool
    {
        $token = $this->server_value('HTTP_X_FACETFENCE_HEALTH_CHECK');
        if ($token === '') {
            return false;
        }
        $stored = get_transient(self::HEALTH_CHECK_TOKEN_TRANSIENT);
        if (!is_string($stored) || $stored === '') {
            return false;
        }
        return hash_equals($stored, $token);
    }

    private function self_test_expected_statuses(array $opts): array
    {
        $allow = [200];
        $deny = [403, 429];
        if ((string) ($opts['block_response'] ?? '403') === '404') {
            $deny[] = 404;
        }
        $emergency = [503];
        switch ((string) $opts['protection_mode']) {
            case 'cookie':
                return ['no_cookie' => $deny, 'cookie_only' => $allow, 'cookie_referer' => $allow];
            case 'cookie_referer':
                return ['no_cookie' => $deny, 'cookie_only' => $deny, 'cookie_referer' => $allow];
            case 'strict':
                return ['no_cookie' => $deny, 'cookie_only' => $deny, 'cookie_referer' => $deny];
            case 'emergency':
                return ['no_cookie' => $emergency, 'cookie_only' => $emergency, 'cookie_referer' => $emergency];
            case 'off':
            case 'seo_only':
            case 'monitor':
            default:
                return ['no_cookie' => $allow, 'cookie_only' => $allow, 'cookie_referer' => $allow];
        }
    }

    private function test_head(string $label, string $url, array $args, array $expected): array
    {
        $args = array_merge(['timeout' => 12, 'redirection' => 3], $args);
        $response = wp_safe_remote_get($url, $args);
        if (is_wp_error($response)) {
            return ['label' => $label, 'url' => $url, 'status' => 'error', 'x_robots' => '', 'ok' => false, 'error' => $response->get_error_message()];
        }
        $status = (int) wp_remote_retrieve_response_code($response);
        $x = (string) wp_remote_retrieve_header($response, 'x-robots-tag');
        $ok = in_array($status, $expected, true);
        return ['label' => $label, 'url' => $url, 'status' => $status, 'x_robots' => $x, 'ok' => $ok];
    }

    private function tests_are_ok($tests): bool
    {
        if (!is_array($tests) || empty($tests['items']) || !is_array($tests['items'])) {
            return false;
        }
        foreach ($tests['items'] as $item) {
            if (empty($item['ok'])) {
                return false;
            }
        }
        return true;
    }

    private function sanitize_health_check_test_path(string $path): string
    {
        $path = trim($path);
        if ($path === '') {
            return '';
        }
        $parts = wp_parse_url($path);
        if (is_array($parts) && !empty($parts['path'])) {
            $path = (string) $parts['path'];
        }
        $path = '/' . ltrim($path, '/');
        $path = strtok($path, '?');
        $path = sanitize_text_field((string) $path);
        return $path === '/' ? '' : trailingslashit($path);
    }

    private function health_check_test_path(array $opts): string
    {
        $path = $this->sanitize_health_check_test_path((string) ($opts['health_check_test_path'] ?? ''));
        if ($path !== '') {
            return $path;
        }
        return $this->auto_detect_health_check_test_path();
    }

    private function auto_detect_health_check_test_path(): string
    {
        if (function_exists('wc_get_page_permalink')) {
            $shop_url = (string) wc_get_page_permalink('shop');
            $shop_path = $this->sanitize_health_check_test_path($shop_url);
            if ($shop_path !== '') {
                return $shop_path;
            }
        }

        if (function_exists('get_terms') && function_exists('get_term_link')) {
            $terms = get_terms([
                'taxonomy' => 'product_cat',
                'hide_empty' => true,
                'number' => 1,
            ]);
            if (is_array($terms) && !empty($terms)) {
                $link = get_term_link($terms[0]);
                if (!is_wp_error($link)) {
                    $term_path = $this->sanitize_health_check_test_path((string) $link);
                    if ($term_path !== '') {
                        return $term_path;
                    }
                }
            }
        }

        return '';
    }

    private function validate_options(array $opts): array
    {
        $errors = [];
        foreach (['protected_paths_regex' => __('Protected path regex is invalid.', 'facetfence-product-filters'), 'query_keys_regex' => __('Query key regex is invalid.', 'facetfence-product-filters')] as $key => $message) {
            $value = trim((string) ($opts[$key] ?? ''));
            if ($value === '' || !$this->regex_is_valid($value)) {
                $errors[] = $message;
            }
        }
        $legacy_cookie_regex = trim((string) ($opts['allowed_cookie_regex'] ?? ''));
        if ($legacy_cookie_regex !== '' && !$this->regex_is_valid($legacy_cookie_regex)) {
            $errors[] = __('Compatible cookie-name regex is invalid.', 'facetfence-product-filters');
        }
        $ua_regex = trim((string) ($opts['allow_user_agent_regex'] ?? ''));
        if ($ua_regex !== '' && !$this->regex_is_valid($ua_regex)) {
            $errors[] = __('Allow User-Agent regex is invalid.', 'facetfence-product-filters');
        }
        if (!empty($opts['manage_htaccess']) && in_array($opts['protection_mode'], ['strict', 'emergency'], true)) {
            foreach (['protected_paths_regex', 'query_keys_regex'] as $key) {
                if (!$this->apache_regex_fragment_is_safe((string) ($opts[$key] ?? ''))) {
                    /* translators: %s: settings field key. */
                    $errors[] = sprintf(__('%s contains characters that are unsafe for single-line Apache RewriteCond rules.', 'facetfence-product-filters'), $key);
                }
            }
        }
        return $errors;
    }

    private function sanitize_cookie_name($name): string
    {
        $name = sanitize_key((string) $name);
        return preg_replace('/[^a-zA-Z0-9_\-]/', '', $name) ?: self::defaults()['cookie_name'];
    }

    private function sanitize_regex_fragment($value): string
    {
        $value = trim((string) $value);
        return str_replace(["\r", "\n"], '', $value);
    }

    private function sanitize_multiline($value): string
    {
        $value = (string) $value;
        $lines = preg_split('/[\r\n]+/', $value);
        $out = [];
        foreach ((array) $lines as $line) {
            $line = trim($line);
            if ($line !== '') {
                $out[] = sanitize_text_field($line);
            }
        }
        return implode("\n", $out);
    }

    private function sanitize_roles($value): string
    {
        $value = (string) $value;
        $parts = array_filter(array_map('sanitize_key', array_map('trim', explode(',', $value))));
        return implode(',', $parts);
    }

    private function build_regex(string $fragment, string $modifiers = ''): string
    {
        foreach (['~', '#', '%', '!', '@'] as $delimiter) {
            if (strpos($fragment, $delimiter) === false) {
                return $delimiter . $fragment . $delimiter . $modifiers;
            }
        }
        return '';
    }

    private function regex_is_valid(string $fragment): bool
    {
        return $this->regex_match($fragment, 'facetfence-product-filters-test', '') !== false;
    }

    private function regex_match(string $fragment, string $subject, string $modifiers = '')
    {
        $regex = $this->build_regex($fragment, $modifiers);
        if ($regex === '') {
            return false;
        }
        $result = preg_match($regex, $subject);
        return $result === false ? false : $result;
    }

    private function regex_match_all(string $fragment, string $subject, array &$matches, string $modifiers = '')
    {
        $regex = $this->build_regex($fragment, $modifiers);
        if ($regex === '') {
            return false;
        }
        $result = preg_match_all($regex, $subject, $matches);
        return $result === false ? false : $result;
    }

    private function apache_regex_fragment_is_safe(string $fragment): bool
    {
        $fragment = trim($fragment);
        if ($fragment === '') {
            return false;
        }
        if (preg_match('/[\r\n\t\x00<>"\']/', $fragment)) {
            return false;
        }
        if (preg_match('/\s/', $fragment)) {
            return false;
        }
        return true;
    }

    private function current_cookie_name(array $opts): string
    {
        $base = $this->sanitize_cookie_name($opts['cookie_name']);
        if (empty($opts['rotate_cookie_name'])) {
            return $base;
        }
        $suffix = substr(hash_hmac('sha256', gmdate('Ymd') . '|' . $this->cookie_secret_version(), wp_salt('auth')), 0, 8);
        return $base . '_' . $suffix;
    }

    private function cookie_secret_version(): string
    {
        $version = get_option('facetfence_cookie_secret_version', 'v1');
        return is_scalar($version) ? (string) $version : 'v1';
    }

    private function make_human_cookie_value(array $opts): string
    {
        if (empty($opts['signed_cookie'])) {
            return '1';
        }
        $timestamp = (string) time();
        $random = wp_generate_password(12, false, false);
        $payload = $timestamp . '.' . $random;
        $signature = $this->cookie_signature($payload, $opts);
        return $payload . '.' . $signature;
    }

    private function validate_human_cookie(string $value, array $opts): bool
    {
        if (empty($opts['signed_cookie'])) {
            return $value !== '';
        }
        $parts = explode('.', $value);
        if (count($parts) !== 3) {
            return false;
        }
        [$timestamp, $random, $signature] = $parts;
        if (!ctype_digit($timestamp) || $random === '' || $signature === '') {
            return false;
        }
        $ttl = max(300, min(86400, (int) $opts['cookie_ttl']));
        if ((int) $timestamp < time() - $ttl || (int) $timestamp > time() + 300) {
            return false;
        }
        $expected = $this->cookie_signature($timestamp . '.' . $random, $opts);
        return hash_equals($expected, $signature);
    }

    private function cookie_signature(string $payload, array $opts): string
    {
        $binding = '';
        if (!empty($opts['bind_cookie_ua'])) {
            $binding .= '|ua:' . $this->hash_value($this->server_value('HTTP_USER_AGENT'));
        }
        if (!empty($opts['bind_cookie_ip_prefix'])) {
            $binding .= '|ip:' . $this->ip_prefix($this->remote_ip());
        }
        return hash_hmac('sha256', $payload . $binding . '|' . $this->cookie_secret_version(), wp_salt('auth'));
    }

    private function request_has_valid_human_cookie(array $opts): bool
    {
        if ($this->request_has_valid_health_check_token()) {
            return true;
        }

        foreach ($this->candidate_human_cookie_names($opts) as $name) {
            $cookie_value = $this->cookie_value($name);
            if ($cookie_value !== '' && $this->validate_human_cookie($cookie_value, $opts)) {
                return true;
            }
        }
        return false;
    }

    private function candidate_human_cookie_names(array $opts): array
    {
        $names = [];
        $current = $this->current_cookie_name($opts);
        if ($current !== '') {
            $names[] = $current;
        }
        $legacy = $this->sanitize_cookie_name($opts['cookie_name'] ?? self::defaults()['cookie_name']);
        if ($legacy !== '') {
            $names[] = $legacy;
        }

        $regex = trim((string) ($opts['allowed_cookie_regex'] ?? ''));
        if ($regex !== '') {
            foreach (array_keys($_COOKIE) as $cookie_name) {
                $cookie_name = is_scalar($cookie_name) ? (string) $cookie_name : '';
                if ($cookie_name !== '' && $this->regex_match($regex, $cookie_name, 'i') === 1) {
                    $names[] = $cookie_name;
                }
            }
        }

        return array_values(array_unique(array_filter($names)));
    }

    private function server_cookie_base_name(array $opts): string
    {
        return $this->sanitize_cookie_name($opts['cookie_name'] ?? self::defaults()['cookie_name']);
    }

    private function server_cookie_regex(array $opts): string
    {
        $base = $this->server_cookie_base_name($opts);
        if ($base === '') {
            return 'a^';
        }
        // Server/CDN rules must remain stable when daily cookie-name rotation is enabled.
        // PHP still validates the HMAC signature and expiry; the server layer only checks a plugin-owned cookie-name pattern.
        return preg_quote($base, '/') . '(_[a-f0-9]{8})?';
    }

    private function cloudflare_cookie_presence_expression(array $opts, bool $use_regex_cookie = true): string
    {
        $base = $this->server_cookie_base_name($opts);
        if ($base === '') {
            return 'false';
        }

        if ($use_regex_cookie) {
            $regex = '(^|;\s*)' . preg_quote($base, '/') . '(_[a-f0-9]{8})?=';
            return 'http.cookie matches r"' . $this->cloudflare_escape_raw_regex($regex) . '"';
        }

        $base_cookie = $this->cloudflare_escape($base . '=');
        $base_cookie_spaced = $this->cloudflare_escape('; ' . $base . '=');
        $base_cookie_compact = $this->cloudflare_escape(';' . $base . '=');
        $rotated_prefix = $this->cloudflare_escape($base . '_');
        $rotated_prefix_spaced = $this->cloudflare_escape('; ' . $base . '_');
        $rotated_prefix_compact = $this->cloudflare_escape(';' . $base . '_');

        return '(starts_with(http.cookie, "' . $base_cookie . '") or http.cookie contains "' . $base_cookie_spaced . '" or http.cookie contains "' . $base_cookie_compact . '" or starts_with(http.cookie, "' . $rotated_prefix . '") or http.cookie contains "' . $rotated_prefix_spaced . '" or http.cookie contains "' . $rotated_prefix_compact . '")';
    }

    private function cloudflare_escape_raw_regex(string $value): string
    {
        return str_replace('"', '\"', $value);
    }

    private function has_internal_referer(): bool
    {
        $referer = $this->server_value('HTTP_REFERER');
        if ($referer === '') {
            return false;
        }
        $referer_host = wp_parse_url($referer, PHP_URL_HOST);
        $site_host = wp_parse_url(home_url('/'), PHP_URL_HOST);
        if (!$referer_host || !$site_host || strtolower((string) $referer_host) !== strtolower((string) $site_host)) {
            return false;
        }

        $prefix = $this->home_path_prefix();
        if ($prefix === '') {
            return true;
        }

        $referer_path = (string) wp_parse_url($referer, PHP_URL_PATH);
        return $referer_path === $prefix || strpos($referer_path, $prefix . '/') === 0;
    }

    private function clean_current_archive_url(): string
    {
        if (function_exists('is_product_category') && is_product_category()) {
            $term = get_queried_object();
            if ($term && !is_wp_error($term)) {
                $link = get_term_link($term);
                return is_wp_error($link) ? '' : (string) $link;
            }
        }
        if (function_exists('is_shop') && is_shop() && function_exists('wc_get_page_permalink')) {
            return (string) wc_get_page_permalink('shop');
        }
        $path = (string) wp_parse_url($this->server_value('REQUEST_URI'), PHP_URL_PATH);
        return home_url($path ?: '/');
    }

    private function redirect_to_clean_url(string $rule, array $context): void
    {
        $url = $this->clean_current_archive_url();
        if (!$url) {
            $this->block_request(403, 'blocked_filter_request', $rule, $context);
        }
        $this->log_event('blocked_filter_request', ['action_taken' => 'redirect_clean', 'response_status' => 302, 'matched_rule' => $rule] + $context);
        wp_safe_redirect($url, 302);
        exit;
    }

    private function block_request(int $status, string $event_type, string $rule, array $context): void
    {
        if (in_array($event_type, ['blocked_filter_request', 'fake_search_bot_blocked'], true)) {
            $this->increment_attack_window_counter($context);
        }
        $this->log_event($event_type, ['action_taken' => 'block', 'response_status' => $status, 'matched_rule' => $rule] + $context);
        status_header($status);
        nocache_headers();
        header('X-Robots-Tag: noindex, nofollow, noarchive, nosnippet', true);
        echo esc_html((string) $status);
        exit;
    }

    private function rate_limit_exceeded(array $opts, array $context): bool
    {
        $ip = $this->remote_ip();
        if ($ip === '') {
            return false;
        }
        $window = max(10, (int) $opts['rate_limit_window_seconds']);
        $block_seconds = max(60, (int) $opts['rate_limit_block_seconds']);
        $ip_key = 'ip-' . $this->hash_value($ip);
        $range_key = 'range-' . $this->hash_value($this->ip_prefix($ip));
        $ip_exceeded = $this->increment_runtime_counter($ip_key, $window, $block_seconds, (int) $opts['rate_limit_ip_threshold']);
        $range_exceeded = $this->increment_runtime_counter($range_key, $window, $block_seconds, (int) $opts['rate_limit_range_threshold']);
        return $ip_exceeded || $range_exceeded;
    }

    private function increment_runtime_counter(string $key, int $window, int $block_seconds, int $threshold): bool
    {
        $cache_key = 'facetfence_runtime_' . md5($key);
        $now = time();
        $data = get_transient($cache_key);
        if (!is_array($data)) {
            $data = ['window_start' => $now, 'request_count' => 0, 'blocked_until' => 0, 'last_seen' => $now];
        }
        if (!empty($data['blocked_until']) && (int) $data['blocked_until'] > $now) {
            return true;
        }
        if (empty($data['window_start']) || (int) $data['window_start'] + $window < $now) {
            $data = ['window_start' => $now, 'request_count' => 0, 'blocked_until' => 0, 'last_seen' => $now];
        }
        $data['request_count'] = (int) $data['request_count'] + 1;
        $data['last_seen'] = $now;
        $exceeded = $threshold > 0 && (int) $data['request_count'] > $threshold;
        if ($exceeded) {
            $data['blocked_until'] = $now + $block_seconds;
        }
        set_transient($cache_key, $data, $window + $block_seconds + MINUTE_IN_SECONDS);
        return $exceeded;
    }

    private function cleanup_old_runtime_files(): void
    {
        $dir = $this->runtime_dir();
        foreach ($this->directory_entries($dir, 'files') as $file) {
            $mtime = $this->path_mtime($file);
            if (substr($file, -5) === '.json' && $mtime > 0 && $mtime < time() - DAY_IN_SECONDS) {
                wp_delete_file($file);
            }
        }
    }

    private function cleanup_old_ndjson_files(int $days): void
    {
        $dir = $this->log_dir();
        foreach ($this->directory_entries($dir, 'files') as $file) {
            $mtime = $this->path_mtime($file);
            if (substr($file, -7) === '.ndjson' && $mtime > 0 && $mtime < time() - ($days * DAY_IN_SECONDS)) {
                wp_delete_file($file);
            }
        }
    }

    private function search_bot_decision(array $opts, array $context): string
    {
        $ua = strtolower($this->server_value('HTTP_USER_AGENT'));
        $is_google = strpos($ua, 'googlebot') !== false;
        $is_bing = strpos($ua, 'bingbot') !== false;
        if (!$is_google && !$is_bing) {
            return 'not_bot';
        }
        if (($is_google && empty($opts['verify_googlebot'])) || ($is_bing && empty($opts['verify_bingbot']))) {
            return 'not_verified_policy_disabled';
        }
        $verified = $this->verify_search_bot_ip($this->remote_ip(), $is_google ? 'google' : 'bing', $opts);
        if (!$verified && !empty($opts['block_fake_search_bots'])) {
            return 'fake_block';
        }
        if (!$verified) {
            return 'not_verified_allowed_by_policy';
        }
        return $context['complexity_score'] <= (int) $opts['verified_bot_max_score'] ? 'verified_allow' : 'verified_block';
    }

    private function verify_search_bot_ip(string $ip, string $bot, array $opts): bool
    {
        if ($ip === '') {
            return false;
        }
        $key = self::BOT_TRANSIENT_PREFIX . md5($bot . '|' . $ip);
        $cached = get_transient($key);
        if ($cached !== false) {
            return $cached === '1';
        }
        $host = gethostbyaddr($ip);
        $ok = false;
        if (is_string($host) && $host !== $ip) {
            $host_lc = strtolower(rtrim($host, '.'));
            if ($bot === 'google') {
                $ok = preg_match('/\.(googlebot\.com|google\.com)$/', $host_lc) === 1;
            } elseif ($bot === 'bing') {
                $ok = preg_match('/\.search\.msn\.com$/', $host_lc) === 1;
            }
            if ($ok) {
                $records = gethostbynamel($host_lc);
                $ok = is_array($records) && in_array($ip, $records, true);
            }
        }
        set_transient($key, $ok ? '1' : '0', max(300, (int) $opts['verified_bot_cache_ttl']));
        return $ok;
    }

    private function maybe_auto_emergency(array $opts, array $context): void
    {
        if (empty($opts['auto_emergency_enabled'])) {
            return;
        }
        $stats = $this->recent_attack_stats((int) $opts['auto_window_minutes']);
        $mode = $opts['protection_mode'];
        $now = time();
        $auto_until = (int) get_option('facetfence_auto_until', 0);
        if (in_array($mode, ['strict', 'emergency'], true) && $auto_until > 0 && $auto_until <= $now && (int) $stats['pressure'] < (int) $opts['auto_strict_threshold']) {
            $previous = get_option('facetfence_previous_mode', $opts['base_recovery_mode']);
            $opts['protection_mode'] = is_scalar($previous) && array_key_exists((string) $previous, $this->modes()) ? (string) $previous : $opts['base_recovery_mode'];
            delete_option('facetfence_auto_until');
            $this->update_options($opts);
            $this->apply_file_rules($opts, 'auto_recovery');
            $this->log_event('emergency_mode_disabled', ['action_taken' => 'auto_recovery', 'matched_rule' => $mode . '->' . $opts['protection_mode'], 'response_status' => 200] + $context);
            return;
        }
        if (in_array($mode, ['strict', 'emergency'], true)) {
            return;
        }
        $target = '';
        if ((int) $stats['pressure'] >= (int) $opts['auto_emergency_threshold']) {
            $target = 'emergency';
        } elseif ((int) $stats['pressure'] >= (int) $opts['auto_strict_threshold'] || (int) $stats['distinct_ips'] >= (int) $opts['auto_distinct_ip_threshold']) {
            $target = 'strict';
        }
        if ($target === '') {
            return;
        }
        update_option('facetfence_previous_mode', $mode, false);
        update_option('facetfence_auto_until', $now + ((int) $opts['auto_recovery_minutes'] * MINUTE_IN_SECONDS), false);
        $opts['protection_mode'] = $target;
        $this->update_options($opts);
        $this->apply_file_rules($opts, 'auto_emergency');
        $this->log_event('emergency_mode_enabled', ['action_taken' => 'auto_' . $target, 'matched_rule' => 'pressure=' . $stats['pressure'] . ',blocked=' . $stats['blocked'] . ',total=' . $stats['total'] . ',ips=' . $stats['distinct_ips'], 'response_status' => 200] + $context);
    }

    private function recent_attack_stats(int $minutes): array
    {
        global $wpdb;
        $since = gmdate('Y-m-d H:i:s', time() - max(1, $minutes) * MINUTE_IN_SECONDS);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate used for emergency detection.
        $blocked = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE event_type = %s AND created_at >= %s', $this->table_name(), 'blocked_filter_request', $since));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate used for emergency detection.
        $allowed = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE event_type = %s AND created_at >= %s', $this->table_name(), 'allowed_filter_request', $since));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate used for emergency detection.
        $distinct_ips = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(DISTINCT ip_hash) FROM %i WHERE created_at >= %s AND ip_hash IS NOT NULL AND ip_hash <> ''", $this->table_name(), $since));
        $runtime = $this->recent_attack_runtime_stats($minutes);
        $total = max($blocked + $allowed, $runtime['total']);
        $blocked = max($blocked, $runtime['blocked']);
        return [
            'blocked' => $blocked,
            'total' => $total,
            'pressure' => max($blocked, $total),
            'distinct_ips' => max($distinct_ips, $runtime['distinct_ips']),
        ];
    }

    private function increment_attack_window_counter(array $context): void
    {
        $minute = gmdate('YmdHi');
        $key = 'facetfence_attack_' . $minute;
        $data = get_transient($key);
        if (!is_array($data)) {
            $data = ['blocked' => 0, 'ips' => []];
        }
        $data['blocked'] = (int) ($data['blocked'] ?? 0) + 1;
        $ip_hash = (string) ($context['ip_hash'] ?? '');
        if ($ip_hash !== '') {
            $data['ips'][$ip_hash] = 1;
            if (count($data['ips']) > 1000) {
                $data['ips'] = array_slice($data['ips'], -1000, null, true);
            }
        }
        set_transient($key, $data, 2 * HOUR_IN_SECONDS);
    }

    private function increment_filtered_request_window_counter(array $context): void
    {
        $minute = gmdate('YmdHi');
        $key = 'facetfence_attack_' . $minute;
        $data = get_transient($key);
        if (!is_array($data)) {
            $data = ['blocked' => 0, 'total' => 0, 'ips' => []];
        }
        $data['total'] = (int) ($data['total'] ?? 0) + 1;
        $ip_hash = (string) ($context['ip_hash'] ?? '');
        if ($ip_hash !== '') {
            $data['ips'][$ip_hash] = 1;
            if (count($data['ips']) > 1000) {
                $data['ips'] = array_slice($data['ips'], -1000, null, true);
            }
        }
        set_transient($key, $data, 2 * HOUR_IN_SECONDS);
    }

    private function recent_attack_runtime_stats(int $minutes): array
    {
        $blocked = 0;
        $total = 0;
        $ips = [];
        $minutes = max(1, min(60, $minutes));
        for ($i = 0; $i <= $minutes; $i++) {
            $key = 'facetfence_attack_' . gmdate('YmdHi', time() - ($i * MINUTE_IN_SECONDS));
            $data = get_transient($key);
            if (!is_array($data)) {
                continue;
            }
            $blocked += (int) ($data['blocked'] ?? 0);
            $total += (int) ($data['total'] ?? 0);
            foreach ((array) ($data['ips'] ?? []) as $ip_hash => $seen) {
                if ($ip_hash !== '') {
                    $ips[$ip_hash] = 1;
                }
            }
        }
        return ['blocked' => $blocked, 'total' => max($total, $blocked), 'distinct_ips' => count($ips)];
    }

    private function log_event(string $event_type, array $data = []): void
    {
        $opts = $this->options();
        if (empty($opts['event_log_enabled'])) {
            return;
        }
        $context = array_merge($this->empty_event_context($opts), $this->request_context($opts), $data);
        $context['event_type'] = sanitize_key($event_type);
        $context['created_at'] = current_time('mysql', true);
        if ($this->should_skip_repetitive_event_log($event_type, $context, $opts)) {
            return;
        }
        $storage = $opts['event_log_storage'];
        if (in_array($storage, ['database', 'both'], true)) {
            $this->insert_event_db($context);
        }
        if (in_array($storage, ['ndjson', 'both'], true)) {
            $this->append_event_ndjson($context);
        }
    }

    private function should_skip_repetitive_event_log(string $event_type, array $context, array $opts): bool
    {
        if (!empty($opts['event_log_disable_per_request_in_emergency']) && (string) ($context['protection_mode'] ?? '') === 'emergency' && in_array($event_type, ['blocked_filter_request', 'allowed_filter_request', 'seo_noindex_applied'], true)) {
            return true;
        }
        $threshold = max(0, (int) ($opts['event_log_sample_after_per_minute'] ?? 0));
        if ($threshold <= 0) {
            return false;
        }
        $rate = max(1, (int) ($opts['event_log_sample_rate'] ?? 1));
        $key = 'facetfence_log_rate_' . md5($event_type . '|' . gmdate('YmdHi'));
        $count = (int) get_transient($key);
        $count++;
        set_transient($key, $count, 2 * MINUTE_IN_SECONDS);
        return $count > $threshold && ($count % $rate) !== 0;
    }

    private function empty_event_context(array $opts): array
    {
        return [
            'ip' => $this->logged_ip_value($opts),
            'ip_hash' => $this->hash_value($this->remote_ip()),
            'method' => $this->server_value('REQUEST_METHOD'),
            'uri' => $this->server_value('REQUEST_URI'),
            'query_string' => $this->server_value('QUERY_STRING'),
            'query_length' => strlen($this->server_value('QUERY_STRING')),
            'filter_count' => 0,
            'query_type_count' => 0,
            'user_agent' => substr($this->server_value('HTTP_USER_AGENT'), 0, 600),
            'user_agent_hash' => $this->hash_value($this->server_value('HTTP_USER_AGENT')),
            'referer_present' => $this->server_value('HTTP_REFERER') !== '' ? 1 : 0,
            'cookie_present' => $this->server_value('HTTP_COOKIE') !== '' ? 1 : 0,
            'matched_rule' => '',
            'action_taken' => '',
            'response_status' => 0,
            'protection_mode' => $opts['protection_mode'],
            'complexity_score' => 0,
        ];
    }

    private function insert_event_db(array $context): void
    {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Intentional insert into this plugin's custom event-log table.
        $wpdb->insert($this->table_name(), [
            'event_type' => substr((string) $context['event_type'], 0, 80),
            'created_at' => (string) $context['created_at'],
            'ip' => $context['ip'],
            'ip_hash' => $context['ip_hash'],
            'method' => substr((string) $context['method'], 0, 12),
            'uri' => $context['uri'],
            'query_string' => $context['query_string'],
            'query_length' => (int) $context['query_length'],
            'filter_count' => (int) $context['filter_count'],
            'query_type_count' => (int) $context['query_type_count'],
            'user_agent' => $context['user_agent'],
            'user_agent_hash' => $context['user_agent_hash'],
            'referer_present' => (int) $context['referer_present'],
            'cookie_present' => (int) $context['cookie_present'],
            'matched_rule' => substr((string) $context['matched_rule'], 0, 120),
            'action_taken' => substr((string) $context['action_taken'], 0, 80),
            'response_status' => (int) $context['response_status'],
            'protection_mode' => substr((string) $context['protection_mode'], 0, 40),
            'complexity_score' => (int) $context['complexity_score'],
        ]);
    }

    private function append_event_ndjson(array $context): void
    {
        if (!$this->ensure_dir($this->log_dir())) {
            return;
        }
        $file = trailingslashit($this->log_dir()) . gmdate('Y-m-d-H-i') . '.ndjson';
        $line = wp_json_encode($context) . "\n";
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Atomic append with flock is required for NDJSON event logs; WP_Filesystem has no append/lock primitive.
        $handle = fopen($file, 'ab');
        if (!is_resource($handle)) {
            return;
        }
        if (flock($handle, LOCK_EX)) {
            // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fwrite -- Atomic append with flock is required for NDJSON event logs.
            fwrite($handle, $line);
            flock($handle, LOCK_UN);
        }
        // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Closing the append handle opened above.
        fclose($handle);
    }

    private function dashboard_stats(): array
    {
        global $wpdb;
        $since = gmdate('Y-m-d H:i:s', time() - 10 * MINUTE_IN_SECONDS);
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate used for emergency detection.
        $blocked = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE event_type = %s AND created_at >= %s', $this->table_name(), 'blocked_filter_request', $since));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate for the admin dashboard.
        $allowed = (int) $wpdb->get_var($wpdb->prepare('SELECT COUNT(*) FROM %i WHERE event_type = %s AND created_at >= %s', $this->table_name(), 'allowed_filter_request', $since));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate for the admin dashboard.
        $distinct = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(DISTINCT ip_hash) FROM %i WHERE created_at >= %s AND ip_hash IS NOT NULL AND ip_hash <> ''", $this->table_name(), $since));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table aggregate for the admin dashboard.
        $avg = (float) $wpdb->get_var($wpdb->prepare('SELECT AVG(complexity_score) FROM %i WHERE created_at >= %s', $this->table_name(), $since));
        $top_key = $this->top_query_key($since);
        return ['blocked_10m' => $blocked, 'allowed_10m' => $allowed, 'distinct_ips_10m' => $distinct, 'avg_score_10m' => number_format_i18n($avg, 1), 'top_query_key' => $top_key];
    }

    private function top_query_key(string $since): string
    {
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table query for calculating top query keys.
        $rows = $wpdb->get_col($wpdb->prepare('SELECT query_string FROM %i WHERE created_at >= %s AND query_string <> %s ORDER BY id DESC LIMIT 200', $this->table_name(), $since, ''));
        $counts = [];
        foreach ((array) $rows as $query) {
            parse_str((string) $query, $params);
            foreach (array_keys((array) $params) as $key) {
                $counts[$key] = ($counts[$key] ?? 0) + 1;
            }
        }
        if (!$counts) {
            return '';
        }
        arsort($counts);
        return (string) array_key_first($counts);
    }

    private function recent_events(int $limit): array
    {
        global $wpdb;
        $limit = max(1, min(100, $limit));
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table query for displaying recent events.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT created_at,event_type,action_taken,response_status,complexity_score,uri FROM %i ORDER BY id DESC LIMIT %d', $this->table_name(), (int) $limit), ARRAY_A);
        return is_array($rows) ? $rows : [];
    }

    private function export_events_csv(): void
    {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('Unauthorized', 'facetfence-product-filters'));
        }
        global $wpdb;
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom event-log table query for CSV export.
        $rows = $wpdb->get_results($wpdb->prepare('SELECT created_at,event_type,ip,ip_hash,method,uri,query_length,filter_count,query_type_count,referer_present,cookie_present,matched_rule,action_taken,response_status,protection_mode,complexity_score FROM %i ORDER BY id DESC LIMIT %d', $this->table_name(), 5000), ARRAY_A);
        nocache_headers();
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename=facetfence-product-filters-events-' . gmdate('Ymd-His') . '.csv');
        // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- csv_line() escapes CSV fields according to RFC 4180-style quoting.
        echo $this->csv_line(['created_at','event_type','ip','ip_hash','method','uri','query_length','filter_count','query_type_count','referer_present','cookie_present','matched_rule','action_taken','response_status','protection_mode','complexity_score']);
        foreach ((array) $rows as $row) {
            // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- csv_line() escapes CSV fields according to RFC 4180-style quoting.
            echo $this->csv_line((array) $row);
        }
        exit;
    }

    private function csv_line(array $fields): string
    {
        $escaped = array_map(static function ($field): string {
            $value = (string) $field;
            return '"' . str_replace('"', '""', $value) . '"';
        }, $fields);
        return implode(',', $escaped) . "\r\n";
    }

    private function list_backups(int $limit): array
    {
        $root = $this->backup_root();
        $dirs = $this->directory_entries($root, 'dirs');
        rsort($dirs);
        $out = [];
        foreach (array_slice($dirs, 0, $limit) as $dir) {
            $files = [];
            foreach ($this->directory_entries($dir, 'files') as $file) {
                if (basename($file) !== 'meta.json') {
                    $files[] = basename($file);
                }
            }
            $meta = [];
            $meta_file = trailingslashit($dir) . 'meta.json';
            $fs = $this->filesystem();
            if ($fs && $fs->exists($meta_file) && $fs->is_readable($meta_file)) {
                $decoded = json_decode((string) $fs->get_contents($meta_file), true);
                if (is_array($decoded)) {
                    $meta = $decoded;
                }
            }
            $out[] = ['name' => basename($dir), 'files' => $files, 'reason' => (string) ($meta['reason'] ?? '')];
        }
        return $out;
    }

    private function restore_latest_backup(): bool
    {
        $root = $this->backup_root();
        $dirs = $this->directory_entries($root, 'dirs');
        rsort($dirs);
        $fs = $this->filesystem();
        if (!$fs) {
            return false;
        }
        foreach ($dirs as $dir) {
            $ok = false;
            if ($this->path_is_file(trailingslashit($dir) . 'htaccess.bak')) {
                $ok = $fs->copy(trailingslashit($dir) . 'htaccess.bak', $this->htaccess_path(), true, $this->fs_chmod_file()) || $ok;
            }
            if ($this->path_is_file(trailingslashit($dir) . 'robots.txt.bak')) {
                $ok = $fs->copy(trailingslashit($dir) . 'robots.txt.bak', $this->robots_path(), true, $this->fs_chmod_file()) || $ok;
            }
            if ($this->path_is_file(trailingslashit($dir) . 'blocked-light.html.bak')) {
                $ok = $fs->copy(trailingslashit($dir) . 'blocked-light.html.bak', $this->blocked_light_path(), true, $this->fs_chmod_file()) || $ok;
            }
            if ($ok) {
                return true;
            }
        }
        return false;
    }

    private function logged_ip_value(array $opts)
    {
        $ip = $this->remote_ip();
        if ($ip === '') {
            return null;
        }
        if ($opts['ip_logging_mode'] === 'full') {
            return $ip;
        }
        if ($opts['ip_logging_mode'] === 'anonymized') {
            return $this->anonymize_ip($ip);
        }
        return null;
    }

    private function anonymize_ip(string $ip): string
    {
        if (strpos($ip, ':') !== false) {
            $parts = explode(':', $ip);
            return implode(':', array_slice($parts, 0, 4)) . '::';
        }
        $parts = explode('.', $ip);
        if (count($parts) === 4) {
            $parts[3] = '0';
            return implode('.', $parts);
        }
        return '';
    }

    private function ip_prefix(string $ip): string
    {
        if (strpos($ip, ':') !== false) {
            $parts = explode(':', $ip);
            return implode(':', array_slice($parts, 0, 4)) . '::/64';
        }
        $parts = explode('.', $ip);
        if (count($parts) === 4) {
            return $parts[0] . '.' . $parts[1] . '.' . $parts[2] . '.0/24';
        }
        return $ip;
    }

    private function hash_value(string $value): string
    {
        if ($value === '') {
            return '';
        }
        return hash_hmac('sha256', $value, wp_salt('auth'));
    }

    private function truncate(string $value, int $length): string
    {
        return strlen($value) > $length ? substr($value, 0, $length - 3) . '...' : $value;
    }
}

add_action('before_woocommerce_init', static function (): void {
    if (class_exists('\\Automattic\\WooCommerce\\Utilities\\FeaturesUtil')) {
        \Automattic\WooCommerce\Utilities\FeaturesUtil::declare_compatibility('custom_order_tables', __FILE__, true);
    }
});

register_activation_hook(__FILE__, ['FacetFence_Plugin', 'activate']);
register_deactivation_hook(__FILE__, ['FacetFence_Plugin', 'deactivate']);

FacetFence_Plugin::instance();
