<?php
/**
 * Uninstall cleanup for Filter Guard for WooCommerce.
 *
 * @package FilterGuardForWooCommerce
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Remove a managed marker block from a text file through WP_Filesystem.
 *
 * @param WP_Filesystem_Base $woo_filter_guard_fs Filesystem instance.
 * @param string             $woo_filter_guard_path File path.
 * @param string             $woo_filter_guard_begin Begin marker.
 * @param string             $woo_filter_guard_end End marker.
 * @return void
 */
function woo_filter_guard_uninstall_remove_managed_block($woo_filter_guard_fs, string $woo_filter_guard_path, string $woo_filter_guard_begin, string $woo_filter_guard_end): void
{
    if (!$woo_filter_guard_fs || !$woo_filter_guard_fs->exists($woo_filter_guard_path) || !$woo_filter_guard_fs->is_writable($woo_filter_guard_path)) {
        return;
    }

    $woo_filter_guard_content = $woo_filter_guard_fs->get_contents($woo_filter_guard_path);
    if (!is_string($woo_filter_guard_content)) {
        return;
    }

    $woo_filter_guard_pattern = '/' . preg_quote($woo_filter_guard_begin, '/') . '.*?' . preg_quote($woo_filter_guard_end, '/') . "\s*/s";
    $woo_filter_guard_content = (string) preg_replace($woo_filter_guard_pattern, '', $woo_filter_guard_content);
    $woo_filter_guard_fs->put_contents($woo_filter_guard_path, ltrim($woo_filter_guard_content), FS_CHMOD_FILE);
}


/**
 * Get the public front-end root path used for .htaccess, robots.txt, and block page cleanup.
 *
 * @return string
 */
function woo_filter_guard_uninstall_public_root_path(): string
{
    if (!function_exists('get_home_path')) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }

    if (function_exists('get_home_path')) {
        $woo_filter_guard_home_path = get_home_path();
        if (is_string($woo_filter_guard_home_path) && $woo_filter_guard_home_path !== '') {
            return trailingslashit(wp_normalize_path($woo_filter_guard_home_path));
        }
    }

    return trailingslashit(wp_normalize_path(ABSPATH));
}

/**
 * Run uninstall cleanup.
 *
 * @return void
 */
function woo_filter_guard_uninstall_cleanup_current_site(): void
{
    $woo_filter_guard_options = get_option('woo_filter_guard_options', []);
    if (!is_array($woo_filter_guard_options)) {
        $woo_filter_guard_options = [];
    }

    require_once ABSPATH . 'wp-admin/includes/file.php';
    WP_Filesystem();
    global $wp_filesystem;

    $woo_filter_guard_public_root = woo_filter_guard_uninstall_public_root_path();

    $woo_filter_guard_remove_file_rules = !empty($woo_filter_guard_options['remove_file_rules_on_uninstall']);
    if ($woo_filter_guard_remove_file_rules && $wp_filesystem) {
        woo_filter_guard_uninstall_remove_managed_block($wp_filesystem, $woo_filter_guard_public_root . '.htaccess', '# BEGIN FILTER_GUARD_FOR_WOOCOMMERCE', '# END FILTER_GUARD_FOR_WOOCOMMERCE');
        woo_filter_guard_uninstall_remove_managed_block($wp_filesystem, $woo_filter_guard_public_root . '.htaccess', '# BEGIN WOO_FILTER_GUARD', '# END WOO_FILTER_GUARD');
        woo_filter_guard_uninstall_remove_managed_block($wp_filesystem, $woo_filter_guard_public_root . 'robots.txt', '# BEGIN FILTER_GUARD_FOR_WOOCOMMERCE_ROBOTS', '# END FILTER_GUARD_FOR_WOOCOMMERCE_ROBOTS');
        woo_filter_guard_uninstall_remove_managed_block($wp_filesystem, $woo_filter_guard_public_root . 'robots.txt', '# BEGIN WOO_FILTER_GUARD_ROBOTS', '# END WOO_FILTER_GUARD_ROBOTS');

        $woo_filter_guard_blocked_file = $woo_filter_guard_public_root . 'blocked-light.html';
        if ($wp_filesystem->exists($woo_filter_guard_blocked_file) && $wp_filesystem->is_writable($woo_filter_guard_blocked_file)) {
            $wp_filesystem->delete($woo_filter_guard_blocked_file, false, 'f');
        }
    }

    if ($wp_filesystem) {
        $woo_filter_guard_uploads = wp_upload_dir();
        if (empty($woo_filter_guard_uploads['error']) && !empty($woo_filter_guard_uploads['basedir'])) {
            $wp_filesystem->delete(trailingslashit($woo_filter_guard_uploads['basedir']) . 'filter-guard-for-woocommerce', true, 'd');
            $wp_filesystem->delete(trailingslashit($woo_filter_guard_uploads['basedir']) . 'woo-filter-guard', true, 'd');
        }
        $wp_filesystem->delete(trailingslashit(WP_CONTENT_DIR) . 'filter-guard-for-woocommerce', true, 'd');
        $wp_filesystem->delete(trailingslashit(WP_CONTENT_DIR) . 'cache/filter-guard-for-woocommerce', true, 'd');
        $wp_filesystem->delete(trailingslashit(WP_CONTENT_DIR) . 'cache/woo-filter-guard', true, 'd');
    }

    global $wpdb;
    $woo_filter_guard_table = $wpdb->prefix . 'woo_filter_guard_events';
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall intentionally removes this plugin's custom event-log table.
    $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $woo_filter_guard_table));

    delete_option('woo_filter_guard_options');
    delete_option('wfg_options');
    delete_option('woo_filter_guard_db_version');
    delete_option('woo_filter_guard_last_test_results');
    delete_option('wfg_last_test_results');
    delete_option('woo_filter_guard_cookie_secret_version');
    delete_option('woo_filter_guard_previous_mode');
    delete_option('woo_filter_guard_auto_until');
}

/**
 * Run uninstall cleanup for single-site and multisite installations.
 *
 * @return void
 */
function woo_filter_guard_uninstall_cleanup(): void
{
    if (is_multisite() && function_exists('get_sites')) {
        $woo_filter_guard_site_ids = get_sites(['fields' => 'ids', 'number' => 0]);
        if (is_array($woo_filter_guard_site_ids)) {
            foreach ($woo_filter_guard_site_ids as $woo_filter_guard_site_id) {
                switch_to_blog((int) $woo_filter_guard_site_id);
                woo_filter_guard_uninstall_cleanup_current_site();
                restore_current_blog();
            }
            return;
        }
    }

    woo_filter_guard_uninstall_cleanup_current_site();
}

woo_filter_guard_uninstall_cleanup();
