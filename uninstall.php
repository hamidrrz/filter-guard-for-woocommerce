<?php
/**
 * Uninstall cleanup for FacetFence Product Filters.
 *
 * @package FacetFence
 */

if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

/**
 * Remove a managed marker block from a text file through WP_Filesystem.
 *
 * @param WP_Filesystem_Base $facetfence_fs Filesystem instance.
 * @param string             $facetfence_path File path.
 * @param string             $facetfence_begin Begin marker.
 * @param string             $facetfence_end End marker.
 * @return void
 */
function facetfence_uninstall_remove_managed_block($facetfence_fs, string $facetfence_path, string $facetfence_begin, string $facetfence_end): void
{
    if (!$facetfence_fs || !$facetfence_fs->exists($facetfence_path) || !$facetfence_fs->is_writable($facetfence_path)) {
        return;
    }

    $facetfence_content = $facetfence_fs->get_contents($facetfence_path);
    if (!is_string($facetfence_content)) {
        return;
    }

    $facetfence_pattern = '/' . preg_quote($facetfence_begin, '/') . '.*?' . preg_quote($facetfence_end, '/') . "\s*/s";
    $facetfence_content = (string) preg_replace($facetfence_pattern, '', $facetfence_content);
    $facetfence_fs->put_contents($facetfence_path, ltrim($facetfence_content), FS_CHMOD_FILE);
}


/**
 * Get the public front-end root path used for .htaccess, robots.txt, and block page cleanup.
 *
 * @return string
 */
function facetfence_uninstall_public_root_path(): string
{
    if (!function_exists('get_home_path')) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }

    if (function_exists('get_home_path')) {
        $facetfence_home_path = get_home_path();
        if (is_string($facetfence_home_path) && $facetfence_home_path !== '') {
            return trailingslashit(wp_normalize_path($facetfence_home_path));
        }
    }

    return trailingslashit(wp_normalize_path(ABSPATH));
}

/**
 * Run uninstall cleanup.
 *
 * @return void
 */
function facetfence_uninstall_cleanup_current_site(): void
{
    $facetfence_options = get_option('facetfence_options', []);
    if (!is_array($facetfence_options)) {
        $facetfence_options = [];
    }

    require_once ABSPATH . 'wp-admin/includes/file.php';
    WP_Filesystem();
    global $wp_filesystem;

    $facetfence_public_root = facetfence_uninstall_public_root_path();

    $facetfence_remove_file_rules = !empty($facetfence_options['remove_file_rules_on_uninstall']);
    if ($facetfence_remove_file_rules && $wp_filesystem) {
        facetfence_uninstall_remove_managed_block($wp_filesystem, $facetfence_public_root . '.htaccess', '# BEGIN FACETFENCE_PRODUCT_FILTERS', '# END FACETFENCE_PRODUCT_FILTERS');
        facetfence_uninstall_remove_managed_block($wp_filesystem, $facetfence_public_root . '.htaccess', '# BEGIN FACETFENCE_LEGACY', '# END FACETFENCE_LEGACY');
        facetfence_uninstall_remove_managed_block($wp_filesystem, $facetfence_public_root . 'robots.txt', '# BEGIN FACETFENCE_PRODUCT_FILTERS_ROBOTS', '# END FACETFENCE_PRODUCT_FILTERS_ROBOTS');
        facetfence_uninstall_remove_managed_block($wp_filesystem, $facetfence_public_root . 'robots.txt', '# BEGIN FACETFENCE_LEGACY_ROBOTS', '# END FACETFENCE_LEGACY_ROBOTS');

        $facetfence_blocked_file = $facetfence_public_root . 'blocked-light.html';
        if ($wp_filesystem->exists($facetfence_blocked_file) && $wp_filesystem->is_writable($facetfence_blocked_file)) {
            $wp_filesystem->delete($facetfence_blocked_file, false, 'f');
        }
    }

    if ($wp_filesystem) {
        $facetfence_uploads = wp_upload_dir();
        if (empty($facetfence_uploads['error']) && !empty($facetfence_uploads['basedir'])) {
            $wp_filesystem->delete(trailingslashit($facetfence_uploads['basedir']) . 'facetfence-product-filters', true, 'd');
        }
    }

    global $wpdb;
    $facetfence_table = $wpdb->prefix . 'facetfence_events';
    // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange -- Uninstall intentionally removes this plugin's custom event-log table.
    $wpdb->query($wpdb->prepare('DROP TABLE IF EXISTS %i', $facetfence_table));

    delete_option('facetfence_options');
    delete_option('facetfence_legacy_options');
    delete_option('facetfence_db_version');
    delete_option('facetfence_last_test_results');
    delete_option('facetfence_legacy_last_test_results');
    delete_option('facetfence_cookie_secret_version');
    delete_option('facetfence_previous_mode');
    delete_option('facetfence_auto_until');
}

/**
 * Run uninstall cleanup for single-site and multisite installations.
 *
 * @return void
 */
function facetfence_uninstall_cleanup(): void
{
    if (is_multisite() && function_exists('get_sites')) {
        $facetfence_site_ids = get_sites(['fields' => 'ids', 'number' => 0]);
        if (is_array($facetfence_site_ids)) {
            foreach ($facetfence_site_ids as $facetfence_site_id) {
                switch_to_blog((int) $facetfence_site_id);
                facetfence_uninstall_cleanup_current_site();
                restore_current_blog();
            }
            return;
        }
    }

    facetfence_uninstall_cleanup_current_site();
}

facetfence_uninstall_cleanup();
