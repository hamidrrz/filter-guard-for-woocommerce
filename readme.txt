=== FacetFence Product Filters ===
Contributors: hrezaei
Tags: woocommerce, security, seo, crawler, noindex
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 7.4
Requires Plugins: woocommerce
Stable tag: 1.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect WooCommerce filtered URLs from crawl floods with noindex/canonical controls, signed cookies, rate limits, logs, and rollback.

== Description ==

FacetFence Product Filters is a defensive WooCommerce plugin for expensive layered-filter URLs such as:

`/product-category/active-equipment/?filter_poe=donthave&query_type_poe=or&filter_brand=cisco&query_type_brand=or`

These URLs can create heavy WordPress/WooCommerce execution paths, consume PHP-FPM workers, and waste crawl budget. The plugin provides a safe default Monitor mode and lets administrators gradually enable stronger controls.

Major features:

* Real Event Log and admin dashboard for blocked, allowed, SEO, mode, self-test, XML-RPC, and rule-generation events.
* Privacy modes for IP logging: full, anonymized, or hash-only.
* Query Complexity Scoring for `filter_`, `query_type_`, query length, multi-value filters, and WooCommerce query keys.
* SEO Soft Mode: allow normal filtered URLs while applying `noindex`, `nofollow`, `X-Robots-Tag`, and clean canonical URLs.
* Signed HMAC human cookie with optional daily rotating cookie name, User-Agent binding, and IP-prefix binding.
* Best-effort transient/object-cache based rate limiting, disabled by default so Monitor mode never blocks unexpectedly. Server/CDN rate limits are still recommended for very high-volume attacks.
* Auto Emergency Mode with strict/emergency thresholds, recovery period, and filtered-request pressure counting even in Monitor mode.
* Verified Googlebot and Bingbot checks using reverse DNS plus forward DNS confirmation.
* Apache/LiteSpeed `.htaccess`, Nginx, and Cloudflare rule generator with mode-aware, public-root-aware, subdirectory-aware, signed-cookie-pattern server checks, Cloudflare args.names query matching, and emergency rules aligned with configured query keys.
* Health Check / Self-Test after changes with real signed-cookie tests, separate bypass-token test, optional rollback, redirect following, and configurable real WooCommerce test paths.
* Rollback backups for public-root `.htaccess`, `robots.txt`, and `blocked-light.html`.
* robots.txt virtual and physical managed blocks, disabled in Off/Monitor modes.
* Optional XML-RPC blocking.
* Multisite-aware activation/deactivation/uninstall cleanup; network activation creates per-site runtime tables and options.

The default mode is Monitor Only: it logs and scores only and does not modify SEO tags, cookies, robots, rate limits, XML-RPC, or server-level rules.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/` or install the ZIP file from the WordPress admin.
2. Activate FacetFence Product Filters.
3. Go to Settings > FacetFence Product Filters.
4. Review dashboard, event log, and generated rules.
5. Start with Monitor or SEO Soft Mode.
6. Enable stronger protection only after running the built-in health checks.

== Frequently Asked Questions ==

= Does this plugin require WooCommerce? =

Yes. It is designed for WooCommerce archive and layered-filter URLs. The plugin declares WooCommerce as a dependency through the `Requires Plugins` header.

= Does this plugin support multisite? =

Yes. Network activation/deactivation and uninstall are handled per site. Each site gets its own event-log table using that site's database prefix. Server file rules still depend on each site's public root and should be reviewed carefully on custom multisite deployments.

= Does it block all filtered URLs by default? =

No. The default mode is Monitor Only. You can switch to SEO Soft, Cookie, Cookie + Referer, Strict, or Emergency modes from the settings page.

= Can the plugin write .htaccess rules? =

Yes, but writing `.htaccess` is off by default. If enabled, the plugin creates backups and writes a managed BEGIN/END block. The settings page also shows generated Apache/LiteSpeed, Nginx, and Cloudflare rules for manual deployment.

= Does the signed cookie work at Apache level? =

Apache/LiteSpeed, Nginx, and Cloudflare can only pre-check that a FacetFence signed cookie name exists. Generated server/CDN rules no longer trust WooCommerce cart/session cookies. Full HMAC signature validation always happens in PHP when WordPress receives the request.

For Cloudflare, the generated expression uses query argument names and regex cookie matching for a tighter edge pre-check. The `matches` operator may require a plan that supports Cloudflare regex matching; PHP validation remains authoritative.

= How does bot verification work? =

For Googlebot and Bingbot, the plugin can perform reverse DNS lookup and then forward DNS lookup to confirm that the source IP resolves back to the claimed crawler host. Results are cached with a configurable TTL.

= Does this plugin store personal data? =

It can store security event logs. IP logging can be configured as full IP, anonymized IP, or hash-only. Hash-only is the default. Retention is configurable and logs are deleted on uninstall.

== Privacy ==

FacetFence Product Filters can record security events related to expensive filtered URL requests. Depending on settings, logs may include event type, timestamp, method, URI, query length, filter count, User-Agent hash, IP hash, anonymized IP or full IP, referer/cookie presence, action taken, response status, protection mode, and complexity score.

Default privacy behavior:

* IP logging mode: hash-only.
* Event retention: 14 days.
* Rate-limit counters use best-effort short-lived WordPress transients/object cache entries.
* NDJSON event files and rollback backups are stored under the WordPress uploads directory in a `facetfence-product-filters/` subdirectory with deny rules and index files. NDJSON mode uses scoped append locking and remains optional; database logging is the default. For Nginx deployments, apply the generated internal-data deny rules or equivalent server restrictions.
* Event database table and plugin-owned uploads-based runtime/log directories are removed on uninstall.


== Changelog ==

= 1.6 =
* Renamed the plugin to FacetFence Product Filters and updated the slug, text domain, and plugin metadata.
* Reworked plugin prefixes for classes, options, transients, hooks, and admin assets to avoid generic naming collisions.
* Moved plugin-generated event logs, backups, and runtime files to an uploads-based plugin directory with aligned cleanup paths.
* Clarified .htaccess guard status so non-server-blocking modes show it as not required instead of a missing requirement.
* Hardened uploads-based runtime folders by creating index.php and .htaccess denial files with a local fallback when WP_Filesystem is unavailable.
* Treat the managed .htaccess guard as required only when .htaccess management is enabled and the selected protection features need server-level rules.

= 1.5.8 =
* Initial public release.
* Added WooCommerce filtered URL protection, SEO soft mode, signed cookie checks, event logging, rollback, and server rule generators.