=== Filter Guard for WooCommerce ===
Contributors: hamidrezarezaei
Tags: woocommerce, security, seo, crawler, noindex
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 7.4
Requires Plugins: woocommerce
Stable tag: 1.4.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Protect WooCommerce filtered URLs from crawl floods with noindex/canonical controls, signed cookies, rate limits, logs, and rollback.

== Description ==

Filter Guard for WooCommerce is a defensive WooCommerce plugin for expensive layered-filter URLs such as:

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
* Health Check / Self-Test after changes with optional rollback, GET requests, redirect following, and configurable real WooCommerce test paths.
* Rollback backups for public-root `.htaccess`, `robots.txt`, and `blocked-light.html`.
* robots.txt virtual and physical managed blocks, disabled in Off/Monitor modes.
* Optional XML-RPC blocking.
* Multisite-aware activation/deactivation/uninstall cleanup; network activation creates per-site runtime tables and options.

The default mode is Monitor Only: it logs and scores only and does not modify SEO tags, cookies, robots, rate limits, XML-RPC, or server-level rules.

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/` or install the ZIP file from the WordPress admin.
2. Activate Filter Guard for WooCommerce.
3. Go to Settings > Filter Guard for WooCommerce.
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

Apache/LiteSpeed, Nginx, and Cloudflare can only pre-check that a Filter Guard signed cookie name exists. Generated server/CDN rules no longer trust WooCommerce cart/session cookies. Full HMAC signature validation always happens in PHP when WordPress receives the request.

For Cloudflare, the generated expression uses query argument names and regex cookie matching for a tighter edge pre-check. The `matches` operator may require a plan that supports Cloudflare regex matching; PHP validation remains authoritative.

= How does bot verification work? =

For Googlebot and Bingbot, the plugin can perform reverse DNS lookup and then forward DNS lookup to confirm that the source IP resolves back to the claimed crawler host. Results are cached with a configurable TTL.

= Does this plugin store personal data? =

It can store security event logs. IP logging can be configured as full IP, anonymized IP, or hash-only. Hash-only is the default. Retention is configurable and logs are deleted on uninstall.

== Privacy ==

Filter Guard for WooCommerce can record security events related to expensive filtered URL requests. Depending on settings, logs may include event type, timestamp, method, URI, query length, filter count, User-Agent hash, IP hash, anonymized IP or full IP, referer/cookie presence, action taken, response status, protection mode, and complexity score.

Default privacy behavior:

* IP logging mode: hash-only.
* Event retention: 14 days.
* Rate-limit counters use best-effort short-lived WordPress transients/object cache entries.
* NDJSON event files and rollback backups are stored under `wp-content/filter-guard-for-woocommerce/` with deny rules and index files. NDJSON mode uses scoped append locking and remains optional; database logging is the default. For Nginx deployments, apply the generated internal-data deny rules or equivalent server restrictions.
* Event database table and plugin-owned runtime/log directories are removed on uninstall.

== Screenshots ==

1. Live dashboard with blocked/allowed request counters and current mode.
2. Protection settings with complexity scoring and signed cookie options.
3. Event log table and CSV export.
4. Server rule generators for Apache/LiteSpeed, Nginx, and Cloudflare.
5. Rollback backup list and health check results.

== Changelog ==

= 1.4.1 =
* Renamed the main plugin class from lowercase prefix style to PascalCase prefix style: Filter_Guard_For_Woocommerce_Plugin.
* Kept all 1.4.0 hardening changes intact.

= 1.4.0 =
* Count all expensive filtered requests, not only blocked requests, for Auto Emergency pressure detection.
* Align Emergency `.htaccess` query matching with the configured query key regex.
* Generate Cloudflare query rules from `http.request.uri.args.names` instead of broad query-string contains checks.
* Tighten Cloudflare cookie pre-check with a stable signed-cookie regex pattern for rotated cookie names.

= 1.3.9 =
* Made generated Apache/LiteSpeed, Nginx, and Cloudflare cookie checks stable when daily signed-cookie name rotation is enabled.
* Expanded generated Cloudflare query matching to follow configured expensive query keys beyond filter_ and query_type_.
* Clarified that server/CDN rules only pre-check plugin-owned cookie name patterns; PHP validates HMAC signatures.

= 1.3.8 =
* Renamed the main plugin class to start with the exact plugin prefix expected by WordPress Coding Standards / Plugin Check.
* Kept all 1.3.7 hardening changes intact.

= 1.3.7 =
* Added update-time database schema migration, multisite-aware lifecycle cleanup, signed-cookie-only server rule generation, and Nginx internal-data deny snippets.

= 1.3.6 =
* Added public-root compatibility using get_home_path(), hardened Cloudflare expressions, clarified best-effort rate limits, removed regex suppression, and improved filesystem helper usage.

= 1.3.5 =
* Made Monitor mode neutral, improved server rule generation, added GET-based health checks, decoupled Auto Emergency from event logging, and hardened NDJSON logging.

= 1.3.4 =
* Guarded manual .htaccess rewrites in safe modes, added health-check test paths, hardened rule generator safe-mode output, and improved uninstall warnings.

= 1.3.3 =
* Hardened Monitor mode so it does not block filtered traffic, XML-RPC, or rate-limit by default.
* Reworked rate limiting to use short-lived WordPress transients/object cache counters instead of JSON file counters.
* Added event-log sampling and emergency-mode per-request log suppression to reduce database pressure during attacks.
* Made Health Check mode-aware and stricter.
* Moved backups and NDJSON events outside public uploads.
* Added optional direct canonical tag output toggle.
* Updated managed .htaccess/robots.txt markers while preserving legacy marker cleanup.

= 1.3.2 =
* Fixed Plugin Check errors around translator comments and CSV output context.

= 1.3.1 =
* Renamed plugin and slug to avoid restricted/trademarked terms at the beginning of the name.
* Hardened SQL preparation, filesystem operations, nonce/sanitize handling, and readme metadata.

= 1.3.0 =
* Added event logging, dashboard stats, signed cookies, bot verification, complexity scoring, rate limiting, emergency mode, rule generators, health checks, and rollback.

== Upgrade Notice ==

= 1.4.1 =
Fixes the main class name to use a PascalCase plugin-prefix format expected by WordPress Coding Standards / Plugin Check.

= 1.4.0 =
Use this version for stricter Cloudflare query/cookie matching, better Auto Emergency detection in Monitor mode, and emergency server rules aligned with configured query keys.

= 1.3.9 =
Stabilizes server/CDN cookie-name rules for daily cookie rotation and expands generated Cloudflare query matching for configured expensive query keys.

= 1.3.8 =
Renamed the main plugin class to start with the exact plugin prefix expected by WordPress Coding Standards / Plugin Check.

= 1.3.7 =
Adds update-time database schema migration, multisite-aware lifecycle cleanup, signed-cookie-only server rule generation, and Nginx internal-data deny snippets.

= 1.3.6 =
Use this version for public-root compatibility, tighter Cloudflare expressions, and clearer best-effort rate-limit documentation.

= 1.3.5 =
Use this version for neutral Monitor mode, mode-aware server rules, GET-based health checks, and better Auto Emergency behavior.
