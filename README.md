# Filter Guard for WooCommerce

[![License: GPL v2 or later](https://img.shields.io/badge/license-GPLv2%2B-blue.svg)](https://www.gnu.org/licenses/gpl-2.0.html)
[![WordPress](https://img.shields.io/badge/WordPress-6.5%2B-blue.svg)](https://wordpress.org/)
[![Tested up to WordPress](https://img.shields.io/badge/tested%20up%20to-WordPress%207.0-blue.svg)](https://wordpress.org/)
[![PHP](https://img.shields.io/badge/PHP-7.4%2B-777BB4.svg)](https://www.php.net/)
[![WooCommerce](https://img.shields.io/badge/WooCommerce-8.0%2B-96588A.svg)](https://woocommerce.com/)

**Filter Guard for WooCommerce** is a defensive WordPress plugin for WooCommerce stores that receive crawler, bot, or accidental traffic spikes against expensive layered-filter archive URLs.

It is designed to reduce the operational impact of URLs such as:

```text
/product-category/network-switches/?filter_brand=cisco&query_type_brand=or&filter_poe=donthave&query_type_poe=or
```

These URLs can trigger heavy WooCommerce archive queries, waste crawl budget, generate duplicate indexable URLs, and consume PHP-FPM/Apache/Nginx resources. Filter Guard provides a gradual protection model: start in Monitor mode, review the event log and complexity scores, then enable SEO, cookie, strict, emergency, or server/CDN-level controls when needed.

---

## Highlights

- **Safe default Monitor Mode** — logs and scores expensive filtered URLs without blocking visitors, adding SEO tags, setting cookies, or changing robots rules.
- **SEO Soft Mode** — applies `noindex`, `nofollow`, `X-Robots-Tag`, and clean canonical URLs to expensive filtered archive requests.
- **Query Complexity Scoring** — scores filter-heavy query strings using `filter_`, `query_type_`, query length, multi-value filters, and WooCommerce query keys such as `orderby`, `per_page`, `min_price`, and `max_price`.
- **Signed Human Cookie** — HMAC-signed human cookie with optional daily rotating name, User-Agent binding, and IP-prefix binding.
- **Verified Search Bots** — optional Googlebot/Bingbot verification using reverse DNS plus forward DNS confirmation.
- **Event Log & Dashboard** — records allowed, blocked, SEO, mode-change, bot-verification, XML-RPC, self-test, and rule-generation events.
- **Privacy-aware Logging** — choose full IP, anonymized IP, or hash-only logging. Hash-only is the default.
- **Best-effort WordPress Rate Limiting** — transient/object-cache counters for WordPress-level throttling, disabled by default.
- **Auto Emergency Mode** — detects filtered-request pressure and can automatically move from monitor/normal modes to strict or emergency modes.
- **Server Rule Generator** — Apache/LiteSpeed, Nginx, and Cloudflare rule snippets generated from plugin settings.
- **Rollback & Health Check** — backups for public-root `.htaccess`, `robots.txt`, and `blocked-light.html`, plus GET-based health checks with redirect following.
- **Multisite-aware Lifecycle** — network activation/deactivation/uninstall support with per-site event tables and cleanup.

---

## Protection Modes

| Mode | Blocks visitors? | SEO controls? | Cookies? | Robots rules? | Typical use |
|---|---:|---:|---:|---:|---|
| Off | No | No | No | No | Fully disabled |
| Monitor | No | No | No | No | Safe observation and scoring |
| SEO Soft | Limited, score-based | Yes | No | Optional | Crawl/index control without hard blocking |
| Cookie | Yes, if signed cookie is missing/invalid | Optional | Yes | Optional | Allow browser-like users after cookie challenge |
| Cookie + Referer | Yes, if cookie or internal referer is missing | Optional | Yes | Optional | Stricter pre-PHP filtering |
| Strict | Yes | Optional | Optional | Optional | Active crawl-flood mitigation |
| Emergency | Yes, lightweight response | Optional | Optional | Optional | Severe attack / resource exhaustion response |

---

## Requirements

- WordPress 6.5 or newer
- PHP 7.4 or newer
- WooCommerce 8.0 or newer
- Apache/LiteSpeed for managed `.htaccess` rules, or manual Nginx/Cloudflare deployment using generated snippets

Plugin headers include:

```php
Requires Plugins: woocommerce
WC requires at least: 8.0
WC tested up to: 9.5
```

---

## Installation

1. Download or clone this repository.
2. Copy the plugin folder to:

   ```text
   wp-content/plugins/filter-guard-for-woocommerce/
   ```

3. Activate **Filter Guard for WooCommerce** from the WordPress admin.
4. Open:

   ```text
   Settings → Filter Guard for WooCommerce
   ```

5. Keep the plugin in **Monitor** mode first.
6. Configure a real WooCommerce category path for Health Check, for example:

   ```text
   /product-category/network-switches/
   ```

7. Review the dashboard, event log, complexity scores, and generated server rules before enabling stronger modes.

---

## Recommended Rollout

### 1. Observe first

Start with **Monitor** mode. This mode records and scores expensive filtered requests but does not modify SEO output, set cookies, write robots rules, rate-limit, block XML-RPC, or generate server-level effects.

### 2. Enable SEO Soft Mode

Use this when filtered WooCommerce URLs are being indexed or wasting crawl budget but you do not want to block users.

SEO Soft Mode can apply:

- `noindex`
- `nofollow`
- `noarchive`
- `nosnippet`
- `X-Robots-Tag`
- clean canonical URL output

Direct canonical output can be disabled if another SEO plugin already manages canonical tags.

### 3. Enable cookie-based protection

Use **Cookie** or **Cookie + Referer** mode when filtered URLs are causing expensive repeated PHP/WooCommerce execution.

The plugin uses an HMAC-signed cookie. Server/CDN rules only pre-check the presence of plugin-owned cookie name patterns. PHP remains authoritative and validates the full signed value.

### 4. Deploy server/CDN rules carefully

Generated rules are available for:

- Apache / LiteSpeed
- Nginx
- Cloudflare

Always review generated rules before applying them to production. For Nginx and Cloudflare, deploy rules manually and test with the built-in Health Check.

### 5. Use Emergency only when necessary

Emergency mode is intended for active resource exhaustion or severe crawl flood conditions. It should not be the default long-term operating mode.

---

## Server Rule Notes

### Apache / LiteSpeed

When enabled, the plugin can write a managed block to the public-root `.htaccess` file. It creates backups before writing and can roll back after failed checks.

Managed server rules are disabled by default.

### Nginx

Nginx does not process `.htaccess` files. Use the generated Nginx snippets and review them with a server administrator.

The generator also includes deny rules for internal plugin data paths, for example:

```nginx
location ^~ /wp-content/filter-guard-for-woocommerce/ { deny all; }
location ^~ /wp-content/cache/filter-guard-for-woocommerce/ { deny all; }
```

### Cloudflare

The generated Cloudflare expression uses query argument names and cookie-name pattern checks. Cloudflare can pre-check cookie presence at the edge, but PHP still validates the HMAC signature.

Some Cloudflare expression features such as regex matching may depend on the Cloudflare plan and ruleset feature availability. If regex matching is unavailable, use Apache/Nginx rules or adapt the generated expression to your Cloudflare plan.

---

## Event Logging and Privacy

Filter Guard can record security events related to expensive filtered URL requests.

Depending on configuration, event records may include:

- event type
- timestamp
- HTTP method
- request URI
- query string or query metadata
- query length
- filter count
- User-Agent hash
- IP hash, anonymized IP, or full IP
- referer presence
- cookie presence
- matched rule
- action taken
- response status
- protection mode
- complexity score

Default privacy behavior:

- IP logging mode: **hash-only**
- Event retention: **14 days**
- Database logging: enabled by default
- NDJSON logging: optional
- Rate-limit counters: short-lived WordPress transients/object-cache values

On uninstall, plugin-owned runtime data, log data, and event tables are removed. Managed `.htaccess` and `robots.txt` rules are removed only if the relevant cleanup setting is enabled before uninstall.

---

## Health Check and Rollback

The plugin includes a GET-based Health Check system with redirect following.

Health checks can test:

- homepage reachability
- filtered URL behavior without cookie/referer
- filtered URL behavior with cookie
- filtered URL behavior with cookie and referer
- XML-RPC behavior
- robots.txt behavior

Set a real WooCommerce category path before relying on Health Check results. A synthetic or non-existent category path can produce misleading results.

Rollback backups are created for:

- public-root `.htaccess`
- public-root `robots.txt`
- public-root `blocked-light.html`

---

## Multisite

Filter Guard is multisite-aware:

- network activation creates per-site runtime options and event tables
- network deactivation clears scheduled hooks per site
- uninstall cleans plugin-owned data per site

Server-level rules still depend on each site's public root and should be reviewed carefully on custom multisite deployments.

---

## Development

### Recommended checks

Run PHP syntax checks:

```bash
php -l filter-guard-for-woocommerce.php
php -l uninstall.php
```

Validate ZIP integrity:

```bash
unzip -t filter-guard-for-woocommerce.zip
```

Run WordPress Plugin Check inside a real WordPress installation:

```bash
wp plugin check filter-guard-for-woocommerce --checks=plugin_repo
```

### Important implementation notes

- The plugin uses WordPress APIs for admin UI, options, transients, cron, database access, HTTP requests, escaping, and sanitization.
- Custom event-log queries are prepared with `$wpdb->prepare()`.
- Public-root file paths use `get_home_path()` for better compatibility with WordPress-in-own-directory setups.
- Most filesystem operations use the WordPress Filesystem API.
- NDJSON append mode uses scoped `fopen()`/`flock()` for atomic append because the WordPress Filesystem API does not provide an append-with-lock primitive.

---

## Repository Topics

Suggested GitHub topics:

```text
wordpress-plugin, woocommerce, security, crawler, crawl-budget, noindex, rate-limiting, cloudflare, nginx, apache, ecommerce, php
```

---

## FAQ

### Does this replace a WAF or CDN rate limiter?

No. Filter Guard provides WordPress-level protection and generated server/CDN rules. For very high-volume attacks, use it alongside Cloudflare, Nginx, Apache/LiteSpeed, hosting-level protection, or another WAF.

### Does it block normal product pages?

No. The plugin targets expensive WooCommerce archive/filter URLs based on path and query settings. Product pages are not the intended target.

### Does it trust WooCommerce cart/session cookies?

No. Server/CDN rules only check plugin-owned signed-cookie name patterns. Full HMAC validation is performed in PHP.

### Is Monitor mode safe?

Yes. Monitor mode logs and scores only. It does not block, rate-limit, set cookies, modify robots output, add SEO tags, or write server rules.

### Can I use this on Nginx?

Yes, but Nginx requires manual server configuration. Apply the generated Nginx snippets and internal-data deny rules manually.

### Can I use this with Cloudflare?

Yes. Use the generated Cloudflare expression as a starting point and adapt it to your Cloudflare plan, especially if regex matching is unavailable.

---

## Security

Please report security issues privately instead of opening a public issue.

Recommended contact:

```text
Hamidreza Rezaei
https://hrezaei.ir
```

---

## License

This project is licensed under the **GPLv2 or later**.

See:

```text
https://www.gnu.org/licenses/gpl-2.0.html
```

---

## Author

**Hamidreza Rezaei**  
Website: <https://hrezaei.ir>
