# dwith Bot Insight (Lite)

A lightweight WordPress plugin for observing **WordPress bot traffic** and **mid/high risk requests** that actually reach WordPress, designed specifically for Cloudflare-based sites.

This plugin does not attempt to identify or block traffic.  
It records outcomes only.

## Design Philosophy

Cloudflare already handles bot verification, blocking, and challenges at the edge.  
WordPress should not repeat identity verification.

This plugin focuses on a single question:

What traffic still reaches WordPress after Cloudflare?

## What This Plugin Records

Search engine bot traffic:
- Recorded only when the User-Agent clearly matches known search engine bots
- No reverse DNS
- No IP verification
- No access.log parsing

Risk traffic:
- Only requests classified as mid or high risk
- Based on HTTP status codes, request paths, and behavior patterns
- Only traffic that successfully enters WordPress

## What This Plugin Does NOT Do

- No server log access
- No reverse DNS lookups
- No IP reputation checks
- No firewall rules
- No blocking or rate limiting
- No frontend scripts

## Detection Logic Summary

Search bots:
- Googlebot
- Bingbot
- DuckDuckBot
- YandexBot
- Slurp

Risk classification:
- High risk: 5xx responses, known probe paths
- Mid risk: repeated 4xx responses, scanner User-Agents
- Low risk traffic is ignored

## Performance Characteristics

- Zero frontend output
- No cron jobs
- One database insert at shutdown
- Optional short-term deduplication via transients
- Lazy cleanup only when admin page is opened

Designed for minimal overhead.

## Admin Interface

WordPress Admin:
- Bot Insight menu
- Collapsible settings panel
- Collapsible tools panel
- Search and filterable event table
- Per-page limits
- Optional proxy trust (Cloudflare / X-Forwarded-For)

No data is exposed on the frontend.

## Requirements

- WordPress 6.0+
- PHP 7.4+
- MySQL 5.7+ or equivalent

## Installation

1. Upload plugin folder to `wp-content/plugins/`
2. Activate **dwith Bot Insight (Lite)** in WordPress admin
3. Visit **Bot Insight** in the admin menu

No additional configuration required.

## Recommended Environment

- Cloudflare in front of WordPress
- Firewall rules handled at Cloudflare level
- WordPress used as observation layer only

## Data Storage

- Custom database table
- Retention period configurable
- Manual purge available
- Manual cleanup trigger available

## License

MIT

## Author

https://dwith.com
