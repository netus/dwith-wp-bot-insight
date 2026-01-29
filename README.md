# dwith Bot Insight (Lite)

A minimal WordPress plugin for observing **WordPress bot traffic** and **mid/high-risk requests** that actually reach WordPress, designed for Cloudflare-based sites.

This plugin does **not** attempt to identify, verify, or block traffic.  
It records outcomes only.

---

## Purpose

Cloudflare already performs bot verification, blocking, and challenges at the edge.

This plugin answers a single question:

**After Cloudflare filtering, what traffic still reaches WordPress?**

---

## Design Philosophy

- Do not fight Cloudflare’s architecture  
- Do not re-verify identities inside WordPress  
- Do not parse server access logs  
- Do not rely on reverse DNS  
- Observe only what successfully enters WordPress  

WordPress acts as an **inbound result observer**, not a security gate.

---

## What This Plugin Records

### 1. Search Engine Bot Traffic
Recorded only when the **User-Agent clearly matches** known search engine crawlers:

- Googlebot  
- bingbot  
- DuckDuckBot  
- YandexBot  
- Yahoo Slurp  

No IP verification or DNS lookup is performed.

---

### 2. Mid / High Risk Requests
Requests that reach WordPress and match **clear risk signals**, including:

- 4xx / 5xx response codes  
- Known probe paths (e.g. `/wp-login.php`, `/xmlrpc.php`, `/wp-admin/`)  
- Common scanning or exploitation tool signatures in User-Agent  

Only requests that actually execute within WordPress are recorded.

---

## What This Plugin Does NOT Do

- No traffic blocking  
- No firewall rules  
- No access.log parsing  
- No reverse DNS verification  
- No Cloudflare API usage  
- No frontend scripts  
- No JavaScript tracking  

---

## Performance Characteristics

- Runs entirely inside the WordPress request lifecycle  
- Executes lightweight string matching only  
- Writes to database **only when a record is relevant**  
- Optional deduplication via transients  
- No impact on page rendering  

Designed for negligible overhead.

---

## Data Storage

- Stored in a dedicated WordPress database table  
- Automatically cleaned based on retention settings  
- No server-level file access required  

---

## Admin Interface

- View recent search bot and risk events  
- Filter by type, status code, keyword  
- Adjustable retention period  
- Optional request deduplication  
- Manual cleanup and purge tools  

Admin-only visibility.

---

## Intended Use Cases

- Understanding real search engine crawl behavior  
- Observing which attacks bypass Cloudflare rules  
- Deriving new firewall rules from actual inbound patterns  
- Keeping WordPress-level visibility clean and focused  

---

## Not Intended For

- Bot blocking or mitigation  
- Security enforcement  
- Analytics replacement  
- SEO ranking analysis  

---

## Installation

1. Upload the plugin folder to `wp-content/plugins/`
2. Activate **dwith Bot Insight (Lite)** in WordPress Admin
3. Visit **Bot Insight** in the admin menu

No configuration required to start.

---

## Uninstall Behavior

- Deactivation stops all logging  
- Database table remains until manually purged  
- Purge tool available in admin interface  

---

## License

MIT License

---

## Author

Designed by dwith  
https://dwith.com
