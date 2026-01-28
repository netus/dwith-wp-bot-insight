<?php
/*
Plugin Name: dwith Bot Insight (Lite)
Description: Log only (1) search engine bots by UA match, (2) mid/high risk traffic reaching WordPress. Minimal overhead.
Version: 1.2.0
Author: dwith.com
*/

if (!defined('ABSPATH')) exit;

if (!class_exists('Dwith_Bot_Insight_Lite')) {

class Dwith_Bot_Insight_Lite {

    /* =========================
       MODULE: CONSTANTS
       ========================= */
    const OPT            = 'dwith_bi_lite_settings_v1';
    const OPT_MAINT_TS   = 'dwith_bi_lite_maint_ts_v1';
    const TABLE          = 'dwith_bi_lite_events';
    const DEFAULT_TTL    = 60;
    const MAINT_INTERVAL = 43200; // 12h
    /* =========================
       END MODULE: CONSTANTS
       ========================= */

    /* =========================
       MODULE: BOOTSTRAP
       ========================= */
    private static $pending = null;

    public static function init() {
        add_action('template_redirect', [__CLASS__, 'capture_request'], 0);
        add_action('shutdown',          [__CLASS__, 'log_on_shutdown'], 0);

        add_action('admin_menu',        [__CLASS__, 'admin_menu']);
        add_action('admin_init',        [__CLASS__, 'handle_post']);
        add_action('admin_footer',      [__CLASS__, 'admin_footer_credit']);
    }
    /* =========================
       END MODULE: BOOTSTRAP
       ========================= */

    /* =========================
       MODULE: SETTINGS
       ========================= */
    public static function settings() {
        $d = [
            'trust_proxy'   => 0,
            'days_keep'     => 30,
            'per_page'      => 200,  // 100/200/500/1000
            'dedupe_ttl'    => self::DEFAULT_TTL, // 10..600
            'enable_dedupe' => 1,
        ];
        $s = get_option(self::OPT, []);
        if (!is_array($s)) $s = [];
        $s = array_merge($d, $s);

        $s['days_keep']  = max(7, min(365, intval($s['days_keep'])));
        $s['per_page']   = in_array(intval($s['per_page']), [100,200,500,1000], true) ? intval($s['per_page']) : 200;
        $s['dedupe_ttl'] = max(10, min(600, intval($s['dedupe_ttl'])));

        foreach (['trust_proxy','enable_dedupe'] as $k) $s[$k] = !empty($s[$k]) ? 1 : 0;
        return $s;
    }

    public static function save_settings($post) {
        $s = self::settings();
        foreach (['trust_proxy','enable_dedupe'] as $k) $s[$k] = !empty($post[$k]) ? 1 : 0;

        $dk = intval($post['days_keep'] ?? $s['days_keep']);
        $s['days_keep'] = max(7, min(365, $dk));

        $pp = intval($post['per_page'] ?? $s['per_page']);
        $s['per_page'] = in_array($pp, [100,200,500,1000], true) ? $pp : 200;

        $tt = intval($post['dedupe_ttl'] ?? $s['dedupe_ttl']);
        $s['dedupe_ttl'] = max(10, min(600, $tt));

        update_option(self::OPT, $s, false);
        return $s;
    }
    /* =========================
       END MODULE: SETTINGS
       ========================= */

    /* =========================
       MODULE: DB
       ========================= */
    public static function table() {
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    public static function activate() {
        self::db_install();
    }

    public static function db_install() {
        global $wpdb;
        require_once ABSPATH.'wp-admin/includes/upgrade.php';
        $charset = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE ".self::table()." (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            created_at DATETIME NOT NULL,
            ip VARCHAR(45) NOT NULL,
            ua TEXT NOT NULL,
            path TEXT NOT NULL,
            status SMALLINT UNSIGNED NOT NULL,
            type VARCHAR(16) NOT NULL,      /* search | risk */
            subtype VARCHAR(64) NOT NULL,   /* bot name | risk tag */
            risk_level VARCHAR(8) NOT NULL, /* mid | high | '' */
            PRIMARY KEY (id),
            KEY created_at (created_at),
            KEY type (type),
            KEY subtype (subtype),
            KEY status (status),
            KEY risk_level (risk_level)
        ) $charset;";
        dbDelta($sql);
    }
    /* =========================
       END MODULE: DB
       ========================= */

    /* =========================
       MODULE: DETECT (SEARCH + RISK)
       ========================= */
    public static function search_bot_map() {
        return [
            'Googlebot'   => ['Googlebot'],
            'bingbot'     => ['bingbot'],
            'Slurp'       => ['Slurp'],
            'YandexBot'   => ['YandexBot'],
            'DuckDuckBot' => ['DuckDuckBot'],
        ];
    }

    public static function detect_search_bot($ua) {
        $ua = (string)$ua;
        if ($ua === '') return '';
        foreach (self::search_bot_map() as $name => $needles) {
            foreach ($needles as $n) {
                if (stripos($ua, $n) !== false) return $name;
            }
        }
        return '';
    }

    public static function detect_risk($status, $path, $ua) {
        $status = intval($status);
        $path   = (string)$path;
        $ua     = (string)$ua;

        if ($status >= 500) return ['high','status_5xx'];
        if (in_array($status, [444,520,521,522,523,524,525,526], true)) return ['high','status_edge'];

        $hi = [
            '/.env','/wp-login.php','/xmlrpc.php','/wp-admin/','/phpmyadmin','/cgi-bin','/actuator','/vendor/',
            '/solr/','/boaform','/HNAP1','/manager/html','/server-status'
        ];
        foreach ($hi as $p) if (stripos($path, $p) !== false) return ['high','probe_path'];

        if (in_array($status, [401,403,404], true)) return ['mid','status_4xx'];

        $mid_ua = ['sqlmap','acunetix','nikto','nmap','masscan','zgrab','fuzz','dirbuster'];
        foreach ($mid_ua as $k) if ($ua !== '' && stripos($ua, $k) !== false) return ['mid','ua_tool'];

        return ['',''];
    }
    /* =========================
       END MODULE: DETECT (SEARCH + RISK)
       ========================= */

    /* =========================
       MODULE: REQUEST CAPTURE (NO DB)
       ========================= */
    public static function client_ip($trust_proxy) {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if (!$trust_proxy) return $ip;

        $ip = $_SERVER['HTTP_CF_CONNECTING_IP']
            ?? $_SERVER['HTTP_X_FORWARDED_FOR']
            ?? $ip;

        if (strpos($ip, ',') !== false) $ip = trim(explode(',', $ip)[0]);
        return $ip;
    }

    public static function capture_request() {
        if (is_admin()) return;
        if (defined('DOING_CRON') && DOING_CRON) return;
        if (defined('DOING_AJAX') && DOING_AJAX) return;

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if ($ua === '') return;

        $s = self::settings();
        $ip = self::client_ip($s['trust_proxy']);
        if ($ip === '') return;

        $path = $_SERVER['REQUEST_URI'] ?? '/';
        $path_only = strtok($path, '?') ?: '/';

        self::$pending = [
            'ts'   => current_time('mysql'),
            'ip'   => $ip,
            'ua'   => $ua,
            'path' => $path_only,
            's'    => $s,
        ];
    }
    /* =========================
       END MODULE: REQUEST CAPTURE
       ========================= */

    /* =========================
       MODULE: LOGGER (DB ON SHUTDOWN)
       ========================= */
    public static function log_on_shutdown() {
        if (!self::$pending) return;

        $p = self::$pending;
        self::$pending = null;

        $ua   = $p['ua'];
        $path = $p['path'];
        $s    = $p['s'];

        $status = 200;
        if (function_exists('http_response_code')) {
            $tmp = http_response_code();
            if (is_int($tmp) && $tmp > 0) $status = $tmp;
        }
        if (function_exists('is_404') && is_404()) $status = 404;

        $bot = self::detect_search_bot($ua);
        if ($bot !== '') {
            $type='search'; $sub=$bot; $risk='';
        } else {
            [$risk,$tag] = self::detect_risk($status, $path, $ua);
            if ($risk === '' || ($risk !== 'mid' && $risk !== 'high')) return;
            $type='risk'; $sub=$tag; $risk=$risk;
        }

        if (!empty($s['enable_dedupe'])) {
            $ttl = intval($s['dedupe_ttl']);
            $dedupe_key = 'dwith_bi_lite_'.md5($type.'|'.$sub.'|'.$p['ip'].'|'.$path.'|'.substr($ua,0,64));
            if (get_transient($dedupe_key)) return;
            set_transient($dedupe_key, 1, $ttl);
        }

        global $wpdb;
        $wpdb->insert(self::table(), [
            'created_at'=> $p['ts'],
            'ip'        => $p['ip'],
            'ua'        => $ua,
            'path'      => $path,
            'status'    => $status,
            'type'      => $type,
            'subtype'   => (string)$sub,
            'risk_level'=> (string)$risk,
        ], ['%s','%s','%s','%s','%d','%s','%s','%s']);
    }
    /* =========================
       END MODULE: LOGGER
       ========================= */

    /* =========================
       MODULE: MAINT (LAZY CLEANUP)
       ========================= */
    public static function lazy_cleanup_if_needed() {
        $last = intval(get_option(self::OPT_MAINT_TS, 0));
        if ($last > 0 && (time() - $last) < self::MAINT_INTERVAL) return;

        $s = self::settings();
        $days = max(7, min(365, intval($s['days_keep'])));
        $threshold = date('Y-m-d H:i:s', current_time('timestamp') - ($days * DAY_IN_SECONDS));

        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "DELETE FROM ".self::table()." WHERE created_at < %s",
            $threshold
        ));
        update_option(self::OPT_MAINT_TS, time(), false);
    }
    /* =========================
       END MODULE: MAINT
       ========================= */

    /* =========================
       MODULE: ADMIN (MENU + POST)
       ========================= */
    public static function admin_menu() {
        add_menu_page(
            'dwith Bot Insight',
            'Bot Insight',
            'manage_options',
            'dwith-bot-insight',
            [__CLASS__, 'admin_page'],
            'dashicons-visibility',
            80
        );
    }

    public static function handle_post() {
        if (!is_admin() || !current_user_can('manage_options')) return;
        if (!isset($_GET['page']) || $_GET['page'] !== 'dwith-bot-insight') return;

        if (isset($_POST['dwith_bi_save'])) {
            check_admin_referer('dwith_bi_save_nonce');
            self::save_settings($_POST);
            wp_redirect(admin_url('admin.php?page=dwith-bot-insight&saved=1'));
            exit;
        }

        if (isset($_POST['dwith_bi_purge'])) {
            check_admin_referer('dwith_bi_tools_nonce');
            global $wpdb;
            $wpdb->query("TRUNCATE TABLE ".self::table());
            wp_redirect(admin_url('admin.php?page=dwith-bot-insight&purged=1'));
            exit;
        }

        if (isset($_POST['dwith_bi_cleanup_now'])) {
            check_admin_referer('dwith_bi_tools_nonce');
            update_option(self::OPT_MAINT_TS, 0, false);
            self::lazy_cleanup_if_needed();
            wp_redirect(admin_url('admin.php?page=dwith-bot-insight&cleaned=1'));
            exit;
        }
    }
    /* =========================
       END MODULE: ADMIN (MENU + POST)
       ========================= */

    /* =========================
       MODULE: ADMIN (PAGE)
       ========================= */
    public static function admin_page() {
        if (!current_user_can('manage_options')) return;

        self::lazy_cleanup_if_needed();

        global $wpdb;
        $s = self::settings();
        $table = self::table();

        $filter_type   = isset($_GET['type']) ? sanitize_key($_GET['type']) : '';
        $filter_status = isset($_GET['status']) ? intval($_GET['status']) : 0;
        $filter_q      = isset($_GET['q']) ? sanitize_text_field($_GET['q']) : '';

        $allowed_types = ['', 'search', 'risk'];
        if (!in_array($filter_type, $allowed_types, true)) $filter_type = '';

        $where = "WHERE 1=1";
        $params = [];

        if ($filter_type !== '') { $where .= " AND type = %s"; $params[] = $filter_type; }
        if ($filter_status > 0)  { $where .= " AND status = %d"; $params[] = $filter_status; }
        if ($filter_q !== '') {
            $where .= " AND (ua LIKE %s OR path LIKE %s OR ip LIKE %s OR subtype LIKE %s)";
            $like = '%'.$wpdb->esc_like($filter_q).'%';
            $params[]=$like; $params[]=$like; $params[]=$like; $params[]=$like;
        }

        $per_page = intval($s['per_page']);

        $sql_main = $params
            ? $wpdb->prepare("SELECT * FROM $table $where ORDER BY created_at DESC LIMIT $per_page", ...$params)
            : "SELECT * FROM $table $where ORDER BY created_at DESC LIMIT $per_page";
        $rows_main = $wpdb->get_results($sql_main);

        $sum = $wpdb->get_results(
            "SELECT type, COUNT(*) cnt FROM $table GROUP BY type",
            ARRAY_A
        );
        $sum_map = ['search'=>0,'risk'=>0];
        foreach ($sum as $r) if (isset($sum_map[$r['type']])) $sum_map[$r['type']] = intval($r['cnt']);

        $search_by_bot = $wpdb->get_results(
            "SELECT subtype, COUNT(*) cnt FROM $table WHERE type='search' GROUP BY subtype ORDER BY cnt DESC",
            ARRAY_A
        );

        echo '<div class="wrap"><h1>dwith Bot Insight</h1>';

        if (isset($_GET['saved']))   echo '<div class="notice notice-success"><p>Settings saved.</p></div>';
        if (isset($_GET['purged']))  echo '<div class="notice notice-warning"><p>All data purged.</p></div>';
        if (isset($_GET['cleaned'])) echo '<div class="notice notice-info"><p>Cleanup done.</p></div>';

        echo '<details style="margin:12px 0;padding:12px;background:#fff;border:1px solid #ccd0d4">';
        echo '<summary style="cursor:pointer"><strong>Settings</strong></summary>';
        echo '<form method="post" style="margin-top:12px">';
        wp_nonce_field('dwith_bi_save_nonce');
        echo '<label><input type="checkbox" name="trust_proxy" value="1" '.checked($s['trust_proxy'],1,false).'> Trust proxy headers (CF/XFF)</label><br>';
        echo '<label><input type="checkbox" name="enable_dedupe" value="1" '.checked($s['enable_dedupe'],1,false).'> Enable dedupe</label><br><br>';
        echo 'Keep days: <input type="number" name="days_keep" value="'.esc_attr($s['days_keep']).'" style="width:90px"> ';
        echo 'Dedupe TTL: <input type="number" name="dedupe_ttl" value="'.esc_attr($s['dedupe_ttl']).'" style="width:90px"> sec ';
        echo 'Per page: <select name="per_page">';
        foreach ([100,200,500,1000] as $n) echo '<option value="'.$n.'" '.selected($s['per_page'],$n,false).'>'.$n.'</option>';
        echo '</select>';
        echo '<p><button class="button button-primary" name="dwith_bi_save" value="1">Save</button></p>';
        echo '</form>';
        echo '</details>';

        echo '<details style="margin:12px 0;padding:12px;background:#fff;border:1px solid #ccd0d4">';
        echo '<summary style="cursor:pointer"><strong>Tools</strong></summary>';
        echo '<form method="post" style="margin-top:12px;display:inline-block;margin-right:10px">';
        wp_nonce_field('dwith_bi_tools_nonce');
        echo '<button class="button" name="dwith_bi_cleanup_now" value="1">Cleanup now</button>';
        echo '</form>';
        echo '<form method="post" style="margin-top:12px;display:inline-block">';
        wp_nonce_field('dwith_bi_tools_nonce');
        echo '<button class="button" name="dwith_bi_purge" value="1" onclick="return confirm(\'Purge all data?\')">Purge all</button>';
        echo '</form>';
        echo '</details>';

        echo '<div style="margin:12px 0;padding:12px;background:#fff;border:1px solid #ccd0d4">';
        echo '<strong>Counts</strong><br>';
        echo 'Search: '.intval($sum_map['search']).' | Risk(mid/high): '.intval($sum_map['risk']).'<br><br>';
        echo '<strong>Search bots by UA match</strong><br>';
        if ($search_by_bot) {
            foreach ($search_by_bot as $r) echo esc_html($r['subtype']).': '.intval($r['cnt']).'&nbsp;&nbsp;';
        } else {
            echo 'No data';
        }
        echo '</div>';

        echo '<details open style="margin:12px 0;padding:12px;background:#fff;border:1px solid #ccd0d4">';
        echo '<summary style="cursor:pointer"><strong>Events (newest first)</strong></summary>';

        echo '<form method="get" style="margin-top:12px">';
        echo '<input type="hidden" name="page" value="dwith-bot-insight">';
        echo '<select name="type">';
        echo '<option value="" '.selected($filter_type,'',false).'>All</option>';
        echo '<option value="search" '.selected($filter_type,'search',false).'>Search</option>';
        echo '<option value="risk" '.selected($filter_type,'risk',false).'>Risk</option>';
        echo '</select> ';
        echo '<input type="number" name="status" value="'.esc_attr($filter_status?:'').'" style="width:90px" placeholder="status"> ';
        echo '<input type="text" name="q" value="'.esc_attr($filter_q).'" style="width:260px" placeholder="search ip/path/ua/subtype"> ';
        echo '<button class="button" type="submit">Apply</button>';
        echo '</form>';

        echo '<table class="widefat striped" style="margin-top:10px"><thead><tr>';
        echo '<th>Time</th><th>Type</th><th>Sub</th><th>Risk</th><th>Status</th><th>IP</th><th>Path</th><th>UA</th>';
        echo '</tr></thead><tbody>';

        if ($rows_main) {
            foreach ($rows_main as $r) {
                echo '<tr>';
                echo '<td>'.esc_html($r->created_at).'</td>';
                echo '<td>'.esc_html($r->type).'</td>';
                echo '<td>'.esc_html($r->subtype).'</td>';
                echo '<td>'.esc_html($r->risk_level).'</td>';
                echo '<td>'.esc_html($r->status).'</td>';
                echo '<td>'.esc_html($r->ip).'</td>';
                echo '<td style="word-break:break-all">'.esc_html($r->path).'</td>';
                echo '<td style="word-break:break-all;max-width:420px">'.esc_html($r->ua).'</td>';
                echo '</tr>';
            }
        } else {
            echo '<tr><td colspan="8">No data</td></tr>';
        }

        echo '</tbody></table>';
        echo '</details>';

        echo '</div>';
    }
    /* =========================
       END MODULE: ADMIN (PAGE)
       ========================= */

    /* =========================
       MODULE: FOOTER CREDIT
       ========================= */
    public static function admin_footer_credit() {
        if (!is_admin() || !function_exists('get_current_screen')) return;
        $screen = get_current_screen();
        if (!$screen || $screen->id !== 'toplevel_page_dwith-bot-insight') return;

        echo '<div style="position:fixed;bottom:12px;left:50%;transform:translateX(-50%);font-size:12px;color:#666;z-index:9999;white-space:nowrap">';
        echo 'Johnny\'s Life Clips - <a href="https://dwith.com" target="_blank" rel="noopener" style="text-decoration:none">dwith.com</a>';
        echo '</div>';
    }
    /* =========================
       END MODULE: FOOTER CREDIT
       ========================= */
}

Dwith_Bot_Insight_Lite::init();

register_activation_hook(__FILE__,   ['Dwith_Bot_Insight_Lite', 'activate']);

}