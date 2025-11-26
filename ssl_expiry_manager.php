<?php
/**
 * Plugin Name: SSL Expiry Manager (All-in-One + Front Controls + Token Page)
 * Description: ניהול ובדיקת תוקף SSL בטבלה עם עריכה, ייבוא/ייצוא CSV, סל מחזור 90 יום, REST לסוכן מקומי, בקרות פרונט ועמוד ניהול טוקן.
 * Version: 1.5.0
 * Author: Ofri + GPT
 */
 
 add_filter('rest_authentication_errors', function($result){
    $route = $_GET['rest_route'] ?? ($_SERVER['REQUEST_URI'] ?? '');
    if (strpos($route, '/ssl-agent/v1/') === false) return $result;

    $hdr = $_SERVER['HTTP_X_AGENT_TOKEN'] ?? '';
    if(!$hdr){
        return new WP_Error('forbidden','missing token',['status'=>403]);
    }

    global $wpdb;
    $table = $wpdb->prefix . 'ssl_agents';
    $agent = $wpdb->get_row($wpdb->prepare("SELECT * FROM {$table} WHERE token = %s LIMIT 1", $hdr), ARRAY_A);
    if($agent){
        $wpdb->update($table,[
            'last_seen' => current_time('mysql', true),
            'status'    => 'online',
        ],['id'=>(int)$agent['id']]);
        return ['agent'=>$agent];
    }

    return new WP_Error('forbidden','bad token',['status'=>403]);
}, 0);

if (!defined('ABSPATH')) exit;

if (!class_exists('SSL_Expiry_Manager_AIO')) {
class SSL_Expiry_Manager_AIO {
    const CPT = 'ssl_cert';
    const TABLE = 'ssl_em_certificates';
    const CRON_HOOK = 'ssl_expiry_manager_daily_check';
    const CRON_SINGLE_HOOK = 'ssl_expiry_manager_single_check';
    const CRON_MONITOR_HOOK = 'ssl_expiry_manager_monitor';
    const NONCE = 'ssl_expiry_manager_nonce';
    const EXPORT_ACTION = 'ssl_expiry_export';
    const IMPORT_ACTION = 'ssl_expiry_import';
    const SAVE_ACTION   = 'ssl_expiry_save';
    const DELETE_ACTION = 'ssl_expiry_delete';
    const RESTORE_ACTION= 'ssl_expiry_restore';
    const DELETE_PERMANENT_ACTION = 'ssl_delete_permanent';
    const EMPTY_TRASH_ACTION = 'ssl_empty_trash';
    const SINGLE_CHECK_ACTION = 'ssl_expiry_single_check';
    const BATCH_CHECK_ACTION = 'ssl_expiry_batch_check';
    const OPTION_TOKEN  = 'ssl_em_api_token';
    const OPTION_REMOTE = 'ssl_em_remote_client';
    const OPTION_QUEUE  = 'ssl_em_task_queue';
    const OPTION_LOG    = 'ssl_em_activity_log';
    const OPTION_MONITOR_STATE = 'ssl_em_monitor_state';
    const OPTION_CERT_TYPES = 'ssl_em_cert_types';
    const OPTION_SETTINGS = 'ssl_em_settings';
    const OPTION_SQL_SEEDED = 'ssl_em_sql_seeded';
    const TABLE_QUEUE = 'ssl_em_task_queue';
    const TABLE_AGENTS = 'ssl_agents';
    const QUEUE_CLAIM_TTL = 300; // 5 minutes
    const QUEUE_MAX_ATTEMPTS = 5;
    const TOKEN_STALE_WINDOW = 300; // 5 minutes
    const LOG_FILE_NAME = 'ssl_em_debug.log';
    const ADD_TOKEN_ACTION    = 'ssl_add_token';
    const MANAGE_TOKEN_ACTION = 'ssl_manage_token';
    const SAVE_CERT_TYPES_ACTION = 'ssl_save_cert_types';
    const SAVE_GENERAL_SETTINGS_ACTION = 'ssl_save_general_settings';
    const TOGGLE_FOLLOW_UP_ACTION = 'ssl_toggle_follow_up';
    const PAGE_MAIN_FALLBACK  = 'https://kb.macomp.co.il/?page_id=13576';
    const PAGE_TRASH_FALLBACK = 'https://kb.macomp.co.il/?page_id=11134';
    const PAGE_TOKEN_FALLBACK = 'https://kb.macomp.co.il/?page_id=11138';
    const PAGE_LOG_FALLBACK   = 'https://kb.macomp.co.il/?page_id=11141';

    public function __construct() {
        add_action('init', [$this,'register_cpt']);
        add_action('init', [$this,'register_meta']);
        add_action('init', [$this,'ensure_sql_table']);
        add_action('init', [$this,'ensure_task_queue_table']);
        add_action('init', [$this,'ensure_agent_table']);
        add_shortcode('ssl_cert_table', [$this,'shortcode_table']);
        add_shortcode('ssl_trash',      [$this,'shortcode_trash']);
        add_shortcode('ssl_controls',   [$this,'shortcode_controls']);
        add_shortcode('ssl_token',      [$this,'shortcode_token']);
        add_shortcode('ssl_token_page', [$this,'shortcode_token_page']); // חדש
        add_shortcode('ssl_logs',       [$this,'shortcode_logs']);
        add_shortcode('ssl_bulk_editor', [$this,'render_shortcode_bulk_editor']);
        add_action('wp_enqueue_scripts', [$this,'assets']);

        add_action('admin_post_nopriv_'.self::SAVE_ACTION,    [$this,'handle_save']);
        add_action('admin_post_'.self::SAVE_ACTION,           [$this,'handle_save']);
        add_action('admin_post_nopriv_'.self::DELETE_ACTION,  [$this,'handle_delete']);
        add_action('admin_post_'.self::DELETE_ACTION,         [$this,'handle_delete']);
        add_action('admin_post_nopriv_'.self::RESTORE_ACTION, [$this,'handle_restore']);
        add_action('admin_post_'.self::RESTORE_ACTION,        [$this,'handle_restore']);
        add_action('admin_post_nopriv_'.self::DELETE_PERMANENT_ACTION, [$this,'handle_delete_permanent']);
        add_action('admin_post_'.self::DELETE_PERMANENT_ACTION,        [$this,'handle_delete_permanent']);
        add_action('admin_post_nopriv_'.self::EMPTY_TRASH_ACTION, [$this,'handle_empty_trash']);
        add_action('admin_post_'.self::EMPTY_TRASH_ACTION,        [$this,'handle_empty_trash']);
        add_action('admin_post_nopriv_'.self::BATCH_CHECK_ACTION, [$this,'handle_batch_check']);
        add_action('admin_post_'.self::BATCH_CHECK_ACTION,        [$this,'handle_batch_check']);
        add_action('admin_post_nopriv_'.self::SINGLE_CHECK_ACTION, [$this,'handle_single_check']);
        add_action('admin_post_'.self::SINGLE_CHECK_ACTION,        [$this,'handle_single_check']);
        add_action('admin_post_nopriv_'.self::EXPORT_ACTION,  [$this,'handle_export']);
        add_action('admin_post_'.self::EXPORT_ACTION,         [$this,'handle_export']);
        add_action('admin_post_nopriv_'.self::IMPORT_ACTION,  [$this,'handle_import']);
        add_action('admin_post_'.self::IMPORT_ACTION,         [$this,'handle_import']);
        add_action('admin_post_nopriv_ssl_regen_token',       [$this,'handle_regen_token']);
        add_action('admin_post_ssl_regen_token',              [$this,'handle_regen_token']);
        add_action('admin_post_nopriv_'.self::ADD_TOKEN_ACTION,    [$this,'handle_add_token']);
        add_action('admin_post_'.self::ADD_TOKEN_ACTION,            [$this,'handle_add_token']);
        add_action('admin_post_nopriv_'.self::MANAGE_TOKEN_ACTION, [$this,'handle_manage_token']);
        add_action('admin_post_'.self::MANAGE_TOKEN_ACTION,        [$this,'handle_manage_token']);
        add_action('admin_post_nopriv_'.self::SAVE_CERT_TYPES_ACTION, [$this,'handle_save_cert_types']);
        add_action('admin_post_'.self::SAVE_CERT_TYPES_ACTION,        [$this,'handle_save_cert_types']);
        add_action('admin_post_nopriv_'.self::SAVE_GENERAL_SETTINGS_ACTION, [$this,'handle_save_general_settings']);
        add_action('admin_post_'.self::SAVE_GENERAL_SETTINGS_ACTION,        [$this,'handle_save_general_settings']);
        add_action('admin_post_nopriv_'.self::TOGGLE_FOLLOW_UP_ACTION, [$this,'handle_toggle_follow_up']);
        add_action('admin_post_'.self::TOGGLE_FOLLOW_UP_ACTION,        [$this,'handle_toggle_follow_up']);
        add_action('admin_post_ssl_save_remote_client',            [$this,'handle_save_remote_client']);

        add_action('wp', [$this,'ensure_cron']);
        add_action(self::CRON_HOOK, [$this,'cron_check_all']);
        add_action(self::CRON_SINGLE_HOOK, [$this,'cron_check_single'], 10, 2);
        add_action(self::CRON_MONITOR_HOOK, [$this,'cron_monitor_connectivity']);
        add_filter('cron_schedules', [$this,'register_custom_schedules']);

        add_filter('empty_trash_days', function(){ return 90; });
        add_action('init', function(){ if(!function_exists('wp_handle_upload')) require_once(ABSPATH.'wp-admin/includes/file.php'); });
        add_action('init', [$this,'ensure_token_store']);
        add_action('init', [$this,'purge_legacy_queue_option']);
        add_action('init', [$this,'ensure_log_store']);
        add_action('init', [$this,'ensure_cert_type_store']);
        add_action('init', [$this,'ensure_general_settings_store']);
        add_action('init', [$this,'maybe_seed_sql_table']);

        add_action('rest_api_init', [$this,'register_rest']);
        add_action('admin_menu',    [$this,'settings_page']);
        register_activation_hook(__FILE__, [$this,'on_activate']);
        add_action('init', [$this,'route_export_helper']);

        add_action('save_post_'.self::CPT, [$this,'hook_sync_post'], 10, 3);
        add_action('trashed_post', [$this,'hook_trash_post']);
        add_action('untrashed_post', [$this,'hook_untrash_post']);
        add_action('before_delete_post', [$this,'hook_delete_post']);
    }

    public function register_cpt() {
        register_post_type(self::CPT, [
            'label' => 'SSL Certificates',
            'public' => false,
            'show_ui' => true,
            'supports' => ['title'],
            'capability_type' => 'post',
            'map_meta_cap' => true,
            'show_in_rest' => false,
        ]);
    }
    public function register_meta() {
        $fields = [
            'client_name'=>'string','site_url'=>'string','expiry_ts'=>'integer','source'=>'string',
            'notes'=>'string','images'=>'array','last_error'=>'string','expiry_ts_checked_at'=>'integer',
            'follow_up'=>'boolean','cert_cn'=>'string','cert_ca'=>'string','cert_type'=>'string','manual_mode'=>'boolean','allow_duplicate_site'=>'boolean',
            'temporary_note' => 'string','temporary_enabled' => 'boolean','management_owner' => 'string','agent_token' => 'string'
        ];
        foreach ($fields as $k=>$t){
            register_post_meta(self::CPT,$k,[
                'type'=> $t==='array'?'array':$t,'single'=>true,'show_in_rest'=>false,'auth_callback'=>'__return_true',
            ]);
        }
    }

    private function get_table_name(){
        global $wpdb;
        return $wpdb->prefix . self::TABLE;
    }

    private function get_queue_table_name(){
        global $wpdb;
        return $wpdb->prefix . self::TABLE_QUEUE;
    }

    private function get_agents_table_name(){
        global $wpdb;
        return $wpdb->prefix . self::TABLE_AGENTS;
    }

    public function ensure_sql_table(){
        global $wpdb;
        $table = $this->get_table_name();
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'publish',
            client_name VARCHAR(255) NOT NULL DEFAULT '',
            site_url TEXT,
            common_name VARCHAR(255) NOT NULL DEFAULT '',
            issuer_name VARCHAR(255) NOT NULL DEFAULT '',
            expiry_ts BIGINT NULL,
            source VARCHAR(50) NOT NULL DEFAULT '',
            cert_type VARCHAR(100) NOT NULL DEFAULT '',
            notes LONGTEXT,
            guide_url TEXT,
            manual_mode TINYINT(1) NOT NULL DEFAULT 0,
            allow_duplicate_site TINYINT(1) NOT NULL DEFAULT 0,
            follow_up TINYINT(1) NOT NULL DEFAULT 0,
            temporary_note LONGTEXT,
            temporary_enabled TINYINT(1) NOT NULL DEFAULT 0,
            management_owner VARCHAR(50) NOT NULL DEFAULT '',
            agent_token VARCHAR(100) NOT NULL DEFAULT '',
            last_error LONGTEXT,
            expiry_ts_checked_at BIGINT NULL,
            images LONGTEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY post_id (post_id),
            KEY status (status),
            KEY cn_status (common_name(190), status),
            KEY issuer_name (issuer_name(190)),
            KEY site_url (site_url(190)),
            KEY cert_type (cert_type(100))
        ) {$charset};";
        dbDelta($sql);
    }

    public function ensure_task_queue_table(){
        global $wpdb;
        $table = $this->get_queue_table_name();
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            site_url TEXT NOT NULL,
            client_name VARCHAR(255) NOT NULL DEFAULT '',
            context VARCHAR(50) NOT NULL DEFAULT 'manual',
            agent_token VARCHAR(100) NOT NULL DEFAULT '',
            enqueued_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
            request_id VARCHAR(100) NOT NULL DEFAULT '',
            status VARCHAR(20) NOT NULL DEFAULT 'queued',
            claimed_at BIGINT UNSIGNED NOT NULL DEFAULT 0,
            attempts INT UNSIGNED NOT NULL DEFAULT 0,
            PRIMARY KEY (id),
            UNIQUE KEY post_id (post_id),
            KEY status_claimed (status, claimed_at),
            KEY request_id (request_id),
            KEY enqueued_at (enqueued_at)
        ) {$charset};";
        dbDelta($sql);

        if($this->queue_table_exists()){
            $count = (int)$wpdb->get_var("SELECT COUNT(*) FROM {$table}");
            if($count === 0){
                $existing = get_option(self::OPTION_QUEUE, []);
                [$normalized, ] = $this->normalize_queue_items($existing);
                $this->replace_queue_rows($normalized);
            }
            delete_option(self::OPTION_QUEUE);
        }
    }

    public function ensure_agent_table(){
        global $wpdb;
        $table = $this->get_agents_table_name();
        $charset = $wpdb->get_charset_collate();
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        $sql = "CREATE TABLE {$table} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            name VARCHAR(190) NOT NULL DEFAULT '',
            token CHAR(64) NOT NULL DEFAULT '',
            last_seen DATETIME NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'offline',
            notes TEXT,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY token (token),
            KEY name (name)
        ) {$charset};";
        dbDelta($sql);
    }

    public function maybe_seed_sql_table(){
        if(get_option(self::OPTION_SQL_SEEDED)){
            return;
        }
        $this->sync_all_posts_to_table();
        update_option(self::OPTION_SQL_SEEDED, time(), false);
    }

    private function sync_all_posts_to_table(){
        $q = new WP_Query([
            'post_type'      => self::CPT,
            'post_status'    => ['publish','draft','pending','trash'],
            'posts_per_page' => -1,
        ]);
        if($q->have_posts()){
            while($q->have_posts()){
                $q->the_post();
                $post = get_post();
                if($post){
                    $this->sync_table_record($post->ID, $post->post_status);
                }
            }
            wp_reset_postdata();
        }
    }

    public function hook_sync_post($post_id, $post, $update){
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        if(defined('DOING_AUTOSAVE') && DOING_AUTOSAVE){
            return;
        }
        if(wp_is_post_revision($post_id)){
            return;
        }
        $this->sync_table_record($post_id, $post->post_status);
    }

    public function hook_trash_post($post_id){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $this->update_table_status($post_id, 'trash');
    }

    public function hook_untrash_post($post_id){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $this->update_table_status($post_id, $post->post_status ?: 'publish');
    }

    public function hook_delete_post($post_id){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $this->delete_table_record($post_id);
    }

    private function update_table_status($post_id, $status){
        global $wpdb;
        $table = $this->get_table_name();
        $wpdb->update($table, ['status' => sanitize_key($status)], ['post_id' => (int)$post_id]);
    }

    private function sync_table_record($post_id, $status = null){
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            return;
        }
        $status = $status ?: $post->post_status;
        $client = (string)get_post_meta($post_id,'client_name',true);
        $site = (string)get_post_meta($post_id,'site_url',true);
        $expiry = get_post_meta($post_id,'expiry_ts',true);
        $source = (string)get_post_meta($post_id,'source',true);
        $cert_type = (string)get_post_meta($post_id,'cert_type',true);
        $notes = (string)get_post_meta($post_id,'notes',true);
        $guide_url = (string)get_post_meta($post_id,'guide_url',true);
        $manual_mode = (int)get_post_meta($post_id,'manual_mode',true);
        $allow_duplicate_site = (int)get_post_meta($post_id,'allow_duplicate_site',true);
        $follow_up = 0;
        $last_error = (string)get_post_meta($post_id,'last_error',true);
        $checked = get_post_meta($post_id,'expiry_ts_checked_at',true);
        $images = get_post_meta($post_id,'images',true);
        $cn = (string)get_post_meta($post_id,'cert_cn',true);
        $ca = (string)get_post_meta($post_id,'cert_ca',true);
        $temporary_note = (string)get_post_meta($post_id,'temporary_note',true);
        $temporary_enabled = (int)get_post_meta($post_id,'temporary_enabled',true);
        $management_owner = (string)get_post_meta($post_id,'management_owner',true);
        $agent_token = (string)get_post_meta($post_id,'agent_token',true);
        if($agent_token === ''){
            $agent_token = $this->get_default_agent_token_id();
        }
        if(!is_array($images)){
            $images = [];
        }
        $image_ids = array_map('intval', $images);
        global $wpdb;
        $table = $this->get_table_name();
        $images_json = wp_json_encode($image_ids);
        if($images_json === false){
            $images_json = '[]';
        }
        $cert_type_value = $this->sanitize_cert_type_key($cert_type);
        if($cert_type_value === ''){
            $default_type = $this->get_default_cert_type_key();
            if($default_type !== ''){
                $cert_type_value = $default_type;
            }
        }
        $data = [
            'post_id' => (int)$post_id,
            'status' => sanitize_key($status ?: 'publish'),
            'client_name' => wp_strip_all_tags($client),
            'site_url' => esc_url_raw($site),
            'common_name' => wp_strip_all_tags($cn),
            'issuer_name' => wp_strip_all_tags($ca),
            'expiry_ts' => $expiry ? (int)$expiry : null,
            'source' => $this->normalize_source_value($source, 'manual'),
            'cert_type' => $cert_type_value,
            'notes' => $notes,
            'guide_url' => $guide_url !== '' ? esc_url_raw($guide_url) : '',
            'manual_mode' => $manual_mode ? 1 : 0,
            'allow_duplicate_site' => $allow_duplicate_site ? 1 : 0,
            'follow_up' => $follow_up ? 1 : 0,
            'last_error' => $last_error,
            'expiry_ts_checked_at' => $checked ? (int)$checked : null,
            'images' => $images_json,
            'temporary_note' => $temporary_note,
            'temporary_enabled' => $temporary_enabled ? 1 : 0,
            'management_owner' => $this->sanitize_management_owner($management_owner),
            'agent_token' => sanitize_text_field($agent_token),
        ];
        $formats = ['%d','%s','%s','%s','%s','%s','%d','%s','%s','%s','%s','%d','%d','%d','%s','%d','%s','%s','%d','%s','%s'];
        $existing = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table} WHERE post_id = %d", $post_id));
        if($existing){
            $wpdb->update($table, $data, ['post_id' => (int)$post_id], $formats, ['%d']);
        } else {
            $wpdb->insert($table, $data, $formats);
        }
        if(!$expiry){
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET expiry_ts = NULL WHERE post_id = %d", $post_id));
        }
        if(!$checked){
            $wpdb->query($wpdb->prepare("UPDATE {$table} SET expiry_ts_checked_at = NULL WHERE post_id = %d", $post_id));
        }
    }

    private function delete_table_record($post_id){
        global $wpdb;
        $table = $this->get_table_name();
        $wpdb->delete($table, ['post_id' => (int)$post_id], ['%d']);
    }

    private function fetch_certificates($args = []){
        global $wpdb;
        $defaults = [
            'page' => 1,
            'per_page' => 25,
            'search' => '',
            'status' => ['publish','draft','pending'],
            'orderby' => 'expiry_ts',
            'order' => 'ASC',
            'missing_only' => false,
            'filter_client' => '',
            'filter_site' => '',
            'filter_cn' => '',
            'filter_cert_type' => '',
            'filter_management' => '',
            'filter_manual' => '',
        ];
        $args = wp_parse_args($args, $defaults);
        $table = $this->get_table_name();
        $where = ['1=1'];
        $params = [];
        $statuses = array_filter((array)$args['status']);
        if(empty($statuses)){
            $statuses = ['publish'];
        }
        $placeholders = implode(',', array_fill(0, count($statuses), '%s'));
        $where[] = "status IN ({$placeholders})";
        $params = array_merge($params, array_map('sanitize_key', $statuses));

        if($args['search'] !== ''){
            $search = '%' . $wpdb->esc_like($args['search']) . '%';
            $where[] = "(client_name LIKE %s OR site_url LIKE %s OR common_name LIKE %s OR issuer_name LIKE %s)";
            $params[] = $search;
            $params[] = $search;
            $params[] = $search;
            $params[] = $search;
        }
        if(!empty($args['missing_only'])){
            $where[] = "(expiry_ts IS NULL OR expiry_ts = 0)";
        }
        if($args['filter_client'] !== ''){
            $search = '%' . $wpdb->esc_like($args['filter_client']) . '%';
            $where[] = "client_name LIKE %s";
            $params[] = $search;
        }
        if($args['filter_site'] !== ''){
            $search = '%' . $wpdb->esc_like($args['filter_site']) . '%';
            $where[] = "site_url LIKE %s";
            $params[] = $search;
        }
        if($args['filter_cn'] !== ''){
            $search = '%' . $wpdb->esc_like($args['filter_cn']) . '%';
            $where[] = "common_name LIKE %s";
            $params[] = $search;
        }
        if($args['filter_cert_type'] !== ''){
            $where[] = "cert_type = %s";
            $params[] = $this->sanitize_cert_type_key($args['filter_cert_type']);
        }
        if($args['filter_management'] !== ''){
            $where[] = "management_owner = %s";
            $params[] = $this->sanitize_management_owner($args['filter_management']);
        }
        if($args['filter_manual'] !== ''){
            $where[] = "manual_mode = %d";
            $params[] = (int)$args['filter_manual'] ? 1 : 0;
        }
        $order = strtoupper($args['order']) === 'DESC' ? 'DESC' : 'ASC';
        $allowed_orderby = [
            'client_name' => 'client_name',
            'site_url' => 'site_url',
            'expiry_ts' => 'expiry_ts',
            'common_name' => 'common_name',
            'cert_type' => 'cert_type',
            'management_owner' => 'management_owner',
        ];
        $default_orderby = 'expiry_ts';
        $orderby = isset($allowed_orderby[$args['orderby']]) ? $allowed_orderby[$args['orderby']] : $default_orderby;
        $where_sql = 'WHERE ' . implode(' AND ', $where);
        $limit = max(1, (int)$args['per_page']);
        $offset = max(0, ((int)$args['page'] - 1) * $limit);
        if($orderby === 'expiry_ts'){
            $order_sql = "ORDER BY (common_name = '' OR common_name IS NULL) ASC, (expiry_ts IS NULL) ASC, expiry_ts {$order}, client_name ASC";
        } else {
            $order_sql = "ORDER BY {$orderby} {$order}, client_name ASC";
        }
        $limit_sql = "LIMIT %d OFFSET %d";
        $rows_sql = "SELECT * FROM {$table} {$where_sql} {$order_sql} {$limit_sql}";
        $rows_params = array_merge($params, [$limit, $offset]);
        $count_sql = "SELECT COUNT(*) FROM {$table} {$where_sql}";
        $prepared_rows = $wpdb->prepare($rows_sql, $rows_params);
        $rows = $wpdb->get_results($prepared_rows, ARRAY_A);
        if(!empty($params)){
            $total = $wpdb->get_var($wpdb->prepare($count_sql, $params));
        } else {
            $total = $wpdb->get_var($count_sql);
        }
        $count_with_expiry_sql = $count_sql . " AND expiry_ts IS NOT NULL";
        if(!empty($params)){
            $total_with_expiry = $wpdb->get_var($wpdb->prepare($count_with_expiry_sql, $params));
        } else {
            $total_with_expiry = $wpdb->get_var($count_with_expiry_sql);
        }
        foreach($rows as &$row){
            $row['follow_up'] = false;
            $row['manual_mode'] = !empty($row['manual_mode']);
            $row['allow_duplicate_site'] = !empty($row['allow_duplicate_site']);
            $row['images'] = $row['images'] ? json_decode($row['images'], true) : [];
            if(!is_array($row['images'])){
                $row['images'] = [];
            }
            if(!isset($row['guide_url']) || $row['guide_url'] === null){
                $row['guide_url'] = '';
            }
        }
        return [
            'rows' => $rows,
            'total' => (int)$total,
            'total_with_expiry' => (int)$total_with_expiry,
        ];
    }

    private function get_certificate_status_counts(){
        global $wpdb;
        $table = $this->get_table_name();
        $now = current_time('timestamp');
        $thirty_days = $now + (30 * DAY_IN_SECONDS);
        $ninety_days = $now + (90 * DAY_IN_SECONDS);
        $statuses = ['publish','draft','pending'];
        $placeholders = implode(',', array_fill(0, count($statuses), '%s'));
        $sql = "SELECT
            SUM(CASE WHEN expiry_ts IS NULL OR expiry_ts = 0 THEN 1 ELSE 0 END) AS grey,
            SUM(CASE WHEN expiry_ts IS NOT NULL AND expiry_ts <= %d THEN 1 ELSE 0 END) AS red,
            SUM(CASE WHEN expiry_ts IS NOT NULL AND expiry_ts > %d AND expiry_ts <= %d THEN 1 ELSE 0 END) AS yellow,
            SUM(CASE WHEN expiry_ts IS NOT NULL AND expiry_ts > %d THEN 1 ELSE 0 END) AS green
        FROM {$table}
        WHERE status IN ({$placeholders})";
        $params = array_merge([
            $thirty_days,
            $thirty_days,
            $ninety_days,
            $ninety_days,
        ], array_map('sanitize_key', $statuses));
        $prepared = $wpdb->prepare($sql, $params);
        $row = $wpdb->get_row($prepared, ARRAY_A);
        if(!$row){
            return [
                'red' => 0,
                'yellow' => 0,
                'green' => 0,
                'grey' => 0,
            ];
        }
        return [
            'red' => isset($row['red']) ? (int)$row['red'] : 0,
            'yellow' => isset($row['yellow']) ? (int)$row['yellow'] : 0,
            'green' => isset($row['green']) ? (int)$row['green'] : 0,
            'grey' => isset($row['grey']) ? (int)$row['grey'] : 0,
        ];
    }

    private function get_certificate_scope_counts(){
        global $wpdb;
        $table = $this->get_table_name();
        $active_sql = "SELECT COUNT(*) AS total, SUM(CASE WHEN expiry_ts IS NOT NULL AND expiry_ts > 0 THEN 1 ELSE 0 END) AS with_expiry FROM {$table} WHERE status != 'trash'";
        $archive_sql = "SELECT COUNT(*) AS total, SUM(CASE WHEN expiry_ts IS NOT NULL AND expiry_ts > 0 THEN 1 ELSE 0 END) AS with_expiry FROM {$table} WHERE status = 'trash'";
        $active_row = $wpdb->get_row($active_sql, ARRAY_A);
        $archive_row = $wpdb->get_row($archive_sql, ARRAY_A);
        return [
            'active_total' => isset($active_row['total']) ? (int)$active_row['total'] : 0,
            'active_with_expiry' => isset($active_row['with_expiry']) ? (int)$active_row['with_expiry'] : 0,
            'archive_total' => isset($archive_row['total']) ? (int)$archive_row['total'] : 0,
            'archive_with_expiry' => isset($archive_row['with_expiry']) ? (int)$archive_row['with_expiry'] : 0,
        ];
    }

    private function build_sort_link($column, $label, $current_sort, $current_order, $preserved_query){
        $column = sanitize_key($column);
        $current_sort = sanitize_key($current_sort);
        $current_order = strtoupper($current_order) === 'DESC' ? 'DESC' : 'ASC';
        $next_order = ($current_sort === $column && $current_order === 'ASC') ? 'DESC' : 'ASC';
        $query = $preserved_query;
        $query['ssl_sort'] = $column;
        $query['ssl_order'] = $next_order;
        $url = esc_url(add_query_arg($query));
        $indicator = '';
        if($current_sort === $column){
            $indicator = $current_order === 'ASC' ? ' ↑' : ' ↓';
        }
        return '<a href="'.$url.'" class="ssl-sort-link" data-ssl-sort="'.esc_attr($column).'" data-ssl-next-order="'.esc_attr(strtolower($next_order)).'">'.esc_html($label.$indicator).'</a>';
    }

    private function build_bulk_sort_link($column, $label, $current_sort, $current_order, $preserved_query){
        $column = sanitize_key($column);
        $current_sort = sanitize_key($current_sort);
        $current_order = strtoupper($current_order) === 'DESC' ? 'DESC' : 'ASC';
        $next_order = ($current_sort === $column && $current_order === 'ASC') ? 'DESC' : 'ASC';
        $query = $preserved_query;
        $query['ssl_bulk_sort'] = $column;
        $query['ssl_bulk_order'] = $next_order;
        $url = esc_url(add_query_arg($query));
        $indicator = '';
        if($current_sort === $column){
            $indicator = $current_order === 'ASC' ? ' ↑' : ' ↓';
        }
        return '<a href="'.$url.'" class="ssl-sort-link" data-ssl-sort="'.esc_attr($column).'" data-ssl-next-order="'.esc_attr(strtolower($next_order)).'">'.esc_html($label.$indicator).'</a>';
    }

    private function parse_import_file($file_path, $file_name){
        $ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
        if($ext === 'xlsx'){
            if(!class_exists('SimpleXLSX')){
                require_once __DIR__.'/simple_xlsx.php';
            }
            $xlsx = SimpleXLSX::parse($file_path);
            if(!$xlsx){
                return new WP_Error('import_parse', SimpleXLSX::parseError() ?: 'Excel parsing error');
            }
            $raw_rows = $xlsx->rows();
        } else {
            $raw_rows = $this->read_csv_rows($file_path);
        }
        if(empty($raw_rows)){
            return [];
        }
        return $this->normalize_import_rows($raw_rows);
    }

    private function read_csv_rows($file_path){
        $rows = [];
        $contents = file_get_contents($file_path);
        if($contents === false){
            return $rows;
        }
        $encodings = ['UTF-8','UTF-16','UTF-16LE','UTF-16BE','CP1255','ISO-8859-8','Windows-1252'];
        if(function_exists('mb_list_encodings')){
            $supported = array_map('strtoupper', mb_list_encodings());
            $encodings = array_values(array_filter($encodings, function($enc) use ($supported){
                return in_array(strtoupper($enc), $supported, true);
            }));
        }
        if(empty($encodings)){
            $encodings = ['UTF-8'];
        }
        $encoding = function_exists('mb_detect_encoding') ? mb_detect_encoding($contents, $encodings, true) : false;
        if($encoding && strtoupper($encoding) !== 'UTF-8' && function_exists('mb_convert_encoding')){
            $contents = mb_convert_encoding($contents, 'UTF-8', $encoding);
        }
        if(strpos($contents, "\xEF\xBB\xBF") === 0){
            $contents = substr($contents, 3);
        }
        $stream = fopen('php://temp', 'r+');
        fwrite($stream, $contents);
        rewind($stream);
        while(($line = fgetcsv($stream)) !== false){
            $rows[] = $line;
        }
        fclose($stream);
        return $rows;
    }

    private function normalize_import_rows($rows){
        $normalized = [];
        if(empty($rows)){
            return $normalized;
        }
        $header_map = $this->map_import_header($rows[0]);
        if($header_map){
            array_shift($rows);
        } else {
            $first = isset($rows[0]) && is_array($rows[0]) ? $rows[0] : [];
            $count = count($first);
            if($count >= 8){
                $header_map = [
                    'client_name' => 0,
                    'site_url' => 1,
                    'expiry_date' => 2,
                    'common_name' => 3,
                    'cert_type' => 4,
                    'notes' => 5,
                    'guide_url' => 6,
                    'manual_mode' => 7,
                ];
            } else {
                $header_map = [
                    'client_name' => 0,
                    'site_url' => 1,
                    'expiry_date' => 2,
                    'notes' => 3,
                ];
                if($count >= 7){
                    $header_map['cert_type'] = 4;
                } elseif($count >= 6){
                    $header_map['cert_type'] = 4;
                }
            }
        }
        $default_type = $this->get_default_cert_type_key();
        foreach($rows as $row){
            if(!is_array($row)){
                continue;
            }
            $flat = array_map(function($value){
                return trim((string)$value);
            }, $row);
            $is_empty = true;
            foreach($flat as $value){
                if($value !== ''){
                    $is_empty = false;
                    break;
                }
            }
            if($is_empty){
                continue;
            }
            $client = $this->value_from_row($flat, $header_map, 'client_name');
            $site = $this->value_from_row($flat, $header_map, 'site_url');
            $expiry_raw = $this->value_from_row($flat, $header_map, 'expiry_date');
            $cn = $this->value_from_row($flat, $header_map, 'common_name');
            $cert_type_raw = $this->value_from_row($flat, $header_map, 'cert_type');
            $notes = $this->value_from_row($flat, $header_map, 'notes');
            $guide_raw = $this->value_from_row($flat, $header_map, 'guide_url');
            $manual_raw = $this->value_from_row($flat, $header_map, 'manual_mode');
            $date_norm = $this->normalize_import_date($expiry_raw);
            $expiry_ts = $date_norm ? strtotime($date_norm.' 00:00:00') : null;
            $cert_type = $this->sanitize_cert_type_key($cert_type_raw, $default_type);
            if($cert_type === '' && $default_type !== ''){
                $cert_type = $default_type;
            }
            $normalized[] = [
                'client_name' => wp_strip_all_tags($client),
                'site_url' => $this->sanitize_url($site),
                'expiry_date' => $date_norm,
                'expiry_ts' => $expiry_ts ?: null,
                'common_name' => wp_strip_all_tags($cn),
                'cert_type' => $cert_type,
                'notes' => sanitize_textarea_field($notes),
                'guide_url' => $this->sanitize_url($guide_raw),
            'manual_mode' => $this->interpret_bool($manual_raw),
        ];
    }
        return $normalized;
    }

    private function map_import_header($header_row){
        if(empty($header_row) || !is_array($header_row)){
            return null;
        }
        $normalized = [];
        foreach($header_row as $index => $value){
            $label = $this->lower((string)$value);
            if($label !== ''){
                $normalized[$label] = $index;
            }
        }
        $aliases = [
            'client_name' => ['client_name','שם הלקוח','לקוח'],
            'site_url' => ['site_url','url','כתובת','אתר'],
            'expiry_date' => ['expiry_date','expiry','תוקף','תאריך תפוגה'],
            'common_name' => ['common_name','cn','שם תעודה'],
            'cert_type' => ['cert_type','type','סוג','סוג תעודה'],
            'notes' => ['notes','הערות'],
            'guide_url' => ['guide','guide_url','מדריך','קישור מדריך'],
            'manual_mode' => ['manual_mode','manual','ידני'],
        ];
        $map = [];
        foreach($aliases as $field => $options){
            foreach($options as $alias){
                $alias_key = $this->lower($alias);
                if(isset($normalized[$alias_key])){
                    $map[$field] = $normalized[$alias_key];
                    break;
                }
            }
        }
        if(isset($map['client_name']) && isset($map['site_url'])){
            return $map;
        }
        return null;
    }

    private function value_from_row($row, $map, $field){
        if(isset($map[$field]) && isset($row[$map[$field]])){
            return $row[$map[$field]];
        }
        return '';
    }

    private function normalize_import_date($value){
        $value = trim((string)$value);
        if($value === ''){
            return '';
        }
        if(preg_match('/^\d{4}-\d{2}-\d{2}$/', $value)){
            return $value;
        }
        $ts = strtotime($value);
        if($ts){
            return gmdate('Y-m-d', $ts);
        }
        return '';
    }

    private function normalize_source_value($value, $default = 'auto'){
        $value = sanitize_key((string)$value);
        if(in_array($value, ['auto','manual','agent','server'], true)){
            return $value;
        }
        return $default;
    }

    private function interpret_bool($value){
        $value = $this->lower($value);
        if($value === ''){
            return false;
        }
        return in_array($value, ['1','true','yes','y','on','כן','חיובי'], true);
    }

    private function lower($value){
        $value = trim((string)$value);
        if($value === ''){
            return '';
        }
        if(function_exists('mb_strtolower')){
            return mb_strtolower($value, 'UTF-8');
        }
        return strtolower($value);
    }

    public function assets() {
        $css = <<<'CSS'
.ssl-manager{direction:rtl;font-family:"Assistant","Rubik",Arial,sans-serif;background:#fff;border-radius:16px;box-shadow:0 12px 30px rgba(15,23,42,.08);padding:24px;margin:24px 0;max-width:100%;width:100%;display:flex;flex-direction:column;gap:24px;}
@media (max-width:768px){.ssl-manager{padding:18px;}}
.ssl-manager__header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:16px;padding-bottom:16px;border-bottom:1px solid #e2e8f0;}
.ssl-manager__header--tokens{align-items:flex-start;}
.ssl-manager__title h2{margin:0;color:#0f172a;font-size:1.75rem;font-weight:700;}
.ssl-manager__subtitle{color:#64748b;font-size:.95rem;margin-top:4px;}
.ssl-manager__header-actions{display:flex;gap:10px;align-items:center;}
.ssl-inline-form{display:inline-flex;margin:0;}
.ssl-inline-form .ssl-btn{white-space:nowrap;}
.ssl-status-bubbles{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 4px;}
.ssl-status-bubble{flex:1 1 160px;min-width:140px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:.65rem .8rem;display:flex;flex-direction:column;gap:4px;box-shadow:0 6px 16px rgba(15,23,42,.05);}
.ssl-status-bubble__label{font-size:.8rem;font-weight:600;color:#475569;}
.ssl-status-bubble__value{font-size:1.35rem;font-weight:700;color:#0f172a;}
.ssl-status-bubble__description{font-size:.78rem;color:#64748b;}
.ssl-status-bubble--red{background:#fef2f2;border-color:#fecaca;}
.ssl-status-bubble--red .ssl-status-bubble__value{color:#b91c1c;}
.ssl-status-bubble--yellow{background:#fffbeb;border-color:#fde68a;}
.ssl-status-bubble--yellow .ssl-status-bubble__value{color:#b45309;}
.ssl-status-bubble--green{background:#ecfdf3;border-color:#bbf7d0;}
.ssl-status-bubble--green .ssl-status-bubble__value{color:#15803d;}
.ssl-status-bubble--grey{background:#f1f5f9;border-color:#e2e8f0;}
.ssl-status-bubble--grey .ssl-status-bubble__value{color:#475569;}
.ssl-total-row{margin:0 0 8px 0;padding:10px 14px;border-radius:12px;background:#eef2ff;color:#0f172a;font-weight:600;border:1px solid #cbd5f5;display:flex;justify-content:flex-start;gap:8px;box-shadow:inset 0 1px 0 rgba(255,255,255,.65);}
.ssl-total-row strong{font-size:1.05rem;}
.ssl-total-row__details{font-weight:500;color:#475569;font-size:.95rem;}
.ssl-alert{margin:12px 0;padding:.65rem 1rem;border-radius:10px;font-size:.9rem;font-weight:600;}
.ssl-alert--success{background:#dcfce7;color:#065f46;}
.ssl-alert--warning{background:#fef3c7;color:#92400e;}
.ssl-toolbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:12px;}
.ssl-footer-tools{padding-top:16px;border-top:1px solid #e2e8f0;display:flex;flex-direction:column;gap:16px;}
.ssl-toolbar--bottom{width:100%;}
.ssl-toolbar__group,.ssl-toolbar__import{display:flex;gap:10px;align-items:center;justify-content:flex-start;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px;}
.ssl-toolbar__group--end{justify-content:flex-end;}
.ssl-toolbar__import{justify-content:space-between;flex-wrap:wrap;}
.ssl-toolbar--filters .ssl-toolbar__group{background:transparent;border:none;padding:0;max-width:320px;}
.ssl-toolbar--filters .ssl-toolbar__group--toggles{max-width:none;justify-content:flex-start;width:100%;gap:8px;}
.ssl-toolbar--filters label{display:flex;flex-direction:column;gap:6px;width:100%;color:#475569;font-weight:600;font-size:.85rem;}
.ssl-toolbar--filters input[type=search]{border:1px solid #cbd5f5;border-radius:10px;padding:.4rem .6rem;background:#fff;color:#1f2937;font-size:.9rem;}
.ssl-bulk-form{display:flex;justify-content:flex-end;width:100%;}
.ssl-toolbar__import input[type=file]{flex:1 1 180px;font-size:.9rem;color:#475569;}
.ssl-page-size{display:flex;align-items:center;gap:8px;background:#f8fafc;border:1px solid #cbd5f5;border-radius:10px;padding:.14rem .6rem;font-size:.9rem;color:#1e293b;}
.ssl-page-size label{display:flex;align-items:center;gap:6px;margin:0;font-weight:600;color:#1e293b;}
.ssl-page-size select{border:none;background:transparent;font-size:.95rem;font-weight:600;color:#1e293b;min-width:80px;padding:0;height:100%;}
.ssl-page-size select:focus{outline:none;}
.ssl-pagination{margin-top:16px;display:flex;justify-content:center;}
.ssl-pagination__list{display:flex;gap:6px;list-style:none;margin:0;padding:0;}
.ssl-pagination__item .page-numbers{display:inline-flex;align-items:center;justify-content:center;padding:.45rem .9rem;border-radius:10px;border:1px solid #cbd5f5;background:#fff;color:#1e293b;font-weight:600;min-width:42px;text-decoration:none;transition:background .15s ease,color .15s ease,box-shadow .15s ease;}
.ssl-pagination__item .page-numbers:hover{background:#eef2ff;color:#1e3a8a;}
.ssl-pagination__item .page-numbers.current{background:linear-gradient(135deg,#4c6ef5,#364fc7);color:#fff;border-color:transparent;box-shadow:0 10px 18px rgba(54,79,199,.28);}
.ssl-btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;padding:.2rem .7rem;border-radius:10px;border:1px solid transparent;font-weight:600;font-size:.95rem;cursor:pointer;text-decoration:none;transition:transform .15s ease,box-shadow .15s ease,background .15s ease,color .15s ease;}
.ssl-btn-compact{padding:.15rem .55rem;font-size:.85rem;border-radius:8px;}
.ssl-btn:focus{outline:2px solid #c7d2fe;outline-offset:2px;}
.ssl-btn.is-active{box-shadow:0 0 0 3px rgba(76,110,245,.25);}
.ssl-btn-primary{background:linear-gradient(135deg,#4c6ef5,#364fc7);color:#fff;box-shadow:0 8px 16px rgba(76,110,245,.28);}
.ssl-btn-primary:hover{transform:translateY(-1px);box-shadow:0 10px 22px rgba(54,79,199,.32);}
.ssl-btn-surface{background:#fff;border-color:#cbd5f5;color:#1e3a8a;box-shadow:0 4px 12px rgba(15,23,42,.08);}
.ssl-btn-surface:hover{background:#f8fafc;}
.ssl-btn-outline{background:transparent;border-color:#cbd5f5;color:#1f2937;}
.ssl-btn-outline:hover{background:#f8fafc;}
.ssl-btn-ghost{background:transparent;border:none;color:#475569;padding:0 .6rem;}
.ssl-btn-icon{width:32px;height:32px;padding:0;border-radius:50%;font-size:1rem;line-height:1;}
.ssl-btn-danger{background:linear-gradient(135deg,#f87171,#ef4444);color:#fff;box-shadow:0 8px 16px rgba(239,68,68,.24);}
.ssl-table-scroll{max-height:420px;overflow-y:auto;position:relative;border-radius:16px;border:1px solid #e2e8f0;}
.ssl-table-scroll--tokens{max-height:none;overflow:visible;}
.ssl-table-scroll .ssl-table{border-radius:0;box-shadow:none;}
.ssl-table-scroll .ssl-table thead th{position:sticky;top:0;z-index:2;}
.ssl-table{width:100%;border-collapse:separate;border-spacing:0;background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 14px 28px rgba(15,23,42,.05);}
.ssl-table thead th{background:#f1f5f9;color:#0f172a;padding:14px 12px;text-align:right;font-size:.95rem;font-weight:700;border-bottom:1px solid #e2e8f0;}
.ssl-table tbody td{padding:14px 12px;border-bottom:1px solid #e2e8f0;vertical-align:middle;color:#1e293b;font-size:.95rem;text-align:right;}
.ssl-select-cell{text-align:center;width:48px;}
.ssl-select-cell input,.ssl-select-all input{transform:scale(1.05);}
.ssl-select-all{display:flex;justify-content:center;align-items:center;}
.ssl-table thead th:nth-child(3),.ssl-table tbody td:nth-child(3),.ssl-table thead th:nth-child(4),.ssl-table tbody td:nth-child(4){text-align:left;}
.ssl-table tbody td:nth-child(3),.ssl-table tbody td:nth-child(4){direction:ltr;}
.ssl-table thead th:nth-child(5),.ssl-table tbody td:nth-child(5){text-align:left;direction:ltr;white-space:nowrap;}
.ssl-table thead th:nth-child(7),.ssl-table tbody td:nth-child(7){text-align:left;}
.ssl-table tbody tr:nth-child(even){background:#f8fafc;}
.ssl-table tbody tr:hover{background:#eef2ff;}
.ssl-table tbody tr:last-child td{border-bottom:none;}
.ssl-table tbody td img{max-width:60px;max-height:60px;margin:2px;border-radius:8px;box-shadow:0 4px 10px rgba(15,23,42,.12);}
.ssl-sort-link{color:inherit;text-decoration:none;display:inline-flex;align-items:center;gap:4px;font-weight:700;}
.ssl-sort-link:hover{color:#1e3a8a;}
.ssl-client-cell{display:flex;align-items:flex-start;gap:10px;}
.ssl-client-cell__controls{display:flex;flex-direction:column;align-items:center;gap:4px;}
.ssl-client-cell__controls .ssl-btn{padding:0 .45rem;}
.ssl-client-cell__text{display:flex;flex-direction:column;align-items:flex-start;gap:4px;}
.ssl-client-cell--group .ssl-client-cell__text{gap:2px;}
.ssl-client-cell__name{font-weight:600;color:#0f172a;display:inline-block;}
.ssl-details-placeholder{display:inline-flex;width:28px;height:28px;}
.ssl-group-placeholder{display:inline-block;min-width:16px;color:#cbd5f5;}
.ssl-date-field{display:flex;flex-direction:column;gap:6px;color:#475569;font-weight:600;font-size:.85rem;}
.ssl-date-field__controls{display:flex;gap:8px;align-items:center;flex-wrap:wrap;}
.ssl-date-field__controls input[type=date]{flex:1 1 160px;min-width:0;}
.ssl-date-field__controls .ssl-btn{white-space:nowrap;flex:0 0 auto;}
.ssl-color-cell{min-width:110px;text-align:left;direction:ltr;white-space:nowrap;}
.ssl-color-pill{display:inline-flex;align-items:center;justify-content:center;gap:8px;padding:.2rem .7rem;border-radius:999px;font-weight:700;font-size:.8rem;min-width:90px;text-align:center;background:var(--ssl-pill-color,#1e293b);color:var(--ssl-pill-text,#fff);box-shadow:0 6px 14px rgba(15,23,42,.14);}
.ssl-row--stale td{background:#fee2e2!important;}
.ssl-details-toggle{font-weight:700;font-size:.9rem;}
.ssl-group-toggle{border:none;background:#e2e8f0;color:#1e3a8a;border-radius:999px;padding:.2rem .6rem;font-size:.8rem;font-weight:700;cursor:pointer;margin:0;}
.ssl-group-toggle[aria-expanded="true"]{background:#1e3a8a;color:#fff;}
.ssl-group-meta{font-size:.75rem;color:#64748b;margin-top:4px;}
.ssl-client-cell__type{margin-bottom:4px;}
.ssl-type-chip{display:inline-flex;align-items:center;gap:6px;background:var(--ssl-type-color,#1e293b);color:#fff;font-weight:600;padding:.2rem .6rem;border-radius:999px;font-size:.75rem;box-shadow:0 6px 16px rgba(15,23,42,.2);}
.ssl-type-chip__dot{width:8px;height:8px;border-radius:50%;background:#fff;display:inline-block;}
.ssl-table tr[data-ssl-group-child]{background:#f8fafc;}
.ssl-table tr[data-ssl-group-child] td:nth-child(2){padding-right:36px;position:relative;}
.ssl-table tr[data-ssl-group-child] td:nth-child(2):before{content:'↳';position:absolute;right:12px;top:50%;transform:translateY(-50%);color:#94a3b8;}
.ssl-row-details td:first-child{padding-right:16px;}
.ssl-row-details td:first-child:before{display:none;}
.ssl-row-details td{background:#f1f5f9;font-size:.85rem;color:#475569;}
.ssl-row-details__wrap{display:flex;flex-wrap:wrap;gap:16px;align-items:flex-start;}
.ssl-row-details__section{flex:1 1 220px;display:flex;flex-direction:column;gap:8px;}
.ssl-row-details__section--actions{flex:0 0 160px;display:flex;flex-direction:column;align-items:flex-start;gap:8px;}
.ssl-row-details__section h4{margin:0;font-size:.85rem;color:#0f172a;}
.ssl-row-details__section--actions h4{align-self:flex-start;}
.ssl-row-details__images{display:flex;flex-wrap:wrap;gap:8px;}
.ssl-row-details__images a{display:inline-flex;}
.ssl-row-details__error{color:#b91c1c;font-weight:600;}
.ssl-row-details__meta{display:flex;flex-direction:column;gap:6px;}
.ssl-row-details__meta-item{display:flex;align-items:center;gap:6px;font-size:.85rem;color:#334155;}
.ssl-row-details__meta-label{font-weight:700;color:#0f172a;}
.ssl-row-details__meta-value{direction:ltr;text-align:left;color:#1e293b;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.ssl-row-details__actions{display:flex;flex-direction:column;gap:6px;align-items:flex-start;}
.ssl-row-details__actions .ssl-btn{width:auto;justify-content:center;min-width:0;}
.ssl-row-details__actions form{display:flex;}
.ssl-btn--compact{padding:.15rem .5rem;font-size:.8rem;}
.ssl-guide-link{white-space:nowrap;}
.ssl-manager--compact .ssl-table thead th,.ssl-manager--compact .ssl-table tbody td{padding:8px 10px;font-size:.85rem;}
.ssl-manager--compact .ssl-btn{padding:.14rem .45rem;font-size:.85rem;}
.ssl-manager--compact .ssl-toolbar__group,.ssl-manager--compact .ssl-toolbar__import{gap:6px;padding:8px;}
.ssl-manager--compact .ssl-card,.ssl-manager--compact .ssl-card__footer{gap:10px;}
.ssl-badge{display:inline-flex;align-items:center;justify-content:center;padding:.35rem .85rem;border-radius:999px;font-weight:700;min-width:72px;box-shadow:inset 0 -2px 0 rgba(255,255,255,.6);}
.ssl-green{background:#dcfce7;color:#0f766e;}
.ssl-yellow{background:#fef3c7;color:#b45309;}
.ssl-red{background:#fee2e2;color:#b91c1c;}
.ssl-form,.ssl-card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:20px;box-shadow:0 10px 24px rgba(15,23,42,.06);display:flex;flex-direction:column;gap:16px;}
.ssl-card__header{display:flex;justify-content:space-between;align-items:center;gap:12px;}
.ssl-card__header h3{margin:0;font-size:1.1rem;color:#0f172a;}
.ssl-card__body{display:grid;gap:12px;}
.ssl-card__body--compact{grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:10px 16px;}
.ssl-general-grid{grid-template-columns:repeat(auto-fit,minmax(260px,1fr));}
.ssl-card__body--compact label{margin:0;}
.ssl-card__body--compact .ssl-form-span-2{grid-column:span 2;}
.ssl-manager--compact .ssl-card__body--compact{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));}
@media (max-width:640px){
.ssl-card__body--compact .ssl-form-span-2{grid-column:span 1;}
}
.ssl-form-full{grid-column:1/-1;}
.ssl-form-full textarea{min-height:80px;}
.ssl-card--form label.ssl-card__inline{flex-direction:row;align-items:center;gap:12px;}
.ssl-card--form label.ssl-card__inline span{flex:1;}
.ssl-token-row{display:flex;gap:12px;align-items:center;flex-wrap:wrap;}
.ssl-token-input{flex:1 1 320px;border:1px solid #d0d5dd;border-radius:10px;padding:.55rem .75rem;background:#f8fafc;font-family:monospace;font-size:1rem;color:#0f172a;}
.ssl-token-input:focus{outline:2px solid #c7d2fe;outline-offset:2px;}
.ssl-token-form{display:flex;gap:10px;flex-wrap:wrap;}
.ssl-token-form--stack{flex-direction:column;align-items:stretch;gap:16px;}
.ssl-token-manage{display:flex;flex-direction:column;gap:16px;}
.ssl-token-layout{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:12px;align-items:start;}
.ssl-card--token .ssl-card__body label{width:100%;}
.ssl-card--links{border:none;box-shadow:none;padding:0;margin-top:16px;}
.ssl-card--links .ssl-card__footer{padding:0;}
.ssl-card__footer--links{justify-content:flex-start;}
.ssl-card__footer{display:flex;gap:10px;align-items:center;flex-wrap:wrap;justify-content:flex-start;}
.ssl-form-warning{display:block;color:#b91c1c;font-size:.8rem;margin-top:4px;}
.ssl-checkbox--inline{display:inline-flex;align-items:center;gap:6px;font-weight:600;white-space:nowrap;}
.ssl-checkbox--inline input{margin:0;}
.ssl-checkbox--sub{margin-top:4px;font-weight:500;font-size:.85rem;color:#334155;}
.ssl-input-error{border-color:#ef4444!important;box-shadow:0 0 0 2px rgba(239,68,68,.2);}
.ssl-inline-delete,.ssl-inline-refresh{display:inline-flex;margin:0;}
.ssl-inline-delete button,.ssl-inline-refresh button{min-width:0;}
.ssl-card--form{padding:16px;gap:12px;}
.ssl-card--form label{display:flex;flex-direction:column;gap:4px;color:#475569;font-weight:600;font-size:.85rem;}
.ssl-form-toggle{flex-direction:row;align-items:center;gap:8px;}
.ssl-card--form input[type=text],.ssl-card--form input[type=url],.ssl-card--form input[type=file],.ssl-card--form textarea,.ssl-card--form select{border:1px solid #d0d5dd;border-radius:10px;padding:.25rem .5rem;background:#f8fafc;color:#1f2937;font-size:.9rem;}
.ssl-card--form textarea{min-height:80px;resize:vertical;}
.ssl-card--form input[type=file]{padding:.45rem;}
.ssl-card--form input[type=checkbox]{margin-left:6px;transform:scale(1.1);}
.ssl-card--form .ssl-note{margin-top:4px;}
.ssl-note{font-size:.85rem;color:#64748b;}
.ssl-token-create{display:flex;flex-direction:column;gap:12px;}
.ssl-token-create__fields{display:flex;flex-wrap:wrap;gap:12px;align-items:flex-end;}
.ssl-token-create__fields label{flex:1 1 240px;margin:0;gap:4px;}
.ssl-token-create__fields label span{display:block;color:#475569;font-weight:600;font-size:.85rem;margin-bottom:2px;}
.ssl-token-create__fields input[type=text]{width:100%;padding:.5rem .75rem;border-radius:10px;border:1px solid #cbd5f5;background:#f8fafc;color:#1f2937;font-size:.95rem;}
.ssl-token-table{margin-top:8px;}
.ssl-token-table input[type=text]{width:100%;max-width:260px;padding:.35rem .55rem;border:1px solid #cbd5f5;border-radius:8px;background:#f8fafc;color:#0f172a;font-size:.88rem;}
.ssl-token-table input[type=text][readonly]{cursor:text;}
.ssl-token-table__name{min-width:200px;}
.ssl-token-table__token{font-family:monospace;font-size:.9rem;}
.ssl-token-copy{display:flex;align-items:center;gap:8px;}
.ssl-token-copy input{flex:1 1 auto;}
.ssl-token-table__status{min-width:200px;}
 .ssl-token-table__actions{display:flex;gap:8px;justify-content:flex-end;flex-wrap:wrap;}
 .ssl-token-hidden-form{display:none;}
.ssl-token-status{display:flex;gap:10px;align-items:flex-start;}
.ssl-token-status__dot{width:12px;height:12px;border-radius:50%;box-shadow:0 0 0 4px rgba(148,163,184,.18);margin-top:6px;}
.ssl-token-status__dot--online{background:#22c55e;box-shadow:0 0 0 4px rgba(34,197,94,.18);}
.ssl-token-status__dot--offline{background:#ef4444;box-shadow:0 0 0 4px rgba(239,68,68,.18);}
.ssl-token-status__dot--unknown{background:#94a3b8;box-shadow:0 0 0 4px rgba(148,163,184,.2);}
.ssl-token-status__text{display:flex;flex-direction:column;gap:4px;}
.ssl-token-status__label{font-weight:700;color:#0f172a;}
.ssl-token-status__meta{font-size:.8rem;color:#64748b;}
.ssl-token-status__meta--error{color:#b91c1c;}
.ssl-token-table__notify,.ssl-token-table__emails{vertical-align:top;}
.ssl-token-toggle{display:flex;align-items:center;gap:8px;font-size:.85rem;color:#0f172a;font-weight:600;}
.ssl-token-toggle input[type=checkbox]{margin:0;}
.ssl-token-emails{display:flex;flex-direction:column;gap:8px;}
.ssl-token-email-list{display:flex;flex-wrap:wrap;gap:8px;min-height:32px;}
.ssl-token-email-chip{display:inline-flex;align-items:center;gap:6px;background:#e0f2fe;color:#0f172a;padding:.35rem .65rem;border-radius:999px;font-weight:600;font-size:.8rem;box-shadow:0 6px 14px rgba(14,116,144,.18);}
.ssl-token-email-chip__text{direction:ltr;}
.ssl-token-email-chip__remove{background:transparent;border:none;color:#1d4ed8;cursor:pointer;font-size:1rem;line-height:1;padding:0;}
.ssl-token-email-chip__remove:hover{color:#1e3a8a;}
.ssl-token-email-chip--empty{background:#f1f5f9;color:#64748b;box-shadow:none;font-weight:500;}
.ssl-token-email-add{display:flex;flex-wrap:wrap;gap:8px;align-items:center;}
.ssl-token-email-add input{flex:1 1 220px;border:1px solid #cbd5f5;border-radius:10px;padding:.45rem .6rem;background:#fff;color:#0f172a;font-size:.85rem;direction:ltr;}
.ssl-token-email-add button{padding:.45rem 1.1rem;}
.ssl-token-email-error{font-size:.75rem;color:#b91c1c;min-height:1.1em;}
.ssl-token-email-input--error{border-color:#f87171;box-shadow:0 0 0 2px rgba(248,113,113,.25);}
.ssl-log-table__time{white-space:nowrap;font-variant-numeric:tabular-nums;}
.ssl-log-table__level{min-width:110px;}
.ssl-log-level{display:inline-flex;align-items:center;justify-content:center;padding:.3rem .75rem;border-radius:999px;font-weight:700;font-size:.8rem;letter-spacing:.03em;text-transform:uppercase;box-shadow:inset 0 -2px 0 rgba(255,255,255,.45);}
.ssl-log-level--info{background:#e0f2fe;color:#0369a1;}
.ssl-log-level--warning{background:#fef3c7;color:#92400e;}
.ssl-log-level--error{background:#fee2e2;color:#b91c1c;}
.ssl-log-table__message{max-width:360px;white-space:normal;font-weight:600;color:#0f172a;}
.ssl-log-table__context{min-width:300px;white-space:normal;}
.ssl-log-context{margin:0;padding:0;list-style:none;display:flex;flex-direction:column;gap:6px;}
.ssl-log-context__item{display:flex;align-items:center;gap:6px;padding:6px 8px;border-radius:10px;border:1px solid #e2e8f0;background:#fff;box-shadow:0 4px 10px rgba(15,23,42,.04);}
.ssl-log-context__key{font-weight:700;color:#0f172a;margin-left:6px;white-space:nowrap;}
.ssl-log-context__value{direction:ltr;font-family:"Fira Code","Source Code Pro",monospace;font-size:.88rem;color:#334155;word-break:break-word;}
.ssl-log-context__empty{color:#94a3b8;font-style:italic;}
.ssl-token-note{margin-top:12px;}
.ssl-card--types .ssl-card__header{display:flex;justify-content:space-between;align-items:center;gap:12px;}
.ssl-card--types .ssl-card__header h3{margin:0;}
.ssl-card--types .ssl-card__body{overflow-x:visible;}
.ssl-type-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:10px 14px;align-items:start;}
.ssl-type-grid__item{border:1px solid #e2e8f0;border-radius:12px;padding:10px;background:#fff;box-shadow:0 4px 10px rgba(15,23,42,.04);display:flex;flex-direction:column;gap:8px;}
.ssl-type-grid__fields{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;align-items:center;}
.ssl-type-grid__item label{display:flex;flex-direction:column;gap:4px;font-weight:600;color:#0f172a;font-size:.85rem;}
.ssl-type-grid__item input[type=text]{width:100%;font-size:.9rem;padding:.3rem .45rem;border-radius:8px;border:1px solid #cbd5f5;background:#f8fafc;min-height:36px;}
.ssl-type-grid__item input[type=color]{width:42px;height:32px;border:1px solid #cbd5f5;border-radius:8px;background:#fff;cursor:pointer;padding:0;}
.ssl-type-grid__color-picker{display:flex;align-items:center;gap:10px;}
.ssl-type-chip-preview{width:18px;height:18px;border-radius:999px;background:var(--ssl-type-color,#2563eb);box-shadow:0 2px 6px rgba(37,99,235,.25);border:1px solid rgba(15,23,42,.08);}
.ssl-type-grid__actions{display:flex;justify-content:flex-end;}
.ssl-type-remove{background:transparent;border:none;color:#e53935;font-weight:600;font-size:.85rem;cursor:pointer;padding:0;}
.ssl-type-remove:hover{text-decoration:underline;}
.ssl-toggle{display:flex;align-items:center;gap:8px;font-weight:700;color:#0f172a;}
.ssl-table__edit-row td{background:#f8fafc;}
.ssl-empty{text-align:center;padding:24px;font-size:1rem;color:#64748b;}
@media (max-width:640px){
 .ssl-toolbar{grid-template-columns:1fr;}
 .ssl-toolbar__group,.ssl-toolbar__import{flex-direction:column;align-items:stretch;}
 .ssl-toolbar__group--end{justify-content:flex-start;}
 .ssl-manager__header-actions{width:100%;justify-content:stretch;}
 .ssl-manager__header-actions .ssl-btn{flex:1;}
 .ssl-token-create__fields{flex-direction:column;align-items:stretch;}
 .ssl-token-table__actions{justify-content:center;}
 .ssl-token-status{flex-direction:column;align-items:flex-start;}
.ssl-token-email-add{flex-direction:column;align-items:stretch;}
.ssl-token-email-add input,.ssl-token-email-add button{width:100%;flex:1 1 auto;}
.ssl-token-email-list{justify-content:flex-start;}
}
.ssl-management-cell{white-space:nowrap;font-weight:700;color:#0f172a;}
.ssl-bulk-editor__filter-form{margin-bottom:8px;}
.ssl-bulk-grid__wrapper{width:100%;overflow-x:auto;overflow-y:hidden;padding-bottom:8px;}
.ssl-bulk-grid{min-width:1280px;}
.ssl-bulk-grid--resizable{table-layout:fixed;}
.ssl-bulk-grid--resizable th{position:relative;}
.ssl-bulk-grid__handle{position:absolute;top:0;right:-4px;width:8px;cursor:col-resize;user-select:none;height:100%;}
.ssl-bulk-grid__handle::after{content:'';position:absolute;top:6px;bottom:6px;right:3px;width:2px;background:#d4d8dd;border-radius:1px;}
.ssl-bulk-grid__handle:active::after{background:#9aa2ad;}
.ssl-bulk-grid thead th{position:sticky;top:0;background:#f8fafc;}
.ssl-bulk-grid__filters-row input,.ssl-bulk-grid__filters-row select{width:100%;padding:.35rem .45rem;border:1px solid #cbd5f5;border-radius:8px;background:#fff;font-size:.85rem;}
.ssl-bulk-grid__per-page{max-width:70px;text-align:center;}
.ssl-bulk-grid__temporary textarea,.ssl-bulk-grid textarea{width:100%;min-height:36px;resize:vertical;}
.ssl-bulk-grid input[type=text],.ssl-bulk-grid input[type=date],.ssl-bulk-grid select{min-width:160px;}
.ssl-bulk-grid textarea{min-width:220px;}
.ssl-bulk-grid__input-site{min-width:480px;}
.ssl-bulk-grid__input-cn{min-width:320px;}
.ssl-bulk-grid__input-management{min-width:80px;}
.ssl-bulk-grid__guide{margin-top:6px;width:100%;}
.ssl-bulk-grid__actions{white-space:nowrap;}
.ssl-toolbar__quick{margin-bottom:12px;}
.ssl-toolbar__quick-actions{display:inline-flex;gap:10px;align-items:center;flex-wrap:wrap;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:999px;padding:10px 14px;box-shadow:0 1px 2px rgba(15,23,42,.08);}
.ssl-err{color:#b00020;font-size:.85rem;}
CSS;
        wp_register_style('ssl-expiry-manager', false);
        wp_enqueue_style('ssl-expiry-manager');
        wp_add_inline_style('ssl-expiry-manager', $css);
        $js = <<<'JS'
function sslEmailFindWrapper(el){
  return el ? el.closest('[data-email-list]') : null;
}
function sslEmailShowError(wrapper,message){
  if(!wrapper) return;
  var error = wrapper.querySelector('[data-email-error]');
  if(error){
    error.textContent = message || '';
  }
}
function sslEmailEnsure(wrapper){
  if(!wrapper) return;
  var list = wrapper.querySelector('[data-email-chips]');
  if(!list) return;
  var emptyNodes = list.querySelectorAll('[data-email-empty]');
  var hasChip = list.querySelector('[data-email-item]');
  if(hasChip){
    emptyNodes.forEach(function(node){ node.remove(); });
  } else if(!emptyNodes.length){
    var empty = document.createElement('span');
    empty.className = 'ssl-token-email-chip ssl-token-email-chip--empty';
    empty.setAttribute('data-email-empty','');
    empty.textContent = 'אין נמענים';
    list.appendChild(empty);
  }
}
var sslExistingRecords = {sites:[],cns:[]};
function sslNormalizeSiteValue(value){
  if(!value){ return ''; }
  return value.toString().trim().toLowerCase().replace(/^https?:\/\//,'').replace(/\/+$/,'');
}
function sslNormalizeCnValue(value){
  if(!value){ return ''; }
  return value.toString().trim().toLowerCase();
}
function sslAutofillUrlField(field){
  if(!field){ return; }
  var raw = field.value || '';
  var trimmed = raw.trim();
  if(!trimmed){
    field.value = '';
    return;
  }
  var normalized = trimmed.replace(/\s+/g,'');
  if(!/^https?:\/\//i.test(normalized)){
    normalized = 'https://' + normalized.replace(/^\/+/, '');
  }
  field.value = normalized;
}
function sslSetNextYearDate(control){
  if(!control){ return; }
  var container = control.closest('.ssl-date-field__controls');
  if(!container){ return; }
  var input = container.querySelector('[data-ssl-date-input]');
  if(!input){ return; }
  var today = new Date();
  var next = new Date(today.getFullYear() + 1, today.getMonth(), today.getDate());
  var year = next.getFullYear();
  var month = String(next.getMonth() + 1).padStart(2,'0');
  var day = String(next.getDate()).padStart(2,'0');
  var value = year + '-' + month + '-' + day;
  input.value = value;
  input.dispatchEvent(new Event('input', {bubbles:true}));
  input.dispatchEvent(new Event('change', {bubbles:true}));
}
function sslTypeBindRow(row){
  if(!row){ return; }
  var colorInput = row.querySelector('[data-ssl-type-color]');
  var preview = row.querySelector('[data-ssl-type-preview]');
  if(colorInput && preview){
    var updatePreview = function(){
      var val = colorInput.value || '#2563eb';
      preview.style.setProperty('--ssl-type-color', val);
    };
    colorInput.addEventListener('input', updatePreview);
    updatePreview();
  }
}
function sslUpdateCreateDuplicateState(form){
  if(!form){ return; }
  var siteInput = form.querySelector('[data-ssl-create-site]');
  var cnInput = form.querySelector('[data-ssl-create-cn]');
  var submit = form.querySelector('[data-ssl-create-submit]');
  var siteWarning = form.querySelector('[data-ssl-warning-site]');
  var cnWarning = form.querySelector('[data-ssl-warning-cn]');
  var siteValue = siteInput ? sslNormalizeSiteValue(siteInput.value) : '';
  var cnValue = cnInput ? sslNormalizeCnValue(cnInput.value) : '';
  var siteDuplicate = siteValue && sslExistingRecords.sites.indexOf(siteValue) !== -1;
  var cnDuplicate = cnValue && sslExistingRecords.cns.indexOf(cnValue) !== -1;
  if(siteWarning){
    siteWarning.textContent = siteDuplicate ? 'קיימת רשומה עם כתובת אתר זהה.' : '';
    if(siteDuplicate){ siteWarning.removeAttribute('hidden'); }
    else { siteWarning.setAttribute('hidden',''); }
  }
  if(siteInput){
    if(siteDuplicate){ siteInput.classList.add('ssl-input-error'); }
    else { siteInput.classList.remove('ssl-input-error'); }
  }
  if(cnWarning){
    cnWarning.textContent = cnDuplicate ? 'קיימת רשומה עם CN זהה.' : '';
    if(cnDuplicate){ cnWarning.removeAttribute('hidden'); }
    else { cnWarning.setAttribute('hidden',''); }
  }
  if(cnInput){
    if(cnDuplicate){ cnInput.classList.add('ssl-input-error'); }
    else { cnInput.classList.remove('ssl-input-error'); }
  }
  if(submit){
    submit.disabled = !!(siteDuplicate || cnDuplicate);
  }
}
function sslBulkGetItems(form){
  if(!form || !form.id) return [];
  return Array.prototype.slice.call(document.querySelectorAll('[data-ssl-select-item][form="'+form.id+'"]'));
}
function sslBulkUpdateState(form){
  if(!form) return;
  var items = sslBulkGetItems(form);
  var checkedCount = 0;
  items.forEach(function(item){ if(item.checked){ checkedCount++; } });
  var buttons = Array.prototype.slice.call(form.querySelectorAll('[data-ssl-bulk-delete]'));
  var externalButtons = document.querySelectorAll('[data-ssl-bulk-delete][form="'+form.id+'"]');
  Array.prototype.forEach.call(externalButtons,function(btn){
    if(buttons.indexOf(btn) === -1){
      buttons.push(btn);
    }
  });
  buttons.forEach(function(button){
    button.disabled = checkedCount === 0;
  });
  var master = document.querySelector('[data-ssl-select-all][data-ssl-form="'+form.id+'"]');
  if(master){
    master.indeterminate = checkedCount > 0 && checkedCount < items.length;
    master.checked = items.length > 0 && checkedCount === items.length;
  }
}
function sslGroupSetState(toggle, nextState){
  if(!toggle) return;
  var groupKey = toggle.getAttribute('data-ssl-group-toggle');
  if(!groupKey) return;
  var isExpanded = !!nextState;
  toggle.setAttribute('aria-expanded', isExpanded ? 'true' : 'false');
  toggle.textContent = isExpanded ? '−' : '+';
  document.querySelectorAll('[data-ssl-group-child="'+groupKey+'"]').forEach(function(row){
    var isDetailRow = row.hasAttribute('data-ssl-details-row');
    var isEditRow = row.hasAttribute('data-ssl-form');
    var shouldShow = isExpanded && !isDetailRow;
    if(isEditRow && row.getAttribute('data-ssl-form-open') !== '1'){
      shouldShow = false;
    }
    if(shouldShow){
      row.hidden = false;
      row.removeAttribute('hidden');
      row.style.display = 'table-row';
    } else {
      row.hidden = true;
      row.setAttribute('hidden','');
      row.style.display = 'none';
    }
    if(isDetailRow){
      row.setAttribute('data-ssl-details-open','0');
      var detailId = row.getAttribute('data-ssl-details-row');
      document.querySelectorAll('[data-ssl-details="'+detailId+'"]').forEach(function(btn){
        btn.classList.remove('is-active');
        btn.textContent = '+';
      });
    }
  });
}
function sslToggleDetailRow(detailId, forceState){
  if(!detailId){ return null; }
  var detailRow = document.querySelector('[data-ssl-details-row=\"'+detailId+'\"]');
  if(!detailRow){ return null; }
  var isOpen = detailRow.getAttribute('data-ssl-details-open') === '1';
  var shouldOpen = typeof forceState === 'boolean' ? forceState : !isOpen;
  if(shouldOpen){
    detailRow.removeAttribute('hidden');
    detailRow.hidden = false;
    detailRow.style.display = 'table-row';
    detailRow.setAttribute('data-ssl-details-open','1');
  } else {
    detailRow.setAttribute('hidden','');
    detailRow.hidden = true;
    detailRow.style.display = 'none';
    detailRow.setAttribute('data-ssl-details-open','0');
  }
  var buttons = document.querySelectorAll('[data-ssl-details=\"'+detailId+'\"]');
  buttons.forEach(function(btn){
    if(shouldOpen){
      btn.classList.add('is-active');
      btn.textContent = '−';
    } else {
      btn.classList.remove('is-active');
      btn.textContent = '+';
    }
  });
  return shouldOpen;
}
function sslEmailHandleAdd(wrapper){
  if(!wrapper) return;
  var input = wrapper.querySelector('[data-email-input]');
  if(!input) return;
  var raw = input.value.trim();
  sslEmailShowError(wrapper,'');
  input.classList.remove('ssl-token-email-input--error');
  if(!raw){
    sslEmailShowError(wrapper,'הקלד כתובת דוא"ל');
    input.classList.add('ssl-token-email-input--error');
    return;
  }
  var email = raw.toLowerCase();
  var pattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if(!pattern.test(email)){
    sslEmailShowError(wrapper,'כתובת לא תקינה');
    input.classList.add('ssl-token-email-input--error');
    return;
  }
  var exists = Array.prototype.slice.call(wrapper.querySelectorAll('input[type="hidden"][name="token_emails[]"]')).some(function(hidden){
    return hidden.value.toLowerCase() === email;
  });
  if(exists){
    sslEmailShowError(wrapper,'כתובת כבר קיימת');
    input.value = '';
    return;
  }
  var list = wrapper.querySelector('[data-email-chips]');
  if(!list) return;
  var chip = document.createElement('span');
  chip.className = 'ssl-token-email-chip';
  chip.setAttribute('data-email-item','');
  var hidden = document.createElement('input');
  hidden.type = 'hidden';
  hidden.name = 'token_emails[]';
  hidden.value = email;
  var formId = wrapper.getAttribute('data-email-form');
  if(formId){ hidden.setAttribute('form', formId); }
  var text = document.createElement('span');
  text.className = 'ssl-token-email-chip__text';
  text.textContent = raw;
  var remove = document.createElement('button');
  remove.type = 'button';
  remove.className = 'ssl-token-email-chip__remove';
  remove.setAttribute('data-email-remove','');
  remove.setAttribute('aria-label','הסר כתובת');
  remove.textContent = '×';
  chip.appendChild(hidden);
  chip.appendChild(text);
  chip.appendChild(remove);
  list.appendChild(chip);
  input.value = '';
  sslEmailEnsure(wrapper);
}
document.addEventListener('change',function(e){
  if(e.target.matches('[data-ssl-select-all]')){
    var formId = e.target.getAttribute('data-ssl-form');
    var form = formId ? document.getElementById(formId) : null;
    if(form){
      var isChecked = e.target.checked;
      sslBulkGetItems(form).forEach(function(item){ item.checked = isChecked; });
      sslBulkUpdateState(form);
    }
  }
  if(e.target.matches('[data-ssl-select-item]')){
    var bulkForm = e.target.form;
    if(bulkForm){
      sslBulkUpdateState(bulkForm);
    }
  }
});
document.addEventListener('click',function(e){
  var nextYearBtn = e.target.closest('[data-ssl-date-next-year]');
  if(nextYearBtn){
    e.preventDefault();
    sslSetNextYearDate(nextYearBtn);
    return;
  }
  if(e.target.matches('[data-ssl-type-add]')){
    e.preventDefault();
    var template = document.getElementById('ssl-type-row-template');
    var container = document.querySelector('[data-ssl-type-rows]');
    if(template && container){
      var clone = null;
      if(template.content && template.content.firstElementChild){
        clone = template.content.firstElementChild.cloneNode(true);
      } else {
        var tempWrapper = document.createElement('tbody');
        tempWrapper.innerHTML = template.innerHTML || '';
        clone = tempWrapper.firstElementChild;
      }
      if(clone){
        container.appendChild(clone);
        sslTypeBindRow(clone);
      }
    }
    return;
  }
  var typeRemoveBtn = e.target.closest('[data-ssl-type-remove]');
  if(typeRemoveBtn){
    e.preventDefault();
    var typeRow = typeRemoveBtn.closest('[data-ssl-type-row]');
    if(typeRow){
      typeRow.remove();
    }
    return;
  }
  var toggle = e.target.closest('[data-ssl-toggle]');
  if(toggle){
    var action = toggle.getAttribute('data-ssl-toggle');
    if(action==='create'){
      var form = document.querySelector('[data-ssl-create]');
      if(form){
        e.preventDefault();
        if(form.hasAttribute('hidden')){form.removeAttribute('hidden');}
        else{form.setAttribute('hidden','');}
        document.querySelectorAll('[data-ssl-toggle="create"]').forEach(function(btn){
          if(form.hasAttribute('hidden')) btn.classList.remove('is-active');
          else btn.classList.add('is-active');
        });
      }
    }
  }
  var edit = e.target.closest('[data-ssl-edit]');
  if(edit){
    e.preventDefault();
    var id = edit.getAttribute('data-ssl-edit');
    var row = document.querySelector('[data-ssl-form="'+id+'"]');
    if(row){
      var nowHidden = row.hasAttribute('hidden');
      if(nowHidden){
        row.removeAttribute('hidden');
        row.hidden = false;
        row.style.display = 'table-row';
      } else {
        row.setAttribute('hidden','');
        row.hidden = true;
        row.style.display = 'none';
      }
      row.setAttribute('data-ssl-form-open', row.hasAttribute('hidden') ? '0' : '1');
      document.querySelectorAll('[data-ssl-edit="'+id+'"]').forEach(function(btn){
        if(row.hasAttribute('hidden')) btn.classList.remove('is-active');
        else btn.classList.add('is-active');
      });
    }
  }
  var detailBtn = e.target.closest('[data-ssl-details]');
  if(detailBtn){
    e.preventDefault();
    var detailId = detailBtn.getAttribute('data-ssl-details');
    sslToggleDetailRow(detailId);
    return;
  }
  var rowToggle = e.target.closest('tr[data-ssl-row]');
  if(rowToggle && !e.target.closest('a,button,input,select,textarea,label')){
    var detailIdFromRow = rowToggle.getAttribute('data-ssl-row');
    sslToggleDetailRow(detailIdFromRow);
  }
  var copyBtn = e.target.closest('[data-ssl-copy]');
  if(copyBtn){
    e.preventDefault();
    var val = copyBtn.getAttribute('data-ssl-copy') || '';
    if(val){
      if(navigator.clipboard && navigator.clipboard.writeText){
        navigator.clipboard.writeText(val).catch(function(){});
      } else {
        var temp = document.createElement('textarea');
        temp.value = val;
        temp.style.position = 'fixed';
        document.body.appendChild(temp);
        temp.select();
        try{ document.execCommand('copy'); } catch(err){}
        document.body.removeChild(temp);
      }
    }
    return;
  }
  var removeBtn = e.target.closest('[data-email-remove]');
  if(removeBtn){
    var wrapper = sslEmailFindWrapper(removeBtn);
    if(wrapper){
      e.preventDefault();
      var chip = removeBtn.closest('[data-email-item]');
      if(chip){ chip.remove(); }
      sslEmailShowError(wrapper,'');
      sslEmailEnsure(wrapper);
    }
  }
  if(e.target.matches('[data-email-add]')){
    var addWrapper = sslEmailFindWrapper(e.target);
    if(addWrapper){
      e.preventDefault();
      sslEmailHandleAdd(addWrapper);
    }
  }
  var groupToggle = e.target.closest('[data-ssl-group-toggle]');
  if(groupToggle){
    e.preventDefault();
    var groupKey = groupToggle ? groupToggle.getAttribute('data-ssl-group-toggle') : '';
    if(!groupKey){
      return;
    }
    var expanded = groupToggle.getAttribute('aria-expanded') === 'true';
    var nextState = !expanded;
    sslGroupSetState(groupToggle, nextState);
  }
});
document.addEventListener('keydown',function(e){
  if(e.key==='Enter' && e.target.matches('[data-email-input]')){
    var wrapper = sslEmailFindWrapper(e.target);
    if(wrapper){
      e.preventDefault();
      sslEmailHandleAdd(wrapper);
    }
  }
});
window.addEventListener('DOMContentLoaded',function(){
  var existingScript = document.getElementById('ssl-existing-records');
  if(existingScript){
    try {
      var parsedData = JSON.parse(existingScript.textContent || existingScript.innerText || 'null');
      if(parsedData && typeof parsedData === 'object'){
        if(Array.isArray(parsedData.sites)){ sslExistingRecords.sites = parsedData.sites; }
        if(Array.isArray(parsedData.cns)){ sslExistingRecords.cns = parsedData.cns; }
      }
    } catch(err){}
  }
  document.querySelectorAll('[data-ssl-type-row]').forEach(sslTypeBindRow);
  var createFormCard=document.querySelector('[data-ssl-create]');
  if(createFormCard && !createFormCard.hasAttribute('hidden')){
    document.querySelectorAll('[data-ssl-toggle="create"]').forEach(function(btn){btn.classList.add('is-active');});
  }
  var createFormInstance=document.querySelector('[data-ssl-create-form]');
  if(createFormInstance){
    var updateDuplicates=function(){ sslUpdateCreateDuplicateState(createFormInstance); };
    var siteField=createFormInstance.querySelector('[data-ssl-create-site]');
    var cnField=createFormInstance.querySelector('[data-ssl-create-cn]');
    if(siteField){
      siteField.dataset.sslAutofillBound = '1';
      siteField.addEventListener('input', updateDuplicates);
      siteField.addEventListener('blur', function(){
        sslAutofillUrlField(siteField);
        updateDuplicates();
      });
    }
    if(cnField){ cnField.addEventListener('input', updateDuplicates); cnField.addEventListener('blur', updateDuplicates); }
    updateDuplicates();
  }
  document.querySelectorAll('[data-ssl-autofill-url]').forEach(function(field){
    if(field.dataset.sslAutofillBound){ return; }
    field.dataset.sslAutofillBound = '1';
    field.addEventListener('blur', function(){ sslAutofillUrlField(field); });
  });
  document.querySelectorAll('form[data-ssl-bulk-form]').forEach(function(form){
    sslBulkUpdateState(form);
  });
  var bulkTable = document.querySelector('.ssl-bulk-grid');
  if(bulkTable){
    bulkTable.classList.add('ssl-bulk-grid--resizable');
    var headerRow = bulkTable.querySelector('thead tr');
    var headers = headerRow ? headerRow.querySelectorAll('th') : [];
    headers.forEach(function(th, idx){
      if(idx === headers.length - 1){
        return;
      }
      var handle = document.createElement('span');
      handle.className = 'ssl-bulk-grid__handle';
      var startX = 0;
      var startWidth = 0;
      var moveHandler = function(e){
        var delta = e.clientX - startX;
        var newWidth = Math.max(120, startWidth + delta);
        th.style.width = newWidth + 'px';
        bulkTable.querySelectorAll('tbody tr td:nth-child('+(idx+1)+')').forEach(function(cell){
          cell.style.width = newWidth + 'px';
        });
      };
      var upHandler = function(){
        document.removeEventListener('mousemove', moveHandler);
        document.removeEventListener('mouseup', upHandler);
      };
      handle.addEventListener('mousedown', function(e){
        startX = e.clientX;
        startWidth = th.getBoundingClientRect().width;
        document.addEventListener('mousemove', moveHandler);
        document.addEventListener('mouseup', upHandler);
        e.preventDefault();
      });
      th.appendChild(handle);
    });
  }
  document.querySelectorAll('[data-ssl-form]').forEach(function(row){
    if(!row.hasAttribute('hidden')){
      var id=row.getAttribute('data-ssl-form');
      document.querySelectorAll('[data-ssl-edit="'+id+'"]').forEach(function(btn){btn.classList.add('is-active');});
      row.setAttribute('data-ssl-form-open','1');
      row.hidden = false;
      row.style.display = 'table-row';
    } else {
      row.setAttribute('data-ssl-form-open','0');
      row.hidden = true;
      row.style.display = 'none';
    }
  });
  document.querySelectorAll('[data-ssl-details-row]').forEach(function(row){
    var id=row.getAttribute('data-ssl-details-row');
    if(!row){return;}
    var isOpen = !row.hasAttribute('hidden');
    row.setAttribute('data-ssl-details-open', isOpen ? '1' : '0');
    if(isOpen){
      row.hidden = false;
      row.style.display = 'table-row';
    } else {
      row.hidden = true;
      row.style.display = 'none';
    }
    document.querySelectorAll('[data-ssl-details="'+id+'"]').forEach(function(btn){
      if(isOpen){
        btn.classList.add('is-active');
        btn.textContent = '−';
      } else {
        btn.classList.remove('is-active');
        btn.textContent = '+';
      }
    });
  });
  document.querySelectorAll('[data-email-list]').forEach(function(wrapper){
    sslEmailEnsure(wrapper);
  });
  document.querySelectorAll('[data-ssl-page-size]').forEach(function(select){
    select.addEventListener('change',function(){
      var form = select.closest('form');
      if(form){
        var pageInput = form.querySelector('[data-ssl-page-input]');
        if(pageInput){
          pageInput.value = '1';
        }
        form.submit();
      }
    });
  });
  document.querySelectorAll('[data-ssl-filter-form]').forEach(function(form){
    var debounceTimer = null;
    var submitForm = function(){
      if(debounceTimer){
        clearTimeout(debounceTimer);
        debounceTimer = null;
      }
      var pageInput = form.querySelector('input[name="ssl_page"]');
      if(pageInput){
        pageInput.value = '1';
      }
      if(typeof form.requestSubmit === 'function'){
        form.requestSubmit();
      } else {
        form.submit();
      }
    };
    var scheduleSubmit = function(){
      if(debounceTimer){
        clearTimeout(debounceTimer);
      }
      debounceTimer = setTimeout(submitForm, 400);
    };
    var searchInput = form.querySelector('[data-ssl-filter-search]');
    if(searchInput){
      searchInput.addEventListener('input', scheduleSubmit);
    }
    var clearSearch = form.querySelector('[data-ssl-filter-clear]');
    if(clearSearch && searchInput){
      clearSearch.addEventListener('click', function(){
        searchInput.value = '';
        var pageInputReset = form.querySelector('input[name="ssl_page"]');
        if(pageInputReset){
          pageInputReset.value = '1';
        }
        submitForm();
      });
    }
    form.querySelectorAll('[data-ssl-filter-select]').forEach(function(select){
      select.addEventListener('change', submitForm);
    });
    var missingInput = form.querySelector('[data-ssl-missing-input]');
    var missingButtons = document.querySelectorAll('[data-ssl-filter-missing]');
    var resetButtons = document.querySelectorAll('[data-ssl-filter-reset]');
    var updateMissingState = function(btn){
      if(!btn || !missingInput){ return; }
      if(missingInput.value === '1'){ btn.classList.add('is-active'); }
      else { btn.classList.remove('is-active'); }
    };
    missingButtons.forEach(function(btn){
      updateMissingState(btn);
      btn.addEventListener('click', function(){
        if(!missingInput){ return; }
        missingInput.value = missingInput.value === '1' ? '' : '1';
        var pageReset = form.querySelector('input[name="ssl_page"]');
        if(pageReset){ pageReset.value = '1'; }
        updateMissingState(btn);
        submitForm();
      });
    });
    resetButtons.forEach(function(btn){
      btn.addEventListener('click', function(){
        if(missingInput){ missingInput.value = ''; }
        if(searchInput){ searchInput.value = ''; }
        var pageReset = form.querySelector('input[name="ssl_page"]');
        if(pageReset){ pageReset.value = '1'; }
        missingButtons.forEach(updateMissingState);
        submitForm();
      });
    });
  });
  document.querySelectorAll('[data-ssl-group-parent]').forEach(function(row){
    var btn = row.querySelector('[data-ssl-group-toggle]');
    if(btn){
      sslGroupSetState(btn, false);
    }
  });
  document.querySelectorAll('[data-ssl-expand-all]').forEach(function(btn){
    btn.addEventListener('click',function(){
      document.querySelectorAll('[data-ssl-group-toggle]').forEach(function(toggle){
        if(toggle.getAttribute('aria-expanded') !== 'true'){
          toggle.click();
        }
      });
    });
  });
  document.querySelectorAll('[data-ssl-collapse-all]').forEach(function(btn){
    btn.addEventListener('click',function(){
      document.querySelectorAll('[data-ssl-details]').forEach(function(detailBtn){
        if(detailBtn.classList.contains('is-active')){
          detailBtn.click();
        }
      });
      document.querySelectorAll('[data-ssl-group-toggle]').forEach(function(toggle){
        if(toggle.getAttribute('aria-expanded') === 'true'){
          toggle.click();
        }
      });
    });
  });
});
JS;
        wp_register_script('ssl-expiry-manager-js','',[],false,true);
        wp_enqueue_script('ssl-expiry-manager-js');
        wp_add_inline_script('ssl-expiry-manager-js',$js);
    }

    private function nonce_field(){ return wp_nonce_field(self::NONCE, self::NONCE, true, false); }
    private function check_nonce(){ if(!isset($_POST[self::NONCE])||!wp_verify_nonce($_POST[self::NONCE], self::NONCE)) wp_die('Invalid nonce'); }
    private function sanitize_url($url){ $url=trim($url); if($url && !preg_match('#^https?://#i',$url)) $url='https://'.$url; return esc_url_raw($url); }
    private function normalize_site_identifier($value){
        $value = trim((string)$value);
        if($value === ''){
            return '';
        }
        $value = preg_replace('#^https?://#i', '', $value);
        $value = preg_replace('#/+$#', '', $value);
        return strtolower($value);
    }
    private function normalize_cn_identifier($value){
        $value = trim((string)$value);
        if($value === ''){
            return '';
        }
        return strtolower($value);
    }
    private function get_existing_certificate_identifiers(){
        global $wpdb;
        $table = $this->get_table_name();
        $rows = $wpdb->get_results("SELECT site_url, common_name FROM {$table} WHERE status != 'trash'", ARRAY_A);
        $sites = [];
        $cns = [];
        foreach((array)$rows as $row){
            $site = isset($row['site_url']) ? $this->normalize_site_identifier($row['site_url']) : '';
            if($site !== ''){
                $sites[$site] = true;
            }
            $cn = isset($row['common_name']) ? $this->normalize_cn_identifier($row['common_name']) : '';
            if($cn !== ''){
                $cns[$cn] = true;
            }
        }
        return [
            'sites' => array_keys($sites),
            'cns' => array_keys($cns),
        ];
    }
    private function site_identifier_exists($normalized_site, $exclude_post_id = 0){
        if($normalized_site === ''){
            return 0;
        }
        global $wpdb;
        $table = $this->get_table_name();
        $rows = $wpdb->get_results($wpdb->prepare("SELECT post_id, site_url, allow_duplicate_site FROM {$table} WHERE status != 'trash' AND post_id != %d", (int)$exclude_post_id), ARRAY_A);
        foreach((array)$rows as $row){
            if(!empty($row['allow_duplicate_site'])){
                continue;
            }
            $candidate = $this->normalize_site_identifier($row['site_url'] ?? '');
            if($candidate !== '' && $candidate === $normalized_site){
                return isset($row['post_id']) ? (int)$row['post_id'] : 0;
            }
        }
        return 0;
    }
    private function days_left($ts){ if(!$ts) return null; $now=current_time('timestamp'); return (int)floor(($ts-$now)/DAY_IN_SECONDS); }
    private function badge_class($d, $follow_up = false){
        if($d === null){
            return '';
        }
        if($follow_up){
            return ($d <= 14) ? 'ssl-red' : 'ssl-green';
        }
        if($d > 90){
            return 'ssl-green';
        }
        if($d > 30){
            return 'ssl-yellow';
        }
        return 'ssl-red';
    }
    private function should_disable_temporary_note($expiry_ts){
        if(!$expiry_ts){
            return false;
        }
        $days = $this->days_left($expiry_ts);
        $badge = $this->badge_class($days, false);
        return $badge === 'ssl-green';
    }
    private function build_follow_up_form($post_id, $is_follow_up){
        $post_id = (int)$post_id;
        if($post_id <= 0){
            return '';
        }
        $form  = "<form method='post' action='".esc_url(admin_url('admin-post.php'))."' class='ssl-follow-up-form' data-ssl-follow-up-form>";
        $form .= $this->nonce_field();
        $form .= "<input type='hidden' name='action' value='".esc_attr(self::TOGGLE_FOLLOW_UP_ACTION)."'>";
        $form .= "<input type='hidden' name='post_id' value='".esc_attr($post_id)."'>";
        $form .= "<input type='hidden' name='redirect_to' value='".esc_url(add_query_arg([]))."'>";
        $form .= "<label class='ssl-follow-up-toggle'><input type='checkbox' name='follow_up' value='1'".checked($is_follow_up, true, false)." data-ssl-follow-up-toggle></label>";
        $form .= '</form>';
        return $form;
    }
    private function fmt_date($ts){ return $ts ? date_i18n('d-m-Y', $ts) : ''; }
    private function fmt_date_input($ts){ return $ts ? date_i18n('Y-m-d', $ts) : ''; }
    private function parse_user_date($value){
        $value = trim((string)$value);
        if($value === ''){
            return null;
        }
        $formats = ['d-m-Y','Y-m-d'];
        foreach($formats as $format){
            $dt = \DateTime::createFromFormat($format, $value);
            if($dt instanceof \DateTime){
                $errors = \DateTime::getLastErrors();
                if(empty($errors['warning_count']) && empty($errors['error_count'])){
                    $dt->setTime(0, 0, 0);
                    return $dt->getTimestamp();
                }
            }
        }
        $ts = strtotime($value);
        if($ts){
            return $ts;
        }
        return null;
    }
    private function resolve_host_ip($url){
        $host = (string)wp_parse_url($url, PHP_URL_HOST);
        if($host === ''){
            return '';
        }
        static $cache = [];
        if(array_key_exists($host, $cache)){
            return $cache[$host];
        }
        $ip = @gethostbyname($host);
        if($ip === $host || !filter_var($ip, FILTER_VALIDATE_IP)){
            $ip = '';
        }
        $cache[$host] = $ip;
        return $ip;
    }
    private function url_btn($u){ if(!$u) return ''; $u=esc_url($u); return "<a class='ssl-btn ssl-btn-outline' target='_blank' rel='noopener' href='{$u}'>פתיחת אתר</a>"; }
    private function get_activity_log(){
        $log = get_option(self::OPTION_LOG, []);
        if(!is_array($log)){
            $log = [];
        }
        return $log;
    }
    private function get_plugin_log_path(){
        $dir = plugin_dir_path(__FILE__);
        return trailingslashit($dir).self::LOG_FILE_NAME;
    }
    private function append_file_log(array $entry){
        $file = $this->get_plugin_log_path();
        $dir = dirname($file);
        if(!wp_mkdir_p($dir)){
            return;
        }
        $ts = date('Y-m-d H:i:s');
        $level = isset($entry['level']) ? strtoupper((string)$entry['level']) : 'INFO';
        $message = isset($entry['message']) ? (string)$entry['message'] : '';
        $line = sprintf('[%s] [%s] %s', $ts, $level, $message);
        if(!empty($entry['context']) && is_array($entry['context'])){
            $encoded = wp_json_encode($entry['context'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
            if($encoded !== false){
                $line .= ' | '.$encoded;
            }
        }
        if(!file_exists($file)){
            @touch($file);
        }
        @file_put_contents($file, $line.PHP_EOL, FILE_APPEND | LOCK_EX);
    }
    private function sanitize_log_context($context){
        $clean = [];
        foreach((array)$context as $key => $value){
            $clean_key = is_string($key) ? sanitize_key($key) : $key;
            if(is_scalar($value) || $value === null){
                $clean[$clean_key] = is_string($value) ? wp_strip_all_tags((string)$value) : $value;
            } elseif(is_array($value)){
                $clean[$clean_key] = $this->sanitize_log_context($value);
            }
        }
        return $clean;
    }

    private function format_log_context_display($context){
        if(empty($context) || !is_array($context)){
            return '<span class="ssl-log-context__empty"></span>';
        }
        $items = [];
        foreach($context as $key => $value){
            $label = is_string($key) ? sanitize_key($key) : $key;
            if(is_array($value)){
                $encoded = wp_json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                $value = $encoded !== false ? $encoded : '';
            }
            if(is_bool($value)){
                $value = $value ? 'true' : 'false';
            } elseif($value === null){
                $value = 'null';
            }
            if(!is_scalar($value)){
                $value = '';
            }
            $items[] = '<li class="ssl-log-context__item"><span class="ssl-log-context__key">'.esc_html((string)$label).'</span><span class="ssl-log-context__value">'.esc_html((string)$value).'</span></li>';
        }
        if(empty($items)){
            return '<span class="ssl-log-context__empty"></span>';
        }
        return '<ul class="ssl-log-context">'.implode('', $items).'</ul>';
    }
    private function get_current_actor_context(){
        $context = ['actor' => 'מערכת'];
        if(function_exists('is_user_logged_in') && is_user_logged_in()){
            $user = wp_get_current_user();
            if($user && $user->ID){
                $label = $user->display_name ?: $user->user_login;
                if(!$label){
                    $label = 'משתמש #'.$user->ID;
                }
                $context['actor'] = $label;
                $context['actor_id'] = (int)$user->ID;
                if(!empty($user->user_email)){
                    $context['actor_email'] = sanitize_email($user->user_email);
                }
                return $context;
            }
        }
        if(!empty($_SERVER['REMOTE_ADDR'])){
            $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR']));
            $context['actor'] = 'אורח '.$ip;
            $context['actor_ip'] = $ip;
        }
        return $context;
    }
    private function log_activity($message, array $context = [], $level = 'info'){
        $level = in_array($level, ['info','warning','error'], true) ? $level : 'info';
        if(!isset($context['gateway'])){
            $gateway = $this->get_default_gateway_label();
            if($gateway !== ''){
                $context['gateway'] = $gateway;
            }
        }
        $entry = [
            'time'    => time(),
            'level'   => $level,
            'message' => wp_strip_all_tags((string)$message),
            'context' => $this->sanitize_log_context($context),
        ];
        $log = $this->get_activity_log();
        $log[] = $entry;
        if(count($log) > 200){
            $log = array_slice($log, -200);
        }
        update_option(self::OPTION_LOG, $log, false);
        $settings = $this->get_general_settings();
        if(!empty($settings['log_file_enabled'])){
            $this->append_file_log($entry);
        }
    }
    private function queue_table_exists(){
        global $wpdb;
        $table = $this->get_queue_table_name();
        return $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table)) === $table;
    }

    private function replace_queue_rows($queue){
        if(!$this->queue_table_exists()){
            return;
        }
        global $wpdb;
        $table = $this->get_queue_table_name();
        $wpdb->query("DELETE FROM {$table}");
        foreach((array)$queue as $item){
            $wpdb->insert($table, [
                'post_id'     => isset($item['id']) ? (int)$item['id'] : 0,
                'site_url'    => isset($item['site_url']) ? esc_url_raw($item['site_url']) : '',
                'client_name' => isset($item['client_name']) ? wp_strip_all_tags((string)$item['client_name']) : '',
                'context'     => isset($item['context']) ? sanitize_key($item['context']) : 'manual',
                'agent_token' => isset($item['agent_token']) ? sanitize_text_field($item['agent_token']) : '',
                'enqueued_at' => isset($item['enqueued_at']) ? (int)$item['enqueued_at'] : time(),
                'request_id'  => isset($item['request_id']) ? sanitize_text_field($item['request_id']) : '',
                'status'      => isset($item['status']) ? sanitize_text_field($item['status']) : 'queued',
                'claimed_at'  => isset($item['claimed_at']) ? (int)$item['claimed_at'] : 0,
                'attempts'    => isset($item['attempts']) ? (int)$item['attempts'] : 0,
            ], ['%d','%s','%s','%s','%s','%d','%s','%s','%d','%d']);
        }
    }

    private function normalize_queue_items($items){
        $normalized = [];
        $changed = false;
        foreach((array)$items as $item){
            if(!is_array($item)){
                $changed = true;
                continue;
            }
            $id  = isset($item['id']) ? (int)$item['id'] : 0;
            $url = isset($item['site_url']) ? (string)$item['site_url'] : '';
            if($id <= 0 || $url === ''){
                $changed = true;
                continue;
            }
            $request_id = isset($item['request_id']) ? preg_replace('/[^a-zA-Z0-9_-]/', '', (string)$item['request_id']) : '';
            if($request_id === ''){
                $request_id = 'job'.wp_generate_password(10, false, false);
                $changed = true;
            }
            $status = isset($item['status']) && in_array($item['status'], ['queued','claimed'], true) ? $item['status'] : 'queued';
            if(!isset($item['status']) || $item['status'] !== $status){
                $changed = true;
            }
            $agent_token = isset($item['agent_token']) ? sanitize_text_field($item['agent_token']) : '';
            $normalized[] = [
                'id'          => $id,
                'site_url'    => esc_url_raw($url),
                'client_name' => isset($item['client_name']) ? wp_strip_all_tags((string)$item['client_name']) : '',
                'context'     => isset($item['context']) && $item['context'] !== '' ? sanitize_key($item['context']) : 'manual',
                'agent_token' => $agent_token,
                'enqueued_at' => isset($item['enqueued_at']) ? (int)$item['enqueued_at'] : time(),
                'request_id'  => $request_id,
                'status'      => $status,
                'claimed_at'  => isset($item['claimed_at']) ? (int)$item['claimed_at'] : 0,
                'attempts'    => isset($item['attempts']) ? (int)$item['attempts'] : 0,
            ];
        }
        return [$normalized, $changed];
    }
    private function get_task_queue(){
        if(!$this->queue_table_exists()){
            return [];
        }
        $this->release_stale_claims();
        global $wpdb;
        $table = $this->get_queue_table_name();
        $rows = $wpdb->get_results("SELECT id AS queue_id, post_id, site_url, client_name, context, agent_token, enqueued_at, request_id, status, claimed_at, attempts FROM {$table} ORDER BY enqueued_at ASC", ARRAY_A);
        $queue = [];
        foreach((array)$rows as $row){
            if(empty($row['post_id']) || empty($row['site_url'])){
                continue;
            }
            $queue[] = [
                'queue_id'   => (int)$row['queue_id'],
                'id'         => (int)$row['post_id'],
                'post_id'    => (int)$row['post_id'],
                'site_url'   => esc_url_raw((string)$row['site_url']),
                'client_name'=> wp_strip_all_tags((string)$row['client_name']),
                'context'    => isset($row['context']) && $row['context'] !== '' ? sanitize_key((string)$row['context']) : 'manual',
                'agent_token'=> isset($row['agent_token']) ? sanitize_text_field((string)$row['agent_token']) : '',
                'enqueued_at'=> isset($row['enqueued_at']) ? (int)$row['enqueued_at'] : 0,
                'request_id' => isset($row['request_id']) ? sanitize_text_field((string)$row['request_id']) : '',
                'status'     => isset($row['status']) && in_array($row['status'], ['queued','claimed'], true) ? $row['status'] : 'queued',
                'claimed_at' => isset($row['claimed_at']) ? (int)$row['claimed_at'] : 0,
                'attempts'   => isset($row['attempts']) ? (int)$row['attempts'] : 0,
            ];
        }
        return $queue;
    }
    private function release_stale_claims(&$queue = null){
        $threshold = time() - self::QUEUE_CLAIM_TTL;
        if(!$this->queue_table_exists()){
            return false;
        }
        global $wpdb;
        $table = $this->get_queue_table_name();
        $updated = $wpdb->query($wpdb->prepare("UPDATE {$table} SET status = 'queued', claimed_at = 0 WHERE status = 'claimed' AND claimed_at > 0 AND claimed_at < %d", $threshold));
        return $updated > 0;
    }

    private function get_pending_db_queue_count(){
        if(!$this->queue_table_exists()){
            return 0;
        }
        global $wpdb;
        $table = $this->get_queue_table_name();
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE status = 'queued' AND attempts < %d", self::QUEUE_MAX_ATTEMPTS));
        return (int)$count;
    }

    private function remove_task_from_queue($post_id){
        $post_id = (int)$post_id;
        if($post_id <= 0){
            return;
        }
        if(!$this->queue_table_exists()){
            return;
        }
        global $wpdb;
        $table = $this->get_queue_table_name();
        $wpdb->delete($table, ['post_id' => $post_id], ['%d']);
    }

    private function is_manual_mode($post_id){
        return (int)get_post_meta($post_id,'manual_mode',true) ? true : false;
    }
    private function enqueue_task($post_id, $context = 'manual'){
        $post_id = (int)$post_id;
        if($post_id <= 0){
            return false;
        }
        $url = (string)get_post_meta($post_id, 'site_url', true);
        if(!$url){
            return false;
        }
        if($this->is_manual_mode($post_id)){
            $this->log_activity('המשימה לא נוספה - רשומה ידנית', array_merge([
                'id' => $post_id,
                'context' => $context,
                'site_url' => $url,
            ], $this->get_current_actor_context()));
            return false;
        }
        $request_id = 'job'.wp_generate_password(10, false, false);
        $client_name = (string)get_post_meta($post_id, 'client_name', true);
        $agent_token = $this->get_effective_agent_token($post_id);
        if(!$this->queue_table_exists()){
            return false;
        }
        global $wpdb;
        $table = $this->get_queue_table_name();
        $wpdb->replace($table, [
            'post_id'     => $post_id,
            'site_url'    => esc_url_raw($url),
            'client_name' => $client_name,
            'context'     => $context,
            'agent_token' => $agent_token,
            'enqueued_at' => time(),
            'request_id'  => $request_id,
            'status'      => 'queued',
            'claimed_at'  => 0,
            'attempts'    => 0,
        ], ['%d','%s','%s','%s','%d','%s','%s','%d','%d']);
        update_post_meta($post_id,'expiry_ts_checked_at', time());
        $this->sync_table_record($post_id, get_post_status($post_id));
        $post = get_post($post_id);
        $this->log_activity('המשימה נוספה לתור', array_merge([
            'id' => $post_id,
            'context' => $context,
            'site_url' => $url,
            'client_name' => $client_name,
            'check_name' => $post ? $post->post_title : $client_name,
        ], $this->get_current_actor_context()));
        return true;
    }
    private function claim_queue_tasks($limit, $agent_filter = null, $token_label = ''){
        // מגבלת משימות לפול אחד
        $limit = min(100, max(1, (int)$limit));

        // שחרור תביעות ישנות
        $this->release_stale_claims();

        if ( ! $this->queue_table_exists() ) {
            return array();
        }

        global $wpdb;
        $table = $this->get_queue_table_name();
        $now   = time();

        // 0 = queued, 1 = claimed
        $STATUS_QUEUED  = 0;
        $STATUS_CLAIMED = 1;

        // שליפת משימות במצב queued בלבד, ללא סינון לפי agent/token
        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id AS queue_id, post_id, site_url, client_name, context, enqueued_at, request_id, status, attempts
                 FROM {$table}
                 WHERE status = %d AND attempts < %d
                 ORDER BY enqueued_at ASC, id ASC
                 LIMIT %d",
                $STATUS_QUEUED,
                self::QUEUE_MAX_ATTEMPTS,
                $limit
            ),
            ARRAY_A
        );

        $claimed  = array();
        $jobs_log = array();

        foreach ( (array) $rows as $row ) {
            $queue_id = (int) $row['queue_id'];
            $post_id  = (int) $row['post_id'];
            $attempts = isset( $row['attempts'] ) ? (int) $row['attempts'] : 0;
            $attempts++;

            // סימון כ-claimed והגדלת attempts
            $updated = $wpdb->update(
                $table,
                array(
                    'status'     => $STATUS_CLAIMED,
                    'claimed_at' => $now,
                    'attempts'   => $attempts,
                ),
                array( 'id' => $queue_id ),
                array( '%d', '%d', '%d' ),
                array( '%d' )
            );
            if ( false === $updated ) {
                continue;
            }

            $ctx = isset( $row['context'] ) && $row['context'] !== '' ? $row['context'] : 'manual';

            $claimed[] = array(
                'queue_id'    => $queue_id,
                'id'          => $post_id,
                'post_id'     => $post_id,
                'site_url'    => (string) $row['site_url'],
                'client_name' => (string) $row['client_name'],
                'context'     => $ctx,
                'enqueued_at' => isset( $row['enqueued_at'] ) ? (int) $row['enqueued_at'] : 0,
                'request_id'  => isset( $row['request_id'] ) ? (string) $row['request_id'] : '',
                'status'      => 'claimed', // לוגי בלבד – במערכת זה 1
                'claimed_at'  => $now,
                'attempts'    => $attempts,
            );

            $jobs_log[] = array(
                'id'          => $post_id,
                'post_id'     => $post_id,
                'client_name' => (string) $row['client_name'],
                'site_url'    => (string) $row['site_url'],
                'context'     => $ctx,
            );
        }

        if ( empty( $claimed ) ) {
            return array();
        }

        // callback ל-report
        $callback = rest_url( 'ssl-agent/v1/report' );
        foreach ( $claimed as &$job ) {
            $job['callback'] = $callback;
        }
        unset( $job );

        $this->log_activity(
            'משימות נמסרו לסוכן',
            array(
                'count' => count( $claimed ),
                'token' => $token_label,
                'jobs'  => $jobs_log,
            ) + $this->get_current_actor_context()
        );

        return $claimed;
    }
    private function peek_queue_tasks($limit, $agent_filter = null){
        $limit = min(100, max(1, (int)$limit));
        $tasks = [];
        $this->release_stale_claims();
        if(!$this->queue_table_exists()){
            return [];
        }
        global $wpdb;
        $table = $this->get_queue_table_name();
        $sql = "SELECT post_id, site_url, client_name, context, agent_token, enqueued_at, request_id, attempts FROM {$table} WHERE status = 'queued' AND attempts < %d";
        $params = [self::QUEUE_MAX_ATTEMPTS];
        if($agent_filter !== null && $agent_filter !== ''){
            $sql .= " AND agent_token = %s";
            $params[] = sanitize_text_field($agent_filter);
        }
        $sql .= " ORDER BY enqueued_at ASC LIMIT %d";
        $params[] = $limit;
        $rows = $wpdb->get_results($wpdb->prepare($sql, ...$params), ARRAY_A);
        foreach((array)$rows as $row){
            $tasks[] = [
                'id'          => (int)$row['post_id'],
                'post_id'     => (int)$row['post_id'],
                'site_url'    => esc_url_raw((string)$row['site_url']),
                'client_name' => wp_strip_all_tags((string)$row['client_name']),
                'context'     => isset($row['context']) && $row['context'] !== '' ? sanitize_key((string)$row['context']) : 'manual',
                'agent_token' => isset($row['agent_token']) ? sanitize_text_field((string)$row['agent_token']) : '',
                'enqueued_at' => isset($row['enqueued_at']) ? (int)$row['enqueued_at'] : 0,
                'request_id'  => isset($row['request_id']) ? sanitize_text_field((string)$row['request_id']) : '',
                'status'      => 'queued',
                'attempts'    => isset($row['attempts']) ? (int)$row['attempts'] : 0,
                'callback'    => rest_url('ssl-agent/v1/report'),
            ];
        }
        return $tasks;
    }
    private function complete_queue_task($post_id, $request_id, $success = true, $message = '', array $extra_context = [], $queue_id = 0){
        $post_id = (int)$post_id;
        $queue_id = (int)$queue_id;
        $request_id = (string)$request_id;
        $removed = false;
        $job_context = null;
        if($this->queue_table_exists()){
            global $wpdb;
            $table = $this->get_queue_table_name();
            $query = "SELECT * FROM {$table} WHERE post_id = %d";
            $params = [$post_id];
            if($queue_id > 0){
                $query = "SELECT * FROM {$table} WHERE id = %d";
                $params = [$queue_id];
            }
            if($request_id){
                $query .= " AND request_id = %s";
                $params[] = $request_id;
            }
            $query .= " LIMIT 1";
            $job_context = $wpdb->get_row($wpdb->prepare($query, ...$params), ARRAY_A);
            if($job_context){
                $wpdb->delete($table, ['id' => (int)$job_context['id']], ['%d']);
                $removed = true;
            }
        }
        $post = get_post($post_id);
        $client_name = is_array($job_context) && isset($job_context['client_name']) ? $job_context['client_name'] : ($post ? get_post_meta($post_id,'client_name',true) : '');
        $site_url = is_array($job_context) && isset($job_context['site_url']) ? $job_context['site_url'] : ($post ? get_post_meta($post_id,'site_url',true) : '');
        $attempts = is_array($job_context) && isset($job_context['attempts']) ? (int)$job_context['attempts'] : 0;
        $context_label = is_array($job_context) && isset($job_context['context']) ? $job_context['context'] : '';
        $log_context = array_merge([
            'id' => $post_id,
            'request_id' => $request_id,
            'site_url' => $site_url,
            'client_name' => $client_name,
            'check_name' => $post ? $post->post_title : $client_name,
            'queue_context' => $context_label,
            'status' => $success ? 'success' : 'failure',
            'message' => $message,
            'attempts' => $attempts,
            'checked_at' => date_i18n('d/m/Y H:i:s'),
        ], $extra_context, $this->get_current_actor_context());
        if(!empty($extra_context['issuer_name'])){
            update_post_meta($post_id,'cert_ca', sanitize_text_field($extra_context['issuer_name']));
        }
        if(!empty($log_context['expiry_ts'])){
            $log_context['expiry_ts'] = (int)$log_context['expiry_ts'];
            if($log_context['expiry_ts'] > 0){
                $log_context['expiry_date'] = date_i18n('Y-m-d', $log_context['expiry_ts']);
            }
        }
        if($removed){
            $this->log_activity($success ? 'משימת בדיקה הסתיימה' : 'משימת בדיקה נכשלה', $log_context, $success ? 'info' : 'error');
        } else {
            $this->log_activity('משימה שלא נמצאה בתור', $log_context, 'warning');
        }
    }
    public function ensure_token_store(){
        $tokens = get_option(self::OPTION_TOKEN, null);
        if($tokens === null){
            add_option(self::OPTION_TOKEN, []);
            return;
        }
        if(!is_array($tokens)){
            if($tokens){
                $converted = [[
                    'id'      => $this->generate_token_id(),
                    'name'    => 'Token ראשי',
                    'token'   => (string)$tokens,
                    'created' => time(),
                    'updated' => time(),
                ]];
                update_option(self::OPTION_TOKEN, $converted);
            } else {
                update_option(self::OPTION_TOKEN, []);
            }
        } else {
            $normalized = $this->normalize_tokens($tokens);
            if($normalized !== $tokens){
                update_option(self::OPTION_TOKEN, $normalized);
            }
        }
    }

    public function purge_legacy_queue_option(){
        delete_option(self::OPTION_QUEUE);
    }

    public function ensure_log_store(){
        $log = get_option(self::OPTION_LOG, null);
        if($log === null){
            add_option(self::OPTION_LOG, [], false);
            $log = [];
        }
        if(!is_array($log)){
            update_option(self::OPTION_LOG, [], false);
            $log = [];
        }
        $log_path = $this->get_plugin_log_path();
        if(function_exists('wp_mkdir_p')){
            wp_mkdir_p(dirname($log_path));
        }
        if(!file_exists($log_path)){
            @touch($log_path);
        }
    }
    public function ensure_cert_type_store(){
        $types = get_option(self::OPTION_CERT_TYPES, null);
        if($types === null){
            add_option(self::OPTION_CERT_TYPES, $this->get_default_cert_types(), false);
            return;
        }
        if(!is_array($types)){
            update_option(self::OPTION_CERT_TYPES, $this->get_default_cert_types(), false);
            return;
        }
        $normalized = $this->normalize_cert_types($types);
        if($normalized !== $types){
            update_option(self::OPTION_CERT_TYPES, $normalized, false);
        }
    }
    public function ensure_general_settings_store(){
        $settings = get_option(self::OPTION_SETTINGS, null);
        if($settings === null){
            add_option(self::OPTION_SETTINGS, $this->sanitize_general_settings([]), false);
            return;
        }
        if(!is_array($settings)){
            update_option(self::OPTION_SETTINGS, $this->sanitize_general_settings([]), false);
            return;
        }
        $normalized = $this->sanitize_general_settings($settings);
        if($normalized !== $settings){
            update_option(self::OPTION_SETTINGS, $normalized, false);
        }
    }
    private function get_default_cert_types(){
        return [
            [
                'key'   => 'fortigate',
                'label' => 'Fortigate',
                'color' => '#16a34a',
            ],
            [
                'key'   => 'priority',
                'label' => 'Priority',
                'color' => '#2563eb',
            ],
            [
                'key'   => 'website',
                'label' => 'Website',
                'color' => '#111827',
            ],
            [
                'key'   => 'wms',
                'label' => 'WMS',
                'color' => '#facc15',
            ],
        ];
    }
    private function normalize_cert_types($types){
        $normalized = [];
        $used = [];
        foreach((array)$types as $type){
            if(!is_array($type)){
                continue;
            }
            $label = isset($type['label']) ? sanitize_text_field($type['label']) : '';
            $key = isset($type['key']) ? $this->sanitize_cert_type_key($type['key'], $label) : $this->sanitize_cert_type_key('', $label);
            if($key === ''){
                continue;
            }
            if(isset($used[$key])){
                $suffix = 2;
                $base = $key;
                while(isset($used[$base.'-'.$suffix])){
                    $suffix++;
                }
                $key = $base.'-'.$suffix;
            }
            $color = isset($type['color']) ? $this->sanitize_cert_type_color($type['color']) : '#2563eb';
            if($label === ''){
                $label = ucfirst(str_replace('-', ' ', $key));
            }
            $used[$key] = true;
            $normalized[] = [
                'key'   => $key,
                'label' => $label,
                'color' => $color,
            ];
        }
        if(empty($normalized)){
            $normalized = $this->get_default_cert_types();
        }
        return $normalized;
    }
    private function sanitize_cert_type_key($value, $fallback = ''){
        $value = sanitize_key((string)$value);
        if($value !== ''){
            return $value;
        }
        $fallback = sanitize_text_field((string)$fallback);
        if($fallback === ''){
            return '';
        }
        $fallback = strtolower($fallback);
        $fallback = preg_replace('/[^a-z0-9\-]+/', '-', $fallback);
        $fallback = trim($fallback, '-');
        return sanitize_key($fallback);
    }
    private function sanitize_management_owner($value){
        $value = sanitize_key((string)$value);
        if($value === 'not-ours'){
            return 'not-ours';
        }
        return 'ours';
    }
    private function determine_auto_cert_type($site_url, $current_type){
        $site_url = trim((string)$site_url);
        $current_type = $this->sanitize_cert_type_key($current_type);
        if($site_url === ''){
            return $current_type;
        }
        $parsed = wp_parse_url($site_url);
        $host = isset($parsed['host']) ? strtolower($parsed['host']) : '';
        $port = isset($parsed['port']) ? (int)$parsed['port'] : null;
        if($host === ''){
            $host = preg_replace('#^https?://#i','',$site_url);
            $host = trim((string)$host, '/');
        }
        if($port === 7443){
            return 'fortigate';
        }
        $normalized_host = preg_replace('/^www\./i', '', $host);
        if($normalized_host !== ''){
            $parts = explode('.', $normalized_host);
            if(count($parts) <= 2){
                return 'website';
            }
            return 'priority';
        }
        return $current_type;
    }
    private function sanitize_general_settings($settings){
        $defaults = [
            'manual_interval' => 10,
            'default_gateway' => '',
            'expiry_alert_days' => 30,
            'monitor_email' => '',
            'smtp_host' => '',
            'smtp_username' => '',
            'smtp_password' => '',
            'smtp_port' => 587,
            'smtp_encryption' => '',
            'smtp_from' => '',
            'smtp_from_name' => '',
            'log_file_enabled' => 1,
        ];
        $settings = wp_parse_args(is_array($settings) ? $settings : [], $defaults);
        $interval = isset($settings['manual_interval']) ? (int)$settings['manual_interval'] : $defaults['manual_interval'];
        if($interval < 1){
            $interval = 1;
        }
        if($interval > DAY_IN_SECONDS){
            $interval = DAY_IN_SECONDS;
        }
        $gateway = isset($settings['default_gateway']) ? sanitize_text_field($settings['default_gateway']) : '';
        $expiry_days = isset($settings['expiry_alert_days']) ? (int)$settings['expiry_alert_days'] : $defaults['expiry_alert_days'];
        if($expiry_days < 1){
            $expiry_days = 1;
        }
        if($expiry_days > 365){
            $expiry_days = 365;
        }
        $monitor_email = isset($settings['monitor_email']) ? sanitize_email($settings['monitor_email']) : '';
        $smtp_host = isset($settings['smtp_host']) ? sanitize_text_field($settings['smtp_host']) : '';
        $smtp_username = isset($settings['smtp_username']) ? sanitize_text_field($settings['smtp_username']) : '';
        $smtp_password = isset($settings['smtp_password']) ? wp_strip_all_tags((string)$settings['smtp_password']) : '';
        $smtp_port = isset($settings['smtp_port']) ? (int)$settings['smtp_port'] : $defaults['smtp_port'];
        if($smtp_port < 1){
            $smtp_port = 1;
        }
        $allowed_encryptions = ['','ssl','tls'];
        $smtp_encryption_raw = isset($settings['smtp_encryption']) ? strtolower((string)$settings['smtp_encryption']) : '';
        $smtp_encryption = in_array($smtp_encryption_raw, $allowed_encryptions, true) ? $smtp_encryption_raw : '';
        $smtp_from = isset($settings['smtp_from']) ? sanitize_email($settings['smtp_from']) : '';
        $smtp_from_name = isset($settings['smtp_from_name']) ? sanitize_text_field($settings['smtp_from_name']) : '';
        $log_file_enabled = !empty($settings['log_file_enabled']) ? 1 : 0;
        return [
            'manual_interval' => $interval,
            'default_gateway' => $gateway,
            'monitor_email' => $monitor_email,
            'expiry_alert_days' => $expiry_days,
            'smtp_host' => $smtp_host,
            'smtp_username' => $smtp_username,
            'smtp_password' => $smtp_password,
            'smtp_port' => $smtp_port,
            'smtp_encryption' => $smtp_encryption,
            'smtp_from' => $smtp_from,
            'smtp_from_name' => $smtp_from_name,
            'log_file_enabled' => $log_file_enabled,
        ];
    }
    private function get_general_settings(){
        $settings = get_option(self::OPTION_SETTINGS, []);
        if(!is_array($settings)){
            $settings = [];
        }
        return $this->sanitize_general_settings($settings);
    }
    private function get_manual_batch_interval(){
        $settings = $this->get_general_settings();
        return isset($settings['manual_interval']) ? (int)$settings['manual_interval'] : 10;
    }
    private function get_default_gateway_label(){
        $settings = $this->get_general_settings();
        return isset($settings['default_gateway']) ? $settings['default_gateway'] : '';
    }
    private function get_monitor_emails(){
        $settings = $this->get_general_settings();
        $emails = [];
        if(!empty($settings['token_alert_emails']) && is_array($settings['token_alert_emails'])){
            foreach($settings['token_alert_emails'] as $email){
                $email = sanitize_email($email);
                if($email){
                    $emails[$email] = $email;
                }
            }
        }
        if(empty($emails) && !empty($settings['monitor_email'])){
            $email = sanitize_email($settings['monitor_email']);
            if($email){
                $emails[$email] = $email;
            }
        }
        if(empty($emails)){
            $admin = sanitize_email(get_option('admin_email'));
            if($admin){
                $emails[$admin] = $admin;
            }
        }
        return array_values($emails);
    }
    private function sanitize_cert_type_color($value){
        $value = (string)$value;
        if($value === ''){
            return '#2563eb';
        }
        $color = sanitize_hex_color($value);
        if($color){
            return $color;
        }
        return '#2563eb';
    }
    private function get_cert_type_contrast_color($color){
        $color = ltrim((string)$color, '#');
        if(strlen($color) === 3){
            $color = $color[0].$color[0].$color[1].$color[1].$color[2].$color[2];
        }
        if(strlen($color) !== 6){
            return '#ffffff';
        }
        $r = hexdec(substr($color, 0, 2));
        $g = hexdec(substr($color, 2, 2));
        $b = hexdec(substr($color, 4, 2));
        $components = [$r, $g, $b];
        foreach($components as $index => $component){
            $normalized = $component / 255;
            if($normalized <= 0.03928){
                $components[$index] = $normalized / 12.92;
            } else {
                $components[$index] = pow(($normalized + 0.055) / 1.055, 2.4);
            }
        }
        $luminance = 0.2126 * $components[0] + 0.7152 * $components[1] + 0.0722 * $components[2];
        return ($luminance > 0.6) ? '#0f172a' : '#ffffff';
    }
    public function get_certificate_types(){
        $types = get_option(self::OPTION_CERT_TYPES, []);
        if(!is_array($types)){
            $this->ensure_cert_type_store();
            $types = get_option(self::OPTION_CERT_TYPES, []);
        }
        return $this->normalize_cert_types($types);
    }
    public function get_certificate_type_map(){
        $map = [];
        foreach($this->get_certificate_types() as $type){
            $key = isset($type['key']) ? $this->sanitize_cert_type_key($type['key']) : '';
            if($key === ''){
                continue;
            }
            $map[$key] = $type;
        }
        return $map;
    }
    private function get_default_cert_type_key(){
        $types = $this->get_certificate_types();
        if(!empty($types)){
            $first = reset($types);
            return isset($first['key']) ? $this->sanitize_cert_type_key($first['key']) : '';
        }
        return '';
    }
    private function build_cert_type_options($selected){
        $options = '';
        $selected = $this->sanitize_cert_type_key($selected);
        foreach($this->get_certificate_types() as $type){
            $key = isset($type['key']) ? $this->sanitize_cert_type_key($type['key']) : '';
            if($key === ''){
                continue;
            }
            $label = isset($type['label']) && $type['label'] !== '' ? $type['label'] : $key;
            $options .= "<option value='".esc_attr($key)."'".selected($selected, $key, false).">".esc_html($label)."</option>";
        }
        if($options === ''){
            $options = "<option value='' selected>אין סוגים זמינים</option>";
        }
        return $options;
    }
    private function render_cert_type_badge($slug){
        $key = $this->sanitize_cert_type_key($slug);
        if($key === ''){
            return '';
        }
        $map = $this->get_certificate_type_map();
        if(!isset($map[$key])){
            return '';
        }
        $type = $map[$key];
        $label = isset($type['label']) && $type['label'] !== '' ? $type['label'] : $key;
        $color = isset($type['color']) ? $this->sanitize_cert_type_color($type['color']) : '#334155';
        $style = " style='--ssl-type-color:".esc_attr($color)."'";
        return "<span class='ssl-type-chip' data-ssl-type='".esc_attr($key)."'{$style}><span class='ssl-type-chip__dot' aria-hidden='true'></span>".esc_html($label)."</span>";
    }
    private function normalize_tokens($tokens){
        $normalized = [];
        foreach((array)$tokens as $token){
            if(!is_array($token)) continue;
            $token['id'] = isset($token['id']) && $token['id'] ? sanitize_key($token['id']) : $this->generate_token_id();
            $token['name'] = isset($token['name']) && $token['name'] !== '' ? sanitize_text_field($token['name']) : 'ללא שם';
            $token['token'] = isset($token['token']) && $token['token'] ? (string)$token['token'] : $this->generate_token_value();
            $token['created'] = isset($token['created']) ? (int)$token['created'] : time();
            $token['updated'] = isset($token['updated']) ? (int)$token['updated'] : time();
            $status = isset($token['last_status']) ? strtolower((string)$token['last_status']) : 'unknown';
            if(!in_array($status, ['online','offline','unknown'], true)){
                $status = 'unknown';
            }
            $token['last_status'] = $status;
            $token['last_seen'] = isset($token['last_seen']) ? (int)$token['last_seen'] : 0;
            $token['last_error'] = isset($token['last_error']) ? sanitize_text_field($token['last_error']) : '';
            $token['notify_down'] = !empty($token['notify_down']) ? 1 : 1;
            $emails = [];
            if(isset($token['emails'])){
                foreach((array)$token['emails'] as $email){
                    $email = sanitize_email($email);
                    if($email){
                        $emails[$email] = $email;
                    }
                }
            }
            $token['emails'] = array_values($emails);
            $token['notified_down_at'] = isset($token['notified_down_at']) ? (int)$token['notified_down_at'] : 0;
            $normalized[] = $token;
        }
        return $normalized;
    }
    private function get_tokens(){
        $tokens = get_option(self::OPTION_TOKEN, []);
        if(!is_array($tokens)){
            $tokens = [];
        }
        $tokens = $this->normalize_tokens($tokens);
        $tokens = $this->apply_token_recency($tokens);
        $this->sync_tokens_to_agents($tokens);
        return $tokens;
    }
    private function save_tokens($tokens){
        update_option(self::OPTION_TOKEN, $this->normalize_tokens($tokens));
        $this->sync_tokens_to_agents($tokens);
    }

    private function apply_token_recency(array $tokens){
        $cutoff = time() - self::TOKEN_STALE_WINDOW;
        $dirty  = false;
        foreach($tokens as &$token){
            $last_seen = isset($token['last_seen']) ? (int)$token['last_seen'] : 0;
            $status    = isset($token['last_status']) ? (string)$token['last_status'] : 'unknown';
            $should_offline = ($status === 'online') && ($last_seen === 0 || $last_seen < $cutoff);
            if($should_offline){
                $token['last_status'] = 'offline';
                if(empty($token['last_error'])){
                    $token['last_error'] = $last_seen
                        ? sprintf('לא התקבלה תקשורת מאז %s', date_i18n('d.m.Y H:i', $last_seen))
                        : 'לא התקבלה תקשורת מהסוכן';
                }
                $dirty = true;
            }
        }
        unset($token);
        if($dirty){
            update_option(self::OPTION_TOKEN, $tokens);
        }
        return $tokens;
    }

    private function describe_token_status(array $token){
        $now       = time();
        $cutoff    = $now - self::TOKEN_STALE_WINDOW;
        $last_seen = isset($token['last_seen']) ? (int)$token['last_seen'] : 0;
        $status    = isset($token['last_status']) ? (string)$token['last_status'] : 'unknown';
        $effective = $status;
        if($last_seen === 0){
            $effective = $status === 'offline' ? 'offline' : 'unknown';
        } elseif($last_seen < $cutoff){
            $effective = 'offline';
        }

        $label = 'לא ידוע';
        $dot   = 'ssl-token-status__dot--unknown';
        if($effective === 'online'){
            $label = 'מחובר';
            $dot   = 'ssl-token-status__dot--online';
        } elseif($effective === 'offline'){
            $label = 'מנותק';
            $dot   = 'ssl-token-status__dot--offline';
        }

        $meta = [];
        if($last_seen){
            $meta[] = 'חיבור אחרון: '.date_i18n('d.m.Y H:i', $last_seen);
            if($last_seen < $cutoff){
                $meta[] = 'לא זוהתה תקשורת '.human_time_diff($last_seen, $now).' (סומן מנותק)';
            }
        } else {
            $meta[] = 'לא התקבלה תקשורת עדיין';
        }
        if(!empty($token['last_error']) && $effective !== 'online'){
            $meta[] = 'שגיאה אחרונה: '.$token['last_error'];
        }
        if(!empty($token['updated'])){
            $meta[] = 'עודכן: '.date_i18n('d.m.Y H:i', (int)$token['updated']);
        }

        return [
            'label' => $label,
            'dot'   => $dot,
            'meta'  => $meta,
        ];
    }
    private function ensure_default_token(){
        $tokens = $this->get_tokens();
        if(!empty($tokens)){
            return $tokens;
        }
        $default = [[
            'id'      => $this->generate_token_id(),
            'name'    => 'Token ראשי',
            'token'   => $this->generate_token_value(),
            'created' => time(),
            'updated' => time(),
            'last_status' => 'unknown',
            'last_seen'   => 0,
            'last_error'  => '',
            'notify_down' => 1,
            'emails'      => [],
            'notified_down_at' => 0,
        ]];
        $this->save_tokens($default);
        return $default;
    }
    private function sync_tokens_to_agents($tokens){
        global $wpdb;
        $table = $this->get_agents_table_name();
        foreach((array)$tokens as $token){
            if(empty($token['token'])){
                continue;
            }
            $existing = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table} WHERE token = %s", $token['token']));
            if(!$existing){
                $wpdb->insert($table,[
                    'name'   => $token['name'] ?? 'Agent',
                    'token'  => $token['token'],
                    'status' => 'unknown',
                ]);
            }
        }
    }
    private function generate_token_value(){
        return bin2hex(random_bytes(16));
    }
    private function generate_token_id(){
        return 'tok_'.wp_generate_password(8, false, false);
    }
    private function get_primary_token(){
        $tokens = $this->ensure_default_token();
        return $tokens[0] ?? null;
    }
    private function get_default_agent_token_id(){
        $primary = $this->get_primary_token();
        return $primary && !empty($primary['id']) ? sanitize_text_field($primary['id']) : '';
    }
    private function get_effective_agent_token($post_id){
        $stored = (string)get_post_meta($post_id,'agent_token',true);
        if($stored !== ''){
            return sanitize_text_field($stored);
        }
        $default = $this->get_default_agent_token_id();
        if($default !== ''){
            update_post_meta($post_id,'agent_token',$default);
        }
        return $default;
    }
    private function get_page_url($slug, $fallback){
        $page = get_page_by_path($slug);
        if($page){
            $url = get_permalink($page);
            if($url){
                return $url;
            }
        }
        return $fallback;
    }

    private function resolve_main_page_url(){
        foreach(['ssl-cert-table','ssl-manager','ssl-table'] as $slug){
            $candidate = $this->get_page_url($slug, '');
            if($candidate){
                return $candidate;
            }
        }
        return self::PAGE_MAIN_FALLBACK;
    }

    private function resolve_token_page_url(){
        $page = $this->get_page_url('ssl-token-page', '');
        if($page){
            return $page;
        }
        $legacy = $this->get_page_url('ssl-token', '');
        if($legacy){
            return $legacy;
        }
        return self::PAGE_TOKEN_FALLBACK;
    }

    private function resolve_trash_page_url(){
        return $this->get_page_url('ssl-trash', self::PAGE_TRASH_FALLBACK);
    }

    private function resolve_logs_page_url(){
        $page = $this->get_page_url('ssl-logs', '');
        if($page){
            return $page;
        }
        return self::PAGE_LOG_FALLBACK;
    }

    private function get_primary_token_value(){
        $token = $this->get_primary_token();
        if($token && !empty($token['token'])){
            return (string)$token['token'];
        }
        return '';
    }

    private function update_token_fields($token_id, array $changes){
        $tokens = $this->ensure_default_token();
        $updated = null;
        $token_value = '';
        foreach($tokens as &$token){
            if($token['id'] !== $token_id){
                continue;
            }
            $token_value = $token['token'] ?? '';
            foreach($changes as $key => $value){
                $token[$key] = $value;
            }
            $updated = $token;
            break;
        }
        unset($token);
        if($updated !== null){
            $this->save_tokens($tokens);
            if($token_value){
                global $wpdb;
                $table = $this->get_agents_table_name();
                $wpdb->update($table,[
                    'last_seen' => isset($changes['last_seen']) ? date('Y-m-d H:i:s', (int)$changes['last_seen']) : current_time('mysql', true),
                    'status'    => $changes['last_status'] ?? 'unknown',
                    'notes'     => $changes['last_error'] ?? '',
                ],['token'=>$token_value]);
            }
        }
        return $updated;
    }

    private function mark_token_online($token_id){
        return $this->update_token_fields($token_id, [
            'last_seen' => time(),
            'last_status' => 'online',
            'last_error' => '',
            'notified_down_at' => 0,
        ]);
    }

    private function mark_token_offline($token_id, $message){
        return $this->update_token_fields($token_id, [
            'last_status' => 'offline',
            'last_error' => $message,
        ]);
    }

    private function maybe_notify_token_down($token, $message){
        if(empty($token['notify_down'])){
            return;
        }
        $recipients = array_filter(array_map('sanitize_email', (array)($token['emails'] ?? [])));
        if(empty($recipients)){
            return;
        }
        $already = isset($token['notified_down_at']) ? (int)$token['notified_down_at'] : 0;
        if($already && (time() - $already) < HOUR_IN_SECONDS){
            return;
        }
        if(!function_exists('wp_mail')){
            return;
        }
        $site = wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES);
        $subject = sprintf('התראת חיבור סוכן SSL - %s', $token['name']);
        $body = sprintf("שלום,\n\nהחיבור לסוכן ה-SSL עבור הטוקן \"%s\" נפל.\nהודעה אחרונה: %s\nאתר: %s\nזמן: %s\n\nהטוקן יסומן כמנותק עד שיתקבל חיבור מחודש.",
            $token['name'],
            $message ? $message : 'לא התקבלה שגיאה מפורטת',
            home_url('/'),
            date_i18n('d.m.Y H:i')
        );
        wp_mail($recipients, $subject.' - '.$site, $body);
        $this->update_token_fields($token['id'], ['notified_down_at' => time()]);
    }

    private function has_recent_agent_contact($window_seconds = self::TOKEN_STALE_WINDOW){
        $cutoff = time() - absint($window_seconds);
        foreach($this->get_tokens() as $token){
            if(!empty($token['last_seen']) && (int)$token['last_seen'] >= $cutoff){
                return true;
            }
        }
        global $wpdb;
        $table = $this->get_agents_table_name();
        $cutoff_mysql = gmdate('Y-m-d H:i:s', $cutoff);
        $count = $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM {$table} WHERE last_seen IS NOT NULL AND last_seen >= %s", $cutoff_mysql));
        return (int)$count > 0;
    }

    private function get_stale_tokens($window_seconds = null){
        $window_seconds = $window_seconds === null ? self::TOKEN_STALE_WINDOW : (int)$window_seconds;
        $cutoff = time() - absint($window_seconds);
        $stale = [];
        foreach($this->get_tokens() as $token){
            $last_seen = isset($token['last_seen']) ? (int)$token['last_seen'] : 0;
            if($last_seen === 0 || $last_seen < $cutoff){
                $stale[] = $token;
            }
        }
        return $stale;
    }

    private function collect_token_email_choices(){
        $choices = [];
        $admin_email = sanitize_email(get_option('admin_email'));
        if($admin_email){
            $choices[$admin_email] = $admin_email.' (מנהל)';
        }
        $users = get_users(['fields' => ['ID','display_name','user_email']]);
        foreach($users as $user){
            $email = sanitize_email($user->user_email);
            if(!$email){
                continue;
            }
            $label = $email;
            if(!empty($user->display_name) && stripos($user->display_name, $email) === false){
                $label = $user->display_name.' <'.$email.'>';
            }
            $choices[$email] = $label;
        }
        return $choices;
    }
    private function build_agent_option_markup($selected_token, $disabled = false){
        $tokens = $this->get_tokens();
        $selected = $selected_token ?: $this->get_default_agent_token_id();
        $html = '';
        foreach($tokens as $token){
            if(empty($token['id']) || empty($token['name'])){
                continue;
            }
            $value = sanitize_text_field($token['id']);
            $label = sanitize_text_field($token['name']);
            $html .= "<option value='".esc_attr($value)."'".selected($selected,$value,false).($disabled?" disabled":'').">".esc_html($label)."</option>";
        }
        return $html;
    }

    private function parse_token_emails($selected, $extra){
        $emails = [];
        foreach((array)$selected as $email){
            $email = sanitize_email($email);
            if($email){
                $emails[$email] = $email;
            }
        }
        if($extra){
            $parts = preg_split('/[\s,;]+/', (string)$extra);
            foreach($parts as $email){
                $email = sanitize_email($email);
                if($email){
                    $emails[$email] = $email;
                }
            }
        }
        return array_values($emails);
    }

    private function get_remote_client_settings(){
        // Always treat the agent as enabled; no UI toggle remains.
        $saved = get_option(self::OPTION_REMOTE, []);
        if(!is_array($saved)){
            $saved = [];
        }
        // Preserve shape for future options but default to enabled.
        $defaults = [
            'enabled' => 1,
        ];
        $settings = wp_parse_args($saved, $defaults);
        $settings = [
            'enabled' => 1,
        ];
        return $settings;
    }

    private function remote_client_is_ready($settings = null){
        // Enabled state no longer depends on UI; only require a primary token.
        $primary = $this->get_primary_token();
        if(!$primary || empty($primary['token'])){
            return false;
        }
        return true;
    }

    private function dispatch_remote_check($post_id, $url, $context = 'manual', $settings = null){
        if($this->is_manual_mode($post_id)){
            return false;
        }
        if($settings === null){
            $settings = $this->get_remote_client_settings();
        }
        if(!$this->remote_client_is_ready($settings)){
            return false;
        }
        $success = $this->enqueue_task($post_id, $context);
        if($success){
            $primary = $this->get_primary_token();
            if($primary){
                $this->mark_token_online($primary['id']);
            }
        }
        return $success;
    }

    public function shortcode_table($atts = []) {
        $default_trash = $this->resolve_trash_page_url();
        $default_token = $this->resolve_token_page_url();
        $default_logs  = $this->resolve_logs_page_url();
        $a = shortcode_atts([
            'trash_url' => $default_trash,
            'token_url' => $default_token,
            'logs_url'  => $default_logs,
        ], $atts);
        $per_page_choices = [25, 100, 500];
        $requested_per_page = isset($_GET['ssl_per_page']) ? intval($_GET['ssl_per_page']) : 25;
        if(!in_array($requested_per_page, $per_page_choices, true)){
            $requested_per_page = 25;
        }
        $current_page = isset($_GET['ssl_page']) ? max(1, intval($_GET['ssl_page'])) : 1;
        $preserved_query = [];
        if(!empty($_GET)){
            foreach($_GET as $key => $value){
                if(is_array($value)){
                    continue;
                }
                $preserved_query[$key] = sanitize_text_field(wp_unslash($value));
            }
        }
        $duplicate_error = isset($preserved_query['ssl_error']) && $preserved_query['ssl_error'] === 'duplicate_site';
        $single_success_id = isset($_GET['ssl_single']) ? max(0, intval($_GET['ssl_single'])) : 0;
        $single_error_code = isset($_GET['ssl_single_error']) ? sanitize_key($_GET['ssl_single_error']) : '';
        $sort = isset($preserved_query['ssl_sort']) ? sanitize_key($preserved_query['ssl_sort']) : 'expiry_ts';
        $order = isset($preserved_query['ssl_order']) && strtolower($preserved_query['ssl_order']) === 'desc' ? 'DESC' : 'ASC';
        $search = $preserved_query['ssl_search'] ?? '';
        $missing_only = !empty($preserved_query['ssl_missing']);
        unset($preserved_query['ssl_single'], $preserved_query['ssl_single_error'], $preserved_query['ssl_error']);
        $group_mode = 'cn';
        $preserved_query['ssl_group'] = 'cn';
        $table_data = $this->fetch_certificates([
            'page' => $current_page,
            'per_page' => $requested_per_page,
            'search' => $search,
            'orderby' => $sort,
            'order' => $order,
            'missing_only' => $missing_only,
        ]);
        $rows = $table_data['rows'];
        $total_found = $table_data['total'];
        $total_with_expiry = isset($table_data['total_with_expiry']) ? (int)$table_data['total_with_expiry'] : 0;
        $current_page_total = count($rows);
        $current_page_with_expiry = 0;
        foreach($rows as $row_for_counts){
            if(!empty($row_for_counts['expiry_ts'])){
                $current_page_with_expiry++;
            }
        }
        $scope_counts = $this->get_certificate_scope_counts();
        $status_counts = $this->get_certificate_status_counts();
        $bubble_total = 0;
        foreach(['red','yellow','green','grey'] as $status_key){
            $bubble_total += isset($status_counts[$status_key]) ? (int)$status_counts[$status_key] : 0;
        }
        if($bubble_total === 0 && $total_found > 0){
            $bubble_total = (int)$total_found;
        }
        $total_pages = max(1, (int)ceil($total_found / $requested_per_page));
        $is_create_hidden = empty($_GET['ssl_new']);
        $create_attr = $is_create_hidden ? ' hidden' : '';
        $admin_email = sanitize_email(get_option('admin_email'));
        $single_success_message = '';
        $single_error_message = '';
        if($single_success_id > 0){
            $client_label = sanitize_text_field((string)get_post_meta($single_success_id,'client_name',true));
            $site_label_raw = (string)get_post_meta($single_success_id,'site_url',true);
            $site_label = $site_label_raw !== '' ? esc_url_raw($site_label_raw) : '';
            if($client_label === ''){
                $client_label = sprintf('רשומה #%d', $single_success_id);
            }
            if($site_label !== ''){
                $single_success_message = sprintf('הופעלה בדיקת SSL עבור %s (%s).', $client_label, $site_label);
            } else {
                $single_success_message = sprintf('הופעלה בדיקת SSL עבור %s.', $client_label);
            }
        } elseif($single_error_code !== ''){
            $single_error_messages = [
                'missing' => 'לא נבחרה רשומה לעדכון.',
                'invalid' => 'הרשומה שביקשת לעדכן לא נמצאה.',
                'nosite'  => 'לא הוגדר אתר לרשומה זו ולכן לא ניתן לבצע בדיקה.',
                'manual'  => 'רשומה זו מוגדרת כידנית ולכן אינה נבדקת אוטומטית.',
            ];
            $single_error_message = $single_error_messages[$single_error_code] ?? 'לא ניתן היה להפעיל עדכון לרשומה.';
        }
        $export_url = esc_url(site_url('?ssl_action='.self::EXPORT_ACTION));
        $refresh_url = esc_url(remove_query_arg(['ssl_new','ssl_single','ssl_single_error']));
        $manager_classes = 'ssl-manager';
        $bulk_edit_url = 'https://kb.macomp.co.il/?page_id=13973';
        if($requested_per_page >= 250){
            $manager_classes .= ' ssl-manager--compact';
        }
        $cert_type_map = $this->get_certificate_type_map();
        $default_cert_type = $this->get_default_cert_type_key();
        $cert_type_options_default = $this->build_cert_type_options($default_cert_type);
        $agent_option_markup_default = $this->build_agent_option_markup($this->get_default_agent_token_id());
        $agent_label_map = [];
        foreach($this->get_tokens() as $agent_token){
            if(!empty($agent_token['id']) && !empty($agent_token['name'])){
                $agent_label_map[$agent_token['id']] = $agent_token['name'];
            }
        }
        $existing_identifiers = $this->get_existing_certificate_identifiers();
        $existing_json = wp_json_encode($existing_identifiers, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP);
        ob_start();
        if($existing_json){
            echo "<script type='application/json' id='ssl-existing-records'>{$existing_json}</script>";
        }
        echo "<div class='".esc_attr($manager_classes)."'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>ניהול תאריכי תפוגת תעודת אבטחה</h2>"; 
        if ($admin_email) {
            echo "<div class='ssl-manager__subtitle'>".esc_html($admin_email)."</div>";
        }
        echo "</div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-primary' data-ssl-toggle='create' href='".esc_url(add_query_arg('ssl_new','1'))."'>הוסף רשומה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($bulk_edit_url)."'>עריכה קבוציתית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>הגדרות</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "<form class='ssl-page-size' method='get'>";
        foreach($preserved_query as $key => $value){
            if(in_array($key, ['ssl_per_page','ssl_page'], true)){
                continue;
            }
            echo "<input type='hidden' name='".esc_attr($key)."' value='".esc_attr($value)."'>";
        }
        echo "<input type='hidden' name='ssl_page' value='1' data-ssl-page-input>";
        echo "<label>הצג<select name='ssl_per_page' data-ssl-page-size>";
        foreach($per_page_choices as $choice){
            $label = number_format_i18n($choice);
            $selected = selected($requested_per_page, $choice, false);
            echo "<option value='".esc_attr($choice)."'{$selected}>".esc_html($label).'  רשומות לדף' ."</option>";
        }
        echo "</select></label>";
        echo "<noscript><button class='ssl-btn ssl-btn-outline' type='submit'>עדכן</button></noscript>";
        echo "</form>";
        echo "</div></div>";
        $bubble_defs = [
            'red' => ['label' => 'אדום', 'description' => 'דורש טיפול מידי', 'class' => 'ssl-status-bubble--red'],
            'yellow' => ['label' => 'צהוב', 'description' => 'חודש-שלושה הקרובים', 'class' => 'ssl-status-bubble--yellow'],
            'green' => ['label' => 'ירוק', 'description' => 'מעל 90 יום', 'class' => 'ssl-status-bubble--green'],
            'grey' => ['label' => 'ללא תאריך', 'description' => 'אין תוקף שמור', 'class' => 'ssl-status-bubble--grey'],
        ];
        echo "<div class='ssl-status-bubbles' role='region' aria-label='התפלגות סטטוסים'>";
        foreach($bubble_defs as $key => $bubble){
            $count = isset($status_counts[$key]) ? (int)$status_counts[$key] : 0;
            $formatted = number_format_i18n($count);
            $label = esc_html($bubble['label']);
            $desc = esc_html($bubble['description']);
            $class = esc_attr($bubble['class']);
            echo "<div class='ssl-status-bubble {$class}'>";
            echo "<span class='ssl-status-bubble__label'>{$label}</span>";
            echo "<span class='ssl-status-bubble__value'>{$formatted}</span>";
            echo "<span class='ssl-status-bubble__description'>{$desc}</span>";
            echo "</div>";
        }
        echo "</div>";
        $total_row_display = sprintf(
            'סה\"כ רשומות: <strong>%1$s</strong> <span class="ssl-total-row__details">(מוצגות כעת: %2$s, הגדרת דף: %3$s)</span>',
            esc_html(number_format_i18n($bubble_total)),
            esc_html(number_format_i18n($current_page_total)),
            esc_html(number_format_i18n($requested_per_page))
        );
        echo "<div class='ssl-total-row' role='status'>{$total_row_display}</div>";
        $stale_tokens = $this->get_stale_tokens();
        if(!empty($stale_tokens)){
            $label_parts = [];
            foreach($stale_tokens as $token){
                $name = isset($token['name']) && $token['name'] !== '' ? $token['name'] : 'טוקן ללא שם';
                $last_seen_label = !empty($token['last_seen']) ? date_i18n('d.m.Y H:i', (int)$token['last_seen']) : 'לא התקבל חיבור';
                $label_parts[] = esc_html(sprintf('%s (אחרון: %s)', $name, $last_seen_label));
            }
            $label_text = implode(', ', $label_parts);
            echo "<div class='ssl-alert ssl-alert--warning'>החיבור לטוקנים הבאים לא זמין מעל 5 דקות: {$label_text}. נשלחת התראת דוא\"ל במקביל.</div>";
        }
        if($single_success_message !== ''){
            echo "<div class='ssl-alert ssl-alert--success'>".esc_html($single_success_message)."</div>";
        } elseif($single_error_message !== ''){
            echo "<div class='ssl-alert ssl-alert--warning'>".esc_html($single_error_message)."</div>";
        }
        if($duplicate_error){
            echo "<div class='ssl-alert ssl-alert--warning'>כבר קיימת רשומה עם אותו אתר. סמן \"אפשר כפילות בשם האתר\" אם נדרש להוסיף בכל זאת.</div>";
        }

        echo "<div class='ssl-card ssl-card--form' data-ssl-create{$create_attr}>";
        echo "<div class='ssl-card__header'><h3>הוספת רשומה חדשה</h3><button type='button' class='ssl-btn ssl-btn-ghost' data-ssl-toggle='create' title='סגירת הטופס' aria-label='סגירת הטופס'>&#10005;</button></div>";
        echo "<form class='ssl-create-form' data-ssl-create-form method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
              ."  <input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />"
              ."  <input type='hidden' name='post_id' value='0' />"
              ."  <div class='ssl-card__body ssl-card__body--compact'>"
              ."    <label>שם הלקוח<input type='text' name='client_name' required></label>"
              ."    <label>אתר (URL)<input type='text' name='site_url' placeholder='example.com' data-ssl-create-site data-ssl-autofill-url><span class='ssl-form-warning' data-ssl-warning-site hidden></span><label class='ssl-checkbox ssl-checkbox--inline ssl-checkbox--sub'><input type='checkbox' name='allow_duplicate_site' value='1'> אפשר כפילות בשם האתר</label></label>"
              ."    <label class='ssl-date-field ssl-form-span-2'><span>תאריך תפוגה</span><div class='ssl-date-field__controls'><input type='date' name='expiry_date' data-ssl-date-input><label class='ssl-checkbox ssl-checkbox--inline'><input type='checkbox' name='manual_mode' value='1'> ידני (ללא בדיקות אוטומטיות)</label><button type='button' class='ssl-btn ssl-btn-outline' data-ssl-date-next-year>היום בשנה הבאה</button></div></label>"
              ."    <label><span>סוג</span><select name='cert_type' data-ssl-create-type>".$cert_type_options_default."</select></label>"
              ."    <label><span>בניהול</span><select name='management_owner'><option value='ours'>שלנו</option><option value='not-ours'>לא שלנו</option></select></label>"
              ."    <label><span>AGENT</span><select name='agent_token'>".$agent_option_markup_default."</select></label>"
              ."    <label>CN של התעודה<input type='text' name='cert_cn' placeholder='*.example.com' data-ssl-create-cn><span class='ssl-form-warning' data-ssl-warning-cn hidden></span></label>"
                ."    <label>קישור למדריך<input type='text' name='guide_url' placeholder='https://help.example.com' data-ssl-autofill-url></label>"
              ."    <label class='ssl-form-full'>הערות<textarea name='notes' rows='2'></textarea></label>"
              ."    <label class='ssl-form-full'>טקסט זמני<textarea name='temporary_note' rows='2'></textarea><label class='ssl-checkbox ssl-checkbox--inline ssl-checkbox--sub'><input type='checkbox' name='temporary_enabled' value='1'> הפעל טקסט זמני</label></label>"
              ."    <label class='ssl-form-full'>תמונות<input type='file' name='images[]' multiple accept='image/*'></label>"
              ."  </div>"
              ."  <div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit' data-ssl-create-submit>שמור</button></div>"
              ."</form>"
              ."</div>";

        $preview_key = isset($preserved_query['ssl_preview']) ? sanitize_key($preserved_query['ssl_preview']) : '';
        if($preview_key){
            $preview_data = get_transient('ssl_import_'.$preview_key);
            $cancel_url = esc_url(remove_query_arg('ssl_preview'));
            echo "<div class='ssl-card ssl-card--form'>";
            echo "<div class='ssl-card__header'><h3>תצוגה מקדימה לייבוא</h3><a class='ssl-btn ssl-btn-ghost' href='{$cancel_url}'>בטל</a></div>";
            if($preview_data && !empty($preview_data['rows'])){
                $preview_rows = array_slice($preview_data['rows'], 0, 10);
                $total_preview = isset($preview_data['total']) ? (int)$preview_data['total'] : count($preview_data['rows']);
                $file_label = !empty($preview_data['filename']) ? esc_html($preview_data['filename']) : 'קובץ לא מזוהה';
                echo "<div class='ssl-card__body'>";
                echo "<p>קובץ: {$file_label}. יוצגו עד 10 שורות מתוך ".esc_html(number_format_i18n($total_preview)).".</p>";
                echo "<table class='ssl-table'><thead><tr><th>לקוח</th><th>אתר</th><th>CN</th><th>תוקף</th></tr></thead><tbody>";
                foreach($preview_rows as $row){
                    $client_p = esc_html($row['client_name']);
                    $site_p = esc_html($row['site_url']);
                    $cn_p = $row['common_name'] ? esc_html($row['common_name']) : '';
                    $expiry_display = '';
                    if(!empty($row['expiry_date'])){
                        $preview_ts = $this->parse_user_date($row['expiry_date']);
                        if($preview_ts){
                            $expiry_display = esc_html($this->fmt_date($preview_ts));
                        } else {
                            $expiry_display = esc_html($row['expiry_date']);
                        }
                    }
                    echo "<tr><td>{$client_p}</td><td>{$site_p}</td><td>{$cn_p}</td><td>{$expiry_display}</td></tr>";
                }
                if(empty($preview_rows)){
                    echo "<tr><td colspan='4' class='ssl-empty'>לא נמצאו שורות בתצוגה מקדימה</td></tr>";
                }
                echo "</tbody></table>";
                if($total_preview > count($preview_rows)){
                    echo "<div class='ssl-note'>קיימות שורות נוספות שייכללו בייבוא.</div>";
                }
                echo "</div>";
                echo "<div class='ssl-card__footer'>";
                echo "<form method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
                    ."<input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."'>"
                    ."<input type='hidden' name='ssl_import_step' value='confirm'>"
                    ."<input type='hidden' name='preview_key' value='".esc_attr($preview_key)."'>"
                    ."<button class='ssl-btn ssl-btn-primary' type='submit'>אשר ייבוא</button>"
                    ."</form>";
                echo "<a class='ssl-btn ssl-btn-outline' href='{$cancel_url}'>בטל תצוגה מקדימה</a>";
                echo "</div>";
            } else {
                echo "<div class='ssl-card__body'><p>התצוגה המקדימה אינה זמינה או שפג תוקפה.</p></div>";
                echo "<div class='ssl-card__footer'><a class='ssl-btn ssl-btn-outline' href='{$cancel_url}'>חזרה</a></div>";
            }
            echo "</div>";
        }

        $missing_button_class = 'ssl-btn ssl-btn-surface';
        if($missing_only){
            $missing_button_class .= ' is-active';
        }
        echo "<div class='ssl-toolbar ssl-toolbar--filters'>";
        echo "  <div class='ssl-toolbar__group ssl-toolbar__group--toggles'>";
        echo "    <button type='button' class='ssl-btn ssl-btn-surface' data-ssl-expand-all>הרחב הכל</button>";
        echo "    <button type='button' class='ssl-btn ssl-btn-surface' data-ssl-collapse-all>כווץ הכל</button>";
        echo "    <button type='button' class='".esc_attr($missing_button_class)."' data-ssl-filter-missing>חוסרים</button>";
        echo "    <button type='button' class='ssl-btn ssl-btn-surface' data-ssl-filter-reset>הצג כל</button>";
        echo "  </div>";
        echo "  <form class='ssl-toolbar__group' method='get' data-ssl-filter-form>";
        foreach($preserved_query as $key => $value){
            if(in_array($key, ['ssl_search','ssl_page','ssl_group','ssl_missing'], true)){
                continue;
            }
            echo "<input type='hidden' name='".esc_attr($key)."' value='".esc_attr($value)."'>";
        }
        echo "    <input type='hidden' name='ssl_page' value='1'>";
        echo "    <input type='hidden' name='ssl_group' value='cn'>";
        echo "    <input type='hidden' name='ssl_missing' value='".($missing_only ? '1' : '')."' data-ssl-missing-input>";
        echo "    <label>חיפוש<input type='search' name='ssl_search' value='".esc_attr($search)."' placeholder='חפש לקוח, דומיין או CN' data-ssl-filter-search></label>";
        echo "    <button type='button' class='ssl-btn ssl-btn-ghost ssl-btn-icon' data-ssl-filter-clear aria-label='נקה חיפוש'>✕</button>";
        echo "  </form>";
        echo "</div>";

        $has_rows = !empty($rows);
        $header_columns = [
            ['key' => 'select', 'label' => '', 'sortable' => false],
            ['key' => 'client_name', 'label' => 'שם הלקוח', 'sortable' => true],
            ['key' => 'site_url', 'label' => 'אתר', 'sortable' => true],
            ['key' => 'common_name', 'label' => 'CN', 'sortable' => true],
            ['key' => 'expiry_ts', 'label' => 'תאריך תפוגה', 'sortable' => true],
            ['key' => 'days', 'label' => 'ימים', 'sortable' => false],
            ['key' => 'color', 'label' => 'סוג', 'sortable' => false],
            ['key' => 'management_owner', 'label' => 'בניהול', 'sortable' => true],
        ];
        $column_count = count($header_columns);
        $bulk_form_id = 'ssl-bulk-form-'.substr(md5(serialize($preserved_query).'-'.$current_page.'-'.count($rows)), 0, 8);
        echo "<form id='".esc_attr($bulk_form_id)."' class='ssl-bulk-form' method='post' action='".esc_url(admin_url('admin-post.php'))."' data-ssl-bulk-form>";
        echo $this->nonce_field();
        echo "<input type='hidden' name='action' value='".esc_attr(self::DELETE_ACTION)."' />";
        echo "</form>";
        echo "<table class='ssl-table'><thead><tr>";
        foreach($header_columns as $col){
            echo "<th>";
            if($col['key'] === 'select'){
                $disabled_attr = $has_rows ? '' : ' disabled';
                echo "<label class='ssl-select-all'><input type='checkbox' data-ssl-select-all data-ssl-form='".esc_attr($bulk_form_id)."' aria-label='בחר הכל'{$disabled_attr}></label>";
            } elseif(!empty($col['sortable'])){
                echo $this->build_sort_link($col['key'], $col['label'], $sort, $order, $preserved_query);
            } else {
                echo esc_html($col['label']);
            }
            echo "</th>";
        }
        echo "</tr></thead><tbody>";

        if(!empty($rows)){
            if($group_mode === 'cn'){
                $group_sequence = [];
                $group_map = [];
                foreach($rows as $row){
                    $cn_value = isset($row['common_name']) ? $row['common_name'] : '';
                    if($cn_value === ''){
                        $group_sequence[] = [
                            'key' => 'row-'.$row['post_id'],
                            'rows' => [$row],
                        ];
                        continue;
                    }
                    if(!isset($group_map[$cn_value])){
                        $group_sequence[] = [
                            'key' => $cn_value,
                            'rows' => [],
                        ];
                        $group_map[$cn_value] = count($group_sequence) - 1;
                    }
                    $group_index = $group_map[$cn_value];
                    $group_sequence[$group_index]['rows'][] = $row;
                }
            } else {
                $group_sequence = [];
                foreach($rows as $row){
                    $group_sequence[] = [
                        'key' => 'row-'.$row['post_id'],
                        'rows' => [$row],
                    ];
                }
            }
            foreach($group_sequence as $group_index => $group){
                $group_id = 'group-'.md5($group['key'].$group_index);
                $group_rows = $group['rows'];
                $total_in_group = count($group_rows);
                $is_cn_group = ($group_mode === 'cn' && $total_in_group > 1);
                if($is_cn_group){
                    $first_row = $group_rows[0];
                    $group_cn = isset($first_row['common_name']) ? (string)$first_row['common_name'] : '';
                    if($group_cn === ''){
                        $group_cn = (string)$group['key'];
                    }
                    $group_expiry = 0;
                    foreach($group_rows as $candidate_row){
                        $candidate_expiry = !empty($candidate_row['expiry_ts']) ? (int)$candidate_row['expiry_ts'] : 0;
                        if($candidate_expiry > 0 && ($group_expiry === 0 || $candidate_expiry < $group_expiry)){
                            $group_expiry = $candidate_expiry;
                        }
                    }
                    $group_days = $group_expiry > 0 ? $this->days_left($group_expiry) : null;
                    $group_badge = $this->badge_class($group_days, false);
                    $group_days_txt = $group_days === null ? '' : $group_days;
                    $group_badge_html = ($group_badge === '' && $group_days_txt === '') ? '' : "<span class='ssl-badge {$group_badge}'>".esc_html($group_days_txt)."</span>";
                    $toggle_label = sprintf('%s רשומות', number_format_i18n($total_in_group));
                    $group_toggle_label = $group_cn !== '' ? sprintf('הצג רשומות עבור %s', $group_cn) : 'הצג רשומות מאוחדות';
                    $group_toggle_html = sprintf(
                        "<button type='button' class='ssl-btn ssl-btn-ghost ssl-group-toggle' data-ssl-group-toggle='%s' aria-expanded='false' aria-label='%s'>+</button>",
                        esc_attr($group_id),
                        esc_attr($group_toggle_label)
                    );
                    $group_meta_html = "<div class='ssl-group-meta'>".esc_html($toggle_label)."</div>";
                    $group_client_text = "<div class='ssl-client-cell__text'>".esc_html($group_cn).$group_meta_html."</div>";
                    $group_client_controls = "<div class='ssl-client-cell__controls'>".$group_toggle_html."</div>";
                    echo "<tr data-ssl-group-parent='".esc_attr($group_id)."'>";
                    echo "<td class='ssl-select-cell'></td>";
                    echo "<td><div class='ssl-client-cell'>".$group_client_controls.$group_client_text."</div></td>";
                    echo "<td></td>";
                    echo "<td>".esc_html($group_cn)."</td>";
                    echo "<td>".$this->fmt_date($group_expiry)."</td>";
                    echo "<td>{$group_badge_html}</td>";
                    echo "<td class='ssl-color-cell'><span class='ssl-group-placeholder'>&mdash;</span></td>";
                    echo "<td class='ssl-management-cell'></td>";
                    echo "</tr>";
                }
                foreach($group_rows as $row_index => $row){
                    $id = (int)$row['post_id'];
                    $client = $row['client_name'];
                    $url = $row['site_url'];
                    $cn = $row['common_name'];
                    $expiry = !empty($row['expiry_ts']) ? (int)$row['expiry_ts'] : 0;
                    $manual_mode_row = !empty($row['manual_mode']);
                    $allow_duplicate_row = !empty($row['allow_duplicate_site']);
                    $src_default = $manual_mode_row ? 'manual' : 'auto';
                    $src = $this->normalize_source_value($row['source'] ?? $src_default, $src_default);
                    $notes = $row['notes'];
                    $err = isset($row['last_error']) ? (string)$row['last_error'] : '';
                    $imgs = $row['images'];
                    $issuer = isset($row['issuer_name']) ? $row['issuer_name'] : '';
                    $guide_url = isset($row['guide_url']) ? (string)$row['guide_url'] : '';
                    $cert_type_key = $this->sanitize_cert_type_key($row['cert_type'] ?? '', $default_cert_type);
                    if($cert_type_key === '' && $default_cert_type !== ''){
                        $cert_type_key = $default_cert_type;
                    }
                    $management_owner = $this->sanitize_management_owner($row['management_owner'] ?? 'ours');
                    $management_label = $management_owner === 'not-ours' ? 'לא שלנו' : 'שלנו';
                    $agent_token_value = isset($row['agent_token']) ? sanitize_text_field((string)$row['agent_token']) : $this->get_default_agent_token_id();
                    $temporary_note = isset($row['temporary_note']) ? (string)$row['temporary_note'] : '';
                    $temporary_enabled = !empty($row['temporary_enabled']);
                    $cert_type_label = '';
                    if($cert_type_key && isset($cert_type_map[$cert_type_key])){
                        $cert_type_label = $cert_type_map[$cert_type_key]['label'] ?? $cert_type_key;
                    }
                    $type_color = '';
                    $type_text_color = '';
                    if($cert_type_key && isset($cert_type_map[$cert_type_key]['color'])){
                        $type_color = $this->sanitize_cert_type_color($cert_type_map[$cert_type_key]['color']);
                        $type_text_color = $this->get_cert_type_contrast_color($type_color);
                    }
                    $days = $this->days_left($expiry);
                    $badge = $this->badge_class($days);
                    $days_txt = $days === null ? '' : $days;
                    $badge_html = ($badge === '' && $days_txt === '') ? '' : "<span class='ssl-badge {$badge}'>".esc_html($days_txt)."</span>";
                    if($src === 'agent'){
                        $src_label = 'Agent';
                    } elseif($src === 'auto'){
                        $src_label = 'Auto';
                    } else {
                        $src_label = 'Manual';
                    }
                    $row_attributes = [];
                    if($is_cn_group){
                        $row_attributes[] = "data-ssl-group-child='".esc_attr($group_id)."'";
                        $row_attributes[] = 'hidden';
                    }
                    $row_attributes[] = "data-ssl-row='".esc_attr($id)."'";
                    $updated_at = isset($row['updated_at']) ? strtotime($row['updated_at']) : 0;
                    $should_flag_stale = false;
                    if($updated_at){
                        $age = current_time('timestamp') - $updated_at;
                        if($age > 2 * DAY_IN_SECONDS && $src === 'auto' && $expiry > 0){
                            $should_flag_stale = true;
                        }
                    }
                    if($should_flag_stale){
                        $row_attributes[] = "class='ssl-row--stale'";
                    }
                    $row_attr_string = $row_attributes ? ' '.implode(' ', $row_attributes) : '';
                    echo "<tr{$row_attr_string}>";
                    echo "<td class='ssl-select-cell'><input type='checkbox' name='post_ids[]' value='".esc_attr($id)."' data-ssl-select-item aria-label='בחר רשומה' form='".esc_attr($bulk_form_id)."'></td>";
                    $client_label = esc_html($client);
                    $has_group = ($group_mode === 'cn' && $total_in_group > 1);
                    $detail_button = "<button class='ssl-btn ssl-btn-ghost ssl-details-toggle' type='button' data-ssl-details='".esc_attr($id)."' aria-label='הצג פרטים'>+</button>";
                    $client_controls = "<div class='ssl-client-cell__controls'>".$detail_button."</div>";
                    $client_text_inner = "<span class='ssl-client-cell__name'>{$client_label}</span>";
                    $client_text = "<div class='ssl-client-cell__text'>".$client_text_inner."</div>";
                    $client_wrapper_class = 'ssl-client-cell';
                    if($has_group && $row_index === 0){
                        $client_wrapper_class .= ' ssl-client-cell--group';
                    }
                    echo "<td><div class='".esc_attr($client_wrapper_class)."'>".$client_controls.$client_text."</div></td>";
                    $link = $url ? "<a target='_blank' rel='noopener' href='".esc_url($url)."'>".esc_html($url)."</a>" : '';
                    $cn_cell = esc_html($cn);
                    $expiry_cell = $this->fmt_date($expiry);
                    $days_cell = $badge_html;
                    $color_inner = '<span class=\'ssl-group-placeholder\'>&mdash;</span>';
                    if($type_color !== ''){
                        $label_for_color = $cert_type_label !== '' ? $cert_type_label : $cert_type_key;
                        $style = " style='--ssl-pill-color:".esc_attr($type_color)."'";
                        if($type_text_color !== ''){
                            $style = " style='--ssl-pill-color:".esc_attr($type_color).";--ssl-pill-text:".esc_attr($type_text_color)."'";
                        }
                        $color_inner = "<span class='ssl-color-pill'{$style}>".esc_html($label_for_color)."</span>";
                    }
                    echo "<td>{$link}</td>";
                    echo "<td>{$cn_cell}</td>";
                    echo "<td>{$expiry_cell}</td>";
                    echo "<td>{$days_cell}</td>";
                    echo "<td class='ssl-color-cell'>{$color_inner}</td>";
                    echo "<td class='ssl-management-cell'>".esc_html($management_label)."</td>";
                    echo "</tr>";
                    $meta_items = [];
                    if($cert_type_label !== ''){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>סוג:</span><span class='ssl-row-details__meta-value'>".esc_html($cert_type_label)."</span></div>";
                    }
                    $missing_reason = '';
                    if(($expiry <= 0) && $manual_mode_row){
                        $missing_reason = 'רשומה במצב ידני – בדיקות הסוכן מושבתות.';
                    } elseif(($expiry <= 0) && $err !== ''){
                        $missing_reason = $err;
                    } elseif($expiry <= 0){
                        $last_checked = isset($row['expiry_ts_checked_at']) ? (int)$row['expiry_ts_checked_at'] : 0;
                        $source_hint = ($src === 'agent' || $src === 'auto') ? 'הסוכן' : 'השרת';
                        if($last_checked > 0){
                            $missing_reason = 'לא התקבלו נתונים מ'.$source_hint.' בבדיקה האחרונה ('.$this->fmt_date($last_checked).').';
                        } else {
                            $missing_reason = 'לא התקבלו נתונים מהסוכן והבקשה האחרונה לא מכילה חותמת זמן.';
                        }
                    }
                    if($missing_reason !== ''){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>חוסר נתונים:</span><span class='ssl-row-details__meta-value'>".esc_html($missing_reason)."</span></div>";
                    }
                    if($manual_mode_row){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>מצב:</span><span class='ssl-row-details__meta-value'>ידני</span></div>";
                    }
                    if($management_label !== ''){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>בניהול:</span><span class='ssl-row-details__meta-value'>".esc_html($management_label)."</span></div>";
                    }
                    $agent_display = $agent_label_map[$agent_token_value] ?? ($agent_token_value ?: 'Main Token');
                    $resolved_ip = '';
                    if($url !== ''){
                        $resolved_ip = $this->resolve_host_ip($url);
                    }
                    if($agent_display !== ''){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>AGENT:</span><span class='ssl-row-details__meta-value'>".esc_html($agent_display)."</span></div>";
                    }
                    $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>IP:</span><span class='ssl-row-details__meta-value'>".esc_html($resolved_ip !== '' ? $resolved_ip : 'לא אותרה כתובת')."</span></div>";
                    if(!empty($issuer)){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>CA:</span><span class='ssl-row-details__meta-value'>".esc_html($issuer)."</span></div>";
                    }
                    if($err !== ''){
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>סיבת כשל:</span><span class='ssl-row-details__meta-value'>".esc_html($err)."</span></div>";
                    }
                    if($temporary_note !== ''){
                        $temp_status = $temporary_enabled ? '' : ' (כבוי)';
                        $meta_items[] = "<div class='ssl-row-details__meta-item'><span class='ssl-row-details__meta-label'>טקסט זמני:</span><span class='ssl-row-details__meta-value'>".nl2br(esc_html($temporary_note.$temp_status))."</span></div>";
                    }
                    $meta_html = "<div class='ssl-row-details__meta'>".implode('', $meta_items)."</div>";
                    $notes_html = $notes !== '' ? nl2br(esc_html($notes)) : '';
                    $images_markup = '';
                    if(!empty($imgs)){
                        foreach($imgs as $aid){
                            $aid = (int)$aid;
                            if(!$aid){
                                continue;
                            }
                            $thumb = wp_get_attachment_image_url($aid,'thumbnail');
                            $full = wp_get_attachment_url($aid);
                            if($thumb){
                                $full = $full ? esc_url($full) : esc_url($thumb);
                                $images_markup .= "<a target='_blank' href='{$full}'><img src='".esc_url($thumb)."' alt='' /></a>";
                            }
                        }
                    }
                    if($images_markup !== ''){
                        $images_markup = "<div class='ssl-row-details__images'>{$images_markup}</div>";
                    } else {
                        $images_markup = "<div class='ssl-row-details__images'></div>";
                    }
                    $error_markup = $err !== '' ? "<span class='ssl-row-details__error'>".esc_html($err)."</span>" : '';
                    $nonce_action = self::SINGLE_CHECK_ACTION . '_' . $id;
                    $nonce = wp_create_nonce($nonce_action);
                    $refresh_url = add_query_arg([
                        'action'   => self::SINGLE_CHECK_ACTION,
                        'post_id'  => $id,
                        '_wpnonce' => $nonce,
                    ], admin_url('admin-post.php'));
                    $refresh_form = "<a class='ssl-btn ssl-btn-outline ssl-btn--compact' href='".esc_url($refresh_url)."'>בדוק עכשיו</a>";
                    $guide_button = '';
                    if($guide_url !== ''){
                        $guide_button = "<a class='ssl-btn ssl-btn-outline ssl-btn--compact ssl-guide-link' target='_blank' rel='noopener' href='".esc_url($guide_url)."'>מדריך</a>";
                    }
                    $actions_detail = "<div class='ssl-row-details__actions'><button type='button' class='ssl-btn ssl-btn-surface ssl-btn--compact' data-ssl-edit='".esc_attr($id)."'>עריכה</button>".$refresh_form.$guide_button."</div>";
                    $details_html = "<div class='ssl-row-details__wrap'>"
                        ."<div class='ssl-row-details__section'><h4>הגדרות</h4>{$meta_html}</div>"
                        ."<div class='ssl-row-details__section'><h4>הערות</h4><div>{$notes_html}</div></div>"
                        ."<div class='ssl-row-details__section'><h4>תמונות</h4>{$images_markup}</div>"
                        ."<div class='ssl-row-details__section ssl-row-details__section--actions'><h4>פעולות</h4>{$actions_detail}</div>"
                        ."</div>";
                    $detail_attrs = " data-ssl-details-row='".esc_attr($id)."' data-ssl-details-open='0' hidden";
                    if($is_cn_group){
                        $detail_attrs .= " data-ssl-group-child='".esc_attr($group_id)."'";
                    }
                    echo "<tr class='ssl-row-details'{$detail_attrs}><td colspan='".esc_attr($column_count)."'>{$details_html}</td></tr>";

                    $form_id = 'ssl-edit-form-'.md5($id.'-'.$group_id.'-'.$row_index);
                    $cert_type_options_current = $this->build_cert_type_options($cert_type_key);
                    $form_attrs = " data-ssl-form='".esc_attr($id)."' class='ssl-table__edit-row' hidden data-ssl-form-open='0'";
                    if($group_mode === 'cn' && $total_in_group > 1){
                        $form_attrs .= " data-ssl-group-child='".esc_attr($group_id)."'";
                    }
                    echo "<tr{$form_attrs}><td colspan='".esc_attr($column_count)."'><div class='ssl-card ssl-card--form'>"
                        ."<div class='ssl-card__header'><h3>עריכת רשומה</h3><button type='button' class='ssl-btn ssl-btn-ghost' data-ssl-edit='".esc_attr($id)."' title='סגירת עריכה' aria-label='סגירת עריכה'>&#10005;</button></div>"
                        ."<form id='".esc_attr($form_id)."' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field()
                        ."<input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."' />"
                        ."<input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                        ."<div class='ssl-card__body ssl-card__body--compact'>"
                        ."<label>שם הלקוח<input type='text' name='client_name' value='".esc_attr($client)."'></label>"
                        ."<label>אתר (URL)<input type='text' name='site_url' value='".esc_attr($url)."' data-ssl-autofill-url><label class='ssl-checkbox ssl-checkbox--inline ssl-checkbox--sub'><input type='checkbox' name='allow_duplicate_site' value='1' ".checked($allow_duplicate_row,true,false)."> אפשר כפילות בשם האתר</label></label>"
                        ."<label class='ssl-date-field ssl-form-span-2'><span>תאריך תפוגה</span><div class='ssl-date-field__controls'><input type='date' name='expiry_date' value='".esc_attr($this->fmt_date_input($expiry))."' data-ssl-date-input><label class='ssl-checkbox ssl-checkbox--inline'><input type='checkbox' name='manual_mode' value='1' ".checked($manual_mode_row,true,false)."> ידני (ללא בדיקות אוטומטיות)</label><button type='button' class='ssl-btn ssl-btn-outline' data-ssl-date-next-year>היום בשנה הבאה</button></div></label>"
                        ."<label><span>סוג</span><select name='cert_type'>".$cert_type_options_current."</select></label>"
                        ."<label><span>בניהול</span><select name='management_owner'>".
                            "<option value='ours'".selected($management_owner,'ours',false).">שלנו</option>".
                            "<option value='not-ours'".selected($management_owner,'not-ours',false).">לא שלנו</option>".
                          "</select></label>"
                        ."<label><span>AGENT</span><select name='agent_token'".($manual_mode_row ? ' disabled' : '').">".$this->build_agent_option_markup($agent_token_value, $manual_mode_row)."</select>".
                            ($manual_mode_row ? "<input type='hidden' name='agent_token' value='".esc_attr($agent_token_value)."'>" : '').
                        "</label>"
                        ."<label>CN של התעודה<input type='text' name='cert_cn' value='".esc_attr($cn)."'></label>"
                        ."<label>קישור למדריך<input type='text' name='guide_url' value='".esc_attr($guide_url)."' data-ssl-autofill-url></label>"
                        ."<label class='ssl-form-full'>הערות<textarea name='notes' rows='2'>".esc_textarea($notes)."</textarea></label>"
                        ."<label class='ssl-form-full'>טקסט זמני<textarea name='temporary_note' rows='2'>".esc_textarea($temporary_note)."</textarea><label class='ssl-checkbox ssl-checkbox--inline ssl-checkbox--sub'><input type='checkbox' name='temporary_enabled' value='1' ".checked($temporary_enabled,true,false)."> הפעל טקסט זמני</label></label>"
                        ."<label class='ssl-form-full'>תמונות (להוסיף חדשות) <input type='file' name='images[]' multiple accept='image/*'></label>"
                        ."</div>"
                        ."</form>"
                        ."<div class='ssl-card__footer'>"
                        ."<button class='ssl-btn ssl-btn-primary' type='submit' form='".esc_attr($form_id)."'>שמור</button>"
                        ."<form class='ssl-inline-delete' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
                        ."<input type='hidden' name='action' value='".esc_attr(self::DELETE_ACTION)."' />"
                        ."<input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                        ."<button class='ssl-btn ssl-btn-danger' type='submit' onclick=\"return confirm('להעביר לסל מחזור?')\">מחק</button>"
                        ."</form>"
                        ."</div>"
                        ."</div></td></tr>";
                }
            }
        } else {
            echo "<tr><td class='ssl-empty' colspan='".esc_attr($column_count)."'>אין נתונים</td></tr>";
        }
        echo "</tbody></table>";

        if($total_pages > 1){
            $pagination_args = [];
            foreach($preserved_query as $key => $value){
                if($key === 'ssl_page'){
                    continue;
                }
                $pagination_args[$key] = $value;
            }
            $pagination_args['ssl_per_page'] = $requested_per_page;
            $base_url = remove_query_arg('ssl_page', add_query_arg([]));
            $links = paginate_links([
                'base'      => add_query_arg('ssl_page', '%#%', $base_url),
                'format'    => '',
                'current'   => $current_page,
                'total'     => $total_pages,
                'type'      => 'array',
                'add_args'  => $pagination_args,
                'prev_text' => '&laquo; הקודם',
                'next_text' => 'הבא &raquo;',
            ]);
            if(!empty($links)){
                echo "<div class='ssl-pagination'><ul class='ssl-pagination__list'>";
                foreach($links as $link){
                    echo "<li class='ssl-pagination__item'>".$link."</li>";
                }
                echo "</ul></div>";
            }
        }
        $note_counts = sprintf(
            'בעמוד זה %1$s רשומות פעילות (%2$s עם תאריך תפוגה). בכלל המערכת %3$s מתוך %4$s רשומות כוללות תאריך תפוגה. בארכיון %5$s רשומות (%6$s עם תאריך תפוגה).',
            esc_html(number_format_i18n($current_page_total)),
            esc_html(number_format_i18n($current_page_with_expiry)),
            esc_html(number_format_i18n($scope_counts['active_with_expiry'] ?? 0)),
            esc_html(number_format_i18n($scope_counts['active_total'] ?? 0)),
            esc_html(number_format_i18n($scope_counts['archive_total'] ?? 0)),
            esc_html(number_format_i18n($scope_counts['archive_with_expiry'] ?? 0))
        );
        echo "<div class='ssl-note'>".$note_counts."</div>";
        echo "<div class='ssl-footer-tools'>";
        echo "  <div class='ssl-toolbar__quick'><div class='ssl-toolbar__quick-actions'>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='".esc_url(add_query_arg('ssl_new','1'))."'>הוסף רשומה</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='".esc_url($bulk_edit_url)."'>עריכה קבוציתית</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='".esc_url($a['token_url'])."'>הגדרות</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "  </div></div>";
        echo "  <div class='ssl-toolbar ssl-toolbar--bottom'>";
        echo "    <div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='{$export_url}'>ייצוא CSV</a>";
        echo "    <a class='ssl-btn ssl-btn-surface' href='{$refresh_url}'>רענון</a>";
        echo "    <button class='ssl-btn ssl-btn-danger' type='submit' form='".esc_attr($bulk_form_id)."' data-ssl-bulk-delete disabled onclick=\"return confirm('למחוק את הרשומות שנבחרו?')\">מחק רשומות נבחרות</button></div>";
        echo "    <form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field()
             ."      <input type='hidden' name='action' value='".esc_attr(self::IMPORT_ACTION)."' />"
             ."      <input type='hidden' name='ssl_import_step' value='preview' />"
             ."      <input type='file' name='import_file' accept='.csv,.xlsx' required />"
             ."      <button class='ssl-btn ssl-btn-primary' type='submit'>תצוגה מקדימה לייבוא</button>"
             ."    </form>";
        echo "    <div class='ssl-toolbar__group ssl-toolbar__group--end'><span class='ssl-note'>ייבוא תומך ב-CSV וב-Excel (כולל עברית).</span></div>";
        echo "  </div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_trash($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $logs_default = $this->resolve_logs_page_url();
        $bulk_edit_url = 'https://kb.macomp.co.il/?page_id=13973';
        $a = shortcode_atts([
            'main_url' => $main_default,
            'logs_url' => $logs_default,
        ], $atts);
        $q = new WP_Query(['post_type'=> self::CPT,'post_status'=> 'trash','posts_per_page'=> -1,'orderby'=>'modified','order'=>'DESC']);
        $admin_action_url = esc_url(admin_url('admin-post.php'));
        $empty_action = esc_attr(self::EMPTY_TRASH_ACTION);
        $delete_action = esc_attr(self::DELETE_PERMANENT_ACTION);
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>סל מחזור</h2><div class='ssl-manager__subtitle'>רשומות שנמחקו נשמרות למשך 90 יום לפני מחיקה סופית.</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['main_url'])."'>חזרה לטבלה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($bulk_edit_url)."'>עריכה קבוציתית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "<form class='ssl-inline-form' method='post' action='{$admin_action_url}' onsubmit=\"return confirm('למחוק לצמיתות את כל הרשומות בסל המחזור?')\">".$this->nonce_field()
            ."<input type='hidden' name='action' value='{$empty_action}' />"
            ."<button class='ssl-btn ssl-btn-danger' type='submit'>נקה סל מחזור</button>"
            ."</form>";
        echo "</div>";
        echo "</div>";
        echo "<table class='ssl-table'><thead><tr><th>שם הלקוח</th><th>אתר</th><th>נמחק</th><th>שחזור</th><th>מחיקה</th></tr></thead><tbody>";
        if ($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id=get_the_ID(); $url=get_post_meta($id,'site_url',true);
                echo "<tr><td>".esc_html(get_post_meta($id,'client_name',true))."</td>"
                    ."<td>".esc_html($url)."</td>"
                    ."<td>".esc_html(get_the_modified_date('Y-m-d'))."</td>"
                    ."<td><form method='post' action='{$admin_action_url}' class='ssl-actions'>".$this->nonce_field().""
                    ."        <input type='hidden' name='action' value='".esc_attr(self::RESTORE_ACTION)."' />"
                    ."        <input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                    ."        <button class='ssl-btn ssl-btn-primary' type='submit'>שחזר</button>"
                    ."      </form></td>"
                    ."<td><form method='post' action='{$admin_action_url}' class='ssl-actions' onsubmit=\"return confirm('למחוק רשומה זו לצמיתות?')\">".$this->nonce_field().""
                    ."        <input type='hidden' name='action' value='{$delete_action}' />"
                    ."        <input type='hidden' name='post_id' value='".esc_attr($id)."' />"
                    ."        <button class='ssl-btn ssl-btn-danger' type='submit'>מחק</button>"
                    ."      </form></td></tr>";
            }
            wp_reset_postdata();
        } else {
            echo "<tr><td class='ssl-empty' colspan='5'>אין רשומות בסל המחזור</td></tr>";
        }
        echo "</tbody></table>";
        echo "</div>";
        return ob_get_clean();
    }

    public function shortcode_controls($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $default_token = $this->resolve_token_page_url();
        $default_trash = $this->resolve_trash_page_url();
        $default_logs  = $this->resolve_logs_page_url();
        $bulk_edit_url = 'https://kb.macomp.co.il/?page_id=13973';
        $a = shortcode_atts([
            'main_url'=>$main_default,
            'trash_url'=>$default_trash,
            'token_url'=>$default_token,
            'logs_url'=>$default_logs,
        ], $atts);
        $export_url = site_url('?ssl_action='.self::EXPORT_ACTION);
        $import_action = esc_attr(self::IMPORT_ACTION);
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>פעולות מהירות</h2><div class='ssl-manager__subtitle'>ניהול זריז של רשומות SSL</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-primary' href='".esc_url(add_query_arg('ssl_new','1',$a['main_url']))."'>הוסף רשומה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($bulk_edit_url)."'>עריכה קבוציתית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>הגדרות</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        echo "</div></div>";
        echo "<div class='ssl-toolbar'>";
        echo "<div class='ssl-toolbar__group'><a class='ssl-btn ssl-btn-surface' href='".esc_url($export_url)."'>ייצוא CSV</a>";
        echo "<a class='ssl-btn ssl-btn-surface' href='".esc_url($a['main_url'])."'>לטבלה הראשית</a></div>";
        echo "<form class='ssl-toolbar__import' method='post' action='".esc_url(admin_url('admin-post.php'))."' enctype='multipart/form-data'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$import_action}' />"
                ."<input type='hidden' name='ssl_import_step' value='preview' />"
                ."<input type='file' name='import_file' accept='.csv,.xlsx' required />"
                ."<button class='ssl-btn ssl-btn-primary' type='submit'>תצוגה מקדימה לייבוא</button>"
              ."</form>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_token() {
        $tokens = $this->ensure_default_token();
        $token  = $tokens[0];
        $action = esc_attr('ssl_regen_token');
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-card'>";
        echo "<div class='ssl-card__header'><h3>".esc_html($token['name'])."</h3></div>";
        echo "<div class='ssl-card__body ssl-token-row'>";
        echo "<input class='ssl-token-input' type='text' readonly value='".esc_attr($token['token'])."'>";
        echo "<form class='ssl-token-form ssl-token-form--stack' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$action}'>"
                ."<input type='hidden' name='token_id' value='".esc_attr($token['id'])."'>"
              ."</form>";
        echo "</div>";
        echo "<div class='ssl-note'>Header: <code>X-SSL-Token</code> = הערך לעיל</div>";
        echo "</div>";
        echo "</div>";
        return ob_get_clean();
    }
    public function shortcode_token_page($atts = []) {
        $main_default = $this->resolve_main_page_url();
        $trash_default = $this->resolve_trash_page_url();
        $logs_default  = $this->resolve_logs_page_url();
        $a = shortcode_atts([
            'main_url'  => $main_default,
            'trash_url' => $trash_default,
            'logs_url'  => $logs_default,
        ], $atts);
        $tokens = $this->ensure_default_token();
        $cert_types = $this->get_certificate_types();
        $general_settings = $this->get_general_settings();
        $add_action    = esc_attr(self::ADD_TOKEN_ACTION);
        $manage_action = esc_attr(self::MANAGE_TOKEN_ACTION);
        $types_action  = esc_attr(self::SAVE_CERT_TYPES_ACTION);
        $general_action = esc_attr(self::SAVE_GENERAL_SETTINGS_ACTION);
        $email_choices = $this->collect_token_email_choices();
        $scheduled_notice = isset($_GET['ssl_batch']) ? max(0, intval($_GET['ssl_batch'])) : 0;
        $batch_error = isset($_GET['ssl_batch_error']);
        $types_updated = isset($_GET['ssl_types']);
        $general_updated = isset($_GET['ssl_general']);
        $manual_interval = isset($general_settings['manual_interval']) ? max(1, (int)$general_settings['manual_interval']) : 10;
        $monitor_email_value = isset($general_settings['monitor_email']) ? sanitize_email($general_settings['monitor_email']) : '';
        $expiry_alert_days = isset($general_settings['expiry_alert_days']) ? (int)$general_settings['expiry_alert_days'] : 30;
        $smtp_host_value = isset($general_settings['smtp_host']) ? sanitize_text_field($general_settings['smtp_host']) : '';
        $smtp_username_value = isset($general_settings['smtp_username']) ? sanitize_text_field($general_settings['smtp_username']) : '';
        $smtp_password_value = isset($general_settings['smtp_password']) ? (string)$general_settings['smtp_password'] : '';
        $smtp_port_value = isset($general_settings['smtp_port']) ? (int)$general_settings['smtp_port'] : 587;
        $smtp_encryption_value = isset($general_settings['smtp_encryption']) ? sanitize_text_field($general_settings['smtp_encryption']) : '';
        $smtp_from_value = isset($general_settings['smtp_from']) ? sanitize_email($general_settings['smtp_from']) : '';
        $smtp_from_name_value = isset($general_settings['smtp_from_name']) ? sanitize_text_field($general_settings['smtp_from_name']) : '';
        $log_file_enabled_value = !empty($general_settings['log_file_enabled']);
        $bulk_edit_url = 'https://kb.macomp.co.il/?page_id=13973';
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header ssl-manager__header--tokens'>";
        echo "<div class='ssl-manager__title'>";
        echo "<h2>הגדרות תוסף ניהול SSL</h2>";
        echo "<div class='ssl-manager__subtitle'>ניהול סוגי תעודות, טוקנים פעילים והגדרות סוכן מרוחק.</div>";
        echo "</div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-surface' href='".esc_url($a['main_url'])."'>חזרה לטבלה הראשית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($bulk_edit_url)."'>עריכה קבוציתית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>מעבר לסל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['logs_url'])."'>לוג פעילות</a>";
        $batch_form_action = esc_url(admin_url('admin-post.php'));
        $manual_interval_label = sprintf('בדוק את כל הדומיינים (מרווח %s שניות)', number_format_i18n($manual_interval));
        echo "<form class='ssl-inline-form' method='post' action='{$batch_form_action}'>".$this->nonce_field()
            ."<input type='hidden' name='action' value='".esc_attr(self::BATCH_CHECK_ACTION)."'>"
            ."<input type='hidden' name='redirect_to' value='".esc_attr($a['main_url'])."'>"
            ."<button class='ssl-btn ssl-btn-primary' type='submit'>".esc_html($manual_interval_label)."</button>"
            ."</form>";
        echo "</div>";
        echo "</div>";
        if($types_updated){
            echo "<div class='ssl-alert ssl-alert--success'>סוגי התעודות עודכנו בהצלחה.</div>";
        }
        if($general_updated){
            echo "<div class='ssl-alert ssl-alert--success'>ההגדרות נשמרו בהצלחה.</div>";
        }
        if($scheduled_notice > 0){
            $message = sprintf('תוזמנו %s בדיקות רציפות.', number_format_i18n($scheduled_notice));
            echo "<div class='ssl-alert ssl-alert--success'>".esc_html($message)."</div>";
        } elseif($batch_error){
            echo "<div class='ssl-alert ssl-alert--warning'>לא נמצאו דומיינים זמינים לבדיקה.</div>";
        }

        echo "<div class='ssl-card ssl-card--form ssl-card--types'>";
        echo "<div class='ssl-card__header'><h3>ניהול סוגי תעודות</h3><button type='button' class='ssl-btn ssl-btn-surface ssl-btn-compact' data-ssl-type-add>הוסף סוג</button></div>";
        echo "<form class='ssl-type-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
            ."<input type='hidden' name='action' value='{$types_action}'>"
            ."<div class='ssl-card__body ssl-card__body--compact'>"
            ."<div class='ssl-type-grid' data-ssl-type-rows>";
        foreach($cert_types as $type){
            $type_key = $this->sanitize_cert_type_key($type['key'] ?? '');
            $type_label = isset($type['label']) && $type['label'] !== '' ? $type['label'] : $type_key;
            $type_color = $this->sanitize_cert_type_color($type['color'] ?? '#2563eb');
            echo "<div class='ssl-type-grid__item' data-ssl-type-row>";
            echo "<div class='ssl-type-grid__fields'>";
            echo "<label><span>סוג</span><input type='text' name='cert_type_label[]' value='".esc_attr($type_label)."' required></label>";
            echo "<label class='ssl-type-grid__color'><span>צבע</span><div class='ssl-type-grid__color-picker'><span class='ssl-type-chip-preview' data-ssl-type-preview style='--ssl-type-color:".esc_attr($type_color).";'></span><input type='color' name='cert_type_color[]' value='".esc_attr($type_color)."' data-ssl-type-color></div></label>";
            echo "</div>";
            echo "<div class='ssl-type-grid__actions'><input type='hidden' name='cert_type_key[]' value='".esc_attr($type_key)."'><button type='button' class='ssl-type-remove' data-ssl-type-remove aria-label='הסר סוג'>מחק</button></div>";
            echo "</div>";
        }
        echo "</div>";
        echo "</div>";
        echo "<div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary ssl-btn-compact' type='submit'>שמור סוגים</button></div>";
        echo "</form>";
        echo "<template id='ssl-type-row-template'><div class='ssl-type-grid__item' data-ssl-type-row><div class='ssl-type-grid__fields'><label><span>סוג</span><input type='text' name='cert_type_label[]' required></label><label class='ssl-type-grid__color'><span>צבע</span><div class='ssl-type-grid__color-picker'><span class='ssl-type-chip-preview' data-ssl-type-preview style='--ssl-type-color:#2563eb;'></span><input type='color' name='cert_type_color[]' value='#2563eb' data-ssl-type-color></div></label></div><div class='ssl-type-grid__actions'><input type='hidden' name='cert_type_key[]' value=''><button type='button' class='ssl-type-remove' data-ssl-type-remove aria-label='הסר סוג'>מחק</button></div></div></template>";
        echo "<div class='ssl-note'>הסוגים שנבחרו יוצגו בתווית צבעונית לצד כל רשומה בטבלה הראשית. ניתן לגרור או למלא שני סוגים בכל שורה בזכות הפריסה הרחבה.</div>";
        echo "</div>";


        echo "<div class='ssl-token-layout'>";
        echo "<div class='ssl-card ssl-card--form ssl-card--general'>";
        echo "<div class='ssl-card__header'><h3>הגדרות כלליות</h3></div>";
        echo "<form id='ssl-general-form' class='ssl-general-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
            ."<input type='hidden' name='action' value='{$general_action}'>"
            ."<div class='ssl-card__body ssl-card__body--compact ssl-general-grid'>"
            ."  <label><span>ימים להתראת תפוגה</span><input type='number' name='expiry_alert_days' min='1' max='365' value='".esc_attr($expiry_alert_days)."'></label>"
            ."  <label class='ssl-toggle'><input type='checkbox' name='log_file_enabled' value='1'".checked($log_file_enabled_value,true,false)."> הפעל רישום לקובץ לוג של התוסף</label>"
            ."  <input type='hidden' name='monitor_email' value='".esc_attr($monitor_email_value)."'>"
            ."</div>";
        echo "<div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit'>שמור הגדרות</button><span class='ssl-note'>המרווח חל על הפעולה \"בדוק את כל הדומיינים\" ועל ניטור החיבור האוטומטי.</span></div>";
        echo "</form>";
        echo "</div>";

        echo "<div class='ssl-card ssl-card--form ssl-card--mail'>";
        echo "<div class='ssl-card__header'><h3>הגדרות דואר</h3></div>";
        echo "<form id='ssl-mail-form' class='ssl-general-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
            ."<input type='hidden' name='action' value='{$general_action}'>"
            ."<div class='ssl-card__body ssl-card__body--compact ssl-general-grid'>"
            ."  <label><span>שרת SMTP</span><input type='text' name='smtp_host' placeholder='smtp.example.com' value='".esc_attr($smtp_host_value)."'></label>"
            ."  <label><span>שם משתמש SMTP</span><input type='text' name='smtp_username' value='".esc_attr($smtp_username_value)."'></label>"
            ."  <label><span>סיסמה</span><input type='password' name='smtp_password' value='".esc_attr($smtp_password_value)."' autocomplete='new-password'></label>"
            ."  <label><span>פורט</span><input type='number' name='smtp_port' min='1' max='65535' value='".esc_attr($smtp_port_value)."'></label>"
            ."  <label><span>הצפנה</span><select name='smtp_encryption'><option value=''".selected($smtp_encryption_value,'',false).">ללא</option><option value='ssl'".selected($smtp_encryption_value,'ssl',false).">SSL</option><option value='tls'".selected($smtp_encryption_value,'tls',false).">TLS</option></select></label>"
            ."  <label><span>כתובת שולח</span><input type='email' name='smtp_from' placeholder='alerts@example.com' value='".esc_attr($smtp_from_value)."'></label>"
            ."  <label><span>שם שולח</span><input type='text' name='smtp_from_name' placeholder='SSL Monitor' value='".esc_attr($smtp_from_name_value)."'></label>"
            ."</div>";
        echo "<div class='ssl-card__footer'><button class='ssl-btn ssl-btn-primary' type='submit'>שמור הגדרות דואר</button><span class='ssl-note'>שדות אלו משמשים לשליחת התראות מהתוסף.</span></div>";
        echo "</form>";
        echo "</div>";
        echo "</div>";

        echo "<div class='ssl-card ssl-card--form ssl-card--tokens'>";
        echo "<div class='ssl-card__header'><h3>ניהול טוקנים</h3></div>";
        echo "<div class='ssl-card__body'>";
        echo "<form class='ssl-token-create' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                ."<input type='hidden' name='action' value='{$add_action}'>"
                ."<div class='ssl-token-create__fields'>"
                ."  <label><span>שם הטוקן</span><input type='text' name='token_name' placeholder='לדוגמה: סוכן ראשי' required></label>"
                ."  <button class='ssl-btn ssl-btn-primary' type='submit'>הוסף טוקן</button>"
                ."</div>"
                ."<p class='ssl-note'>הוסיפו טוקנים לפי הצורך והשתמשו בערך שלהם בבקשות מרוחקות.</p>"
              ."</form>";
        echo "<div class='ssl-table-scroll ssl-table-scroll--tokens'>";
        echo "<table class='ssl-table ssl-token-table'>";
        echo "<thead><tr><th>שם הטוקן</th><th>ערך הטוקן</th><th>סטטוס חיבור</th><th style='width:240px'>פעולות</th></tr></thead>";
        echo "<tbody>";
        if(!empty($tokens)){
            foreach($tokens as $token){
                $form_id = 'ssl-token-manage-'.sanitize_key($token['id']);
                $status_view = $this->describe_token_status($token);
                $stored_emails = array_filter((array)($token['emails'] ?? []));
                $email_options = $email_choices;
                foreach($stored_emails as $email){
                    if($email && !isset($email_options[$email])){
                        $email_options[$email] = $email;
                    }
                }
                echo "<tr>";
                echo "<td class='ssl-token-table__name'><input form='".esc_attr($form_id)."' type='text' name='token_name' value='".esc_attr($token['name'])."' readonly></td>";
                echo "<td class='ssl-token-table__token'><div class='ssl-token-copy'><input type='text' readonly value='".esc_attr($token['token'])."'><button type='button' class='ssl-btn ssl-btn-outline ssl-btn-compact' data-ssl-copy='".esc_attr($token['token'])."'>העתק</button></div></td>";
                echo "<td class='ssl-token-table__status'><div class='ssl-token-status'><span class='ssl-token-status__dot " .esc_attr($status_view['dot'])."' aria-hidden='true'></span><div class='ssl-token-status__text'><div class='ssl-token-status__label'>".esc_html($status_view['label'])."</div>";
                foreach($status_view['meta'] as $meta){
                    $is_error = (strpos($meta, 'שגיאה אחרונה') === 0);
                    $meta_class = $is_error ? ' ssl-token-status__meta--error' : '';
                    echo "<div class='ssl-token-status__meta{$meta_class}'>".esc_html($meta)."</div>";
                }
                echo "</div></div></td>";
                echo "<td><div class='ssl-token-table__actions'>";
                echo "<button class='ssl-btn ssl-btn-primary' type='submit' form='".esc_attr($form_id)."' name='sub_action' value='update'>שמור</button>";
                echo "<button class='ssl-btn ssl-btn-danger' type='submit' form='".esc_attr($form_id)."' name='sub_action' value='delete' onclick=\"return confirm('למחוק את הטוקן?')\">מחק</button>";
                echo "</div></td>";
                echo "</tr>";
            }
        } else {
            echo "<tr><td class='ssl-empty' colspan='4'>לא נמצאו טוקנים</td></tr>";
        }
        echo "</tbody>";
        echo "</table>";
        echo "</div>";
        echo "</div>";
        echo "</div>";

        $forms = '';
        foreach($tokens as $token){
            $form_id = 'ssl-token-manage-'.sanitize_key($token['id']);
            $forms .= "<form id='".esc_attr($form_id)."' class='ssl-token-hidden-form' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field().""
                    ."<input type='hidden' name='action' value='{$manage_action}'>"
                    ."<input type='hidden' name='token_id' value='".esc_attr($token['id'])."'>"
                 ."</form>";
        }
        echo $forms;
        return ob_get_clean();
    }

    public function render_shortcode_bulk_editor($atts = []) {
        if(!current_user_can('manage_options')){
            return '';
        }
        $a = shortcode_atts([
            'per_page' => 50,
        ], $atts);
        $request = wp_unslash($_GET);
        $per_page = isset($request['ssl_bulk_per_page']) ? max(1, (int)$request['ssl_bulk_per_page']) : (int)$a['per_page'];
        if($per_page < 1){
            $per_page = 50;
        }
        $current_page = isset($request['ssl_bulk_page']) ? max(1, (int)$request['ssl_bulk_page']) : 1;
        $sort = sanitize_key($request['ssl_bulk_sort'] ?? 'client_name');
        $order = strtoupper($request['ssl_bulk_order'] ?? 'ASC');
        $order = $order === 'DESC' ? 'DESC' : 'ASC';
        $allowed_sort = ['client_name','site_url','common_name','expiry_ts','cert_type','management_owner'];
        if(!in_array($sort, $allowed_sort, true)){
            $sort = 'client_name';
        }
        $filter_client = isset($request['bulk_client']) ? sanitize_text_field($request['bulk_client']) : '';
        $filter_site = isset($request['bulk_site']) ? sanitize_text_field($request['bulk_site']) : '';
        $filter_cn = isset($request['bulk_cn']) ? sanitize_text_field($request['bulk_cn']) : '';
        $filter_cert_type = isset($request['bulk_cert_type']) ? $this->sanitize_cert_type_key($request['bulk_cert_type']) : '';
        $filter_management_raw = isset($request['bulk_management']) ? sanitize_text_field($request['bulk_management']) : '';
        $filter_management = $filter_management_raw === '' ? '' : $this->sanitize_management_owner($filter_management_raw);
        $filter_manual = isset($request['bulk_manual']) ? sanitize_text_field($request['bulk_manual']) : '';

        $data = $this->fetch_certificates([
            'page' => $current_page,
            'per_page' => $per_page,
            'orderby' => $sort,
            'order' => $order,
            'filter_client' => $filter_client,
            'filter_site' => $filter_site,
            'filter_cn' => $filter_cn,
            'filter_cert_type' => $filter_cert_type,
            'filter_management' => $filter_management,
            'filter_manual' => $filter_manual,
        ]);

        $rows = $data['rows'];
        $total_found = $data['total'];
        $total_with_expiry = $data['total_with_expiry'];
        $total_pages = max(1, (int)ceil($total_found / $per_page));
        $filter_form_id = 'ssl-bulk-filter-form';
        $main_url = $this->resolve_main_page_url();
        $preserved_query = [];
        foreach($request as $key => $value){
            if(strpos($key, 'ssl_bulk_') === 0 || strpos($key, 'bulk_') === 0){
                $preserved_query[$key] = sanitize_text_field($value);
            }
        }
        $preserved_query['ssl_bulk_per_page'] = $per_page;

        ob_start();
        echo "<div class='ssl-manager ssl-bulk-editor'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>עריכה קבוצתית</h2><div class='ssl-manager__subtitle'>תצוגת GRID פתוחה לעריכה עם כל השדות המרכזיים.</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($main_url)."'>חזרה לטבלה</a>";
        echo "</div>";
        echo "</div>";
        echo "<form id='".esc_attr($filter_form_id)."' class='ssl-bulk-editor__filter-form' method='get'>";
        echo "<input type='hidden' name='ssl_bulk_page' value='1'>";
        echo "<input type='hidden' name='ssl_bulk_sort' value='".esc_attr($sort)."'>";
        echo "<input type='hidden' name='ssl_bulk_order' value='".esc_attr($order)."'>";
        echo "</form>";
        echo "<div class='ssl-bulk-grid__wrapper'>";
        echo "<table class='ssl-table ssl-bulk-grid'><thead>";
        echo "<tr>";
        echo "<th>#</th>";
        echo "<th>שם הלקוח</th>";
        echo "<th>אתר</th>";
        echo "<th>CN</th>";
        echo "<th>".$this->build_bulk_sort_link('expiry_ts','תאריך תפוגה',$sort,$order,$preserved_query)."</th>";
        echo "<th>".$this->build_bulk_sort_link('cert_type','סוג',$sort,$order,$preserved_query)."</th>";
        echo "<th>".$this->build_bulk_sort_link('management_owner','בניהול',$sort,$order,$preserved_query)."</th>";
        echo "<th>ידני</th>";
        echo "<th>טקסט זמני</th>";
        echo "<th>הערות</th>";
        echo "<th>פעולות</th>";
        echo "</tr>";
        echo "<tr class='ssl-bulk-grid__filters-row'>";
        echo "<th><input type='number' form='".esc_attr($filter_form_id)."' name='ssl_bulk_per_page' min='1' value='".esc_attr($per_page)."' class='ssl-bulk-grid__per-page' aria-label='רשומות בעמוד'></th>";
        echo "<th><input type='text' form='".esc_attr($filter_form_id)."' name='bulk_client' value='".esc_attr($filter_client)."' placeholder='לקוח'></th>";
        echo "<th><input class='ssl-bulk-grid__input-site' type='text' form='".esc_attr($filter_form_id)."' name='bulk_site' value='".esc_attr($filter_site)."' placeholder='אתר'></th>";
        echo "<th><input class='ssl-bulk-grid__input-cn' type='text' form='".esc_attr($filter_form_id)."' name='bulk_cn' value='".esc_attr($filter_cn)."' placeholder='CN'></th>";
        echo "<th><input type='text' form='".esc_attr($filter_form_id)."' name='ssl_bulk_expiry_hint' value='' placeholder='סינון לפי תאריך' disabled></th>";
        echo "<th><input type='text' form='".esc_attr($filter_form_id)."' name='bulk_cert_type' value='".esc_attr($filter_cert_type)."' placeholder='סוג'></th>";
        echo "<th><select class='ssl-bulk-grid__input-management' form='".esc_attr($filter_form_id)."' name='bulk_management'><option value=''>הכל</option><option value='ours'".selected($filter_management,'ours',false).">שלנו</option><option value='not-ours'".selected($filter_management,'not-ours',false).">לא שלנו</option></select></th>";
        echo "<th><select form='".esc_attr($filter_form_id)."' name='bulk_manual'><option value=''>הכל</option><option value='1'".selected($filter_manual,'1',false).">ידני</option><option value='0'".selected($filter_manual,'0',false).">אוטומטי</option></select></th>";
        echo "<th></th><th></th>";
        echo "<th><button class='ssl-btn ssl-btn-primary' type='submit' form='".esc_attr($filter_form_id)."'>סנן</button></th>";
        echo "</tr>";
        echo "</thead><tbody>";
        if(!empty($rows)){
            foreach($rows as $row){
                $id = (int)$row['post_id'];
                $client = $row['client_name'];
                $url = $row['site_url'];
                $cn = $row['common_name'];
                $expiry = !empty($row['expiry_ts']) ? (int)$row['expiry_ts'] : 0;
                $cert_type_key = $this->sanitize_cert_type_key($row['cert_type'] ?? '');
                $manual_mode_row = !empty($row['manual_mode']);
                $allow_duplicate_row = !empty($row['allow_duplicate_site']);
                $temporary_note = isset($row['temporary_note']) ? (string)$row['temporary_note'] : '';
                $temporary_enabled = !empty($row['temporary_enabled']);
                $management_owner = $this->sanitize_management_owner($row['management_owner'] ?? 'ours');
                $notes = $row['notes'];
                $guide_url = isset($row['guide_url']) ? (string)$row['guide_url'] : '';
                $form_id = 'ssl-bulk-edit-'.$id;
                $cert_type_options_current = $this->build_cert_type_options($cert_type_key);
                echo "<form id='".esc_attr($form_id)."' method='post' action='".esc_url(admin_url('admin-post.php'))."'>".$this->nonce_field()
                    ."<input type='hidden' name='action' value='".esc_attr(self::SAVE_ACTION)."'>"
                    ."<input type='hidden' name='post_id' value='".esc_attr($id)."'>"
                    ."<input type='hidden' name='allow_duplicate_site' value='".esc_attr($allow_duplicate_row ? '1' : '0')."'>"
                    ."</form>";
                echo "<tr>";
                echo "<td class='ssl-bulk-grid__id'>".esc_html($id)."</td>";
                echo "<td><input form='".esc_attr($form_id)."' type='text' name='client_name' value='".esc_attr($client)."'></td>";
                echo "<td><input class='ssl-bulk-grid__input-site' form='".esc_attr($form_id)."' type='text' name='site_url' value='".esc_attr($url)."'></td>";
                echo "<td><input class='ssl-bulk-grid__input-cn' form='".esc_attr($form_id)."' type='text' name='cert_cn' value='".esc_attr($cn)."'></td>";
                echo "<td><input form='".esc_attr($form_id)."' type='date' name='expiry_date' value='".esc_attr($this->fmt_date_input($expiry))."'></td>";
                echo "<td><select form='".esc_attr($form_id)."' name='cert_type'>".$cert_type_options_current."</select></td>";
                echo "<td><select class='ssl-bulk-grid__input-management' form='".esc_attr($form_id)."' name='management_owner'><option value='ours'".selected($management_owner,'ours',false).">שלנו</option><option value='not-ours'".selected($management_owner,'not-ours',false).">לא שלנו</option></select></td>";
                $manual_checked = $manual_mode_row ? " checked" : '';
                echo "<td class='ssl-bulk-grid__checkbox'><input form='".esc_attr($form_id)."' type='checkbox' name='manual_mode' value='1'{$manual_checked}></td>";
                $temp_checked = $temporary_enabled ? " checked" : '';
                echo "<td class='ssl-bulk-grid__temporary'><textarea form='".esc_attr($form_id)."' name='temporary_note' rows='1'>".esc_textarea($temporary_note)."</textarea><label class='ssl-checkbox ssl-checkbox--inline ssl-checkbox--sub'><input form='".esc_attr($form_id)."' type='checkbox' name='temporary_enabled' value='1'{$temp_checked}> הפעלה</label></td>";
                echo "<td><textarea form='".esc_attr($form_id)."' name='notes' rows='1'>".esc_textarea($notes)."</textarea><input form='".esc_attr($form_id)."' type='text' name='guide_url' value='".esc_attr($guide_url)."' placeholder='קישור למדריך' class='ssl-bulk-grid__guide'></td>";
                echo "<td class='ssl-bulk-grid__actions'><button class='ssl-btn ssl-btn-primary' type='submit' form='".esc_attr($form_id)."'>שמור</button></td>";
                echo "</tr>";
            }
        } else {
            echo "<tr><td colspan='11' class='ssl-empty'>אין נתונים לעריכה</td></tr>";
        }
        echo "</tbody></table>";
        echo "</div>";

        if($total_pages > 1){
            $pagination_args = [];
            foreach($preserved_query as $key => $value){
                if($key === 'ssl_bulk_page'){
                    continue;
                }
                $pagination_args[$key] = $value;
            }
            $pagination_args['ssl_bulk_per_page'] = $per_page;
            $base_url = remove_query_arg('ssl_bulk_page', add_query_arg([]));
            $links = paginate_links([
                'base'      => add_query_arg('ssl_bulk_page', '%#%', $base_url),
                'format'    => '',
                'current'   => $current_page,
                'total'     => $total_pages,
                'type'      => 'array',
                'add_args'  => $pagination_args,
                'prev_text' => '&laquo; הקודם',
                'next_text' => 'הבא &raquo;',
            ]);
            if(!empty($links)){
                echo "<div class='ssl-pagination'><ul class='ssl-pagination__list'>";
                foreach($links as $link){
                    echo "<li class='ssl-pagination__item'>".$link."</li>";
                }
                echo "</ul></div>";
            }
        }
        echo "<div class='ssl-note'>במערכת קיימות ".esc_html(number_format_i18n($total_found))." רשומות, מתוכן ".esc_html(number_format_i18n($total_with_expiry))." כוללות תאריך תפוגה.</div>";
        echo "</div>";
        return ob_get_clean();
    }

    public function shortcode_logs($atts = []) {
        $main_default  = $this->resolve_main_page_url();
        $trash_default = $this->resolve_trash_page_url();
        $token_default = $this->resolve_token_page_url();
        $a = shortcode_atts([
            'limit'    => 100,
            'main_url' => $main_default,
            'trash_url'=> $trash_default,
            'token_url'=> $token_default,
        ], $atts);
        $limit = absint($a['limit']);
        if($limit === 0){
            $limit = 100;
        }
        $limit = min($limit, 200);
        $log_entries = array_reverse($this->get_activity_log());
        if($limit > 0){
            $log_entries = array_slice($log_entries, 0, $limit);
        }
        $bulk_edit_url = 'https://kb.macomp.co.il/?page_id=13973';
        ob_start();
        echo "<div class='ssl-manager'>";
        echo "<div class='ssl-manager__header'>";
        echo "<div class='ssl-manager__title'><h2>לוג פעילות הסוכן</h2><div class='ssl-manager__subtitle'>מוצגות עד ".esc_html($limit)." הרשומות האחרונות.</div></div>";
        echo "<div class='ssl-manager__header-actions'>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['main_url'])."'>חזרה לטבלה</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($bulk_edit_url)."'>עריכה קבוציתית</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['trash_url'])."'>סל מחזור</a>";
        echo "<a class='ssl-btn ssl-btn-outline' href='".esc_url($a['token_url'])."'>הגדרות</a>";
        echo "</div>";
        echo "</div>";
        if(empty($log_entries)){
            echo "<div class='ssl-empty'>לא נמצאו רשומות פעילות עדיין.</div>";
        } else {
            echo "<table class='ssl-table ssl-log-table'><thead><tr><th>זמן</th><th>רמה</th><th>תיאור</th><th>פרטים</th></tr></thead><tbody>";
            foreach($log_entries as $entry){
                $time = !empty($entry['time']) ? date_i18n('d/m/Y H:i:s', (int)$entry['time']) : '';
                $raw_level = strtolower(is_string($entry['level'] ?? '') ? $entry['level'] : '');
                if(!in_array($raw_level, ['info','warning','error'], true)){
                    $raw_level = 'info';
                }
                $level_label = strtoupper($raw_level);
                $message = esc_html($entry['message'] ?? '');
                $context_html = $this->format_log_context_display($entry['context'] ?? []);
                echo "<tr>";
                echo "<td class='ssl-log-table__time'>".esc_html($time)."</td>";
                echo "<td class='ssl-log-table__level'><span class='ssl-log-level ssl-log-level--".esc_attr($raw_level)."'>".esc_html($level_label)."</span></td>";
                echo "<td class='ssl-log-table__message'>".$message."</td>";
                echo "<td class='ssl-log-table__context'>".$context_html."</td>";
                echo "</tr>";
            }
            echo "</tbody></table>";
        }
        echo "</div>";
        return ob_get_clean();
    }
    public function handle_regen_token() {
        $this->check_nonce();
        $tokens = $this->ensure_default_token();
        $token_id = sanitize_text_field($_POST['token_id'] ?? '');
        if(!$token_id && !empty($tokens)){
            $token_id = $tokens[0]['id'];
        }
        $updated = false;
        $token_name = '';
        foreach($tokens as &$token){
            if($token['id'] === $token_id){
                $token_name = $token['name'];
                $token['token'] = $this->generate_token_value();
                $token['updated'] = time();
                $token['last_status'] = 'unknown';
                $token['last_seen'] = 0;
                $token['last_error'] = '';
                $token['notified_down_at'] = 0;
                $updated = true;
                break;
            }
        }
        unset($token);
        if($updated){
            $this->save_tokens($tokens);
            $this->log_activity('טוקן אופס מחדש', array_merge([
                'token_id' => $token_id,
                'token_name' => $token_name,
            ], $this->get_current_actor_context()));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_add_token(){
        $this->check_nonce();
        $tokens = $this->get_tokens();
        $name = sanitize_text_field($_POST['token_name'] ?? '');
        if($name === ''){
            $name = 'ללא שם';
        }
        $new_token = [
            'id'      => $this->generate_token_id(),
            'name'    => $name,
            'token'   => $this->generate_token_value(),
            'created' => time(),
            'updated' => time(),
            'last_status' => 'unknown',
            'last_seen'   => 0,
            'last_error'  => '',
            'notify_down' => 1,
            'emails'      => [],
            'notified_down_at' => 0,
        ];
        $tokens[] = $new_token;
        $this->save_tokens($tokens);
        $this->log_activity('טוקן חדש נוצר', array_merge([
            'token_id' => $new_token['id'],
            'token_name' => $new_token['name'],
        ], $this->get_current_actor_context()));
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_manage_token(){
        $this->check_nonce();
        $tokens = $this->get_tokens();
        $token_id = sanitize_text_field($_POST['token_id'] ?? '');
        $sub = sanitize_key($_POST['sub_action'] ?? 'update');
        $name = sanitize_text_field($_POST['token_name'] ?? '');
        if($name === ''){
            $name = 'ללא שם';
        }
        $notify = 1;
        $emails = null;
        $changed = false;
        $log_action = '';
        $log_context = [];
        foreach($tokens as $index => &$token){
            if($token['id'] !== $token_id){
                continue;
            }
            if($sub === 'delete'){
                $log_action = 'delete';
                $log_context = [
                    'token_id' => $token['id'],
                    'token_name' => $token['name'],
                ];
                unset($tokens[$index]);
                $changed = true;
                break;
            }
            if(in_array($sub, ['regen','update'], true)){
                $log_action = $sub === 'regen' ? 'regen' : 'update';
                $token['name'] = $name;
                $token['notify_down'] = $notify;
                if($emails === null){
                    $emails = isset($token['emails']) ? (array)$token['emails'] : [];
                }
                $token['emails'] = $emails;
                if(!$notify){
                    $token['notified_down_at'] = 0;
                }
                if($sub === 'regen'){
                    $token['token'] = $this->generate_token_value();
                    $token['last_status'] = 'unknown';
                    $token['last_seen'] = 0;
                    $token['last_error'] = '';
                    $token['notified_down_at'] = 0;
                }
                $token['updated'] = time();
                $log_context = [
                    'token_id' => $token['id'],
                    'token_name' => $token['name'],
                    'notify_down' => (bool)$notify,
                    'emails' => $emails,
                ];
                if($sub === 'regen'){
                    $log_context['regenerated'] = true;
                }
                $changed = true;
            }
            break;
        }
        unset($token);
        if($changed){
            $tokens = array_values($tokens);
            if(empty($tokens)){
                $default_token = [
                    'id'      => $this->generate_token_id(),
                    'name'    => 'Token ראשי',
                    'token'   => $this->generate_token_value(),
                    'created' => time(),
                    'updated' => time(),
                    'last_status' => 'unknown',
                    'last_seen'   => 0,
                    'last_error'  => '',
                    'notify_down' => 1,
                    'emails'      => [],
                    'notified_down_at' => 0,
                ];
                $tokens[] = $default_token;
                $this->log_activity('נוצר טוקן ברירת מחדל חדש', array_merge([
                    'token_id' => $default_token['id'],
                    'token_name' => $default_token['name'],
                ], $this->get_current_actor_context()));
            }
            $this->save_tokens($tokens);
            if($log_action){
                $messages = [
                    'delete' => 'טוקן נמחק',
                    'regen'  => 'טוקן אופס מחדש',
                    'update' => 'טוקן עודכן',
                ];
                $message = $messages[$log_action] ?? 'שינוי טוקן';
                $this->log_activity($message, array_merge($log_context, $this->get_current_actor_context()));
            }
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_save_cert_types(){
        $this->check_nonce();
        $redirect = wp_get_referer();
        if(!$redirect){
            $redirect = $this->resolve_token_page_url();
        }
        $labels = isset($_POST['cert_type_label']) ? (array)$_POST['cert_type_label'] : [];
        $colors = isset($_POST['cert_type_color']) ? (array)$_POST['cert_type_color'] : [];
        $keys   = isset($_POST['cert_type_key']) ? (array)$_POST['cert_type_key'] : [];
        $types = [];
        $count = max(count($labels), count($colors), count($keys));
        for($i = 0; $i < $count; $i++){
            $label = sanitize_text_field($labels[$i] ?? '');
            $color = sanitize_text_field($colors[$i] ?? '');
            $key   = sanitize_text_field($keys[$i] ?? '');
            if($label === ''){
                continue;
            }
            $types[] = [
                'label' => $label,
                'color' => $color,
                'key'   => $key,
            ];
        }
        $normalized = $this->normalize_cert_types($types);
        update_option(self::OPTION_CERT_TYPES, $normalized, false);
        $log_types = array_map(function($type){
            return [
                'key'   => $type['key'] ?? '',
                'label' => $type['label'] ?? '',
                'color' => $type['color'] ?? '',
            ];
        }, $normalized);
        $this->log_activity('עודכנו סוגי התעודות', array_merge([
            'types' => $log_types,
        ], $this->get_current_actor_context()));
        $redirect = add_query_arg('ssl_types', 1, $redirect);
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_save_general_settings(){
        $this->check_nonce();
        if(!current_user_can('manage_options')){
            wp_die('אין לך הרשאה לעדכן הגדרות אלו');
        }
        $current = $this->get_general_settings();
        $posted_interval = isset($_POST['manual_interval']) ? (int)$_POST['manual_interval'] : $current['manual_interval'];
        $posted_gateway = isset($_POST['default_gateway']) ? sanitize_text_field(wp_unslash($_POST['default_gateway'])) : '';
        $posted_email = isset($_POST['monitor_email']) ? sanitize_email(wp_unslash($_POST['monitor_email'])) : '';
        $expiry_days = isset($_POST['expiry_alert_days']) ? (int)$_POST['expiry_alert_days'] : ($current['expiry_alert_days'] ?? 30);
        $smtp_host = array_key_exists('smtp_host', $_POST) ? sanitize_text_field(wp_unslash($_POST['smtp_host'])) : ($current['smtp_host'] ?? '');
        $smtp_username = array_key_exists('smtp_username', $_POST) ? sanitize_text_field(wp_unslash($_POST['smtp_username'])) : ($current['smtp_username'] ?? '');
        $smtp_password = array_key_exists('smtp_password', $_POST) ? wp_strip_all_tags((string)wp_unslash($_POST['smtp_password'])) : ($current['smtp_password'] ?? '');
        $smtp_port = array_key_exists('smtp_port', $_POST) ? (int)$_POST['smtp_port'] : ($current['smtp_port'] ?? 587);
        $smtp_encryption = array_key_exists('smtp_encryption', $_POST) ? sanitize_text_field(wp_unslash($_POST['smtp_encryption'])) : ($current['smtp_encryption'] ?? '');
        $smtp_from = array_key_exists('smtp_from', $_POST) ? sanitize_email(wp_unslash($_POST['smtp_from'])) : ($current['smtp_from'] ?? '');
        $smtp_from_name = array_key_exists('smtp_from_name', $_POST) ? sanitize_text_field(wp_unslash($_POST['smtp_from_name'])) : ($current['smtp_from_name'] ?? '');
        $log_file_enabled = array_key_exists('log_file_enabled', $_POST) ? (!empty($_POST['log_file_enabled']) ? 1 : 0) : ($current['log_file_enabled'] ?? 0);
        $merged = array_merge($current, [
            'manual_interval' => $posted_interval,
            'default_gateway' => $posted_gateway,
            'monitor_email' => $posted_email,
            'expiry_alert_days' => $expiry_days,
            'smtp_host' => $smtp_host,
            'smtp_username' => $smtp_username,
            'smtp_password' => $smtp_password,
            'smtp_port' => $smtp_port,
            'smtp_encryption' => $smtp_encryption,
            'smtp_from' => $smtp_from,
            'smtp_from_name' => $smtp_from_name,
            'log_file_enabled' => $log_file_enabled,
        ]);
        $normalized = $this->sanitize_general_settings($merged);
        update_option(self::OPTION_SETTINGS, $normalized, false);
        $this->log_activity('עודכנו הגדרות כלליות', array_merge([
            'manual_interval' => $normalized['manual_interval'],
            'default_gateway' => $normalized['default_gateway'],
            'monitor_email' => $normalized['monitor_email'],
            'expiry_alert_days' => $normalized['expiry_alert_days'],
            'smtp_host' => $normalized['smtp_host'] !== '' ? '***' : '',
            'smtp_username' => $normalized['smtp_username'] !== '' ? '***' : '',
            'smtp_port' => $normalized['smtp_port'],
            'smtp_encryption' => $normalized['smtp_encryption'],
            'log_file_enabled' => $normalized['log_file_enabled'],
        ], $this->get_current_actor_context()));
        $redirect = wp_get_referer();
        if(!$redirect){
            $redirect = $this->resolve_token_page_url();
        }
        $redirect = remove_query_arg('ssl_general', $redirect);
        $redirect = add_query_arg('ssl_general', 1, $redirect);
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_toggle_follow_up(){
        $this->check_nonce();
        $post_id = isset($_POST['post_id']) ? (int)$_POST['post_id'] : 0;
        $follow_up = !empty($_POST['follow_up']) ? 1 : 0;
        $redirect = '';
        if(isset($_POST['redirect_to'])){
            $candidate = esc_url_raw(wp_unslash($_POST['redirect_to']));
            if($candidate){
                $redirect = $candidate;
            }
        }
        if(!$redirect){
            $redirect = wp_get_referer();
        }
        if(!$redirect){
            $redirect = $this->resolve_main_page_url();
        }
        if($post_id <= 0){
            wp_safe_redirect($redirect);
            exit;
        }
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            wp_safe_redirect($redirect);
            exit;
        }
        update_post_meta($post_id,'follow_up',$follow_up ? 1 : 0);
        $this->sync_table_record($post_id, get_post_status($post_id));
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_save_remote_client(){
        if(!current_user_can('manage_options')){
            wp_die('אין לך הרשאה לעדכן הגדרות אלו');
        }
        check_admin_referer('ssl_remote_client');
        $settings = [
            // Always enable the remote agent; saving simply affirms the default.
            'enabled' => 1,
        ];
        update_option(self::OPTION_REMOTE, $settings);
        $this->log_activity('עודכנו הגדרות הסוכן המרוחק', array_merge($settings, $this->get_current_actor_context()));
        $redirect = add_query_arg([
            'page' => 'ssl-expiry-api',
            'remote-updated' => 1,
        ], admin_url('options-general.php'));
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_batch_check() {
        $this->check_nonce();
        $redirect = '';
        if(isset($_POST['redirect_to'])){
            $candidate = esc_url_raw(wp_unslash($_POST['redirect_to']));
            if($candidate){
                $redirect = $candidate;
            }
        }
        if(!$redirect){
            $redirect = wp_get_referer();
        }
        if(!$redirect){
            $redirect = $this->resolve_main_page_url();
        }
        $redirect = remove_query_arg(['ssl_batch','ssl_batch_error'], $redirect);
        $interval = $this->get_manual_batch_interval();
        $start_delay = max(1, $interval);
        $scheduled = $this->schedule_certificate_batch('manual', time() + $start_delay, $interval);
        $this->log_activity('בוצעה בדיקת SSL יזומה לכל הדומיינים', array_merge([
            'scheduled' => $scheduled,
            'interval' => $interval,
        ], $this->get_current_actor_context()));
        if($scheduled > 0){
            $redirect = add_query_arg('ssl_batch', $scheduled, $redirect);
        } else {
            $redirect = add_query_arg('ssl_batch_error', 1, $redirect);
        }
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_single_check() {
        $post_id = isset($_GET['post_id']) ? (int)$_GET['post_id'] : 0;
        check_admin_referer(self::SINGLE_CHECK_ACTION . '_' . $post_id);
        $redirect = '';
        if(isset($_POST['redirect_to'])){
            $candidate = esc_url_raw(wp_unslash($_POST['redirect_to']));
            if($candidate){
                $redirect = $candidate;
            }
        }
        if(!$redirect){
            $redirect = wp_get_referer();
        }
        if(!$redirect){
            $redirect = $this->resolve_main_page_url();
        }
        $redirect = remove_query_arg(['ssl_single','ssl_single_error'], $redirect);
        if($post_id <= 0){
            $redirect = add_query_arg('ssl_single_error', 'missing', $redirect);
            wp_safe_redirect($redirect);
            exit;
        }
        $post = get_post($post_id);
        if(!$post || $post->post_type !== self::CPT){
            $redirect = add_query_arg('ssl_single_error', 'invalid', $redirect);
            wp_safe_redirect($redirect);
            exit;
        }
        if($this->is_manual_mode($post_id)){
            $redirect = add_query_arg('ssl_single_error', 'manual', $redirect);
            wp_safe_redirect($redirect);
            exit;
        }
        $site = (string)get_post_meta($post_id,'site_url',true);
        if($site === ''){
            $redirect = add_query_arg('ssl_single_error', 'nosite', $redirect);
            wp_safe_redirect($redirect);
            exit;
        }
        $client = (string)get_post_meta($post_id,'client_name',true);
        $settings = $this->get_remote_client_settings();
        $remote_ready = $this->remote_client_is_ready($settings);
        $queued = false;
        if($remote_ready){
            $queued = $this->dispatch_remote_check($post_id, $site, 'manual-request', $settings);
            if(!$queued){
                $this->log_activity('הוספת משימה לתור נכשלה', array_merge([
                    'id' => $post_id,
                    'client_name' => $client,
                    'site_url' => $site,
                    'context' => 'manual-request',
                ], $this->get_current_actor_context()));
            }
        }
        if(!$queued){
            $this->cron_check_single($post_id, 'manual-request');
            update_post_meta($post_id,'expiry_ts_checked_at', time());
        }
        $this->log_activity('בקשת בדיקת SSL ידנית נשלחה', array_merge([
            'id' => $post_id,
            'client_name' => $client,
            'site_url' => $site,
            'check_name' => $post->post_title,
            'context' => 'manual-request',
            'queued' => $queued ? 1 : 0,
            'remote_ready' => $remote_ready ? 1 : 0,
        ], $this->get_current_actor_context()));
        $redirect = add_query_arg('ssl_single', $post_id, $redirect);
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_save() {
        $this->check_nonce();
        $post_id=intval($_POST['post_id'] ?? 0);
        $is_new = $post_id ? false : true;
        $client=sanitize_text_field($_POST['client_name'] ?? '');
        $site=$this->sanitize_url($_POST['site_url'] ?? '');
        $expiry_date=sanitize_text_field($_POST['expiry_date'] ?? '');
        $default_cert_type = $this->get_default_cert_type_key();
        $raw_cert_type = isset($_POST['cert_type']) ? $_POST['cert_type'] : $default_cert_type;
        $cert_type = $this->sanitize_cert_type_key($raw_cert_type, $default_cert_type);
        if($cert_type === '' && $default_cert_type !== ''){
            $cert_type = $default_cert_type;
        }
        $notes=sanitize_textarea_field($_POST['notes'] ?? '');
        $guide_url=$this->sanitize_url($_POST['guide_url'] ?? '');
        $cert_cn = sanitize_text_field($_POST['cert_cn'] ?? '');
        $manual_mode = !empty($_POST['manual_mode']) ? 1 : 0;
        $allow_duplicate = !empty($_POST['allow_duplicate_site']) ? 1 : 0;
        $temporary_note = sanitize_textarea_field($_POST['temporary_note'] ?? '');
        $temporary_enabled = !empty($_POST['temporary_enabled']) ? 1 : 0;
        $management_owner = $this->sanitize_management_owner($_POST['management_owner'] ?? 'ours');
        $agent_token = isset($_POST['agent_token']) ? sanitize_text_field($_POST['agent_token']) : '';

        $expiry_ts = $this->parse_user_date($expiry_date);

        if($is_new){
            $cert_type = $this->determine_auto_cert_type($site, $cert_type);
        }

        if($post_id){ wp_update_post(['ID'=>$post_id,'post_title'=>$client?:'SSL Item']); }
        else { $post_id=wp_insert_post(['post_type'=>self::CPT,'post_status'=>'publish','post_title'=>$client?:'SSL Item']); }

        $normalized_site = $this->normalize_site_identifier($site);
        if($normalized_site !== '' && !$allow_duplicate){
            $duplicate_post = $this->site_identifier_exists($normalized_site, $post_id);
            if($duplicate_post){
                $this->log_activity('נחסמה שמירת דומיין כפול', array_merge([
                    'site_url' => $site,
                    'duplicate_of' => $duplicate_post,
                ], $this->get_current_actor_context()));
                $redirect_target = wp_get_referer() ?: home_url('/');
                $redirect_target = add_query_arg('ssl_error', 'duplicate_site', $redirect_target);
                wp_safe_redirect($redirect_target);
                exit;
            }
        }

        if($post_id && !is_wp_error($post_id)){
            if($is_new){
                update_post_meta($post_id,'source',$this->normalize_source_value('manual'));
            }
            update_post_meta($post_id,'client_name',$client);
            update_post_meta($post_id,'site_url',$site);
            if($expiry_ts) update_post_meta($post_id,'expiry_ts',$expiry_ts);
            update_post_meta($post_id,'notes',$notes);
            update_post_meta($post_id,'guide_url',$guide_url);
            update_post_meta($post_id,'manual_mode',$manual_mode);
            update_post_meta($post_id,'allow_duplicate_site',$allow_duplicate);
            if($manual_mode){
                $this->remove_task_from_queue($post_id);
                $agent_token = get_post_meta($post_id,'agent_token',true);
            }
            if(!$manual_mode){
                if($agent_token === ''){
                    $agent_token = $this->get_default_agent_token_id();
                }
                update_post_meta($post_id,'agent_token',$agent_token);
            }
            update_post_meta($post_id,'follow_up',0);
            update_post_meta($post_id,'cert_cn',$cert_cn);
            update_post_meta($post_id,'cert_type',$cert_type);
            update_post_meta($post_id,'temporary_note',$temporary_note);
            update_post_meta($post_id,'temporary_enabled',$temporary_enabled ? 1 : 0);
            update_post_meta($post_id,'management_owner',$management_owner);

            if($this->should_disable_temporary_note($expiry_ts)){
                update_post_meta($post_id,'temporary_enabled',0);
            }

            $dispatched = false;
            $fallback_used = false;
            if(!empty($_FILES['images']) && is_array($_FILES['images']['name'])){
                $ids=get_post_meta($post_id,'images',true); if(!is_array($ids)) $ids=[];
                $f=$_FILES['images'];
                for($i=0;$i<count($f['name']);$i++){
                    if($f['error'][$i]===UPLOAD_ERR_OK && $f['size'][$i]>0){
                        $fa=['name'=>sanitize_file_name($f['name'][$i]),'type'=>$f['type'][$i],'tmp_name'=>$f['tmp_name'][$i],'error'=>0,'size'=>$f['size'][$i]];
                        $move=wp_handle_upload($fa,['test_form'=>false]);
                        if($move && empty($move['error'])){
                            $att=['post_mime_type'=>$move['type'],'post_title'=>sanitize_file_name($fa['name']),'post_status'=>'inherit'];
                            $aid=wp_insert_attachment($att,$move['file'],$post_id);
                            require_once(ABSPATH.'wp-admin/includes/image.php');
                            $meta=wp_generate_attachment_metadata($aid,$move['file']);
                            wp_update_attachment_metadata($aid,$meta);
                            $ids[]=$aid;
                        }
                    }
                }
                update_post_meta($post_id,'images',$ids);
            }
            if($site && !$manual_mode){
                $settings = $this->get_remote_client_settings();
                if($this->dispatch_remote_check($post_id, $site, 'manual-save', $settings)){
                    $dispatched = true;
                }
            }
            $collection_method = 'manual';
            if(!$manual_mode){
                if($dispatched){
                    $collection_method = 'agent';
                } elseif($fallback_used){
                    $collection_method = 'server';
                } else {
                    $collection_method = 'existing';
                }
            }
            $this->log_activity($is_new ? 'נוצרה רשומת SSL חדשה' : 'עודכנה רשומת SSL קיימת', array_merge([
                'id' => $post_id,
                'client_name' => $client,
                'site_url' => $site,
                'common_name' => $cert_cn,
                'cert_type' => $cert_type,
                'guide_url' => $guide_url,
                'manual_mode' => (bool)$manual_mode,
                'allow_duplicate_site' => (bool)$allow_duplicate,
                'dispatched_to_agent' => $dispatched,
                'local_fallback_used' => $fallback_used,
                'collection_method' => $collection_method,
            ], $this->get_current_actor_context()));
            $this->sync_table_record($post_id, get_post_status($post_id));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }
    public function handle_delete(){
        $this->check_nonce();
        $ids = [];
        if(!empty($_POST['post_ids']) && is_array($_POST['post_ids'])){
            foreach($_POST['post_ids'] as $raw_id){
                $candidate = (int)$raw_id;
                if($candidate > 0){
                    $ids[$candidate] = $candidate;
                }
            }
        }
        $single = isset($_POST['post_id']) ? (int)$_POST['post_id'] : 0;
        if($single > 0){
            $ids[$single] = $single;
        }
        $records = [];
        foreach($ids as $id){
            $post = get_post($id);
            if(!$post || $post->post_type !== self::CPT){
                continue;
            }
            $client = get_post_meta($id,'client_name',true);
            $site = get_post_meta($id,'site_url',true);
            $cn = get_post_meta($id,'cert_cn',true);
            wp_trash_post($id);
            $records[] = [
                'id' => $id,
                'client_name' => $client,
                'site_url' => $site,
                'common_name' => $cn,
                'post_title' => $post->post_title,
            ];
        }
        if(count($records) === 1){
            $info = $records[0];
            $this->log_activity('רשומת SSL הועברה לסל המחזור', array_merge($info, $this->get_current_actor_context()));
        } elseif(!empty($records)){
            $summary = [
                'count' => count($records),
                'ids' => array_column($records, 'id'),
                'clients' => array_values(array_filter(array_map(function($item){ return $item['client_name']; }, $records))),
            ];
            $this->log_activity('רשומות SSL הועברו לסל המחזור', array_merge($summary, $this->get_current_actor_context()));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }
    public function handle_restore(){
        $this->check_nonce();
        $id=intval($_POST['post_id']??0);
        if($id){
            $post = get_post($id);
            $client = get_post_meta($id,'client_name',true);
            $site = get_post_meta($id,'site_url',true);
            $cn = get_post_meta($id,'cert_cn',true);
            wp_untrash_post($id);
            $this->log_activity('רשומת SSL שוחזרה', array_merge([
                'id' => $id,
                'client_name' => $client,
                'site_url' => $site,
                'common_name' => $cn,
                'post_title' => $post ? $post->post_title : '',
            ], $this->get_current_actor_context()));
        }
        wp_safe_redirect( wp_get_referer() ?: home_url('/') ); exit;
    }

    public function handle_delete_permanent(){
        $this->check_nonce();
        $redirect = '';
        if(isset($_POST['redirect_to'])){
            $candidate = esc_url_raw(wp_unslash($_POST['redirect_to']));
            if($candidate){
                $redirect = $candidate;
            }
        }
        if(!$redirect){
            $redirect = wp_get_referer();
        }
        if(!$redirect){
            $redirect = home_url('/');
        }
        $post_id = isset($_POST['post_id']) ? (int)$_POST['post_id'] : 0;
        if($post_id > 0){
            $post = get_post($post_id);
            if($post && $post->post_type === self::CPT && $post->post_status === 'trash'){
                $client = get_post_meta($post_id,'client_name',true);
                $site = get_post_meta($post_id,'site_url',true);
                $cn = get_post_meta($post_id,'cert_cn',true);
                wp_delete_post($post_id, true);
                $this->log_activity('רשומת SSL נמחקה לצמיתות', array_merge([
                    'id' => $post_id,
                    'client_name' => $client,
                    'site_url' => $site,
                    'common_name' => $cn,
                ], $this->get_current_actor_context()));
            }
        }
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_empty_trash(){
        $this->check_nonce();
        $redirect = '';
        if(isset($_POST['redirect_to'])){
            $candidate = esc_url_raw(wp_unslash($_POST['redirect_to']));
            if($candidate){
                $redirect = $candidate;
            }
        }
        if(!$redirect){
            $redirect = wp_get_referer();
        }
        if(!$redirect){
            $redirect = home_url('/');
        }
        $trashed = get_posts([
            'post_type' => self::CPT,
            'post_status' => 'trash',
            'posts_per_page' => -1,
            'fields' => 'ids',
        ]);
        $deleted = 0;
        if(!empty($trashed)){
            foreach($trashed as $trashed_id){
                $trashed_id = (int)$trashed_id;
                if($trashed_id <= 0){
                    continue;
                }
                wp_delete_post($trashed_id, true);
                $deleted++;
            }
        }
        if($deleted > 0){
            $this->log_activity('סל המחזור נוקה', array_merge([
                'count' => $deleted,
            ], $this->get_current_actor_context()));
        }
        wp_safe_redirect($redirect);
        exit;
    }

    public function handle_export() {
        $filename='ssl-export-'.date('Ymd-His').'.csv';
        header('Content-Type: text/csv; charset=utf-8');
        header('Content-Disposition: attachment; filename='.$filename);
        $out=fopen('php://output','w');
        fputcsv($out,['client_name','site_url','expiry_date','common_name','cert_type','notes','guide_url','manual_mode']);
        global $wpdb;
        $table = $this->get_table_name();
        $rows = $wpdb->get_results("SELECT * FROM {$table} WHERE status != 'trash'", ARRAY_A);
        $exported = 0;
        foreach($rows as $row){
            $client = $row['client_name'] ?? '';
            $site = $row['site_url'] ?? '';
            $expiry = !empty($row['expiry_ts']) ? gmdate('Y-m-d', (int)$row['expiry_ts']) : '';
            $cn = $row['common_name'] ?? '';
            $cert_type = isset($row['cert_type']) ? $this->sanitize_cert_type_key($row['cert_type']) : '';
            $notes = $row['notes'] ?? '';
            $guide_url = $row['guide_url'] ?? '';
            $manual_mode_row = !empty($row['manual_mode']) ? 1 : 0;
            fputcsv($out, [$client, $site, $expiry, $cn, $cert_type, $notes, $guide_url, $manual_mode_row]);
            $exported++;
        }
        fclose($out);
        $this->log_activity('בוצע ייצוא רשומות', array_merge([
            'filename' => $filename,
            'exported' => $exported,
        ], $this->get_current_actor_context()));
        exit;
    }

    public function handle_import() {
        $this->check_nonce();
        $step = sanitize_text_field($_POST['ssl_import_step'] ?? '');
        if($step === 'preview'){
            if(empty($_FILES['import_file']) || $_FILES['import_file']['error'] !== UPLOAD_ERR_OK){
                wp_die('קובץ ייבוא לא התקבל');
            }
            $uploaded_name = sanitize_file_name($_FILES['import_file']['name'] ?? '');
            $rows = $this->parse_import_file($_FILES['import_file']['tmp_name'], $uploaded_name);
            if(is_wp_error($rows)){
                wp_die($rows->get_error_message());
            }
            $total = is_array($rows) ? count($rows) : 0;
            $key = substr(md5(uniqid('', true)), 0, 12);
            set_transient('ssl_import_'.$key, [
                'rows' => $rows,
                'filename' => $uploaded_name,
                'total' => $total,
                'created_at' => time(),
            ], HOUR_IN_SECONDS);
            $redirect = add_query_arg('ssl_preview', $key, wp_get_referer() ?: home_url('/'));
            wp_safe_redirect($redirect);
            exit;
        }

        if($step === 'confirm'){
            $preview_key = sanitize_key($_POST['preview_key'] ?? '');
            if(!$preview_key){
                wp_die('תצוגה מקדימה חסרה');
            }
            $preview_data = get_transient('ssl_import_'.$preview_key);
            if(empty($preview_data) || empty($preview_data['rows']) || !is_array($preview_data['rows'])){
                wp_die('הקובץ לתצוגה מקדימה אינו זמין');
            }
            $rows = $preview_data['rows'];
            $created = 0;
            $rows_logged = [];
            $rows_extra = 0;
            $default_cert_type = $this->get_default_cert_type_key();
            foreach($rows as $row){
                $client = sanitize_text_field($row['client_name'] ?? '');
                $site = $this->sanitize_url($row['site_url'] ?? '');
                $expiry_ts = !empty($row['expiry_ts']) ? (int)$row['expiry_ts'] : null;
                $notes = sanitize_textarea_field($row['notes'] ?? '');
                $guide_url = $this->sanitize_url($row['guide_url'] ?? '');
                $manual_mode = !empty($row['manual_mode']) ? 1 : 0;
                $common_name = sanitize_text_field($row['common_name'] ?? '');
                $cert_type = $this->sanitize_cert_type_key($row['cert_type'] ?? '', $default_cert_type);
                if($cert_type === '' && $default_cert_type !== ''){
                    $cert_type = $default_cert_type;
                }
                if($client === '' && $site === ''){
                    continue;
                }
                $post_title = $client ?: ($site ?: 'SSL Item');
                $pid = wp_insert_post([
                    'post_type' => self::CPT,
                    'post_status' => 'publish',
                    'post_title' => $post_title,
                ]);
                if(is_wp_error($pid)){
                    continue;
                }
                update_post_meta($pid,'client_name',$client);
                update_post_meta($pid,'site_url',$site);
                if($expiry_ts){
                    update_post_meta($pid,'expiry_ts',$expiry_ts);
                }
                update_post_meta($pid,'notes',$notes);
                update_post_meta($pid,'guide_url',$guide_url);
                update_post_meta($pid,'manual_mode',$manual_mode);
                update_post_meta($pid,'cert_cn',$common_name);
                update_post_meta($pid,'cert_type',$cert_type);
                $this->sync_table_record($pid, get_post_status($pid));
                $created++;
                if(count($rows_logged) < 10){
                    $rows_logged[] = [
                        'id' => $pid,
                        'client_name' => $client,
                        'site_url' => $site,
                        'common_name' => $common_name,
                        'cert_type' => $cert_type,
                    ];
                } else {
                    $rows_extra++;
                }
            }
            delete_transient('ssl_import_'.$preview_key);
            $this->log_activity('בוצע ייבוא רשומות', array_merge([
                'filename' => $preview_data['filename'] ?? '',
                'created' => $created,
                'records' => $rows_logged,
                'records_additional' => $rows_extra,
            ], $this->get_current_actor_context()));
            $redirect = remove_query_arg('ssl_preview', wp_get_referer() ?: home_url('/'));
            wp_safe_redirect($redirect);
            exit;
        }

        wp_die('שלב ייבוא לא תקין');
    }

    public function ensure_cron(){
        $target = $this->next_midnight_gmt();
        $next = wp_next_scheduled(self::CRON_HOOK);
        if(!$next){
            wp_schedule_event($target, 'daily', self::CRON_HOOK);
            return;
        }
        if(absint($next - $target) > 300){
            wp_unschedule_event($next, self::CRON_HOOK);
            wp_schedule_event($target, 'daily', self::CRON_HOOK);
        }
        $monitor_next = wp_next_scheduled(self::CRON_MONITOR_HOOK);
        if(!$monitor_next){
            wp_schedule_event(time() + self::QUEUE_CLAIM_TTL, 'ssl_five_minutes', self::CRON_MONITOR_HOOK);
        }
    }
    public function cron_check_all() {
        $scheduled = $this->schedule_certificate_batch('cron', time(), 120);
        $this->log_activity('תוזמנה בדיקת חצות לכל הדומיינים', array_merge([
            'scheduled' => $scheduled,
        ], $this->get_current_actor_context()));
    }
    public function cron_monitor_connectivity(){
        $state = get_option(self::OPTION_MONITOR_STATE, []);
        if(!is_array($state)){
            $state = [];
        }
        $window = self::TOKEN_STALE_WINDOW;
        $emails = $this->get_monitor_emails();
        $now = time();
        $last_status = isset($state['status']) ? $state['status'] : 'unknown';
        $last_notice = isset($state['last_notice']) ? (int)$state['last_notice'] : 0;
        $token_notices = isset($state['token_notices']) && is_array($state['token_notices']) ? $state['token_notices'] : [];
        $stale_tokens = $this->get_stale_tokens($window);
        if(!empty($stale_tokens)){
            $notify_tokens = [];
            foreach($stale_tokens as $token){
                $token_id = isset($token['id']) ? $token['id'] : '';
                $last_for_token = isset($token_notices[$token_id]) ? (int)$token_notices[$token_id] : 0;
                if(($now - $last_for_token) > HOUR_IN_SECONDS){
                    $notify_tokens[] = $token;
                    $token_notices[$token_id] = $now;
                }
            }
            $should_notify = ($last_status !== 'down') || (($now - $last_notice) > HOUR_IN_SECONDS) || !empty($notify_tokens);
            if($should_notify && !empty($emails) && function_exists('wp_mail')){
                $names = [];
                foreach($stale_tokens as $token){
                    $name = isset($token['name']) ? $token['name'] : 'טוקן ללא שם';
                    $last_seen = !empty($token['last_seen']) ? date_i18n('d.m.Y H:i', (int)$token['last_seen']) : 'לא התקבל חיבור';
                    $names[] = sprintf('%s (אחרון: %s)', $name, $last_seen);
                }
                $subject = sprintf('התראת חיבור טוקן SSL - %s', wp_specialchars_decode(get_bloginfo('name'), ENT_QUOTES));
                $body = "שלום,\n\nלא זוהתה תקשורת עם הטוקנים הבאים במהלך חלון של 5 דקות:\n- " . implode("\n- ", $names) . "\n\nהמערכת תמשיך לנסות להתחבר אחת ל-5 דקות ולשלוח התראה אם התקלה נמשכת.";
                foreach($emails as $email){
                    wp_mail($email, $subject, $body);
                }
            }
            $this->log_activity('ניטור חיבור: טוקנים לא זמינים', [
                'window_seconds' => $window,
                'monitor_email' => implode(',', $emails),
                'token_names' => array_map(function($token){ return $token['name'] ?? ''; }, $stale_tokens),
            ], 'warning');
            $state['last_notice'] = $now;
            $state['status'] = 'down';
            $state['token_notices'] = $token_notices;
            $state['down_tokens'] = array_map(function($token){
                return [
                    'id' => $token['id'] ?? '',
                    'name' => $token['name'] ?? '',
                    'last_seen' => $token['last_seen'] ?? 0,
                ];
            }, $stale_tokens);
            update_option(self::OPTION_MONITOR_STATE, $state, false);
            return;
        }
        if($last_status === 'down'){
            $this->log_activity('ניטור חיבור: הסוכן חזר לתקשר', [
                'window_seconds' => $window,
                'monitor_email' => implode(',', $emails),
            ], 'info');
        }
        $state['status'] = 'up';
        $state['last_notice'] = $now;
        $state['token_notices'] = $token_notices;
        $state['down_tokens'] = [];
        update_option(self::OPTION_MONITOR_STATE, $state, false);
    }
    private function next_midnight_gmt(){
        $now_local = current_time('timestamp');
        $now_gmt = current_time('timestamp', true);
        $midnight_local = strtotime('today midnight', $now_local);
        if($midnight_local <= $now_local){
            $midnight_local = strtotime('tomorrow midnight', $now_local);
        }
        $offset = $midnight_local - $now_local;
        return $now_gmt + $offset;
    }
    public function register_custom_schedules($schedules){
        if(!isset($schedules['ssl_five_minutes'])){
            $schedules['ssl_five_minutes'] = [
                'interval' => 300,
                'display'  => __('Every 5 Minutes (SSL Manager)', 'ssl-expiry-manager'),
            ];
        }
        return $schedules;
    }
    private function schedule_single_check($timestamp, $post_id, $context){
        $timestamp = (int)$timestamp;
        $post_id = (int)$post_id;
        $context_key = sanitize_key($context ?: 'cron');
        if($timestamp <= 0 || $post_id <= 0){
            return false;
        }
        $args = [$post_id, $context_key];
        $existing = wp_next_scheduled(self::CRON_SINGLE_HOOK, $args);
        if($existing){
            wp_unschedule_event($existing, self::CRON_SINGLE_HOOK, $args);
        }
        return (bool)wp_schedule_single_event($timestamp, self::CRON_SINGLE_HOOK, $args);
    }
    private function schedule_certificate_batch($context, $start_timestamp, $interval_seconds = 120){
        $start = max(time(), (int)$start_timestamp);
        $interval = max(1, (int)$interval_seconds);
        $settings = $this->get_remote_client_settings();
        $remote_ready = $this->remote_client_is_ready($settings);
        $query_args = [
            'post_type' => self::CPT,
            'post_status' => ['publish','draft','pending'],
            'posts_per_page' => -1,
            'fields' => 'ids',
        ];
        $scheduled = 0;
        $offset = 0;
        $q = new WP_Query($query_args);
        if($q->have_posts()){
            foreach($q->posts as $post_id){
                $post_id = (int)$post_id;
                if($post_id <= 0){
                    continue;
                }
                $url = (string)get_post_meta($post_id,'site_url',true);
                if($url === ''){
                    continue;
                }
                if($this->is_manual_mode($post_id)){
                    continue;
                }
                if($remote_ready && $this->dispatch_remote_check($post_id, $url, $context, $settings)){
                    $scheduled++;
                } else {
                    $run_at = $start + ($offset * $interval);
                    if($this->schedule_single_check($run_at, $post_id, $context)){
                        $scheduled++;
                        $offset++;
                    }
                }
            }
            wp_reset_postdata();
        }
        return $scheduled;
    }
    public function cron_check_single($post_id, $context = 'cron'){
        $post_id = (int)$post_id;
        if($post_id <= 0){
            return;
        }
        $url = (string)get_post_meta($post_id,'site_url',true);
        if($url === ''){
            return;
        }
        if($this->is_manual_mode($post_id)){
            return;
        }
        $settings = $this->get_remote_client_settings();
        $remote_ready = $this->remote_client_is_ready($settings);

        // אם ה-agent לא מוכן – לא מבצעים בדיקה מהשרת, פשוט יוצאים
        if(!$remote_ready){
            return;
        }

        // ניסיון שליחה ל-agent בלבד ללא fallback לשרת
        $this->dispatch_remote_check($post_id, $url, $context, $settings);
    }
    private function fetch_ssl_certificate_details($url){
        $parsed_url = wp_parse_url($url);
        if(!$parsed_url || empty($parsed_url['host'])){
            return null;
        }
        $host = $parsed_url['host'];
        $port = isset($parsed_url['port']) ? (int)$parsed_url['port'] : 443;
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ],
        ]);
        $client = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, 10, STREAM_CLIENT_CONNECT, $context);
        if(!$client){
            return null;
        }
        $params = stream_context_get_params($client);
        fclose($client);
        if(empty($params['options']['ssl']['peer_certificate'])){
            return null;
        }
        $certificate = $params['options']['ssl']['peer_certificate'];
        $cert_data = openssl_x509_parse($certificate);
        if(!$cert_data || empty($cert_data['validTo_time_t'])){
            return null;
        }
        $common_name = '';
        $issuer_name = '';
        if(!empty($cert_data['subject']) && is_array($cert_data['subject'])){
            if(!empty($cert_data['subject']['CN'])){
                $common_name = $cert_data['subject']['CN'];
            } elseif(!empty($cert_data['subject']['commonName'])){
                $common_name = $cert_data['subject']['commonName'];
            }
        }
        if($common_name === '' && !empty($cert_data['extensions']['subjectAltName'])){
            $alt_names = explode(',', $cert_data['extensions']['subjectAltName']);
            foreach($alt_names as $alt){
                $alt = trim($alt);
                if(stripos($alt, 'DNS:') === 0){
                    $candidate = trim(substr($alt, 4));
                    if($candidate !== ''){
                        $common_name = $candidate;
                        break;
                    }
                }
            }
        }
        if(!empty($cert_data['issuer']) && is_array($cert_data['issuer'])){
            $issuer_values = [];
            $preferred = ['organizationName','O','commonName','CN'];
            foreach($preferred as $key){
                if(empty($cert_data['issuer'][$key])){
                    continue;
                }
                $value = $cert_data['issuer'][$key];
                if(is_array($value)){
                    $value = reset($value);
                }
                if(is_string($value)){
                    $issuer_values[] = $value;
                }
            }
            if(empty($issuer_values)){
                foreach($cert_data['issuer'] as $value){
                    if(is_string($value)){
                        $issuer_values[] = $value;
                    } elseif(is_array($value)){
                        foreach($value as $nested){
                            if(is_string($nested)){
                                $issuer_values[] = $nested;
                            }
                        }
                    }
                }
            }
            if(!empty($issuer_values)){
                $issuer_values = array_map('trim', $issuer_values);
                $issuer_values = array_filter($issuer_values, function($val){ return $val !== ''; });
                $issuer_values = array_values(array_unique($issuer_values));
                if(!empty($issuer_values)){
                    $issuer_name = implode(' / ', $issuer_values);
                }
            }
        }
        return [
            'expiry_ts' => (int)$cert_data['validTo_time_t'],
            'common_name' => $common_name,
            'issuer_name' => $issuer_name,
        ];
    }

    private function apply_certificate_details($post_id, $details, $source_label = 'agent', $checked_at = null){
        if(!$post_id || !is_array($details)){
            return false;
        }
        $updated = false;
        $result = [
            'expiry_ts' => null,
            'common_name' => '',
            'issuer_name' => '',
        ];

        $primary_expiry = $details['expiry_ts'] ?? null;
        if($primary_expiry === null || $primary_expiry === ''){
            $expiry_candidates = [
                $details['expiryts'] ?? null,
                $details['expiry'] ?? null,
                $details['not_after'] ?? null,
                $details['notafter'] ?? null,
            ];
        } else {
            $expiry_candidates = [$primary_expiry];
        }
        foreach($expiry_candidates as $candidate){
            if($candidate === null || $candidate === ''){
                continue;
            }
            $parsed = is_numeric($candidate) ? (int)$candidate : strtotime((string)$candidate);
            if($parsed && $parsed > 1000000000){
                update_post_meta($post_id,'expiry_ts',$parsed);
                $result['expiry_ts'] = $parsed;
                $updated = true;
                break;
            }
            error_log('SSL Expiry Manager: invalid expiry_ts value for post '.$post_id.' from details payload: '.print_r($details,true));
        }

        $name_candidates = [
            $details['common_name'] ?? null,
            $details['cn'] ?? null,
            $details['cert_cn'] ?? null,
        ];
        foreach($name_candidates as $candidate){
            if($candidate === null){
                continue;
            }
            $common_name = sanitize_text_field($candidate);
            if($common_name !== ''){
                update_post_meta($post_id,'cert_cn',$common_name);
                $result['common_name'] = $common_name;
                $updated = true;
                break;
            }
        }

        $issuer_candidates = [
            $details['issuer_name'] ?? null,
            $details['issuer'] ?? null,
            $details['ca'] ?? null,
            $details['cert_ca'] ?? null,
        ];
        foreach($issuer_candidates as $candidate){
            if($candidate === null){
                continue;
            }
            $issuer_name = sanitize_text_field($candidate);
            if($issuer_name !== ''){
                update_post_meta($post_id,'cert_ca',$issuer_name);
                $result['issuer_name'] = $issuer_name;
                $updated = true;
                break;
            }
        }

        if($updated){
            $checked_value = $checked_at && is_numeric($checked_at) ? (int)$checked_at : time();
            update_post_meta($post_id,'source',$this->normalize_source_value($source_label, 'auto'));
            delete_post_meta($post_id,'last_error');
            update_post_meta($post_id,'expiry_ts_checked_at', $checked_value);
            if(!empty($result['expiry_ts']) && $this->should_disable_temporary_note($result['expiry_ts'])){
                update_post_meta($post_id,'temporary_enabled',0);
            }
            $this->sync_table_record($post_id, get_post_status($post_id));
        }
        return $updated ? $result : false;
    }

    private function attempt_server_certificate_update($post_id, $site_url, $context = ''){
        if(!$post_id){
            return false;
        }
        $details = $this->fetch_ssl_certificate_details($site_url);
        if(!$details){
            return false;
        }
        $applied = $this->apply_certificate_details($post_id, $details, 'server');
        if($applied){
            $this->log_activity('בדיקת SSL בוצעה דרך השרת', array_merge([
                'id' => $post_id,
                'site_url' => $site_url,
                'expiry_ts' => isset($applied['expiry_ts']) ? $applied['expiry_ts'] : null,
                'context' => $context,
            ], $this->get_current_actor_context()));
        }
        return $applied;
    }

    private function collect_rest_tasks($limit, $force = false, $agent_filter = null){
        $limit = min(100, max(1, (int)$limit));
        $now = time();
        $stale = $now - DAY_IN_SECONDS;

        $meta_query = [
            'relation' => 'AND',
            [
                'key' => 'site_url',
                'value' => '',
                'compare' => '!=',
            ],
        ];

        $meta_query[] = [
            'relation' => 'OR',
            [
                'key' => 'manual_mode',
                'value' => 1,
                'compare' => '!=',
                'type' => 'NUMERIC',
            ],
            [
                'key' => 'manual_mode',
                'compare' => 'NOT EXISTS',
            ],
        ];

        if(!$force){
            $meta_query[] = [
                'relation' => 'OR',
                [
                    'key' => 'expiry_ts_checked_at',
                    'value' => $stale,
                    'compare' => '<=',
                    'type' => 'NUMERIC',
                ],
                [
                    'key' => 'expiry_ts_checked_at',
                    'compare' => 'NOT EXISTS',
                ],
            ];
        }

        $query_args = [
            'post_type'      => self::CPT,
            'post_status'    => ['publish','draft','pending'],
            'posts_per_page' => $limit,
            'orderby'        => 'modified',
            'order'          => 'DESC',
            'meta_query'     => $meta_query,
        ];

        $q = new WP_Query($query_args);
        $tasks = [];

        if($q->have_posts()){
            while($q->have_posts()){ $q->the_post();
                $id = get_the_ID();
                $url = (string)get_post_meta($id,'site_url',true);
                if(!$url){
                    continue;
                }
                $tasks[] = [
                    'id' => $id,
                    'client_name' => (string)get_post_meta($id,'client_name',true),
                    'site_url' => $url,
                ];
                update_post_meta($id,'expiry_ts_checked_at', $now);
                $this->sync_table_record($id, get_post_status($id));
            }
        }
        wp_reset_postdata();

        return $tasks;
    }

    public function register_rest() {
        register_rest_route('ssl/v1','/tasks',['methods'=>'GET','permission_callback'=>'__return_true','callback'=>[$this,'rest_tasks']]);
        register_rest_route('ssl/v1','/report',['methods'=>'POST','permission_callback'=>'__return_true','callback'=>[$this,'rest_report']]);
        register_rest_route('ssl-agent/v1','/poll',[
            'methods'  => ['GET','POST'],
            'permission_callback' => '__return_true',
            'callback' => [$this,'rest_agent_poll'],
        ]);
        register_rest_route('ssl-agent/v1','/ack',[
            'methods'  => ['POST'],
            'permission_callback' => '__return_true',
            'callback' => [$this,'rest_agent_ack'],
        ]);
        register_rest_route('ssl-agent/v1','/report',[
            'methods'  => ['POST'],
            'permission_callback' => '__return_true',
            'callback' => [$this,'rest_report'],
        ]);
    }
    private function rest_auth($req){
        $token=$req->get_header('x-agent-token') ?: '';
        if(!$token){
            $this->log_activity('בקשת Agent ללא טוקן', $this->get_current_actor_context(), 'warning');
            return new WP_Error('forbidden','invalid token',['status'=>403]);
        }
        $tokens=$this->ensure_default_token();
        foreach($tokens as $stored){
            if(!empty($stored['token']) && hash_equals($stored['token'], $token)){
                $previous_status = isset($stored['last_status']) ? (string)$stored['last_status'] : 'unknown';
                $updated = $this->mark_token_online($stored['id']);
                if($previous_status !== 'online'){
                    $this->log_activity('סוכן אומת בהצלחה', array_merge([
                        'token' => $stored['name'] ?? $stored['id'],
                    ], $this->get_current_actor_context()));
                }
                return ['token' => $updated ?: $stored];
            }
        }
        $fragment = substr($token, 0, 8);
        $this->log_activity('ניסיון אימות טוקן נכשל', array_merge([
            'token_fragment' => $fragment,
        ], $this->get_current_actor_context()), 'warning');
        return new WP_Error('forbidden','invalid token',['status'=>403]);
    }
    public function rest_tasks(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $limit=min(100,max(1,intval($req->get_param('limit') ?: 50)));
        $token_data = is_array($auth) && isset($auth['token']) && is_array($auth['token']) ? $auth['token'] : [];
        $agent_filter = isset($token_data['id']) ? sanitize_text_field($token_data['id']) : '';
        $items=$this->peek_queue_tasks($limit,$agent_filter);
        return new WP_REST_Response(['tasks'=>$items,'count'=>count($items),'pending'=>$this->get_pending_db_queue_count()],200);
    }

    public function rest_agent_poll(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $limit=min(100,max(1,intval($req->get_param('limit') ?: 50)));
        $force=intval($req->get_param('force') ?: 0)===1;
        $token_data = is_array($auth) && isset($auth['token']) && is_array($auth['token']) ? $auth['token'] : [];
        $token_label = '';
        if(!empty($token_data['name'])){
            $token_label = (string)$token_data['name'];
        } elseif(!empty($token_data['id'])){
            $token_label = (string)$token_data['id'];
        }
        $agent_filter = isset($token_data['id']) ? sanitize_text_field($token_data['id']) : '';

        $this->release_stale_claims();
        if(!$this->queue_table_exists()){
            return new WP_REST_Response([
                'jobs'   => [],
                'tasks'  => [],
                'count'  => 0,
                'pending'=> 0,
            ],200);
        }

        global $wpdb;
        $table = $this->get_queue_table_name();
        $now   = time();

        $STATUS_QUEUED  = 0;
        $STATUS_CLAIMED = 1;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT id AS queue_id, post_id, site_url, client_name, context, enqueued_at, request_id, status, attempts
                 FROM {$table}
                 WHERE status = %d AND attempts < %d
                 ORDER BY enqueued_at ASC, id ASC
                 LIMIT %d",
                $STATUS_QUEUED,
                self::QUEUE_MAX_ATTEMPTS,
                $limit
            ),
            ARRAY_A
        );

        $items = [];
        foreach((array)$rows as $row){
            $queue_id = (int)$row['queue_id'];
            $post_id  = (int)$row['post_id'];
            $attempts = isset($row['attempts']) ? (int)$row['attempts'] : 0;
            $attempts++;

            $updated = $wpdb->update(
                $table,
                [
                    'status'     => $STATUS_CLAIMED,
                    'claimed_at' => $now,
                    'attempts'   => $attempts,
                ],
                ['id' => $queue_id],
                ['%d','%d','%d'],
                ['%d']
            );
            if(false === $updated){
                continue;
            }

            $items[] = [
                'queue_id'    => $queue_id,
                'id'          => $post_id,
                'post_id'     => $post_id,
                'site_url'    => isset($row['site_url']) ? (string)$row['site_url'] : '',
                'client_name' => isset($row['client_name']) ? (string)$row['client_name'] : '',
                'request_id'  => isset($row['request_id']) ? (string)$row['request_id'] : '',
                'context'     => isset($row['context']) && $row['context'] !== '' ? $row['context'] : 'manual',
                'callback'    => rest_url('ssl-agent/v1/report'),
                'queue_key'   => $queue_id,
                'agent_token' => $agent_filter,
                'claimed_at'  => $now,
                'attempts'    => $attempts,
            ];
        }

        if($force){
            $this->log_activity('סוכן דרש משימות בכפייה', array_merge([
                'limit' => $limit,
                'token' => $token_label,
            ], $this->get_current_actor_context()));
        }
        $jobs = [];
        foreach($items as $item){
            $queue_id = isset($item['queue_id']) ? (int)$item['queue_id'] : (isset($item['id']) ? (int)$item['id'] : 0);
            $post_id  = isset($item['post_id']) ? (int)$item['post_id'] : (isset($item['id']) ? (int)$item['id'] : 0);
            $jobs[] = [
                'id'          => $post_id,
                'post_id'     => $post_id,
                'queue_id'    => $queue_id,
                'site_url'    => isset($item['site_url']) ? $item['site_url'] : '',
                'client_name' => isset($item['client_name']) ? $item['client_name'] : '',
                'request_id'  => isset($item['request_id']) ? $item['request_id'] : '',
                'context'     => isset($item['context']) ? $item['context'] : null,
                'callback'    => isset($item['callback']) ? $item['callback'] : rest_url('ssl-agent/v1/report'),
                'queue_key'   => $queue_id,
                'agent_token' => isset($item['agent_token']) ? $item['agent_token'] : $agent_filter,
            ];
        }
        $this->log_activity('סוכן משך משימות מהשרת', array_merge([
            'count' => count($jobs),
            'token' => $token_label,
            'force' => $force,
        ], $this->get_current_actor_context()));

        $pending = (int) $wpdb->get_var(
            $wpdb->prepare(
                "SELECT COUNT(*) FROM {$table} WHERE status = %d",
                $STATUS_QUEUED
            )
        );

        return new WP_REST_Response([
            'jobs'   => $jobs,
            'tasks'  => $jobs,
            'count'  => count($jobs),
            'pending'=> $pending,
        ],200);
    }
    public function rest_agent_ack(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $data=$req->get_json_params();
        $rows = [];
        if(isset($data['tasks']) && is_array($data['tasks'])){
            $rows = $data['tasks'];
        } elseif(isset($data['acks']) && is_array($data['acks'])){
            $rows = $data['acks'];
        } elseif(isset($data['acknowledged']) && is_array($data['acknowledged'])){
            $rows = $data['acknowledged'];
        }
        $acknowledged=[];
        foreach($rows as $row){
            $id=isset($row['id'])?(int)$row['id']:0;
            if($id<=0){
                continue;
            }
            $acknowledged[]=[
                'id'=>$id,
                'request_id'=>isset($row['request_id'])?sanitize_text_field($row['request_id']):'',
            ];
        }
        if(!empty($acknowledged)){
            $token_data = is_array($auth) && isset($auth['token']) && is_array($auth['token']) ? $auth['token'] : [];
            $token_label = '';
            if(!empty($token_data['name'])){
                $token_label = (string)$token_data['name'];
            } elseif(!empty($token_data['id'])){
                $token_label = (string)$token_data['id'];
            }
            $log_records = [];
            foreach($acknowledged as $item){
                $entry = ['id' => $item['id']];
                if($item['request_id'] !== ''){
                    $entry['request_id'] = $item['request_id'];
                }
                $log_records[] = $entry;
            }
            $this->log_activity('סוכן אישר קבלת משימות', array_merge([
                'token' => $token_label,
                'acknowledged' => $log_records,
            ], $this->get_current_actor_context()));
        }
        return new WP_REST_Response(['ok'=>true,'acknowledged'=>count($acknowledged)],200);
    }
    public function rest_report(WP_REST_Request $req){
        $auth=$this->rest_auth($req); if(is_wp_error($auth)) return $auth;
        $data=$req->get_json_params();
        $rows=is_array($data['results']??null)?$data['results']:[];
        $token_data = is_array($auth) && isset($auth['token']) && is_array($auth['token']) ? $auth['token'] : [];
        $token_label = '';
        if(!empty($token_data['name'])){
            $token_label = (string)$token_data['name'];
        } elseif(!empty($token_data['id'])){
            $token_label = (string)$token_data['id'];
        }
        foreach($rows as $row){
            $queue_id = isset($row['queue_id']) ? (int)$row['queue_id'] : 0;
            $post_id = isset($row['post_id']) ? (int)$row['post_id'] : 0;
            $id = isset($row['id']) ? (int)$row['id'] : 0;
            if(!$post_id && $id){
                $post_id = $id;
            }
            if(!$post_id && $queue_id > 0 && $this->queue_table_exists()){
                global $wpdb;
                $table = $this->get_queue_table_name();
                $row_from_queue = $wpdb->get_row($wpdb->prepare("SELECT post_id FROM {$table} WHERE id = %d LIMIT 1", $queue_id), ARRAY_A);
                if($row_from_queue && !empty($row_from_queue['post_id'])){
                    $post_id = (int)$row_from_queue['post_id'];
                }
            }
            if(!$post_id){
                continue;
            }
            $request_id = isset($row['request_id']) ? sanitize_text_field($row['request_id']) : '';
            $error_message = '';
            $expiry_ts = 0;
            $primary_expiry = $row['expiry_ts'] ?? null;
            if($primary_expiry !== null && $primary_expiry !== ''){
                $expiry_ts = is_numeric($primary_expiry) ? intval($primary_expiry) : intval(strtotime((string)$primary_expiry));
            }
            if($expiry_ts <= 0){
                $expiry_candidates = [
                    $row['expiryts'] ?? null,
                    $row['expiry'] ?? null,
                    $row['expiry_ts'] ?? null,
                    $row['not_after'] ?? null,
                    $row['notafter'] ?? null,
                ];
                foreach($expiry_candidates as $candidate){
                    if($candidate === null || $candidate === ''){
                        continue;
                    }
                    $expiry_ts = is_numeric($candidate) ? intval($candidate) : intval(strtotime((string)$candidate));
                    if($expiry_ts > 1000000000){
                        break;
                    }
                    $expiry_ts = 0;
                }
            }
            if($expiry_ts <= 0){
                $non_empty_candidates = array_values(array_filter($expiry_candidates, function($candidate){
                    return !($candidate === null || $candidate === '');
                }));
                $reason = empty($non_empty_candidates) ? 'missing expiry' : ('invalid expiry values: '.print_r($non_empty_candidates, true));
                error_log('SSL Expiry Manager: agent report '.$reason.' for post '.$post_id.' payload='.print_r($row, true));
            }
            $reported_source = $this->normalize_source_value($row['source'] ?? 'agent', 'agent');
            $reported_cn = '';
            if(!empty($row['common_name'])){
                $reported_cn = sanitize_text_field($row['common_name']);
            } elseif(!empty($row['cn'])){
                $reported_cn = sanitize_text_field($row['cn']);
            }
            $reported_issuer = '';
            if(!empty($row['issuer_name'])){
                $reported_issuer = sanitize_text_field($row['issuer_name']);
            } elseif(!empty($row['issuer'])){
                $reported_issuer = sanitize_text_field($row['issuer']);
            } elseif(!empty($row['ca'])){
                $reported_issuer = sanitize_text_field($row['ca']);
            }
            $details_payload = [];
            if($expiry_ts){
                $details_payload['expiry_ts'] = $expiry_ts;
            }
            if($reported_cn !== ''){
                $details_payload['common_name'] = $reported_cn;
            }
            if($reported_issuer !== ''){
                $details_payload['issuer_name'] = $reported_issuer;
            }
            $executed_at_ts = 0;
            if(!empty($row['executed_at'])){
                $executed_at_ts = strtotime(sanitize_text_field($row['executed_at']));
            }
            $applied_details = [];
            if(!empty($details_payload)){
                $applied_candidate = $this->apply_certificate_details($post_id, $details_payload, $reported_source ?: 'agent', $executed_at_ts ?: null);
                if($applied_candidate){
                    $applied_details = $applied_candidate;
                }
            }
            if($expiry_ts > 0 && (empty($applied_details['expiry_ts']) || (int)$applied_details['expiry_ts'] <= 0)){
                update_post_meta($post_id,'expiry_ts',$expiry_ts);
                $checked_value = $executed_at_ts && is_numeric($executed_at_ts) ? (int)$executed_at_ts : time();
                update_post_meta($post_id,'expiry_ts_checked_at', $checked_value);
                $this->sync_table_record($post_id, get_post_status($post_id));
                $applied_details['expiry_ts'] = $expiry_ts;
            }
            if(!empty($row['error'])){
                $error_message = sanitize_text_field($row['error']);
                update_post_meta($post_id,'last_error',$error_message);
            } else {
                delete_post_meta($post_id,'last_error');
            }
            $check_label = !empty($row['check_name']) ? sanitize_text_field($row['check_name']) : '';
            $status_label = !empty($row['status']) ? sanitize_text_field($row['status']) : '';
            $latency_ms = isset($row['latency_ms']) ? intval($row['latency_ms']) : 0;
            $extra = [
                'token' => $token_label,
            ];
            if($check_label !== ''){
                $extra['agent_check'] = $check_label;
            }
            if($status_label !== ''){
                $extra['agent_status'] = $status_label;
            }
            if($latency_ms > 0){
                $extra['latency_ms'] = $latency_ms;
            }
            if(!empty($applied_details['expiry_ts'])){
                $extra['expiry_ts'] = (int)$applied_details['expiry_ts'];
            } elseif($expiry_ts){
                $extra['expiry_ts'] = $expiry_ts;
            }
            if(!empty($applied_details['common_name'])){
                $extra['common_name'] = $applied_details['common_name'];
            } elseif($reported_cn !== ''){
                $extra['common_name'] = $reported_cn;
            }
            if(!empty($applied_details['issuer_name'])){
                $extra['issuer_name'] = $applied_details['issuer_name'];
            } elseif($reported_issuer !== ''){
                $extra['issuer_name'] = $reported_issuer;
            }
            if($reported_source !== ''){
                $extra['source'] = $reported_source;
            } else {
                $extra['source'] = 'agent';
            }
            if(!empty($row['executed_at'])){
                $extra['agent_executed_at'] = sanitize_text_field($row['executed_at']);
            }
            if(!empty($row['initiator'])){
                $extra['initiator'] = sanitize_text_field($row['initiator']);
            }
            if($error_message){
                $extra['error'] = $error_message;
                $this->complete_queue_task($post_id,$request_id,false,$error_message,$extra,$queue_id);
            } else {
                $this->complete_queue_task($post_id,$request_id,true,'',$extra,$queue_id);
            }
        }
        if(empty($rows)){
            $this->log_activity('דוח סוכן התקבל ללא תוצאות', array_merge([
                'token' => $token_label,
            ], $this->get_current_actor_context()));
        }
        return new WP_REST_Response(['ok'=>true,'updated'=>count($rows)],200);
    }

    public function settings_page(){
        add_options_page('SSL Expiry API','SSL Expiry API','manage_options','ssl-expiry-api',function(){
            if(!current_user_can('manage_options')){
                return;
            }
            $tokens = $this->ensure_default_token();
            $remote = $this->get_remote_client_settings();
            $remote_ready = $this->remote_client_is_ready($remote);
            echo '<div class="wrap"><h1>SSL Expiry API</h1>';
            if(!empty($_GET['remote-updated'])){
                echo '<div class="notice notice-success"><p>ההגדרות נשמרו בהצלחה.</p></div>';
            }
            echo '<p>ניהול הטוקנים מתבצע דרך הקיצור <code>[ssl_token_page]</code> בפרונט. להלן הטוקנים הפעילים:</p>';
            echo '<table class="widefat striped"><thead><tr><th>שם הטוקן</th><th>ערך</th><th>עודכן</th></tr></thead><tbody>';
            foreach($tokens as $token){
                $updated = !empty($token['updated']) ? date_i18n('Y-m-d H:i', (int)$token['updated']) : '';
                echo '<tr><td>'.esc_html($token['name']).'</td><td><code>'.esc_html($token['token']).'</code></td><td>'.esc_html($updated).'</td></tr>';
            }
            echo '</tbody></table>';
            $poll_url = rest_url('ssl-agent/v1/poll');
            $report_url = rest_url('ssl-agent/v1/report');
            $ack_url = rest_url('ssl-agent/v1/ack');
            echo '<p>כל קריאת REST חייבת לכלול Header בשם <code>X-Agent-Token</code>. נקודות הקצה הזמינות:</p>';
            echo '<ul style="list-style:disc;padding-right:20px;">';
            echo '<li><code>'.esc_html($poll_url).'</code> &mdash; משיכת משימות לסוכן.</li>';
            echo '<li><code>'.esc_html($ack_url).'</code> &mdash; אישור קבלת משימות (POST JSON עם מזהים).</li>';
            echo '<li><code>'.esc_html($report_url).'</code> &mdash; שליחת דוחות ביצוע.</li>';
            echo '</ul>';
            echo '<hr />';
            echo '<h2>הגדרות סוכן מרוחק</h2>';
            if($remote_ready){
                echo '<p><span style="color:#0a7a0a;font-weight:600;">הסוכן המרוחק פעיל תמיד כשקיים טוקן ראשי.</span> משימות חדשות ייכנסו לתור ויאספו באמצעות השירות במשרד.</p>';
            } else {
                echo '<p><span style="color:#b91c1c;font-weight:600;">אין טוקן ראשי פעיל.</span> המשימות יבוצעו מקומית עד להוספת טוקן.</p>';
            }
            echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" class="ssl-remote-form">';
            wp_nonce_field('ssl_remote_client');
            echo '<input type="hidden" name="action" value="ssl_save_remote_client" />';
            echo '<table class="form-table" role="presentation"><tbody>';
            echo '<tr><th scope="row">מפתחי הסוכן</th><td><p class="description">התוסף מפנה תמיד לסוכן המרוחק כאשר קיים טוקן ראשי זמין. אין צורך להפעיל או לכבות ידנית.</p></td></tr>';
            echo '<tr><th scope="row">REST Poll</th><td><code>'.esc_html($poll_url).'</code><p class="description">השתמש בקישור זה להגדרת שירות ה-Agent (GET/POST).</p></td></tr>';
            echo '<tr><th scope="row">REST Ack</th><td><code>'.esc_html($ack_url).'</code><p class="description">קריאה אופציונלית לאישור קבלת משימות לאחר שליפה.</p></td></tr>';
            echo '<tr><th scope="row">REST Report</th><td><code>'.esc_html($report_url).'</code><p class="description">הסוכן שולח לכאן תוצאות באמצעות POST.</p></td></tr>';
            $primary_token_value = $this->get_primary_token_value();
            if($primary_token_value){
                echo '<tr><th scope="row">Token לאימות</th><td><code>'.esc_html($primary_token_value).'</code><p class="description">העבר ערך זה בכותרת <code>X-Agent-Token</code> בכל קריאה מהסוכן.</p></td></tr>';
            }
            echo '</tbody></table>';
            echo '<p class="submit"><button type="submit" class="button button-primary">שמירת הגדרות</button></p>';
            echo '</form>';
            echo '<p class="description">להתקנה מהירה ניתן להריץ את הפקודה <code>python3 remote_client_installer.py --wp-url='.esc_html(home_url('/')).' --agent-token=TOKEN</code> על התחנה במשרד. הסקריפט יוודא תלותים, יתקין את השירות ויתחבר לנקודות הקצה לעיל.</p>';

            $queue = $this->get_task_queue();
            echo '<hr /><h2>תור משימות</h2>';
            if(empty($queue)){
                echo '<p>אין משימות ממתינות בתור.</p>';
            } else {
                echo '<p>כמות משימות ממתינות: <strong>'.count($queue).'</strong>.</p>';
                echo '<table class="widefat striped"><thead><tr><th>ID</th><th>לקוח</th><th>URL</th><th>הקשר</th><th>סטטוס</th><th>זמן</th></tr></thead><tbody>';
                foreach($queue as $job){
                    $status = $job['status'] === 'claimed' ? 'בתהליך' : 'ממתין';
                    $time = !empty($job['claimed_at']) ? (int)$job['claimed_at'] : (int)$job['enqueued_at'];
                    $time_label = $time ? date_i18n('d/m/Y H:i', $time) : '';
                    echo '<tr>';
                    echo '<td>'.esc_html($job['id']).'</td>';
                    echo '<td>'.esc_html($job['client_name']).'</td>';
                    echo '<td><code>'.esc_html($job['site_url']).'</code></td>';
                    echo '<td>'.esc_html($job['context']).'</td>';
                    echo '<td>'.esc_html($status).'</td>';
                    echo '<td>'.esc_html($time_label).'</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            }

            $log_entries = array_reverse($this->get_activity_log());
            $log_limit = array_slice($log_entries, 0, 50);
            echo '<hr /><h2>לוג פעילות</h2>';
            if(empty($log_limit)){
                echo '<p>לא קיימות רשומות פעילות בשלב זה.</p>';
            } else {
                echo '<p>מוצגות עד 50 הרשומות האחרונות (החדשה ביותר בראש).</p>';
                echo '<table class="widefat striped"><thead><tr><th>זמן</th><th>רמה</th><th>תיאור</th><th>פרטים</th></tr></thead><tbody>';
                foreach($log_limit as $entry){
                    $time = !empty($entry['time']) ? date_i18n('d/m/Y H:i:s', (int)$entry['time']) : '';
                    $level = strtoupper(esc_html($entry['level'] ?? 'info'));
                    $message = esc_html($entry['message'] ?? '');
                    $context = '';
                    if(!empty($entry['context'])){
                        $context_json = wp_json_encode($entry['context'], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                        if($context_json){
                            $context = '<code>'.esc_html($context_json).'</code>';
                        }
                    }
                    echo '<tr>';
                    echo '<td>'.esc_html($time).'</td>';
                    echo '<td>'.esc_html($level).'</td>';
                    echo '<td>'.$message.'</td>';
                    echo '<td>'.$context.'</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            }
            echo '</div>';
        });
    }
    public function on_activate(){
        if(!get_option(self::OPTION_TOKEN)) add_option(self::OPTION_TOKEN, wp_generate_password(32,false,false));
        if(!get_page_by_path('ssl-trash')){
            wp_insert_post(['post_title'=>'סל מחזור SSL','post_name'=>'ssl-trash','post_type'=>'page','post_status'=>'publish','post_content'=>'[ssl_trash]']);
        }
        $this->ensure_sql_table();
        $this->ensure_task_queue_table();
        $this->ensure_agent_table();
        $this->maybe_seed_sql_table();
    }
    public function route_export_helper(){
        if(!empty($_GET['ssl_action']) && $_GET['ssl_action']==self::EXPORT_ACTION){
            do_action('admin_post_nopriv_'.self::EXPORT_ACTION); exit;
        }
    }
}
}

if (!isset($GLOBALS['ssl_expiry_manager_aio']) || !($GLOBALS['ssl_expiry_manager_aio'] instanceof SSL_Expiry_Manager_AIO)) {
    $GLOBALS['ssl_expiry_manager_aio'] = new SSL_Expiry_Manager_AIO();
}