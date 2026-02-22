<?php
/**
 * Plugin Name: Questit Warden
 * Plugin URI: https://questit.gr
 * Description: Secure site monitoring agent - Reports WordPress, PHP & plugin update status to Questit Watchtower
 * Version: 3.5.2
 * Author: Questit
 * Author URI: https://questit.gr
 * License: GPL v2 or later
 * Text Domain: questit-warden
 * Requires at least: 5.6
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

define( 'QUESTIT_WARDEN_VERSION', '3.5.2' );
define( 'QUESTIT_WARDEN_GITHUB_USER', 'questitgr' );
define( 'QUESTIT_WARDEN_GITHUB_REPO', 'questit-warden' );
define( 'QUESTIT_WARDEN_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'QUESTIT_WARDEN_PLUGIN_FILE', __FILE__ );

class Questit_Warden {
    
    private static $instance = null;
    private $watchtower_url;
    private $api_key;
    
    // Encryption settings
    private $cipher = 'AES-256-CBC';
    
    // Cron hook name
    const CRON_HOOK = 'questit_warden_daily_report';
    
    public static function get_instance() {
        if ( self::$instance === null ) {
            self::$instance = new self();
        }
        return self::$instance;
    }
    
    private function __construct() {
        $this->watchtower_url = get_option( 'questit_warden_watchtower_url', '' );
        $this->api_key = get_option( 'questit_warden_api_key', '' );
        
        // Admin hooks only
        if ( is_admin() ) {
            add_action( 'admin_menu', array( $this, 'add_settings_page' ) );
            add_action( 'admin_init', array( $this, 'register_settings' ) );
            add_action( 'admin_post_questit_warden_send_now', array( $this, 'handle_send_now' ) );
            add_action( 'admin_notices', array( $this, 'admin_notices' ) );
            
            // GitHub auto-updater
            add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_github_update' ) );
            add_filter( 'plugins_api', array( $this, 'github_plugin_info' ), 10, 3 );
            add_filter( 'upgrader_post_install', array( $this, 'github_post_install' ), 10, 3 );
        }
        
        // Cron hook
        add_action( self::CRON_HOOK, array( $this, 'send_report' ) );
        
        // REST API endpoint for remote trigger from Watchtower
        add_action( 'rest_api_init', array( $this, 'register_rest_endpoints' ) );
        
        // Settings link
        add_filter( 'plugin_action_links_' . plugin_basename( __FILE__ ), array( $this, 'add_settings_link' ) );
    }
    
    /**
     * Plugin activation
     */
    public static function activate() {
        // Schedule daily cron if not exists
        if ( ! wp_next_scheduled( self::CRON_HOOK ) ) {
            wp_schedule_event( time() + 300, 'daily', self::CRON_HOOK );
        }
        
        // Set default privacy option
        if ( get_option( 'questit_warden_send_plugin_names' ) === false ) {
            add_option( 'questit_warden_send_plugin_names', '1', '', 'no' );
        }
    }
    
    /**
     * Plugin deactivation
     */
    public static function deactivate() {
        // Clear scheduled hook
        wp_clear_scheduled_hook( self::CRON_HOOK );
        
        // Clear transients
        delete_transient( 'questit_warden_latest_wp' );
        delete_transient( 'questit_warden_latest_php' );
    }
    
    /**
     * Add settings link to plugins page
     */
    public function add_settings_link( $links ) {
        $settings_link = '<a href="' . admin_url( 'options-general.php?page=questit-warden' ) . '">' . __( 'Ρυθμίσεις', 'questit-warden' ) . '</a>';
        array_unshift( $links, $settings_link );
        return $links;
    }
    
    /**
     * Add settings page under Settings menu
     */
    public function add_settings_page() {
        add_options_page(
            'Questit Warden',
            'Questit Warden',
            'manage_options',
            'questit-warden',
            array( $this, 'render_settings_page' )
        );
    }
    
    /**
     * Register settings
     */
    public function register_settings() {
        register_setting( 'questit_warden_settings', 'questit_warden_watchtower_url', array(
            'sanitize_callback' => array( $this, 'sanitize_watchtower_url' )
        ) );
        register_setting( 'questit_warden_settings', 'questit_warden_api_key', array(
            'sanitize_callback' => array( $this, 'sanitize_api_key' )
        ) );
        register_setting( 'questit_warden_settings', 'questit_warden_send_plugin_names', array(
            'sanitize_callback' => array( $this, 'sanitize_checkbox' )
        ) );
    }
    
    /**
     * Sanitize checkbox value
     */
    public function sanitize_checkbox( $value ) {
        return $value ? '1' : '0';
    }
    
    /**
     * Sanitize API key - keep existing if empty submitted
     */
    public function sanitize_api_key( $value ) {
        $value = sanitize_text_field( $value );
        
        // If empty, keep the existing key
        if ( empty( $value ) ) {
            return get_option( 'questit_warden_api_key', '' );
        }
        
        return $value;
    }
    
    /**
     * Sanitize and validate Watchtower URL - MUST be HTTPS
     */
    public function sanitize_watchtower_url( $url ) {
        $url = esc_url_raw( $url );
        
        if ( empty( $url ) ) {
            return '';
        }
        
        // Enforce HTTPS
        if ( strpos( $url, 'https://' ) !== 0 ) {
            add_settings_error(
                'questit_warden_watchtower_url',
                'invalid_url',
                __( 'Το Watchtower URL πρέπει να είναι HTTPS για λόγους ασφαλείας.', 'questit-warden' ),
                'error'
            );
            return get_option( 'questit_warden_watchtower_url', '' );
        }
        
        // Validate URL format
        if ( ! wp_http_validate_url( $url ) ) {
            add_settings_error(
                'questit_warden_watchtower_url',
                'invalid_url',
                __( 'Μη έγκυρο URL.', 'questit-warden' ),
                'error'
            );
            return get_option( 'questit_warden_watchtower_url', '' );
        }
        
        return $url;
    }
    
    /**
     * Handle "Send Now" button
     */
    public function handle_send_now() {
        // Verify capability
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( __( 'Δεν έχετε δικαίωμα πρόσβασης.', 'questit-warden' ) );
        }
        
        // Verify nonce (proper WP way)
        $nonce = isset( $_POST['_wpnonce'] ) ? sanitize_text_field( wp_unslash( $_POST['_wpnonce'] ) ) : '';
        if ( ! wp_verify_nonce( $nonce, 'questit_warden_send_now' ) ) {
            wp_die( __( 'Άκυρο nonce.', 'questit-warden' ) );
        }
        
        // Force send (bypass hash check)
        $result = $this->send_report( true );
        
        // Redirect back with status
        $redirect_url = add_query_arg(
            array(
                'page' => 'questit-warden',
                'sent' => $result ? '1' : '0'
            ),
            admin_url( 'options-general.php' )
        );
        
        wp_safe_redirect( $redirect_url );
        exit;
    }
    
    /**
     * Show admin notices after send
     */
    public function admin_notices() {
        $screen = get_current_screen();
        if ( ! $screen || $screen->id !== 'settings_page_questit-warden' ) {
            return;
        }
        
        if ( isset( $_GET['sent'] ) ) {
            $sent = sanitize_text_field( wp_unslash( $_GET['sent'] ) );
            if ( $sent === '1' ) {
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__( 'Η αναφορά στάλθηκε επιτυχώς!', 'questit-warden' ) . '</p></div>';
            } else {
                $last_error = get_option( 'questit_warden_last_error', '' );
                echo '<div class="notice notice-error is-dismissible"><p>' . esc_html__( 'Αποτυχία αποστολής αναφοράς.', 'questit-warden' );
                if ( $last_error ) {
                    echo ' <strong>' . esc_html( $last_error ) . '</strong>';
                }
                echo '</p></div>';
            }
        }
    }
    
    /**
     * Render settings page
     */
    public function render_settings_page() {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }
        
        $watchtower_url = get_option( 'questit_warden_watchtower_url', '' );
        $api_key = get_option( 'questit_warden_api_key', '' );
        $send_plugin_names = get_option( 'questit_warden_send_plugin_names', '1' );
        $last_report = get_option( 'questit_warden_last_report', '' );
        $last_status = get_option( 'questit_warden_last_status', '' );
        $last_error = get_option( 'questit_warden_last_error', '' );
        
        // Check requirements
        $openssl_ok = extension_loaded( 'openssl' );
        $next_scheduled = wp_next_scheduled( self::CRON_HOOK );
        
        // Generate key_id for display (first 8 chars of hashed key)
        $key_id = $api_key ? substr( hash( 'sha256', $api_key ), 0, 8 ) : '';
        ?>
        <div class="wrap">
            <h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
            
            <div style="background: #fff; padding: 20px; border: 1px solid #ccd0d4; margin-top: 20px; max-width: 700px;">
                <h2 style="margin-top: 0;">🛡️ Questit Warden <small style="color: #666; font-weight: normal;">v<?php echo esc_html( QUESTIT_WARDEN_VERSION ); ?></small></h2>
                <p style="color: #666;">
                    Στέλνει <strong>κρυπτογραφημένες</strong> αναφορές για την κατάσταση του site στο Questit Watchtower.
                </p>
                
                <?php if ( ! $openssl_ok ): ?>
                <div style="background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; padding: 10px 15px; border-radius: 4px; margin-bottom: 20px;">
                    <strong>⚠️ Προσοχή:</strong> Η επέκταση OpenSSL δεν είναι ενεργοποιημένη. Η κρυπτογράφηση δεν θα λειτουργήσει.
                </div>
                <?php endif; ?>
                
                <?php settings_errors(); ?>
                
                <form method="post" action="options.php">
                    <?php settings_fields( 'questit_warden_settings' ); ?>
                    
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row">
                                <label for="questit_warden_watchtower_url">Watchtower URL</label>
                            </th>
                            <td>
                                <input type="url" 
                                       id="questit_warden_watchtower_url" 
                                       name="questit_warden_watchtower_url" 
                                       value="<?php echo esc_attr( $watchtower_url ); ?>" 
                                       class="regular-text"
                                       placeholder="https://monitor.yourcompany.gr"
                                       pattern="https://.*"
                                       title="Πρέπει να ξεκινάει με https://">
                                <p class="description">Το URL του Questit Watchtower. <strong>Πρέπει να είναι HTTPS.</strong></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">
                                <label for="questit_warden_api_key">API Key</label>
                            </th>
                            <td>
                                <?php if ( $api_key ): ?>
                                    <div style="margin-bottom: 10px;">
                                        <code style="background: #f0f0f0; padding: 8px 12px; border-radius: 4px; display: inline-block;">
                                            ••••••••-••••-••••-••••-<?php echo esc_html( substr( $api_key, -12 ) ); ?>
                                        </code>
                                        <span style="color: green; margin-left: 10px;">✓ Configured</span>
                                        <br><small style="color: #666;">Key ID: <code><?php echo esc_html( $key_id ); ?></code></small>
                                    </div>
                                    <details style="margin-top: 10px;">
                                        <summary style="cursor: pointer; color: #0073aa;">Αλλαγή API Key</summary>
                                        <div style="margin-top: 10px;">
                                            <input type="password" 
                                                   id="questit_warden_api_key" 
                                                   name="questit_warden_api_key" 
                                                   value="" 
                                                   class="regular-text"
                                                   placeholder="Νέο API key (αφήστε κενό για να κρατήσετε το υπάρχον)">
                                            <button type="button" class="button" onclick="toggleApiKey()" style="margin-left: 5px;">👁️</button>
                                        </div>
                                    </details>
                                <?php else: ?>
                                    <input type="password" 
                                           id="questit_warden_api_key" 
                                           name="questit_warden_api_key" 
                                           value="" 
                                           class="regular-text"
                                           placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                                    <button type="button" class="button" onclick="toggleApiKey()" style="margin-left: 5px;">👁️</button>
                                    <p class="description">Το API key από το Watchtower.</p>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row">Privacy</th>
                            <td>
                                <label>
                                    <input type="checkbox" 
                                           name="questit_warden_send_plugin_names" 
                                           value="1" 
                                           <?php checked( $send_plugin_names, '1' ); ?>>
                                    Αποστολή ονομάτων plugins
                                </label>
                                <p class="description">
                                    Αν απενεργοποιηθεί, θα στέλνεται μόνο ο αριθμός των plugins που χρειάζονται update (όχι τα ονόματα).
                                </p>
                            </td>
                        </tr>
                    </table>
                    
                    <?php submit_button( 'Αποθήκευση' ); ?>
                </form>
                
                <script>
                function toggleApiKey() {
                    var input = document.getElementById('questit_warden_api_key');
                    input.type = input.type === 'password' ? 'text' : 'password';
                }
                </script>
                
                <hr style="margin: 30px 0;">
                
                <!-- Send Now Button -->
                <h3>📤 Χειροκίνητη Αποστολή</h3>
                <p style="color: #666;">Στείλε αναφορά τώρα (χωρίς να περιμένεις το cron).</p>
                
                <form method="post" action="<?php echo esc_url( admin_url( 'admin-post.php' ) ); ?>" style="margin-top: 15px;">
                    <input type="hidden" name="action" value="questit_warden_send_now">
                    <?php wp_nonce_field( 'questit_warden_send_now' ); ?>
                    <button type="submit" class="button button-primary" <?php echo ( empty( $watchtower_url ) || empty( $api_key ) ) ? 'disabled' : ''; ?>>
                        Αποστολή Τώρα
                    </button>
                    <?php if ( empty( $watchtower_url ) || empty( $api_key ) ): ?>
                        <span style="color: #999; margin-left: 10px;">Συμπληρώστε πρώτα τις ρυθμίσεις.</span>
                    <?php endif; ?>
                </form>
                
                <hr style="margin: 30px 0;">
                
                <!-- Status -->
                <h3>📊 Κατάσταση</h3>
                <table class="widefat" style="max-width: 500px;">
                    <tr>
                        <td><strong>Τελευταία αναφορά:</strong></td>
                        <td>
                            <?php if ( $last_report ): ?>
                                <?php echo esc_html( $last_report ); ?>
                                <?php if ( $last_status === 'success' ): ?>
                                    <span style="color: green;">✓</span>
                                <?php else: ?>
                                    <span style="color: red;">✗</span>
                                <?php endif; ?>
                            <?php else: ?>
                                <em>Δεν έχει σταλεί ακόμα</em>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php if ( $last_status === 'failed' && $last_error ): ?>
                    <tr>
                        <td><strong>Σφάλμα:</strong></td>
                        <td style="color: #d63638;"><?php echo esc_html( $last_error ); ?></td>
                    </tr>
                    <?php endif; ?>
                    <tr>
                        <td><strong>Επόμενη αυτόματη:</strong></td>
                        <td>
                            <?php if ( $next_scheduled ): ?>
                                <?php echo esc_html( wp_date( 'd/m/Y H:i:s', $next_scheduled ) ); ?>
                            <?php else: ?>
                                <span style="color: orange;">Δεν είναι προγραμματισμένη</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <tr>
                        <td><strong>Κρυπτογράφηση:</strong></td>
                        <td>
                            <?php if ( $openssl_ok ): ?>
                                <span style="color: green;">✓ AES-256-CBC</span>
                            <?php else: ?>
                                <span style="color: red;">✗ Μη διαθέσιμη</span>
                            <?php endif; ?>
                        </td>
                    </tr>
                </table>
                
                <hr style="margin: 30px 0;">
                
                <!-- Security Info -->
                <h3>🔒 Ασφάλεια</h3>
                <ul style="color: #666; margin-left: 20px;">
                    <li>✓ Κρυπτογράφηση AES-256-CBC</li>
                    <li>✓ HMAC-SHA256 signature (το API key δεν στέλνεται)</li>
                    <li>✓ Αποστολή μόνο μέσω HTTPS</li>
                    <li>✓ Scheduled reports (1x/day)</li>
                    <li>✓ Remote trigger με rate limiting (1x/5min)</li>
                </ul>
            </div>
        </div>
        <?php
    }
    
    /**
     * Register REST API endpoints
     */
    public function register_rest_endpoints() {
        register_rest_route( 'questit-warden/v1', '/trigger', array(
            'methods'             => 'POST',
            'callback'            => array( $this, 'handle_remote_trigger' ),
            'permission_callback' => '__return_true', // We handle auth manually
        ) );
    }
    
    /**
     * Handle remote trigger request from Watchtower
     * 
     * Security measures:
     * - Rate limiting: 1 request per 5 minutes PER IP
     * - Timestamp validation: 5 minute window (anti-replay)
     * - Watchtower URL verification
     * - HMAC-SHA256 signature verification
     */
    public function handle_remote_trigger( $request ) {
        // Get client IP for rate limiting
        $client_ip = $this->get_client_ip();
        $rate_limit_key = 'qw_trigger_' . md5( $client_ip );
        $last_trigger = get_transient( $rate_limit_key );
        
        if ( $last_trigger !== false ) {
            $wait_time = 300 - ( time() - intval( $last_trigger ) );
            if ( $wait_time > 0 ) {
                return new WP_Error( 
                    'rate_limited', 
                    sprintf( 'Παρακαλώ περιμένετε %d δευτερόλεπτα.', $wait_time ),
                    array( 'status' => 429 )
                );
            }
        }
        
        $data = $request->get_json_params();
        
        // Validate required fields
        if ( empty( $data['watchtower_url'] ) || 
             empty( $data['timestamp'] ) || 
             empty( $data['signature'] ) ) {
            return new WP_Error( 
                'missing_fields', 
                'Missing required fields', 
                array( 'status' => 400 ) 
            );
        }
        
        // Check timestamp (5 minute window to prevent replay attacks)
        $timestamp_diff = abs( time() - intval( $data['timestamp'] ) );
        if ( $timestamp_diff > 300 ) {
            return new WP_Error( 
                'invalid_timestamp', 
                'Request expired', 
                array( 'status' => 401 ) 
            );
        }
        
        // Refresh options
        $this->watchtower_url = get_option( 'questit_warden_watchtower_url', '' );
        $this->api_key = get_option( 'questit_warden_api_key', '' );
        
        // Check if configured
        if ( empty( $this->watchtower_url ) || empty( $this->api_key ) ) {
            return new WP_Error( 
                'not_configured', 
                'Warden not configured', 
                array( 'status' => 500 ) 
            );
        }
        
        // Verify the request comes from our configured Watchtower
        // Use normalized comparison to handle trailing slashes, ports, etc.
        if ( ! $this->urls_match( $this->watchtower_url, $data['watchtower_url'] ) ) {
            return new WP_Error( 
                'invalid_watchtower', 
                'Watchtower URL mismatch', 
                array( 'status' => 401 ) 
            );
        }
        
        // Verify HMAC signature
        // Format: watchtower_url|timestamp|site_url
        $site_url = rtrim( site_url(), '/' );
        $signature_data = $data['watchtower_url'] . '|' . $data['timestamp'] . '|' . $site_url;
        $expected_signature = hash_hmac( 'sha256', $signature_data, $this->api_key );
        
        if ( ! hash_equals( $expected_signature, $data['signature'] ) ) {
            return new WP_Error( 
                'invalid_signature', 
                'Signature verification failed', 
                array( 'status' => 401 ) 
            );
        }
        
        // All security checks passed - set rate limit
        set_transient( $rate_limit_key, time(), 300 );
        
        // Clear data hash to force a new report
        delete_option( 'questit_warden_data_hash' );
        
        // Send report immediately (forced)
        $result = $this->send_report( true );
        
        if ( $result === true ) {
            return rest_ensure_response( array(
                'success' => true,
                'message' => 'Report sent successfully',
                'site'    => site_url()
            ) );
        } else {
            return new WP_Error( 
                'report_failed', 
                'Failed to send report', 
                array( 'status' => 500 ) 
            );
        }
    }
    
    /**
     * Get client IP address
     */
    private function get_client_ip() {
        $ip = '';
        
        if ( ! empty( $_SERVER['HTTP_CF_CONNECTING_IP'] ) ) {
            // Cloudflare
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_CF_CONNECTING_IP'] ) );
        } elseif ( ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            // Proxy - get first IP in chain
            $ips = explode( ',', sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) );
            $ip = trim( $ips[0] );
        } elseif ( ! empty( $_SERVER['HTTP_X_REAL_IP'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['HTTP_X_REAL_IP'] ) );
        } elseif ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
            $ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
        }
        
        // Validate IP
        if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
            return $ip;
        }
        
        return 'unknown';
    }
    
    /**
     * Compare two URLs with normalization
     * Handles: trailing slashes, default ports, www vs non-www
     */
    private function urls_match( $url1, $url2 ) {
        $parsed1 = $this->normalize_url( $url1 );
        $parsed2 = $this->normalize_url( $url2 );
        
        return $parsed1 === $parsed2;
    }
    
    /**
     * Normalize URL for comparison
     */
    private function normalize_url( $url ) {
        $parsed = wp_parse_url( $url );
        
        if ( ! $parsed || empty( $parsed['host'] ) ) {
            return strtolower( rtrim( $url, '/' ) );
        }
        
        // Build normalized URL
        $scheme = isset( $parsed['scheme'] ) ? strtolower( $parsed['scheme'] ) : 'https';
        $host = strtolower( $parsed['host'] );
        
        // Remove www. prefix for comparison
        $host = preg_replace( '/^www\./i', '', $host );
        
        // Only include port if non-standard
        $port = '';
        if ( ! empty( $parsed['port'] ) ) {
            if ( ( $scheme === 'https' && $parsed['port'] != 443 ) ||
                 ( $scheme === 'http' && $parsed['port'] != 80 ) ) {
                $port = ':' . $parsed['port'];
            }
        }
        
        // Normalize path
        $path = isset( $parsed['path'] ) ? rtrim( $parsed['path'], '/' ) : '';
        
        return $scheme . '://' . $host . $port . $path;
    }
    
    /**
     * Generate key_id from API key (public identifier)
     */
    private function get_key_id() {
        return substr( hash( 'sha256', $this->api_key ), 0, 16 );
    }
    
    /**
     * Encrypt data using AES-256-CBC
     */
    private function encrypt_data( $data ) {
        if ( ! extension_loaded( 'openssl' ) ) {
            return false;
        }
        
        // Create a proper 256-bit key from API key
        $key = hash( 'sha256', $this->api_key, true );
        
        // Generate cryptographically secure random IV
        $iv_length = openssl_cipher_iv_length( $this->cipher );
        try {
            $iv = random_bytes( $iv_length );
        } catch ( Exception $e ) {
            // Fallback for older systems (though random_bytes is PHP 7+)
            $iv = openssl_random_pseudo_bytes( $iv_length );
        }
        
        // Encrypt
        $encrypted = openssl_encrypt(
            wp_json_encode( $data ),
            $this->cipher,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        if ( $encrypted === false ) {
            return false;
        }
        
        return array(
            'iv' => base64_encode( $iv ),
            'payload' => base64_encode( $encrypted )
        );
    }
    
    /**
     * Create HMAC signature (API key never leaves the client)
     */
    private function create_signature( $data ) {
        $string_to_sign = $data['site_url'] . '|' . $data['key_id'] . '|' . $data['iv'] . '|' . $data['payload'] . '|' . $data['timestamp'];
        return hash_hmac( 'sha256', $string_to_sign, $this->api_key );
    }
    
    /**
     * Get the latest WordPress version from the official API
     */
    private function get_latest_wp_version() {
        $transient_key = 'questit_warden_latest_wp';
        $cached = get_transient( $transient_key );
        
        if ( $cached !== false ) {
            return $cached;
        }
        
        $response = wp_remote_get( 'https://api.wordpress.org/core/version-check/1.7/', array(
            'timeout' => 10
        ) );
        
        if ( is_wp_error( $response ) ) {
            return null;
        }
        
        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body );
        
        if ( isset( $data->offers[0]->version ) ) {
            $latest = $data->offers[0]->version;
            set_transient( $transient_key, $latest, 12 * HOUR_IN_SECONDS );
            return $latest;
        }
        
        return null;
    }
    
    /**
     * Get the latest stable PHP version
     */
    private function get_latest_php_version() {
        $transient_key = 'questit_warden_latest_php';
        $cached = get_transient( $transient_key );
        
        if ( $cached !== false ) {
            return $cached;
        }
        
        $response = wp_remote_get( 'https://www.php.net/releases/index.php?json', array(
            'timeout' => 10
        ) );
        
        if ( is_wp_error( $response ) ) {
            return null;
        }
        
        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );
        
        if ( is_array( $data ) ) {
            $versions = array_keys( $data );
            if ( ! empty( $versions ) ) {
                rsort( $versions, SORT_NUMERIC );
                $latest = $versions[0];
                set_transient( $transient_key, $latest, 12 * HOUR_IN_SECONDS );
                return $latest;
            }
        }
        
        return null;
    }
    
    /**
     * Parse version into major.minor
     */
    private function parse_version( $version ) {
        $parts = explode( '.', $version );
        return array(
            'major' => isset( $parts[0] ) ? (int) $parts[0] : 0,
            'minor' => isset( $parts[1] ) ? (int) $parts[1] : 0,
            'patch' => isset( $parts[2] ) ? (int) $parts[2] : 0,
        );
    }
    
    /**
     * Calculate version status
     */
    private function get_version_status( $current, $latest, $type = 'wp' ) {
        if ( ! $latest || ! $current ) {
            return 'unknown';
        }
        
        if ( version_compare( $current, $latest, '>=' ) ) {
            return 'current';
        }
        
        $current_parsed = $this->parse_version( $current );
        $latest_parsed = $this->parse_version( $latest );
        
        if ( $type === 'wp' ) {
            // WordPress: more than 2 minor versions behind = critical
            $current_score = $current_parsed['major'] * 10 + $current_parsed['minor'];
            $latest_score = $latest_parsed['major'] * 10 + $latest_parsed['minor'];
            
            if ( $latest_score - $current_score >= 3 ) {
                return 'critical';
            }
            return 'outdated';
        }
        
        if ( $type === 'php' ) {
            // PHP: different major or more than 1 minor behind = critical
            if ( $current_parsed['major'] < $latest_parsed['major'] ) {
                return 'critical';
            }
            if ( $latest_parsed['minor'] - $current_parsed['minor'] >= 2 ) {
                return 'critical';
            }
            return 'outdated';
        }
        
        return 'outdated';
    }
    
    /**
     * Collect all site data
     */
    private function collect_data() {
        // Ensure get_plugins() is available
        if ( ! function_exists( 'get_plugins' ) ) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        
        // Get plugins that need updates
        $all_plugins = get_plugins();
        $plugin_details = array();
        $current = get_site_transient( 'update_plugins' );
        $send_plugin_names = get_option( 'questit_warden_send_plugin_names', '1' ) === '1';
        
        if ( isset( $current->response ) && is_array( $current->response ) ) {
            foreach ( $current->response as $plugin_file => $update ) {
                $plugin_data = isset( $all_plugins[ $plugin_file ] ) ? $all_plugins[ $plugin_file ] : array();
                
                if ( $send_plugin_names ) {
                    // Full details
                    $plugin_details[] = array(
                        'name'            => $plugin_data['Name'] ?? dirname( $plugin_file ),
                        'slug'            => dirname( $plugin_file ),
                        'current_version' => $plugin_data['Version'] ?? 'unknown',
                        'new_version'     => $update->new_version ?? 'unknown'
                    );
                } else {
                    // Privacy mode - only counts, no names
                    $plugin_details[] = array(
                        'slug'            => 'hidden',
                        'current_version' => 'hidden',
                        'new_version'     => 'available'
                    );
                }
            }
        }
        
        // Get active theme info
        $theme = wp_get_theme();
        $theme_updates = get_site_transient( 'update_themes' );
        $theme_slug = $theme->get_stylesheet();
        $theme_needs_update = false;
        $theme_new_version = '';
        
        if ( isset( $theme_updates->response[ $theme_slug ] ) ) {
            $theme_needs_update = true;
            $theme_new_version = $theme_updates->response[ $theme_slug ]['new_version'] ?? '';
        }
        
        // Current versions (proper parsing)
        $php_current = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
        $wp_current = get_bloginfo( 'version' );
        
        // Latest versions
        $wp_latest = $this->get_latest_wp_version();
        $php_latest = $this->get_latest_php_version();
        
        // Statuses
        $wp_status = $this->get_version_status( $wp_current, $wp_latest, 'wp' );
        $php_status = $this->get_version_status( $php_current, $php_latest, 'php' );
        
        $data = array(
            'site_name'          => get_bloginfo( 'name' ),
            'wp_current'         => $wp_current,
            'wp_latest'          => $wp_latest,
            'wp_status'          => $wp_status,
            'php_current'        => $php_current,
            'php_latest'         => $php_latest,
            'php_status'         => $php_status,
            'plugins_count'      => count( $plugin_details ),
            'plugins_json'       => $plugin_details,
            'theme_name'         => $theme->get( 'Name' ),
            'theme_version'      => $theme->get( 'Version' ),
            'theme_needs_update' => $theme_needs_update ? 1 : 0,
            'theme_new_version'  => $theme_new_version,
            'warden_version'     => QUESTIT_WARDEN_VERSION,
            'timezone'           => wp_timezone_string(),
            'favicon_url'        => get_site_icon_url( 64, '' )
        );
        
        // Only include plugin names if enabled
        if ( $send_plugin_names ) {
            $data['plugins_list'] = implode( ',', array_column( $plugin_details, 'name' ) );
        } else {
            $data['plugins_list'] = '';
        }
        
        return $data;
    }
    
    /**
     * Send report to Watchtower
     * 
     * @param bool $force Force send even if data hasn't changed
     * @return bool Success or failure
     */
    public function send_report( $force = false ) {
        // Refresh options (in case called from cron)
        $this->watchtower_url = get_option( 'questit_warden_watchtower_url', '' );
        $this->api_key = get_option( 'questit_warden_api_key', '' );
        
        // Check if configured
        if ( empty( $this->watchtower_url ) || empty( $this->api_key ) ) {
            $this->log_error( 'Δεν έχουν ρυθμιστεί URL ή API Key' );
            return false;
        }
        
        // Verify HTTPS
        if ( strpos( $this->watchtower_url, 'https://' ) !== 0 ) {
            $this->log_error( 'Το URL δεν είναι HTTPS' );
            return false;
        }
        
        // Collect data
        $data = $this->collect_data();
        
        // Create hash to detect changes
        $data_hash = md5( serialize( $data ) );
        $stored_hash = get_option( 'questit_warden_data_hash', '' );
        $last_report_time = get_option( 'questit_warden_last_report', '' );
        
        // Heartbeat logic:
        // - If data changed → always send
        // - If data unchanged but last report was >20h ago → send heartbeat (keeps site "Online" in Watchtower)
        // - If data unchanged and sent recently → skip (avoid redundant traffic)
        if ( ! $force && $data_hash === $stored_hash ) {
            $hours_since_last = $last_report_time
                ? ( time() - strtotime( $last_report_time ) ) / 3600
                : 25; // No previous report → send now
            
            if ( $hours_since_last < 20 ) {
                return true; // Recent heartbeat already sent, skip
            }
            // >20h passed with no change → fall through and send heartbeat
        }
        
        // Encrypt the sensitive data
        $encrypted = $this->encrypt_data( $data );
        
        if ( $encrypted === false ) {
            $this->log_error( 'Αποτυχία κρυπτογράφησης' );
            return false;
        }
        
        // Prepare the secure payload
        // NOTE: API key is NOT sent - only key_id for identification
        // The actual key is used only locally for encryption and HMAC
        // NOTE: site_url is normalized (no trailing slash) to ensure consistent HMAC signatures
        $timestamp = time();
        $secure_payload = array(
            'site_url'    => rtrim( site_url(), '/' ),
            'key_id'      => $this->get_key_id(),  // Public identifier only
            'iv'          => $encrypted['iv'],
            'payload'     => $encrypted['payload'],
            'timestamp'   => $timestamp,
        );
        
        // Add HMAC signature (proves we have the key without sending it)
        $secure_payload['signature'] = $this->create_signature( $secure_payload );
        
        // Send to Watchtower
        $endpoint = trailingslashit( $this->watchtower_url ) . 'wp-json/questit-watchtower/v1/report';
        
        $response = wp_remote_post( $endpoint, array(
            'timeout'     => 15,
            'headers'     => array(
                'Content-Type' => 'application/json'
            ),
            'body'        => wp_json_encode( $secure_payload )
        ) );
        
        // Handle response
        if ( is_wp_error( $response ) ) {
            $this->log_error( $response->get_error_message() );
            return false;
        }
        
        $response_code = wp_remote_retrieve_response_code( $response );
        
        if ( $response_code !== 200 ) {
            $body = wp_remote_retrieve_body( $response );
            $decoded = json_decode( $body, true );
            $error_msg = $decoded['message'] ?? "HTTP $response_code";
            $this->log_error( $error_msg );
            return false;
        }
        
        // Success
        update_option( 'questit_warden_data_hash', $data_hash, false );
        update_option( 'questit_warden_last_report', current_time( 'mysql' ), false );
        update_option( 'questit_warden_last_status', 'success', false );
        delete_option( 'questit_warden_last_error' );
        
        return true;
    }
    
    /**
     * Log error
     */
    private function log_error( $message ) {
        update_option( 'questit_warden_last_report', current_time( 'mysql' ), false );
        update_option( 'questit_warden_last_status', 'failed', false );
        update_option( 'questit_warden_last_error', $message, false );
    }
}

    /**
     * =========================================================================
     * GITHUB AUTO-UPDATER
     * =========================================================================
     */
    
    /**
     * Fetch latest release info from GitHub API
     * Cached for 12 hours to avoid hitting rate limits
     */
    private function get_github_release() {
        $transient_key = 'questit_warden_github_release';
        $cached = get_transient( $transient_key );
        
        if ( $cached !== false ) {
            return $cached;
        }
        
        $api_url = sprintf(
            'https://api.github.com/repos/%s/%s/releases/latest',
            QUESTIT_WARDEN_GITHUB_USER,
            QUESTIT_WARDEN_GITHUB_REPO
        );
        
        $response = wp_remote_get( $api_url, array(
            'timeout' => 10,
            'headers' => array(
                'Accept'     => 'application/vnd.github.v3+json',
                'User-Agent' => 'Questit-Warden/' . QUESTIT_WARDEN_VERSION,
            ),
        ) );
        
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            return null;
        }
        
        $release = json_decode( wp_remote_retrieve_body( $response ) );
        
        if ( empty( $release->tag_name ) ) {
            return null;
        }
        
        // Cache for 12 hours
        set_transient( $transient_key, $release, 12 * HOUR_IN_SECONDS );
        
        return $release;
    }
    
    /**
     * Inject update info into WordPress update transient
     * This makes the plugin appear in Dashboard → Updates
     */
    public function check_github_update( $transient ) {
        if ( empty( $transient->checked ) ) {
            return $transient;
        }
        
        $release = $this->get_github_release();
        
        if ( ! $release ) {
            return $transient;
        }
        
        // Strip 'v' prefix from tag (v3.5.2 → 3.5.2)
        $latest_version = ltrim( $release->tag_name, 'v' );
        
        if ( version_compare( $latest_version, QUESTIT_WARDEN_VERSION, '>' ) ) {
            $plugin_slug = plugin_basename( QUESTIT_WARDEN_PLUGIN_FILE );
            
            $transient->response[ $plugin_slug ] = (object) array(
                'slug'        => dirname( $plugin_slug ),
                'plugin'      => $plugin_slug,
                'new_version' => $latest_version,
                'url'         => sprintf(
                    'https://github.com/%s/%s',
                    QUESTIT_WARDEN_GITHUB_USER,
                    QUESTIT_WARDEN_GITHUB_REPO
                ),
                'package'     => $release->zipball_url, // GitHub auto-generated zip
            );
        }
        
        return $transient;
    }
    
    /**
     * Provide plugin info for the "View version x.x.x details" popup
     */
    public function github_plugin_info( $result, $action, $args ) {
        if ( $action !== 'plugin_information' ) {
            return $result;
        }
        
        if ( ! isset( $args->slug ) || $args->slug !== dirname( plugin_basename( QUESTIT_WARDEN_PLUGIN_FILE ) ) ) {
            return $result;
        }
        
        $release = $this->get_github_release();
        
        if ( ! $release ) {
            return $result;
        }
        
        $latest_version = ltrim( $release->tag_name, 'v' );
        
        return (object) array(
            'name'          => 'Questit Warden',
            'slug'          => dirname( plugin_basename( QUESTIT_WARDEN_PLUGIN_FILE ) ),
            'version'       => $latest_version,
            'author'        => '<a href="https://questit.gr">Questit</a>',
            'homepage'      => sprintf( 'https://github.com/%s/%s', QUESTIT_WARDEN_GITHUB_USER, QUESTIT_WARDEN_GITHUB_REPO ),
            'requires'      => '5.6',
            'tested'        => get_bloginfo( 'version' ),
            'last_updated'  => $release->published_at ?? '',
            'sections'      => array(
                'description' => 'Secure site monitoring agent - Reports WordPress, PHP & plugin update status to Questit Watchtower.',
                'changelog'   => nl2br( esc_html( $release->body ?? 'See GitHub for changelog.' ) ),
            ),
            'download_link' => $release->zipball_url,
        );
    }
    
    /**
     * After installation: rename the extracted folder to the correct plugin slug
     * GitHub zips extract with a folder like "questitgr-questit-warden-abc1234"
     * WordPress expects "questit-warden"
     */
    public function github_post_install( $response, $hook_extra, $result ) {
        global $wp_filesystem;
        
        $plugin_slug    = dirname( plugin_basename( QUESTIT_WARDEN_PLUGIN_FILE ) );
        $plugin_dir     = WP_PLUGIN_DIR . DIRECTORY_SEPARATOR . $plugin_slug;
        $install_dir    = $result['destination'];
        
        // Rename extracted folder to correct plugin folder
        if ( $install_dir !== $plugin_dir ) {
            $wp_filesystem->move( $install_dir, $plugin_dir, true );
            $result['destination'] = $plugin_dir;
        }
        
        // Re-activate plugin after update
        if ( is_plugin_active( plugin_basename( QUESTIT_WARDEN_PLUGIN_FILE ) ) ) {
            activate_plugin( plugin_basename( QUESTIT_WARDEN_PLUGIN_FILE ) );
        }
        
        // Clear GitHub release cache so next check fetches fresh data
        delete_transient( 'questit_warden_github_release' );
        
        return $result;
    }

// Initialize
Questit_Warden::get_instance();

// Activation/Deactivation hooks
register_activation_hook( __FILE__, array( 'Questit_Warden', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Questit_Warden', 'deactivate' ) );
