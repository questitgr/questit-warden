<?php
/**
 * Questit Warden Uninstall
 * 
 * This file runs when the plugin is deleted via WordPress admin.
 * It cleans up all plugin data from the database.
 */

// Exit if not called by WordPress uninstall process
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
    exit;
}

// Remove all plugin options
$options_to_delete = array(
    'questit_warden_watchtower_url',
    'questit_warden_api_key',
    'questit_warden_send_plugin_names',
    'questit_warden_data_hash',
    'questit_warden_last_report',
    'questit_warden_last_status',
    'questit_warden_last_error',
);

foreach ( $options_to_delete as $option ) {
    delete_option( $option );
}

// Clear transients
delete_transient( 'questit_warden_latest_wp' );
delete_transient( 'questit_warden_latest_php' );

// Clear any scheduled cron hooks
wp_clear_scheduled_hook( 'questit_warden_daily_report' );
