<?php
/**
 * Minimal WordPress runtime stubs for isolated unit/regression tests.
 *
 * This file is NOT loaded inside WordPress. It provides the small subset of the
 * WordPress API the tested security primitives touch, backed by in-memory state,
 * so real plugin source files can execute outside a full installation.
 *
 * @package GracewellSecuritySuitePro
 */

error_reporting( E_ALL );
ini_set( 'display_errors', '1' );

if ( ! defined( 'ABSPATH' ) ) {
	define( 'ABSPATH', __DIR__ . '/fake-wp/' );
}
if ( ! defined( 'GWQSH_PATH' ) ) {
	define( 'GWQSH_PATH', dirname( __DIR__ ) . '/' );
}
if ( ! defined( 'GWQSH_URL' ) ) {
	define( 'GWQSH_URL', 'https://example.test/wp-content/plugins/gracewell-security-suite-pro/' );
}
if ( ! defined( 'GWQSH_VERSION' ) ) {
	define( 'GWQSH_VERSION', '1.3.0-rc.5' );
}
if ( ! defined( 'GWQSH_PLUGIN_BASENAME' ) ) {
	define( 'GWQSH_PLUGIN_BASENAME', 'gracewell-security-suite-pro/gracewell-security-suite-pro.php' );
}
if ( ! defined( 'GWQSH_PLUGIN_FILE' ) ) {
	define( 'GWQSH_PLUGIN_FILE', dirname( __DIR__ ) . '/gracewell-security-suite-pro.php' );
}
if ( ! defined( 'HOUR_IN_SECONDS' ) ) {
	define( 'HOUR_IN_SECONDS', 3600 );
}
if ( ! defined( 'DAY_IN_SECONDS' ) ) {
	define( 'DAY_IN_SECONDS', 86400 );
}

/** In-memory option store. */
$GLOBALS['gw_test_options']    = array();
$GLOBALS['gw_test_site_options'] = array();
$GLOBALS['gw_test_actions']    = array();
$GLOBALS['gw_test_filters']    = array();
$GLOBALS['gw_test_current_user_can'] = array( 'manage_options' => true, 'read' => true );
$GLOBALS['gw_test_user_meta'] = array();
$GLOBALS['gw_test_time']       = null;

if ( ! class_exists( 'WP_Error' ) ) {
	/** Minimal WP_Error. */
	class WP_Error {
		/** @var string */
		private $code;
		/** @var string */
		private $message;
		/** @var mixed */
		private $data;

		/**
		 * Constructor.
		 *
		 * @param string $code Code.
		 * @param string $message Message.
		 * @param mixed  $data Data.
		 */
		public function __construct( $code = '', $message = '', $data = null ) {
			$this->code    = (string) $code;
			$this->message = (string) $message;
			$this->data    = $data;
		}

		/** Error code. */
		public function get_error_code() {
			return $this->code;
		}

		/** Error message. */
		public function get_error_message() {
			return $this->message;
		}

		/** Error data. */
		public function get_error_data() {
			return $this->data;
		}
	}
}

if ( ! function_exists( 'is_wp_error' ) ) {
	/**
	 * Is WP error.
	 *
	 * @param mixed $thing Value.
	 */
	function is_wp_error( $thing ) {
		return $thing instanceof WP_Error;
	}
}

if ( ! function_exists( 'get_option' ) ) {
	/**
	 * Get option from the in-memory store.
	 *
	 * @param string $key Key.
	 * @param mixed  $default Default.
	 */
	function get_option( $key, $default = false ) {
		return array_key_exists( $key, $GLOBALS['gw_test_options'] ) ? $GLOBALS['gw_test_options'][ $key ] : $default;
	}
}

if ( ! function_exists( 'update_option' ) ) {
	/**
	 * Update option in the in-memory store.
	 *
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 * @param mixed  $autoload Autoload flag (ignored).
	 */
	function update_option( $key, $value, $autoload = null ) {
		$GLOBALS['gw_test_options'][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'delete_option' ) ) {
	/**
	 * Delete option.
	 *
	 * @param string $key Key.
	 */
	function delete_option( $key ) {
		unset( $GLOBALS['gw_test_options'][ $key ] );
		return true;
	}
}

if ( ! function_exists( 'get_site_option' ) ) {
	/**
	 * Get network option.
	 *
	 * @param string $key Key.
	 * @param mixed  $default Default.
	 */
	function get_site_option( $key, $default = false ) {
		return array_key_exists( $key, $GLOBALS['gw_test_site_options'] ) ? $GLOBALS['gw_test_site_options'][ $key ] : $default;
	}
}

if ( ! function_exists( 'update_site_option' ) ) {
	/**
	 * Update network option.
	 *
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 */
	function update_site_option( $key, $value ) {
		$GLOBALS['gw_test_site_options'][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'wp_parse_args' ) ) {
	/**
	 * Parse args.
	 *
	 * @param array|object $args Args.
	 * @param array        $defaults Defaults.
	 */
	function wp_parse_args( $args, $defaults = array() ) {
		$args = (array) $args;
		return array_merge( $defaults, $args );
	}
}

if ( ! function_exists( 'add_action' ) ) {
	/**
	 * Register action.
	 *
	 * @param string   $hook Hook.
	 * @param callable $callback Callback.
	 * @param int      $priority Priority.
	 * @param int      $args Args.
	 */
	function add_action( $hook, $callback, $priority = 10, $args = 1 ) {
		$GLOBALS['gw_test_actions'][ $hook ][] = array( $callback, $priority, $args );
		return true;
	}
}

if ( ! function_exists( 'add_filter' ) ) {
	/**
	 * Register filter.
	 *
	 * @param string   $hook Hook.
	 * @param callable $callback Callback.
	 * @param int      $priority Priority.
	 * @param int      $args Args.
	 */
	function add_filter( $hook, $callback, $priority = 10, $args = 1 ) {
		$GLOBALS['gw_test_filters'][ $hook ][] = array( $callback, $priority, $args );
		return true;
	}
}

if ( ! function_exists( 'apply_filters' ) ) {
	/**
	 * Apply filters through registered callbacks.
	 *
	 * @param string $hook Hook.
	 * @param mixed  $value Value.
	 */
	function apply_filters( $hook, $value ) {
		$extra = array_slice( func_get_args(), 2 );
		foreach ( $GLOBALS['gw_test_filters'][ $hook ] ?? array() as $registered ) {
			$value = call_user_func_array( $registered[0], array_merge( array( $value ), $extra ) );
		}
		return $value;
	}
}

if ( ! function_exists( 'do_action' ) ) {
	/**
	 * Run action callbacks.
	 *
	 * @param string $hook Hook.
	 */
	function do_action( $hook ) {
		$extra = array_slice( func_get_args(), 1 );
		foreach ( $GLOBALS['gw_test_actions'][ $hook ] ?? array() as $registered ) {
			call_user_func_array( $registered[0], $extra );
		}
	}
}

if ( ! function_exists( 'sanitize_text_field' ) ) {
	/**
	 * Sanitize text field.
	 *
	 * @param string $value Value.
	 */
	function sanitize_text_field( $value ) {
		if ( ! is_scalar( $value ) ) {
			return '';
		}
		$value = (string) $value;
		$value = preg_replace( '/[\r\n\t ]+/', ' ', $value );
		return trim( preg_replace( '/[\x00-\x1F\x7F]/', '', strip_tags( $value ) ) );
	}
}

if ( ! function_exists( 'sanitize_key' ) ) {
	/**
	 * Sanitize key.
	 *
	 * @param string $key Key.
	 */
	function sanitize_key( $key ) {
		return preg_replace( '/[^a-z0-9_\-]/', '', strtolower( (string) $key ) );
	}
}

if ( ! function_exists( 'sanitize_file_name' ) ) {
	/**
	 * Sanitize file name.
	 *
	 * @param string $name Name.
	 */
	function sanitize_file_name( $name ) {
		return preg_replace( '/[^A-Za-z0-9._-]/', '', (string) $name );
	}
}

if ( ! function_exists( 'sanitize_email' ) ) {
	/**
	 * Sanitize email.
	 *
	 * @param string $email Email.
	 */
	function sanitize_email( $email ) {
		return filter_var( (string) $email, FILTER_SANITIZE_EMAIL );
	}
}

if ( ! function_exists( 'wp_unslash' ) ) {
	/**
	 * Unsplash values.
	 *
	 * @param mixed $value Value.
	 */
	function wp_unslash( $value ) {
		if ( is_array( $value ) ) {
			return array_map( 'wp_unslash', $value );
		}
		return is_string( $value ) ? stripslashes( $value ) : $value;
	}
}

if ( ! function_exists( 'wp_json_encode' ) ) {
	/**
	 * JSON encode.
	 *
	 * @param mixed $value Value.
	 * @param int   $flags Flags.
	 * @param int   $depth Depth.
	 */
	function wp_json_encode( $value, $flags = 0, $depth = 512 ) {
		return json_encode( $value, $flags, $depth );
	}
}

if ( ! function_exists( 'absint' ) ) {
	/**
	 * Absolute integer.
	 *
	 * @param mixed $value Value.
	 */
	function absint( $value ) {
		return abs( (int) $value );
	}
}

if ( ! function_exists( 'esc_html' ) ) {
	/**
	 * Escape HTML.
	 *
	 * @param string $text Text.
	 */
	function esc_html( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_attr' ) ) {
	/**
	 * Escape attribute.
	 *
	 * @param string $text Text.
	 */
	function esc_attr( $text ) {
		return htmlspecialchars( (string) $text, ENT_QUOTES, 'UTF-8' );
	}
}

if ( ! function_exists( 'esc_url' ) ) {
	/**
	 * Escape URL.
	 *
	 * @param string $url URL.
	 */
	function esc_url( $url ) {
		return filter_var( (string) $url, FILTER_SANITIZE_URL );
	}
}

if ( ! function_exists( 'esc_url_raw' ) ) {
	/**
	 * Escape URL raw.
	 *
	 * @param string $url URL.
	 */
	function esc_url_raw( $url ) {
		return filter_var( (string) $url, FILTER_SANITIZE_URL );
	}
}

if ( ! function_exists( '__' ) ) {
	/**
	 * Translate.
	 *
	 * @param string $text Text.
	 * @param string $domain Domain.
	 */
	function __( $text, $domain = 'default' ) {
		return $text;
	}
}

if ( ! function_exists( 'esc_html__' ) ) {
	/**
	 * Translate and escape.
	 *
	 * @param string $text Text.
	 * @param string $domain Domain.
	 */
	function esc_html__( $text, $domain = 'default' ) {
		return esc_html( $text );
	}
}

if ( ! function_exists( 'current_user_can' ) ) {
	/**
	 * Capability check backed by test state.
	 *
	 * @param string $capability Capability.
	 */
	function current_user_can( $capability ) {
		return ! empty( $GLOBALS['gw_test_current_user_can'][ $capability ] );
	}
}

if ( ! function_exists( 'is_multisite' ) ) {
	/** Multisite test flag. */
	function is_multisite() {
		return ! empty( $GLOBALS['gw_test_is_multisite'] );
	}
}

if ( ! function_exists( 'wp_timezone_string' ) ) {
	/** Test timezone. */
	function wp_timezone_string() {
		return 'UTC';
	}
}

if ( ! function_exists( 'wp_parse_url' ) ) {
	/**
	 * Parse URL.
	 *
	 * @param string $url URL.
	 * @param int    $component Component.
	 */
	function wp_parse_url( $url, $component = -1 ) {
		return -1 === $component ? parse_url( $url ) : parse_url( $url, $component );
	}
}

if ( ! function_exists( 'wp_convert_hr_to_bytes' ) ) {
	/**
	 * Convert human readable size to bytes.
	 *
	 * @param string $value Value.
	 */
	function wp_convert_hr_to_bytes( $value ) {
		$value = strtolower( trim( (string) $value ) );
		$bytes = (float) $value;
		if ( str_contains( $value, 'g' ) ) {
			$bytes *= 1024 * 1024 * 1024;
		} elseif ( str_contains( $value, 'm' ) ) {
			$bytes *= 1024 * 1024;
		} elseif ( str_contains( $value, 'k' ) ) {
			$bytes *= 1024;
		}
		return (int) $bytes;
	}
}

if ( ! function_exists( 'wp_doing_cron' ) ) {
	/** Doing cron flag. */
	function wp_doing_cron() {
		return false;
	}
}

if ( ! function_exists( 'wp_doing_ajax' ) ) {
	/** Doing ajax flag. */
	function wp_doing_ajax() {
		return false;
	}
}

if ( ! function_exists( 'is_admin' ) ) {
	/** Is admin flag. */
	function is_admin() {
		return false;
	}
}

if ( ! function_exists( 'is_user_logged_in' ) ) {
	/** Logged-in flag. */
	function is_user_logged_in() {
		return ! empty( $GLOBALS['gw_test_logged_in'] );
	}
}

if ( ! function_exists( 'get_user_meta' ) ) {
	/**
	 * Get user meta.
	 *
	 * @param int    $user_id User ID.
	 * @param string $key Key.
	 * @param bool   $single Single.
	 */
	function get_user_meta( $user_id, $key, $single = false ) {
		$value = $GLOBALS['gw_test_user_meta'][ $user_id ][ $key ] ?? '';
		return $single ? $value : (array) $value;
	}
}

if ( ! function_exists( 'update_user_meta' ) ) {
	/**
	 * Update user meta.
	 *
	 * @param int    $user_id User ID.
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 */
	function update_user_meta( $user_id, $key, $value ) {
		$GLOBALS['gw_test_user_meta'][ $user_id ][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'wp_salt' ) ) {
	/**
	 * Test salt.
	 *
	 * @param string $scheme Scheme.
	 */
	function wp_salt( $scheme = 'auth' ) {
		return 'test-salt-' . $scheme;
	}
}

if ( ! function_exists( 'get_current_user_id' ) ) {
	/** Current user. */
	function get_current_user_id() {
		return (int) ( $GLOBALS['gw_test_user_id'] ?? 0 );
	}
}

if ( ! function_exists( 'rest_url' ) ) {
	/**
	 * REST URL.
	 *
	 * @param string $path Path.
	 */
	function rest_url( $path = '' ) {
		return 'https://example.test/wp-json/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'admin_url' ) ) {
	/**
	 * Admin URL.
	 *
	 * @param string $path Path.
	 */
	function admin_url( $path = '' ) {
		return 'https://example.test/wp-admin/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'home_url' ) ) {
	/**
	 * Home URL.
	 *
	 * @param string $path Path.
	 */
	function home_url( $path = '' ) {
		return 'https://example.test/' . ltrim( (string) $path, '/' );
	}
}

if ( ! function_exists( 'status_header' ) ) {
	/**
	 * Status header stub.
	 *
	 * @param int $code Code.
	 */
	function status_header( $code ) {
		$GLOBALS['gw_test_status'] = (int) $code;
	}
}

if ( ! function_exists( 'nocache_headers' ) ) {
	/** No-cache headers stub. */
	function nocache_headers() {
		$GLOBALS['gw_test_nocache'] = true;
	}
}

if ( ! function_exists( 'current_time' ) ) {
	/**
	 * Current time.
	 *
	 * @param string $type Type.
	 * @param bool   $gmt GMT.
	 */
	function current_time( $type = 'mysql', $gmt = false ) {
		return 'timestamp' === $type || 'U' === $type ? time() : gmdate( 'Y-m-d H:i:s' );
	}
}

if ( ! function_exists( 'wp_next_scheduled' ) ) {
	/**
	 * Next scheduled stub.
	 *
	 * @param string $hook Hook.
	 * @param array  $args Args.
	 */
	function wp_next_scheduled( $hook, $args = array() ) {
		return false;
	}
}

if ( ! function_exists( 'wp_schedule_single_event' ) ) {
	/**
	 * Schedule stub.
	 *
	 * @param int    $timestamp Timestamp.
	 * @param string $hook Hook.
	 * @param array  $args Args.
	 */
	function wp_schedule_single_event( $timestamp, $hook, $args = array() ) {
		return true;
	}
}

if ( ! function_exists( '_get_cron_array' ) ) {
	/** Cron array stub. */
	function _get_cron_array() {
		return array();
	}
}

if ( ! function_exists( 'get_transient' ) ) {
	/**
	 * Get transient stub.
	 *
	 * @param string $key Key.
	 */
	function get_transient( $key ) {
		return $GLOBALS['gw_test_transients'][ $key ] ?? false;
	}
}

if ( ! function_exists( 'set_transient' ) ) {
	/**
	 * Set transient stub.
	 *
	 * @param string $key Key.
	 * @param mixed  $value Value.
	 * @param int    $ttl TTL.
	 */
	function set_transient( $key, $value, $ttl = 0 ) {
		$GLOBALS['gw_test_transients'][ $key ] = $value;
		return true;
	}
}

if ( ! function_exists( 'wp_safe_remote_get' ) ) {
	/**
	 * Remote get stub (never performs network I/O in tests).
	 *
	 * @param string $url URL.
	 * @param array  $args Args.
	 */
	function wp_safe_remote_get( $url, $args = array() ) {
		return new WP_Error( 'disabled_in_tests', 'Network access is disabled in the test harness.' );
	}
}

if ( ! function_exists( 'wp_remote_retrieve_response_code' ) ) {
	/**
	 * Response code stub.
	 *
	 * @param mixed $response Response.
	 */
	function wp_remote_retrieve_response_code( $response ) {
		return 0;
	}
}

if ( ! function_exists( 'wp_remote_retrieve_body' ) ) {
	/**
	 * Response body stub.
	 *
	 * @param mixed $response Response.
	 */
	function wp_remote_retrieve_body( $response ) {
		return '';
	}
}

if ( ! function_exists( 'wp_remote_post' ) ) {
	/**
	 * Remote post stub.
	 *
	 * @param string $url URL.
	 * @param array  $args Args.
	 */
	function wp_remote_post( $url, $args = array() ) {
		return new WP_Error( 'disabled_in_tests', 'Network access is disabled in the test harness.' );
	}
}

if ( ! function_exists( 'wp_kses_post' ) ) {
	/**
	 * KSES stub.
	 *
	 * @param string $value Value.
	 */
	function wp_kses_post( $value ) {
		return (string) $value;
	}
}

if ( ! function_exists( 'wp_strip_all_tags' ) ) {
	/**
	 * Strip tags.
	 *
	 * @param string $value Value.
	 */
	function wp_strip_all_tags( $value ) {
		return strip_tags( (string) $value );
	}
}

if ( ! function_exists( 'get_bloginfo' ) ) {
	/**
	 * Blog info stub.
	 *
	 * @param string $show Show.
	 */
	function get_bloginfo( $show = '' ) {
		return 'name' === $show ? 'Test Site' : '';
	}
}

if ( ! function_exists( 'wp_generate_password' ) ) {
	/**
	 * Password generator.
	 *
	 * @param int  $length Length.
	 * @param bool $special Special.
	 * @param bool $extra Extra.
	 */
	function wp_generate_password( $length = 12, $special = true, $extra = false ) {
		return substr( bin2hex( random_bytes( max( 8, (int) $length ) ) ), 0, (int) $length );
	}
}

if ( ! function_exists( 'wp_hash' ) ) {
	/**
	 * Hash helper.
	 *
	 * @param string $data Data.
	 * @param string $scheme Scheme.
	 */
	function wp_hash( $data, $scheme = 'auth' ) {
		return hash_hmac( 'md5', (string) $data, wp_salt( $scheme ) );
	}
}

if ( ! function_exists( 'wp_random_bytes' ) ) {
	/**
	 * Random bytes helper.
	 *
	 * @param int $length Length.
	 */
	function wp_random_bytes( $length ) {
		return random_bytes( $length );
	}
}
