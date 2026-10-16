<?php
/**
 * Admin screens, asset enqueuing, and view rendering for Gracewell Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/**
 * GWQSH Admin implementation.
 */
final class GWQSH_Admin {

	private const PAGES = array(
		'dashboard'        => array( 'gracewell-security-suite-pro', 'Dashboard' ),
		'login-protection' => array( 'gracewell-security-suite-pro-login', 'Login Protection' ),
		'two-factor'       => array( 'gracewell-security-suite-pro-two-factor', 'Two-Factor' ),
		'file-integrity'   => array( 'gracewell-security-suite-pro-file-integrity', 'File Integrity' ),
		'firewall-cleanup' => array( 'gracewell-security-suite-pro-firewall-cleanup', 'Firewall & Cleanup' ),
		'hardening'        => array( 'gracewell-security-suite-pro-hardening', 'Hardening' ),
		'activity-log'     => array( 'gracewell-security-suite-pro-activity-log', 'Activity Log' ),
		'settings'         => array( 'gracewell-security-suite-pro-settings', 'Settings' ),
	);

	/**
	 * Hooks.
	 *
	 * @var array
	 */
	private static $hooks = array();

	/**
	 * Active hero background ('lighthouse' or 'classic').
	 *
	 * @var string|null
	 */
	private static $hero_bg = null;

	/** Management of shared security files requires network authority on multisite.
	 *
	 * @return string WordPress capability.
	 */
	public static function management_capability() {
		return is_multisite() ? 'manage_network_options' : 'manage_options';
	}

	/**
	 * Get or initialize random hero background.
	 *
	 * @return string
	 */
	public static function get_hero_bg() {
		if ( null === self::$hero_bg ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only whitelisted hero background selection; no persisted state or privileged action.
			if ( isset( $_GET['hero_bg'] ) && in_array( $_GET['hero_bg'], array( 'lighthouse', 'classic' ), true ) ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only whitelisted hero background selection; no persisted state or privileged action.
				self::$hero_bg = sanitize_key( $_GET['hero_bg'] );
			} else {
				self::$hero_bg = ( wp_rand( 0, 1 ) === 1 ) ? 'lighthouse' : 'classic';
			}
		}
		return self::$hero_bg;
	}

	/**
	 * Init.
	 */
	public static function init() {
		add_action( 'admin_init', array( __CLASS__, 'redirect_legacy_page' ), 1 );
		add_action( 'admin_menu', array( __CLASS__, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( __CLASS__, 'assets' ) );
		add_filter( 'admin_body_class', array( __CLASS__, 'body_class' ) );
		add_filter( 'script_loader_tag', array( __CLASS__, 'module_script' ), 10, 3 );
		add_action( 'admin_head', array( __CLASS__, 'theme_bootstrap' ), 1 );
	}
	/** Preserve bookmarks from the previous Pro development identity. */
	public static function redirect_legacy_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only bookmark redirect; registered pages enforce access capabilities.
		$legacy = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		if ( 0 !== strpos( $legacy, 'gracewell-quietshield' ) ) {
			return;
		}
		$target = 'gracewell-security-suite-pro' . substr( $legacy, strlen( 'gracewell-quietshield' ) );
		foreach ( self::PAGES as $definition ) {
			if ( $target === $definition[0] ) {
				wp_safe_redirect( add_query_arg( 'page', $target, admin_url( 'admin.php' ) ) );
				exit;
			}
		}
	}
	/**
	 * Menu.
	 */
	public static function menu() {
		self::$hooks['dashboard'] = add_menu_page(
			'Security Suite Pro Dashboard',
			'Security Suite Pro',
			self::management_capability(),
			self::PAGES['dashboard'][0],
			array( __CLASS__, 'render' ),
			'data:image/svg+xml;base64,' . base64_encode( file_get_contents( GWQSH_PATH . 'assets/img/quietshield-menu.svg' ) ),
			81
		);

		foreach ( self::PAGES as $key => $page ) {
			self::$hooks[ $key ] = add_submenu_page(
				self::PAGES['dashboard'][0],
				$page[1],
				$page[1],
				'two-factor' === $key ? 'read' : self::management_capability(),
				$page[0],
				array( __CLASS__, 'render' )
			);
		}
		if ( ! current_user_can( self::management_capability() ) ) {
			self::$hooks['two-factor'] = add_submenu_page( 'profile.php', 'Your 2FA Setup', 'Your 2FA Setup', 'read', self::PAGES['two-factor'][0], array( __CLASS__, 'render' ) );
		}
	}
	/**
	 * Current page.
	 */
	public static function current_page() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Read-only page selection; admin page registration checks its capability and AJAX mutations require a nonce.
		$page = isset( $_GET['page'] ) ? sanitize_key( wp_unslash( $_GET['page'] ) ) : '';
		foreach ( self::PAGES as $key => $definition ) {
			if ( $page === $definition[0] ) {
				return $key;
			}
		}
		return null;
	}
	/**
	 * Render.
	 */
	public static function render() {
		if ( ! current_user_can( self::management_capability() ) && ! ( 'two-factor' === self::current_page() && current_user_can( 'read' ) ) ) {
			GWQSH_UI::error( 403, 'Access restricted', 'You do not have permission to view this security page.' );
		}

		$page = self::current_page();
		if ( null === $page ) {
			return;
		}

		$current_user = wp_get_current_user();
		$user_login   = $current_user && $current_user->exists() ? $current_user->user_login : 'admin';
		$user_initial = strtoupper( substr( $user_login, 0, 1 ) );
		$user_role    = ( ! empty( $current_user->roles ) ) ? ucfirst( $current_user->roles[0] ) : 'Administrator';
		$logout_url   = wp_logout_url();

		echo '<div id="gracewell-security-suite-pro-app" data-page="' . esc_attr( $page ) . '" data-hero-bg="' . esc_attr( self::get_hero_bg() ) . '">';
		require GWQSH_PATH . 'admin/views/' . $page . '.php';
		require GWQSH_PATH . 'admin/views/upgrade-panels.php';
		require GWQSH_PATH . 'admin/views/footer.php';
		echo '</div>';
	}
	/**
	 * Body class.
	 *
	 * @param mixed $classes Classes.
	 */
	public static function body_class( $classes ) {
		return null !== self::current_page() ? $classes . ' gwqsh-admin' : $classes;
	}
	/**
	 * Theme bootstrap.
	 */
	public static function theme_bootstrap() {
		if ( null === self::current_page() ) {
			return;
		}
		$preferences = GWQSH_Settings::get_all();
		echo '<script>window.GWQSH_PREFS=' . wp_json_encode( array_intersect_key( $preferences, array_flip( array( 'theme', 'compact', 'anim', 'tips' ) ) ) ) . ';try{var gwqshTheme=localStorage.getItem("gwqsh-theme")||localStorage.getItem("qs-theme")||window.GWQSH_PREFS.theme;if(!["light","dark","system"].includes(gwqshTheme)){gwqshTheme="light";}document.documentElement.dataset.theme=gwqshTheme==="system"?(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"):gwqshTheme;var gwqshDensity=localStorage.getItem("gwqsh-density")||localStorage.getItem("qs-density")||(window.GWQSH_PREFS.compact?"compact":"comfortable");if(gwqshDensity){document.documentElement.dataset.density=gwqshDensity;}}catch(e){}</script>';
	}
	/**
	 * Assets.
	 *
	 * @param mixed $hook Hook.
	 */
	public static function assets( $hook ) {
		$page = array_search( $hook, self::$hooks, true );
		if ( false === $page ) {
			return;
		}

		// Scoped Stylesheets.
		$styles = array( 'dashboard' );
		if ( ! in_array( $page, array( 'dashboard', 'login-protection', 'two-factor', 'firewall-cleanup', 'hardening' ), true ) ) {
			$styles[] = 'page-fixes';
			$styles[] = $page;
		}
		if ( 'activity-log' === $page ) {
			$styles = array( 'dashboard' );
		}

		$dependency = array();
		foreach ( $styles as $style ) {
			$handle = 'gwqsh-' . $style . '-style';
			wp_enqueue_style( $handle, GWQSH_URL . 'assets/css/scoped/' . $style . '.css', $dependency, in_array( $style, array( 'file-integrity', 'login-protection' ), true ) ? (string) filemtime( GWQSH_PATH . 'assets/css/scoped/' . $style . '.css' ) : GWQSH_VERSION );
			$dependency = array( $handle );
		}
		wp_enqueue_style( 'gwqsh-admin-compat', GWQSH_URL . 'assets/css/admin-compat.css', $dependency, GWQSH_VERSION );

		// Vendor scripts.
		wp_enqueue_script( 'gwqsh-motion', GWQSH_URL . 'assets/js/qs-motion.js', array(), GWQSH_VERSION, true );

		if ( 'two-factor' === $page ) {
			wp_enqueue_script( 'gwqsh-qrcode', GWQSH_URL . 'assets/js/qrcode.js', array(), GWQSH_VERSION, true );
		}

		$dependencies = array( 'gwqsh-motion' );
		if ( 'two-factor' === $page ) {
			$dependencies[] = 'gwqsh-qrcode';
		}

		// Configuration & page routing dictionary.
		$page_urls = array();
		foreach ( self::PAGES as $key => $definition ) {
			$page_urls[ $key ] = admin_url( 'admin.php?page=' . $definition[0] );
		}

		$current_user = wp_get_current_user();
		$user_login   = ( $current_user && $current_user->exists() ) ? $current_user->user_login : 'admin';
		$user_role    = ( ! empty( $current_user->roles ) ) ? ucfirst( $current_user->roles[0] ) : 'Administrator';

		$config_obj = array(
			'ajax_url'      => admin_url( 'admin-ajax.php' ),
			'upgrade'       => array(
				'recovery'   => 'two-factor' === $page ? GWQSH_Recovery::data( get_current_user_id() ) : null,
				'ip_history' => 'login-protection' === $page ? GWQSH_IP_Blocks::history() : null,
				'schedule'   => 'file-integrity' === $page ? GWQSH_Scheduler::data() : null,
			),
			'asset_url'     => GWQSH_URL . 'assets/img/spot-illustrations/',
			'site_timezone' => wp_timezone_string(),
			'site_offset'   => wp_timezone()->getOffset( new DateTimeImmutable( 'now', wp_timezone() ) ),
			'nonce'         => wp_create_nonce( 'gwqsh_nonce' ),
			'pages'         => $page_urls,
			'current'       => $page,
			'home_url'      => home_url( '/' ),
			'login_base'    => GWQSH_Login_Protection::custom_login_base(),
			'login_suffix'  => get_option( 'permalink_structure' ) ? '/' : '',
			'version'       => GWQSH_VERSION,
			'notifications' => current_user_can( self::management_capability() ) ? GWQSH_Activity_Logger::query_logs(
				array(
					'limit' => 3,
					'days'  => 1,
				)
			)['items'] : array(),
			'logout_url'    => wp_logout_url(),
			'user'          => array(
				'login'   => $user_login,
				'role'    => $user_role,
				'initial' => strtoupper( substr( $user_login, 0, 1 ) ),
			),
			'hero_bg'       => self::get_hero_bg(),
		);

		// Prepare real initial dataset for current screen.
		$initial_data = self::get_page_initial_data( $page );
		if ( in_array( $page, array( 'dashboard', 'login-protection', 'two-factor', 'firewall-cleanup', 'hardening' ), true ) ) {
			wp_enqueue_style( 'gwqsh-pro-dashboard', GWQSH_URL . 'assets/css/scoped/pro-dashboard.css', array( 'gwqsh-admin-compat' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-dashboard.css' ) );
		}

		if ( 'login-protection' === $page ) {
			wp_enqueue_style( 'gwqsh-pro-login', GWQSH_URL . 'assets/css/scoped/pro-login.css', array( 'gwqsh-pro-dashboard' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-login.css' ) );
		}
		if ( 'two-factor' === $page ) {
			wp_enqueue_style( 'gwqsh-pro-two-factor', GWQSH_URL . 'assets/css/scoped/pro-two-factor.css', array( 'gwqsh-pro-dashboard' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-two-factor.css' ) );
		}
		if ( 'firewall-cleanup' === $page ) {
			wp_enqueue_style( 'gwqsh-pro-firewall-cleanup', GWQSH_URL . 'assets/css/scoped/pro-firewall-cleanup.css', array( 'gwqsh-pro-dashboard' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-firewall-cleanup.css' ) );
		}
		if ( 'hardening' === $page ) {
			wp_enqueue_style( 'gwqsh-pro-hardening', GWQSH_URL . 'assets/css/scoped/pro-hardening.css', array( 'gwqsh-pro-dashboard' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-hardening.css' ) );
		}
		if ( 'activity-log' === $page ) {
			wp_enqueue_style( 'gwqsh-pro-dashboard', GWQSH_URL . 'assets/css/scoped/pro-dashboard.css', array( 'gwqsh-admin-compat' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-dashboard.css' ) );
			wp_enqueue_style( 'gwqsh-pro-activity', GWQSH_URL . 'assets/css/scoped/pro-activity-log.css', array( 'gwqsh-pro-dashboard' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-activity-log.css' ) );
		}
		if ( 'file-integrity' === $page ) {
			wp_enqueue_style( 'gwqsh-pro-dashboard', GWQSH_URL . 'assets/css/scoped/pro-dashboard.css', array( 'gwqsh-admin-compat' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-dashboard.css' ) );
			wp_enqueue_style( 'gwqsh-pro-integrity', GWQSH_URL . 'assets/css/scoped/pro-file-integrity.css', array( 'gwqsh-pro-dashboard' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/pro-file-integrity.css' ) );
		}
		// Shared hero layout follows page styles so every screen uses the same responsive rules.
		$hero_dependencies = array_filter(
			array( 'gwqsh-admin-compat', 'gwqsh-pro-dashboard', 'gwqsh-pro-login', 'gwqsh-pro-two-factor', 'gwqsh-pro-firewall-cleanup', 'gwqsh-pro-hardening', 'gwqsh-pro-activity', 'gwqsh-pro-integrity' ),
			static function ( $handle ) {
				return wp_style_is( $handle, 'enqueued' );
			}
		);
		wp_enqueue_style( 'gwqsh-responsive-hero', GWQSH_URL . 'assets/css/scoped/responsive-hero.css', array_values( $hero_dependencies ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/responsive-hero.css' ) );
		wp_enqueue_style( 'gwqsh-shared-theme', GWQSH_URL . 'assets/css/scoped/shared-theme.css', array( 'gwqsh-responsive-hero' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/shared-theme.css' ) );
		wp_enqueue_style( 'gwqsh-ui-refinement', GWQSH_URL . 'assets/css/scoped/ui-refinement.css', array( 'gwqsh-shared-theme' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/ui-refinement.css' ) );
		wp_enqueue_style( 'gwqsh-upgrade', GWQSH_URL . 'assets/css/scoped/upgrade.css', array( 'gwqsh-ui-refinement' ), (string) filemtime( GWQSH_PATH . 'assets/css/scoped/upgrade.css' ) );
		// Enqueue Core script.
		wp_enqueue_script( 'gwqsh-core', GWQSH_URL . 'assets/js/qs-core.js', $dependencies, (string) filemtime( GWQSH_PATH . 'assets/js/qs-core.js' ), true );
		wp_add_inline_script(
			'gwqsh-core',
			'window.GWQSH_CONFIG = ' . wp_json_encode( $config_obj ) . ';' .
			'window.GWQSH_PAGES = ' . wp_json_encode( $page_urls ) . ';' .
			'window.GWQSH_DATA = ' . wp_json_encode( $initial_data ) . ';',
			'before'
		);

		// Enqueue Page specific script.
		$handle = 'gwqsh-' . $page . '-script';
		wp_enqueue_script( $handle, GWQSH_URL . 'assets/js/' . $page . '.js', array( 'gwqsh-core', 'gwqsh-enterprise' ), (string) filemtime( GWQSH_PATH . 'assets/js/' . $page . '.js' ), true );

		wp_enqueue_script( 'gwqsh-upgrade', GWQSH_URL . 'assets/js/upgrade.js', array( $handle ), (string) filemtime( GWQSH_PATH . 'assets/js/upgrade.js' ), true );
		if ( ! GWQSH_Settings::get( 'hero_animation', true ) || ! GWQSH_Settings::get( 'anim', true ) ) {
			return; }
		// Three.js Hero birds.
		wp_enqueue_script( 'gwqsh-hero-birds', GWQSH_URL . 'assets/js/hero-birds.js', array( $handle ), (string) filemtime( GWQSH_PATH . 'assets/js/hero-birds.js' ), true );
		wp_script_add_data( 'gwqsh-hero-birds', 'type', 'module' );
	}
	/**
	 * Get page initial data.
	 *
	 * @param mixed $page Page.
	 */
	public static function get_page_initial_data( $page ) {
		$data = array();

		switch ( $page ) {
			case 'dashboard':
				return GWQSH_Dashboard_Data::get();

			case 'login-protection':
				return GWQSH_Login_View_Data::get();

			case 'two-factor':
				return GWQSH_Two_Factor_View_Data::get();

			case 'firewall-cleanup':
				return GWQSH_Firewall::data();

			case 'file-integrity':
				GWQSH_Quarantine_Manager::reconcile();
				$paged = GWQSH_File_Integrity::get_scan_issues_paged( array( 'per_page' => GWQSH_Quarantine_Manager::validate_page_size( get_user_meta( get_current_user_id(), 'gwqsh_integrity_per_page', true ) ) ) );
				$data  = array(
					'summary'  => GWQSH_File_Integrity::get_summary(),
					'issues'   => $paged['items'],
					'total'    => $paged['total'],
					'page'     => $paged['page'],
					'per_page' => $paged['per_page'],
					'pages'    => $paged['pages'],
					'history'  => GWQSH_File_Integrity::get_scan_history(),
					'schedule' => GWQSH_Scheduler::data(),
				);
				break;

			case 'hardening':
				return GWQSH_Hardening_Data::get();

			case 'activity-log':
				return GWQSH_Activity_View_Data::get( array( 'overview' => 1 ) );

			case 'settings':
				$data = array(
					'settings'           => GWQSH_Settings::get_all(),
					'site_locale'        => determine_locale(),
					'site_timezone'      => wp_timezone_string(),
					'can_manage_updates' => GWQSH_Settings::can_manage_updates(),
				);
				break;
		}

		if ( in_array( $page, array( 'dashboard', 'hardening' ), true ) ) {
			$data['score_components'] = self::get_score_components();
			$data['security_score']   = self::score_from_components( $data['score_components'] );
		}
		return $data;
	}
	/**
	 * Get score components.
	 */
	public static function get_score_components() {
		$coverage = GWQSH_Two_Factor::coverage_counts();
		$scan     = GWQSH_File_Integrity::get_summary();
		$issues   = $scan['modified'] + $scan['missing'] + $scan['suspicious'];
		return array(
			'login'     => GWQSH_Settings::is_active() && GWQSH_Login_Protection::get_settings()['enabled'] ? 100 : 0,
			'tfa'       => $coverage['total'] ? (int) round( $coverage['enabled'] / $coverage['total'] * 100 ) : 0,
			'file'      => $scan['total'] ? max( 0, (int) round( ( $scan['total'] - $issues ) / $scan['total'] * 100 ) ) : 0,
			'hardening' => GWQSH_Hardening::get_risk()['score'],
			'activity'  => wp_next_scheduled( 'gwqsh_daily_log_cleanup' ) ? 100 : 0,
		);
	}
	/**
	 * Score from components.
	 *
	 * @param array $values Values.
	 */
	public static function score_from_components( array $values ) {
		return (int) round( $values['login'] * .2 + $values['tfa'] * .25 + $values['file'] * .15 + $values['hardening'] * .25 + $values['activity'] * .15 );
	}
	/**
	 * Module script.
	 *
	 * @param mixed $tag Tag.
	 * @param mixed $handle Handle.
	 * @param mixed $src Src.
	 */
	public static function module_script( $tag, $handle, $src ) {
		if ( 'gwqsh-hero-birds' !== $handle ) {
			return $tag;
		}
		// Keep WordPress's enqueued tag and its attributes, changing only the script type.
		$tag = preg_replace( '/\s+type=([\"\'])[^\"\']*\1/', '', $tag );
		return preg_replace( '/(<)(script)\b/', '$1$2 type="module"', $tag, 1 );
	}
}
