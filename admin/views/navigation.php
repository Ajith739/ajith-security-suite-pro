<?php
/**
 * Shared header navigation; retain page-specific header and hero markup.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
$gwqsh_navigation = array(
	'dashboard'        => array( '', 'Dashboard', 'grid' ),
	'login-protection' => array( '-login', 'Login Protection', 'lock' ),
	'two-factor'       => array( '-two-factor', 'Two-Factor', 'shield-check' ),
	'file-integrity'   => array( '-file-integrity', 'File Integrity', 'file' ),
	'firewall-cleanup' => array( '-firewall-cleanup', 'Firewall & Cleanup', 'shield-check' ),
	'hardening'        => array( '-hardening', 'Hardening', 'gear' ),
	'activity-log'     => array( '-activity-log', 'Activity Log', 'list' ),
);
?>
<nav class="nav" id="mainNav" aria-label="Main">
<?php foreach ( $gwqsh_navigation as $gwqsh_key => $gwqsh_link ) : ?>
<a class="nav-link<?php echo GWQSH_Admin::current_page() === $gwqsh_key ? ' active' : ''; ?>" <?php echo GWQSH_Admin::current_page() === $gwqsh_key ? 'aria-current="page"' : ''; ?> href="<?php echo esc_url( admin_url( 'admin.php?page=gracewell-security-suite-pro' . $gwqsh_link[0] ) ); ?>"><svg class="i" aria-hidden="true"><use href="#i-<?php echo esc_attr( $gwqsh_link[2] ); ?>" /></svg><span><?php echo esc_html( $gwqsh_link[1] ); ?></span></a>
<?php endforeach; ?>
</nav>
