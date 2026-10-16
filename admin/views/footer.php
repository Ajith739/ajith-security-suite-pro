<?php
/**
 * Shared global footer template for Security Suite Pro.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;
?>
<footer class="qs-global-footer" role="contentinfo">
	<div class="qs-footer-in">
		<div class="qs-footer-brand">
			<b>Gracewell Security Suite Pro</b>
			<span class="qs-footer-sep" aria-hidden="true">|</span>
			<span class="qs-footer-ver">v<?php echo esc_html( GWQSH_VERSION ); ?></span>
			<span class="qs-footer-sep" aria-hidden="true">|</span>
			<span class="qs-footer-desc">A lightweight WordPress security plugin</span>
		</div>
		<nav class="qs-footer-nav" aria-label="Plugin resources">
			<a href="https://developer.wordpress.org/advanced-administration/security/hardening/" target="_blank" rel="noopener">Documentation</a>
			<a href="https://wordpress.org/support/forums/" target="_blank" rel="noopener">Support</a>
			<a href="https://gracewell.in/" target="_blank" rel="noopener">Feedback</a>
		</nav>
	</div>
</footer>
