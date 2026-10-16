<?php
/** Owned uploads rules only; root Apache/Nginx configuration is never edited.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Recoverable, bounded direct-filesystem updates. */
final class GWQSH_Hardening_Rules {
	/** Exact existing plugin block. */
	public static function block() {
		return "# BEGIN Gracewell QuietShield\n<FilesMatch \"\\.(?i:php[0-9]?|phtml|phps|phar|inc)(?:[. ]*)$\">\nRequire all denied\n</FilesMatch>\n# END Gracewell QuietShield\n";
	}
	/** Server identification is a hint, not proof of AllowOverride.
	 *
	 * @return string Detected server family.
	 */
	public static function server() {
		$server = isset( $_SERVER['SERVER_SOFTWARE'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_SOFTWARE'] ) ) : '';
		return false !== stripos( $server, 'Apache' ) ? 'Apache' : ( false !== stripos( $server, 'nginx' ) ? 'Nginx' : 'Unknown' );
	}
	/** Validate a trusted WordPress uploads target without accepting browser paths. */
	public static function path() {
		$uploads = wp_upload_dir( null, false );
		$dir     = $uploads['basedir'];
		$file    = trailingslashit( $dir ) . '.htaccess';
		if ( ! empty( $uploads['error'] ) || ! is_dir( $dir ) || ! GWQSH_Security_Runtime::safe_path( $dir, dirname( $dir ) ) || is_link( $file ) || ( file_exists( $file ) && ( ! is_file( $file ) || ! GWQSH_Security_Runtime::safe_path( $file, $dir ) || filesize( $file ) > 1048576 ) ) ) {
			return false;
		}
		return $file;
	}
	/** Inspect only the managed block; no writes on page load. */
	public static function inspect() {
		$file = self::path();
		if ( ! $file ) {
			return array(
				'owned'   => false,
				'safe'    => false,
				'message' => 'Uploads rules cannot be safely inspected.',
			); }
		$text = file_exists( $file ) ? file_get_contents( $file ) : '';
		if ( false === $text ) {
			return array(
				'owned'   => false,
				'safe'    => false,
				'message' => 'Uploads rules are unreadable.',
			); }
		$normalized = str_replace( "\r\n", "\n", $text );
		$owned      = false !== strpos( $normalized, self::block() );
		$begins     = substr_count( $normalized, '# BEGIN Gracewell QuietShield' );
		$ends       = substr_count( $normalized, '# END Gracewell QuietShield' );
		$safe       = ( 0 === $begins && 0 === $ends ) || ( 1 === $begins && 1 === $ends && $owned );
		return array(
			'hash'    => hash( 'sha256', $text ),
			'owned'   => $owned && $safe,
			'safe'    => $safe,
			'message' => $safe ? 'Only the exact owned uploads block is managed. Other directives are preserved.' : 'Managed markers are duplicated or edited. Review the file manually.',
		);
	}
	/** Apply/remove only the exact known block, retaining all unrelated bytes.
	 *
	 * @param bool $enable Whether to install the owned block.
	 * @return bool Confirmed write result.
	 */
	public static function sync( $enable ) {
		if ( $enable && 'Apache' !== self::server() ) {
			return true; } // A saved request on other servers requires manual configuration; never write ineffective .htaccess rules.
		$file = self::path();
		if ( ! $file || ! self::inspect()['safe'] ) {
			return false; }
		$exists = file_exists( $file );
		$old    = $exists ? file_get_contents( $file ) : '';
		if ( false === $old ) {
			return false; }
		$block    = self::block();
		$crlf     = str_replace( "\n", "\r\n", $block );
		$new      = str_replace( array( $block, $crlf ), '', $old );
		$tracking = get_option( 'gwqsh_hardening_uploads_backup', array() );
		if ( $tracking && ( $tracking['path'] ?? '' ) !== $file ) {
			return false; }
		$separator = $tracking['separator'] ?? '';
		if ( $separator && isset( $tracking['hash'] ) && hash_equals( $tracking['hash'], hash( 'sha256', $old ) ) ) {
			$new = str_replace( array( $separator . $block, $separator . $crlf ), '', $old );
		}
		if ( $enable ) {
			$separator = $new && ! preg_match( '/\R$/', $new ) ? "\n" : '';
			$new      .= $separator . $block;
		}
		if ( $new === $old ) {
			return true; }
		require_once ABSPATH . 'wp-admin/includes/file.php';
		if ( 'direct' !== get_filesystem_method( array(), dirname( $file ) ) ) {
			return false; }
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-base.php';
		require_once ABSPATH . 'wp-admin/includes/class-wp-filesystem-direct.php';
		$fs   = new WP_Filesystem_Direct( null );
		$lock = dirname( $file ) . '/.quietshield-hardening.lock';
		if ( is_link( $lock ) || file_exists( $lock ) ) {
			return false; }
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$handle = fopen( $lock, 'x' );
		if ( ! $handle ) {
			return false; }
		$temp = dirname( $file ) . '/.quietshield-' . wp_generate_password( 20, false, false ) . '.tmp';
		try {
			// Backup is stored in the protected options repository, not a publicly downloadable file.
			update_option(
				'gwqsh_hardening_uploads_last_backup',
				array(
					'path'    => $file,
					'exists'  => $exists,
					'content' => $old,
					'hash'    => hash( 'sha256', $old ),
				),
				false
			);
			$backup = get_option( 'gwqsh_hardening_uploads_last_backup' );
			if ( ! $backup || hash( 'sha256', $old ) !== $backup['hash'] ) {
				return false; }
			if ( ! $fs->put_contents( $temp, $new, $exists ? ( fileperms( $file ) & 0777 ) : 0644 ) || $fs->get_contents( $temp ) !== $new ) {
				return false; }
			// Detect external edits before the atomic rename; do not overwrite a changed file.
			// phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			if ( is_link( $file ) || ( file_exists( $file ) ? file_get_contents( $file ) : '' ) !== $old || ! rename( $temp, $file ) ) {
				return false; }
			if ( $fs->get_contents( $file ) !== $new ) {
				return false; }
			if ( $enable ) {
				update_option(
					'gwqsh_hardening_uploads_backup',
					array(
						'path'      => $file,
						'separator' => $separator,
						'created'   => ! $exists,
						'hash'      => hash( 'sha256', $new ),
					),
					false
				); } else {
				if ( ! $new && ! empty( $tracking['created'] ) ) {
					if ( ! $fs->delete( $file ) ) {
						return false; }
				}
				delete_option( 'gwqsh_hardening_uploads_backup' );
				}
				return true;
		} finally {
			if ( file_exists( $temp ) ) {
				$fs->delete( $temp ); }
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			fclose( $handle );
			$fs->delete( $lock );
		}
	}
}
