<?php
/**
 * Gracewell Early Guardian entry point. Embedded after its reviewed runtime.
 * Alphabetical order helps; filesystem attackers can sort before this module.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

( static function () {
	try {
		$root  = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : ( defined( 'WP_CONTENT_DIR' ) ? WP_CONTENT_DIR . '/mu-plugins' : '' );
		$state = GWQSH_GUARDIAN_STATE;
		if ( ! is_dir( $root ) || is_link( $root ) || ! GWQSH_Security_Runtime::safe_path( $state . '/index.php', $state ) ) {
			return;
		}
		$lock = $state . '/guardian.lock';
		if ( is_link( $lock ) ) {
			return;
		}
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fopen -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
		$fp = @fopen( $lock, 'c' );
		if ( ! $fp || ! flock( $fp, LOCK_EX | LOCK_NB ) ) {
			if ( $fp ) {
				// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
				fclose( $fp );
			}
			return;
		}
		try {
			$count   = 0;
			$entries = 0;
			$start   = microtime( true );
			foreach ( new DirectoryIterator( $root ) as $item ) {
				if ( ++$entries > 1024 || microtime( true ) - $start > 0.1 ) {
					GWQSH_Security_Runtime::atomic_write( $state . '/guardian-health.json', '{"decision":"coverage_limited"}' );
					break;
				}
				if ( $item->isDot() || $item->isLink() || ! $item->isFile() || 'php' !== $item->getExtension() || $item->getPathname() === __FILE__ ) {
					continue;
				}
				// Explicit degraded coverage; never perform a site-wide early scan.
				if ( ++$count > 128 || microtime( true ) - $start > 0.1 ) {
					GWQSH_Security_Runtime::atomic_write( $state . '/guardian-health.json', '{"decision":"coverage_limited"}' );
					break;
				}
				$file = GWQSH_Security_Runtime::safe_path( $item->getPathname(), $root );
				if ( ! $file || ! is_readable( $file ) || $item->getSize() > GWQSH_Security_Runtime::LIMIT ) {
					GWQSH_Security_Runtime::atomic_write( $state . '/guardian-health.json', '{"decision":"uninspected_file"}' );
					continue;
				}
				$content = @file_get_contents( $file, false, null, 0, GWQSH_Security_Runtime::LIMIT + 1 );
				if ( false === $content || strlen( $content ) > GWQSH_Security_Runtime::LIMIT ) {
					continue;
				}
				$result = GWQSH_Security_Runtime::analyze( $content );
				if ( ! empty( $result['partial'] ) ) {
					GWQSH_Security_Runtime::atomic_write( $state . '/guardian-health.json', '{"decision":"token_budget_limit"}' );
				}
				if ( $result['auto_block'] && $result['score'] >= 95 ) {
					// Detection is independent of cleanup authorization. Early boot has no
					// authenticated administrator to confirm a file replacement.
					GWQSH_Security_Runtime::atomic_write(
						$state . '/guardian-health.json',
						json_encode(
							array(
								'decision' => 'review_required',
								'original' => $item->getFilename(),
								'hash'     => hash( 'sha256', $content ),
								'rules'    => $result['rules'],
								'time'     => time(),
							)
						)
					);
				}
			}
		} finally {
			flock( $fp, LOCK_UN );
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Validated local security file operation; atomic writes, locks and verified failure handling require direct filesystem access.
			fclose( $fp );
		}
	} catch ( Throwable $error ) {
		// No exception messages: they could contain sensitive paths or file contents.
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Fixed production diagnostic for a security inspection failure; no sensitive data.
		error_log( 'Gracewell Early Guardian: local inspection unavailable.' );
	}
} )();
