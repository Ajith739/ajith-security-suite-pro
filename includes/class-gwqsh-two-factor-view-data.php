<?php
/**
 * Safe, bounded Two-Factor screen snapshots. Secrets belong only to the viewer.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Safe Two-Factor administration read model. */
final class GWQSH_Two_Factor_View_Data {
	/**
	 * Build the screen and a paginated user table.
	 *
	 * @param array $filters User search, role, status and page.
	 */
	public static function get( $filters = array() ) {
		$me       = wp_get_current_user();
		$manage   = current_user_can( GWQSH_Admin::management_capability() );
		$secret   = GWQSH_Two_Factor::get_provisioning_secret( $me->ID );
		$settings = GWQSH_Two_Factor::get_settings();
		$roles    = array_map(
			static function ( $role ) {
				return translate_user_role( $role['name'] );
			},
			wp_roles()->roles
		);
		$summary  = $manage ? get_transient( 'gwqsh_tf_summary' ) : false;
		if ( ! is_array( $summary ) ) {
			$counts = array(
				'total'   => 0,
				'enabled' => 0,
				'devices' => 0,
				'last'    => '',
			);
			$states = array(
				'Enabled'  => array(),
				'Pending'  => array(),
				'Disabled' => array(),
			);
			$offset = 0;
			do {
				$batch = $manage ? get_users(
					array(
						'number'  => 500,
						'offset'  => $offset,
						'orderby' => 'ID',
						'order'   => 'ASC',
					)
				) : array( $me );
				update_meta_cache( 'user', wp_list_pluck( $batch, 'ID' ) );
				foreach ( $batch as $u ) {
					$state              = self::state( $u );
					$states[ $state ][] = $u->ID;
					++$counts['total'];
					$counts['enabled'] += 'Enabled' === $state ? 1 : 0;
					$counts['devices'] += count( GWQSH_Two_Factor::get_trusted_devices( $u->ID ) );
					$last               = get_user_meta( $u->ID, 'gwqsh_2fa_last_verified', true );
					if ( $last > $counts['last'] ) {
						$counts['last'] = $last; }
				}
				$batch_count = count( $batch );
				$offset     += 500;
			} while ( $manage && 500 === $batch_count );
			$summary = array(
				'counts' => $counts,
				'states' => $states,
			);
			// IDs and counters only; never cache secrets, tokens, or backup code values.
			if ( $manage ) {
				set_transient( 'gwqsh_tf_summary', $summary, 15 ); }
		}
		$counts = $summary['counts'];
		$args   = array(
			'number'      => 25,
			'paged'       => max( 1, absint( $filters['page'] ?? 1 ) ),
			'orderby'     => 'login',
			'order'       => 'ASC',
			'count_total' => true,
		);
		if ( ! $manage ) {
			$args['include'] = array( $me->ID ); }
		if ( ! empty( $filters['search'] ) ) {
			$args['search']         = '*' . trim( $filters['search'] ) . '*';
			$args['search_columns'] = $manage ? array( 'user_login', 'display_name', 'user_email' ) : array( 'user_login', 'display_name' );
		}
		if ( ! empty( $filters['role'] ) ) {
			$args['role'] = $filters['role']; }
		if ( ! empty( $filters['status'] ) ) {
			$ids             = $summary['states'][ $filters['status'] ] ?? array();
			$args['include'] = $manage ? ( $ids ? $ids : array( 0 ) ) : ( in_array( $me->ID, $ids, true ) ? array( $me->ID ) : array( 0 ) );
		}
		$query = new WP_User_Query( $args );
		$total = (int) $query->get_total();
		$pages = max( 1, (int) ceil( $total / 25 ) );
		$page  = min( $pages, $args['paged'] );
		if ( $page !== $args['paged'] ) {
			$args['paged'] = $page;
			$query         = new WP_User_Query( $args ); }
		$users = $query->get_results();
		update_meta_cache( 'user', wp_list_pluck( $users, 'ID' ) );
		$matches = array();
		foreach ( $users as $u ) {
			$state     = self::state( $u );
			$last      = get_user_meta( $u->ID, 'gwqsh_2fa_last_verified', true );
			$backup    = get_user_meta( $u->ID, 'gwqsh_backup_codes', true );
			$remaining = count(
				array_filter(
					is_array( $backup ) ? $backup : array(),
					static function ( $r ) {
						return is_array( $r ) && empty( $r['used'] ) && ( ! empty( $r['hash'] ) || ! empty( $r['code'] ) );
					}
				)
			);
			$matches[] = array(
				'id'                  => $u->ID,
				'u'                   => $u->user_login,
				'name'                => $u->display_name,
				'role'                => implode(
					', ',
					array_map(
						static function ( $r ) use ( $roles ) {
							return $roles[ $r ] ?? $r;
						},
						$u->roles
					)
				),
				'st'                  => $state,
				'enrolled'            => GWQSH_Two_Factor::is_user_2fa_enabled( $u->ID ),
				'required'            => (bool) GWQSH_Two_Factor::required( $u->ID ),
				'individual_required' => (bool) get_user_meta( $u->ID, 'gwqsh_2fa_required', true ),
				'm'                   => 'Enabled' === $state ? 'TOTP' : '—',
				'a'                   => $last ? GWQSH_Time::format( $last ) : '—',
				'backup_remaining'    => $remaining,
				'device_count'        => count( GWQSH_Two_Factor::get_trusted_devices( $u->ID ) ),
				'me'                  => $u->ID === $me->ID,
				'can_edit'            => $manage && current_user_can( 'edit_user', $u->ID ),
			);
		}
		$codes     = GWQSH_Two_Factor::get_user_backup_codes( $me->ID );
		$remaining = count(
			array_filter(
				$codes,
				static function ( $r ) {
					return empty( $r['used'] );
				}
			)
		);
		$percent   = $counts['total'] ? (int) round( $counts['enabled'] / $counts['total'] * 100 ) : 0;
		$protected = $counts['enabled'] && $counts['enabled'] === $counts['total'];
		return array(
			'can_manage'        => $manage,
			'settings'          => $settings,
			'recovery'          => GWQSH_Recovery::data( $me->ID ),
			'roles'             => $roles,
			'counts'            => $counts,
			'percent'           => $percent,
			'protection'        => $protected ? 'Protected' : ( $counts['enabled'] || $settings['require_admin'] || $settings['enforce_roles'] ? 'Partial' : 'Disabled' ),
			'secret'            => $secret ? $secret : '',
			'qr_uri'            => $secret ? GWQSH_Two_Factor::get_totp_uri( $me->user_login, $secret ) : '',
			'is_enabled'        => GWQSH_Two_Factor::is_user_2fa_enabled( $me->ID ),
			'effective_enabled' => GWQSH_Two_Factor::is_user_2fa_enabled( $me->ID ) && (bool) GWQSH_Two_Factor::get_user_secret( $me->ID ),
			'backup_codes'      => $codes,
			'backup_remaining'  => $remaining,
			'backup_generated'  => get_user_meta( $me->ID, 'gwqsh_backup_generated', true ) ? get_user_meta( $me->ID, 'gwqsh_backup_generated', true ) : 'Not recorded',
			'devices'           => GWQSH_Two_Factor::get_trusted_devices( $me->ID ),
			'users'             => $matches,
			'user_total'        => $total,
			'user_page'         => $page,
			'user_pages'        => $pages,
			'last_label'        => $counts['last'] ? human_time_diff( strtotime( get_gmt_from_date( $counts['last'] ) . ' UTC' ), time() ) . ' ago' : 'Never',
			'last_date'         => $counts['last'] ? GWQSH_Time::format( $counts['last'] ) : 'No verification recorded',
			'site'              => home_url( '/' ),
			'username'          => $me->user_login,
			'events'            => $manage ? GWQSH_Activity_Logger::query_logs(
				array(
					'limit' => 3,
					'days'  => 1,
				)
			)['items'] : array(),
		);
	}
	/**
	 * Resolve actual enrollment, including broken or incomplete setup.
	 *
	 * @param WP_User $user Account.
	 */
	private static function state( $user ) {
		$enrolled = GWQSH_Two_Factor::is_user_2fa_enabled( $user->ID );
		if ( $enrolled && GWQSH_Two_Factor::get_user_secret( $user->ID ) ) {
			return 'Enabled'; }
		return $enrolled || get_user_meta( $user->ID, 'gwqsh_2fa_pending_secret', true ) || get_user_meta( $user->ID, 'gwqsh_2fa_secret', true ) || GWQSH_Two_Factor::required( $user->ID ) ? 'Pending' : 'Disabled';
	}
	/** Invalidate only counters and state IDs after enrollment, roles, or users change. */
	public static function invalidate() {
		delete_transient( 'gwqsh_tf_summary' );
		delete_transient( 'gwqsh_tf_coverage' ); }
	/**
	 * Ignore unrelated metadata writes (including replay/rate limit counters).
	 *
	 * @param int    $meta_id Metadata ID.
	 * @param int    $user_id Owner.
	 * @param string $key Metadata key.
	 */
	public static function metadata_changed( $meta_id, $user_id, $key ) {
		if ( in_array( $key, array( 'gwqsh_2fa_enabled', 'gwqsh_2fa_secret', 'gwqsh_2fa_pending_secret', 'gwqsh_2fa_required', 'gwqsh_2fa_last_verified', 'gwqsh_trusted_devices' ), true ) || false !== strpos( $key, 'capabilities' ) ) {
			self::invalidate(); }
	}
}
