<?php
/**
 * WAF rollout and decision policy.
 *
 * @package GracewellSecuritySuitePro
 */

gw_group( 'waf-policy' );

$policy = array( 'mode' => 'block', 'authenticated' => 'report', 'enforce_new' => false, 'enforce_sql_extended' => false );

gw_same( 'Legacy rule blocks in block mode', 'SQL Injection', GWQSH_Firewall::decision( 'SQL Injection', '', '', $policy, 'block', false )['rule'] );
$reported = GWQSH_Firewall::decision( 'SQL Injection', '', '', array_merge( $policy, array( 'mode' => 'report' ) ), 'report', false );
gw_same( 'Report mode records the match instead of blocking', true, $reported['report'] );
gw_same( 'Report mode keeps the matched rule identifier', 'SQL Injection', $reported['rule'] );

$new_rule = GWQSH_Firewall::decision( '', 'GWQSH-1001', '', $policy, 'block', false );
gw_same( 'New rule is report-only until enforce_new', true, $new_rule['report'] );
gw_same( 'New rule still reported as the matched rule', 'GWQSH-1001', $new_rule['rule'] );

$enforced = GWQSH_Firewall::decision( '', 'GWQSH-1007', '', array_merge( $policy, array( 'enforce_new' => true ) ), 'block', false );
gw_same( 'New rule blocks after enforce_new approval', false, $enforced['report'] );

$sql_new = GWQSH_Firewall::decision( '', 'GWQSH-1006', '', array_merge( $policy, array( 'enforce_new' => true ) ), 'block', false );
gw_same( 'Extended SQL correlation needs its own approval', true, $sql_new['report'] );

$sql_ok = GWQSH_Firewall::decision( '', 'GWQSH-1006', '', array_merge( $policy, array( 'enforce_new' => true, 'enforce_sql_extended' => true ) ), 'block', false );
gw_same( 'Extended SQL correlation blocks with both approvals', false, $sql_ok['report'] );

$patch = GWQSH_Firewall::decision( '', '', 'ADV-1', $policy, 'block', true );
gw_same( 'Virtual patch blocks only when approved', 'ADV-1', $patch['rule'] );
gw_same( 'Virtual patch is report-only without approval', true, GWQSH_Firewall::decision( '', '', 'ADV-1', $policy, 'block', false )['report'] );

gw_same( 'Report-only rule cannot shadow a legacy block', 'SQL Injection', GWQSH_Firewall::decision( 'SQL Injection', 'GWQSH-1001', '', array_merge( $policy, array( 'mode' => 'report' ) ), 'block', false )['rule'] );

gw_same( 'Authenticated traffic defaults to report', 'report', GWQSH_Firewall::rollout( true, array( 'mode' => 'block', 'authenticated' => 'report' ) ) );
gw_same( 'Guest traffic uses the global mode', 'block', GWQSH_Firewall::rollout( false, array( 'mode' => 'block', 'authenticated' => 'report' ) ) );
gw_same( 'Authenticated enforcement is possible when configured', 'block', GWQSH_Firewall::rollout( true, array( 'mode' => 'block', 'authenticated' => 'block' ) ) );

gw_same( 'Strictest inspection state wins', 'inspection_budget_exceeded', GWQSH_Firewall::inspection_state( 'fully_inspected', 'inspection_budget_exceeded', 'parsing_error' ) );
gw_same( 'Parsing error beats partial inspection', 'parsing_error', GWQSH_Firewall::inspection_state( 'partially_inspected', 'parsing_error' ) );
gw_same( 'Clean state reported as fully inspected', 'fully_inspected', GWQSH_Firewall::inspection_state( 'fully_inspected' ) );

gw_same( 'Oversized REST JSON is not parsed as an attack verdict', 'inspection_budget_exceeded', GWQSH_Firewall::native_json( str_repeat( 'a', 100 ), 10 )['state'] );
gw_same( 'Malformed JSON is a parsing error', 'parsing_error', GWQSH_Firewall::native_json( '{"a":', 100 )['state'] );
gw_same( 'JSON scalar is an unsupported format', 'unsupported_request_format', GWQSH_Firewall::native_json( '"just a string"', 100 )['state'] );
gw_same( 'Valid JSON object is inspected', 'fully_inspected', GWQSH_Firewall::native_json( '{"a":"b"}', 100 )['state'] );

gw_same( 'WooCommerce REST bodies get a larger budget', 524288, GWQSH_Firewall::endpoint_body_limit( '/wp-json/wc/store/v1/checkout', false ) );
gw_same( 'Anonymous REST bodies stay small', 16384, GWQSH_Firewall::endpoint_body_limit( '/wp-json/wp/v2/posts', false ) );
gw_same( 'Authenticated editor bodies are larger', 1048576, GWQSH_Firewall::endpoint_body_limit( '/wp-json/wp/v2/posts', true ) );

gw_group( 'waf-evidence' );

$deep = array();
$cursor = &$deep;
for ( $i = 0; $i < 12; $i++ ) {
	$cursor['n'] = array();
	$cursor = &$cursor['n'];
}
$cursor['x'] = "' OR 1=1--";
unset( $cursor );
$evidence = GWQSH_Firewall::evidence( $deep );
gw_same( 'Deeply nested input is bounded and reported', true, in_array( 'request_depth', $evidence['limits'], true ) );

$wide = array();
for ( $i = 0; $i < 200; $i++ ) {
	$wide[ 'k' . $i ] = str_repeat( 'a', 100 );
}
$evidence = GWQSH_Firewall::evidence( $wide );
gw_same( 'Wide input is bounded and reported', true, ! empty( $evidence['limits'] ) );
gw_same( 'Inspection status reflects the budget', 'budget_exceeded', $evidence['status'] );

$cred = GWQSH_Firewall::evidence( array( 'password' => "' OR 1=1--", 'user_login' => 'admin' ) );
gw_same( 'Credential keys are not ordinary evidence', 0, count( $cred['values'] ) );
gw_same( 'Credential keys are still collected for injection screening', 2, count( $cred['credential_values'] ) );
