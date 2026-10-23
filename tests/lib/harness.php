<?php
/**
 * Tiny assertion harness (no Composer/PHPUnit dependency).
 *
 * @package GracewellSecuritySuitePro
 */

/** @var array<int, array<string, mixed>> Collected results. */
$GLOBALS['gw_results'] = array();
/** @var string */
$GLOBALS['gw_current_group'] = 'general';

/**
 * Start a named test group.
 *
 * @param string $group Group name.
 */
function gw_group( $group ) {
	$GLOBALS['gw_current_group'] = (string) $group;
}

/**
 * Record a result.
 *
 * @param string $name Test name.
 * @param bool   $passed Passed.
 * @param string $detail Detail/evidence.
 */
function gw_record( $name, $passed, $detail = '' ) {
	$GLOBALS['gw_results'][] = array(
		'group'   => $GLOBALS['gw_current_group'],
		'test'    => $name,
		'passed'  => (bool) $passed,
		'detail'  => $detail,
	);
}

/**
 * Assert a condition.
 *
 * @param string $name Test name.
 * @param bool   $condition Condition.
 * @param string $detail Detail.
 */
function gw_assert( $name, $condition, $detail = '' ) {
	gw_record( $name, (bool) $condition, $detail );
	return (bool) $condition;
}

/**
 * Assert strict equality.
 *
 * @param string $name Test name.
 * @param mixed  $expected Expected.
 * @param mixed  $actual Actual.
 */
function gw_same( $name, $expected, $actual ) {
	$ok = $expected === $actual;
	gw_record(
		$name,
		$ok,
		$ok ? 'matched' : 'expected ' . var_export( $expected, true ) . ' got ' . var_export( $actual, true )
	);
	return $ok;
}

/**
 * Mark a test as skipped with a reason (never counted as a pass).
 *
 * @param string $name Test name.
 * @param string $reason Reason.
 */
function gw_skip( $name, $reason ) {
	$GLOBALS['gw_results'][] = array(
		'group'   => $GLOBALS['gw_current_group'],
		'test'    => $name,
		'passed'  => null,
		'skipped' => true,
		'detail'  => (string) $reason,
	);
}

/**
 * Assert every item in a name=>value map satisfies the expected callable result.
 *
 * @param string   $name Test name.
 * @param array    $samples name => payload.
 * @param callable $predicate Receives payload, returns true when detected.
 */
function gw_expect_all( $name, array $samples, callable $predicate ) {
	$failures = array();
	foreach ( $samples as $label => $payload ) {
		if ( ! $predicate( $payload ) ) {
			$failures[] = $label;
		}
	}
	gw_record(
		$name,
		empty( $failures ),
		empty( $failures ) ? count( $samples ) . ' samples matched' : 'missed: ' . implode( ', ', $failures )
	);
}

/**
 * Assert no item in a list is flagged.
 *
 * @param string   $name Test name.
 * @param array    $samples name => payload.
 * @param callable $predicate Receives payload, returns 'truthy' when flagged.
 */
function gw_expect_none( $name, array $samples, callable $predicate ) {
	$false_positives = array();
	foreach ( $samples as $label => $payload ) {
		if ( $predicate( $payload ) ) {
			$false_positives[] = $label;
		}
	}
	gw_record(
		$name,
		empty( $false_positives ),
		empty( $false_positives ) ? count( $samples ) . ' benign samples allowed' : 'flagged: ' . implode( ', ', $false_positives )
	);
}
