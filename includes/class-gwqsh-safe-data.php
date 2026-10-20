<?php
/**
 * Bounded PHP-serialized primitive/array reader, without PHP deserialization.
 *
 * @package GracewellSecuritySuitePro
 */

defined( 'ABSPATH' ) || exit;

/** Reject objects, references, recursion and unsupported encodings as data. */
final class GWQSH_Safe_Data {
	/** Parse exactly one complete serialized data value.
	 *
	 * @param mixed $raw Raw bytes, not an option API result.
	 * @return mixed Primitive/array, or WP_Error on unsupported/partial input.
	 * @throws UnexpectedValueException Caught locally and converted to a safe error.
	 */
	public static function decode( $raw ) {
		if ( ! is_string( $raw ) || strlen( $raw ) > 65536 ) {
			return new WP_Error( 'data_limit', 'Stored structure exceeds the inspection limit.' );
		}
		$offset = 0;
		$nodes  = 0;
		try {
			$value = self::read( $raw, $offset, $nodes, 0 );
			if ( strlen( $raw ) !== $offset ) {
				throw new UnexpectedValueException();
			}
			return $value;
		} catch ( UnexpectedValueException $error ) {
			return new WP_Error( 'unsupported_data', 'Stored structure is malformed, partial or outside the supported data-only grammar.' );
		}
	}

	/** Read one bounded token; never invokes autoload or object lifecycle methods.
	 *
	 * @param string $raw Raw bytes.
	 * @param int    $offset Cursor.
	 * @param int    $nodes Token budget.
	 * @param int    $depth Nesting depth.
	 * @return mixed Decoded primitive/array.
	 * @throws UnexpectedValueException On unsupported input.
	 */
	private static function read( $raw, &$offset, &$nodes, $depth ) {
		if ( ++$nodes > 2048 || $depth > 12 || $offset >= strlen( $raw ) ) {
			throw new UnexpectedValueException();
		}
		$tail = substr( $raw, $offset, 64 );
		if ( 0 === strpos( $tail, 'N;' ) ) {
			$offset += 2;
			return null;
		}
		if ( preg_match( '/^b:([01]);/', $tail, $match ) ) {
			$offset += 4;
			return '1' === $match[1];
		}
		if ( preg_match( '/^i:(-?(?:0|[1-9][0-9]{0,18}));/', $tail, $match ) ) {
			$integer = filter_var( $match[1], FILTER_VALIDATE_INT );
			if ( false === $integer ) {
				throw new UnexpectedValueException();
			}
			$offset += strlen( $match[0] );
			return $integer;
		}
		if ( preg_match( '/^d:(-?[0-9]+(?:\.[0-9]+)?(?:E[+-]?[0-9]+)?);/i', $tail, $match ) && is_finite( (float) $match[1] ) ) {
			$offset += strlen( $match[0] );
			return (float) $match[1];
		}
		if ( preg_match( '/^s:([0-9]{1,5}):"/', $tail, $match ) ) {
			$length  = (int) $match[1];
			$offset += strlen( $match[0] );
			if ( $length > strlen( $raw ) - $offset || substr( $raw, $offset + $length, 2 ) !== '";' ) {
				throw new UnexpectedValueException();
			}
			$value   = substr( $raw, $offset, $length );
			$offset += $length + 2;
			return $value;
		}
		if ( preg_match( '/^a:([0-9]{1,4}):\{/', $tail, $match ) && (int) $match[1] <= 512 ) {
			$count   = (int) $match[1];
			$offset += strlen( $match[0] );
			$value   = array();
			for ( $i = 0; $i < $count; ++$i ) {
				$key = self::read( $raw, $offset, $nodes, $depth + 1 );
				if ( ( ! is_string( $key ) && ! is_int( $key ) ) || array_key_exists( $key, $value ) ) {
					throw new UnexpectedValueException();
				}
				$value[ $key ] = self::read( $raw, $offset, $nodes, $depth + 1 );
			}
			if ( substr( $raw, $offset, 1 ) !== '}' ) {
				throw new UnexpectedValueException();
			}
			++$offset;
			return $value;
		}
		throw new UnexpectedValueException();
	}
}
