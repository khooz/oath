<?php

/**
 * interface.BaseConverterInterface
 * Provides an interface for base conversion classes
 *
 * @author Mustafa Talaeezadeh Khouzani <brother.t@live.com>
 * @version 5.8
 * @copyright MIT
 *
 */

namespace Khooz\Oath;


interface BaseConverterInterface
{
	/**
	 * fromString
	 *
	 * Convert any string to a base32 string
	 * This should be binary safe...
	 *
	 * @param string $str The string to convert
	 *
	 * @return string The converted base32 string
	 */
	public static function fromString (string $str) : string;

	/**
	 * toString
	 *
	 * Convert any base32 string to a normal sctring
	 * This should be binary safe...
	 *
	 * @param string $str The base32 string to convert
	 *
	 * @return string The normal string
	 */
	public static function toString (string $str) : string;
}