<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use function hash_equals;
use function md5;
use function strpos;

final class UnsafeMD5PasswordEncoder implements PasswordEncoder
{

	/**
	 * Same as crypt() md5 prefix
	 *
	 * @see https://www.php.net/manual/en/function.crypt.php
	 */
	private const Prefix = '$1$';

	public function encode(string $raw): string
	{
		return self::Prefix . md5($raw);
	}

	public function needsReEncode(string $encoded): bool
	{
		return !$this->isMD5Hashed($encoded);
	}

	public function isValid(string $raw, string $encoded): bool
	{
		if (!$this->isMD5Hashed($encoded)) {
			return false;
		}

		return hash_equals($encoded, $this->encode($raw));
	}

	private function isMD5Hashed(string $encoded): bool
	{
		return strpos($encoded, '$1$') === 0;
	}

}
