<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function strpos;
use const PASSWORD_BCRYPT;
use const PASSWORD_BCRYPT_DEFAULT_COST;

final class BcryptPasswordEncoder implements PasswordEncoder
{

	/** @var int<4, 31> */
	private int $cost;

	/**
	 * @param int<4, 31> $cost
	 */
	public function __construct(int $cost = PASSWORD_BCRYPT_DEFAULT_COST)
	{
		$this->cost = $cost;
	}

	public function encode(string $raw): string
	{
		return password_hash($raw, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function needsReEncode(string $encoded): bool
	{
		if (!$this->isBcryptHashed($encoded)) {
			return true;
		}

		return password_needs_rehash($encoded, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function isValid(string $raw, string $encoded): bool
	{
		if (!$this->isBcryptHashed($encoded)) {
			return false;
		}

		return password_verify($raw, $encoded);
	}

	/**
	 * @return array<mixed>
	 */
	private function getOptions(): array
	{
		/** @infection-ignore-all */
		return [
			'cost' => $this->cost,
		];
	}

	private function isBcryptHashed(string $encoded): bool
	{
		return strpos($encoded, '$2y$') === 0;
	}

}
