<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function strpos;
use const PASSWORD_BCRYPT;

final class BcryptPasswordHasher implements PasswordHasher
{

	/** @var int<4, 31> */
	private int $cost;

	/**
	 * @param int<4, 31> $cost
	 */
	public function __construct(int $cost = 13)
	{
		$this->cost = $cost;
	}

	public function hash(string $raw): string
	{
		return password_hash($raw, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function needsRehash(string $hashed): bool
	{
		if (!$this->isBcryptHashed($hashed)) {
			return true;
		}

		return password_needs_rehash($hashed, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function isValid(string $raw, string $hashed): bool
	{
		if (!$this->isBcryptHashed($hashed)) {
			return false;
		}

		return password_verify($raw, $hashed);
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

	private function isBcryptHashed(string $hashed): bool
	{
		return strpos($hashed, '$2y$') === 0;
	}

}
