<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use SensitiveParameter;
use function assert;
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

	// phpcs:ignore SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature
	public function hash(
		#[SensitiveParameter]
		string $raw
	): string
	{
		$hash = password_hash($raw, PASSWORD_BCRYPT, $this->getOptions());
		assert($hash !== false); // Since php 7.4 password_hash cannot return false
		assert($hash !== null); // All failing conditions are handled

		return $hash;
	}

	public function needsRehash(string $hashed): bool
	{
		if (!$this->isBcryptHashed($hashed)) {
			return true;
		}

		return password_needs_rehash($hashed, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function isValid(
		#[SensitiveParameter]
		string $raw,
		string $hashed
	): bool
	{
		if (!$this->isBcryptHashed($hashed)) {
			return false;
		}

		return password_verify($raw, $hashed);
	}

	/**
	 * @return array{cost: int<4, 31>}
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
