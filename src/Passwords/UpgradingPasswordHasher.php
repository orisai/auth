<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use SensitiveParameter;
use function password_verify;

final class UpgradingPasswordHasher implements PasswordHasher
{

	private PasswordHasher $preferredHasher;

	/** @var array<PasswordHasher> */
	private array $outdatedHashers;

	/**
	 * @param array<PasswordHasher> $outdatedHashers
	 */
	public function __construct(PasswordHasher $preferredHasher, array $outdatedHashers = [])
	{
		$this->preferredHasher = $preferredHasher;
		$this->outdatedHashers = $outdatedHashers;
	}

	// phpcs:ignore SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature
	public function hash(
		#[SensitiveParameter]
		string $raw
	): string
	{
		return $this->preferredHasher->hash($raw);
	}

	public function needsRehash(string $hashed): bool
	{
		return $this->preferredHasher->needsRehash($hashed);
	}

	public function isValid(
		#[SensitiveParameter]
		string $raw,
		string $hashed
	): bool
	{
		if ($this->preferredHasher->isValid($raw, $hashed)) {
			return true;
		}

		if (!$this->preferredHasher->needsRehash($hashed)) {
			return false;
		}

		foreach ($this->outdatedHashers as $hasher) {
			if ($hasher->isValid($raw, $hashed)) {
				return true;
			}
		}

		return password_verify($raw, $hashed);
	}

}
