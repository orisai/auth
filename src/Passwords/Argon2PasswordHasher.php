<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use Orisai\Utils\Dependencies\Dependencies;
use Orisai\Utils\Dependencies\Exception\ExtensionRequired;
use SensitiveParameter;
use function assert;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function strpos;
use const PASSWORD_ARGON2ID;

final class Argon2PasswordHasher implements PasswordHasher
{

	/** @var int<1, max> */
	private int $timeCost;

	/** @var int<8, max> */
	private int $memoryCost;

	/** @var int<1, max> */
	private int $threads;

	/**
	 * @param int<1, max>|null $timeCost
	 * @param int<8, max>|null $memoryCost
	 * @param int<1, max>|null $threads
	 */
	public function __construct(?int $timeCost = null, ?int $memoryCost = null, ?int $threads = null)
	{
		if (!self::isSupported()) {
			throw ExtensionRequired::forClass(['sodium'], self::class);
		}

		/** @infection-ignore-all */
		$this->timeCost = $timeCost ?? 16;
		/** @infection-ignore-all */
		$this->memoryCost = $memoryCost ?? 65_536;
		/** @infection-ignore-all */
		$this->threads = $threads ?? 4;
	}

	// phpcs:ignore SlevomatCodingStandard.Classes.RequireSingleLineMethodSignature
	public function hash(
		#[SensitiveParameter]
		string $raw
	): string
	{
		$hash = password_hash($raw, PASSWORD_ARGON2ID, $this->getOptions());
		assert($hash !== false); // Since php 7.4 password_hash cannot return false
		assert($hash !== null); // All failing conditions are handled

		return $hash;
	}

	public function needsRehash(string $hashed): bool
	{
		if (!$this->isArgonHashed($hashed)) {
			return true;
		}

		return password_needs_rehash($hashed, PASSWORD_ARGON2ID, $this->getOptions());
	}

	public function isValid(
		#[SensitiveParameter]
		string $raw,
		string $hashed
	): bool
	{
		if (!$this->isArgonHashed($hashed)) {
			return false;
		}

		return password_verify($raw, $hashed);
	}

	public static function isSupported(): bool
	{
		return Dependencies::isExtensionLoaded('sodium');
	}

	private function isArgonHashed(string $hashed): bool
	{
		return strpos($hashed, '$argon') === 0;
	}

	/**
	 * @return array{time_cost: int<1, max>, memory_cost: int<8, max>, threads: int<1, max>}
	 */
	private function getOptions(): array
	{
		/** @infection-ignore-all */
		return [
			'time_cost' => $this->timeCost,
			'memory_cost' => $this->memoryCost,
			'threads' => $this->threads,
		];
	}

}
