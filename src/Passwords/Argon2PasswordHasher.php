<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use Orisai\Utils\Dependencies\Dependencies;
use Orisai\Utils\Dependencies\Exception\ExtensionRequired;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function strpos;
use const PASSWORD_ARGON2ID;

final class Argon2PasswordHasher implements PasswordHasher
{

	private int $timeCost;

	private int $memoryCost;

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
		$this->memoryCost = $memoryCost ?? 15_000;
		/** @infection-ignore-all */
		$this->threads = $threads ?? 2;
	}

	public function hash(string $raw): string
	{
		return password_hash($raw, PASSWORD_ARGON2ID, $this->getOptions());
	}

	public function needsRehash(string $hashed): bool
	{
		if (!$this->isArgonHashed($hashed)) {
			return true;
		}

		return password_needs_rehash($hashed, PASSWORD_ARGON2ID, $this->getOptions());
	}

	public function isValid(string $raw, string $hashed): bool
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
	 * @return array<string, mixed>
	 */
	private function getOptions(): array
	{
		/** @infection-ignore-all */
		return [
			'memory_cost' => $this->memoryCost,
			'time_cost' => $this->timeCost,
			'threads' => $this->threads,
		];
	}

}
