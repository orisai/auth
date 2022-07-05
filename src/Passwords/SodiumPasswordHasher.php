<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use Orisai\Utils\Dependencies\Dependencies;
use Orisai\Utils\Dependencies\Exception\ExtensionRequired;
use function max;
use function sodium_crypto_pwhash_str;
use function sodium_crypto_pwhash_str_needs_rehash;
use function sodium_crypto_pwhash_str_verify;
use function strpos;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

final class SodiumPasswordHasher implements PasswordHasher
{

	/** @var int<3, max> */
	private int $timeCost;

	/** @var int<10240, max> */
	private int $memoryCost;

	/**
	 * @param int<3, max>|null $timeCost
	 * @param int<10240, max>|null $memoryCost
	 */
	public function __construct(?int $timeCost = null, ?int $memoryCost = null)
	{
		if (!self::isSupported()) {
			throw ExtensionRequired::forClass(['sodium'], self::class);
		}

		/** @infection-ignore-all */
		$this->timeCost = $timeCost
			?? max(4, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE);
		/** @infection-ignore-all */
		$this->memoryCost = $memoryCost
			?? max(64 * 1_024 * 1_024, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);
	}

	public function hash(string $raw): string
	{
		return sodium_crypto_pwhash_str($raw, $this->timeCost, $this->memoryCost);
	}

	public function needsRehash(string $hashed): bool
	{
		if (!$this->isArgonHashed($hashed)) {
			return true;
		}

		return sodium_crypto_pwhash_str_needs_rehash($hashed, $this->timeCost, $this->memoryCost);
	}

	public function isValid(string $raw, string $hashed): bool
	{
		if (!$this->isArgonHashed($hashed)) {
			return false;
		}

		return sodium_crypto_pwhash_str_verify($hashed, $raw);
	}

	public static function isSupported(): bool
	{
		return Dependencies::isExtensionLoaded('sodium');
	}

	private function isArgonHashed(string $hashed): bool
	{
		return strpos($hashed, '$argon') === 0;
	}

}
