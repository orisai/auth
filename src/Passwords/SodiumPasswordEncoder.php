<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use Orisai\Utils\Dependencies\Dependencies;
use Orisai\Utils\Dependencies\Exception\ExtensionRequired;
use function max;
use function sodium_crypto_pwhash_str;
use function sodium_crypto_pwhash_str_needs_rehash;
use function sodium_crypto_pwhash_str_verify;
use function sprintf;
use function strpos;
use const SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE;
use const SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE;

final class SodiumPasswordEncoder implements PasswordEncoder
{

	private int $timeCost;
	private int $memoryCost;

	public function __construct(?int $timeCost = null, ?int $memoryCost = null)
	{
		if (!self::isSupported()) {
			throw ExtensionRequired::forClass(['sodium'], self::class);
		}

		$timeCost ??= max(4, SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE);
		$memoryCost ??= max(64 * 1_024 * 1_024, SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE);

		if ($timeCost < 3) {
			$message = Message::create()
				->withContext('Trying to set argon2 algorithm time cost.')
				->withProblem(sprintf('Cost %s is too low.', $timeCost))
				->withSolution('Choose cost 3 or greater.');

			throw InvalidArgument::create()
				->withMessage($message);
		}

		if ($memoryCost < ($minMemoryCost = 10 * 1_024)) {
			$message = Message::create()
				->withContext('Trying to set argon2 algorithm memory cost.')
				->withProblem(sprintf('Cost %s is too low.', $memoryCost))
				->withSolution(sprintf('Choose cost %s or greater (in bytes).', $minMemoryCost));

			throw InvalidArgument::create()
				->withMessage($message);
		}

		$this->timeCost = $timeCost;
		$this->memoryCost = $memoryCost;
	}

	public function encode(string $raw): string
	{
		return sodium_crypto_pwhash_str($raw, $this->timeCost, $this->memoryCost);
	}

	public function needsReEncode(string $encoded): bool
	{
		if (!$this->isArgonHashed($encoded)) {
			return true;
		}

		return sodium_crypto_pwhash_str_needs_rehash($encoded, $this->timeCost, $this->memoryCost);
	}

	public function isValid(string $raw, string $encoded): bool
	{
		if (!$this->isArgonHashed($encoded)) {
			return false;
		}

		return sodium_crypto_pwhash_str_verify($encoded, $raw);
	}

	public static function isSupported(): bool
	{
		return Dependencies::isExtensionLoaded('sodium');
	}

	private function isArgonHashed(string $encoded): bool
	{
		return strpos($encoded, '$argon') === 0;
	}

}
