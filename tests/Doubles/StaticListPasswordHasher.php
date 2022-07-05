<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Passwords\PasswordHasher;
use function array_key_exists;
use function array_search;
use function md5;
use function str_starts_with;

final class StaticListPasswordHasher implements PasswordHasher
{

	private const Prefix = 'static_';

	/** @var array<string, string> */
	private array $list = [];

	public function hash(string $raw): string
	{
		if (!array_key_exists($raw, $this->list)) {
			$this->list[$raw] = self::createHashed($raw);
		}

		return $this->list[$raw];
	}

	public function needsRehash(string $hashed): bool
	{
		if (!str_starts_with($hashed, self::Prefix)) {
			return true;
		}

		$raw = array_search($hashed, $this->list, true);

		if ($raw === false) {
			return true;
		}

		return $this->list[$raw] !== $hashed;
	}

	public function isValid(string $raw, string $hashed): bool
	{
		return ($this->list[$raw] ?? null) === $hashed;
	}

	public static function createHashed(string $raw): string
	{
		return self::Prefix . md5($raw);
	}

}
