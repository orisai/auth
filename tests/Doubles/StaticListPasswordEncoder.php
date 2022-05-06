<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Passwords\PasswordEncoder;
use function array_key_exists;
use function array_search;
use function md5;
use function str_starts_with;

final class StaticListPasswordEncoder implements PasswordEncoder
{

	private const Prefix = 'static_';

	/** @var array<string, string> */
	private array $list = [];

	public function encode(string $raw): string
	{
		if (!array_key_exists($raw, $this->list)) {
			$this->list[$raw] = self::createEncoded($raw);
		}

		return $this->list[$raw];
	}

	public function needsReEncode(string $encoded): bool
	{
		if (!str_starts_with($encoded, self::Prefix)) {
			return true;
		}

		$raw = array_search($encoded, $this->list, true);

		if ($raw === false) {
			return true;
		}

		return $this->list[$raw] !== $encoded;
	}

	public function isValid(string $raw, string $encoded): bool
	{
		return ($this->list[$raw] ?? null) === $encoded;
	}

	public static function createEncoded(string $raw): string
	{
		return self::Prefix . md5($raw);
	}

}
