<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use ValueError;

final class AccessEntryResult
{

	private const Allowed = 'allowed',
		Forbidden = 'forbidden',
		Skipped = 'skipped';

	private const ValuesAndNames = [
		self::Allowed => 'Allowed',
		self::Forbidden => 'Forbidden',
		self::Skipped => 'Skipped',
	];

	/** @readonly */
	public string $name;

	/** @readonly */
	public string $value;

	/** @var array<string, self> */
	private static array $instances = [];

	private function __construct(string $name, string $value)
	{
		$this->name = $name;
		$this->value = $value;
	}

	public static function allowed(): self
	{
		return self::from(self::Allowed);
	}

	public static function forbidden(): self
	{
		return self::from(self::Forbidden);
	}

	public static function skipped(): self
	{
		return self::from(self::Skipped);
	}

	public static function fromBool(bool $bool): self
	{
		return $bool ? self::allowed() : self::forbidden();
	}

	public static function tryFrom(string $value): ?self
	{
		$key = self::ValuesAndNames[$value] ?? null;

		if ($key === null) {
			return null;
		}

		return self::$instances[$key] ??= new self($key, $value);
	}

	public static function from(string $value): self
	{
		$self = self::tryFrom($value);

		if ($self === null) {
			throw new ValueError();
		}

		return $self;
	}

	/**
	 * @return array<self>
	 */
	public static function cases(): array
	{
		$cases = [];
		foreach (self::ValuesAndNames as $value => $name) {
			$cases[] = self::from($value);
		}

		return $cases;
	}

}
