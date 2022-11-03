<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use ValueError;

final class LogoutCode
{

	private const Manual = 1,
		Inactivity = 2,
		InvalidIdentity = 3;

	private const ValuesAndNames = [
		self::Manual => 'Manual',
		self::Inactivity => 'Inactivity',
		self::InvalidIdentity => 'InvalidIdentity',
	];

	/** @readonly */
	public string $name;

	/** @readonly */
	public int $value;

	/** @var array<string, self> */
	private static array $instances = [];

	private function __construct(string $name, int $value)
	{
		$this->name = $name;
		$this->value = $value;
	}

	public static function manual(): self
	{
		return self::from(self::Manual);
	}

	public static function inactivity(): self
	{
		return self::from(self::Inactivity);
	}

	public static function invalidIdentity(): self
	{
		return self::from(self::InvalidIdentity);
	}

	public static function tryFrom(int $value): ?self
	{
		$key = self::ValuesAndNames[$value] ?? null;

		if ($key === null) {
			return null;
		}

		return self::$instances[$key] ??= new self($key, $value);
	}

	public static function from(int $value): self
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
