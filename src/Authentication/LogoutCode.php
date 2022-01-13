<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use ValueError;
use function array_key_exists;

final class LogoutCode
{

	private const MANUAL = 1,
		INACTIVITY = 2,
		INVALID_IDENTITY = 3;

	private const VALUES_AND_NAMES = [
		self::MANUAL => 'manual',
		self::INACTIVITY => 'inactivity',
		self::INVALID_IDENTITY => 'invalidIdentity',
	];

	/** @readonly */
	public string $name;

	/** @readonly */
	public int $value;

	private function __construct(string $name, int $value)
	{
		$this->name = $name;
		$this->value = $value;
	}

	public static function manual(): self
	{
		return self::from(self::MANUAL);
	}

	public static function inactivity(): self
	{
		return self::from(self::INACTIVITY);
	}

	public static function invalidIdentity(): self
	{
		return self::from(self::INVALID_IDENTITY);
	}

	public static function tryFrom(int $value): ?self
	{
		if (!array_key_exists($value, self::VALUES_AND_NAMES)) {
			return null;
		}

		return new self(self::VALUES_AND_NAMES[$value], $value);
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
		foreach (self::VALUES_AND_NAMES as $value => $name) {
			$cases[] = self::from($value);
		}

		return $cases;
	}

}
