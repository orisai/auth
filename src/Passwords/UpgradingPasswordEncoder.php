<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use function password_verify;

final class UpgradingPasswordEncoder implements PasswordEncoder
{

	private PasswordEncoder $preferredEncoder;

	/** @var array<PasswordEncoder> */
	private array $outdatedEncoders;

	/**
	 * @param array<PasswordEncoder> $outdatedEncoders
	 */
	public function __construct(PasswordEncoder $preferredEncoder, array $outdatedEncoders = [])
	{
		$this->preferredEncoder = $preferredEncoder;
		$this->outdatedEncoders = $outdatedEncoders;
	}

	public function encode(string $raw): string
	{
		return $this->preferredEncoder->encode($raw);
	}

	public function needsReEncode(string $encoded): bool
	{
		return $this->preferredEncoder->needsReEncode($encoded);
	}

	public function isValid(string $raw, string $encoded): bool
	{
		if ($this->preferredEncoder->isValid($raw, $encoded)) {
			return true;
		}

		if (!$this->preferredEncoder->needsReEncode($encoded)) {
			return false;
		}

		foreach ($this->outdatedEncoders as $encoder) {
			if ($encoder->isValid($raw, $encoded)) {
				return true;
			}
		}

		return password_verify($raw, $encoded);
	}

}
