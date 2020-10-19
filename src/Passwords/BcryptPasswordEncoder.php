<?php declare(strict_types = 1);

namespace Orisai\Auth\Passwords;

use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Message;
use function password_hash;
use function password_needs_rehash;
use function password_verify;
use function sprintf;
use function strpos;
use const PASSWORD_BCRYPT;
use const PASSWORD_BCRYPT_DEFAULT_COST;

final class BcryptPasswordEncoder implements PasswordEncoder
{

	private int $cost;

	public function __construct(int $cost = PASSWORD_BCRYPT_DEFAULT_COST)
	{
		if ($cost < 4 || $cost > 31) {
			$message = Message::create()
				->withContext('Trying to set bcrypt algorithm cost.')
				->withProblem(sprintf('Cost %s is out of range.', $cost))
				->withSolution('Choose cost in range 4-31.');

			throw InvalidArgument::create()
				->withMessage($message);
		}

		$this->cost = $cost;
	}

	public function encode(string $raw): string
	{
		return password_hash($raw, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function needsReEncode(string $encoded): bool
	{
		if (!$this->isBcryptHashed($encoded)) {
			return true;
		}

		return password_needs_rehash($encoded, PASSWORD_BCRYPT, $this->getOptions());
	}

	public function isValid(string $raw, string $encoded): bool
	{
		if (!$this->isBcryptHashed($encoded)) {
			return false;
		}

		return password_verify($raw, $encoded);
	}

	/**
	 * @return array<mixed>
	 */
	private function getOptions(): array
	{
		return [
			'cost' => $this->cost,
		];
	}

	private function isBcryptHashed(string $encoded): bool
	{
		return strpos($encoded, '$2y$') === 0;
	}

}
