<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Data\Logins;
use Orisai\Auth\Authentication\LoginStorage;
use function random_int;

final class TestingArrayLoginStorage implements LoginStorage
{

	/** @var array<Logins> */
	private array $logins = [];

	/** @var array<int> */
	private array $tokens = [];

	public function getLogins(string $namespace): Logins
	{
		return $this->logins[$namespace]
			?? ($this->logins[$namespace] = new Logins());
	}

	public function regenerateSecurityToken(string $namespace): void
	{
		$this->tokens[$namespace] = random_int(0, 1_000_000);
	}

	public function alreadyExists(string $namespace): bool
	{
		return isset($this->logins[$namespace]);
	}

	public function getToken(string $namespace): int
	{
		return $this->tokens[$namespace]
			?? ($this->tokens[$namespace] = random_int(0, 1_000_000));
	}

}
