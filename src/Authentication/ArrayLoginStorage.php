<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authentication\Data\Logins;

final class ArrayLoginStorage implements LoginStorage
{

	/** @var array<Logins> */
	private array $logins = [];

	public function getLogins(string $namespace): Logins
	{
		return $this->logins[$namespace]
			?? ($this->logins[$namespace] = new Logins());
	}

	public function regenerateSecurityToken(string $namespace): void
	{
		// There is none
	}

	public function alreadyExists(string $namespace): bool
	{
		return isset($this->logins[$namespace]);
	}

}
