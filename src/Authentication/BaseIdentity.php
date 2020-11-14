<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use function in_array;

abstract class BaseIdentity implements Identity
{

	/** @var array<string> */
	protected array $roles;

	/**
	 * @return array<string>
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}

	public function hasRole(string $role): bool
	{
		return in_array($role, $this->roles, true);
	}

}
