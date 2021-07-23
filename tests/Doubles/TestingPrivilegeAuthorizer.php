<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authorization\PrivilegeAuthorizer;

final class TestingPrivilegeAuthorizer extends PrivilegeAuthorizer
{

	public function privilegeExists(string $privilege): bool
	{
		return parent::privilegeExists($privilege);
	}

	/**
	 * @return array<string, array<mixed>>
	 */
	public function getDebugRolePrivileges(): array
	{
		return $this->rolePrivileges;
	}

	/**
	 * @return array<mixed>
	 */
	public function getDebugPrivileges(): array
	{
		return $this->privileges;
	}

}
