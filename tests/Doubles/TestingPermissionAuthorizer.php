<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authorization\PermissionAuthorizer;

final class TestingPermissionAuthorizer extends PermissionAuthorizer
{

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
