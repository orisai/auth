<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authorization\PrivilegeAuthorizer;

final class TestingPrivilegeAuthorizer extends PrivilegeAuthorizer
{

	/**
	 * @return array<string, array<mixed>>
	 */
	public function getDebugRolePrivileges(): array
	{
		return $this->data->getRoleAllowedPrivileges();
	}

	/**
	 * @return array<mixed>
	 */
	public function getDebugPrivileges(): array
	{
		return $this->data->getPrivileges();
	}

}
