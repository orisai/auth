<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidState;
use function array_key_exists;

final class AuthorizationDataBuilder
{

	/** @var array<string, null> */
	protected array $roles = [];

	/** @var array<mixed> */
	protected array $privileges = [];

	/** @var array<string, array<mixed>> */
	protected array $roleAllowedPrivileges = [];

	public bool $throwOnUnknownRolePrivilege = false;

	public function addRole(string $role): void
	{
		$this->roles[$role] = null;
		$this->roleAllowedPrivileges[$role] ??= [];
	}

	public function addPrivilege(string $privilege): void
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);

		$privilegesCurrent = &$this->privileges;

		Arrays::addKeyValue($privilegesCurrent, $privilegeParts, []);
	}

	public function allow(string $role, string $privilege): void
	{
		$this->checkRole($role);

		PrivilegeProcessor::allow(
			$privilege,
			$role,
			$this->roleAllowedPrivileges,
			$this->privileges,
			$this->throwOnUnknownRolePrivilege,
			self::class,
			__FUNCTION__,
		);
	}

	public function deny(string $role, string $privilege): void
	{
		$this->checkRole($role);

		PrivilegeProcessor::deny(
			$privilege,
			$role,
			$this->roleAllowedPrivileges,
			$this->privileges,
			$this->throwOnUnknownRolePrivilege,
			self::class,
			__FUNCTION__,
		);
	}

	private function checkRole(string $role): void
	{
		if (!array_key_exists($role, $this->roles)) {
			$class = self::class;

			throw InvalidState::create()
				->withMessage("Role {$role} does not exist, add it with {$class}->addRole(\$role)");
		}
	}

	public function build(): AuthorizationData
	{
		return new AuthorizationData(
			$this->roles,
			$this->privileges,
			$this->roleAllowedPrivileges,
		);
	}

}
