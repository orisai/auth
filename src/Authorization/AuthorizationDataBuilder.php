<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidState;
use function array_key_exists;

final class AuthorizationDataBuilder extends BaseAuthorizationDataBuilder
{

	/** @var array<string, null> */
	private array $rawRoles = [];

	/** @var array<mixed> */
	private array $rawPrivileges = [];

	/** @var array<string, array<mixed>> */
	private array $rawRoleAllowedPrivileges = [];

	/** @var array<string, null> */
	private array $rawRootRoles = [];

	public bool $throwOnUnknownPrivilege = true;

	public function addRole(string $role): void
	{
		$this->rawRoles[$role] = null;
		$this->rawRoleAllowedPrivileges[$role] ??= [];
	}

	public function addPrivilege(string $privilege): void
	{
		$privilegesCurrent = &$this->rawPrivileges;

		Arrays::addKeyValue(
			$privilegesCurrent,
			PrivilegeProcessor::parsePrivilege($privilege),
			[],
		);
	}

	public function allow(string $role, string $privilege): void
	{
		$this->checkRole($role);

		self::addPrivilegeToList(
			$privilege,
			$role,
			$this->rawRoleAllowedPrivileges,
			$this->rawPrivileges,
			$this->throwOnUnknownPrivilege,
			self::class,
			__FUNCTION__,
		);
	}

	public function removeAllow(string $role, string $privilege): void
	{
		$this->checkRole($role);

		self::removePrivilegeFromList(
			$privilege,
			$role,
			$this->rawRoleAllowedPrivileges,
			$this->rawPrivileges,
			$this->throwOnUnknownPrivilege,
			self::class,
			__FUNCTION__,
		);
	}

	public function addRoot(string $role): void
	{
		$this->checkRole($role);

		$this->rawRootRoles[$role] = null;
	}

	public function removeRoot(string $role): void
	{
		$this->checkRole($role);

		unset($this->rawRootRoles[$role]);
	}

	private function checkRole(string $role): void
	{
		if (!array_key_exists($role, $this->rawRoles)) {
			$class = self::class;

			throw InvalidState::create()
				->withMessage("Role {$role} does not exist, add it with {$class}->addRole(\$role)");
		}
	}

	public function build(): AuthorizationData
	{
		return new AuthorizationData(
			$this->rawRoles,
			$this->rawPrivileges,
			$this->rawRoleAllowedPrivileges,
			$this->rawRootRoles,
			$this->throwOnUnknownPrivilege,
		);
	}

}
