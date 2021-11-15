<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidState;
use function array_key_exists;

final class AuthorizationDataBuilder extends BaseAuthorizationDataBuilder
{

	/** @var array<string, null> */
	protected array $rawRoles = [];

	/** @var array<mixed> */
	protected array $rawPrivileges = [];

	/** @var array<string, array<mixed>> */
	protected array $rawRoleAllowedPrivileges = [];

	public bool $throwOnUnknownPrivilege = false;

	public function addRole(string $role): void
	{
		$this->rawRoles[$role] = null;
		$this->rawRoleAllowedPrivileges[$role] ??= [];
	}

	public function addPrivilege(string $privilege): void
	{
		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);

		$privilegesCurrent = &$this->rawPrivileges;

		Arrays::addKeyValue($privilegesCurrent, $privilegeParts, []);
	}

	public function allow(string $role, string $privilege): void
	{
		$this->checkRole($role);

		self::allowInternal(
			$privilege,
			$role,
			$this->rawRoleAllowedPrivileges,
			$this->rawPrivileges,
			$this->throwOnUnknownPrivilege,
			self::class,
			__FUNCTION__,
		);
	}

	public function deny(string $role, string $privilege): void
	{
		$this->checkRole($role);

		self::denyInternal(
			$privilege,
			$role,
			$this->rawRoleAllowedPrivileges,
			$this->rawPrivileges,
			$this->throwOnUnknownPrivilege,
			self::class,
			__FUNCTION__,
		);
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
			$this->throwOnUnknownPrivilege,
		);
	}

}
