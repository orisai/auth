<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidState;
use function array_key_exists;
use function get_class;

final class AuthorizationDataBuilder
{

	/** @var array<string, null> */
	protected array $roles = [];

	/** @var array<mixed> */
	protected array $privileges = [];

	/** @var array<string, array<mixed>> */
	protected array $roleAllowedPrivileges = [];

	private PrivilegeAuthorizer $authorizer;

	public function __construct(PrivilegeAuthorizer $authorizer)
	{
		$this->authorizer = $authorizer;
	}

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

		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			$this->roleAllowedPrivileges[$role] = $this->privileges;

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = PrivilegeProcessor::getPrivilege($privilege, $privilegeParts, $this->privileges);

		if ($privilegeValue === null) {
			if ($this->authorizer->throwOnUnknownRolePrivilege) {
				$this->authorizer->unknownPrivilege($privilege, __FUNCTION__);
			}

			return;
		}

		$rolePrivilegesCurrent = &$this->roleAllowedPrivileges[$role];

		Arrays::addKeyValue($rolePrivilegesCurrent, $privilegeParts, $privilegeValue);
	}

	public function deny(string $role, string $privilege): void
	{
		$this->checkRole($role);

		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			$this->roleAllowedPrivileges[$role] = [];

			return;
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);
		$privilegeValue = PrivilegeProcessor::getPrivilege($privilege, $privilegeParts, $this->privileges);

		if ($privilegeValue === null) {
			if ($this->authorizer->throwOnUnknownRolePrivilege) {
				$this->authorizer->unknownPrivilege($privilege, __FUNCTION__);
			}

			return;
		}

		Arrays::removeKey($this->roleAllowedPrivileges[$role], $privilegeParts);
	}

	private function checkRole(string $role): void
	{
		if (!array_key_exists($role, $this->roles)) {
			$class = get_class($this->authorizer);

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
