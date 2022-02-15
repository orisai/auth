<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use Orisai\Exceptions\Message;
use function array_key_exists;

final class AuthorizationDataBuilder extends BaseAuthorizationDataBuilder
{

	/** @var array<string, null> */
	protected array $rawRoles = [];

	/** @var array<mixed> */
	protected array $rawPrivileges = [];

	/** @var array<string, array<mixed>> */
	protected array $rawRoleAllowedPrivileges = [];

	public bool $throwOnUnknownPrivilege = true;

	public function addRole(string $role): void
	{
		$this->rawRoles[$role] = null;
		$this->rawRoleAllowedPrivileges[$role] ??= [];
	}

	public function addPrivilege(string $privilege): void
	{
		if ($privilege === Authorizer::ROOT_PRIVILEGE) {
			$class = self::class;
			$function = __FUNCTION__;
			$message = Message::create()
				->withContext("Trying to add privilege '$privilege' via $class->$function().")
				->withProblem("Privilege '$privilege' is reserved representation of root privilege and " .
					'cannot be added.');

			throw InvalidArgument::create()
				->withMessage($message);
		}

		$privilegeParts = PrivilegeProcessor::parsePrivilege($privilege);

		$privilegesCurrent = &$this->rawPrivileges;

		Arrays::addKeyValue($privilegesCurrent, $privilegeParts, []);
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
