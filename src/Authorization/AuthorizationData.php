<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use function array_keys;

final class AuthorizationData
{

	/** @var array<string, null> */
	protected array $rawRoles = [];

	/** @var array<mixed> */
	protected array $rawPrivileges = [];

	/** @var array<string, array<mixed>> */
	protected array $rawRoleAllowedPrivileges = [];

	/**
	 * Accepts preprocessed data from builder
	 *
	 * @param array<string, null>         $rawRoles
	 * @param array<mixed>                $rawPrivileges
	 * @param array<string, array<mixed>> $rawRoleAllowedPrivileges
	 *
	 * @internal
	 */
	public function __construct(array $rawRoles, array $rawPrivileges, array $rawRoleAllowedPrivileges)
	{
		$this->rawRoles = $rawRoles;
		$this->rawPrivileges = $rawPrivileges;
		$this->rawRoleAllowedPrivileges = $rawRoleAllowedPrivileges;
	}

	/**
	 * @return array<string, null>
	 */
	public function getRawRoles(): array
	{
		return $this->rawRoles;
	}

	/**
	 * @return array<int, string>
	 */
	public function getRoles(): array
	{
		return array_keys($this->rawRoles);
	}

	/**
	 * @return array<mixed>
	 */
	public function getRawPrivileges(): array
	{
		return $this->rawPrivileges;
	}

	/**
	 * @return array<string>
	 */
	public function getPrivileges(): array
	{
		return Arrays::keysToStrings($this->rawPrivileges);
	}

	public function privilegeExists(string $privilege): bool
	{
		if ($privilege === Authorizer::ALL_PRIVILEGES) {
			return true;
		}

		$privileges = $this->rawPrivileges;
		$privilegeValue = Arrays::getKey($privileges, PrivilegeProcessor::parsePrivilege($privilege));

		return $privilegeValue !== null;
	}

	/**
	 * @return array<string, array<mixed>>
	 */
	public function getRawRoleAllowedPrivileges(): array
	{
		return $this->rawRoleAllowedPrivileges;
	}

	/**
	 * @return array<string>
	 */
	public function getAllowedPrivilegesForRole(string $role): array
	{
		$roleAllowedPrivileges = $this->getRawRoleAllowedPrivileges();
		$privileges = $roleAllowedPrivileges[$role] ?? [];

		return Arrays::keysToStrings($privileges);
	}

}
