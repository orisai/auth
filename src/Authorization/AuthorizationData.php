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

	private bool $throwOnUnknownPrivilege;

	/**
	 * Accepts preprocessed data from builder
	 *
	 * @param array<string, null>         $rawRoles
	 * @param array<mixed>                $rawPrivileges
	 * @param array<string, array<mixed>> $rawRoleAllowedPrivileges
	 *
	 * @internal
	 * @see AuthorizationDataBuilder::build()
	 */
	public function __construct(
		array $rawRoles,
		array $rawPrivileges,
		array $rawRoleAllowedPrivileges,
		bool $throwOnUnknownPrivilege
	)
	{
		$this->rawRoles = $rawRoles;
		$this->rawPrivileges = $rawPrivileges;
		$this->rawRoleAllowedPrivileges = $rawRoleAllowedPrivileges;
		$this->throwOnUnknownPrivilege = $throwOnUnknownPrivilege;
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

	public function isThrowOnUnknownPrivilege(): bool
	{
		return $this->throwOnUnknownPrivilege;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'rawRoles' => $this->rawRoles,
			'rawPrivileges' => $this->rawPrivileges,
			'rawRoleAllowedPrivileges' => $this->rawRoleAllowedPrivileges,
			'throwOnUnknownPrivilege' => $this->throwOnUnknownPrivilege,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->rawRoles = $data['rawRoles'];
		$this->rawPrivileges = $data['rawPrivileges'];
		$this->rawRoleAllowedPrivileges = $data['rawRoleAllowedPrivileges'];
		$this->throwOnUnknownPrivilege = $data['throwOnUnknownPrivilege'];
	}

}
