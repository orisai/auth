<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Utils\Arrays;
use function array_keys;

final class AuthorizationData
{

	/** @var array<string, null> */
	private array $rawRoles;

	/** @var array<mixed> */
	private array $rawPrivileges;

	/** @var array<string, array<mixed>> */
	private array $rawRoleAllowedPrivileges;

	/** @var array<string, null> */
	private array $rawRootRoles;

	private bool $throwOnUnknownPrivilege;

	/**
	 * Accepts preprocessed data from builder
	 *
	 * @param array<string, null>         $rawRoles
	 * @param array<mixed>                $rawPrivileges
	 * @param array<string, array<mixed>> $rawRoleAllowedPrivileges
	 * @param array<string, null>         $rawRootRoles
	 *
	 * @internal
	 * @see AuthorizationDataBuilder::build()
	 */
	public function __construct(
		array $rawRoles,
		array $rawPrivileges,
		array $rawRoleAllowedPrivileges,
		array $rawRootRoles,
		bool $throwOnUnknownPrivilege
	)
	{
		$this->rawRoles = $rawRoles;
		$this->rawPrivileges = $rawPrivileges;
		$this->rawRoleAllowedPrivileges = $rawRoleAllowedPrivileges;
		$this->rawRootRoles = $rawRootRoles;
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

	/**
	 * @return array<string, null>
	 */
	public function getRawRootRoles(): array
	{
		return $this->rawRootRoles;
	}

	/**
	 * @return array<int, string>
	 */
	public function getRootRoles(): array
	{
		return array_keys($this->rawRootRoles);
	}

	public function shouldThrowOnUnknownPrivilege(): bool
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
			'rawRootRoles' => $this->rawRootRoles,
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
		$this->rawRootRoles = $data['rawRootRoles'] ?? [];
		$this->throwOnUnknownPrivilege = $data['throwOnUnknownPrivilege'];
	}

}
