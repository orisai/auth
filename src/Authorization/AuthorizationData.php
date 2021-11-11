<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

final class AuthorizationData
{

	/** @var array<string, null> */
	protected array $roles = [];

	/** @var array<mixed> */
	protected array $privileges = [];

	/** @var array<string, array<mixed>> */
	protected array $roleAllowedPrivileges = [];

	/**
	 * Accepts preprocessed data from builder
	 *
	 * @param array<string, null>         $roles
	 * @param array<mixed>                $privileges
	 * @param array<string, array<mixed>> $roleAllowedPrivileges
	 *
	 * @internal
	 */
	public function __construct(array $roles, array $privileges, array $roleAllowedPrivileges)
	{
		$this->roles = $roles;
		$this->privileges = $privileges;
		$this->roleAllowedPrivileges = $roleAllowedPrivileges;
	}

	/**
	 * @return array<string, null>
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}

	/**
	 * @return array<mixed>
	 */
	public function getPrivileges(): array
	{
		return $this->privileges;
	}

	/**
	 * @return array<string, array<mixed>>
	 */
	public function getRoleAllowedPrivileges(): array
	{
		return $this->roleAllowedPrivileges;
	}

}
