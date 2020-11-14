<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use function in_array;

final class StringIdentity implements Identity
{

	private string $id;

	/** @var array<string> */
	private array $roles;

	/**
	 * @param array<string> $roles
	 */
	public function __construct(string $id, array $roles)
	{
		$this->id = $id;
		$this->roles = $roles;
	}

	public function getId(): string
	{
		return $this->id;
	}

	/**
	 * @return array<string>
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}

	public function hasRole(string $role): bool
	{
		return in_array($role, $this->roles, true);
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'id' => $this->id,
			'roles' => $this->roles,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->id = $data['id'];
		$this->roles = $data['roles'];
	}

}
