<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authorization\IdentityAuthorizationData;

interface Identity
{

	/**
	 * @return int|string
	 */
	public function getId();

	/**
	 * @return array<string>
	 */
	public function getRoles(): array;

	public function hasRole(string $role): bool;

	public function getAuthData(): ?IdentityAuthorizationData;

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array;

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void;

}
