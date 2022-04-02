<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authorization\IdentityAuthorizationData;
use Orisai\Exceptions\Logic\InvalidArgument;
use function in_array;

abstract class BaseIdentity implements Identity
{

	/** @var array<int, string> */
	private array $roles;

	private ?IdentityAuthorizationData $authorizationData = null;

	/**
	 * @param array<int, string> $roles
	 */
	public function __construct(array $roles)
	{
		$this->roles = $roles;
	}

	/**
	 * @return array<int, string>
	 */
	public function getRoles(): array
	{
		return $this->roles;
	}

	public function hasRole(string $role): bool
	{
		return in_array($role, $this->roles, true);
	}

	public function getAuthorizationData(): ?IdentityAuthorizationData
	{
		return $this->authorizationData;
	}

	public function setAuthorizationData(IdentityAuthorizationData $authData): void
	{
		if (($dataId = $authData->getId()) !== ($id = $this->getId())) {
			throw InvalidArgument::create()
				->withMessage(
					"Identity data with identity ID '$dataId' can't be used with identity with ID '$id'.",
				);
		}

		$this->authorizationData = $authData;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'roles' => $this->roles,
			'authData' => $this->authorizationData,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->roles = $data['roles'];
		$this->authorizationData = $data['authData'] ?? null;
	}

}
