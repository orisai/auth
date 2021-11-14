<?php declare(strict_types = 1);

namespace Orisai\Auth\Authentication;

use Orisai\Auth\Authorization\IdentityAuthorizationData;
use Orisai\Exceptions\Logic\InvalidArgument;
use function in_array;

abstract class BaseIdentity implements Identity
{

	/** @var array<string> */
	protected array $roles;

	protected ?IdentityAuthorizationData $authData = null;

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

	public function getAuthData(): ?IdentityAuthorizationData
	{
		return $this->authData;
	}

	public function setAuthData(IdentityAuthorizationData $authData): void
	{
		if (($dataId = $authData->getId()) !== ($id = $this->getId())) {
			throw InvalidArgument::create()
				->withMessage(
					"Identity data with identity ID '$dataId' can't be used with identity with ID '$id'.",
				);
		}

		$this->authData = $authData;
	}

	/**
	 * @return array<mixed>
	 */
	public function __serialize(): array
	{
		return [
			'roles' => $this->roles,
			'authData' => $this->authData,
		];
	}

	/**
	 * @param array<mixed> $data
	 */
	public function __unserialize(array $data): void
	{
		$this->roles = $data['roles'];
		$this->authData = $data['authData'];
	}

}
