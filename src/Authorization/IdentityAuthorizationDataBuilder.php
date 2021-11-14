<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

final class IdentityAuthorizationDataBuilder
{

	private AuthorizationData $data;

	/** @var array<int|string, array<mixed>> */
	private array $identityAllowedPrivileges = [];

	public function __construct(AuthorizationData $data)
	{
		$this->data = $data;
	}

	public function allow(Identity $identity, string $privilege): void
	{
		PrivilegeProcessor::allow(
			$privilege,
			$identity->getId(),
			$this->identityAllowedPrivileges,
			$this->data->getRawPrivileges(),
			$this->data->isThrowOnUnknownPrivilege(),
			self::class,
			__FUNCTION__,
		);
	}

	public function deny(Identity $identity, string $privilege): void
	{
		PrivilegeProcessor::deny(
			$privilege,
			$identity->getId(),
			$this->identityAllowedPrivileges,
			$this->data->getRawPrivileges(),
			$this->data->isThrowOnUnknownPrivilege(),
			self::class,
			__FUNCTION__,
		);
	}

	public function build(Identity $identity): IdentityAuthorizationData
	{
		$id = $identity->getId();

		return new IdentityAuthorizationData(
			$id,
			$this->identityAllowedPrivileges[$identity->getId()] ?? [],
		);
	}

}
