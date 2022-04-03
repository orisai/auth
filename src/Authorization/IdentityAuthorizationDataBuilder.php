<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;
use function array_key_exists;

final class IdentityAuthorizationDataBuilder extends BaseAuthorizationDataBuilder
{

	private AuthorizationData $data;

	/** @var array<int|string, array<mixed>> */
	private array $identityAllowedPrivileges = [];

	/** @var array<int|string, null> */
	private array $rawRootIds = [];

	public function __construct(AuthorizationData $data)
	{
		$this->data = $data;
	}

	public function allow(Identity $identity, string $privilege): void
	{
		self::addPrivilegeToList(
			$privilege,
			$identity->getId(),
			$this->identityAllowedPrivileges,
			$this->data->getRawPrivileges(),
			$this->data->shouldThrowOnUnknownPrivilege(),
			self::class,
			__FUNCTION__,
		);
	}

	public function removeAllow(Identity $identity, string $privilege): void
	{
		self::removePrivilegeFromList(
			$privilege,
			$identity->getId(),
			$this->identityAllowedPrivileges,
			$this->data->getRawPrivileges(),
			$this->data->shouldThrowOnUnknownPrivilege(),
			self::class,
			__FUNCTION__,
		);
	}

	public function addRoot(Identity $identity): void
	{
		$this->rawRootIds[$identity->getId()] = null;
	}

	public function removeRoot(Identity $identity): void
	{
		unset($this->rawRootIds[$identity->getId()]);
	}

	public function build(Identity $identity): IdentityAuthorizationData
	{
		$id = $identity->getId();

		return new IdentityAuthorizationData(
			$id,
			$this->identityAllowedPrivileges[$id] ?? [],
			array_key_exists($id, $this->rawRootIds),
		);
	}

}
