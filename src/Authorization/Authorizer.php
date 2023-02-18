<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

interface Authorizer
{

	/**
	 * @phpstan-param literal-string $privilege
	 */
	public function hasPrivilege(Identity $identity, string $privilege): bool;

	/**
	 * @phpstan-param literal-string $privilege
	 * @param-out AccessEntry|null $entry
	 */
	public function isAllowed(
		?Identity $identity,
		string $privilege,
		?object $requirements = null,
		?AccessEntry &$entry = null,
		?CurrentUserPolicyContextCreator $creator = null
	): bool;

	public function isRoot(Identity $identity): bool;

	public function getData(): AuthorizationData;

}
