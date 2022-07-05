<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\Auth\Authentication\Identity;

interface Authorizer
{

	/**
	 * @phpstan-param literal-string $privilege
	 */
	public function hasPrivilege(Identity $identity, string $privilege): bool;

	/**
	 * @phpstan-param literal-string $privilege
	 */
	public function isAllowed(
		?Identity $identity,
		string $privilege,
		?object $requirements = null,
		?DecisionReason &$reason = null,
		?CurrentUserPolicyContextCreator $creator = null
	): bool;

	public function isRoot(Identity $identity): bool;

	public function getData(): AuthorizationData;

}
