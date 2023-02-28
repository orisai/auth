<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

interface Authorizer
{

	/**
	 * @param literal-string $privilege
	 */
	public function hasPrivilege(Identity $identity, string $privilege): bool;

	/**
	 * @param array{}|null   $entries
	 * @param literal-string $privilege
	 * @param-out list<AccessEntry|MatchAllOfEntries|MatchAnyOfEntries> $entries
	 */
	public function isAllowed(
		?Identity $identity,
		string $privilege,
		?object $requirements = null,
		?array &$entries = null,
		?CurrentUserPolicyContextCreator $creator = null
	): bool;

	public function isRoot(Identity $identity): bool;

	public function getData(): AuthorizationData;

}
