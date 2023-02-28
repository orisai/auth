<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Generator;
use Orisai\Auth\Authentication\Identity;

/**
 * @template R of object
 *
 * @see OptionalIdentityPolicy
 * @see OptionalRequirementsPolicy
 */
interface Policy
{

	/**
	 * @return literal-string
	 */
	public static function getPrivilege(): string;

	/**
	 * @return class-string<R>
	 *
	 * @see NoRequirements
	 */
	public static function getRequirementsClass(): string;

	/**
	 * @param R $requirements
	 * @return Generator<int, AccessEntry|MatchAllOfEntries|MatchAnyOfEntries, null, void>
	 */
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator;

}
