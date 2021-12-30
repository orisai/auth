<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

/**
 * @phpstan-template R of object
 *
 * @see OptionalIdentityPolicy
 * @see OptionalRequirementsPolicy
 */
interface Policy
{

	/**
	 * @phpstan-return literal-string
	 */
	public static function getPrivilege(): string;

	/**
	 * @return class-string
	 * @phpstan-return class-string<R>
	 *
	 * @see NoRequirements
	 */
	public static function getRequirementsClass(): string;

	/**
	 * @param CurrentUserPolicyContext|AnyUserPolicyContext $context
	 * @phpstan-param R $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool;

}
