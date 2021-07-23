<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Identity;

/**
 * @phpstan-template R of object
 */
interface Policy
{

	public static function getPrivilege(): string;

	/**
	 * @return class-string
	 * @phpstan-return class-string<R>
	 */
	public static function getRequirementsClass(): string;

	/**
	 * @phpstan-param R $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, Authorizer $authorizer): bool;

}
