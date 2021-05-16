<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Firewall;

/**
 * @phpstan-template F of Firewall
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
	 * @phpstan-param F $firewall
	 * @phpstan-param R $requirements
	 */
	public function isAllowed(Firewall $firewall, object $requirements): bool;

}
