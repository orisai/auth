<?php declare(strict_types = 1);

namespace Orisai\Auth\Authorization;

use Orisai\Auth\Authentication\Firewall;

/**
 * @phpstan-template F of Firewall
 */
interface Policy
{

	public static function getPrivilege(): string;

	/**
	 * @phpstan-param F $firewall
	 */
	public function isAllowed(Firewall $firewall): bool;

}
