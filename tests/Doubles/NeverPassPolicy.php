<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<Firewall>
 */
final class NeverPassPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'never-pass';
	}

	public function isAllowed(Firewall $firewall): bool
	{
		return false;
	}

}
