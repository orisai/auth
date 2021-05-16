<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<Firewall, Article>
 */
final class NullableRequirementsPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'nullable-requirements';
	}

	public static function getRequirementsClass(): string
	{
		return Article::class;
	}

	public function isAllowed(Firewall $firewall, ?object $requirements): bool
	{
		return false;
	}

}
