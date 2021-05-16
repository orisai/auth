<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Firewall;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-template F of Firewall
 * @phpstan-implements Policy<F, NoRequirements>
 */
final class NeverPassPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'never-pass';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Firewall $firewall, object $requirements): bool
	{
		return false;
	}

	/**
	 * @return array{string, null}
	 */
	public static function get(): array
	{
		return [self::getPrivilege(), null];
	}

}
