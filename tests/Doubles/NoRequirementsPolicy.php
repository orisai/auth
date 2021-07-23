<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Authorizer;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;

/**
 * @phpstan-implements Policy<NoRequirements>
 */
final class NoRequirementsPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'no-requirements';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, Authorizer $authorizer): bool
	{
		return false;
	}

}
