<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\OptionalIdentityPolicy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements OptionalIdentityPolicy<NoRequirements>
 */
final class PassWithNoIdentityPolicy implements OptionalIdentityPolicy
{

	public static function getPrivilege(): string
	{
		return 'pass.with.no.identity';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(?Identity $identity, object $requirements, PolicyContext $context): bool
	{
		return $identity === null;
	}

}