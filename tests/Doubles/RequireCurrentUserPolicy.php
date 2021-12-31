<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\CurrentUserPolicyContext;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements Policy<NoRequirements>
 */
final class RequireCurrentUserPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'require-current-user';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool
	{
		return $context instanceof CurrentUserPolicyContext;
	}

}
