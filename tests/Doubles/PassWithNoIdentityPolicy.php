<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\OptionalIdentityPolicy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @implements OptionalIdentityPolicy<NoRequirements>
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

	public function isAllowed(?Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryResult::fromBool($identity === null),
			'Not logged in',
		);
	}

}
