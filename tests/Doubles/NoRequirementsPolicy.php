<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @implements Policy<NoRequirements>
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

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryResult::fromBool($requirements instanceof NoRequirements),
			'[internal behavior] No requirements',
		);
	}

}
