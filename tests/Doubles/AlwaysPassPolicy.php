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
final class AlwaysPassPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'always-pass';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryResult::allowed(),
			'[internal behavior] Always pass',
		);

		yield new AccessEntry(
			AccessEntryResult::allowed(),
			'[internal behavior] Always pass',
		);
	}

}
