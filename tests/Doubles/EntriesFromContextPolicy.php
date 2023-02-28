<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @implements Policy<EntriesFromContext>
 */
final class EntriesFromContextPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'entries-from-context';
	}

	public static function getRequirementsClass(): string
	{
		return EntriesFromContext::class;
	}

	/**
	 * @param EntriesFromContext $requirements
	 */
	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield from $requirements->entries;
	}

}
