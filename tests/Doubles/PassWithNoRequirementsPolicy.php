<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryType;
use Orisai\Auth\Authorization\OptionalRequirementsPolicy;
use Orisai\Auth\Authorization\PolicyContext;

/**
 * @phpstan-implements OptionalRequirementsPolicy<Article>
 */
final class PassWithNoRequirementsPolicy implements OptionalRequirementsPolicy
{

	public static function getPrivilege(): string
	{
		return 'nullable-requirements';
	}

	public static function getRequirementsClass(): string
	{
		return Article::class;
	}

	public function isAllowed(Identity $identity, ?object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryType::fromBool($requirements === null),
			'',
		);
	}

}
