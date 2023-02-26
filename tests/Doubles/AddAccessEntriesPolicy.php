<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Generator;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;
use Orisai\TranslationContracts\TranslatableMessage;

/**
 * @implements Policy<NoRequirements>
 */
final class AddAccessEntriesPolicy implements Policy
{

	public static function getPrivilege(): string
	{
		return 'add-access-entry';
	}

	public static function getRequirementsClass(): string
	{
		return NoRequirements::class;
	}

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): Generator
	{
		yield new AccessEntry(
			AccessEntryResult::allowed(),
			'Message',
		);

		yield new AccessEntry(
			AccessEntryResult::allowed(),
			new TranslatableMessage('message.id'),
		);
	}

}
