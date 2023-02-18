<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Doubles;

use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\NoRequirements;
use Orisai\Auth\Authorization\Policy;
use Orisai\Auth\Authorization\PolicyContext;
use Orisai\TranslationContracts\TranslatableMessage;

/**
 * @phpstan-implements Policy<NoRequirements>
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

	public function isAllowed(Identity $identity, object $requirements, PolicyContext $context): bool
	{
		$context->addAccessEntry(new AccessEntry('Message'));
		$context->addAccessEntry(new AccessEntry(new TranslatableMessage('message.id')));

		return true;
	}

}
