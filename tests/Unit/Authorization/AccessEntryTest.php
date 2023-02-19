<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryResult;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;

final class AccessEntryTest extends TestCase
{

	public function test(): void
	{
		$message = 'Message';
		$entry = new AccessEntry(AccessEntryResult::allowed(), $message);

		self::assertSame(AccessEntryResult::allowed(), $entry->getResult());
		self::assertSame($message, $entry->getMessage());
	}

	public function testTranslatable(): void
	{
		$message = new TranslatableMessage('translatable.message', ['a' => 'b']);
		$entry = new AccessEntry(AccessEntryResult::forbidden(), $message);

		self::assertSame(AccessEntryResult::forbidden(), $entry->getResult());
		self::assertSame($message, $entry->getMessage());
	}

}
