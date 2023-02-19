<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AccessEntry;
use Orisai\Auth\Authorization\AccessEntryType;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;

final class AccessEntryTest extends TestCase
{

	public function test(): void
	{
		$message = 'Message';
		$entry = new AccessEntry(AccessEntryType::allowed(), $message);

		self::assertSame(AccessEntryType::allowed(), $entry->getType());
		self::assertSame($message, $entry->getMessage());
	}

	public function testTranslatable(): void
	{
		$message = new TranslatableMessage('translatable.message', ['a' => 'b']);
		$entry = new AccessEntry(AccessEntryType::forbidden(), $message);

		self::assertSame(AccessEntryType::forbidden(), $entry->getType());
		self::assertSame($message, $entry->getMessage());
	}

}
