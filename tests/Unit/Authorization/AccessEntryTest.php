<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\AccessEntry;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class AccessEntryTest extends TestCase
{

	public function test(): void
	{
		$message = 'Message';
		$reason = new AccessEntry($message);

		self::assertSame($message, $reason->getMessage());
		self::assertEquals($reason, unserialize(serialize($reason)));
	}

	public function testTranslatable(): void
	{
		$message = new TranslatableMessage('translatable.message', ['a' => 'b']);
		$reason = new AccessEntry($message);

		self::assertSame($message, $reason->getMessage());
		self::assertEquals($reason, unserialize(serialize($reason)));
	}

}
