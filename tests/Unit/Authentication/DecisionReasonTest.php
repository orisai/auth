<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\DecisionReason;
use Orisai\TranslationContracts\TranslatableMessage;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class DecisionReasonTest extends TestCase
{

	public function test(): void
	{
		$message = 'Message';
		$reason = new DecisionReason($message);

		self::assertSame($message, $reason->getMessage());
		self::assertEquals($reason, unserialize(serialize($reason)));
	}

	public function testTranslatable(): void
	{
		$message = new TranslatableMessage('translatable.message', ['a' => 'b']);
		$reason = new DecisionReason($message);

		self::assertSame($message, $reason->getMessage());
		self::assertEquals($reason, unserialize(serialize($reason)));
	}

	public function testSerializationBC(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:7:"Message";s:10:"parameters";a:0:{}s:12:"translatable";b:0;}';
		$reason = unserialize($serialized);

		self::assertInstanceOf(DecisionReason::class, $reason);
		self::assertSame('Message', $reason->getMessage());

		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:20:"translatable.message";s:10:"parameters";a:1:{s:1:"a";s:1:"b";}s:12:"translatable";b:1;}';
		$reason = unserialize($serialized);

		self::assertInstanceOf(DecisionReason::class, $reason);
		self::assertEquals(
			new TranslatableMessage('translatable.message', ['a' => 'b']),
			$reason->getMessage(),
		);
	}

}
