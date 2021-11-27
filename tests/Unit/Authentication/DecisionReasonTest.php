<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\DecisionReason;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class DecisionReasonTest extends TestCase
{

	public function test(): void
	{
		$reason = DecisionReason::create('Message');

		self::assertSame('Message', $reason->getMessage());
		self::assertSame([], $reason->getParameters());
		self::assertFalse($reason->isTranslatable());

		self::assertEquals($reason, unserialize(serialize($reason)));
	}

	public function testTranslatable(): void
	{
		$reason = DecisionReason::createTranslatable('translatable.message', ['a' => 'b']);

		self::assertSame('translatable.message', $reason->getMessage());
		self::assertSame(['a' => 'b'], $reason->getParameters());
		self::assertTrue($reason->isTranslatable());

		self::assertEquals($reason, unserialize(serialize($reason)));
	}

	public function testSerializationBC(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:7:"Message";s:10:"parameters";a:0:{}s:12:"translatable";b:0;}';
		$reason = unserialize($serialized);

		self::assertInstanceOf(DecisionReason::class, $reason);
		self::assertSame('Message', $reason->getMessage());
		self::assertSame([], $reason->getParameters());
		self::assertFalse($reason->isTranslatable());
	}

	public function testSerializationBCTranslatable(): void
	{
		// phpcs:ignore SlevomatCodingStandard.Files.LineLength.LineTooLong
		$serialized = 'O:41:"Orisai\Auth\Authentication\DecisionReason":3:{s:7:"message";s:20:"translatable.message";s:10:"parameters";a:1:{s:1:"a";s:1:"b";}s:12:"translatable";b:1;}';
		$reason = unserialize($serialized);

		self::assertInstanceOf(DecisionReason::class, $reason);
		self::assertSame('translatable.message', $reason->getMessage());
		self::assertSame(['a' => 'b'], $reason->getParameters());
		self::assertTrue($reason->isTranslatable());
	}

}
