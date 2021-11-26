<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authorization;

use Orisai\Auth\Authorization\DecisionReason;
use PHPUnit\Framework\TestCase;

final class DecisionReasonTest extends TestCase
{

	public function test(): void
	{
		$reason = DecisionReason::create('Message');

		self::assertSame('Message', $reason->getMessage());
		self::assertSame([], $reason->getParameters());
		self::assertFalse($reason->isTranslatable());
	}

	public function testTranslatable(): void
	{
		$reason = DecisionReason::createTranslatable('translatable.message', ['a' => 'b']);

		self::assertSame('translatable.message', $reason->getMessage());
		self::assertSame(['a' => 'b'], $reason->getParameters());
		self::assertTrue($reason->isTranslatable());
	}

}
