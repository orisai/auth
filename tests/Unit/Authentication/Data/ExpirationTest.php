<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Brick\DateTime\Duration;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\Data\Expiration;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class ExpirationTest extends TestCase
{

	public function test(): void
	{
		$time = Instant::of(123);
		$delta = Duration::ofSeconds(456);
		$expiration = new Expiration($time, $delta);
		self::assertSame($time, $expiration->getTime());
		self::assertSame($delta, $expiration->getDelta());
		self::assertEquals($expiration, unserialize(serialize($expiration)));
	}

	public function testSerializationBC(): void
	{
		$serialized = 'O:42:"Orisai\Auth\Authentication\Data\Expiration":2:{s:4:"time";i:123;s:5:"delta";i:456;}';
		$expiration = unserialize($serialized);

		self::assertInstanceOf(Expiration::class, $expiration);
		self::assertSame(123, $expiration->getTime()->getEpochSecond());
		self::assertSame(456, $expiration->getDelta()->getSeconds());
	}

}
