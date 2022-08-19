<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use DateTimeImmutable;
use Orisai\Auth\Authentication\Data\CurrentExpiration;
use PHPUnit\Framework\TestCase;
use function unserialize;

final class CurrentExpirationTest extends TestCase
{

	public function test(): void
	{
		$time1 = DateTimeImmutable::createFromFormat('U', '123');
		$delta = 456;
		$expiration = new CurrentExpiration($time1, $delta);
		self::assertSame($time1, $expiration->getTime());
		self::assertSame($delta, $expiration->getDelta());

		$time2 = DateTimeImmutable::createFromFormat('U', '789');
		$expiration->setTime($time2);
		self::assertSame($time2, $expiration->getTime());
	}

	public function testSerializationBC(): void
	{
		$serialized = 'O:49:"Orisai\Auth\Authentication\Data\CurrentExpiration":2:{s:4:"time";i:123;s:5:"delta";i:456;}';
		$expiration = unserialize($serialized);

		self::assertInstanceOf(CurrentExpiration::class, $expiration);
		self::assertSame(123, $expiration->getTime()->getTimestamp());
		self::assertSame(456, $expiration->getDelta());
	}

}
