<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Orisai\Auth\Authentication\Data\Expiration;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class ExpirationTest extends TestCase
{

	public function test(): void
	{
		$expiration = new Expiration(123, 456);
		self::assertSame(123, $expiration->getTimestamp());
		self::assertSame(456, $expiration->getDelta());
		self::assertEquals($expiration, unserialize(serialize($expiration)));
	}

}
