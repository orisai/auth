<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication\Data;

use Orisai\Auth\Authentication\Data\CurrentExpiration;
use PHPStan\Testing\TestCase;

final class CurrentExpirationTest extends TestCase
{

	public function test(): void
	{
		$expiration = new CurrentExpiration(123, 456);
		self::assertSame(123, $expiration->getTimestamp());
		self::assertSame(456, $expiration->getDelta());
		$expiration->setTimestamp(789);
		self::assertSame(789, $expiration->getTimestamp());
	}

}
