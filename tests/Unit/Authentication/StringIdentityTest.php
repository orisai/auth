<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\StringIdentity;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class StringIdentityTest extends TestCase
{

	public function test(): void
	{
		$identity = new StringIdentity('123', ['foo', 'bar']);

		self::assertSame('123', $identity->getId());

		self::assertSame(['foo', 'bar'], $identity->getRoles());
		self::assertTrue($identity->hasRole('foo'));
		self::assertTrue($identity->hasRole('bar'));
		self::assertFalse($identity->hasRole('baz'));

		$serialized = serialize($identity);
		self::assertEquals($identity, unserialize($serialized));
	}

}
