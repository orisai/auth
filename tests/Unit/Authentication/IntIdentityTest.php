<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authorization\IdentityAuthorizationData;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class IntIdentityTest extends TestCase
{

	public function testBase(): void
	{
		$identity = new IntIdentity(123, ['foo', 'bar']);

		self::assertSame(123, $identity->getId());

		self::assertSame(['foo', 'bar'], $identity->getRoles());
		self::assertTrue($identity->hasRole('foo'));
		self::assertTrue($identity->hasRole('bar'));
		self::assertFalse($identity->hasRole('baz'));

		self::assertNull($identity->getAuthorizationData());

		$data = new IdentityAuthorizationData($identity->getId(), []);
		$identity->setAuthorizationData($data);
		self::assertSame($data, $identity->getAuthorizationData());

		$serialized = serialize($identity);
		self::assertEquals($identity, unserialize($serialized));
	}

	public function testSetDataException(): void
	{
		$identity = new IntIdentity(123, []);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(
			"Identity data with identity ID '456' can't be used with identity with ID '123'.",
		);

		$identity->setAuthorizationData(new IdentityAuthorizationData(456, []));
	}

	public function testSerializationBC(): void
	{
		$serialized = 'O:38:"Orisai\Auth\Authentication\IntIdentity":2:{s:5:"roles";a:0:{}s:2:"id";i:1;}';
		$identity = unserialize($serialized);

		self::assertInstanceOf(IntIdentity::class, $identity);
		self::assertSame(1, $identity->getId());
		self::assertSame([], $identity->getRoles());
		self::assertNull($identity->getAuthorizationData());
	}

}
