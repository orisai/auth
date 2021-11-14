<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Orisai\Auth\Authentication\StringIdentity;
use Orisai\Auth\Authorization\IdentityAuthorizationData;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use function serialize;
use function unserialize;

final class StringIdentityTest extends TestCase
{

	public function testBase(): void
	{
		$identity = new StringIdentity('123', ['foo', 'bar']);

		self::assertSame('123', $identity->getId());

		self::assertSame(['foo', 'bar'], $identity->getRoles());
		self::assertTrue($identity->hasRole('foo'));
		self::assertTrue($identity->hasRole('bar'));
		self::assertFalse($identity->hasRole('baz'));

		self::assertNull($identity->getAuthData());

		$data = new IdentityAuthorizationData($identity->getId(), []);
		$identity->setAuthData($data);
		self::assertSame($data, $identity->getAuthData());

		$serialized = serialize($identity);
		self::assertEquals($identity, unserialize($serialized));
	}

	public function testSetDataException(): void
	{
		$identity = new StringIdentity('123', []);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(
			"Identity data with identity ID '456' can't be used with identity with ID '123'.",
		);

		$identity->setAuthData(new IdentityAuthorizationData('456', []));
	}

}
