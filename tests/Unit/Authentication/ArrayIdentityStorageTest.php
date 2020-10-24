<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use DateTimeImmutable;
use Orisai\Auth\Authentication\IntIdentity;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\ArrayIdentityStorage;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;

final class ArrayIdentityStorageTest extends TestCase
{

	public function testBase(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		self::assertFalse($storage->isAuthenticated());
		self::assertNull($storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage->setAuthenticated($identity);
		self::assertTrue($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage->setUnauthenticated();
		self::assertFalse($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame($storage::REASON_MANUAL, $storage->getLogoutReason());
	}

	public function testExpiredIdentity(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->setAuthenticated($identity);
		self::assertTrue($storage->isAuthenticated());

		$storage->setExpiration(new DateTimeImmutable('10 seconds ago'));
		self::assertFalse($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame($storage::REASON_INACTIVITY, $storage->getLogoutReason());
	}

	public function testNotExpiredIdentity(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->setAuthenticated($identity);
		self::assertTrue($storage->isAuthenticated());

		$storage->setExpiration(new DateTimeImmutable('10 minutes'));
		self::assertTrue($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRemovedExpiration(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->setAuthenticated($identity);
		self::assertTrue($storage->isAuthenticated());

		$storage->setExpiration(new DateTimeImmutable('10 seconds ago'));
		$storage->removeExpiration();
		self::assertTrue($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRenewerSameIdentity(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'), new AlwaysPassIdentityRenewer());
		$identity = new IntIdentity(123, []);

		$storage->setAuthenticated($identity);
		self::assertTrue($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRenewerNewIdentity(): void
	{
		$newIdentity = new IntIdentity(456, []);
		$originalIdentity = new IntIdentity(123, []);
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'), new NewIdentityIdentityRenewer($newIdentity));

		$storage->setAuthenticated($originalIdentity);
		self::assertTrue($storage->isAuthenticated());
		self::assertSame($newIdentity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRenewerRemovedIdentity(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'), new NeverPassIdentityRenewer());
		$identity = new IntIdentity(123, []);

		$storage->setAuthenticated($identity);
		self::assertFalse($storage->isAuthenticated());
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame($storage::REASON_INVALID_IDENTITY, $storage->getLogoutReason());
	}

}
