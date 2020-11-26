<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use DateTimeImmutable;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\ArrayLoginStorage;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;
use function array_keys;

final class ArrayLoginStorageTest extends TestCase
{

	public function testGetLogins(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));

		$logins = $storage->getLogins();
		self::assertNull($logins->getCurrentLogin());
		self::assertSame([], $logins->getExpiredLogins());
	}

	public function testLogin(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		self::assertNull($storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());

		$storage->logout($storage::REASON_MANUAL);
		self::assertNull($storage->getIdentity());
	}

	public function testExpiredLogins(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage->logout($storage::REASON_MANUAL);
		self::assertNull($storage->getIdentity());

		$expiredLogins = $storage->getExpiredLogins();
		self::assertCount(1, $expiredLogins);

		$expired1 = $expiredLogins[123];
		self::assertSame($identity, $expired1->getIdentity());
		self::assertNull($expired1->getExpiration());
		self::assertSame($storage::REASON_MANUAL, $expired1->getLogoutReason());
		self::assertIsInt($expired1->getAuthenticationTimestamp());

		$identity2 = new IntIdentity(123, []);
		$storage->login($identity2);
		$storage->logout($storage::REASON_INVALID_IDENTITY);

		$expiredLogins = $storage->getExpiredLogins();
		self::assertCount(1, $expiredLogins);

		$expired2 = $expiredLogins[123];
		self::assertSame($identity2, $expired2->getIdentity());
		self::assertSame($storage::REASON_INVALID_IDENTITY, $expired2->getLogoutReason());

		$identity3 = new IntIdentity(456, []);
		$storage->login($identity3);
		$storage->logout($storage::REASON_INVALID_IDENTITY);

		$expiredLogins = $storage->getExpiredLogins();
		self::assertCount(2, $expiredLogins);
		self::assertSame($expired2, $expiredLogins[123]);

		$expired3 = $expiredLogins[456];
		self::assertSame($identity3, $expired3->getIdentity());
		self::assertSame($storage::REASON_INVALID_IDENTITY, $expired3->getLogoutReason());
	}

	public function testRenewIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage->renewIdentity($identity);
		self::assertSame($identity, $storage->getIdentity());

		$newIdentity = new IntIdentity(123, []);
		$storage->renewIdentity($newIdentity);
		self::assertSame($newIdentity, $storage->getIdentity());
	}

	public function testTimeExpiredIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage->setExpiration(new DateTimeImmutable('10 seconds ago'));
		self::assertNull($storage->getIdentity());

		$expired = $storage->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($storage::REASON_INACTIVITY, $expired->getLogoutReason());
	}

	public function testNotTimeExpiredIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage->setExpiration(new DateTimeImmutable('10 minutes'));
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRemovedTimeExpiration(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage->setExpiration(new DateTimeImmutable('10 seconds ago'));
		$storage->removeExpiration();
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testExpiredIdentities(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$storage->setExpiredIdentitiesLimit(3);
		$identity1 = new IntIdentity(1, []);

		$storage->login($identity1);
		self::assertSame([], $storage->getExpiredLogins());

		$storage->logout($storage::REASON_MANUAL);
		self::assertSame([1], array_keys($storage->getExpiredLogins()));

		$storage->login($identity1);
		self::assertSame([], $storage->getExpiredLogins());

		$identity2 = new StringIdentity('second', []);
		$storage->login($identity2);
		self::assertSame([1], array_keys($storage->getExpiredLogins()));

		$storage->logout($storage::REASON_MANUAL);
		self::assertSame([1, 'second'], array_keys($storage->getExpiredLogins()));

		$identity3 = new IntIdentity(3, []);
		$storage->login($identity3);
		$storage->login($identity2);
		$storage->logout($storage::REASON_MANUAL);
		self::assertSame([1, 3, 'second'], array_keys($storage->getExpiredLogins()));

		// logout removes logins above limit
		$identity4 = new IntIdentity(4, []);
		$storage->login($identity4);
		$storage->logout($storage::REASON_MANUAL);
		self::assertSame([3, 'second', 4], array_keys($storage->getExpiredLogins()));

		// new login also removes logins above limit
		$storage->login($identity1);
		$identity5 = new StringIdentity('fifth', []);
		$storage->login($identity5);
		self::assertSame(['second', 4, 1], array_keys($storage->getExpiredLogins()));

		// Remove expired login with specific ID
		$storage->removeExpiredLogin(4);
		self::assertSame(['second', 1], array_keys($storage->getExpiredLogins()));

		// Remove expired logins above limit
		$storage->setExpiredIdentitiesLimit(1);
		self::assertSame([1], array_keys($storage->getExpiredLogins()));

		// Remove all expired logins
		$storage->removeExpiredLogins();
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRenewerSameIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'), new AlwaysPassIdentityRenewer());
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRenewerNewIdentity(): void
	{
		$newIdentity = new IntIdentity(456, []);
		$originalIdentity = new IntIdentity(123, []);
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'), new NewIdentityIdentityRenewer($newIdentity));

		$storage->login($originalIdentity);
		self::assertSame($newIdentity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRenewerRemovedIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'), new NeverPassIdentityRenewer());
		$identity = new IntIdentity(123, []);

		$storage->login($identity);
		self::assertNull($storage->getIdentity());

		$expired = $storage->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($storage::REASON_INVALID_IDENTITY, $expired->getLogoutReason());
	}

}
