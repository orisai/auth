<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use DateTimeImmutable;
use Orisai\Auth\Authentication\Exception\CannotAccessIdentity;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\ArrayLoginStorage;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use function array_keys;

final class BaseFirewallTest extends TestCase
{

	public function testBase(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		self::assertFalse($firewall->isLoggedIn());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->logout();
		self::assertFalse($firewall->isLoggedIn());

		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_MANUAL, $expired->getLogoutReason());

		$this->expectException(CannotAccessIdentity::class);
		$firewall->getIdentity();
	}

	public function testExpiredIdentities(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$firewall->setExpiredIdentitiesLimit(3);
		$identity1 = new IntIdentity(1, []);

		$firewall->login($identity1);
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->logout();
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		$firewall->login($identity1);
		self::assertSame([], $firewall->getExpiredLogins());

		$identity2 = new StringIdentity('second', []);
		$firewall->login($identity2);
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		$firewall->logout();
		self::assertSame([1, 'second'], array_keys($firewall->getExpiredLogins()));

		$identity3 = new IntIdentity(3, []);
		$firewall->login($identity3);
		$firewall->login($identity2);
		$firewall->logout();
		self::assertSame([1, 3, 'second'], array_keys($firewall->getExpiredLogins()));

		// logout removes logins above limit
		$identity4 = new IntIdentity(4, []);
		$firewall->login($identity4);
		$firewall->logout();
		self::assertSame([3, 'second', 4], array_keys($firewall->getExpiredLogins()));

		// new login also removes logins above limit
		$firewall->login($identity1);
		$identity5 = new StringIdentity('fifth', []);
		$firewall->login($identity5);
		self::assertSame(['second', 4, 1], array_keys($firewall->getExpiredLogins()));

		// Remove expired login with specific ID
		$firewall->removeExpiredLogin(4);
		self::assertSame(['second', 1], array_keys($firewall->getExpiredLogins()));

		// Remove expired logins above limit
		$firewall->setExpiredIdentitiesLimit(1);
		self::assertSame([1], array_keys($firewall->getExpiredLogins()));

		// Remove all expired logins
		$firewall->removeExpiredLogins();
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRenewIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$newIdentity = new IntIdentity(123, []);
		$firewall->renewIdentity($newIdentity);
		self::assertSame($newIdentity, $storage->getIdentity());
		self::assertSame($newIdentity, $firewall->getIdentity());
	}

	public function testRenewIdentityFailure(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		$this->expectException(CannotRenewIdentity::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to renew identity with
         Tests\Orisai\Auth\Doubles\TestingFirewall->renewIdentity().
Problem: User is not logged in firewall.
Solution: Use TestingFirewall->login() instead or check with
          TestingFirewall->isLoggedIn().
MSG);

		$firewall->renewIdentity($identity);
	}

	public function testTimeExpiration(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(new DateTimeImmutable('10 seconds ago'));
		self::assertFalse($firewall->isLoggedIn());
		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INACTIVITY, $expired->getLogoutReason());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRemoveTimeExpiration(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(new DateTimeImmutable('10 seconds ago'));
		$firewall->removeExpiration();

		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testNotLoggedInGetIdentity(): void
	{
		$storage = new ArrayLoginStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);

		$this->expectException(CannotAccessIdentity::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to get valid identity with
         Tests\Orisai\Auth\Doubles\TestingFirewall->getIdentity().
Problem: User is not logged in firewall.
Solution: Check with TestingFirewall->isLoggedIn() or use
          TestingFirewall->getExpiredIdentity().
MSG);

		$firewall->getIdentity();
	}

}
