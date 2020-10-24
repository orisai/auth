<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use DateTimeImmutable;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Exceptions\Logic\InvalidState;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\ArrayIdentityStorage;
use Tests\Orisai\Auth\Doubles\TestingFirewall;

final class BaseFirewallTest extends TestCase
{

	public function testBase(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		self::assertFalse($firewall->isLoggedIn());
		self::assertNull($firewall->getExpiredIdentity());
		self::assertNull($firewall->getLogoutReason());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame($identity, $firewall->getExpiredIdentity());
		self::assertNull($firewall->getLogoutReason());

		$firewall->logout();
		self::assertFalse($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getExpiredIdentity());
		self::assertSame($firewall::REASON_MANUAL, $firewall->getLogoutReason());
	}

	public function testExpiration(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(new DateTimeImmutable('10 seconds ago'));
		self::assertFalse($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getExpiredIdentity());
		self::assertSame($firewall::REASON_INACTIVITY, $firewall->getLogoutReason());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame($identity, $firewall->getExpiredIdentity());
		self::assertNull($firewall->getLogoutReason());
	}

	public function testRemoveExpiration(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(new DateTimeImmutable('10 seconds ago'));
		$firewall->removeExpiration();

		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame($identity, $firewall->getExpiredIdentity());
		self::assertNull($firewall->getLogoutReason());
	}

	public function testNotLoggedInGetIdentity(): void
	{
		$storage = new ArrayIdentityStorage(new DateTimeImmutable('now'));
		$firewall = new TestingFirewall($storage);

		$this->expectException(InvalidState::class);
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
