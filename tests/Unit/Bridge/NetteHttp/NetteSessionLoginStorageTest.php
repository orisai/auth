<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Bridge\NetteHttp;

use DateTimeImmutable;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\Session;
use Nette\Http\UrlScript;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\LoginStorage;
use Orisai\Auth\Authentication\StringIdentity;
use Orisai\Auth\Bridge\NetteHttp\NetteSessionLoginStorage;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;
use function array_keys;
use function sleep;

/**
 * @runTestsInSeparateProcesses
 */
final class NetteSessionLoginStorageTest extends TestCase
{

	private function createSession(): Session
	{
		return new Session(new Request(new UrlScript('https://example.com')), new Response());
	}

	private function createStorage(Session $session, ?IdentityRenewer $renewer = null): LoginStorage
	{
		return new NetteSessionLoginStorage('admin', $session, $renewer);
	}

	private function createIdentity(): Identity
	{
		return new IntIdentity(123, []);
	}

	public function testLogin(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);
		$identity = $this->createIdentity();

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
		$session = $this->createSession();
		$storage = $this->createStorage($session);
		$identity = $this->createIdentity();

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
		$session = $this->createSession();
		$storage = $this->createStorage($session);
		$identity = $this->createIdentity();

		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage->renewIdentity($identity);
		self::assertSame($identity, $storage->getIdentity());

		$newIdentity = $this->createIdentity();
		$storage->renewIdentity($newIdentity);
		self::assertSame($newIdentity, $storage->getIdentity());
	}

	public function testUseExistingSession(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());

		$storage = $this->createStorage($session);
		self::assertSame($identity, $storage->getIdentity());
	}

	public function testTimeExpiredIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		$storage->setExpiration(new DateTimeImmutable('1 second'));
		self::assertSame($identity, $storage->getIdentity());
		sleep(2);

		$storage = $this->createStorage($session);
		self::assertNull($storage->getIdentity());

		$expired = $storage->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($storage::REASON_INACTIVITY, $expired->getLogoutReason());
	}

	public function testNotTimeExpiredIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		$storage->setExpiration(new DateTimeImmutable('10 minutes'));
		self::assertSame($identity, $storage->getIdentity());

		$storage = $this->createStorage($session);
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRemovedTimeExpiration(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		$storage->setExpiration(new DateTimeImmutable('1 seconds'));
		$storage->removeExpiration();
		self::assertSame($identity, $storage->getIdentity());
		sleep(2);

		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testExpirationTimeInThePast(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);
		$identity = $this->createIdentity();

		$storage->login($identity);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time is lower than current time.
Solution: Choose expiration time which is in future.
MSG);

		$storage->setExpiration(new DateTimeImmutable('10 seconds ago'));
	}

	public function testExpiredIdentities(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);
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
		$session = $this->createSession();
		$identity = $this->createIdentity();
		$renewer = new AlwaysPassIdentityRenewer();

		$storage = $this->createStorage($session, $renewer);
		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());

		$storage = $this->createStorage($session, $renewer);
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRenewerNewIdentity(): void
	{
		$newIdentity = new IntIdentity(456, []);
		$originalIdentity = $this->createIdentity();
		$renewer = new NewIdentityIdentityRenewer($newIdentity);

		$session = $this->createSession();

		$storage = $this->createStorage($session, $renewer);
		$storage->login($originalIdentity);
		self::assertSame($originalIdentity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());

		$storage = $this->createStorage($session, $renewer);
		self::assertSame($newIdentity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());
	}

	public function testRenewerRemovedIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();
		$renewer = new NeverPassIdentityRenewer();

		$storage = $this->createStorage($session, $renewer);
		$storage->login($identity);
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame([], $storage->getExpiredLogins());

		$storage = $this->createStorage($session, $renewer);
		$expired = $storage->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($storage::REASON_INVALID_IDENTITY, $expired->getLogoutReason());
	}

}
