<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Bridge\NetteHttp;

use DateTimeImmutable;
use Nette\Http\Request;
use Nette\Http\Response;
use Nette\Http\Session;
use Nette\Http\UrlScript;
use Orisai\Auth\Authentication\Identity;
use Orisai\Auth\Authentication\IdentityRenewer;
use Orisai\Auth\Authentication\IdentityStorage;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Bridge\NetteHttp\NetteSessionIdentityStorage;
use Orisai\Exceptions\Logic\InvalidArgument;
use Orisai\Exceptions\Logic\InvalidState;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;
use function sleep;

/**
 * @runTestsInSeparateProcesses
 */
final class NetteSessionIdentityStorageTest extends TestCase
{

	private function createSession(): Session
	{
		return new Session(new Request(new UrlScript('https://example.com')), new Response());
	}

	private function createStorage(Session $session, ?IdentityRenewer $renewer = null): IdentityStorage
	{
		return new NetteSessionIdentityStorage('admin', $session, $renewer);
	}

	private function createIdentity(): Identity
	{
		return new IntIdentity(123, []);
	}

	public function testBase(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);
		$identity = $this->createIdentity();

		self::assertFalse($storage->isLoggedIn());
		self::assertNull($storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage->login($identity);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage->logout($storage::REASON_MANUAL);
		self::assertFalse($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame($storage::REASON_MANUAL, $storage->getLogoutReason());
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
		self::assertTrue($storage->isLoggedIn());

		$storage = $this->createStorage($session);
		self::assertTrue($storage->isLoggedIn());
	}

	public function testExpiredIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		$storage->setExpiration(new DateTimeImmutable('1 second'));
		self::assertTrue($storage->isLoggedIn());
		sleep(2);

		$storage = $this->createStorage($session);
		self::assertFalse($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame($storage::REASON_INACTIVITY, $storage->getLogoutReason());
	}

	public function testNotExpiredIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		$storage->setExpiration(new DateTimeImmutable('10 minutes'));
		self::assertTrue($storage->isLoggedIn());

		$storage = $this->createStorage($session);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRemovedExpiration(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();

		$storage = $this->createStorage($session);
		$storage->login($identity);
		$storage->setExpiration(new DateTimeImmutable('1 seconds'));
		$storage->removeExpiration();
		self::assertTrue($storage->isLoggedIn());
		sleep(2);

		self::assertTrue($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testExpirationTimeGreaterThanSessionExpiration(): void
	{
		$session = $this->createSession();
		$session->setOptions([
			'gc_maxlifetime' => 10_800,
		]);
		$storage = $this->createStorage($session);

		$this->expectException(InvalidState::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time 315532800 seconds is greater than the session
         expiration time of 10800 seconds.
Solution: Choose expiration time lower than the session expiration time or set
          higher session expiration time.
MSG);

		$storage->setExpiration(new DateTimeImmutable('10 years'));
	}

	/**
	 * @doesNotPerformAssertions
	 */
	public function testSessionNeverExpire(): void
	{
		$session = $this->createSession();
		$session->setOptions([
			'gc_maxlifetime' => 0,
		]);
		$storage = $this->createStorage($session);

		$storage->setExpiration(new DateTimeImmutable('10 years'));
	}

	public function testExpirationTimeInThePast(): void
	{
		$session = $this->createSession();
		$storage = $this->createStorage($session);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time is lower than current time.
Solution: Choose expiration time which is in future.
MSG);

		$storage->setExpiration(new DateTimeImmutable('10 seconds ago'));
	}

	public function testRenewerSameIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();
		$renewer = new AlwaysPassIdentityRenewer();

		$storage = $this->createStorage($session, $renewer);
		$storage->login($identity);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage = $this->createStorage($session, $renewer);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRenewerNewIdentity(): void
	{
		$newIdentity = new IntIdentity(456, []);
		$originalIdentity = $this->createIdentity();
		$renewer = new NewIdentityIdentityRenewer($newIdentity);

		$session = $this->createSession();

		$storage = $this->createStorage($session, $renewer);
		$storage->login($originalIdentity);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($originalIdentity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage = $this->createStorage($session, $renewer);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($newIdentity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());
	}

	public function testRenewerRemovedIdentity(): void
	{
		$session = $this->createSession();
		$identity = $this->createIdentity();
		$renewer = new NeverPassIdentityRenewer();

		$storage = $this->createStorage($session, $renewer);
		$storage->login($identity);
		self::assertTrue($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertNull($storage->getLogoutReason());

		$storage = $this->createStorage($session, $renewer);
		self::assertFalse($storage->isLoggedIn());
		self::assertSame($identity, $storage->getIdentity());
		self::assertSame($storage::REASON_INVALID_IDENTITY, $storage->getLogoutReason());
	}

}
