<?php declare(strict_types = 1);

namespace Tests\Orisai\Auth\Unit\Authentication;

use Brick\DateTime\Clock\FixedClock;
use Brick\DateTime\Instant;
use Orisai\Auth\Authentication\ArrayLoginStorage;
use Orisai\Auth\Authentication\Exception\CannotAccessIdentity;
use Orisai\Auth\Authentication\Exception\CannotGetAuthenticationTime;
use Orisai\Auth\Authentication\Exception\CannotRenewIdentity;
use Orisai\Auth\Authentication\IntIdentity;
use Orisai\Auth\Authentication\StringIdentity;
use Orisai\Exceptions\Logic\InvalidArgument;
use PHPUnit\Framework\TestCase;
use Tests\Orisai\Auth\Doubles\AlwaysPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NeverPassIdentityRenewer;
use Tests\Orisai\Auth\Doubles\NewIdentityIdentityRenewer;
use Tests\Orisai\Auth\Doubles\TestingFirewall;
use function array_keys;

final class BaseFirewallTest extends TestCase
{

	public function renewer(): AlwaysPassIdentityRenewer
	{
		return new AlwaysPassIdentityRenewer();
	}

	public function testBase(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());
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

	public function testSeparateNamespaces(): void
	{
		$storage = new ArrayLoginStorage();
		$identity = new IntIdentity(123, []);

		$firewall1 = new TestingFirewall($storage, $this->renewer(), null, 'one');
		$firewall2 = new TestingFirewall($storage, $this->renewer(), null, 'two');

		self::assertFalse($storage->alreadyExists('one'));
		self::assertFalse($storage->alreadyExists('two'));

		$firewall1->login($identity);
		self::assertTrue($storage->alreadyExists('one'));
		self::assertFalse($storage->alreadyExists('two'));

		$firewall2->login($identity);
		self::assertTrue($storage->alreadyExists('one'));
		self::assertTrue($storage->alreadyExists('two'));

		self::assertSame($firewall1->getIdentity(), $firewall2->getIdentity());

		$newIdentity = new IntIdentity(456, []);
		$firewall1->login($newIdentity);

		self::assertSame($newIdentity, $firewall1->getIdentity());
		self::assertSame($identity, $firewall2->getIdentity());
	}

	public function testIdentityClassUpdate(): void
	{
		$originalIdentity = new IntIdentity(123, []);
		$renewedIdentity = new StringIdentity('string', []);

		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, new NewIdentityIdentityRenewer($renewedIdentity));

		$firewall->login($originalIdentity);
		$firewall->resetLoginsChecks();
		self::assertSame($renewedIdentity, $firewall->getLogins()->getCurrentLogin()->getIdentity());
	}

	public function testHasRole(): void
	{
		$identity = new IntIdentity(123, ['foo']);

		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());

		self::assertFalse($firewall->hasRole('foo'));

		$firewall->login($identity);
		self::assertTrue($firewall->hasRole('foo'));
		self::assertFalse($firewall->hasRole('bar'));
	}

	public function testExpiredIdentities(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());
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

	public function testManualRenewIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$firewall->renewIdentity($identity);
		self::assertSame($identity, $firewall->getIdentity());

		$newIdentity = new IntIdentity(456, []);
		$firewall->renewIdentity($newIdentity);
		self::assertSame($newIdentity, $firewall->getIdentity());
	}

	public function testManualRenewIdentityFailure(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());
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

	public function testRenewerSameIdentity(): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$renewer = new AlwaysPassIdentityRenewer();
		$firewall = new TestingFirewall($storage, $renewer);

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRenewerNewIdentity(): void
	{
		$originalIdentity = new IntIdentity(123, []);
		$newIdentity = new IntIdentity(456, []);

		$storage = new ArrayLoginStorage();
		$renewer = new NewIdentityIdentityRenewer($newIdentity);
		$firewall = new TestingFirewall($storage, $renewer);

		$firewall->login($originalIdentity);
		self::assertSame($originalIdentity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		self::assertSame($newIdentity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRenewerRemovedIdentity(): void
	{
		$identity = new IntIdentity(123, []);

		$storage = new ArrayLoginStorage();
		$renewer = new NeverPassIdentityRenewer();
		$firewall = new TestingFirewall($storage, $renewer);

		$firewall->login($identity);
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());

		$firewall->resetLoginsChecks();

		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INVALID_IDENTITY, $expired->getLogoutReason());
	}

	public function testTimeExpiredIdentity(): void
	{
		$clock = new FixedClock(Instant::now());
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $clock);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(Instant::now()->plusSeconds(1));
		self::assertSame($identity, $firewall->getIdentity());

		$clock->move(2);
		$firewall->resetLoginsChecks();

		self::assertFalse($firewall->isLoggedIn());
		$expired = $firewall->getExpiredLogins()[123];
		self::assertSame($identity, $expired->getIdentity());
		self::assertSame($firewall::REASON_INACTIVITY, $expired->getLogoutReason());

		$firewall->login($identity);
		self::assertTrue($firewall->isLoggedIn());
		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testNotTimeExpiredIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(Instant::now()->plusMinutes(10));
		self::assertSame($identity, $firewall->getIdentity());

		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testRemovedTimeExpiration(): void
	{
		$clock = new FixedClock(Instant::now());
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), $clock);
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);
		$firewall->setExpiration(Instant::now()->plusSeconds(1));
		$firewall->removeExpiration();
		self::assertSame($identity, $firewall->getIdentity());

		$clock->move(2);
		$firewall->resetLoginsChecks();

		self::assertSame($identity, $firewall->getIdentity());
		self::assertSame([], $firewall->getExpiredLogins());
	}

	public function testExpirationTimeInThePast(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());
		$identity = new IntIdentity(123, []);

		$firewall->login($identity);

		$this->expectException(InvalidArgument::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to set login expiration time.
Problem: Expiration time is lower than current time.
Solution: Choose expiration time which is in future.
MSG);

		$firewall->setExpiration(Instant::now()->minusSeconds(10));
	}

	public function testNotLoggedInGetIdentity(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());

		$this->expectException(CannotAccessIdentity::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to get valid identity with
         Tests\Orisai\Auth\Doubles\TestingFirewall->getIdentity().
Problem: User is not logged in firewall.
Solution: Check with TestingFirewall->isLoggedIn() or use
          TestingFirewall->getExpiredLogins().
MSG);

		$firewall->getIdentity();
	}

	public function testGetAuthenticationTime(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer(), new FixedClock(Instant::of(1)));

		$identity = new IntIdentity(123, []);
		$firewall->login($identity);
		self::assertSame(1, $firewall->getAuthenticationTime()->getEpochSecond());
	}

	public function testNotLoggedInGetAuthTime(): void
	{
		$storage = new ArrayLoginStorage();
		$firewall = new TestingFirewall($storage, $this->renewer());

		$this->expectException(CannotGetAuthenticationTime::class);
		$this->expectExceptionMessage(<<<'MSG'
Context: Trying to get authentication time with
         Tests\Orisai\Auth\Doubles\TestingFirewall->getAuthenticationTime().
Problem: User is not logged in firewall.
Solution: Check with TestingFirewall->isLoggedIn().
MSG);

		$firewall->getAuthenticationTime();
	}

	/**
	 * Prevents errors like "headers already sent" when storage uses session
	 * and firewall is used for read after headers were sent
	 */
	public function testReadOnlyMethodsDoesNotTriggerStorageCreation(): void
	{
		$storage = new ArrayLoginStorage();
		$namespace = 'test';
		$firewall = new TestingFirewall($storage, $this->renewer(), null, $namespace);

		self::assertFalse($storage->alreadyExists($namespace));

		try {
			$firewall->getIdentity();
		}catch (CannotAccessIdentity $exception) {
			// Just to test storage creation
		}

		self::assertFalse($storage->alreadyExists($namespace));

		try {
			$firewall->getAuthenticationTime();
		}catch (CannotGetAuthenticationTime $exception) {
			// Just to test storage creation
		}

		self::assertFalse($storage->alreadyExists($namespace));

		self::assertSame([], $firewall->getExpiredLogins());
		self::assertFalse($storage->alreadyExists($namespace));

		self::assertFalse($firewall->hasRole('any'));
		self::assertFalse($storage->alreadyExists($namespace));
	}

}
